#!/usr/bin/env bash
#
# Start the major HTTP servers in containers and send one request to each over
# every protocol it speaks. Every image is either a Docker Official Image or
# published by the project itself, and each was picked for being a distinct
# implementation rather than a distinct product. This complements scripts/interop.sh: that one goes
# out to whatever the public internet happens to be running, this one pins down
# a known set of server implementations and covers combinations the public one
# cannot — cleartext h2c, and TLS against a server whose certificate we made.
#
# Every server answers the same 13-byte body, so a status of 200 everywhere is
# the whole of the expected output. These are our own containers, so the load
# is real rather than a single request: 200 requests over 50 connections
# exercises connection reuse and concurrency, not just the first exchange.
#
#   scripts/docker-interop.sh          # bring the servers up, test, leave them up
#   scripts/docker-interop.sh --down   # stop them afterwards
#   SHB=target/dist/shb scripts/docker-interop.sh
#   CONNECTIONS=200 REQUESTS=5000 scripts/docker-interop.sh
#
set -uo pipefail

SHB=${SHB:-./target/release/shb}
# Our own servers, so this is a real if small amount of load rather than one
# request; it covers connection reuse, which one request cannot
CONNECTIONS=${CONNECTIONS:-50}
REQUESTS=${REQUESTS:-200}
DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/../docker" && pwd)"

if [ ! -x "$SHB" ]; then
    echo "no shb binary at $SHB (build one, or set SHB=...)" >&2
    exit 2
fi

# server | protocol flag | url | note
#
# Ports are assigned in docker/compose.yml. HTTP/3 shares its port number with
# the TLS port, over UDP.
ENDPOINTS=$(cat <<'EOF'
nginx|h1|http://127.0.0.1:18080/|cleartext
nginx|h2|http://127.0.0.1:18080/|cleartext h2c, prior knowledge
nginx|h1|https://127.0.0.1:18443/|TLS
nginx|h2|https://127.0.0.1:18443/|TLS, ALPN h2
nginx|h3|https://127.0.0.1:18443/|nginx's own QUIC
caddy|h1|http://127.0.0.1:18081/|cleartext
caddy|h2|http://127.0.0.1:18081/|cleartext h2c, prior knowledge
caddy|h1|https://127.0.0.1:18444/|TLS
caddy|h2|https://127.0.0.1:18444/|TLS, ALPN h2
caddy|h3|https://127.0.0.1:18444/|quic-go
haproxy|h1|http://127.0.0.1:18082/|cleartext
haproxy|h2|http://127.0.0.1:18085/|cleartext h2c, on its own bind
haproxy|h1|https://127.0.0.1:18445/|TLS
haproxy|h2|https://127.0.0.1:18445/|TLS, ALPN h2
httpd|h1|http://127.0.0.1:18083/|cleartext
httpd|h2|http://127.0.0.1:18083/|cleartext h2c, mod_http2
httpd|h1|https://127.0.0.1:18446/|TLS
httpd|h2|https://127.0.0.1:18446/|TLS, ALPN h2
envoy|h1|http://127.0.0.1:18084/|cleartext
envoy|h2|http://127.0.0.1:18084/|cleartext h2c, prior knowledge
envoy|h1|https://127.0.0.1:18447/|TLS
envoy|h2|https://127.0.0.1:18447/|TLS, ALPN h2
envoy|h3|https://127.0.0.1:18447/|quiche
varnish|h1|http://127.0.0.1:18086/|cleartext
varnish|h2|http://127.0.0.1:18086/|cleartext h2c, prior knowledge
traefik|h1|http://127.0.0.1:18087/|cleartext
traefik|h2|http://127.0.0.1:18087/|cleartext h2c, prior knowledge
traefik|h1|https://127.0.0.1:18448/|TLS
traefik|h2|https://127.0.0.1:18448/|TLS, ALPN h2
traefik|h3|https://127.0.0.1:18448/|quic-go
tomcat|h1|http://127.0.0.1:18088/|cleartext
tomcat|h2|http://127.0.0.1:18088/|cleartext h2c, Coyote
openlite|h1|http://127.0.0.1:18089/|cleartext
openlite|h1|https://127.0.0.1:18449/|TLS
openlite|h2|https://127.0.0.1:18449/|TLS, ALPN h2
EOF
)

flag_for() {
    case "$1" in
        h1) echo "" ;;
        h2) echo "--http2" ;;
        h3) echo "--http3" ;;
    esac
}

echo "starting servers..."
docker compose -f "$DIR/compose.yml" up -d --wait --wait-timeout 120 >/dev/null 2>&1 ||
    docker compose -f "$DIR/compose.yml" up -d >/dev/null 2>&1
# A server that has bound its port still needs a moment to be ready to answer
sleep 5

pass=0
fail=0
failures=()

printf '%-8s %-5s %-30s %-9s %s\n' SERVER PROTO ENDPOINT RESULT NOTE
printf '%-8s %-5s %-30s %-9s %s\n' -------- ----- ------------------------------ --------- ----

while IFS='|' read -r server proto url note; do
    [ -z "$server" ] && continue
    out=$(timeout 60 "$SHB" $(flag_for "$proto") \
        -c "$CONNECTIONS" -n "$REQUESTS" --connect-timeout 10s -j "$url" 2>/dev/null)

    if [ -n "$out" ] && [ "${out:0:1}" = "{" ]; then
        ok=$(printf '%s' "$out" | jq -r '.requests.ok')
        codes=$(printf '%s' "$out" | jq -r '.statusCodes | keys | join(",")')
    else
        ok=0; codes=""
    fi

    if [ "$ok" = "$REQUESTS" ] && [ "$codes" = "200" ]; then
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "$ok ok" "$note"
        pass=$((pass + 1))
    else
        # Say what actually happened: "failed" on its own costs a whole
        # debugging round trip when this only reproduces in CI
        detail=$(printf '%s' "$out" | jq -rc \
            '"ok=\(.requests.ok) err=\(.requests.errors) connErr=\(.requests.connectErrors) \(.statusCodes)"' 2>/dev/null)
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "failed" "$note"
        failures+=("$server $proto $url  ${detail:-no JSON report; shb itself failed}")
        fail=$((fail + 1))
    fi
done <<< "$ENDPOINTS"

echo
echo "$pass passed, $fail failed"

if [ "${1:-}" = "--down" ]; then
    docker compose -f "$DIR/compose.yml" down >/dev/null 2>&1
    echo "servers stopped"
fi

if [ "$fail" -gt 0 ]; then
    printf '  %s\n' "${failures[@]}"
    echo "logs: docker compose -f $DIR/compose.yml logs <service>"
    exit 1
fi
