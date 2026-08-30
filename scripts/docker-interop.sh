#!/usr/bin/env bash
#
# Start the major HTTP servers in containers and send one request to each over
# every protocol it speaks. This complements scripts/interop.sh: that one goes
# out to whatever the public internet happens to be running, this one pins down
# a known set of server implementations and covers combinations the public one
# cannot — cleartext h2c, and TLS against a server whose certificate we made.
#
# Every server answers the same 13-byte body, so a status of 200 everywhere is
# the whole of the expected output.
#
#   scripts/docker-interop.sh          # bring the servers up, test, leave them up
#   scripts/docker-interop.sh --down   # stop them afterwards
#   SHB=target/dist/shb scripts/docker-interop.sh
#
set -uo pipefail

SHB=${SHB:-./target/release/shb}
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
    out=$(timeout 30 "$SHB" $(flag_for "$proto") \
        -c 1 -t 1 -n 1 --connect-timeout 10s -j "$url" 2>/dev/null)

    if [ -n "$out" ] && [ "${out:0:1}" = "{" ]; then
        ok=$(printf '%s' "$out" | jq -r '.requests.ok')
        codes=$(printf '%s' "$out" | jq -r '.statusCodes | keys | join(",")')
    else
        ok=0; codes=""
    fi

    if [ "$ok" = "1" ] && [ "$codes" = "200" ]; then
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "ok 200" "$note"
        pass=$((pass + 1))
    else
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "failed" "$note"
        failures+=("$server $proto $url")
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
