#!/usr/bin/env bash
#
# Start the major HTTP servers in containers and send one request to each over
# every protocol it speaks. Every image is either a Docker Official Image, one
# published by the project itself, or a few lines built on an official base,
# and each was picked for being a distinct implementation rather than a
# distinct product. Hypercorn, Node and Go are here because the suite had
# drifted towards C proxies sharing libraries and those three decode HTTP/2
# themselves. picoquic, aioquic, quicly and ngtcp2 bring the QUIC
# implementations to eight with Bun's, next to nginx's own, quic-go and
# Google's QUICHE -
# which is not Cloudflare's quiche, a different project with nearly the same
# name. nghttpx is here for its HTTP/2 as much as its HTTP/3: nghttp2 is the
# reference implementation, and until now it was only reachable through a
# public test server. This complements scripts/interop.sh: that one goes
# out to whatever the public internet happens to be running, this one pins down
# a known set of server implementations and covers combinations the public one
# cannot — cleartext h2c, and TLS against a server whose certificate we made.
#
# Every server answers the same 13-byte body, so a status of 200 everywhere is
# the whole of the expected output. The exception is nginx's /bigheaders, which
# returns the same body behind 48 KB of response headers: that is three times
# the default HTTP/2 frame size, so the server has to split the block across
# CONTINUATION frames, a path no page-sized response reaches and one that only
# a server we configure ourselves will produce on demand. Ports 18090 and 18450
# are the same nginx with keepalive_requests 5, which makes it take the
# connection away part way through the run - GOAWAY on HTTP/2 and HTTP/3,
# Connection: close on HTTP/1.1 - so the run only finishes if reconnecting
# works. Both were verified to happen rather than assumed: two CONTINUATION
# frames arrive, and ten GOAWAYs for ten connections. These are our own containers, so the load
# is real rather than a single request: 200 requests over 50 connections
# exercises connection reuse and concurrency, not just the first exchange.
#
# The /bigbody endpoints answer with a quarter of a megabyte instead of the
# usual 13 bytes. Everything else here fits one read, so the receive path was
# only ever walked with a single one: a response spanning buffers, rustls
# refusing more ciphertext until the plaintext waiting is drained, QUIC
# reassembling a stream across datagrams. The file is written below rather than
# kept in the repository.
#
# A third pass sends a large request header block, which nothing else here
# does: every request otherwise carries about fifty bytes of headers, so the
# HTTP/2 encoder never had to split one across CONTINUATION frames and HTTP/3
# never had to put a QPACK field section across several datagrams. nginx's
# /bigheaders covers the same ground in the other direction - reading a large
# block - and only nginx and caddy serve it.
#
# A second pass repeats the run with a request body, because every HTTP/2 bug
# found so far was invisible without one. Every endpoint in the list above
# sends GET, and the one end-to-end test that posts a body talks to a server
# that reads it - so nothing exercised a body against a server that answers
# without reading one, or a body past a frame or a window boundary. Three bugs
# were hiding there: streams retired by counting, which a RST_STREAM after the
# response then mis-retired; DATA and HEADERS frames sent whole however large,
# which every server but nginx and caddy rejects past 16 KiB; and a body over
# 64 KiB that TLS would not take. The default size crosses both boundaries.
#
# The pass asserts the exchange completed, not a particular status: the servers
# are configured for GET and answer a POST with anything from 200 to 405 to
# 413, while all three bugs showed up as a hang or an error.
#
# HTTP/3 is left out of it. Docker's UDP publishing drops a GSO batch of any
# size once a connection has a body's worth to send, so a body over HTTP/3
# would measure that rather than shb - the same servers take one natively at
# full load, and h2load, which does not use GSO, gets through the container.
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
CONNECTIONS=${CONNECTIONS:-10}
REQUESTS=${REQUESTS:-200}
# Past 16384, the frame size a peer may assume, and past 65535, the window a
# connection starts with and the plaintext rustls will hold
BODY_BYTES=${BODY_BYTES:-100000}
BODY_REQUESTS=${BODY_REQUESTS:-20}
BODY_CONNECTIONS=${BODY_CONNECTIONS:-4}
# Past a receive buffer (16 KiB), a TLS record and a QUIC datagram, several
# times over
BIGBODY_BYTES=${BIGBODY_BYTES:-262144}
# Four of these is about 32 KB encoded, twice the frame size a peer may assume,
# so the block cannot go in one HEADERS frame
BIGHEADER_BYTES=${BIGHEADER_BYTES:-8000}
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
nginx|h1|http://127.0.0.1:18080/bigheaders|a 48 KB response header block
nginx|h2|http://127.0.0.1:18080/bigheaders|the same block, split across CONTINUATION frames
nginx|h1|https://127.0.0.1:18443/bigheaders|48 KB of headers over TLS
nginx|h2|https://127.0.0.1:18443/bigheaders|CONTINUATION over TLS
nginx|h3|https://127.0.0.1:18443/bigheaders|a QPACK field section spanning several reads
nginx|h1|http://127.0.0.1:18080/noreuse|Connection: close on every response
nginx|h1|http://127.0.0.1:18090/|Connection: close on the fifth request
nginx|h2|http://127.0.0.1:18090/|GOAWAY on the fifth request
nginx|h1|https://127.0.0.1:18450/|Connection: close on the fifth request, TLS
nginx|h2|https://127.0.0.1:18450/|GOAWAY on the fifth request, TLS
nginx|h3|https://127.0.0.1:18450/|GOAWAY on the fifth request, over QUIC
nginx|h3|https://127.0.0.1:18464/|address validation: the handshake starts over with a Retry token
caddy|h1|http://127.0.0.1:18081/|cleartext
caddy|h2|http://127.0.0.1:18081/|cleartext h2c, prior knowledge
caddy|h1|https://127.0.0.1:18444/|TLS
caddy|h2|https://127.0.0.1:18444/|TLS, ALPN h2
caddy|h3|https://127.0.0.1:18444/|quic-go
nginx|h1|http://127.0.0.1:18080/bigbody|256 KB body, cleartext
nginx|h2|http://127.0.0.1:18080/bigbody|256 KB body, h2c
nginx|h1|https://127.0.0.1:18443/bigbody|256 KB body, TLS
nginx|h2|https://127.0.0.1:18443/bigbody|256 KB body, TLS
nginx|h3|https://127.0.0.1:18443/bigbody|256 KB body over QUIC
caddy|h2|http://127.0.0.1:18081/bigheaders|48 KB of response headers, h2c
caddy|h3|https://127.0.0.1:18444/bigheaders|a QPACK field section spanning several reads
caddy|h1|http://127.0.0.1:18081/bigbody|256 KB body, cleartext
caddy|h2|https://127.0.0.1:18444/bigbody|256 KB body, TLS
caddy|h3|https://127.0.0.1:18444/bigbody|256 KB body over QUIC
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
envoy|h3|https://127.0.0.1:18447/|Google's QUICHE
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
hypercorn|h1|http://127.0.0.1:18091/|cleartext
hypercorn|h2|http://127.0.0.1:18091/|cleartext h2c, Hypercorn's own HTTP/2
hypercorn|h1|https://127.0.0.1:18451/|TLS
hypercorn|h2|https://127.0.0.1:18451/|TLS, ALPN h2
hypercorn|h3|https://127.0.0.1:18451/|aioquic
picoquic|h3|https://127.0.0.1:18455/index.html|picoquic
h2o|h1|https://127.0.0.1:18456/|TLS
h2o|h2|https://127.0.0.1:18456/|TLS, ALPN h2, H2O's own HTTP/2
h2o|h3|https://127.0.0.1:18456/|quicly
nghttpx|h1|https://127.0.0.1:18457/|TLS
nghttpx|h2|https://127.0.0.1:18457/|TLS, ALPN h2, the HTTP/2 reference implementation
nghttpx|h3|https://127.0.0.1:18457/|ngtcp2 and nghttp3
bun|h1|http://127.0.0.1:18459/|cleartext
bun|h1|https://127.0.0.1:18458/|TLS
bun|h2|https://127.0.0.1:18461/|TLS, ALPN h2, via node:http2
bun|h3|https://127.0.0.1:18458/|Bun's own QUIC
deno|h1|http://127.0.0.1:18463/|cleartext
deno|h2|http://127.0.0.1:18463/|cleartext h2c, prior knowledge
deno|h1|https://127.0.0.1:18462/|TLS
deno|h2|https://127.0.0.1:18462/|TLS, ALPN h2, undocumented but present
node|h1|http://127.0.0.1:18093/|cleartext
node|h2|http://127.0.0.1:18092/|cleartext h2c, Node's own HTTP/2
node|h1|https://127.0.0.1:18452/|TLS
node|h2|https://127.0.0.1:18452/|TLS, ALPN h2
goserver|h1|http://127.0.0.1:18094/|cleartext
goserver|h1|https://127.0.0.1:18453/|TLS
goserver|h2|https://127.0.0.1:18453/|TLS, ALPN h2, Go's net/http2
EOF
)

flag_for() {
    case "$1" in
        h1) echo "" ;;
        h2) echo "--http2" ;;
        h3) echo "--http3" ;;
    esac
}

# The servers read this from the conf directory they already mount
head -c "$BIGBODY_BYTES" /dev/zero | tr '\0' 'b' > "$DIR/conf/bigbody.txt"

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

# ---------------------------------------------------------------------------
# Second pass: the same endpoints, with a request body
# ---------------------------------------------------------------------------

body_file=$(mktemp)
trap 'rm -f "$body_file"' EXIT
head -c "$BODY_BYTES" /dev/zero | tr '\0' 'a' > "$body_file"

echo
printf '%-8s %-5s %-30s %-9s %s\n' SERVER PROTO "BODY ${BODY_BYTES}B" RESULT NOTE
printf '%-8s %-5s %-30s %-9s %s\n' -------- ----- ------------------------------ --------- ----

while IFS='|' read -r server proto url note; do
    [ -z "$server" ] && continue
    # See the header: HTTP/3 through Docker's UDP publishing measures Docker
    [ "$proto" = h3 ] && continue
    # These two are about what the server sends, not what it is sent
    case "$url" in *"/bigbody" | *"/bigheaders") continue ;; esac
    skip=""
    case "$server|$proto" in
        # Two of these on one connection wedge it, and curl hangs there too
        openlite\|h1) skip="wedges on a reused connection, curl too" ;;
        # h2load fails this one as well; its HTTP/1.1 on the same port is fine
        hypercorn\|h2)
            [ "${url#https}" != "$url" ] && skip="rejected over TLS, h2load too"
            ;;
    esac
    if [ -n "$skip" ]; then
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "skipped" "$skip"
        continue
    fi

    # What this pass is checking is that the protocol worked, not that the
    # network was perfect. A server under load may close a keep-alive
    # connection with a request on it; that request is genuinely lost and shb
    # is right to report it, but it is not a protocol fault - and a 100 KB body
    # takes long enough to leave a window for it that a GET does not. On a
    # loaded machine it happens to about one cell in sixty.
    #
    # So a cell passes on nine tenths of its requests arriving with no connect
    # errors, and retries once before failing. None of what this pass exists to
    # catch squeaks through that: the frame-size bug failed every request, the
    # TLS one stopped shb before it made a report, and the stream-retiring one
    # hung until the timeout.
    threshold=$(((BODY_REQUESTS * 9 + 9) / 10))
    for attempt in 1 2; do
        out=$(timeout 60 "$SHB" $(flag_for "$proto") -m POST -d "@$body_file" \
            -c "$BODY_CONNECTIONS" -n "$BODY_REQUESTS" --connect-timeout 10s -j "$url" 2>/dev/null)

        if [ -n "$out" ] && [ "${out:0:1}" = "{" ]; then
            ok=$(printf '%s' "$out" | jq -r '.requests.ok')
            conn_err=$(printf '%s' "$out" | jq -r '.requests.connectErrors')
            codes=$(printf '%s' "$out" | jq -r '.statusCodes | keys | join(",")')
        else
            ok=0; conn_err=1; codes=""
        fi

        [ "$ok" -ge "$threshold" ] && [ "$conn_err" = "0" ] && break
        [ "$attempt" = "1" ] && sleep 2
    done

    if [ "$ok" -ge "$threshold" ] && [ "$conn_err" = "0" ]; then
        note_out="$codes"
        [ "$ok" != "$BODY_REQUESTS" ] && note_out="$codes (of $BODY_REQUESTS)"
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "$ok ok" "$note_out"
        pass=$((pass + 1))
    else
        detail=$(printf '%s' "$out" | jq -rc \
            '"ok=\(.requests.ok) err=\(.requests.errors) connErr=\(.requests.connectErrors) \(.statusCodes)"' 2>/dev/null)
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "failed" "$note"
        failures+=("$server $proto $url with a ${BODY_BYTES}-byte body  ${detail:-no JSON report; shb itself failed}")
        fail=$((fail + 1))
    fi
done <<< "$ENDPOINTS"

# ---------------------------------------------------------------------------
# Third pass: the same endpoints, with a large request header block
# ---------------------------------------------------------------------------

big_header=$(head -c "$BIGHEADER_BYTES" /dev/zero | tr '\0' 'h')

echo
printf '%-8s %-5s %-30s %-9s %s\n' SERVER PROTO "BIG REQUEST HEADERS" RESULT NOTE
printf '%-8s %-5s %-30s %-9s %s\n' -------- ----- ------------------------------ --------- ----

while IFS='|' read -r server proto url note; do
    [ -z "$server" ] && continue
    # These two answer about what the server sends, not what it is sent
    case "$url" in *"/bigbody" | *"/bigheaders") continue ;; esac
    skip=""
    case "$server|$proto" in
        # Both cut the stream off rather than answer; their HTTP/1.1 says why,
        # with a 400 for the same block
        haproxy\|h2 | tomcat\|h2) skip="header block over its limit, reset rather than answered" ;;
    esac
    if [ -n "$skip" ]; then
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "skipped" "$skip"
        continue
    fi

    # As with the body pass: what is being checked is that a block too large
    # for one frame is encoded, sent and understood, so any answer counts -
    # several of these servers have their own limit and say 400 or 431, which
    # still means they read it.
    for attempt in 1 2; do
        out=$(timeout 60 "$SHB" $(flag_for "$proto") \
            -H "X-Big-A: $big_header" -H "X-Big-B: $big_header" \
            -H "X-Big-C: $big_header" -H "X-Big-D: $big_header" \
            -c "$BODY_CONNECTIONS" -n "$BODY_REQUESTS" --connect-timeout 10s -j "$url" 2>/dev/null)

        if [ -n "$out" ] && [ "${out:0:1}" = "{" ]; then
            ok=$(printf '%s' "$out" | jq -r '.requests.ok')
            conn_err=$(printf '%s' "$out" | jq -r '.requests.connectErrors')
            codes=$(printf '%s' "$out" | jq -r '.statusCodes | keys | join(",")')
        else
            ok=0; conn_err=1; codes=""
        fi

        [ "$ok" -ge "$threshold" ] && [ "$conn_err" = "0" ] && break
        [ "$attempt" = "1" ] && sleep 2
    done

    if [ "$ok" -ge "$threshold" ] && [ "$conn_err" = "0" ]; then
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "$ok ok" "$codes"
        pass=$((pass + 1))
    else
        detail=$(printf '%s' "$out" | jq -rc \
            '"ok=\(.requests.ok) err=\(.requests.errors) connErr=\(.requests.connectErrors) \(.statusCodes)"' 2>/dev/null)
        printf '%-8s %-5s %-30s %-9s %s\n' "$server" "$proto" "$url" "failed" "$note"
        failures+=("$server $proto $url with a large header block  ${detail:-no JSON report; shb itself failed}")
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
