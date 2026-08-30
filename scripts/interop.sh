#!/usr/bin/env bash
#
# Send one request to a spread of public servers over each protocol, to check
# that shb's HTTP/1.1, HTTP/2 and HTTP/3 implementations interoperate with
# what is actually deployed. The point is the protocol exchange, not the
# response: a 403 from a server that blocks unknown clients still means the
# framing, header coding and TLS all worked, so any HTTP status counts as a
# pass and only a transport or decoding failure counts as a failure.
#
# One request per endpoint, so it is negligible load on someone else's server.
#
#   scripts/interop.sh              # every endpoint
#   scripts/interop.sh h3           # only HTTP/3
#   SHB=target/dist/shb scripts/interop.sh
#   VERBOSE=1 scripts/interop.sh    # show shb's stderr for failures
#
set -uo pipefail

SHB=${SHB:-./target/release/shb}
VERBOSE=${VERBOSE:-}
FILTER=${1:-all}

if [ ! -x "$SHB" ]; then
    echo "no shb binary at $SHB (build one, or set SHB=...)" >&2
    exit 2
fi

# protocol | url | what is known to be serving it
ENDPOINTS=$(cat <<'EOF'
h1|https://example.com/|ICANN
h1|http://example.com/|ICANN, cleartext
h1|https://www.google.com/|Google
h1|https://nginx.org/|nginx
h1|http://nginx.org/|nginx, cleartext
h1|https://www.cloudflare.com/|Cloudflare
h1|https://github.com/|GitHub
h1|https://www.fastly.com/|Fastly
h1|https://facebook.com/|Meta Proxygen
h1|https://www.wikipedia.org/|Wikimedia ATS
h1|https://www.debian.org/|Debian
h1|https://www.kernel.org/|kernel.org
h1|https://crates.io/|crates.io
h1|https://docs.rs/|docs.rs
h1|https://www.rust-lang.org/|Rust
h1|https://www.akamai.com/|Akamai
h1|https://www.apple.com/|Apple
h1|https://aws.amazon.com/|CloudFront
h1|https://www.haproxy.org/|HAProxy
h1|https://caddyserver.com/|Caddy
h1|https://nghttp2.org/|nghttp2
h1|https://litespeedtech.com/|LiteSpeed
h2|https://www.google.com/|Google
h2|https://www.cloudflare.com/|Cloudflare
h2|https://nghttp2.org/|nghttp2, the reference implementation
h2|https://www.fastly.com/|Fastly
h2|https://github.com/|GitHub
h2|https://facebook.com/|Meta Proxygen
h2|https://www.rust-lang.org/|Rust
h2|https://www.wikipedia.org/|Wikimedia ATS
h2|https://crates.io/|crates.io
h2|https://docs.rs/|docs.rs
h2|https://aws.amazon.com/|CloudFront
h2|https://www.apple.com/|Apple
h2|https://caddyserver.com/|Caddy
h2|https://litespeedtech.com/|LiteSpeed
h2|https://gitlab.com/|GitLab
h2|https://stackoverflow.com/|Stack Overflow
h2|https://www.debian.org/|Debian
h3|https://cloudflare-quic.com/|Cloudflare quiche, an HTTP/3 test endpoint
h3|https://quic.nginx.org/|nginx QUIC, an HTTP/3 test endpoint
h3|https://www.google.com/|Google
h3|https://www.youtube.com/|Google
h3|https://www.cloudflare.com/|Cloudflare
h3|https://blog.cloudflare.com/|Cloudflare
h3|https://www.fastly.com/|Fastly
h3|https://facebook.com/|Meta mvfst
h3|https://www.instagram.com/|Meta mvfst
h3|https://litespeedtech.com/|LiteSpeed lsquic
h3|https://discord.com/|Cloudflare
h3|https://www.reddit.com/|Fastly
EOF
)

flag_for() {
    case "$1" in
        h1) echo "" ;;
        h2) echo "--http2" ;;
        h3) echo "--http3" ;;
    esac
}

pass=0
fail=0
skipped=0
failures=()

printf '%-4s %-38s %-9s %s\n' PROTO ENDPOINT RESULT NOTE
printf '%-4s %-38s %-9s %s\n' ---- -------------------------------------- --------- ----

while IFS='|' read -r proto url note; do
    [ -z "$proto" ] && continue
    if [ "$FILTER" != "all" ] && [ "$FILTER" != "$proto" ]; then
        skipped=$((skipped + 1))
        continue
    fi

    err=$(mktemp)
    out=$(timeout 40 "$SHB" $(flag_for "$proto") \
        -c 1 -t 1 -n 1 --connect-timeout 10s -j "$url" 2>"$err")

    if [ -n "$out" ] && [ "${out:0:1}" = "{" ]; then
        ok=$(printf '%s' "$out" | jq -r '.requests.ok')
        codes=$(printf '%s' "$out" | jq -r '.statusCodes | keys | join(",")')
        conn_err=$(printf '%s' "$out" | jq -r '.requests.connectErrors')
    else
        ok=0; codes=""; conn_err=0
    fi

    if [ "$ok" = "1" ]; then
        printf '%-4s %-38s %-9s %s\n' "$proto" "$url" "ok $codes" "$note"
        pass=$((pass + 1))
    else
        reason="failed"
        [ "$conn_err" != "0" ] && reason="no connect"
        printf '%-4s %-38s %-9s %s\n' "$proto" "$url" "$reason" "$note"
        failures+=("$proto $url")
        fail=$((fail + 1))
        if [ -n "$VERBOSE" ] && [ -s "$err" ]; then
            sed 's/^/       /' "$err"
        fi
    fi
    rm -f "$err"
done <<< "$ENDPOINTS"

echo
echo "$pass passed, $fail failed$([ "$skipped" -gt 0 ] && echo ", $skipped filtered out")"
if [ "$fail" -gt 0 ]; then
    echo
    echo "Failures are worth looking at one at a time: a server may simply not"
    echo "offer the protocol (ALPN can pick http/1.1 even when h2 is asked for),"
    echo "or may be refusing an unknown client outright."
    printf '  %s\n' "${failures[@]}"
    exit 1
fi
