#!/usr/bin/env bash
#
# Send one request to a spread of public servers over each protocol, to check
# that shb's HTTP/1.1, HTTP/2 and HTTP/3 implementations interoperate with
# what is actually deployed. The point is the protocol exchange, not the
# response: a 403 from a server that blocks unknown clients still means the
# framing, header coding and TLS all worked, so any HTTP status counts as a
# pass and only a transport or decoding failure counts as a failure.
#
# The one status that is never acceptable is a 1xx: an interim response does
# not finish the message, so recording one means we stopped reading early.
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
h1|https://www.microsoft.com/|Microsoft
h1|https://www.bing.com/|Microsoft
h1|https://www.linkedin.com/|LinkedIn
h1|https://www.adobe.com/|Adobe
h1|https://www.oracle.com/|Oracle
h1|https://www.paypal.com/|PayPal
h1|https://www.netflix.com/|Netflix
h1|https://www.spotify.com/|Spotify
h1|https://www.python.org/|Python
h1|https://pypi.org/|PyPI
h1|https://www.mozilla.org/|Mozilla
h1|https://developer.mozilla.org/|MDN
h1|https://go.dev/|Go
h1|https://www.apache.org/|Apache httpd
h1|https://curl.se/|curl
h1|https://www.nytimes.com/|The New York Times
h1|https://www.theguardian.com/|The Guardian
h1|https://archive.org/|Internet Archive
h1|https://letsencrypt.org/|Let's Encrypt
h1|https://www.eff.org/|EFF
h1|https://kubernetes.io/|Kubernetes
h1|https://prometheus.io/|Prometheus
h1|https://www.docker.com/|Docker
h1|https://hub.docker.com/|Docker Hub
h1|https://archlinux.org/|Arch Linux
h1|https://ubuntu.com/|Canonical
h1|https://www.postgresql.org/|PostgreSQL
h1|https://www.openssl.org/|OpenSSL
h1|https://vercel.com/|Vercel
h1|https://www.netlify.com/|Netlify
h1|https://bitbucket.org/|Bitbucket
h1|https://www.atlassian.com/|Atlassian
h1|https://registry.npmjs.org/|npm registry
h1|https://www.twitch.tv/|Twitch
h1|https://www.linode.com/|Linode
h1|https://www.yahoo.co.jp/|Yahoo! JAPAN
h1|https://www.rakuten.co.jp/|Rakuten
h1|https://qiita.com/|Qiita
h1|https://zenn.dev/|Zenn
h1|https://www.ntt.com/|NTT
h1|https://www.freebsd.org/|FreeBSD, an origin that offers no ALPN but http/1.1
h1|https://www.sakura.ad.jp/|SAKURA internet, HTTP/1.1-only origin
h1|https://www.iij.ad.jp/|IIJ, HTTP/1.1-only origin
h1|https://www.nic.ad.jp/|JPNIC, HTTP/1.1-only origin
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
h2|https://www.microsoft.com/|Microsoft
h2|https://www.bing.com/|Microsoft
h2|https://www.linkedin.com/|LinkedIn
h2|https://www.adobe.com/|Adobe
h2|https://www.oracle.com/|Oracle
h2|https://www.paypal.com/|PayPal
h2|https://www.netflix.com/|Netflix
h2|https://www.spotify.com/|Spotify
h2|https://www.python.org/|Python
h2|https://pypi.org/|PyPI
h2|https://www.mozilla.org/|Mozilla
h2|https://developer.mozilla.org/|MDN
h2|https://go.dev/|Go
h2|https://www.apache.org/|Apache httpd
h2|https://curl.se/|curl
h2|https://www.nytimes.com/|The New York Times
h2|https://www.theguardian.com/|The Guardian
h2|https://archive.org/|Internet Archive
h2|https://letsencrypt.org/|Let's Encrypt
h2|https://www.eff.org/|EFF
h2|https://kubernetes.io/|Kubernetes
h2|https://prometheus.io/|Prometheus
h2|https://www.docker.com/|Docker
h2|https://hub.docker.com/|Docker Hub
h2|https://archlinux.org/|Arch Linux
h2|https://ubuntu.com/|Canonical
h2|https://www.postgresql.org/|PostgreSQL
h2|https://www.openssl.org/|OpenSSL
h2|https://www.kernel.org/|kernel.org
h2|https://vercel.com/|Vercel
h2|https://www.netlify.com/|Netlify
h2|https://bitbucket.org/|Bitbucket
h2|https://www.atlassian.com/|Atlassian
h2|https://registry.npmjs.org/|npm registry
h2|https://www.twitch.tv/|Twitch
h2|https://www.yahoo.co.jp/|Yahoo! JAPAN
h2|https://www.rakuten.co.jp/|Rakuten
h2|https://qiita.com/|Qiita
h2|https://zenn.dev/|Zenn
h2|https://www.ntt.com/|NTT
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
h3|https://www.bing.com/|Microsoft msquic
h3|https://www.linkedin.com/|LinkedIn
h3|https://www.adobe.com/|Akamai
h3|https://www.linode.com/|Akamai
h3|https://www.spotify.com/|Fastly
h3|https://www.python.org/|Fastly
h3|https://pypi.org/|Fastly
h3|https://www.theguardian.com/|Fastly
h3|https://www.mozilla.org/|Mozilla
h3|https://developer.mozilla.org/|MDN
h3|https://curl.se/|curl
h3|https://prometheus.io/|Netlify
h3|https://www.openssl.org/|OpenSSL
h3|https://www.kernel.org/|kernel.org
h3|https://www.atlassian.com/|Atlassian
h3|https://www.twitch.tv/|Twitch, which answers with a 103 Early Hints first
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
    # One retry, and only after a failure. Across this many third-party
    # servers something is always briefly unreachable or rate-limiting, and a
    # weekly run that cries wolf gets ignored. A protocol bug fails twice.
    for attempt in 1 2; do
        out=$(timeout 40 "$SHB" $(flag_for "$proto") \
            -c 1 -t 1 -n 1 --connect-timeout 10s -j "$url" 2>"$err")

        if [ -n "$out" ] && [ "${out:0:1}" = "{" ]; then
            ok=$(printf '%s' "$out" | jq -r '.requests.ok')
            codes=$(printf '%s' "$out" | jq -r '.statusCodes | keys | join(",")')
            conn_err=$(printf '%s' "$out" | jq -r '.requests.connectErrors')
        else
            ok=0; codes=""; conn_err=0
        fi

        [ "$ok" = "1" ] && break
        [ "$attempt" = "1" ] && sleep 3
    done

    if [ "$ok" = "1" ] && [ "${codes#1}" != "$codes" ]; then
        # A 1xx is an interim response: the real one follows it on the same
        # exchange (RFC 9110 Section 15.2), so recording one as the status
        # means we stopped reading too early. Servers that send a 103 Early
        # Hints are common enough that this is worth checking for by name -
        # it is how www.twitch.tv caught an HTTP/3 bug here.
        printf '%-4s %-38s %-9s %s\n' "$proto" "$url" "interim $codes" "$note"
        failures+=("$proto $url recorded an interim $codes as the status")
        fail=$((fail + 1))
    elif [ "$ok" = "1" ]; then
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
