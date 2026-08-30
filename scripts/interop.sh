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
# An endpoint earns its place here by covering an implementation nothing else
# here covers, or by having caught something. Twenty sites behind the same CDN
# exercise one HTTP stack twenty times; what finds bugs is a different stack,
# so the list is chosen by implementation rather than by name recognition, and
# a server that merely passed goes in KNOWN_GOOD below rather than into the
# run. Probing new servers is cheap and worth doing often - promoting one is
# worth doing when it fails, or when it is something new.
#
# HTTP/3 is where that shows most: quicly, ngtcp2, picoquic, aioquic, quic-go,
# quiche, msquic, mvfst, lsquic, nginx, HAProxy, Caddy and Google's QUICHE are
# thirteen separate QUIC implementations, several run by the people who wrote
# the specification.
#
#   scripts/interop.sh              # every endpoint
#   scripts/interop.sh h3           # only HTTP/3
#   EXTRA=1 scripts/interop.sh      # and the known-good list as well
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

# protocol | url | what is known to be serving it | extra shb arguments
#
# The fourth field is optional. It exists because some response shapes cannot
# be reached with a plain GET - HTTP/2 trailers, for one.
ENDPOINTS=$(cat <<'EOF'
h1|http://example.com/|ICANN, cleartext
h1|https://example.com/|ICANN
h1|http://nginx.org/|nginx, cleartext
h1|https://nginx.org/|nginx
h1|https://h2o.examp1e.net/|H2O
h1|https://nghttp2.org/|nghttp2
h1|https://www.apache.org/|Apache httpd
h1|https://www.wikipedia.org/|Apache Traffic Server
h1|https://caddyserver.com/|Caddy
h1|https://www.haproxy.org/|HAProxy
h1|https://www.eclipse.org/|Jetty
h1|https://pgjones.dev/|Hypercorn
h1|https://interop.seemann.io/|quic-go
h1|https://facebook.com/|Meta Proxygen
h1|https://www.google.com/|Google
h1|https://www.cloudflare.com/|Cloudflare
h1|https://www.fastly.com/|Fastly
h1|https://www.akamai.com/|Akamai
h1|https://aws.amazon.com/|CloudFront
h1|https://github.com/|GitHub
h1|https://www.bing.com/|Microsoft
h1|https://www.twitch.tv/|Twitch
h1|https://vercel.com/|Vercel
h1|https://prometheus.io/|Netlify
h1|https://gcore.com/|Gcore
h1|https://www.taobao.com/|Tengine, Alibaba's fork of nginx
h1|https://openresty.org/|OpenResty Edge
h1|https://www.kernel.org/|kernel.org
h1|https://www.debian.org/|Debian
h1|https://www.sakura.ad.jp/|an origin whose ALPN offers only http/1.1
h1|https://www.baidu.com/|Baidu, another http/1.1-only origin
h1|https://s3.amazonaws.com/|AWS S3, another http/1.1-only origin
h1|https://www.jst.go.jp/|an origin that offers no ALPN at all
h2|https://nghttp2.org/|nghttp2, the reference implementation
h2|https://h2o.examp1e.net/|H2O
h2|https://www.apache.org/|Apache httpd, mod_http2
h2|https://www.wikipedia.org/|Apache Traffic Server
h2|https://caddyserver.com/|Caddy
h2|https://www.haproxy.com/|HAProxy
h2|https://www.eclipse.org/|Jetty
h2|https://pgjones.dev/|Hypercorn
h2|https://interop.seemann.io/|quic-go
h2|https://facebook.com/|Meta Proxygen
h2|https://www.google.com/|Google
h2|https://www.cloudflare.com/|Cloudflare
h2|https://www.fastly.com/|Fastly
h2|https://www.adobe.com/|Akamai
h2|https://aws.amazon.com/|CloudFront
h2|https://github.com/|GitHub
h2|https://gitlab.com/|GitLab
h2|https://www.bing.com/|Microsoft
h2|https://www.twitch.tv/|Twitch, which should agree with the HTTP/3 result
h2|https://vercel.com/|Vercel
h2|https://prometheus.io/|Netlify
h2|https://gcore.com/|Gcore
h2|https://www.taobao.com/|Tengine, Alibaba's fork of nginx
h2|https://openresty.org/|OpenResty Edge
h1|https://httpbin.org/post|a real 100 Continue, which no plain GET produces|-m POST -H 'expect: 100-continue' -d aaaa
h2|https://httpbin.org/post|the same 100 Continue over HTTP/2|-m POST -H 'expect: 100-continue' -d aaaa
h2|https://grpcb.in/hello.HelloService/SayHello|gRPC: the one server here that sends HTTP/2 trailers, which v0.2.3 could not read|-m POST -H 'content-type: application/grpc' -H 'te: trailers' -d x
h3|https://cloudflare-quic.com/|Cloudflare quiche, an HTTP/3 test endpoint
h3|https://quic.nginx.org/|nginx QUIC, an HTTP/3 test endpoint
h3|https://h2o.examp1e.net/|quicly, H2O's own QUIC
h3|https://nghttp2.org:4433/|ngtcp2, the reference implementation
h3|https://test.privateoctopus.com:4433/|picoquic
h3|https://quic.aiortc.org/|aioquic
h3|https://pgjones.dev/|aioquic, via Hypercorn
h3|https://interop.seemann.io/|quic-go
h3|https://caddyserver.com/|Caddy, quic-go
h3|https://www.haproxy.com/|HAProxy's own QUIC
h3|https://www.google.com/|Google QUICHE
h3|https://facebook.com/|Meta mvfst, which caught a wrong Huffman table entry
h3|https://www.bing.com/|Microsoft msquic, which caught a connection teardown
h3|https://litespeedtech.com/|LiteSpeed lsquic, the one thing the OpenLiteSpeed container cannot serve
h3|https://www.cloudflare.com/|Cloudflare
h3|https://www.fastly.com/|Fastly
h3|https://www.adobe.com/|Akamai
h3|https://prometheus.io/|Netlify
h3|https://gcore.com/|Gcore
h3|https://www.taobao.com/|XQUIC, Alibaba's own QUIC
h3|https://openresty.org/|OpenResty Edge
h3|https://www.twitch.tv/|Twitch, which answers with a 103 Early Hints first
EOF
)

# Checked once, worked, and kept for reference rather than run
#
# The list above is what gets exercised. These do not, because a passing
# endpoint that has never failed costs runtime without adding coverage - what
# earns a place in the list above is having caught something. They are worth
# keeping written down: each line records a server we have confirmed shb can
# talk to, so a future report of "shb does not work with X" has somewhere to
# start, and any of them can be promoted into the list above the day it fails.
#
# Most of these are sites that sit behind a CDN already represented above, so
# running them would re-test the same HTTP stack under a different hostname.
#
# Run them with EXTRA=1. Protocols a host does not offer are simply absent:
# every omission here was checked with `openssl s_client -alpn h2,http/1.1`
# for HTTP/2 and for an Alt-Svc advertisement for HTTP/3, and was the server's
# doing rather than ours.
KNOWN_GOOD=$(cat <<'EOF'
h1|https://grpcb.in/|gRPC test server
h2|https://grpcb.in/|gRPC test server
h1|https://grpc.io/|gRPC
h2|https://grpc.io/|gRPC
h3|https://grpc.io/|gRPC
h1|https://www.tmall.com/|Tmall, Tengine
h2|https://www.tmall.com/|Tmall, Tengine
h3|https://www.tmall.com/|Tmall, Tengine
h1|https://www.iis.net/|Microsoft IIS
h2|https://www.iis.net/|Microsoft IIS
h1|https://www.jetbrains.com/|JetBrains
h2|https://www.jetbrains.com/|JetBrains
h3|https://www.jetbrains.com/|JetBrains
h1|https://www.redhat.com/|Red Hat, Akamai
h2|https://www.redhat.com/|Red Hat, Akamai
h1|https://quic.tech:8443/|Cloudflare quiche
h2|https://quic.tech:8443/|Cloudflare quiche
h3|https://quic.tech:8443/|Cloudflare quiche
h1|https://www.haproxy.com/|HAProxy
h1|https://www.jenkins.io/|Jenkins, Jetty
h2|https://www.jenkins.io/|Jenkins, Jetty
h1|https://learn.microsoft.com/|Microsoft
h2|https://learn.microsoft.com/|Microsoft
h1|https://azure.microsoft.com/|Azure, HTTP/1.1-only origin
h1|https://www.amazon.com/|Amazon
h2|https://www.amazon.com/|Amazon
h3|https://www.amazon.com/|Amazon
h1|https://www.ebay.com/|eBay
h2|https://www.ebay.com/|eBay
h3|https://www.ebay.com/|eBay
h1|https://www.walmart.com/|Walmart
h2|https://www.walmart.com/|Walmart
h1|https://www.target.com/|Target
h2|https://www.target.com/|Target
h3|https://www.target.com/|Target
h1|https://www.booking.com/|Booking.com
h2|https://www.booking.com/|Booking.com
h1|https://www.airbnb.com/|Airbnb
h2|https://www.airbnb.com/|Airbnb
h3|https://www.airbnb.com/|Airbnb
h1|https://www.expedia.com/|Expedia
h2|https://www.expedia.com/|Expedia
h1|https://www.tumblr.com/|Tumblr
h2|https://www.tumblr.com/|Tumblr
h3|https://www.tumblr.com/|Tumblr
h1|https://medium.com/|Medium
h2|https://medium.com/|Medium
h3|https://medium.com/|Medium
h1|https://substack.com/|Substack
h2|https://substack.com/|Substack
h3|https://substack.com/|Substack
h1|https://www.notion.so/|Notion
h2|https://www.notion.so/|Notion
h1|https://slack.com/|Slack
h2|https://slack.com/|Slack
h3|https://slack.com/|Slack
h1|https://zoom.us/|Zoom
h2|https://zoom.us/|Zoom
h1|https://www.dropbox.com/|Dropbox
h2|https://www.dropbox.com/|Dropbox
h3|https://www.dropbox.com/|Dropbox
h1|https://www.box.com/|Box
h2|https://www.box.com/|Box
h3|https://www.box.com/|Box
h1|https://www.asahi.com/|Asahi Shimbun
h2|https://www.asahi.com/|Asahi Shimbun
h1|https://www.nikkei.com/|Nikkei
h2|https://www.nikkei.com/|Nikkei
h3|https://www.nikkei.com/|Nikkei
h1|https://www3.nhk.or.jp/|NHK
h2|https://www3.nhk.or.jp/|NHK
h1|https://www.itmedia.co.jp/|ITmedia
h2|https://www.itmedia.co.jp/|ITmedia
h1|https://www.pixiv.net/|pixiv
h2|https://www.pixiv.net/|pixiv
h3|https://www.pixiv.net/|pixiv
h1|https://www.nicovideo.jp/|niconico
h2|https://www.nicovideo.jp/|niconico
h1|https://www.jreast.co.jp/|JR East
h2|https://www.jreast.co.jp/|JR East
h1|https://www.jal.co.jp/|Japan Airlines
h2|https://www.jal.co.jp/|Japan Airlines
h1|https://www.bbc.co.uk/|BBC
h2|https://www.bbc.co.uk/|BBC
h3|https://www.bbc.co.uk/|BBC
h1|https://www.reuters.com/|Reuters
h2|https://www.reuters.com/|Reuters
h1|https://apnews.com/|AP
h2|https://apnews.com/|AP
h3|https://apnews.com/|AP
h1|https://www.lemonde.fr/|Le Monde
h2|https://www.lemonde.fr/|Le Monde
h1|https://www.spiegel.de/|Der Spiegel
h2|https://www.spiegel.de/|Der Spiegel
h1|https://www.corriere.it/|Corriere della Sera
h2|https://www.corriere.it/|Corriere della Sera
h1|https://www.globo.com/|Globo, HTTP/1.1-only origin
h1|https://www.abc.net.au/|ABC Australia
h2|https://www.abc.net.au/|ABC Australia
h1|https://litespeedtech.com/|LiteSpeed; its HTTP/1.1 and h2 run in the container suite instead
h2|https://litespeedtech.com/|LiteSpeed, whose HPACK decoder caught a bug here
h1|https://www.qq.com/|Tencent, HTTP/1.1-only origin
h1|https://www.yandex.ru/|Yandex
h2|https://www.yandex.ru/|Yandex
h3|https://www.yandex.ru/|Yandex
h1|https://ya.ru/|Yandex
h2|https://ya.ru/|Yandex
h3|https://ya.ru/|Yandex
h1|https://www.naver.com/|Naver
h2|https://www.naver.com/|Naver
h1|https://www.aliexpress.com/|Alibaba
h2|https://www.aliexpress.com/|Alibaba
h3|https://www.aliexpress.com/|Alibaba
h1|https://weibo.com/|Weibo
h2|https://weibo.com/|Weibo
h1|https://vk.com/|VK
h2|https://vk.com/|VK
h1|https://mail.ru/|Mail.ru
h2|https://mail.ru/|Mail.ru
h1|https://www.shopify.com/|Shopify
h2|https://www.shopify.com/|Shopify
h3|https://www.shopify.com/|Shopify
h1|https://www.squarespace.com/|Squarespace
h2|https://www.squarespace.com/|Squarespace
h1|https://storage.googleapis.com/|Google Cloud Storage
h2|https://storage.googleapis.com/|Google Cloud Storage
h3|https://storage.googleapis.com/|Google Cloud Storage
h1|https://www.gstatic.com/|Google
h2|https://www.gstatic.com/|Google
h3|https://www.gstatic.com/|Google
h1|https://cdn.jsdelivr.net/|jsDelivr
h2|https://cdn.jsdelivr.net/|jsDelivr
h3|https://cdn.jsdelivr.net/|jsDelivr
h1|https://cdnjs.cloudflare.com/|Cloudflare
h2|https://cdnjs.cloudflare.com/|Cloudflare
h3|https://cdnjs.cloudflare.com/|Cloudflare
h1|https://unpkg.com/|unpkg
h2|https://unpkg.com/|unpkg
h3|https://unpkg.com/|unpkg
h1|https://bunny.net/|Bunny
h2|https://bunny.net/|Bunny
h1|https://deno.dev/|Deno Deploy
h2|https://deno.dev/|Deno Deploy
h1|https://fly.io/|Fly.io, HTTP/1.1-only origin
h1|https://www.godaddy.com/|GoDaddy
h2|https://www.godaddy.com/|GoDaddy
h1|https://api.github.com/|GitHub API
h2|https://api.github.com/|GitHub API
h1|https://postman-echo.com/|Postman Echo
h2|https://postman-echo.com/|Postman Echo
h1|https://www.ietf.org/|IETF
h2|https://www.ietf.org/|IETF
h3|https://www.ietf.org/|IETF
h1|https://datatracker.ietf.org/|IETF
h2|https://datatracker.ietf.org/|IETF
h3|https://datatracker.ietf.org/|IETF
h1|https://www.rfc-editor.org/|RFC Editor
h2|https://www.rfc-editor.org/|RFC Editor
h3|https://www.rfc-editor.org/|RFC Editor
h1|https://www.w3.org/|W3C
h2|https://www.w3.org/|W3C
h3|https://www.w3.org/|W3C
h1|https://www.iana.org/|IANA
h2|https://www.iana.org/|IANA
h1|https://www.gov.uk/|UK Government
h2|https://www.gov.uk/|UK Government
h3|https://www.gov.uk/|UK Government
h1|https://www.lighttpd.net/|lighttpd, HTTP/1.1-only origin
h1|https://nginx.com/|F5 NGINX
h2|https://nginx.com/|F5 NGINX
h1|https://www.f5.com/|F5
h2|https://www.f5.com/|F5
h1|https://www.mit.edu/|MIT, HTTP/1.1-only origin
h1|https://www.stanford.edu/|Stanford
h2|https://www.stanford.edu/|Stanford
h1|https://www.u-tokyo.ac.jp/|University of Tokyo, offers no ALPN
h1|https://www.kyoto-u.ac.jp/|Kyoto University
h2|https://www.kyoto-u.ac.jp/|Kyoto University
h1|https://www.soumu.go.jp/|MIC Japan, HTTP/1.1-only origin
h1|https://europa.eu/|European Union, offers no ALPN
h1|https://en.wikipedia.org/|Wikimedia ATS
h2|https://en.wikipedia.org/|Wikimedia ATS
h1|https://commons.wikimedia.org/|Wikimedia ATS
h2|https://commons.wikimedia.org/|Wikimedia ATS
h1|https://www.mediawiki.org/|Wikimedia ATS
h2|https://www.mediawiki.org/|Wikimedia ATS
h1|https://about.gitlab.com/|GitLab
h2|https://about.gitlab.com/|GitLab
h3|https://about.gitlab.com/|GitLab
h1|https://crates.io/|crates.io
h1|https://docs.rs/|docs.rs
h1|https://www.rust-lang.org/|Rust
h1|https://www.apple.com/|Apple
h1|https://www.microsoft.com/|Microsoft
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
h1|https://curl.se/|curl
h1|https://www.nytimes.com/|The New York Times
h1|https://www.theguardian.com/|The Guardian
h1|https://archive.org/|Internet Archive
h1|https://letsencrypt.org/|Let's Encrypt
h1|https://www.eff.org/|EFF
h1|https://kubernetes.io/|Kubernetes
h1|https://www.docker.com/|Docker
h1|https://hub.docker.com/|Docker Hub
h1|https://archlinux.org/|Arch Linux
h1|https://ubuntu.com/|Canonical
h1|https://www.postgresql.org/|PostgreSQL
h1|https://www.openssl.org/|OpenSSL
h1|https://www.netlify.com/|Netlify
h1|https://bitbucket.org/|Bitbucket
h1|https://www.atlassian.com/|Atlassian
h1|https://registry.npmjs.org/|npm registry
h1|https://www.linode.com/|Linode
h1|https://www.yahoo.co.jp/|Yahoo! JAPAN
h1|https://www.rakuten.co.jp/|Rakuten
h1|https://qiita.com/|Qiita
h1|https://zenn.dev/|Zenn
h1|https://www.ntt.com/|NTT
h1|https://www.freebsd.org/|FreeBSD, an origin that offers no ALPN but http/1.1
h1|https://www.iij.ad.jp/|IIJ, HTTP/1.1-only origin
h1|https://www.nic.ad.jp/|JPNIC, HTTP/1.1-only origin
h2|https://www.rust-lang.org/|Rust
h2|https://crates.io/|crates.io
h2|https://docs.rs/|docs.rs
h2|https://www.apple.com/|Apple
h2|https://stackoverflow.com/|Stack Overflow
h2|https://www.debian.org/|Debian
h2|https://www.microsoft.com/|Microsoft
h2|https://www.linkedin.com/|LinkedIn
h2|https://www.oracle.com/|Oracle
h2|https://www.paypal.com/|PayPal
h2|https://www.netflix.com/|Netflix
h2|https://www.spotify.com/|Spotify
h2|https://www.python.org/|Python
h2|https://pypi.org/|PyPI
h2|https://www.mozilla.org/|Mozilla
h2|https://developer.mozilla.org/|MDN
h2|https://go.dev/|Go
h2|https://curl.se/|curl
h2|https://www.nytimes.com/|The New York Times
h2|https://www.theguardian.com/|The Guardian
h2|https://archive.org/|Internet Archive
h2|https://letsencrypt.org/|Let's Encrypt
h2|https://www.eff.org/|EFF
h2|https://kubernetes.io/|Kubernetes
h2|https://www.docker.com/|Docker
h2|https://hub.docker.com/|Docker Hub
h2|https://archlinux.org/|Arch Linux
h2|https://ubuntu.com/|Canonical
h2|https://www.postgresql.org/|PostgreSQL
h2|https://www.openssl.org/|OpenSSL
h2|https://www.kernel.org/|kernel.org
h2|https://www.netlify.com/|Netlify
h2|https://bitbucket.org/|Bitbucket
h2|https://www.atlassian.com/|Atlassian
h2|https://registry.npmjs.org/|npm registry
h2|https://www.yahoo.co.jp/|Yahoo! JAPAN
h2|https://www.rakuten.co.jp/|Rakuten
h2|https://qiita.com/|Qiita
h2|https://zenn.dev/|Zenn
h2|https://www.ntt.com/|NTT
h3|https://www.youtube.com/|Google
h3|https://blog.cloudflare.com/|Cloudflare
h3|https://www.instagram.com/|Meta mvfst
h3|https://discord.com/|Cloudflare
h3|https://www.reddit.com/|Fastly
h3|https://www.linkedin.com/|LinkedIn
h3|https://www.linode.com/|Akamai
h3|https://www.spotify.com/|Fastly
h3|https://www.python.org/|Fastly
h3|https://pypi.org/|Fastly
h3|https://www.theguardian.com/|Fastly
h3|https://www.mozilla.org/|Mozilla
h3|https://developer.mozilla.org/|MDN
h3|https://curl.se/|curl
h3|https://www.openssl.org/|OpenSSL
h3|https://www.kernel.org/|kernel.org
h3|https://www.atlassian.com/|Atlassian
EOF
)

if [ -n "${EXTRA:-}" ]; then
    ENDPOINTS="$ENDPOINTS
$KNOWN_GOOD"
fi

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

while IFS='|' read -r proto url note extra; do
    [ -z "$proto" ] && continue
    extra_args=()
    [ -n "${extra:-}" ] && eval "extra_args=($extra)"
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
            -c 1 -t 1 -n 1 --connect-timeout 10s \
            ${extra_args[@]+"${extra_args[@]}"} -j "$url" 2>"$err")

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
