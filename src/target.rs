use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result, bail};

pub struct Target {
    pub addr: SocketAddr,
    /// Whether the URL scheme is https
    pub tls: bool,
    /// Hostname without brackets or port; used as the TLS SNI name
    pub host: String,
    /// Effective authority: the URL host (with the port, when explicit), or
    /// the value of a `-H "Host: ..."` override, like curl. Used for the
    /// HTTP/1.1 Host header and the HTTP/2 and HTTP/3 :authority
    pub authority: String,
    /// Request path (with query); the HTTP/1.1 request target and the
    /// HTTP/2 and HTTP/3 :path pseudo-header
    pub path: String,
    /// HTTP method (validated as an RFC 9110 token by [`parse_target`])
    pub method: String,
    /// Custom headers in curl -H order. Host is excluded (it becomes
    /// [`Target::authority`]), and so are Content-Length and
    /// Transfer-Encoding: framing follows [`Target::body`], and the one
    /// `Content-Length` that cannot - the `0` of a request without a body -
    /// is a header here so that every protocol sends it. Names keep the
    /// user's casing, which HTTP/1.1 sends as given; the HTTP/2 and HTTP/3
    /// workers lower-case them
    pub headers: Vec<(String, String)>,
    /// Request body (empty = no body)
    pub body: Vec<u8>,
    /// Pre-encoded HTTP/1.1 request
    pub request_bytes: Vec<u8>,
    /// Close the connection after every response (HTTP/1.1 only). The request
    /// already carries `Connection: close`; the worker also drops the
    /// connection unconditionally, so a server that ignores the header cannot
    /// keep it alive
    pub disable_keepalive: bool,
}

/// Connection-specific headers are meaningless (and mostly forbidden) in
/// HTTP/2 and HTTP/3; filter them like curl does
pub fn is_connection_specific(name: &str) -> bool {
    [
        "connection",
        "keep-alive",
        "proxy-connection",
        "transfer-encoding",
        "upgrade",
    ]
    .iter()
    .any(|h| name.eq_ignore_ascii_case(h))
}

pub fn parse_target(
    url: &str,
    method: &str,
    header_args: &[String],
    body: Option<&[u8]>,
    disable_keepalive: bool,
) -> Result<Target> {
    let (tls, rest) = if let Some(rest) = url.strip_prefix("https://") {
        (true, rest)
    } else if let Some(rest) = url.strip_prefix("http://") {
        (false, rest)
    } else {
        bail!("only http:// and https:// URLs are supported");
    };
    // The fragment is the client's own business and never goes on the wire
    // (RFC 9110 Section 7.1)
    let rest = rest.split_once('#').map_or(rest, |(before, _)| before);
    let (authority, path) = match rest.find('/') {
        Some(i) => (&rest[..i], &rest[i..]),
        None => (rest, "/"),
    };
    if authority.is_empty() {
        bail!("missing host in URL");
    }
    let default_port: u16 = if tls { 443 } else { 80 };
    // The Host header uses the authority as-is (including an explicit port)
    let (host_for_lookup, port) = match authority.rsplit_once(':') {
        Some((h, p)) if !h.contains(']') || authority.starts_with('[') => {
            // An IPv6 literal only counts as having a port in the [::1]:8080 form
            if authority.starts_with('[') && !h.ends_with(']') {
                (authority, default_port)
            } else {
                (h, p.parse::<u16>().context("invalid port")?)
            }
        }
        _ => (authority, default_port),
    };
    let host_for_lookup = host_for_lookup
        .trim_start_matches('[')
        .trim_end_matches(']');

    let addr = (host_for_lookup, port)
        .to_socket_addrs()
        .with_context(|| format!("failed to resolve {authority}"))?
        .next()
        .context("no address resolved")?;

    // Parse curl-style "Name: Value" headers
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut host_override: Option<String> = None;
    for header in header_args {
        let (name, value) = header
            .split_once(':')
            .with_context(|| format!("invalid header (expected \"Name: Value\"): {header}"))?;
        let name = name.trim();
        // Whitespace around a value is not part of it (RFC 9110 Section
        // 5.5), and a trailing space that HTTP/1.1 would shrug off makes an
        // HTTP/2 or HTTP/3 field malformed (RFC 9113 Section 8.2.1)
        let value = value.trim();
        if name.is_empty() {
            bail!("invalid header (empty name): {header}");
        }
        // Like curl, -H "Host: ..." replaces the Host header / :authority
        if name.eq_ignore_ascii_case("host") {
            host_override = Some(value.to_string());
        } else {
            headers.push((name.to_string(), value.to_string()));
        }
    }
    // Like curl, -d defaults the content type unless one was given
    if body.is_some()
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("content-type"))
    {
        headers.push((
            "Content-Type".to_string(),
            "application/x-www-form-urlencoded".to_string(),
        ));
    }
    // Ask the server to close too, unless the user already spelled out their
    // own Connection header
    if disable_keepalive
        && !headers
            .iter()
            .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
    {
        headers.push(("Connection".to_string(), "close".to_string()));
    }
    let authority = host_override.unwrap_or_else(|| authority.to_string());
    let body: Vec<u8> = body.map(|b| b.to_vec()).unwrap_or_default();
    frame_body(method, &mut headers, &body)?;

    let request_bytes = encode_request(method, path, &authority, &headers, &body)?;

    Ok(Target {
        addr,
        tls,
        host: host_for_lookup.to_string(),
        authority,
        path: path.to_string(),
        method: method.to_string(),
        headers,
        body,
        request_bytes,
        disable_keepalive,
    })
}

/// Settle how the body is framed, which is shb's to decide rather than the
/// user's: every protocol derives Content-Length from the body itself, so a
/// copy given with -H went out alongside it, and the whole body is in memory
/// before the first request, so chunking has nothing to offer. A
/// Content-Length given by hand is checked against the body and then dropped
/// in favour of the derived one; one that disagrees would announce a body
/// other than the one sent, which RFC 9110 Section 8.6 rules out, and sending
/// it next to a Transfer-Encoding is what RFC 9112 Section 6.2 forbids. The
/// one Content-Length the body cannot stand for is the `0` of a request
/// without one, which a method that gives content a meaning sends
/// unprompted - a bare POST is one that some servers answer with 411 - and
/// which stays a header so that the HTTP/2 and HTTP/3 blocks, which add a
/// content-length only for a body with bytes, send it too.
fn frame_body(method: &str, headers: &mut Vec<(String, String)>, body: &[u8]) -> Result<()> {
    let mut content_length_given = false;
    for (name, value) in headers.iter() {
        if name.eq_ignore_ascii_case("transfer-encoding") {
            bail!("Transfer-Encoding is not supported: the body is sent with a Content-Length");
        }
        if name.eq_ignore_ascii_case("content-length") {
            let value = value.trim();
            if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
                bail!("invalid Content-Length: {value:?}");
            }
            let n: u64 = value.parse().context("Content-Length overflow")?;
            if n != body.len() as u64 {
                bail!(
                    "Content-Length {n} does not match the {} byte body given with -d",
                    body.len()
                );
            }
            content_length_given = true;
        }
    }
    headers.retain(|(name, _)| !name.eq_ignore_ascii_case("content-length"));
    if body.is_empty() && (content_length_given || defines_content(method)) {
        headers.push(("Content-Length".to_string(), "0".to_string()));
    }
    Ok(())
}

/// Methods that define a meaning for request content, which a user agent
/// should send a Content-Length with even when there is none (RFC 9110
/// Section 8.6; PATCH is RFC 5789)
fn defines_content(method: &str) -> bool {
    matches!(method, "POST" | "PUT" | "PATCH")
}

/// RFC 9110 Section 5.6.2 token characters
fn is_token(s: &str) -> bool {
    !s.is_empty()
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b"!#$%&'*+-.^_`|~".contains(&b))
}

/// RFC 9110 Section 5.5 field values: printable ASCII, space and tab
///
/// Rejecting CR and LF is what keeps a `-H` value from injecting a header of
/// its own into the request.
fn is_field_value(s: &str) -> bool {
    s.bytes()
        .all(|b| b == b'\t' || (0x20..=0x7e).contains(&b) || b >= 0x80)
}

/// Build the HTTP/1.1 request sent on every connection
///
/// Encoded once at start-up, so this validates its inputs rather than
/// trusting them: an unchecked method or field name would end up in the
/// HTTP/2 and HTTP/3 header blocks too, which have no framing to resynchronise
/// on.
fn encode_request(
    method: &str,
    path: &str,
    authority: &str,
    headers: &[(String, String)],
    body: &[u8],
) -> Result<Vec<u8>> {
    if !is_token(method) {
        bail!("invalid method: {method:?}");
    }
    if path.is_empty() || path.bytes().any(|b| b <= 0x20 || b == 0x7f) {
        bail!("invalid request target: {path:?}");
    }
    if !is_field_value(authority) {
        bail!("invalid Host header: {authority:?}");
    }

    let mut out = Vec::with_capacity(128 + body.len());
    out.extend_from_slice(method.as_bytes());
    out.push(b' ');
    out.extend_from_slice(path.as_bytes());
    out.extend_from_slice(b" HTTP/1.1\r\nHost: ");
    out.extend_from_slice(authority.as_bytes());
    out.extend_from_slice(b"\r\n");
    for (name, value) in headers {
        if !is_token(name) {
            bail!("invalid header name: {name:?}");
        }
        if !is_field_value(value) {
            bail!("invalid header value for {name:?}");
        }
        out.extend_from_slice(name.as_bytes());
        out.extend_from_slice(b": ");
        out.extend_from_slice(value.as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    if !body.is_empty() {
        out.extend_from_slice(b"Content-Length: ");
        out.extend_from_slice(body.len().to_string().as_bytes());
        out.extend_from_slice(b"\r\n");
    }
    out.extend_from_slice(b"\r\n");
    out.extend_from_slice(body);
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn req(args: &[&str], method: &str, body: Option<&[u8]>) -> String {
        let headers: Vec<String> = args.iter().map(|s| s.to_string()).collect();
        let target = parse_target(
            "http://127.0.0.1:8111/path?q=1",
            method,
            &headers,
            body,
            false,
        )
        .expect("parse");
        String::from_utf8(target.request_bytes).expect("utf8")
    }

    #[test]
    fn plain_get() {
        assert_eq!(
            req(&[], "GET", None),
            "GET /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:8111\r\n\r\n"
        );
    }

    #[test]
    fn post_with_body_gets_a_content_length() {
        assert_eq!(
            req(&[], "POST", Some(b"hello")),
            "POST /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:8111\r\n\
             Content-Type: application/x-www-form-urlencoded\r\n\
             Content-Length: 5\r\n\r\nhello"
        );
    }

    #[test]
    fn custom_headers_keep_their_order_and_casing() {
        assert_eq!(
            req(&["Accept: application/json", "X-A: 1"], "GET", None),
            "GET /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:8111\r\n\
             Accept: application/json\r\nX-A: 1\r\n\r\n"
        );
    }

    #[test]
    fn whitespace_around_a_header_value_is_dropped() {
        assert_eq!(
            req(&["X-A:  a b  ", "X-B:\tc\t"], "GET", None),
            "GET /path?q=1 HTTP/1.1\r\nHost: 127.0.0.1:8111\r\nX-A: a b\r\nX-B: c\r\n\r\n"
        );
    }

    /// The error text of a rejected URL
    fn err_for_url(url: &str) -> String {
        match parse_target(url, "GET", &[], None, false) {
            Ok(_) => panic!("{url} should have been rejected"),
            Err(e) => e.to_string(),
        }
    }

    /// The error text of a rejected target
    fn err_for(method: &str, header_args: &[&str]) -> String {
        let headers: Vec<String> = header_args.iter().map(|s| s.to_string()).collect();
        match parse_target("http://127.0.0.1:1/", method, &headers, None, false) {
            Ok(_) => panic!("expected a rejection"),
            Err(e) => e.to_string(),
        }
    }

    fn target(url: &str) -> Target {
        match parse_target(url, "GET", &[], None, false) {
            Ok(t) => t,
            Err(e) => panic!("{url}: {e}"),
        }
    }

    /// Only addresses that resolve without DNS, so the test does not depend on
    /// the network
    #[test]
    fn ports_come_from_the_url_or_the_scheme() {
        for (url, port) in [
            ("http://127.0.0.1/", 80u16),
            ("https://127.0.0.1/", 443),
            ("http://127.0.0.1:8080/", 8080),
            ("https://127.0.0.1:8080/", 8080),
        ] {
            assert_eq!(target(url).addr.port(), port, "{url}");
        }
    }

    /// A colon inside an IPv6 literal is not a port separator; only the
    /// `[::1]:8080` form has one
    #[test]
    fn ipv6_literals_keep_their_colons() {
        let t = target("http://[::1]/");
        assert_eq!(t.addr.port(), 80);
        assert_eq!(t.host, "::1", "the SNI name drops the brackets");
        assert_eq!(t.authority, "[::1]", "the Host header keeps them");

        let t = target("http://[::1]:8080/");
        assert_eq!(t.addr.port(), 8080);
        assert_eq!(t.host, "::1");
        assert_eq!(t.authority, "[::1]:8080");
    }

    #[test]
    fn the_path_defaults_to_root_and_keeps_its_query() {
        assert_eq!(target("http://127.0.0.1:8080").path, "/");
        assert_eq!(target("http://127.0.0.1:8080/").path, "/");
        assert_eq!(
            target("http://127.0.0.1:8080/a/b?c=1&d=2").path,
            "/a/b?c=1&d=2"
        );
    }

    #[test]
    fn a_fragment_is_not_sent() {
        assert_eq!(
            target("http://127.0.0.1:8080/index.html#top").path,
            "/index.html"
        );
        assert_eq!(target("http://127.0.0.1:8080/a?b=1#c").path, "/a?b=1");
        // Without a path the fragment would otherwise end up in the port
        let t = target("http://127.0.0.1:8080#top");
        assert_eq!(t.path, "/");
        assert_eq!(t.addr.port(), 8080);
    }

    #[test]
    fn the_scheme_decides_tls() {
        assert!(!target("http://127.0.0.1/").tls);
        assert!(target("https://127.0.0.1/").tls);
        let err = err_for_url("ftp://127.0.0.1/");
        assert!(err.contains("http"), "{err}");
    }

    /// Like curl, `-H "Host: ..."` changes what is sent, not where the
    /// connection goes
    #[test]
    fn a_host_override_does_not_move_the_connection() {
        let headers = vec!["Host: example.com".to_string()];
        let t =
            parse_target("http://127.0.0.1:8080/", "GET", &headers, None, false).expect("parse");
        assert_eq!(t.addr.to_string(), "127.0.0.1:8080");
        assert_eq!(t.authority, "example.com");
        assert!(
            String::from_utf8_lossy(&t.request_bytes).contains("Host: example.com\r\n"),
            "the override is what goes on the wire"
        );
        assert!(
            !t.headers
                .iter()
                .any(|(n, _)| n.eq_ignore_ascii_case("host")),
            "and it is not repeated as a normal header"
        );
    }

    #[test]
    fn a_bad_port_or_missing_host_is_rejected() {
        for url in [
            "http://127.0.0.1:70000/",
            "http://127.0.0.1:x/",
            "http:///path",
        ] {
            err_for_url(url);
        }
    }

    #[test]
    fn disable_keepalive_adds_connection_close_once() {
        let t = parse_target("http://127.0.0.1:8080/", "GET", &[], None, true).expect("parse");
        let req = String::from_utf8(t.request_bytes).unwrap();
        assert_eq!(req.matches("Connection: close").count(), 1);

        // A Connection header the caller wrote themselves is left alone
        let headers = vec!["Connection: keep-alive".to_string()];
        let t = parse_target("http://127.0.0.1:8080/", "GET", &headers, None, true).expect("parse");
        let req = String::from_utf8(t.request_bytes).unwrap();
        assert!(req.contains("Connection: keep-alive"), "{req:?}");
        assert!(!req.contains("Connection: close"), "{req:?}");
    }

    /// The error text of a rejected POST with a body
    fn err_for_body(header_args: &[&str], body: &[u8]) -> String {
        let headers: Vec<String> = header_args.iter().map(|s| s.to_string()).collect();
        match parse_target("http://127.0.0.1:1/", "POST", &headers, Some(body), false) {
            Ok(_) => panic!("expected a rejection"),
            Err(e) => e.to_string(),
        }
    }

    #[test]
    fn a_content_length_given_by_hand_is_sent_once() {
        let request = req(&["Content-Length: 5"], "POST", Some(b"hello"));
        assert_eq!(request.matches("Content-Length").count(), 1, "{request:?}");
        assert!(request.contains("Content-Length: 5\r\n"), "{request:?}");

        // Without a body it is kept, which a GET would not get on its own
        let request = req(&["content-length: 0"], "GET", None);
        assert_eq!(
            request.matches("Content-Length: 0\r\n").count(),
            1,
            "{request:?}"
        );
        assert!(!request.contains("content-length"), "{request:?}");
    }

    #[test]
    fn a_bodyless_post_says_so() {
        for method in ["POST", "PUT", "PATCH"] {
            let request = req(&[], method, None);
            assert!(
                request.ends_with("Content-Length: 0\r\n\r\n"),
                "{method}: {request:?}"
            );
            assert_eq!(request.matches("Content-Length").count(), 1, "{method}");
        }
        // Content means nothing to these, so they say nothing about it
        for method in ["GET", "DELETE", "OPTIONS"] {
            let request = req(&[], method, None);
            assert!(!request.contains("Content-Length"), "{method}: {request:?}");
        }
        // And it reaches HTTP/2 and HTTP/3 the way every header does
        let t = parse_target("http://127.0.0.1:1/", "PUT", &[], None, false).expect("parse");
        assert!(
            t.headers
                .iter()
                .any(|(name, value)| name == "Content-Length" && value == "0"),
            "{:?}",
            t.headers
        );
    }

    #[test]
    fn a_content_length_that_is_not_the_body_length_is_rejected() {
        let err = err_for_body(&["Content-Length: 2"], b"abc");
        assert!(err.contains("Content-Length 2"), "{err}");
        let err = err_for_body(&["Content-Length: three"], b"abc");
        assert!(err.contains("Content-Length"), "{err}");
        let err = err_for_body(&["Content-Length: 99999999999999999999999"], b"abc");
        assert!(err.contains("Content-Length"), "{err}");
    }

    #[test]
    fn transfer_encoding_is_rejected() {
        let err = err_for_body(&["Transfer-Encoding: chunked"], b"abc");
        assert!(err.contains("Transfer-Encoding"), "{err}");
    }

    /// HTTP/2 and HTTP/3 build their header blocks from `headers` and the
    /// body length, adding a content-length only for a body with bytes, so
    /// the header list must carry a Content-Length exactly when the body
    /// cannot stand for one
    #[test]
    fn framing_reaches_the_other_protocols_through_the_header_list() {
        let content_lengths = |t: &Target| {
            t.headers
                .iter()
                .filter(|(name, _)| name.eq_ignore_ascii_case("content-length"))
                .count()
        };
        let given = vec!["Content-Length: 3".to_string()];
        let t = parse_target("http://127.0.0.1:1/", "POST", &given, Some(b"abc"), false)
            .expect("parse");
        assert_eq!(content_lengths(&t), 0, "the body length stands for it");

        let given = vec!["Content-Length: 0".to_string()];
        let t = parse_target("http://127.0.0.1:1/", "POST", &given, None, false).expect("parse");
        assert_eq!(content_lengths(&t), 1, "nothing else would send it");
    }

    #[test]
    fn a_method_with_a_space_is_rejected() {
        let err = err_for("GE T", &[]);
        assert!(err.contains("method"), "{err}");
    }

    #[test]
    fn a_header_value_cannot_inject_a_newline() {
        let err = err_for("GET", &["X-A: 1\r\nX-Evil: 2"]);
        assert!(err.contains("value"), "{err}");
    }

    #[test]
    fn a_header_name_must_be_a_token() {
        let err = err_for("GET", &["X A: 1"]);
        assert!(err.contains("name"), "{err}");
    }
}
