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
    /// Custom headers in curl -H order (Host excluded; it becomes
    /// [`Target::authority`]). Names keep the user's casing, which HTTP/1.1
    /// sends as given; the HTTP/2 and HTTP/3 workers lower-case them
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
        let value = value.trim_start();
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

    /// The error text of a rejected target
    fn err_for(method: &str, header_args: &[&str]) -> String {
        let headers: Vec<String> = header_args.iter().map(|s| s.to_string()).collect();
        match parse_target("http://127.0.0.1:1/", method, &headers, None, false) {
            Ok(_) => panic!("expected a rejection"),
            Err(e) => e.to_string(),
        }
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
