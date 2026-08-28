use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result, bail};
use shiguredo_http11::{HeaderName, Method, Request};

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
    /// Request path (with query); used for the HTTP/2 :path pseudo-header
    pub path: String,
    /// HTTP method (validated as an RFC 9110 token by [`parse_target`])
    pub method: String,
    /// Custom headers in curl -H order (Host excluded; it becomes
    /// [`Target::authority`]). Names keep the user's casing; the HTTP/2 and
    /// HTTP/3 workers lowercase them
    pub headers: Vec<(String, String)>,
    /// Request body (empty = no body)
    pub body: Vec<u8>,
    /// Pre-encoded HTTP/1.1 request
    pub request_bytes: Vec<u8>,
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
    let authority = host_override.unwrap_or_else(|| authority.to_string());
    let body: Vec<u8> = body.map(|b| b.to_vec()).unwrap_or_default();

    // Validates the method as an RFC 9110 token; the HTTP/2 and HTTP/3
    // workers rely on this when building their :method pseudo-headers
    let parsed_method =
        Method::new(method).map_err(|e| anyhow::anyhow!("invalid method: {e:?}"))?;
    let mut request = Request::new(parsed_method, path)
        .map_err(|e| anyhow::anyhow!("invalid request target: {e:?}"))?
        .header("Host", authority.as_str())
        .map_err(|e| anyhow::anyhow!("invalid Host header: {e:?}"))?;
    for (name, value) in &headers {
        let header_name = HeaderName::new(name)
            .map_err(|e| anyhow::anyhow!("invalid header name {name:?}: {e:?}"))?;
        request
            .add_header(header_name, value.as_str())
            .map_err(|e| anyhow::anyhow!("invalid header {name:?}: {e:?}"))?;
    }
    if !body.is_empty() {
        request.set_body(body.clone());
    }
    let request_bytes = request
        .encode()
        .map_err(|e| anyhow::anyhow!("failed to encode request: {e:?}"))?;

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
    })
}
