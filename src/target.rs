use std::net::{SocketAddr, ToSocketAddrs};

use anyhow::{Context, Result, bail};
use shiguredo_http11::{Method, Request};

pub struct Target {
    pub addr: SocketAddr,
    /// Whether the URL scheme is https
    pub tls: bool,
    /// Hostname without brackets or port; used as the TLS SNI name
    pub host: String,
    /// Host part of the URL (with the port, when explicit); used for the
    /// HTTP/1.1 Host header and the HTTP/2 :authority pseudo-header
    pub authority: String,
    /// Request path (with query); used for the HTTP/2 :path pseudo-header
    pub path: String,
    /// HTTP method (validated as an RFC 9110 token by [`parse_target`])
    pub method: String,
    /// Pre-encoded HTTP/1.1 request
    pub request_bytes: Vec<u8>,
}

pub fn parse_target(url: &str, method: &str) -> Result<Target> {
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

    // Validates the method as an RFC 9110 token; the HTTP/2 and HTTP/3
    // workers rely on this when building their :method pseudo-headers
    let parsed_method =
        Method::new(method).map_err(|e| anyhow::anyhow!("invalid method: {e:?}"))?;
    let request = Request::new(parsed_method, path)
        .map_err(|e| anyhow::anyhow!("invalid request target: {e:?}"))?
        .header("Host", authority)
        .map_err(|e| anyhow::anyhow!("invalid Host header: {e:?}"))?;
    let request_bytes = request
        .encode()
        .map_err(|e| anyhow::anyhow!("failed to encode request: {e:?}"))?;

    Ok(Target {
        addr,
        tls,
        host: host_for_lookup.to_string(),
        authority: authority.to_string(),
        path: path.to_string(),
        method: method.to_string(),
        request_bytes,
    })
}
