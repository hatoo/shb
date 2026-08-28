use std::net::{SocketAddr, TcpStream};
use std::os::fd::{FromRawFd, IntoRawFd, RawFd};
use std::time::Instant;

use anyhow::{Context, Result, bail};
use shiguredo_http11::{BodyKind, BodyProgress, HttpHead, ResponseDecoder};

/// Create an unconnected TCP socket with TCP_NODELAY set
pub fn make_socket(addr: &SocketAddr) -> Result<RawFd> {
    let socket = socket2::Socket::new(
        socket2::Domain::for_address(*addr),
        socket2::Type::STREAM,
        None,
    )
    .context("socket() failed")?;
    socket
        .set_tcp_nodelay(true)
        .context("setsockopt(TCP_NODELAY) failed")?;
    Ok(socket.into_raw_fd())
}

/// Progress of receiving a response
pub enum ParseOutcome {
    /// One response completed; keep_alive is true if the connection can be reused
    Complete { keep_alive: bool },
    /// Not enough data; keep receiving
    NeedMoreData,
}

/// Metadata of the current response, extracted from the decoded headers
///
/// The ResponseHead is consumed by decode_headers, so keep only the values
/// needed until the response completes.
pub struct ResponseMeta {
    pub body_kind: BodyKind,
    pub keep_alive: bool,
    /// Status code (tallied on completion)
    pub status_code: u16,
}

pub struct Conn {
    pub fd: RawFd,
    /// Whether the TCP connection is established (true after a successful Connect CQE)
    pub connected: bool,
    pub decoder: ResponseDecoder,
    /// Resume position for partial sends
    pub send_offset: usize,
    /// Whether a multishot recv is active (cleared by a CQE without the MORE flag)
    pub recv_armed: bool,
    /// Reconnect generation. Incremented on every close; CQEs from an old
    /// generation (e.g. a cancelled multishot recv) are identified via
    /// user_data and ignored
    pub generation: u64,
    /// Metadata of the current response (None = headers not decoded yet)
    pub resp: Option<ResponseMeta>,
    pub request_start: Instant,
}

impl Conn {
    pub fn new() -> Self {
        Conn {
            fd: -1,
            connected: false,
            decoder: ResponseDecoder::new(),
            send_offset: 0,
            recv_armed: false,
            generation: 0,
            resp: None,
            request_start: Instant::now(),
        }
    }

    pub fn close(&mut self) {
        if self.fd >= 0 {
            // Close by turning the fd back into a TcpStream and dropping it
            drop(unsafe { TcpStream::from_raw_fd(self.fd) });
            self.fd = -1;
        }
        self.connected = false;
        self.recv_armed = false;
        // Bump the generation so CQEs of operations on the old connection are ignored
        self.generation += 1;
    }

    /// Advance the decoder state machine after feeding received data
    pub fn parse(&mut self) -> Result<ParseOutcome> {
        let meta = match &self.resp {
            Some(meta) => meta,
            None => match self
                .decoder
                .decode_headers()
                .map_err(|e| anyhow::anyhow!("decode error: {e:?}"))?
            {
                None => return Ok(ParseOutcome::NeedMoreData),
                Some((head, body_kind)) => &*self.resp.insert(ResponseMeta {
                    body_kind,
                    // A close-delimited body ends with the connection closing,
                    // so keep-alive is impossible regardless of the Connection header
                    keep_alive: head.is_keep_alive()
                        && !matches!(body_kind, BodyKind::CloseDelimited),
                    status_code: head.status_code(),
                }),
            },
        };

        match meta.body_kind {
            BodyKind::None => Ok(ParseOutcome::Complete {
                keep_alive: meta.keep_alive,
            }),
            BodyKind::Tunnel => bail!("unexpected tunnel response"),
            _ => {
                let keep_alive = meta.keep_alive;
                loop {
                    let progress = if let Some(body) = self.decoder.peek_body() {
                        let len = body.len();
                        self.decoder
                            .consume_body(len)
                            .map_err(|e| anyhow::anyhow!("body decode error: {e:?}"))?
                    } else {
                        self.decoder
                            .progress()
                            .map_err(|e| anyhow::anyhow!("body decode error: {e:?}"))?
                    };
                    match progress {
                        BodyProgress::Complete { .. } => {
                            return Ok(ParseOutcome::Complete { keep_alive });
                        }
                        BodyProgress::Advanced => continue,
                        BodyProgress::NeedData => return Ok(ParseOutcome::NeedMoreData),
                    }
                }
            }
        }
    }

    /// Reset per-request state for the next request
    pub fn begin_request(&mut self) {
        self.send_offset = 0;
        self.resp = None;
        self.request_start = Instant::now();
    }
}
