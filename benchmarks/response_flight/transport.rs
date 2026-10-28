//! Server-only h3 adapter. Unidirectional streams use h3-quinn unchanged.
//! A response's finish waits for Quinn's authenticated receipt notification.
//! This does not assert that the remote HTTP application consumed the bytes.
use bytes::{Buf, Bytes};
use h3::quic::{self, ConnectionErrorIncoming, StreamErrorIncoming, StreamId, WriteBuf};
use std::{
    future::Future,
    pin::Pin,
    sync::{Arc, atomic::Ordering},
    task::{Context, Poll, ready},
};

use super::Ledger;

type Incoming = Pin<
    Box<
        dyn Future<Output = Result<(quinn::SendStream, quinn::RecvStream), quinn::ConnectionError>>
            + Send,
    >,
>;
type Receipt =
    Pin<Box<dyn Future<Output = Result<Option<quinn::VarInt>, quinn::StoppedError>> + Send + Sync>>;

pub struct Connection {
    raw: quinn::Connection,
    inner: h3_quinn::Connection,
    incoming: Option<Incoming>,
    ledger: Arc<Ledger>,
}

impl Connection {
    pub fn new(raw: quinn::Connection, ledger: Arc<Ledger>) -> Self {
        Self {
            inner: h3_quinn::Connection::new(raw.clone()),
            raw,
            incoming: None,
            ledger,
        }
    }
}

impl quic::Connection<Bytes> for Connection {
    type RecvStream = h3_quinn::RecvStream;
    type OpenStreams = Self;

    fn poll_accept_recv(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Self::RecvStream, ConnectionErrorIncoming>> {
        <h3_quinn::Connection as quic::Connection<Bytes>>::poll_accept_recv(&mut self.inner, cx)
    }

    fn poll_accept_bidi(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Bidi, ConnectionErrorIncoming>> {
        let raw = self.raw.clone();
        let future = self
            .incoming
            .get_or_insert_with(|| Box::pin(async move { raw.accept_bi().await }));
        let result = ready!(future.as_mut().poll(cx));
        self.incoming = None;
        let (stream, recv) = result.map_err(|e| ConnectionErrorIncoming::Undefined(Arc::new(e)))?;
        let receipt = Box::pin(stream.stopped());
        Poll::Ready(Ok(Bidi {
            recv,
            send: ResponseSend::Response {
                stream,
                receipt,
                writing: None,
                finished: false,
                ledger: self.ledger.clone(),
            },
        }))
    }

    fn opener(&self) -> Self {
        Self::new(self.raw.clone(), self.ledger.clone())
    }
}

impl quic::OpenStreams<Bytes> for Connection {
    type SendStream = ResponseSend;
    type BidiStream = Bidi;

    fn poll_open_send(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<ResponseSend, StreamErrorIncoming>> {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::poll_open_send(&mut self.inner, cx)
            .map_ok(ResponseSend::Uni)
    }

    fn poll_open_bidi(&mut self, _: &mut Context<'_>) -> Poll<Result<Bidi, StreamErrorIncoming>> {
        Poll::Ready(Err(StreamErrorIncoming::Unknown(
            "server cannot initiate a request".into(),
        )))
    }

    fn close(&mut self, code: h3::error::Code, reason: &[u8]) {
        <h3_quinn::Connection as quic::OpenStreams<Bytes>>::close(&mut self.inner, code, reason);
    }
}

pub enum ResponseSend {
    Uni(h3_quinn::SendStream<Bytes>),
    Response {
        stream: quinn::SendStream,
        receipt: Receipt,
        writing: Option<WriteBuf<Bytes>>,
        finished: bool,
        ledger: Arc<Ledger>,
    },
}

fn unknown(e: impl std::error::Error + Send + Sync + 'static) -> StreamErrorIncoming {
    StreamErrorIncoming::Unknown(Box::new(e))
}

impl quic::SendStream<Bytes> for ResponseSend {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        match self {
            Self::Uni(s) => s.poll_ready(cx),
            Self::Response {
                stream, writing, ..
            } => {
                if let Some(data) = writing {
                    while data.has_remaining() {
                        let written = ready!(Pin::new(&mut *stream).poll_write(cx, data.chunk()))
                            .map_err(unknown)?;
                        data.advance(written);
                    }
                }
                *writing = None;
                Poll::Ready(Ok(()))
            }
        }
    }

    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        match self {
            Self::Uni(s) => s.send_data(data),
            Self::Response { writing, .. } => {
                if writing.is_some() {
                    return Err(StreamErrorIncoming::Unknown(
                        "unflushed response data".into(),
                    ));
                }
                *writing = Some(data.into());
                Ok(())
            }
        }
    }

    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        ready!(self.poll_ready(cx))?;
        match self {
            Self::Uni(s) => s.poll_finish(cx),
            Self::Response {
                stream,
                receipt,
                finished,
                ledger,
                ..
            } => {
                if !*finished {
                    stream.finish().map_err(unknown)?;
                    *finished = true;
                    ledger.finished.fetch_add(1, Ordering::Relaxed);
                }
                match ready!(receipt.as_mut().poll(cx)).map_err(unknown)? {
                    None => Poll::Ready(Ok(())),
                    Some(code) => Poll::Ready(Err(StreamErrorIncoming::StreamTerminated {
                        error_code: code.into_inner(),
                    })),
                }
            }
        }
    }

    fn reset(&mut self, code: u64) {
        match self {
            Self::Uni(s) => s.reset(code),
            Self::Response { stream, .. } => {
                let _ = stream.reset(quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX));
            }
        }
    }

    fn send_id(&self) -> StreamId {
        match self {
            Self::Uni(s) => s.send_id(),
            Self::Response { stream, .. } => {
                u64::from(stream.id()).try_into().expect("QUIC stream id")
            }
        }
    }
}

pub struct Bidi {
    send: ResponseSend,
    recv: quinn::RecvStream,
}

impl quic::RecvStream for Bidi {
    type Buf = Bytes;
    fn poll_data(
        &mut self,
        cx: &mut Context<'_>,
    ) -> Poll<Result<Option<Bytes>, StreamErrorIncoming>> {
        let mut buf = [0; 4096];
        let n = ready!(self.recv.poll_read(cx, &mut buf)).map_err(unknown)?;
        Poll::Ready(Ok((n != 0).then(|| Bytes::copy_from_slice(&buf[..n]))))
    }
    fn stop_sending(&mut self, code: u64) {
        let _ = self
            .recv
            .stop(quinn::VarInt::from_u64(code).unwrap_or(quinn::VarInt::MAX));
    }
    fn recv_id(&self) -> StreamId {
        u64::from(self.recv.id())
            .try_into()
            .expect("QUIC stream id")
    }
}

impl quic::SendStream<Bytes> for Bidi {
    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_ready(cx)
    }
    fn send_data<T: Into<WriteBuf<Bytes>>>(&mut self, data: T) -> Result<(), StreamErrorIncoming> {
        self.send.send_data(data)
    }
    fn poll_finish(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), StreamErrorIncoming>> {
        self.send.poll_finish(cx)
    }
    fn reset(&mut self, code: u64) {
        self.send.reset(code);
    }
    fn send_id(&self) -> StreamId {
        self.send.send_id()
    }
}
