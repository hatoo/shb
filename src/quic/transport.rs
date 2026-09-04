//! Transport parameters (RFC 9000 Section 18)
//!
//! Only the ones that change what shb may do are read; the rest are stepped
//! over. A parameter we ignore is one whose default we are already obeying.

use anyhow::{Result, bail};

use super::packet::{ConnectionId, MAX_CID_LEN};
use super::varint::{get_varint, put_varint};

const MAX_IDLE_TIMEOUT: u64 = 0x01;
const STATELESS_RESET_TOKEN: u64 = 0x02;
const MAX_UDP_PAYLOAD_SIZE: u64 = 0x03;
const INITIAL_MAX_DATA: u64 = 0x04;
const INITIAL_MAX_STREAM_DATA_BIDI_LOCAL: u64 = 0x05;
const INITIAL_MAX_STREAM_DATA_BIDI_REMOTE: u64 = 0x06;
const INITIAL_MAX_STREAM_DATA_UNI: u64 = 0x07;
const INITIAL_MAX_STREAMS_BIDI: u64 = 0x08;
const INITIAL_MAX_STREAMS_UNI: u64 = 0x09;
const ACK_DELAY_EXPONENT: u64 = 0x0a;
const MAX_ACK_DELAY: u64 = 0x0b;
const ACTIVE_CONNECTION_ID_LIMIT_ID: u64 = 0x0e;
const INITIAL_SOURCE_CONNECTION_ID: u64 = 0x0f;

/// How many of the peer's connection IDs shb will hold at once (RFC 9000
/// Section 18.2). The minimum: a client that never migrates needs one, and
/// keeps a second only so the peer can rotate the first out from under it.
pub const ACTIVE_CONNECTION_ID_LIMIT: u64 = 2;

/// What the peer will let us do
#[derive(Debug, Clone)]
pub struct Params {
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u64,
    pub initial_max_data: u64,
    /// Applies to bidirectional streams we open
    pub initial_max_stream_data_bidi_remote: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_bidi: u64,
    pub initial_max_streams_uni: u64,
    pub ack_delay_exponent: u32,
    pub max_ack_delay_ms: u64,
    pub active_connection_id_limit: u64,
    pub initial_source_connection_id: Option<ConnectionId>,
    /// What the peer will end its handshake connection ID with if it loses
    /// the connection's state (RFC 9000 Section 10.3)
    pub stateless_reset_token: Option<[u8; 16]>,
}

impl Default for Params {
    fn default() -> Self {
        // RFC 9000 Section 18.2 defaults, which apply to anything the peer
        // leaves out
        Self {
            max_idle_timeout_ms: 0,
            max_udp_payload_size: 65527,
            initial_max_data: 0,
            initial_max_stream_data_bidi_remote: 0,
            initial_max_stream_data_bidi_local: 0,
            initial_max_stream_data_uni: 0,
            initial_max_streams_bidi: 0,
            initial_max_streams_uni: 0,
            ack_delay_exponent: 3,
            max_ack_delay_ms: 25,
            active_connection_id_limit: 2,
            initial_source_connection_id: None,
            stateless_reset_token: None,
        }
    }
}

impl Params {
    pub fn decode(mut buf: &[u8]) -> Result<Self> {
        let mut out = Params::default();
        while !buf.is_empty() {
            let Some((id, n)) = get_varint(buf) else {
                bail!("truncated transport parameter id");
            };
            buf = &buf[n..];
            let Some((len, n)) = get_varint(buf) else {
                bail!("truncated transport parameter length");
            };
            buf = &buf[n..];
            if buf.len() < len as usize {
                bail!("transport parameter runs past the end");
            }
            let (value, rest) = buf.split_at(len as usize);
            buf = rest;
            // A varint-valued parameter, for the many that are one
            let int = || -> Result<u64> {
                let Some((v, n)) = get_varint(value) else {
                    bail!("transport parameter {id:#x} is not a varint");
                };
                if n != value.len() {
                    bail!("transport parameter {id:#x} has trailing bytes");
                }
                Ok(v)
            };
            match id {
                MAX_IDLE_TIMEOUT => out.max_idle_timeout_ms = int()?,
                MAX_UDP_PAYLOAD_SIZE => out.max_udp_payload_size = int()?,
                INITIAL_MAX_DATA => out.initial_max_data = int()?,
                INITIAL_MAX_STREAM_DATA_BIDI_LOCAL => {
                    out.initial_max_stream_data_bidi_local = int()?
                }
                INITIAL_MAX_STREAM_DATA_BIDI_REMOTE => {
                    out.initial_max_stream_data_bidi_remote = int()?
                }
                INITIAL_MAX_STREAM_DATA_UNI => out.initial_max_stream_data_uni = int()?,
                INITIAL_MAX_STREAMS_BIDI => out.initial_max_streams_bidi = int()?,
                INITIAL_MAX_STREAMS_UNI => out.initial_max_streams_uni = int()?,
                ACK_DELAY_EXPONENT => {
                    let v = int()?;
                    if v > 20 {
                        bail!("ack_delay_exponent above the 20 RFC 9000 allows");
                    }
                    out.ack_delay_exponent = v as u32;
                }
                MAX_ACK_DELAY => {
                    let v = int()?;
                    if v >= 1 << 14 {
                        bail!("max_ack_delay of {v}ms is out of range");
                    }
                    out.max_ack_delay_ms = v;
                }
                ACTIVE_CONNECTION_ID_LIMIT_ID => {
                    let v = int()?;
                    if v < 2 {
                        bail!("active_connection_id_limit below the minimum of 2");
                    }
                    out.active_connection_id_limit = v;
                }
                INITIAL_SOURCE_CONNECTION_ID => {
                    if value.len() > MAX_CID_LEN {
                        bail!("initial_source_connection_id is too long");
                    }
                    out.initial_source_connection_id = Some(ConnectionId::new(value)?);
                }
                STATELESS_RESET_TOKEN => {
                    let Ok(token) = <[u8; 16]>::try_from(value) else {
                        bail!("stateless_reset_token is not 16 bytes");
                    };
                    out.stateless_reset_token = Some(token);
                }
                // Everything else is either something we already default to
                // or something only a server needs
                _ => {}
            }
        }
        Ok(out)
    }
}

/// What shb tells the peer about itself
pub struct LocalParams {
    pub initial_max_data: u64,
    pub initial_max_stream_data_bidi_local: u64,
    pub initial_max_stream_data_uni: u64,
    pub initial_max_streams_uni: u64,
    pub max_idle_timeout_ms: u64,
    pub max_udp_payload_size: u64,
    pub source_connection_id: ConnectionId,
}

impl LocalParams {
    pub fn encode(&self) -> Vec<u8> {
        let mut out = Vec::with_capacity(64);
        let mut put = |id: u64, value: u64| {
            put_varint(&mut out, id);
            let mut tmp = Vec::with_capacity(8);
            put_varint(&mut tmp, value);
            put_varint(&mut out, tmp.len() as u64);
            out.extend_from_slice(&tmp);
        };
        put(INITIAL_MAX_DATA, self.initial_max_data);
        put(
            INITIAL_MAX_STREAM_DATA_BIDI_LOCAL,
            self.initial_max_stream_data_bidi_local,
        );
        put(
            INITIAL_MAX_STREAM_DATA_UNI,
            self.initial_max_stream_data_uni,
        );
        put(INITIAL_MAX_STREAMS_UNI, self.initial_max_streams_uni);
        // A client that opens no bidirectional streams for the peer says so
        put(INITIAL_MAX_STREAMS_BIDI, 0);
        put(MAX_IDLE_TIMEOUT, self.max_idle_timeout_ms);
        put(MAX_UDP_PAYLOAD_SIZE, self.max_udp_payload_size);
        // shb acknowledges immediately, so promising anything else would only
        // inflate the peer's probe timeout
        put(MAX_ACK_DELAY, 0);
        put(ACTIVE_CONNECTION_ID_LIMIT_ID, ACTIVE_CONNECTION_ID_LIMIT);
        put_varint(&mut out, INITIAL_SOURCE_CONNECTION_ID);
        put_varint(&mut out, self.source_connection_id.len() as u64);
        out.extend_from_slice(self.source_connection_id.as_slice());
        out
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn param(id: u64, value: u64) -> Vec<u8> {
        let mut out = Vec::new();
        put_varint(&mut out, id);
        let mut tmp = Vec::new();
        put_varint(&mut tmp, value);
        put_varint(&mut out, tmp.len() as u64);
        out.extend_from_slice(&tmp);
        out
    }

    /// RFC 9000 Section 18.2: anything the peer leaves out takes its default,
    /// and the defaults are not all zero
    #[test]
    fn missing_parameters_take_their_defaults() {
        let p = Params::decode(&[]).unwrap();
        assert_eq!(p.ack_delay_exponent, 3);
        assert_eq!(p.max_ack_delay_ms, 25);
        assert_eq!(p.active_connection_id_limit, 2);
        assert_eq!(p.max_udp_payload_size, 65527);
        assert_eq!(p.initial_max_data, 0, "no credit until the peer grants it");
    }

    #[test]
    fn the_parameters_that_matter_are_read() {
        let mut buf = Vec::new();
        buf.extend(param(INITIAL_MAX_DATA, 1 << 20));
        buf.extend(param(INITIAL_MAX_STREAM_DATA_BIDI_REMOTE, 1 << 16));
        buf.extend(param(INITIAL_MAX_STREAMS_BIDI, 100));
        buf.extend(param(MAX_IDLE_TIMEOUT, 30_000));
        buf.extend(param(ACK_DELAY_EXPONENT, 0));
        let p = Params::decode(&buf).unwrap();
        assert_eq!(p.initial_max_data, 1 << 20);
        assert_eq!(p.initial_max_stream_data_bidi_remote, 1 << 16);
        assert_eq!(p.initial_max_streams_bidi, 100);
        assert_eq!(p.max_idle_timeout_ms, 30_000);
        assert_eq!(p.ack_delay_exponent, 0);
    }

    /// Unknown parameters, including the GREASE ones a peer sends on purpose
    /// to catch clients that cannot skip them
    #[test]
    fn unknown_parameters_are_skipped() {
        let mut buf = param(0x1a2a3a4a5a6a7a8, 1);
        buf.extend(param(INITIAL_MAX_DATA, 42));
        let p = Params::decode(&buf).unwrap();
        assert_eq!(p.initial_max_data, 42, "the one after it still parsed");
    }

    #[test]
    fn the_source_connection_id_is_kept_for_checking() {
        let mut buf = Vec::new();
        put_varint(&mut buf, INITIAL_SOURCE_CONNECTION_ID);
        put_varint(&mut buf, 4);
        buf.extend_from_slice(&[1, 2, 3, 4]);
        let p = Params::decode(&buf).unwrap();
        assert_eq!(
            p.initial_source_connection_id.unwrap().as_slice(),
            &[1, 2, 3, 4]
        );
    }

    /// The token is what tells a stateless reset from line noise, so it has
    /// to survive the parse intact, and a token of the wrong length is not a
    /// token at all
    #[test]
    fn the_stateless_reset_token_is_kept_and_must_be_sixteen_bytes() {
        let mut buf = Vec::new();
        put_varint(&mut buf, STATELESS_RESET_TOKEN);
        put_varint(&mut buf, 16);
        buf.extend_from_slice(&[0xab; 16]);
        let p = Params::decode(&buf).unwrap();
        assert_eq!(p.stateless_reset_token, Some([0xab; 16]));

        let mut short = Vec::new();
        put_varint(&mut short, STATELESS_RESET_TOKEN);
        put_varint(&mut short, 15);
        short.extend_from_slice(&[0xab; 15]);
        assert!(Params::decode(&short).is_err());
    }

    #[test]
    fn out_of_range_values_are_rejected() {
        assert!(Params::decode(&param(ACK_DELAY_EXPONENT, 21)).is_err());
        assert!(Params::decode(&param(MAX_ACK_DELAY, 1 << 14)).is_err());
        assert!(
            Params::decode(&param(ACTIVE_CONNECTION_ID_LIMIT_ID, 1)).is_err(),
            "RFC 9000 Section 18.2 sets the minimum at 2"
        );
    }

    #[test]
    fn a_truncated_block_is_rejected() {
        let mut buf = param(INITIAL_MAX_DATA, 1000);
        buf.pop();
        assert!(Params::decode(&buf).is_err());
        // A length that runs past what is there
        let mut buf = Vec::new();
        put_varint(&mut buf, INITIAL_MAX_DATA);
        put_varint(&mut buf, 8);
        buf.extend_from_slice(&[0, 0]);
        assert!(Params::decode(&buf).is_err());
    }

    #[test]
    fn what_we_send_is_what_a_peer_would_read_back() {
        let cid = ConnectionId::new(&[9, 8, 7, 6]).unwrap();
        let local = LocalParams {
            initial_max_data: 1 << 30,
            initial_max_stream_data_bidi_local: 1 << 20,
            initial_max_stream_data_uni: 1 << 16,
            initial_max_streams_uni: 3,
            max_idle_timeout_ms: 30_000,
            max_udp_payload_size: 1452,
            source_connection_id: cid,
        };
        let p = Params::decode(&local.encode()).unwrap();
        assert_eq!(p.initial_max_data, 1 << 30);
        assert_eq!(p.initial_max_stream_data_bidi_local, 1 << 20);
        assert_eq!(p.initial_max_stream_data_uni, 1 << 16);
        assert_eq!(p.initial_max_streams_uni, 3);
        assert_eq!(p.initial_max_streams_bidi, 0, "a client accepts none");
        assert_eq!(p.max_idle_timeout_ms, 30_000);
        assert_eq!(p.max_udp_payload_size, 1452);
        assert_eq!(p.max_ack_delay_ms, 0, "shb acknowledges immediately");
        assert_eq!(
            p.initial_source_connection_id.unwrap().as_slice(),
            &[9, 8, 7, 6]
        );
    }
}
