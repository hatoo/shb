// Frozen ResponseReader from shb fede6eb, before bounded frame carry.
// Kept independent of the production buffering path for differential tests.
use super::super::*;

#[derive(Default)]
pub struct ResponseReader {
    /// A partial frame header or field section carried over
    pending: Vec<u8>,
    /// Bytes still to skip from the frame being read
    skip: u64,
    /// Status from the first HEADERS frame (0 = not seen yet)
    status: u16,
}

impl ResponseReader {
    pub fn status(&self) -> u16 {
        self.status
    }

    /// Consume stream data
    pub fn feed(&mut self, data: &[u8]) -> Result<()> {
        if self.pending.is_empty() {
            let used = self.run(data)?;
            if used < data.len() {
                self.pending.extend_from_slice(&data[used..]);
            }
            return Ok(());
        }
        let mut buf = std::mem::take(&mut self.pending);
        buf.extend_from_slice(data);
        let result = self.run(&buf);
        match result {
            Ok(used) => {
                buf.drain(..used);
                self.pending = buf;
                Ok(())
            }
            Err(e) => Err(e),
        }
    }

    fn run(&mut self, buf: &[u8]) -> Result<usize> {
        let mut pos = 0;
        loop {
            if self.skip > 0 {
                let take = self.skip.min((buf.len() - pos) as u64);
                pos += take as usize;
                self.skip -= take;
                if self.skip > 0 {
                    return Ok(pos);
                }
            }
            let Some((kind, n1)) = get_varint(&buf[pos..]) else {
                return Ok(pos);
            };
            let Some((len, n2)) = get_varint(&buf[pos + n1..]) else {
                return Ok(pos);
            };
            let header_len = n1 + n2;
            if kind == FRAME_HEADERS {
                let end = pos + header_len + len as usize;
                if buf.len() < end {
                    // Wait for the whole field section: decoding it in pieces
                    // would mean keeping QPACK state across reads
                    return Ok(pos);
                }
                let section = &buf[pos + header_len..end];
                // A section with no `:status` is trailers, and a 1xx is
                // informational and precedes the real response (RFC 9110
                // Section 15.2); neither is the status this request gets
                // answered with
                if let Some(status) = qpack::find_status(section)?
                    && !crate::is_informational(status)
                {
                    self.status = status;
                }
                pos = end;
                continue;
            }
            if kind == FRAME_GOAWAY && len > 1 << 20 {
                bail!("oversized GOAWAY");
            }
            // DATA and anything else the client may ignore: skip by length
            pos += header_len;
            self.skip = len;
        }
    }
}

impl ResponseReader {
    pub fn state(&self) -> (&[u8], u64, u16) {
        (&self.pending, self.skip, self.status)
    }
}
