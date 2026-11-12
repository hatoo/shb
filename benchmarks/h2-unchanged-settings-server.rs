//! Fixed h2c peer for unchanged-window SETTINGS comparisons. No dependencies.
//! Usage: server PORT COHORT COHORTS REPEATS
use std::io::{self, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::time::Duration;

const PREFACE: &[u8] = b"PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n";
const CLIENT_SETTINGS: &[u8] = &[0, 1, 0, 0, 0, 0, 0, 2, 0, 0, 0, 0, 0, 4, 127, 255, 255, 255];

fn require(condition: bool, message: &str) -> io::Result<()> {
    if condition {
        Ok(())
    } else {
        Err(io::Error::new(io::ErrorKind::InvalidData, message))
    }
}

fn frame(kind: u8, flags: u8, stream: u32, body: &[u8], out: &mut Vec<u8>) {
    assert!(body.len() <= 16_384);
    out.extend_from_slice(&(body.len() as u32).to_be_bytes()[1..]);
    out.extend_from_slice(&[kind, flags]);
    out.extend_from_slice(&stream.to_be_bytes());
    out.extend_from_slice(body);
}

fn read_frame(input: &mut impl Read) -> io::Result<(u8, u8, u32, Vec<u8>)> {
    let mut header = [0; 9];
    input.read_exact(&mut header)?;
    let length = u32::from_be_bytes([0, header[0], header[1], header[2]]) as usize;
    require(length <= 16_384, "oversized client frame")?;
    let stream = u32::from_be_bytes(header[5..].try_into().unwrap());
    require(stream & (1 << 31) == 0, "reserved stream bit")?;
    let mut body = vec![0; length];
    input.read_exact(&mut body)?;
    Ok((header[3], header[4], stream, body))
}

#[derive(Default, Debug)]
struct Ledger {
    requests: usize,
    responses: usize,
    settings_acks: usize,
    initial_settings: bool,
    connection_credit: bool,
    header_block: Vec<u8>,
}

impl Ledger {
    fn accept(
        &mut self,
        packet: (u8, u8, u32, Vec<u8>),
        output: &mut impl Write,
    ) -> io::Result<()> {
        let (kind, flags, stream, body) = packet;
        match (kind, flags, stream) {
            (4, 0, 0) => {
                require(
                    !self.initial_settings && body == CLIENT_SETTINGS,
                    "client settings",
                )?;
                self.initial_settings = true;
                output.write_all(&[0, 0, 0, 4, 1, 0, 0, 0, 0])?;
            }
            (4, 1, 0) => {
                require(body.is_empty(), "nonempty settings ACK")?;
                self.settings_acks += 1;
            }
            (8, 0, 0) => {
                require(
                    !self.connection_credit && body == [127, 255, 0, 0],
                    "connection credit",
                )?;
                self.connection_credit = true;
            }
            (1, 5, id) => {
                require(
                    self.initial_settings && self.connection_credit,
                    "request before client preface",
                )?;
                require(
                    id as usize == self.requests * 2 + 1,
                    "missing, duplicate or reordered stream ID",
                )?;
                require(!body.is_empty(), "empty request headers")?;
                if self.header_block.is_empty() {
                    self.header_block = body;
                } else {
                    require(body == self.header_block, "different request header block")?;
                }
                self.requests += 1;
            }
            _ => {
                return Err(io::Error::new(
                    io::ErrorKind::InvalidData,
                    "unexpected client frame",
                ));
            }
        }
        Ok(())
    }
}

fn serve(
    mut socket: TcpStream,
    cohort: usize,
    cohorts: usize,
    repeats: usize,
) -> io::Result<Ledger> {
    socket.set_nodelay(true)?;
    socket.set_read_timeout(Some(Duration::from_secs(30)))?;
    socket.set_write_timeout(Some(Duration::from_secs(30)))?;
    let mut input = BufReader::with_capacity(256 * 1024, socket.try_clone()?);
    let mut preface = [0; 24];
    input.read_exact(&mut preface)?;
    require(preface == PREFACE, "client preface")?;
    let mut settings = vec![0, 3];
    settings.extend_from_slice(&(cohort as u32).to_be_bytes());
    let mut output = Vec::new();
    frame(4, 0, 0, &settings, &mut output);
    socket.write_all(&output)?;
    let mut repeated = Vec::new();
    if repeats > 0 {
        let payload = [0, 4, 0, 0, 255, 255].repeat(repeats);
        frame(4, 0, 0, &payload, &mut repeated);
    }
    let mut ledger = Ledger::default();
    let mut expected_acks = 1;
    for cycle in 0..cohorts {
        let target = (cycle + 1) * cohort;
        while ledger.requests < target || ledger.settings_acks < expected_acks {
            ledger.accept(read_frame(&mut input)?, &mut socket)?;
            require(
                ledger.requests <= target && ledger.settings_acks <= expected_acks,
                "cohort exceeded",
            )?;
        }
        if repeats > 0 {
            socket.write_all(&repeated)?;
            expected_acks += 1;
            ledger.accept(read_frame(&mut input)?, &mut socket)?;
            require(
                ledger.settings_acks == expected_acks && ledger.requests == target,
                "missing settings fence",
            )?;
        }
        output.clear();
        for request in cycle * cohort..target {
            frame(1, 5, (request * 2 + 1) as u32, &[0x88], &mut output);
        }
        socket.write_all(&output)?;
        ledger.responses += cohort;
    }
    // Observe a complete client shutdown, including its optional GOAWAY. A
    // truncated frame, extra request, or missing response remains an error.
    let mut tail = Vec::new();
    input.take(1024).read_to_end(&mut tail)?;
    if !tail.is_empty() {
        let mut cursor = io::Cursor::new(&tail);
        let (kind, flags, stream, body) = read_frame(&mut cursor)?;
        require(
            (kind, flags, stream) == (7, 0, 0) && body.len() == 8 && body[4..] == [0; 4],
            "shutdown GOAWAY",
        )?;
        require(
            cursor.position() as usize == tail.len(),
            "extra bytes after GOAWAY",
        )?;
    }
    require(
        ledger.requests == cohort * cohorts
            && ledger.responses == ledger.requests
            && ledger.settings_acks == expected_acks,
        "final counts",
    )?;
    Ok(ledger)
}

fn main() -> io::Result<()> {
    let args: Vec<_> = std::env::args()
        .skip(1)
        .map(|x| x.parse::<usize>().expect("integer argument"))
        .collect();
    assert_eq!(args.len(), 4, "PORT COHORT COHORTS REPEATS");
    let (port, cohort, cohorts, repeats) = (args[0], args[1], args[2], args[3]);
    assert!(port <= u16::MAX as usize && cohort > 0 && cohorts > 0 && repeats <= 2730);
    assert!(cohort.checked_mul(cohorts).is_some_and(|n| n < (1 << 30)));
    let listener = TcpListener::bind(("127.0.0.1", port as u16))?;
    listener.set_nonblocking(true)?;
    println!("READY {}", listener.local_addr()?.port());
    io::stdout().flush()?;
    let deadline = std::time::Instant::now() + Duration::from_secs(30);
    let socket = loop {
        match listener.accept() {
            Ok((socket, _)) => break socket,
            Err(e)
                if e.kind() == io::ErrorKind::WouldBlock
                    && std::time::Instant::now() < deadline =>
            {
                std::thread::sleep(Duration::from_millis(1))
            }
            Err(e) => return Err(e),
        }
    };
    let ledger = serve(socket, cohort, cohorts, repeats)?;
    println!(
        "{{\"requests\":{},\"responses\":{},\"settings_acks\":{}}}",
        ledger.requests, ledger.responses, ledger.settings_acks
    );
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn started() -> Ledger {
        let mut ledger = Ledger::default();
        ledger
            .accept((4, 0, 0, CLIENT_SETTINGS.to_vec()), &mut Vec::new())
            .unwrap();
        ledger
            .accept((8, 0, 0, vec![127, 255, 0, 0]), &mut Vec::new())
            .unwrap();
        ledger
    }

    #[test]
    fn rejects_duplicate_skipped_or_changed_requests() {
        for bad in [
            (1, 5, 1, vec![0x82]),
            (1, 5, 5, vec![0x82]),
            (1, 5, 3, vec![0x83]),
            (1, 4, 3, vec![0x82]),
        ] {
            let mut ledger = started();
            ledger
                .accept((1, 5, 1, vec![0x82]), &mut Vec::new())
                .unwrap();
            assert!(ledger.accept(bad, &mut Vec::new()).is_err());
            assert_eq!(ledger.requests, 1);
        }
    }

    #[test]
    fn rejects_truncated_frames_and_bad_acknowledgments() {
        let wire = [0, 0, 1, 1, 5, 0, 0, 0, 1, 0x88];
        for end in 0..wire.len() {
            assert!(read_frame(&mut &wire[..end]).is_err());
        }
        assert_eq!(
            read_frame(&mut wire.as_slice()).unwrap(),
            (1, 5, 1, vec![0x88])
        );
        assert!(
            started()
                .accept((4, 1, 0, vec![0]), &mut Vec::new())
                .is_err()
        );
    }
}
