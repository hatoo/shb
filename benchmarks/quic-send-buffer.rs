//! Native replay of the production SendStream (see build-quic-send-buffer.py).
use std::hint::black_box;
use std::sync::atomic::{AtomicU64, Ordering};

#[allow(dead_code)]
mod stream;

pub static MOVED: AtomicU64 = AtomicU64::new(0);

#[global_allocator]
static ALLOCATOR: mimalloc::MiMalloc = mimalloc::MiMalloc;

fn main() {
    let args: Vec<_> = std::env::args().collect();
    let size: usize = args[1].parse().unwrap();
    let packet: usize = args[2].parse().unwrap();
    let repeats: usize = args[3].parse().unwrap();
    assert!(size > 0 && packet > 0);
    let data: Vec<_> = (0..size)
        .map(|n| (n ^ (n >> 8) ^ (n >> 16)) as u8)
        .collect();
    let start = std::time::Instant::now();
    for _ in 0..repeats {
        let mut send = stream::SendStream::new(size as u64);
        assert_eq!(send.write(black_box(&data)), size);
        send.finish();
        let mut offset = 0;
        while offset < size {
            let (actual, bytes, fin) = send.next_send(packet, u64::MAX).unwrap();
            assert_eq!(actual, offset as u64);
            assert_eq!(bytes, &data[offset..offset + bytes.len()]);
            let len = bytes.len();
            assert_eq!(fin, offset + len == size);
            black_box(bytes);
            assert_eq!(send.on_sent(actual, len, fin), len);
            send.on_acked(actual, len, fin);
            offset += len;
        }
        assert!(send.is_settled());
        black_box(send);
    }
    println!(
        "{{\"bytes\":{},\"packet\":{packet},\"repeats\":{repeats},\"counted\":{},\"moved_bytes\":{},\"send_stream_size\":{},\"seconds\":{}}}",
        size * repeats,
        cfg!(copy_counts),
        MOVED.load(Ordering::Relaxed),
        std::mem::size_of::<stream::SendStream>(),
        start.elapsed().as_secs_f64()
    );
}
