//! Seeded datagram impairment. A delayed packet must keep its destination:
//! the next front-side datagram can belong to a different client connection.

pub struct Rng(pub u64);

impl Rng {
    fn hits(&mut self, percent: u32) -> bool {
        self.0 ^= self.0 << 13;
        self.0 ^= self.0 >> 7;
        self.0 ^= self.0 << 17;
        percent > 0 && (self.0 >> 33) as u32 % 100 < percent
    }
}

// Holding one datagram until the next passes reorders without a timing sleep.
// Keep both payload and route so the shared front-side queue cannot send an
// earlier client's packet through a later client's upstream socket.
pub fn relay<D: Clone>(
    mut send: impl FnMut(&D, &[u8]),
    rng: &mut Rng,
    held: &mut Option<(D, Vec<u8>)>,
    packet: (&D, &[u8]),
    loss: u32,
    dup: u32,
    reorder: u32,
) {
    let (destination, data) = packet;
    if rng.hits(loss) {
        return;
    }
    if let Some((previous_destination, previous)) = held.take() {
        send(destination, data);
        send(&previous_destination, &previous);
        return;
    }
    if rng.hits(reorder) {
        *held = Some((destination.clone(), data.to_vec()));
        return;
    }
    send(destination, data);
    if rng.hits(dup) {
        send(destination, data);
    }
}

#[test]
fn reordered_packets_keep_their_original_destination() {
    let mut rng = Rng(1);
    let mut held = None;
    let mut sent = Vec::new();
    for (destination, payload) in [(1, b"first".as_slice()), (2, b"second")] {
        relay(
            |to, data| sent.push((*to, data.to_vec())),
            &mut rng,
            &mut held,
            (&destination, payload),
            0,
            0,
            100,
        );
    }
    assert_eq!(sent, [(2, b"second".to_vec()), (1, b"first".to_vec())]);
    assert!(held.is_none());
}

#[test]
fn a_lost_packet_does_not_replace_a_held_packets_destination() {
    let mut rng = Rng(1);
    let mut held = None;
    let mut sent = Vec::new();
    for (destination, payload, loss) in [
        (1, b"held".as_slice(), 0),
        (2, b"lost", 100),
        (3, b"next", 0),
    ] {
        relay(
            |to, data| sent.push((*to, data.to_vec())),
            &mut rng,
            &mut held,
            (&destination, payload),
            loss,
            0,
            100,
        );
    }
    assert_eq!(sent, [(3, b"next".to_vec()), (1, b"held".to_vec())]);
    assert!(held.is_none());
}

#[test]
fn mixed_loss_duplicates_and_reordering_never_cross_routes() {
    let mut rng = Rng(0xd0e5);
    let mut held = None;
    let mut counts = [0; 512];
    let mut delivered = 0;
    let mut duplicates = 0;
    for n in 0..512_u16 {
        let destination = n % 8;
        let mut data = destination.to_be_bytes().to_vec();
        data.extend(n.to_be_bytes());
        relay(
            |to, packet| {
                assert_eq!(*to, u16::from_be_bytes(packet[..2].try_into().unwrap()));
                let id = u16::from_be_bytes(packet[2..].try_into().unwrap()) as usize;
                counts[id] += 1;
                assert!(counts[id] <= 2);
                delivered += 1;
                duplicates += usize::from(counts[id] == 2);
            },
            &mut rng,
            &mut held,
            (&destination, &data),
            20,
            30,
            40,
        );
    }
    assert!(delivered > 256);
    assert!(duplicates > 0);
    assert!(counts.contains(&0));
}
