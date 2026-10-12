// Appended only to a disposable hfast copy. Production shb is unmodified.
impl Connection {
    pub fn probe_ready(&self) -> bool {
        !self.tls.is_handshaking() && !self.ready.is_empty()
    }

    pub fn probe_ack_snapshot(&self) -> Vec<(u64, u64)> {
        self.spaces[Space::Data as usize].ack.ranges.clone()
    }

    pub fn probe_seen(&self) -> &[(u64, u64)] {
        &self.probe_last_ack
    }

    pub fn probe_packet(&mut self, out: &mut Vec<u8>, ack: &[(u64, u64)], ping: bool) -> u64 {
        let st = &mut self.spaces[Space::Data as usize];
        let pn = st.next_pn;
        st.next_pn += 2; // A permanent, unsent gap between every pair of packets.
        out.clear();
        let phase = self.key_updates.as_ref().is_some_and(|keys| keys.phase);
        out.push(0x43 | (u8::from(phase) << 2)); // Fixed four-byte packet number.
        out.extend_from_slice(self.peer_cid.as_slice());
        let pn_offset = out.len();
        out.extend_from_slice(&(pn as u32).to_be_bytes());
        let header_end = out.len();
        frame::put_ack(out, ack, 0);
        if ping {
            put_varint(out, frame::PING);
        }
        let keys = self.local_keys(Space::Data).unwrap();
        let (head, body) = out.split_at_mut(header_end);
        let tag = keys.packet.encrypt_in_place(pn, head, body).unwrap();
        out.extend_from_slice(tag.as_ref());
        protect_header(keys.header.as_ref(), out, pn_offset, 4).unwrap();
        pn
    }
}
