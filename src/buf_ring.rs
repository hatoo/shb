use std::mem;
use std::sync::atomic::{AtomicU16, Ordering};

use anyhow::{Context, Result, bail};
use io_uring::types;

/// Size of a single buffer in the provided buffer ring
pub const RECV_BUF_SIZE: usize = 16 * 1024;

/// Provided buffer ring for multishot recv
///
/// On every receive the kernel takes a buffer from this ring, writes into it,
/// and reports the buffer ID in the CQE flags. Return processed buffers with
/// `recycle`. The kernel keeps referencing the ring area and the data buffers
/// until the buffer group is unregistered (= the io_uring is dropped), so this
/// struct must be declared before the ring so that reverse drop order destroys
/// it after the ring.
///
/// Callers size the ring from the connection count alone, which ignores that
/// one HTTP/2 connection can carry a hundred responses arriving at once: at
/// 100 x 100 the ring runs dry about 18,000 times in nine million requests,
/// and each time the multishot recv ends and has to be re-armed. Raising the
/// count to 256 removes every one of those and does not make it faster - the
/// buffer area goes from 1 MB to 4 MB per worker and loses more to cache than
/// the re-arms cost, and larger is worse again. Measured 2026-08; the sizing
/// is deliberate.
pub struct BufRing {
    /// io_uring_buf entry array (page-aligned, shared with the kernel)
    pub ring_ptr: *mut types::BufRingEntry,
    layout: std::alloc::Layout,
    pub entries: u16,
    mask: u16,
    /// Local shadow of the tail; publish stores it to the shared area with Release
    tail: u16,
    /// Contiguous data buffer of entries * RECV_BUF_SIZE bytes (must never reallocate)
    data: Vec<u8>,
}

impl BufRing {
    pub fn new(entries: u16) -> Result<Self> {
        assert!(entries.is_power_of_two());
        let layout = std::alloc::Layout::from_size_align(
            entries as usize * mem::size_of::<types::BufRingEntry>(),
            4096,
        )
        .context("invalid buffer ring layout")?;
        let ring_ptr = unsafe { std::alloc::alloc_zeroed(layout) } as *mut types::BufRingEntry;
        if ring_ptr.is_null() {
            bail!("failed to allocate buffer ring");
        }
        let mut this = BufRing {
            ring_ptr,
            layout,
            entries,
            mask: entries - 1,
            tail: 0,
            data: vec![0u8; entries as usize * RECV_BUF_SIZE],
        };
        // Seed the ring with every buffer
        for bid in 0..entries {
            this.push_entry(bid);
        }
        this.publish();
        Ok(this)
    }

    fn push_entry(&mut self, bid: u16) {
        let idx = (self.tail & self.mask) as usize;
        unsafe {
            let entry = &mut *self.ring_ptr.add(idx);
            entry.set_addr(self.data.as_ptr() as u64 + bid as u64 * RECV_BUF_SIZE as u64);
            entry.set_len(RECV_BUF_SIZE as u32);
            entry.set_bid(bid);
        }
        self.tail = self.tail.wrapping_add(1);
    }

    /// Publish the tail to the kernel
    fn publish(&self) {
        unsafe {
            let tail_ptr = types::BufRingEntry::tail(self.ring_ptr) as *const AtomicU16;
            (*tail_ptr).store(self.tail, Ordering::Release);
        }
    }

    /// Borrow the data of the buffer reported by a CQE
    pub fn data(&self, bid: u16, len: usize) -> &[u8] {
        let off = bid as usize * RECV_BUF_SIZE;
        &self.data[off..off + len]
    }

    /// Return a processed buffer to the ring
    pub fn recycle(&mut self, bid: u16) {
        self.push_entry(bid);
        self.publish();
    }
}

impl Drop for BufRing {
    fn drop(&mut self) {
        unsafe { std::alloc::dealloc(self.ring_ptr as *mut u8, self.layout) };
    }
}
