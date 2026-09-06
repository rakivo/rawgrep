#![allow(unsafe_op_in_unsafe_fn)]

// Fixed-slot output buffer pool, one pool per worker thread.
//
// Ownership model: each slot belongs to exactly one of three places at a time:
//
// A) free (AtomicBool == true),
//
// B) Held by its owning worker thread as the "currently filling" buffer
//
// C) in flight to OutputWorker via an OutputMessage::Slot. Never two of these at once.

use crate::worker::OutputMessage;

use std::sync::atomic::{AtomicBool, Ordering};
use std::cell::UnsafeCell;

pub const SLOT_CAP:         usize = 64 * 1024;
pub const SLOTS_PER_WORKER: usize = 20;

// Padded to a cache line per worker so OutputWorker releasing worker A's
// slot doesn't bounce a cache line that worker B is also polling via
// try_claim. At SLOTS_PER_WORKER=16 and AtomicBool=1 byte, this block is
// 16 bytes -- comfortably within one 64-byte line, and the alignment
// guarantees it never shares a line with a neighboring worker's block.
#[repr(align(64))]
struct WorkerSlotFlags([AtomicBool; SLOTS_PER_WORKER]);

pub struct OutputSlab {
    storage: Box<[UnsafeCell<u8>]>,
    free:    Box<[WorkerSlotFlags]>,  // One block per worker
}

unsafe impl Sync for OutputSlab {}

impl OutputSlab {
    fn new(num_workers: usize) -> &'static Self {
        let num_slots = num_workers * SLOTS_PER_WORKER;
        let v = vec![0u8; num_slots * SLOT_CAP];
        let mut v = std::mem::ManuallyDrop::new(v);

        // SAFETY: UnsafeCell<u8> is #[repr(transparent)] over u8, so this
        // reinterpret is layout-valid. v's allocation is never freed
        // through `v` again (ManuallyDrop), only through the Box we
        // construct here, which owns it from this point on.
        let storage = unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                v.as_mut_ptr() as *mut UnsafeCell<u8>, v.len()
            ))
        };

        let free = (0..num_workers)
            .map(|_| WorkerSlotFlags(std::array::from_fn(|_| AtomicBool::new(true))))
            .collect();

        //
        // Leaked for the process lifetime -- same philosophy as RawStdout's
        // ManuallyDrop fd: exactly one of these per process, reclaimed by
        // the OS at exit, never freed by us.
        //
        Box::leak(Box::new(Self { storage, free }))
    }

    /// # Safety
    /// Caller must hold exclusive (claimed, not-yet-released)
    /// ownership of `slot`.
    #[inline(always)]
    #[allow(clippy::mut_from_ref)]
    pub unsafe fn slot_mut(&self, slot: usize) -> &mut [u8] {
        let base = self.storage.as_ptr().add(slot * SLOT_CAP) as *mut u8;
        std::slice::from_raw_parts_mut(base, SLOT_CAP)
    }

    /// # Safety
    /// Caller must hold read-side ownership (received via an
    /// OutputMessage::Slot, not yet released).
    #[inline(always)]
    pub unsafe fn slot(&self, slot: usize) -> &[u8] {
        let base = self.storage.as_ptr().add(slot * SLOT_CAP) as *const u8;
        std::slice::from_raw_parts(base, SLOT_CAP)
    }

    /// Called only by OutputWorker, only after writev has confirmed every
    /// byte of `slot` was handed to the kernel. The Release store here
    /// pairs with try_claim's Acquire swap: everything this thread did to
    /// the slot's memory happens-before the next thread that observes the
    /// flag flip back to `true`.
    #[inline(always)]
    pub fn release(&self, slot: usize) {
        let (w, i) = (slot / SLOTS_PER_WORKER, slot % SLOTS_PER_WORKER);
        self.free[w].0[i].store(true, Ordering::Release);
    }

    /// Called only by the owning worker thread, scanning its own block.
    #[inline(always)]
    fn try_claim(&self, worker: usize, local: usize) -> bool {
        self.free[worker].0[local].swap(false, Ordering::Acquire)
    }
}

pub struct SlotPool {
    slab:   &'static OutputSlab,
    worker: usize,
    spills: u64,
}

impl SlotPool {
    #[inline]
    pub fn new_for_workers(num_workers: usize) -> Vec<SlotPool> {
        let slab = OutputSlab::new(num_workers);
        (0..num_workers).map(|w| SlotPool { slab, worker: w, spills: 0 }).collect()
    }

    #[inline]
    pub fn acquire(&mut self) -> SlotBuf {
        for local in 0..SLOTS_PER_WORKER {
            if self.slab.try_claim(self.worker, local) {
                let slot = (self.worker * SLOTS_PER_WORKER + local) as u16;
                return SlotBuf::Slab { slab: self.slab, slot, len: 0 };
            }
        }

        //
        // Pool exhausted (OutputWorker behind draining): don't stall the
        // worker thread, spill this one flush to the heap instead.
        //

        self.spills += 1;
        SlotBuf::Owned(Vec::with_capacity(SLOT_CAP))
    }

    #[inline(always)]
    pub const fn spill_count(&self) -> u64 { self.spills }
}

pub enum SlotBuf {
    Slab { slab: &'static OutputSlab, slot: u16, len: usize },
    Owned(Vec<u8>),
}

impl SlotBuf {
    #[inline(always)]
    pub fn len(&self) -> usize {
        match self { SlotBuf::Slab { len, .. } => *len, SlotBuf::Owned(v) => v.len() }
    }

    #[inline(always)]
    pub fn is_empty(&self) -> bool { self.len() == 0 }

    #[inline(always)]
    pub fn push(&mut self, b: u8) { self.extend_from_slice(&[b]); }

    #[inline(always)]
    pub fn clear(&mut self) {
        match self { SlotBuf::Slab { len, .. } => *len = 0, SlotBuf::Owned(v) => v.clear() }
    }

    #[inline(always)]
    pub fn extend_from_slice(&mut self, bytes: &[u8]) {
        match self {
            SlotBuf::Slab { slab, slot, len } => {
                if bytes.len() > SLOT_CAP - *len {
                    self.spill(bytes);
                    return;
                }

                // SAFETY: this thread has held exclusive ownership of `slot`
                // since acquire(); finish() (below) is the only way it leaves,
                // and that consumes self.
                unsafe { slab.slot_mut(*slot as usize)[*len..*len + bytes.len()].copy_from_slice(bytes); }

                *len += bytes.len();
            }

            SlotBuf::Owned(v) => {
                v.extend_from_slice(bytes);
            }
        }
    }

    /// One flush overruns its slot: promote to heap. The slot never left
    /// this thread, so returning it immediately is safe -- nothing else
    /// could be racing it.
    #[inline]
    fn spill(&mut self, extra: &[u8]) {
        let SlotBuf::Slab { slab, slot, len } = self else { unreachable!() };

        let mut v = Vec::with_capacity(*len + extra.len() + SLOT_CAP / 2);
        unsafe { v.extend_from_slice(&slab.slot(*slot as usize)[..*len]); }
        v.extend_from_slice(extra);

        slab.release(*slot as usize);
        *self = SlotBuf::Owned(v);
    }

    #[inline(always)]
    pub fn finish(self) -> OutputMessage {
        match self {
            SlotBuf::Slab { slab, slot, len } => OutputMessage::Slot { slab, slot, len: len as u32 },
            SlotBuf::Owned(v) => OutputMessage::Owned(crate::util::vec_into_boxed_slice_noshrink(v)),
        }
    }
}
