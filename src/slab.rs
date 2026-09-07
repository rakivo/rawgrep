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
//
// Plus, once handed to OutputWorker on a pipe: possibly
//
// D) referenced by an in-flight vmsplice (page pinned into the pipe's ring buffer).
// That's why storage below is allocated page-aligned: vmsplice pins whole pages,
// and if a slot boundary didn't line up with a page boundary,
// two adjacent (and independently owned/reused) slots could share a physical page,
// letting a live producer write into slot N+1 corrupt a page the kernel still holds open for slot N's vmsplice.

use crate::worker::OutputMessage;

use std::sync::atomic::{AtomicU32, Ordering};
use std::cell::UnsafeCell;

pub const SLOT_CAP:         usize = 64 * 1024;
pub const SLOTS_PER_WORKER: usize = 20;

const PAGE_SIZE: usize = 4096;

const _: () = assert!(SLOTS_PER_WORKER <= 32, "bitmask claim needs SLOTS_PER_WORKER <= 32");

// Padded to a cache line per worker so OutputWorker releasing worker A's
// slot doesn't bounce a cache line that worker B is also polling via
// try_claim. One AtomicU32 per worker (bit i == slot i is free) fits
// comfortably within one 64-byte line, and the alignment guarantees it
// never shares a line with a neighboring worker's block.
#[repr(align(64))]
struct WorkerSlotFlags(AtomicU32);

pub struct OutputSlab {
    storage: Box<[UnsafeCell<u8>]>,
    free:    Box<[WorkerSlotFlags]>,  // One block per worker
}

unsafe impl Sync for OutputSlab {}

impl OutputSlab {
    fn new(num_workers: usize) -> &'static Self {
        let num_slots = num_workers * SLOTS_PER_WORKER;
        let total_bytes = num_slots * SLOT_CAP;

        debug_assert_eq!(
            SLOT_CAP % PAGE_SIZE, 0,
            "SLOT_CAP must be a whole number of pages for vmsplice slot isolation"
        );
        debug_assert!(num_workers > 0, "need at least one worker to size the slab");

        // SAFETY: PAGE_SIZE (4096) is a nonzero power-of-two alignment;
        // total_bytes is nonzero as long as num_workers > 0, upheld above.
        // alloc_zeroed gives zeroed memory starting at a page-aligned
        // address directly from the allocator (unlike Vec<u8>, which only
        // guarantees align_of::<u8>() and merely happens to be page-aligned
        // on some allocators for large sizes). Since SLOT_CAP is itself a
        // whole multiple of PAGE_SIZE, every slot boundary (k * SLOT_CAP)
        // is therefore also a page boundary -- no slot ever shares a
        // physical page with its neighbor.
        let layout = std::alloc::Layout::from_size_align(total_bytes, PAGE_SIZE).expect("slab size/alignment overflow");
        let ptr = unsafe { std::alloc::alloc_zeroed(layout) };
        assert!(!ptr.is_null(), "slab allocation failed ({total_bytes} bytes)");
        debug_assert_eq!(ptr as usize % PAGE_SIZE, 0, "allocator did not honor requested alignment");

        // SAFETY: UnsafeCell<u8> is #[repr(transparent)] over u8, so this
        // reinterpret is layout-valid. `ptr` came from alloc_zeroed with
        // exactly this layout and length, and -- same leak philosophy as
        // before -- is never freed: the OutputSlab this becomes part of is
        // Box::leak'd below for the process lifetime, so no mismatched
        // dealloc (global allocator vs. this Layout) ever happens because
        // no dealloc happens at all.
        let storage = unsafe {
            Box::from_raw(std::ptr::slice_from_raw_parts_mut(
                ptr as *mut UnsafeCell<u8>, total_bytes
            ))
        };

        let free = (0..num_workers)
            .map(|_| WorkerSlotFlags(AtomicU32::new((1u32 << SLOTS_PER_WORKER) - 1)))
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

    /// Called by OutputWorker: pairs with try_claim's Acquire swap; see that
    /// doc for the ordering argument.
    #[inline(always)]
    pub fn release(&self, slot: usize) {
        let (w, i) = (slot / SLOTS_PER_WORKER, slot % SLOTS_PER_WORKER);
        self.free[w].0.fetch_or(1 << i, Ordering::Release);
    }

    /// Called only by the owning worker thread, scanning its own block.
    /// Returns the claimed local index, or None if the worker's block is
    /// fully spoken for.
    #[inline(always)]
    fn try_claim(&self, worker: usize) -> Option<usize> {
        let flags = &self.free[worker].0;
        loop {
            let mask = flags.load(Ordering::Relaxed);
            if mask == 0 { return None; }

            let idx = mask.trailing_zeros() as usize;

            //
            // Only this thread ever clears bits (releases only ever set them),
            // so no other claimer can race this CAS -- but another release()
            // can still flip an unrelated bit between load and here, so we
            // still need compare_exchange rather than a plain fetch_and.
            //
            let new_mask = mask & !(1 << idx);
            if flags.compare_exchange_weak(mask, new_mask, Ordering::Acquire, Ordering::Relaxed).is_ok() {
                return Some(idx);
            }
        }
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
        if let Some(local) = self.slab.try_claim(self.worker) {
            let slot = (self.worker * SLOTS_PER_WORKER + local) as u16;
            return SlotBuf::Slab { slab: self.slab, slot, len: 0 };
        }

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
