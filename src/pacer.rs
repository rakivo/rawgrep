//
// The purpose of this module is to make rawgrep, well ... "look" fast,
// while also not adding much overhead, or no overhead at all, if running
// inside a non-tty environment.
//

use std::sync::atomic::{AtomicU32, AtomicU64, Ordering};
use std::time::Instant;

/// (interval_ms, batch_bytes, check_stride_mask) per ramp step.
/// Stride grows with the step: at low volume we poll every 32 files
/// to stay responsive; at high volume the batch is huge and the
/// interval is long, so there's no reason to touch the shared pacer
/// more than once every few thousand files.
const STEPS: &[(u32, u32, usize)] = &[
    (50,    128  * 1024,     0x003F),  // stride    64 -- flushes 0..2
    (200,   512  * 1024,     0x00FF),  // stride   256 -- flushes 3..5
    (500,   2 * 1024 * 1024, 0x03FF),  // stride  1024 -- flushes 6..8
    (1000,  8 * 1024 * 1024, 0x3FFF),  // stride 16384 -- flushes 9..11
    (2000, 16 * 1024 * 1024, 0x7FFF),  // stride 32768 -- steady state, flushes 12+
];

const FLUSHES_PER_STEP: u32 = 3;
const MAX_STEP: u32 = (STEPS.len() - 1) as u32;

/// Shared across all workers. Cheap to poll, only meaningfully active
/// (for the time-based trigger) when stdout is a tty -- see
/// `detect_output_kind`. The size-based batch hint applies regardless.
#[repr(align(64))]
pub struct FlushPacer {
    enabled:     bool,

    start:       Instant,

    state:       AtomicU64,    // [63:32] last flush ms | [31:0] step
    flush_count: AtomicU32,
}

impl FlushPacer {
    #[inline]
    pub fn new(enabled: bool) -> Self {
        Self {
            enabled,
            start: Instant::now(),
            state: AtomicU64::new(0),
            flush_count: AtomicU32::new(0)
        }
    }

    /// One atomic load. Returns (should_flush, batch_bytes, next_check_mask).
    #[inline]
    pub fn poll(&self, has_pending: bool) -> (bool, u32, usize) {
        let packed = self.state.load(Ordering::Relaxed);
        let step = (packed & 0xFFFF_FFFF) as usize;
        let (interval, batch, mask) = STEPS[step];

        let should_flush = self.enabled && has_pending && {
            let now = self.start.elapsed().as_millis() as u32;
            let last = (packed >> 32) as u32;
            now.wrapping_sub(last) >= interval
        };

        (should_flush, batch, mask)
    }

    #[inline]
    pub fn record_flush(&self) {
        let now = if self.enabled {
            self.start.elapsed().as_millis() as u32
        } else {
            0  // Never read, since should_flush short-circuits on !enabled
        };

        let n = self.flush_count.fetch_add(1, Ordering::Relaxed) + 1;
        let step = (n / FLUSHES_PER_STEP).min(MAX_STEP);

        self.state.store(((now as u64) << 32) | step as u64, Ordering::Relaxed);
    }
}
