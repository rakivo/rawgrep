use std::alloc::{self, Layout};
use std::mem;
use std::ptr::{self, NonNull};
use std::slice;
use std::sync::atomic::{AtomicU32, Ordering};

#[repr(C)]
struct ThinArcInner {
    strong: AtomicU32,
    depth:  u16,
    len:    u32,
}

const HEADER_SIZE:  usize = mem::size_of::<ThinArcInner>();
const HEADER_ALIGN: usize = mem::align_of::<ThinArcInner>();

// Mirrors std Arc's MAX_REFCOUNT guard, sized for a 32-bit counter instead
// of usize. u32::MAX/2 clones would mean ~2 billion live ThinPathArcs
// pointing at one allocation.
const MAX_STRONG: u32 = u32::MAX / 2;

pub struct ThinPathArc {
    ptr: NonNull<ThinArcInner>,
}

unsafe impl Send for ThinPathArc {}
unsafe impl Sync for ThinPathArc {}

impl ThinPathArc {
    #[inline]
    pub fn new(depth: u16, bytes: &[u8]) -> Self {
        let len = u32::try_from(bytes.len()).expect("path longer than 4 GiB");
        let layout = Self::layout(bytes.len());

        unsafe {
            let raw = alloc::alloc(layout);
            if raw.is_null() {
                alloc::handle_alloc_error(layout);
            }

            (raw as *mut ThinArcInner).write(ThinArcInner {
                strong: AtomicU32::new(1),
                depth,
                len,
            });
            ptr::copy_nonoverlapping(bytes.as_ptr(), raw.add(HEADER_SIZE), bytes.len());

            ThinPathArc { ptr: NonNull::new_unchecked(raw as *mut ThinArcInner) }
        }
    }

    #[inline]
    fn layout(len: usize) -> Layout {
        let size = HEADER_SIZE.checked_add(len).expect("path length overflows layout size");
        Layout::from_size_align(size, HEADER_ALIGN).unwrap()
    }

    #[inline]
    fn inner(&self) -> &ThinArcInner {
        unsafe { self.ptr.as_ref() }
    }

    #[inline]
    pub fn depth(&self) -> u16 {
        self.inner().depth
    }

    #[inline]
    pub fn path_bytes(&self) -> &[u8] {
        let len = self.inner().len as usize;
        unsafe {
            let data = (self.ptr.as_ptr() as *const u8).add(HEADER_SIZE);
            slice::from_raw_parts(data, len)
        }
    }
}

impl Clone for ThinPathArc {
    fn clone(&self) -> Self {
        // Relaxed matches std Arc: we're only counting references here,
        // not publishing data through this increment.
        let old = self.inner().strong.fetch_add(1, Ordering::Relaxed);
        if old > MAX_STRONG {
            std::process::abort(); // guard against mem::forget-based overflow
        }

        ThinPathArc { ptr: self.ptr }
    }
}

impl Drop for ThinPathArc {
    fn drop(&mut self) {
        // Release on decrement + Acquire fence on the last decrement:
        // the same dance std Arc uses so the final dealloc happens-after
        // every prior read from every clone.
        if self.inner().strong.fetch_sub(1, Ordering::Release) != 1 {
            return;
        }

        std::sync::atomic::fence(Ordering::Acquire);
        unsafe {
            let len = self.inner().len as usize;
            alloc::dealloc(self.ptr.as_ptr() as *mut u8, Self::layout(len));
        }
    }
}

impl std::fmt::Debug for ThinPathArc {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ThinPathArc")
            .field("depth", &self.depth())
            .field("path", &String::from_utf8_lossy(self.path_bytes()))
            .finish()
    }
}
