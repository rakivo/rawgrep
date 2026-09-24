use crate::tracy;
use crate::index_::Index_;
use crate::stdout::{RawStdout, IOV_MAX};
use crate::worker::OUTPUTTER_FLUSH_BATCH;
use crate::output::{OutputSlab, OutputSlotOwnedOverflow};

use std::io::{self, Write, IoSlice};

use crossbeam_channel::{Sender, Receiver};

pub enum OutputMessage {
    Slot { slab: &'static OutputSlab, slot: u16, len: u32 },
    Owned(OutputSlotOwnedOverflow),
    FlushReq,
}

pub enum PendingBuf {
    Slot { slab: &'static OutputSlab, slot: u16, len: u32 },
    Owned(OutputSlotOwnedOverflow),
}

impl PendingBuf {
    /// # Safety
    /// Caller must hold read-side
    #[inline]
    pub unsafe fn as_slice(&self) -> &[u8] {
        match self {
            PendingBuf::Slot { slab, slot, len, .. } => unsafe { slab.slot(*slot as usize) }.get_(..*len as usize),
            PendingBuf::Owned(v) => v,
        }
    }
}

pub struct OutputWorker {
    pub rx: Receiver<OutputMessage>,
    pub flush_ack_tx: Sender<()>,
    pub writer: RawStdout,

    pub batch:       Vec<PendingBuf>,
    pub batch_bytes: usize,
    pub iov_scratch: Vec<IoSlice<'static>>,
}

impl OutputWorker {
    #[inline]
    pub fn run(mut self) {
        let _span = tracy::span!("OutputThread::run");

        'outer: while let Ok(msg) = self.rx.recv() {
            if !self.absorb(msg) { break 'outer }

            while let Ok(msg) = self.rx.try_recv() {
                if !self.absorb(msg) { break 'outer } // absorb() already flushes when full
            }

            if self.flush_batch().is_err() { break 'outer }
        }

        _ = self.flush_batch();
    }

    #[inline]
    fn absorb(&mut self, msg: OutputMessage) -> bool {
        match msg {
            OutputMessage::Slot { slab, slot, len } => {
                self.batch_bytes += len as usize;
                self.batch.push(PendingBuf::Slot { slab, slot, len });
            }

            OutputMessage::Owned(v) => {
                self.batch_bytes += v.len();
                self.batch.push(PendingBuf::Owned(v));
            }

            OutputMessage::FlushReq => {
                if self.flush_batch().is_err() { return false; }
                _ = self.flush_ack_tx.send(());

                return true;
            }
        }

        if self.batch_bytes >= OUTPUTTER_FLUSH_BATCH || self.batch.len() >= IOV_MAX {
            if self.flush_batch().is_err() {
                return false;
            }
        }

        true
    }

    #[inline]
    fn flush_batch(&mut self) -> io::Result<()> {
        if self.batch.is_empty() { return Ok(()) }

        self.flush_batch_writev()
    }

    #[inline]
    fn flush_batch_writev(&mut self) -> io::Result<()> {
        self.iov_scratch.clear();

        for b in &self.batch {
            // SAFETY: Slot ownership moved to us via the channel send;
            // the sender relinquished it and cannot touch it again until we release it below.
            let bytes = unsafe { b.as_slice() };

            // SAFETY: Every referent here is kept alive by an Arc/Vec still
            // sitting in self.batch, which outlives this function's use of
            // iov_scratch (we don't drain batch until after writev_all() returns Ok).
            let bytes: &'static [u8] = unsafe { std::mem::transmute(bytes) };
            self.iov_scratch.push(IoSlice::new(bytes));
        }

        self.writev_all()?;

        for b in self.batch.drain(..) {
            if let PendingBuf::Slot { slab, slot, .. } = b {
                slab.release(slot as usize);
            }
        }
        self.batch_bytes = 0;

        Ok(())
    }

    #[inline]
    fn writev_all(&mut self) -> io::Result<()> {
        let mut slices = &mut self.iov_scratch[..];
        while !slices.is_empty() {
            match self.writer.write_vectored(slices) {
                Ok(0) => return Err(io::Error::new(io::ErrorKind::WriteZero, "write_vectored wrote 0")),
                Ok(n) => IoSlice::advance_slices(&mut slices, n),

                Err(ref e) if e.kind() == io::ErrorKind::Interrupted => continue,
                Err(e)                 => return Err(e),
            }
        }

        Ok(())
    }
}
