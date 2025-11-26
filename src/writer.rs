use std::io::{self, BufWriter, IsTerminal, Write};

use crate::{NON_TTY_BATCH_SIZE, TTY_BATCH_SIZE};

pub struct SmoothWriter {
    writer: BufWriter<io::Stdout>,
    size_since_last_flush: usize,
    is_tty: bool,
}

impl SmoothWriter {
    #[inline(always)]
    pub fn new() -> Self {
        Self {
            writer: BufWriter::with_capacity(NON_TTY_BATCH_SIZE, io::stdout()),
            size_since_last_flush: 0,
            is_tty: io::stdout().is_terminal(),
        }
    }

    #[inline(always)]
    pub fn write_int(&mut self, mut n: usize) -> io::Result<()> {
        let mut buf = [0u8; 20];
        let mut i = buf.len();

        if n == 0 {
            return self.write_all(b"0");
        }

        while n > 0 {
            i -= 1;
            buf[i] = b'0' + (n % 10) as u8;
            n /= 10;
        }

        self.write_all(&buf[i..])
    }

    #[inline(always)]
    pub fn write_all(&mut self, data: &[u8]) -> io::Result<()> {
        self.writer.write_all(data)?;
        self.size_since_last_flush += data.len();

        if self.is_tty {
            // flush every ~4KB or on newline for instant feedback
            if self.size_since_last_flush >= TTY_BATCH_SIZE || data.ends_with(b"\n") {
                self.flush()?;
            }
        } else {
            // Piped/redirected: use larger batches for throughput
            if self.size_since_last_flush >= NON_TTY_BATCH_SIZE {
                self.flush()?;
            }
        }

        Ok(())
    }

    #[inline(always)]
    pub fn flush(&mut self) -> io::Result<()> {
        self.writer.flush()?;
        self.size_since_last_flush = 0;
        Ok(())
    }
}

