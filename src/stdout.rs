use std::fs::File;
use std::io::{self, Write};
use std::mem::ManuallyDrop;

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle};

/// Owns the process's stdout descriptor/handle directly, bypassing
/// std::io::Stdout's internal LineWriter, which flushes on every '\n'
/// no matter what buffering is wrapped around it.
///
/// ManuallyDrop so dropping this value never closes the descriptor or
/// handle out from under the rest of the process, the OS owns it, not us.
pub struct RawStdout(ManuallyDrop<File>);

impl RawStdout {
    pub fn new() -> Self {
        #[cfg(unix)]
        let file = unsafe { File::from_raw_fd(io::stdout().as_raw_fd()) };

        #[cfg(windows)]
        let file = unsafe { File::from_raw_handle(io::stdout().as_raw_handle()) };

        RawStdout(ManuallyDrop::new(file))
    }
}

impl Write for RawStdout {
    #[inline]
    fn write(&mut self, buf: &[u8]) -> io::Result<usize> {
        self.0.write(buf)
    }

    #[inline]
    fn write_all(&mut self, buf: &[u8]) -> io::Result<()> {
        self.0.write_all(buf)
    }

    #[inline]
    fn flush(&mut self) -> io::Result<()> {
        self.0.flush()
    }
}

unsafe impl Send for RawStdout {}
