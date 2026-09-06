use std::fs::File;
use std::mem::ManuallyDrop;
use std::io::{self, Write, IoSlice};

#[cfg(unix)]
use std::os::unix::io::{AsRawFd, FromRawFd, RawFd};

#[cfg(windows)]
use std::os::windows::io::{AsRawHandle, FromRawHandle};

#[cfg(unix)]
#[derive(Clone, Copy, PartialEq)]
enum OutputKind { Tty, Pipe, File, Other }

#[cfg(unix)]
fn detect_output_kind(fd: std::os::unix::io::RawFd) -> OutputKind {
    unsafe {
        if libc::isatty(fd) == 1 {
            return OutputKind::Tty;
        }

        let mut stat: libc::stat = std::mem::zeroed();
        if libc::fstat(fd, &mut stat) == 0 {
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFIFO {
                return OutputKind::Pipe;
            }
            if (stat.st_mode & libc::S_IFMT) == libc::S_IFREG {
                return OutputKind::File;
            }
        }
    }

    OutputKind::Other
}

/// Owns the process's stdout descriptor/handle directly, bypassing
/// std::io::Stdout's internal LineWriter, which flushes on every '\n'
/// no matter what buffering is wrapped around it.
///
/// ManuallyDrop so dropping this value never closes the descriptor or
/// handle out from under the rest of the process, the OS owns it, not us.
pub struct RawStdout(ManuallyDrop<File>);

impl RawStdout {
    pub fn new() -> Option<(Self, bool, RawFd)> {
        #[cfg(unix)]
        let file = unsafe { File::from_raw_fd(io::stdout().as_raw_fd()) };

        #[cfg(unix)]
        let fd = file.as_raw_fd();

        #[cfg(unix)]
        if is_stdout_being_redirected_to_dev_null(fd) {
            return None;
        }

        #[cfg(windows)]
        let file = unsafe { File::from_raw_handle(io::stdout().as_raw_handle()) };

        let mut is_pipe = false;
        #[cfg(unix)] { // Grow the pipe buffer so the reader doesn't force to block as often
            if detect_output_kind(fd) == OutputKind::Pipe {
                is_pipe = true;

                const F_SETPIPE_SZ: i32 = 1031;
                unsafe { libc::fcntl(fd, F_SETPIPE_SZ, 1024 * 1024); }
            }
        }

        Some((RawStdout(ManuallyDrop::new(file)), is_pipe, fd))
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

    #[inline]
    fn write_vectored(&mut self, bufs: &[IoSlice<'_>]) -> io::Result<usize> {
        self.0.write_vectored(bufs)
    }
}

unsafe impl Send for RawStdout {}

pub const IOV_MAX: usize = 1024; // Linux UIO_MAXIOV

#[cfg(unix)]
fn is_stdout_being_redirected_to_dev_null(fd: i32) -> bool {
    use std::os::unix::fs::MetadataExt;

    let fd_path = format!("/proc/self/fd/{}", fd);
    let Ok(fd_meta) = std::fs::metadata(&fd_path) else { return false }; // follows the symlink, gives target's stat
    let Ok(null_meta) = std::fs::metadata("/dev/null") else { return false };

    fd_meta.dev() == null_meta.dev() && fd_meta.ino() == null_meta.ino()
}

#[cfg(target_os = "linux")]
pub mod vmsplice {
    use std::ffi::c_void;
    use std::io;
    use std::os::unix::io::RawFd;

    #[repr(C)]
    struct IoVec {
        iov_base: *mut c_void,
        iov_len: usize,
    }

    const SPLICE_F_NONBLOCK: u32 = 0x02;

    /// Attempts a non-blocking vmsplice of `buf` into the pipe `fd`.
    /// Returns Ok(n) for however many bytes the kernel accepted (may be
    /// less than buf.len(), including 0 if the pipe is full).
    ///
    /// SAFETY: caller must not touch/reuse the accepted portion of `buf`
    /// until the reader has consumed it, OR must know the kernel has
    /// already copied it out (true for our call site -- see release()
    /// timing in flush_batch_pipe). Only ever call this on a fd known to
    /// be a pipe.
    pub unsafe fn vmsplice_once(fd: RawFd, buf: &[u8]) -> io::Result<usize> {
        let iov = IoVec {
            iov_base: buf.as_ptr() as *mut c_void,
            iov_len: buf.len(),
        };

        let n = unsafe {
            libc::syscall(
                libc::SYS_vmsplice,
                fd,
                &iov as *const IoVec,
                1usize,
                SPLICE_F_NONBLOCK,
            )
        };

        if n < 0 {
            Err(io::Error::last_os_error())
        } else {
            Ok(n as usize)
        }
    }
}
