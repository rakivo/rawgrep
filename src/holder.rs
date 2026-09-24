//
// The holder is a hidden re-exec of this binary. It mmap's the cache files and
// mlock's them so the kernel can't evict or swap them. Clients never talk to it,
// they mmap the same files and share the same physical pages, that we know are
// resident in RAM.
//
// Liveness and election use a single flock on 'holder.lock'. The kernel drops the
// lock however the holder dies, so there are no PID files or sockets to go stale.
//

use std::fs::{File, OpenOptions};
use std::os::fd::AsRawFd;
use std::os::unix::fs::MetadataExt;
use std::path::{Path, PathBuf};
use std::process::{Command, Stdio};
use std::time::{Duration, SystemTime};

use memmap2::Mmap;

const ENV:      &str      = "__RAWGREP_HOLDER";
const POLL:      Duration = Duration::from_secs(2);
const IDLE_EXIT: Duration = Duration::from_secs(30 * 60);

fn lock_path(any_cache_file: &Path) -> PathBuf {
    any_cache_file.with_file_name("holder.lock")
}

fn open_lock(path: &Path) -> Option<File> {
    let f = OpenOptions::new()
        .create(true).write(true).open(path).ok()
        .or_else(|| OpenOptions::new().read(true).open(path).ok())?;

    _ = crate::cache::fix_ownership(path);
    Some(f)
}

pub fn run_if_holder() {
    if let Some(list) = std::env::var_os(ENV) {
        let paths = std::env::split_paths(&list).collect::<Vec<_>>();
        run(paths);
    }
}

/// Client side: make sure a holder is alive for these cache files.
/// Cheap when one exists (open + flock + close). Never fails hard.
pub fn ensure(paths: &[PathBuf]) {
    let Some(first) = paths.first()            else { return };
    let Some(f) = open_lock(&lock_path(first)) else { return };

    let fd = f.as_raw_fd();

    if unsafe { libc::flock(fd, libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        //
        // A holder is alive. Bump the lock file's mtime so it knows we're still in use.
        //
        unsafe { libc::futimens(fd, std::ptr::null()) };
        return;
    }

    //
    // Nobody holds it, release and spawn a new one.
    // If two clients race here, the losing holder fails
    // its own flock and exits immediately.
    //
    unsafe { libc::flock(fd, libc::LOCK_UN) };
    drop(f);

    let Ok(exe) = std::env::current_exe()        else { return };
    let Ok(joined) = std::env::join_paths(paths) else { return };

    //
    // Rust opens fds with O_CLOEXEC, so the holder doesn't inherit any client locks.
    //
    _ = Command::new(exe)
        .env(ENV, joined)
        .stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn();
}

fn run(paths: Vec<PathBuf>) -> ! {
    let Some(first) = paths.first() else { std::process::exit(0) };
    let lock = lock_path(first);

    let Some(lock_file) = open_lock(&lock) else {
        std::process::exit(0)
    };

    if unsafe { libc::flock(lock_file.as_raw_fd(), libc::LOCK_EX | libc::LOCK_NB) } != 0 {
        std::process::exit(0);  // Another holder already won
    }

    unsafe { libc::setsid() };  // Detach from the invoking terminal/session

    raise_memlock_soft_to_hard();

    let mut pinned: Vec<Option<(u64, Mmap)>> = paths.iter().map(|_| None).collect();
    loop {
        for (slot, path) in pinned.iter_mut().zip(&paths) {
            let current = std::fs::metadata(path).ok().map(|m| m.ino());

            //
            // Publishing is tmp+rename, so a new cache means a new inode. Our old
            // mapping keeps the old inode alive (so its number can't be reused).
            //
            let stale = slot.as_ref().map_or(true, |(ino, _)| Some(*ino) != current);
            if stale {
                *slot = None;       // munmap the old mapping, releasing its lock
                *slot = pin(path);  // None if the file is missing or not published yet
            }
        }

        std::thread::sleep(POLL);

        let idle = match std::fs::metadata(&lock) {
            Ok(m) => m.modified().ok()
                .and_then(|t| SystemTime::now().duration_since(t).ok())
                .unwrap_or_default(),

            Err(_) => std::process::exit(0), // Lock deleted: cache was wiped
        };

        if idle > IDLE_EXIT {
            std::process::exit(0);           // Lock_file drops with the process, freeing the flock
        }

        _ = &lock_file;                      // Keep the flock fd alive for the whole loop
    }
}

fn pin(path: &Path) -> Option<(u64, Mmap)> {
    let f = File::open(path).ok()?;
    let meta = f.metadata().ok()?;
    if meta.len() == 0 {
        return None;
    }

    let map = unsafe { Mmap::map(&f).ok()? };

    //
    // mlock populates and locks every page. If it fails, RLIMIT_MEMLOCK is too low
    // (or a cgroup limit is in the way); fall back to a WILLNEED hint.
    //
    if unsafe { libc::mlock(map.as_ptr().cast(), map.len()) } != 0 {
        unsafe { libc::madvise(map.as_ptr() as *mut _, map.len(), libc::MADV_WILLNEED) };
    }

    Some((meta.ino(), map))
}

fn raise_memlock_soft_to_hard() {
    unsafe {
        let mut rl: libc::rlimit = std::mem::zeroed();
        if libc::getrlimit(libc::RLIMIT_MEMLOCK, &mut rl) == 0 && rl.rlim_cur != rl.rlim_max {
            rl.rlim_cur = rl.rlim_max;
            libc::setrlimit(libc::RLIMIT_MEMLOCK, &rl);
        }
    }
}
