use std::fmt;
use std::io;

/// All recoverable failure modes rawgrep can encounter.
#[derive(Debug)]
pub enum Error {
    /// The regex / literal pattern supplied by the caller is not valid.
    InvalidPattern(Box<str>),

    /// The requested path could not be canonicalized (doesn't exist, bad
    /// symlink, etc.).
    PathNotFound { path: Box<str>, source: io::Error },

    /// Auto-detection of the block device for a path failed.
    DeviceDetectionFailed(io::Error),

    /// The explicitly supplied (or auto-detected) device path does not exist.
    DeviceNotFound(Box<str>),

    /// The process lacks the privileges needed to open the raw device.
    /// Suggest `sudo` or `CAP_DAC_READ_SEARCH`.
    PermissionDenied(Box<str>),

    /// The device was opened but the on-disk magic doesn't match any known
    /// filesystem (ext4 / APFS / NTFS).
    UnknownFilesystem(Box<str>),

    /// The superblock / boot-sector data is present but structurally invalid.
    /// Includes a hint for ext4 (partition vs whole-disk confusion).
    InvalidFilesystem { fs: Box<str>, source: io::Error, hint: Option<Box<str>> },

    /// The search root path could not be located inside the filesystem image.
    RootNotFound { path: Box<str>, device: Box<str>, source: io::Error },

    /// The `Matcher` (regex engine) failed to initialise.
    MatcherInit(io::Error),

    /// Any other I/O error that escaped the above categories.
    Io(io::Error),
}

impl fmt::Display for Error {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Error::InvalidPattern(p) => {
                write!(f, "invalid pattern '{p}'\n")?;
                write!(f, "tip: test your regex with `grep -E` or a regex tester before running\n")?;
                write!(f, "patterns must be valid regex or a literal/alternation extractable form")
            }
            Error::PathNotFound { path, source } => {
                write!(f, "couldn't canonicalize '{path}': {source}")
            }
            Error::DeviceDetectionFailed(e) => {
                write!(f, "couldn't auto-detect partition: {e}")
            }
            Error::DeviceNotFound(dev) => {
                write!(f, "device or partition not found: '{dev}'")
            }
            Error::PermissionDenied(dev) => {
                write!(
                    f,
                    "permission denied opening '{dev}'\n\
                     help: try running with sudo/root, or grant the binary \
                     CAP_DAC_READ_SEARCH:\n  \
                     sudo setcap cap_dac_read_search=eip <path-to-binary>"
                )
            }
            Error::UnknownFilesystem(dev) => {
                write!(f, "unrecognised filesystem on '{dev}' (not ext4, APFS, or NTFS)")
            }
            Error::InvalidFilesystem { fs, source, hint } => {
                write!(f, "invalid {fs} filesystem: {source}")?;
                if let Some(h) = hint {
                    write!(f, "\n{h}")?;
                }
                Ok(())
            }
            Error::RootNotFound { path, device, source } => {
                write!(f, "couldn't find '{path}' in '{device}': {source}")
            }
            Error::MatcherInit(e) => {
                write!(f, "failed to build matcher: {e}")
            }
            Error::Io(e) => write!(f, "{e}"),
        }
    }
}

impl std::error::Error for Error {
    #[inline]
    fn source(&self) -> Option<&(dyn std::error::Error + 'static)> {
        match self {
            Error::PathNotFound    { source, .. } => Some(source),
            Error::DeviceDetectionFailed(e)       => Some(e),
            Error::InvalidFilesystem { source, .. } => Some(source),
            Error::RootNotFound    { source, .. } => Some(source),
            Error::MatcherInit(e)                 => Some(e),
            Error::Io(e)                          => Some(e),
            _ => None,
        }
    }
}

impl From<io::Error> for Error {
    #[inline]
    fn from(e: io::Error) -> Self {
        Error::Io(e)
    }
}
