use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{writeln_blue, writeln_green};

#[derive(Default)]
pub struct Stats {
    pub files_searched: usize,
    pub files_encountered: usize,
    pub files_contained_matches: usize,

    pub bytes_searched: usize,

    pub symlinks_followed: usize,
    pub symlinks_broken: usize,

    pub files_skipped_large: usize,
    pub files_skipped_unreadable: usize,
    pub files_skipped_as_binary_due_to_ext: usize,
    pub files_skipped_as_binary_due_to_probe: usize,
    pub files_skipped_gitignore: usize,
    pub files_skipped_by_cache: usize,

    pub dirs_skipped_common: usize,
    pub dirs_skipped_gitignore: usize,
    pub dirs_encountered: usize,
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_files = self.files_encountered;

        let total_dirs = self.dirs_encountered
            + self.dirs_skipped_common
            + self.dirs_skipped_gitignore;

        let total_symlinks = self.symlinks_followed + self.symlinks_broken;

        writeln_green!(f, "\nSearch complete")?;
        writeln_blue!(f, "Files Summary:")?;

        macro_rules! file_row {
            ($label:expr, $count:expr) => {
                let pct = if total_files == 0 { 0.0 } else { ($count as f64 / total_files as f64) * 100.0 };
                writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
            };
        }

        file_row!("Files encountered", self.files_encountered);
        file_row!("Files searched", self.files_searched);
        file_row!("Files contained matches", self.files_contained_matches);
        file_row!("Skipped (large)", self.files_skipped_large);
        file_row!("Skipped (binary ext)", self.files_skipped_as_binary_due_to_ext);
        file_row!("Skipped (binary probe)", self.files_skipped_as_binary_due_to_probe);
        file_row!("Skipped (unreadable)", self.files_skipped_unreadable);
        file_row!("Skipped (gitignore)", self.files_skipped_gitignore);
        file_row!("Skipped (cache)", self.files_skipped_by_cache);

        if total_symlinks > 0 {
            writeln_blue!(f, "\nSymlinks Summary:")?;
            macro_rules! symlink_row {
                ($label:expr, $count:expr) => {
                    let pct = if total_symlinks == 0 { 0.0 } else { ($count as f64 / total_symlinks as f64) * 100.0 };
                    writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
                };
            }
            symlink_row!("Total symlinks", total_symlinks);
            symlink_row!("Followed successfully", self.symlinks_followed);
            symlink_row!("Broken/skipped", self.symlinks_broken);
        }

        writeln_blue!(f, "\nBytes Summary:")?;
        macro_rules! bytes_row {
            ($label:expr, $count:expr) => {
                writeln!(f, "  {:<25} {:>12}", $label, $crate::util::format_bytes($count))?;
            };
        }

        bytes_row!("Bytes searched", self.bytes_searched);

        writeln_blue!(f, "\nDirectories Summary:")?;
        macro_rules! dir_row {
            ($label:expr, $count:expr) => {
                let pct = if total_dirs == 0 { 0.0 } else { ($count as f64 / total_dirs as f64) * 100.0 };
                writeln!(f, "  {:<25} {:>8} ({:>5.1}%)", $label, $count, pct)?;
            };
        }

        dir_row!("Dirs encountered", self.dirs_encountered);
        dir_row!("Skipped (common)", self.dirs_skipped_common);
        dir_row!("Skipped (gitignore)", self.dirs_skipped_gitignore);

        Ok(())
    }
}

impl Stats {
    #[inline]
    pub fn merge_into(&self, shared: &AtomicStats) {
        shared.files_encountered.fetch_add(self.files_encountered as _, Ordering::Relaxed);
        shared.files_searched.fetch_add(self.files_searched as _, Ordering::Relaxed);
        shared.bytes_searched.fetch_add(self.bytes_searched as _, Ordering::Relaxed);
        shared.files_skipped_large.fetch_add(self.files_skipped_large as _, Ordering::Relaxed);
        shared.files_skipped_as_binary_due_to_ext.fetch_add(self.files_skipped_as_binary_due_to_ext as _, Ordering::Relaxed);
        shared.files_skipped_as_binary_due_to_probe.fetch_add(self.files_skipped_as_binary_due_to_probe as _, Ordering::Relaxed);
        shared.files_skipped_gitignore.fetch_add(self.files_skipped_gitignore as _, Ordering::Relaxed);
        shared.files_skipped_by_cache.fetch_add(self.files_skipped_by_cache as _, Ordering::Relaxed);
        shared.files_contained_matches.fetch_add(self.files_contained_matches as _, Ordering::Relaxed);
        shared.dirs_encountered.fetch_add(self.dirs_encountered as _, Ordering::Relaxed);
        shared.dirs_skipped_common.fetch_add(self.dirs_skipped_common as _, Ordering::Relaxed);
        shared.dirs_skipped_gitignore.fetch_add(self.dirs_skipped_gitignore as _, Ordering::Relaxed);
        shared.symlinks_followed.fetch_add(self.symlinks_followed as _, Ordering::Relaxed);
        shared.symlinks_broken.fetch_add(self.symlinks_broken as _, Ordering::Relaxed);
    }
}

pub struct AtomicStats {
    pub files_encountered: AtomicU64,
    pub files_searched: AtomicU64,
    pub files_contained_matches: AtomicU64,
    pub bytes_searched: AtomicU64,
    pub dirs_encountered: AtomicU64,
    pub dirs_skipped_common: AtomicU64,
    pub dirs_skipped_gitignore: AtomicU64,
    pub files_skipped_large: AtomicU64,
    pub files_skipped_as_binary_due_to_ext: AtomicU64,
    pub files_skipped_as_binary_due_to_probe: AtomicU64,
    pub files_skipped_gitignore: AtomicU64,
    pub files_skipped_by_cache: AtomicU64,
    pub symlinks_followed: AtomicU64,
    pub symlinks_broken: AtomicU64,
}

impl Default for AtomicStats {
    fn default() -> Self {
        Self::new()
    }
}

impl AtomicStats {
    pub fn new() -> Self {
        Self {
            files_encountered: AtomicU64::new(0),
            files_searched: AtomicU64::new(0),
            files_contained_matches: AtomicU64::new(0),
            bytes_searched: AtomicU64::new(0),
            dirs_encountered: AtomicU64::new(0),
            dirs_skipped_common: AtomicU64::new(0),
            dirs_skipped_gitignore: AtomicU64::new(0),
            files_skipped_large: AtomicU64::new(0),
            files_skipped_as_binary_due_to_ext: AtomicU64::new(0),
            files_skipped_as_binary_due_to_probe: AtomicU64::new(0),
            files_skipped_gitignore: AtomicU64::new(0),
            files_skipped_by_cache: AtomicU64::new(0),
            symlinks_followed: AtomicU64::new(0),
            symlinks_broken: AtomicU64::new(0),
        }
    }

    pub fn to_stats(&self) -> Stats {
        Stats {
            files_skipped_unreadable: 0,
            files_encountered: self.files_encountered.load(Ordering::Relaxed) as _,
            files_searched: self.files_searched.load(Ordering::Relaxed) as _,
            files_contained_matches: self.files_contained_matches.load(Ordering::Relaxed) as _,
            bytes_searched: self.bytes_searched.load(Ordering::Relaxed) as _,
            dirs_encountered: self.dirs_encountered.load(Ordering::Relaxed) as _,
            dirs_skipped_common: self.dirs_skipped_common.load(Ordering::Relaxed) as _,
            dirs_skipped_gitignore: self.dirs_skipped_gitignore.load(Ordering::Relaxed) as _,
            files_skipped_large: self.files_skipped_large.load(Ordering::Relaxed) as _,
            files_skipped_as_binary_due_to_ext: self.files_skipped_as_binary_due_to_ext.load(Ordering::Relaxed) as _,
            files_skipped_as_binary_due_to_probe: self.files_skipped_as_binary_due_to_probe.load(Ordering::Relaxed) as _,
            files_skipped_gitignore: self.files_skipped_gitignore.load(Ordering::Relaxed) as _,
            files_skipped_by_cache: self.files_skipped_by_cache.load(Ordering::Relaxed) as _,
            symlinks_followed: self.symlinks_followed.load(Ordering::Relaxed) as _,
            symlinks_broken: self.symlinks_broken.load(Ordering::Relaxed) as _,
        }
    }
}

