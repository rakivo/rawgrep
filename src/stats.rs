use std::fmt::Display;
use std::sync::atomic::{AtomicU64, Ordering};

use crate::{writeln_blue, writeln_green};

#[derive(Default)]
pub struct Stats {
    // Hotter
    pub bytes_searched: u64,
    pub files_encountered: u32,
    pub files_searched: u32,
    pub files_skipped_by_cache: u32,
    pub dirs_encountered: u32,

    pub files_contained_matches: u32,
    pub files_skipped_as_binary_cached: u32,
    pub files_skipped_as_binary_due_to_probe: u32,

    pub node_cache_hits: u32,
    pub node_cache_misses: u32,

    pub time_spent_fragment_presence_checking_in_nanos: u64,
    pub time_spent_finding_and_printing_matches_in_nanos: u64,

    // Colder
    pub files_skipped_gitignore: u32,
    pub files_skipped_large: u32,
    pub files_skipped_unreadable: u32,
    pub dirs_skipped_gitignore: u32,
    pub dirs_skipped_reserved: u32,
    pub dirs_skipped_path_too_long: u32,
}

impl Display for Stats {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        let total_files = self.files_encountered;

        let total_dirs = self.dirs_encountered;

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
        file_row!("Skipped (binary probe)", self.files_skipped_as_binary_due_to_probe);
        file_row!("Skipped (binary cached)", self.files_skipped_as_binary_cached);
        file_row!("Skipped (unreadable)", self.files_skipped_unreadable);
        file_row!("Skipped (gitignore)", self.files_skipped_gitignore);
        file_row!("Skipped (cache)", self.files_skipped_by_cache);

        writeln_blue!(f, "\nBytes Summary:")?;
        macro_rules! bytes_row {
            ($label:expr, $count:expr) => {
                writeln!(f, "  {:<25} {:>12}", $label, $crate::util::format_bytes($count as _))?;
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
        dir_row!("Skipped (gitignore)", self.dirs_skipped_gitignore);
        dir_row!("Skipped (reserved)", self.dirs_skipped_reserved);
        if self.dirs_skipped_path_too_long > 0 {
            dir_row!("Skipped (path too long)", self.dirs_skipped_path_too_long);
        }

        writeln_blue!(f, "\nNode Cache:")?;
        writeln!(f, "  Node Cache Hits:   {}", self.node_cache_hits)?;
        writeln!(f, "  Node Cache Misses: {}", self.node_cache_misses)?;

        {
            writeln_blue!(f, "\nTimings:")?;

            macro_rules! timing_row {
                ($label:expr, $nanos:expr) => {
                    let nanos = $nanos;
                    let (time, unit) = if nanos < 1_000 {
                        (nanos as f64, "ns")
                    } else if nanos < 1_000_000 {
                        (nanos as f64 / 1_000.0, "us")
                    } else if nanos < 1_000_000_000 {
                        (nanos as f64 / 1_000_000.0, "ms")
                    } else {
                        (nanos as f64 / 1_000_000_000.0, "s")
                    };

                    writeln!(f, "  {:<25} {time:.3}{unit}", $label)?;
                };
            }

            timing_row!(
                "Fragment Presence Checks",
                self.time_spent_fragment_presence_checking_in_nanos
            );
            timing_row!(
                "Find and Print Matches",
                self.time_spent_finding_and_printing_matches_in_nanos
            );
        }

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
        shared.node_cache_hits.fetch_add(self.node_cache_hits as _, Ordering::Relaxed);
        shared.time_spent_finding_and_printing_matches_in_nanos.fetch_add(self.time_spent_finding_and_printing_matches_in_nanos as _, Ordering::Relaxed);
        shared.node_cache_misses.fetch_add(self.node_cache_misses as _, Ordering::Relaxed);
        shared.files_skipped_as_binary_cached.fetch_add(self.files_skipped_as_binary_cached as _, Ordering::Relaxed);
        shared.files_skipped_as_binary_due_to_probe.fetch_add(self.files_skipped_as_binary_due_to_probe as _, Ordering::Relaxed);
        shared.files_skipped_gitignore.fetch_add(self.files_skipped_gitignore as _, Ordering::Relaxed);
        shared.files_skipped_by_cache.fetch_add(self.files_skipped_by_cache as _, Ordering::Relaxed);
        shared.files_contained_matches.fetch_add(self.files_contained_matches as _, Ordering::Relaxed);
        shared.dirs_encountered.fetch_add(self.dirs_encountered as _, Ordering::Relaxed);
        shared.dirs_skipped_path_too_long.fetch_add(self.dirs_skipped_path_too_long as _, Ordering::Relaxed);
        shared.time_spent_fragment_presence_checking_in_nanos.fetch_add(self.time_spent_fragment_presence_checking_in_nanos as _, Ordering::Relaxed);
        shared.dirs_skipped_gitignore.fetch_add(self.dirs_skipped_gitignore as _, Ordering::Relaxed);
        shared.dirs_skipped_reserved.fetch_add(self.dirs_skipped_reserved as _, Ordering::Relaxed);
    }
}

pub struct AtomicStats {
    pub files_encountered: AtomicU64,
    pub files_searched: AtomicU64,
    pub files_contained_matches: AtomicU64,
    pub bytes_searched: AtomicU64,
    pub node_cache_misses: AtomicU64,
    pub node_cache_hits: AtomicU64,
    pub dirs_encountered: AtomicU64,
    pub dirs_skipped_gitignore: AtomicU64,
    pub dirs_skipped_reserved: AtomicU64,
    pub time_spent_fragment_presence_checking_in_nanos: AtomicU64,
    pub dirs_skipped_path_too_long: AtomicU64,
    pub files_skipped_large: AtomicU64,
    pub files_skipped_as_binary_cached: AtomicU64,
    pub time_spent_finding_and_printing_matches_in_nanos: AtomicU64,
    pub files_skipped_as_binary_due_to_probe: AtomicU64,
    pub files_skipped_gitignore: AtomicU64,
    pub files_skipped_by_cache: AtomicU64,
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
            files_skipped_as_binary_cached: AtomicU64::new(0),
            dirs_encountered: AtomicU64::new(0),
            time_spent_finding_and_printing_matches_in_nanos: AtomicU64::new(0),
            time_spent_fragment_presence_checking_in_nanos: AtomicU64::new(0),
            dirs_skipped_gitignore: AtomicU64::new(0),
            dirs_skipped_reserved: AtomicU64::new(0),
            dirs_skipped_path_too_long: AtomicU64::new(0),
            files_skipped_large: AtomicU64::new(0),
            node_cache_misses: AtomicU64::new(0),
            node_cache_hits: AtomicU64::new(0),
            files_skipped_as_binary_due_to_probe: AtomicU64::new(0),
            files_skipped_gitignore: AtomicU64::new(0),
            files_skipped_by_cache: AtomicU64::new(0),
        }
    }

    pub fn to_stats(&self) -> Stats {
        Stats {
            files_skipped_unreadable: 0,
            time_spent_fragment_presence_checking_in_nanos: self.time_spent_fragment_presence_checking_in_nanos.load(Ordering::Relaxed) as _,
            time_spent_finding_and_printing_matches_in_nanos: self.time_spent_finding_and_printing_matches_in_nanos.load(Ordering::Relaxed) as _,
            dirs_skipped_path_too_long: self.dirs_skipped_path_too_long.load(Ordering::Relaxed) as _,
            files_encountered: self.files_encountered.load(Ordering::Relaxed) as _,
            node_cache_hits: self.node_cache_hits.load(Ordering::Relaxed) as _,
            node_cache_misses: self.node_cache_misses.load(Ordering::Relaxed) as _,
            files_searched: self.files_searched.load(Ordering::Relaxed) as _,
            files_contained_matches: self.files_contained_matches.load(Ordering::Relaxed) as _,
            bytes_searched: self.bytes_searched.load(Ordering::Relaxed) as _,
            dirs_encountered: self.dirs_encountered.load(Ordering::Relaxed) as _,
            dirs_skipped_gitignore: self.dirs_skipped_gitignore.load(Ordering::Relaxed) as _,
            dirs_skipped_reserved: self.dirs_skipped_reserved.load(Ordering::Relaxed) as _,
            files_skipped_large: self.files_skipped_large.load(Ordering::Relaxed) as _,
            files_skipped_as_binary_cached: self.files_skipped_as_binary_cached.load(Ordering::Relaxed) as _,
            files_skipped_as_binary_due_to_probe: self.files_skipped_as_binary_due_to_probe.load(Ordering::Relaxed) as _,
            files_skipped_gitignore: self.files_skipped_gitignore.load(Ordering::Relaxed) as _,
            files_skipped_by_cache: self.files_skipped_by_cache.load(Ordering::Relaxed) as _,
        }
    }
}
