use std::fs;

use nohash_hasher::IntMap; // This is an overkill @Speed

#[inline]
fn num_cpus() -> usize {
    std::thread::available_parallelism().unwrap().get()
}

#[derive(Debug, Clone)]
pub struct CoreTopology {
    pub p_cores: Box<[usize]>,
    pub e_cores: Box<[usize]>,
}

impl CoreTopology {
    /// Detect P-cores and E-cores on Linux
    pub fn detect() -> Self {
        let mut core_frequencies = IntMap::default();

        // -------------- Read base frequencies for all CPUs
        let entries = match fs::read_dir("/sys/devices/system/cpu") {
            Ok(entries) => entries,
            Err(_) => return Self::fallback(),
        };

        for entry in entries {
            let Ok(entry) = entry else { continue };
            let name = entry.file_name();
            let name_str = name.to_string_lossy();

            if !name_str.starts_with("cpu") {
                continue;
            }

            let cpu_num: usize = match name_str.strip_prefix("cpu")
                .and_then(|s| s.parse().ok())
            {
                Some(n) => n,
                None => continue,
            };

            let freq_path = format!("/sys/devices/system/cpu/cpu{cpu_num}/cpufreq/base_frequency");
            if let Ok(Ok(freq)) = fs::read_to_string(&freq_path).map(|f| f.trim().parse::<u64>()) {
                core_frequencies.insert(cpu_num, freq);
            }
        }

        if core_frequencies.is_empty() {
            return Self::fallback();
        }

        // --------- Find median frequency to separate P-cores from E-cores
        let mut freqs = core_frequencies.values().copied().collect::<Vec<_>>();
        freqs.sort_unstable();

        let threshold = if freqs.len() > 1 {
            (freqs[0] + freqs[freqs.len() - 1]) / 2
        } else {
            // single frequency type - no hybrid cores
            return Self::fallback();
        };

        let mut p_cores = Vec::new();
        let mut e_cores = Vec::new();

        for (cpu, freq) in core_frequencies {
            if freq >= threshold {
                p_cores.push(cpu);
            } else {
                e_cores.push(cpu);
            }
        }

        // sort for deterministic behavior
        p_cores.sort_unstable();
        e_cores.sort_unstable();

        if p_cores.is_empty() || e_cores.is_empty() {
            // no hybrid cores detected
            Self::fallback()
        } else {
            Self { p_cores: p_cores.into(), e_cores: e_cores.into() }
        }
    }

    /// Fallback when core detection fails - treat all cores as P-cores
    fn fallback() -> Self {
        let all_cores = (0..num_cpus()).collect::<Vec<_>>();

        Self {
            p_cores: all_cores.into(),
            e_cores: Box::default(),
        }
    }

    /// Get core ID for output thread, prefer E-core if available
    #[inline]
    pub fn output_core(&self) -> Option<usize> {
        self.e_cores.first().copied()
    }

    /// Get core IDs for worker threads, prefer P-core if available
    #[inline]
    pub fn worker_core(&self, worker_id: usize) -> usize {
        if self.p_cores.is_empty() {
            worker_id % num_cpus()
        } else {
            self.p_cores[worker_id % self.p_cores.len()]
        }
    }
}
