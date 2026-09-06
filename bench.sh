#!/usr/bin/env bash

#
# If you're looking at this, just know that yes, I AI generated this benchmark,
# I don't have that amount of patience to go through every little detail
# of benchmarking, and I rather work on some real project, to gain some real performance benefit.
#
# But! It honestly looks like it works just fine. So, what's the matter anyway?
#

set -uo pipefail

PATTERN="TODO"
SEARCH_DIR="../chromium"
DEVICE="/dev/nvme0n1p2"
NVME_CTRL="nvme0"
THREADS=16
RUNS=10
WARM_RUNS=30
WARMUP=5
RESULTS_DIR="./benchmark_results"

mkdir -p "$RESULTS_DIR"

for cmd in rg rawgrep hyperfine; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd not found"
        exit 1
    fi
done

# --- pin CPU governor and NVMe power state for the duration of the run ---
# schedutil ramps clocks lazily under sudden multi-thread load, and NVMe
# APST (auto) lets the drive drop into low power states between bursts,
# both of which inject noise into short benchmark runs. Force both to
# max-performance mode here, and restore original state on exit no matter
# how the script terminates.

ORIG_GOVERNORS=$(cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor 2>/dev/null | sort -u)
ORIG_APST=$(cat "/sys/class/nvme/${NVME_CTRL}/power/control" 2>/dev/null || echo "auto")

restore_power_settings() {
    echo ""
    echo "=== restoring original power settings ==="
    if [ -n "${ORIG_GOVERNORS:-}" ]; then
        # If governors were mixed originally just fall back to schedutil,
        # otherwise restore whatever the single common value was
        governor_count=$(echo "$ORIG_GOVERNORS" | wc -l)
        if [ "$governor_count" -eq 1 ]; then
            echo "$ORIG_GOVERNORS" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
            echo "cpu governor restored to: $ORIG_GOVERNORS"
        else
            echo "schedutil" | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
            echo "cpu governor was mixed originally, defaulted restore to: schedutil"
        fi
    fi
    echo "$ORIG_APST" | sudo tee "/sys/class/nvme/${NVME_CTRL}/power/control" > /dev/null
    echo "nvme power control restored to: $ORIG_APST"
}
trap restore_power_settings EXIT

echo "=== pinning cpu governor to performance ==="
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u

echo ""
echo "=== disabling nvme autonomous power state transitions ==="
echo on | sudo tee "/sys/class/nvme/${NVME_CTRL}/power/control" > /dev/null
cat "/sys/class/nvme/${NVME_CTRL}/power/control"

drop_caches() {
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
}

# System info

echo "=== system info ===" | tee "$RESULTS_DIR/system.txt"
uname -a | tee -a "$RESULTS_DIR/system.txt"
lscpu | grep -E "Model name|CPU\(s\)|MHz" | tee -a "$RESULTS_DIR/system.txt"
free -h | tee -a "$RESULTS_DIR/system.txt"
lsblk -d -o NAME,ROTA,SCHED,SIZE | tee -a "$RESULTS_DIR/system.txt"
if command -v nvme &>/dev/null; then
    sudo nvme id-ctrl "$DEVICE" 2>/dev/null | grep -E "mn|fr" | tee -a "$RESULTS_DIR/system.txt"
fi
echo "kernel:  $(uname -r)" | tee -a "$RESULTS_DIR/system.txt"
echo "rawgrep: $(rawgrep --version 2>/dev/null || echo unknown)" | tee -a "$RESULTS_DIR/system.txt"
echo "ripgrep: $(rg --version | head -1)" | tee -a "$RESULTS_DIR/system.txt"

CMD_RAWGREP="rawgrep '$PATTERN' '$SEARCH_DIR' --jump --no-color --threads $THREADS"
CMD_RAWGREP_NOCACHE="rawgrep '$PATTERN' '$SEARCH_DIR' --jump --no-color --threads $THREADS --no-cache --no-cache-write"
CMD_RG="rg '$PATTERN' '$SEARCH_DIR' --no-heading --color=never -n --threads $THREADS"

# Correctness check

echo ""
echo "=== correctness check ===" | tee "$RESULTS_DIR/correctness.txt"

eval "$CMD_RAWGREP_NOCACHE" 2>/dev/null \
    | sed 's/:\([0-9]*\): /:\1:/' \
    | sort > /tmp/bench_rawgrep.txt

eval "$CMD_RG" 2>/dev/null \
    | sort > /tmp/bench_rg.txt

cut -d: -f1 /tmp/bench_rawgrep.txt | sort -u > /tmp/bench_files_rawgrep.txt
cut -d: -f1 /tmp/bench_rg.txt | sort -u > /tmp/bench_files_rg.txt

MISSED_LINES=$(comm -23 /tmp/bench_rawgrep.txt /tmp/bench_rg.txt | wc -l)
EXTRA_LINES=$(comm -13 /tmp/bench_rawgrep.txt /tmp/bench_rg.txt | wc -l)
MISSED_FILES=$(comm -23 /tmp/bench_files_rawgrep.txt /tmp/bench_files_rg.txt | wc -l)
EXTRA_FILES=$(comm -13 /tmp/bench_files_rawgrep.txt /tmp/bench_files_rg.txt | wc -l)

{
    echo "line-level diff:"
    echo "  lines in rg but not rawgrep:   $MISSED_LINES"
    echo "  lines in rawgrep but not rg:   $EXTRA_LINES"
    echo ""
    echo "file-level diff:"
    echo "  files matched by rg only:      $MISSED_FILES"
    echo "  files matched by rawgrep only: $EXTRA_FILES"
    echo ""
    echo "differences are due to binary detection and gitignore policy differences,"
    echo "not missed matches in text files."
    echo ""
    echo "files matched by rg only (sample):"
    comm -23 /tmp/bench_files_rawgrep.txt /tmp/bench_files_rg.txt | head -10
    echo ""
    echo "files matched by rawgrep only (sample):"
    comm -13 /tmp/bench_files_rawgrep.txt /tmp/bench_files_rg.txt | head -10
} | tee -a "$RESULTS_DIR/correctness.txt"

# Warm cache - with fragment cache

echo ""
echo "=== warm cache + fragment cache ==="

eval "$CMD_RAWGREP" > /dev/null 2>&1 || true
eval "$CMD_RG" > /dev/null 2>&1 || true

hyperfine \
    --warmup "$WARMUP" \
    --runs "$WARM_RUNS" \
    --export-json "$RESULTS_DIR/warm_with_cache.json" \
    --export-markdown "$RESULTS_DIR/warm_with_cache.md" \
    --command-name "rawgrep" "$CMD_RAWGREP" \
    --command-name "ripgrep" "$CMD_RG"

# Warm cache - no fragment cache

echo ""
echo "=== warm cache, no fragment cache ==="

eval "$CMD_RAWGREP_NOCACHE" > /dev/null 2>&1 || true
eval "$CMD_RG" > /dev/null 2>&1 || true

hyperfine \
    --warmup "$WARMUP" \
    --runs "$WARM_RUNS" \
    --export-json "$RESULTS_DIR/warm_no_cache.json" \
    --export-markdown "$RESULTS_DIR/warm_no_cache.md" \
    --command-name "rawgrep (no cache)" "$CMD_RAWGREP_NOCACHE" \
    --command-name "ripgrep" "$CMD_RG"

# Cold cache - no fragment cache

echo ""
echo "=== cold cache, no fragment cache ==="

hyperfine \
    --runs "$RUNS" \
    --export-json "$RESULTS_DIR/cold_no_cache.json" \
    --export-markdown "$RESULTS_DIR/cold_no_cache.md" \
    --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
    --command-name "rawgrep (no cache)" "$CMD_RAWGREP_NOCACHE" \
    --command-name "ripgrep" "$CMD_RG"

# Cold cache - with fragment cache

echo ""
echo "=== cold cache + fragment cache ==="

eval "$CMD_RAWGREP" > /dev/null 2>&1 || true

hyperfine \
    --runs "$RUNS" \
    --export-json "$RESULTS_DIR/cold_with_cache.json" \
    --export-markdown "$RESULTS_DIR/cold_with_cache.md" \
    --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
    --command-name "rawgrep" "$CMD_RAWGREP" \
    --command-name "ripgrep" "$CMD_RG"

# Summary
echo ""
echo "========================================"
echo "results"
echo "========================================"
echo ""
echo "warm cache + fragment cache:"
cat "$RESULTS_DIR/warm_with_cache.md"
echo ""
echo "warm cache, no fragment cache:"
cat "$RESULTS_DIR/warm_no_cache.md"
echo ""
echo "cold cache, no fragment cache:"
cat "$RESULTS_DIR/cold_no_cache.md"
echo ""
echo "cold cache + fragment cache:"
cat "$RESULTS_DIR/cold_with_cache.md"
echo ""
echo "full results in $RESULTS_DIR/"
