#!/usr/bin/env bash

set -uo pipefail

PATTERN="TODO"
SEARCH_DIR="../chromium"
DEVICE="/dev/nvme0n1p2"
NVME_CTRL="nvme0"
THREADS=16
RUNS=10
WARM_RUNS=100
WARMUP=5
RESULTS_DIR="./benchmark_results"
DO_CORRECTNESS_CHECK=true

if [[ "${1:-}" == "--no-correctness-check" ]]; then
    DO_CORRECTNESS_CHECK=false
fi

mkdir -p "$RESULTS_DIR"

for cmd in rg rawgrep hyperfine fff jq; do
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
echo "fff:     $(fff --version 2>/dev/null || echo unknown)" | tee -a "$RESULTS_DIR/system.txt"
echo "hyperfine: $(hyperfine --version)" | tee -a "$RESULTS_DIR/system.txt"

CMD_RAWGREP="rawgrep '$PATTERN' '$SEARCH_DIR' --jump --no-color --reserved-tool-dirs --large --threads $THREADS"
CMD_RAWGREP_NOCACHE="rawgrep '$PATTERN' '$SEARCH_DIR' --jump --no-color --threads $THREADS --reserved-tool-dirs --large --no-cache --no-cache-write"
CMD_RG="rg '$PATTERN' '$SEARCH_DIR' --no-heading --color=never -n --threads $THREADS"

# fff has no positional search-dir arg on `grep`, it resolves the project
# root from cwd via git discovery. So fff commands run in a subshell that cd's into SEARCH_DIR first.
FFF_MAX_RESULTS=999999999999
CMD_FFF_GREP="(cd '$SEARCH_DIR' && fff grep '$PATTERN' --max-results $FFF_MAX_RESULTS)"
CMD_FFF_INDEX="(cd '$SEARCH_DIR' && fff index --force)"
CMD_FFF_RM_CACHE="rm -rf '$SEARCH_DIR/.fff'"

# Build fff's cache exactly once, right here, up front. I just don't have enough time for it to be any slower.
echo ""
echo "=== building fff cache once (will not be rebuilt again) ==="
eval "$CMD_FFF_RM_CACHE"
eval "$CMD_FFF_INDEX" > /dev/null 2>&1 || true

# Correctness check

if $DO_CORRECTNESS_CHECK; then
    echo ""
    echo "=== correctness check ===" | tee "$RESULTS_DIR/correctness.txt"

    # Strip ANSI codes, carriage returns, trailing/leading spaces, and empty lines
    eval "$CMD_RAWGREP_NOCACHE" 2>/dev/null \
        | tr -d '\r' \
        | sed -E 's/\x1B\[[0-9;]*[a-zA-R]//g' \
        | sed 's/:\([0-9]*\): /:\1:/' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | LC_ALL=C sort > /tmp/bench_rawgrep.txt

    eval "$CMD_RG" 2>/dev/null \
        | tr -d '\r' \
        | sed -E 's/\x1B\[[0-9;]*[a-zA-R]//g' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | LC_ALL=C sort > /tmp/bench_rg.txt

    eval "$CMD_FFF_GREP" 2>/dev/null | tr -d '\r' | sed -E 's/\x1B\[[0-9;]*[a-zA-R]//g' | sed 's/[[:space:]]*$//' | grep -v '^$' | LC_ALL=C sort > /tmp/bench_fff.txt

    # fff's grep output paths are relative to $SEARCH_DIR (it cd's there before
    # running, since it has no positional path arg -- see CMD_FFF_GREP above),
    # while rg/rawgrep's paths are relative to wherever this script runs from
    # and so carry a "$SEARCH_DIR/" prefix. Strip that prefix from rg/rawgrep's
    # output before diffing, or every real match looks like a mismatch.
    SEARCH_DIR_PREFIX=$(printf '%s\n' "${SEARCH_DIR%/}/" | sed 's/[.[\*^$/]/\\&/g')
    sed -i "s|^${SEARCH_DIR_PREFIX}||" /tmp/bench_rawgrep.txt
    sed -i "s|^${SEARCH_DIR_PREFIX}||" /tmp/bench_rg.txt

    cut -d: -f1 /tmp/bench_rawgrep.txt | grep -v '^$' | LC_ALL=C sort -u > /tmp/bench_files_rawgrep.txt
    cut -d: -f1 /tmp/bench_rg.txt | grep -v '^$' | LC_ALL=C sort -u > /tmp/bench_files_rg.txt
    cut -d: -f1 /tmp/bench_fff.txt | grep -v '^$' | LC_ALL=C sort -u > /tmp/bench_files_fff.txt

    # File 1 = rg, File 2 = rawgrep across all comparisons
    # comm -23 file1 file2 -> items in file1 (rg) but NOT file2 (rawgrep)
    # comm -13 file1 file2 -> items in file2 (rawgrep) but NOT file1 (rg)
    MISSED_LINES=$(LC_ALL=C comm -23 /tmp/bench_rg.txt /tmp/bench_rawgrep.txt | wc -l)
    EXTRA_LINES=$(LC_ALL=C comm -13 /tmp/bench_rg.txt /tmp/bench_rawgrep.txt | wc -l)
    MISSED_FILES=$(LC_ALL=C comm -23 /tmp/bench_files_rg.txt /tmp/bench_files_rawgrep.txt | wc -l)
    EXTRA_FILES=$(LC_ALL=C comm -13 /tmp/bench_files_rg.txt /tmp/bench_files_rawgrep.txt | wc -l)

    FFF_MISSED_LINES=$(LC_ALL=C comm -23 /tmp/bench_rg.txt /tmp/bench_fff.txt | wc -l)
    FFF_EXTRA_LINES=$(LC_ALL=C comm -13 /tmp/bench_rg.txt /tmp/bench_fff.txt | wc -l)
    FFF_MISSED_FILES=$(LC_ALL=C comm -23 /tmp/bench_files_rg.txt /tmp/bench_files_fff.txt | wc -l)
    FFF_EXTRA_FILES=$(LC_ALL=C comm -13 /tmp/bench_files_rg.txt /tmp/bench_files_fff.txt | wc -l)

    {
        echo "rawgrep vs rg:"
        echo "  lines in rg but not rawgrep:   $MISSED_LINES"
        echo "  lines in rawgrep but not rg:   $EXTRA_LINES"
        echo "  files matched by rg only:      $MISSED_FILES"
        echo "  files matched by rawgrep only: $EXTRA_FILES"
        echo ""
        echo "files matched by rg only (sample):"
        LC_ALL=C comm -23 /tmp/bench_files_rg.txt /tmp/bench_files_rawgrep.txt | head -10
        echo ""
        echo "files matched by rawgrep only (sample):"
        LC_ALL=C comm -13 /tmp/bench_files_rg.txt /tmp/bench_files_rawgrep.txt | head -10
        echo ""
        echo "fff vs rg:"
        echo "  lines in rg but not fff:   $FFF_MISSED_LINES"
        echo "  lines in fff but not rg:   $FFF_EXTRA_LINES"
        echo "  files matched by rg only:  $FFF_MISSED_FILES"
        echo "  files matched by fff only: $FFF_EXTRA_FILES"
        echo ""
        echo "files matched by rg only, not fff (sample):"
        LC_ALL=C comm -23 /tmp/bench_files_rg.txt /tmp/bench_files_fff.txt | head -10
        echo ""
        echo "files matched by fff only, not rg (sample):"
        LC_ALL=C comm -13 /tmp/bench_files_rg.txt /tmp/bench_files_fff.txt | head -10
    } | tee -a "$RESULTS_DIR/correctness.txt"
else
    echo ""
    echo "=== skipping correctness check ==="
fi

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

# Warm - fff (cache built once, up front, never rebuilt) vs rawgrep (fragment cache)

echo ""
echo "=== warm, fff (cache built once) vs rawgrep (fragment cache) ==="

eval "$CMD_FFF_GREP" > /dev/null 2>&1 || true
eval "$CMD_RAWGREP" > /dev/null 2>&1 || true

hyperfine \
    --warmup "$WARMUP" \
    --runs "$WARM_RUNS" \
    --export-json "$RESULTS_DIR/warm_fff.json" \
    --export-markdown "$RESULTS_DIR/warm_fff.md" \
    --command-name "fff (cache built once)" "$CMD_FFF_GREP" \
    --command-name "rawgrep" "$CMD_RAWGREP"

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

# Cold - fff (cache built once, up front, never rebuilt) vs rawgrep
# (fragment cache). Both get a dropped page cache before each run via
# --prepare; only .fff/ and rawgrep's own cache are left in place,
# isolating "does the persisted index/cache help" from "is the page
# cache warm."

echo ""
echo "=== cold, fff (cache built once) vs rawgrep (fragment cache) ==="

eval "$CMD_RAWGREP" > /dev/null 2>&1 || true

hyperfine \
    --runs "$RUNS" \
    --export-json "$RESULTS_DIR/cold_fff.json" \
    --export-markdown "$RESULTS_DIR/cold_fff.md" \
    --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
    --command-name "fff (cache built once)" "$CMD_FFF_GREP" \
    --command-name "rawgrep" "$CMD_RAWGREP"

# RAM usage
#
# hyperfine's --export-json already captured peak RSS per run in
# memory_usage_byte (see note at top of file) — just pull it back out and
# report mean/max per command across every JSON file we wrote above.

echo ""
echo "=== ram usage (peak RSS, from hyperfine's own measurements) ===" | tee "$RESULTS_DIR/ram.txt"

for f in "$RESULTS_DIR"/*.json; do
    jq -r '
        .results[]
        | select(.memory_usage_byte != null)
        | [.command,
           (([.memory_usage_byte[]] | add / length) / 1048576 | floor),
           (([.memory_usage_byte[]] | max) / 1048576 | floor)]
        | @tsv
    ' "$f" 2>/dev/null
done | awk -F'\t' '{printf "%-40s mean %6s MiB   max %6s MiB\n", $1, $2, $3}' \
    | tee -a "$RESULTS_DIR/ram.txt"

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
echo "warm, fff (cache built once) vs rawgrep:"
cat "$RESULTS_DIR/warm_fff.md"
echo ""
echo "cold cache, no fragment cache:"
cat "$RESULTS_DIR/cold_no_cache.md"
echo ""
echo "cold cache + fragment cache:"
cat "$RESULTS_DIR/cold_with_cache.md"
echo ""
echo "cold, fff (cache built once) vs rawgrep:"
cat "$RESULTS_DIR/cold_fff.md"
echo ""
echo "ram usage:"
cat "$RESULTS_DIR/ram.txt"
echo ""
echo "full results in $RESULTS_DIR/"
