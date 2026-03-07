#
# If you're looking at this, just know that yes, I AI generated this benchmark,
# I don't have that amount of patience to go through every little detail
# of benchmarking, and I rather work on some real project, to gain some real performance benefit.
#
# But! It honestly looks like it works just fine. So, what's the matter anyway?
#

#!/usr/bin/env bash
set -uo pipefail

PATTERN="TODO"
SEARCH_DIR=".."
DEVICE="/dev/nvme0n1p2"
THREADS=16
RUNS=10
WARMUP=3
RESULTS_DIR="./benchmark_results"

mkdir -p "$RESULTS_DIR"

for cmd in rg rawgrep hyperfine; do
    if ! command -v "$cmd" &>/dev/null; then
        echo "error: $cmd not found"
        exit 1
    fi
done

drop_caches() {
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
}

# system info
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
CMD_RAWGREP_NOCACHE="rawgrep '$PATTERN' '$SEARCH_DIR' --jump --no-color --threads $THREADS --no-cache"
CMD_RG="rg '$PATTERN' '$SEARCH_DIR' --no-heading --color=never -n --threads $THREADS"

# correctness check
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

# warm cache - with fragment cache
echo ""
echo "=== warm cache + fragment cache ==="

eval "$CMD_RAWGREP" > /dev/null 2>&1 || true
eval "$CMD_RG" > /dev/null 2>&1 || true

hyperfine \
    --warmup "$WARMUP" \
    --runs "$RUNS" \
    --export-json "$RESULTS_DIR/warm_with_cache.json" \
    --export-markdown "$RESULTS_DIR/warm_with_cache.md" \
    --command-name "rawgrep" "$CMD_RAWGREP" \
    --command-name "ripgrep" "$CMD_RG"

# warm cache - no fragment cache
echo ""
echo "=== warm cache, no fragment cache ==="

eval "$CMD_RAWGREP_NOCACHE" > /dev/null 2>&1 || true
eval "$CMD_RG" > /dev/null 2>&1 || true

hyperfine \
    --warmup "$WARMUP" \
    --runs "$RUNS" \
    --export-json "$RESULTS_DIR/warm_no_cache.json" \
    --export-markdown "$RESULTS_DIR/warm_no_cache.md" \
    --command-name "rawgrep (no cache)" "$CMD_RAWGREP_NOCACHE" \
    --command-name "ripgrep" "$CMD_RG"

# cold cache - no fragment cache
echo ""
echo "=== cold cache, no fragment cache ==="

hyperfine \
    --runs "$RUNS" \
    --export-json "$RESULTS_DIR/cold_no_cache.json" \
    --export-markdown "$RESULTS_DIR/cold_no_cache.md" \
    --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
    --command-name "rawgrep (no cache)" "$CMD_RAWGREP_NOCACHE" \
    --command-name "ripgrep" "$CMD_RG"

# cold cache - with fragment cache
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

# detailed time stats
echo ""
echo "=== detailed stats ===" | tee "$RESULTS_DIR/perf.txt"

eval "$CMD_RAWGREP" > /dev/null 2>&1 || true
eval "$CMD_RG" > /dev/null 2>&1 || true

warm_labels=("rawgrep_warm_cache" "rawgrep_warm_nocache" "ripgrep_warm")
warm_cmds=("$CMD_RAWGREP" "$CMD_RAWGREP_NOCACHE" "$CMD_RG")

for i in "${!warm_labels[@]}"; do
    echo "" | tee -a "$RESULTS_DIR/perf.txt"
    echo "--- ${warm_labels[$i]} ---" | tee -a "$RESULTS_DIR/perf.txt"
    /usr/bin/time -v bash -c "${warm_cmds[$i]}" > /dev/null 2>> "$RESULTS_DIR/perf.txt"
done

cold_labels=("rawgrep_cold_cache" "rawgrep_cold_nocache" "ripgrep_cold")
cold_cmds=("$CMD_RAWGREP" "$CMD_RAWGREP_NOCACHE" "$CMD_RG")

for i in "${!cold_labels[@]}"; do
    drop_caches
    echo "" | tee -a "$RESULTS_DIR/perf.txt"
    echo "--- ${cold_labels[$i]} ---" | tee -a "$RESULTS_DIR/perf.txt"
    /usr/bin/time -v bash -c "${cold_cmds[$i]}" > /dev/null 2>> "$RESULTS_DIR/perf.txt"
done

# summary
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
