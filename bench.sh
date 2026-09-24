#!/usr/bin/env bash

set -uo pipefail

# --- config ---

THREADS=16
RUNS=10
WARM_RUNS=75
WARMUP=5
RESULTS_DIR="./benchmark_results"
DO_CORRECTNESS_CHECK=true

DEVICE="/dev/nvme0n1p2"
NVME_CTRL="nvme0"

HYPERGREP_BIN="hgrep"

# rawgrep's on-disk fragment cache. Each suite gets a clean slate: whatever
# is there when a suite starts gets moved aside, the suite runs (writing
# and reading its own fresh cache), and the original is restored afterward
# -- including on ^C or any other exit, via the trap below.
RAWGREP_CACHE_FILE="$HOME/.cache/rawgrep/fragment_cache.bin"
RAWGREP_CACHE_BACKUP=""

# search trees + patterns we benchmark against.
CHROMIUM_DIR="../chromium"
LINUX_DIR="../linux"
LINUX_VERSION="7.3.0-rc1"   # just for the system-info header, no functional effect

PATTERN_TODO="TODO"
PATTERN_TODO_REGEX='(?i)\bTODO\((?:crbug\.com/\d+|[a-zA-Z][\w.-]*)\)'
PATTERN_REGEX='[A-Z]+_SUSPEND'

# fffd/fffq: fffd indexes a directory and listens on its default socket;
# fffq is the client that queries whatever fffd currently has running.
# Neither takes a --socket flag -- it doesn't exist on either binary.
#
# fffd has two indexing modes we care about here:
#   - normal (default): builds an in-memory content index, so fffq
#     queries never touch disk after startup. This is fffd's equivalent
#     of rawgrep's fragment cache.
#   - --no-cache: only indexes paths, so each fffq query has
#     to read file contents off disk itself. This is fffd's equivalent of
#     rawgrep's --no-cache.
# Since the mode is fixed at daemon startup, matching rawgrep's
# with-cache/no-cache split means killing and relaunching fffd whenever
# the mode needs to flip, not just passing a different flag to fffq.
#
# fffd only ever indexes one directory in one mode at a time, so we track
# both (FFFD_CURRENT_DIR, FFFD_CURRENT_MODE) and only pay for a
# kill+reindex when either changes -- see ensure_fffd() below.
FFFD_BIN="fffd"
FFFQ_BIN="fffq"
FFFD_SOCK="/tmp/fffd.sock"   # fffd's default socket path, used only for our own cleanup
FFFD_PID=""
FFFD_STDERR=""
FFFD_CURRENT_DIR=""
FFFD_CURRENT_MODE=""

if [[ "${1:-}" == "--no-correctness-check" ]]; then
    DO_CORRECTNESS_CHECK=false
fi

mkdir -p "$RESULTS_DIR"

for cmd in rg rawgrep "$HYPERGREP_BIN" "$FFFD_BIN" "$FFFQ_BIN" hyperfine jq; do
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

# --- rawgrep fragment-cache isolation ---
# Called at the start/end of each run_search_benchmarks suite so suites
# don't inherit each other's warmed fragment cache. restore_fragment_cache
# is also invoked from the exit trap below so a ^C mid-suite still puts
# the user's real cache back rather than leaving it swapped out or
# clobbered by whatever the interrupted suite had written.

isolate_fragment_cache() {
    if [ -f "$RAWGREP_CACHE_FILE" ]; then
        RAWGREP_CACHE_BACKUP="${RAWGREP_CACHE_FILE}.bak.$$"
        mv "$RAWGREP_CACHE_FILE" "$RAWGREP_CACHE_BACKUP"
    else
        RAWGREP_CACHE_BACKUP=""
    fi
}

restore_fragment_cache() {
    # Drop whatever this suite wrote, then put the original back if there
    # was one. Safe to call more than once: once restored, the backup
    # var is cleared, so a second call (e.g. suite-end then exit trap)
    # is a no-op beyond the redundant rm.
    rm -f "$RAWGREP_CACHE_FILE"
    if [ -n "$RAWGREP_CACHE_BACKUP" ] && [ -f "$RAWGREP_CACHE_BACKUP" ]; then
        mv "$RAWGREP_CACHE_BACKUP" "$RAWGREP_CACHE_FILE"
        RAWGREP_CACHE_BACKUP=""
    fi
}

cleanup() {
    restore_power_settings
    restore_fragment_cache
    stop_fffd
}
trap cleanup EXIT
# EXIT alone won't fire on ^C/SIGTERM unless the signal actually ends the
# process, so route both into an explicit exit -- that trips the EXIT trap.
trap 'exit 130' INT
trap 'exit 143' TERM

echo "=== pinning cpu governor to performance ==="
echo performance | sudo tee /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor > /dev/null
cat /sys/devices/system/cpu/cpu*/cpufreq/scaling_governor | sort -u

echo ""
echo "=== disabling nvme autonomous power state transitions ==="
echo on | sudo tee "/sys/class/nvme/${NVME_CTRL}/power/control" > /dev/null
cat "/sys/class/nvme/${NVME_CTRL}/power/control"

# used as hyperfine's --prepare for every cold-cache run below. Exported so
# the subshell hyperfine spawns for --prepare can actually see it -- this
# used to be duplicated inline at every --prepare call site, no reason for
# that now that hyperfine gets it as a real function.
drop_caches() {
    sync
    echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null
    sleep 1
}
export -f drop_caches

# --- system info ---

echo "=== system info ===" | tee "$RESULTS_DIR/system.txt"
uname -a | tee -a "$RESULTS_DIR/system.txt"
lscpu | grep -E "Model name|CPU\(s\)|MHz" | tee -a "$RESULTS_DIR/system.txt"
free -h | tee -a "$RESULTS_DIR/system.txt"
lsblk -d -o NAME,ROTA,SCHED,SIZE | tee -a "$RESULTS_DIR/system.txt"
if command -v nvme &>/dev/null; then
    sudo nvme id-ctrl "$DEVICE" 2>/dev/null | grep -E "mn|fr" | tee -a "$RESULTS_DIR/system.txt"
fi
echo "kernel:      $(uname -r)" | tee -a "$RESULTS_DIR/system.txt"
echo "rawgrep:     $(rawgrep --version 2>/dev/null || echo unknown)" | tee -a "$RESULTS_DIR/system.txt"
echo "ripgrep:     $(rg --version | head -1)" | tee -a "$RESULTS_DIR/system.txt"
echo "hypergrep:   $($HYPERGREP_BIN --version 2>/dev/null || echo unknown)" | tee -a "$RESULTS_DIR/system.txt"
echo "fffd:        $($FFFD_BIN --version 2>/dev/null || echo unknown)" | tee -a "$RESULTS_DIR/system.txt"
echo "hyperfine:   $(hyperfine --version)" | tee -a "$RESULTS_DIR/system.txt"
echo "linux tree:  $LINUX_VERSION" | tee -a "$RESULTS_DIR/system.txt"

# --- correctness check ---
# compares a candidate tool's output against rg's for a given
# search-dir/pattern pair, treating rg as ground truth. Called once per
# candidate (rawgrep, hypergrep, fffq) so each gets its own report and its
# own set of temp files -- the temp files are namespaced by $label so
# multiple calls made per suite don't clobber each other.

check_correctness() {
    local label="$1"                    # e.g. "rawgrep", "hypergrep", or "fffq"
    local cmd_candidate_nocache="$2"
    local cmd_rg="$3"
    local search_dir="$4"
    local out_file="$5"

    local candidate_txt="/tmp/bench_${label}.txt"
    local candidate_files_txt="/tmp/bench_files_${label}.txt"
    local rg_txt="/tmp/bench_rg_${label}.txt"
    local rg_files_txt="/tmp/bench_files_rg_${label}.txt"

    echo ""
    echo "=== correctness check ($label vs rg): $out_file ==="

    # rawgrep's --jump output has an extra space after the line number
    # ("file:123: text") that rg's -n output doesn't -- fffd's daemon
    # protocol does the same ("path:line: content", see fffd's
    # push_unchecked calls), so both get normalized here. hypergrep is
    # assumed to already match rg's "file:line:text" shape -- if that
    # turns out wrong, add an equivalent branch here rather than guessing
    # at a fix downstream.
    local candidate_normalizer="cat"
    if [[ "$label" == "rawgrep" || "$label" == "fffq" ]]; then
        candidate_normalizer="sed 's/:\([0-9]*\): /:\1:/'"
    fi

    # Strip ANSI codes, carriage returns, trailing/leading spaces, and empty lines
    eval "$cmd_candidate_nocache" 2>/dev/null \
        | tr -d '\r' \
        | sed -E 's/\x1B\[[0-9;]*[a-zA-R]//g' \
        | eval "$candidate_normalizer" \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | LC_ALL=C sort > "$candidate_txt"

    eval "$cmd_rg" 2>/dev/null \
        | tr -d '\r' \
        | sed -E 's/\x1B\[[0-9;]*[a-zA-R]//g' \
        | sed 's/[[:space:]]*$//' \
        | grep -v '^$' \
        | LC_ALL=C sort > "$rg_txt"

    # rg/candidate's paths carry a "$search_dir/" prefix since we run from
    # outside it; strip that prefix before diffing or every real match
    # looks like a mismatch. Tools disagree on which *form* of that
    # prefix they emit, though: rg echoes back whatever we gave it on
    # the command line (e.g. "../chromium/"), while fffd resolves the
    # base_path to an absolute, canonical path once at startup and every
    # match it returns is built off that (e.g.
    # "/home/mark/Coding/chromium/") -- see fffd's std::fs::canonicalize
    # call. So strip both the literal, as-given prefix and its canonical
    # absolute form; whichever one a given tool actually used, one of
    # the two substitutions is a no-op and the other does the stripping.
    local search_dir_abs search_dir_prefix search_dir_abs_prefix
    search_dir_abs=$(realpath -m "$search_dir" 2>/dev/null || echo "$search_dir")
    search_dir_prefix=$(printf '%s\n' "${search_dir%/}/" | sed 's/[.[\*^$/]/\\&/g')
    search_dir_abs_prefix=$(printf '%s\n' "${search_dir_abs%/}/" | sed 's/[.[\*^$/]/\\&/g')
    sed -i -e "s|^${search_dir_prefix}||" -e "s|^${search_dir_abs_prefix}||" "$candidate_txt"
    sed -i -e "s|^${search_dir_prefix}||" -e "s|^${search_dir_abs_prefix}||" "$rg_txt"

    cut -d: -f1 "$candidate_txt" | grep -v '^$' | LC_ALL=C sort -u > "$candidate_files_txt"
    cut -d: -f1 "$rg_txt" | grep -v '^$' | LC_ALL=C sort -u > "$rg_files_txt"

    # File 1 = rg, File 2 = candidate across all comparisons
    # comm -23 file1 file2 -> items in file1 (rg) but NOT file2 (candidate)
    # comm -13 file1 file2 -> items in file2 (candidate) but NOT file1 (rg)
    local missed_lines extra_lines missed_files extra_files
    missed_lines=$(LC_ALL=C comm -23 "$rg_txt" "$candidate_txt" | wc -l)
    extra_lines=$(LC_ALL=C comm -13 "$rg_txt" "$candidate_txt" | wc -l)
    missed_files=$(LC_ALL=C comm -23 "$rg_files_txt" "$candidate_files_txt" | wc -l)
    extra_files=$(LC_ALL=C comm -13 "$rg_files_txt" "$candidate_files_txt" | wc -l)

    {
        echo "$label vs rg:"
        echo "  lines in rg but not $label:   $missed_lines"
        echo "  lines in $label but not rg:   $extra_lines"
        echo "  files matched by rg only:        $missed_files"
        echo "  files matched by $label only:    $extra_files"
        echo ""
        echo "files matched by rg only (sample):"
        LC_ALL=C comm -23 "$rg_files_txt" "$candidate_files_txt" | head -10
        echo ""
        echo "files matched by $label only (sample):"
        LC_ALL=C comm -13 "$rg_files_txt" "$candidate_files_txt" | head -10
    } | tee -a "$out_file"
}

# start_fffd backgrounds fffd (in either its normal content-indexed mode,
# or --no-cache mode -- see the config block up top), then
# blocks until fffd writes anything to stderr. In practice that first
# write is the one-line "fffd: indexed and listening on /tmp/fffd.sock"
# message, but we don't pattern-match that text specifically here -- fffd
# is expected to stay silent on stderr until it's done indexing and ready
# to serve queries, so "stderr became non-empty" and "ready" are the same
# event as far as this script cares.
#
# If fffd dies before ever writing to stderr, that's treated as a startup
# failure.
start_fffd() {
    local search_dir="$1"
    local mode="${2:-cache}"   # "cache" (default, content-indexed) or "nocache"

    rm -f "$FFFD_SOCK"
    FFFD_STDERR=$(mktemp)

    local -a fffd_args=("$search_dir")
    if [[ "$mode" == "nocache" ]]; then
        fffd_args+=("--no-cache")
    fi

    "$FFFD_BIN" "${fffd_args[@]}" >/dev/null 2>"$FFFD_STDERR" &
    FFFD_PID=$!

    echo "waiting for fffd to index $search_dir (mode: $mode) ..."
    while [ ! -s "$FFFD_STDERR" ]; do
        if ! kill -0 "$FFFD_PID" 2>/dev/null; then
            echo "error: fffd exited before it finished indexing $search_dir" >&2
            cat "$FFFD_STDERR" >&2
            rm -f "$FFFD_STDERR"
            FFFD_PID=""
            return 1
        fi
        sleep 0.1
    done

    # first line fffd wrote is the ready signal (normally the
    # "indexed and listening on ..." message) -- surface it so it ends up
    # in the script's own log too.
    cat "$FFFD_STDERR"
    FFFD_CURRENT_DIR="$search_dir"
    FFFD_CURRENT_MODE="$mode"
}

stop_fffd() {
    if [ -n "$FFFD_PID" ] && kill -0 "$FFFD_PID" 2>/dev/null; then
        kill "$FFFD_PID" 2>/dev/null
        wait "$FFFD_PID" 2>/dev/null
    fi
    FFFD_PID=""
    rm -f "$FFFD_SOCK"
    [ -n "$FFFD_STDERR" ] && rm -f "$FFFD_STDERR"
    FFFD_STDERR=""
    FFFD_CURRENT_DIR=""
    FFFD_CURRENT_MODE=""
}

# Only kill+reindex when the directory or the indexing mode actually
# changes; if fffd is already up, already covers $1, and is already in
# mode $2, this is a no-op. This is what lets the fff correctness and
# timing passes below flip between content-indexed and --no-cache runs,
# and move on to the next directory, without hand-rolling the restart
# logic at every call site -- and what keeps that flipping down to once
# per directory instead of once per pattern.
#
# Note this always pays for a full kill+reindex on any dir/mode change,
# content-indexing included: there's no "resume from a previous
# content-indexed run" path here, so every time a phase re-enters
# "cache" mode (e.g. coming back from a "nocache" phase) fffd is
# relaunched from scratch and rebuilds its in-memory index from disk
# before that phase's hyperfine call starts -- it never reuses a stale
# index left over from earlier in the suite.
ensure_fffd() {
    local search_dir="$1"
    local mode="${2:-cache}"

    if [ -n "$FFFD_PID" ] && kill -0 "$FFFD_PID" 2>/dev/null \
        && [ "$FFFD_CURRENT_DIR" == "$search_dir" ] \
        && [ "$FFFD_CURRENT_MODE" == "$mode" ]; then
        return 0
    fi

    stop_fffd
    start_fffd "$search_dir" "$mode"
}

# builds the rawgrep invocation used both for the main suites and for the
# fff suites, so the long flag list only lives in one place.
build_rawgrep_cmd() {
    local pattern="$1"
    local search_dir="$2"
    echo "rawgrep '$pattern' '$search_dir' --jump --color=never --reserved-tool-dirs --large --threads $THREADS"
}

# --- main benchmark suite ---
# runs the 4 cache-state permutations (warm+cache, warm+no-cache,
# cold+no-cache, cold+cache) for one search-dir/pattern pair, across all
# three tools. This is the function that gets called once per (tree,
# pattern) combination below.

run_search_benchmarks() {
    local suite_label="$1"   # also doubles as the output subdir name, e.g. "chromium_todo"
    local search_dir="$2"
    local pattern="$3"

    local out_dir="$RESULTS_DIR/$suite_label"
    mkdir -p "$out_dir"

    # This suite never touches fffd/fffq -- it's purely rawgrep vs rg vs
    # hypergrep -- so fffd has no business being resident while it runs.
    # A leftover fffd from an earlier correctness check or fff benchmark
    # would still be holding its whole content index in memory and
    # burning CPU/RAM that rawgrep/rg/hypergrep would otherwise have to
    # themselves, which would make this suite's numbers unfair to compare
    # against a run where fffd never started. Unconditionally tear it down
    # before we begin; only the fff-specific functions are allowed to
    # bring it back up.
    stop_fffd

    # give this suite its own clean fragment cache, isolated from whatever
    # the previous suite (or the user's normal usage) left behind.
    isolate_fragment_cache

    local cmd_rawgrep
    cmd_rawgrep="$(build_rawgrep_cmd "$pattern" "$search_dir") --no-ignore"
    local cmd_rawgrep_nocache="$cmd_rawgrep --no-cache"
    local cmd_rg="rg '$pattern' '$search_dir' --no-heading --no-ignore --color=never -n --threads $THREADS"
    # hypergrep has no on-disk fragment cache to toggle like rawgrep does,
    # so (like rg) one command covers all four cache-state phases below.
    local cmd_hypergrep="$HYPERGREP_BIN -n --ignore-gitindex '$pattern' '$search_dir'"

    echo ""
    echo "########################################"
    echo "# $suite_label  (pattern: $pattern)"
    echo "########################################"

    if $DO_CORRECTNESS_CHECK; then
        check_correctness "rawgrep" "$cmd_rawgrep_nocache" "$cmd_rg" "$search_dir" "$out_dir/correctness.txt"
        check_correctness "hypergrep" "$cmd_hypergrep" "$cmd_rg" "$search_dir" "$out_dir/correctness_hypergrep.txt"
    fi

    # warm cache, with rawgrep's fragment cache
    echo ""
    echo "=== [$suite_label] warm cache + fragment cache ==="
    eval "$cmd_rawgrep" > /dev/null 2>&1 || true
    eval "$cmd_rg" > /dev/null 2>&1 || true
    eval "$cmd_hypergrep" > /dev/null 2>&1 || true
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$WARM_RUNS" \
        --export-json "$out_dir/warm_with_cache.json" \
        --export-markdown "$out_dir/warm_with_cache.md" \
        --command-name "rawgrep" "$cmd_rawgrep" \
        --command-name "ripgrep" "$cmd_rg" \
        --command-name "hypergrep" "$cmd_hypergrep"

    # warm cache, no fragment cache
    echo ""
    echo "=== [$suite_label] warm cache, no fragment cache ==="
    eval "$cmd_rawgrep_nocache" > /dev/null 2>&1 || true
    eval "$cmd_rg" > /dev/null 2>&1 || true
    eval "$cmd_hypergrep" > /dev/null 2>&1 || true
    hyperfine \
        --warmup "$WARMUP" \
        --runs "$WARM_RUNS" \
        --export-json "$out_dir/warm_no_cache.json" \
        --export-markdown "$out_dir/warm_no_cache.md" \
        --command-name "rawgrep (no cache)" "$cmd_rawgrep_nocache" \
        --command-name "ripgrep" "$cmd_rg" \
        --command-name "hypergrep" "$cmd_hypergrep"

    # cold cache, no fragment cache
    echo ""
    echo "=== [$suite_label] cold cache, no fragment cache ==="
    hyperfine \
        --runs "$RUNS" \
        --export-json "$out_dir/cold_no_cache.json" \
        --export-markdown "$out_dir/cold_no_cache.md" \
        --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
        --command-name "rawgrep (no cache)" "$cmd_rawgrep_nocache" \
        --command-name "ripgrep" "$cmd_rg" \
        --command-name "hypergrep" "$cmd_hypergrep"

    # cold cache, with fragment cache
    echo ""
    echo "=== [$suite_label] cold cache + fragment cache ==="
    eval "$cmd_rawgrep" > /dev/null 2>&1 || true
    hyperfine \
        --runs "$RUNS" \
        --export-json "$out_dir/cold_with_cache.json" \
        --export-markdown "$out_dir/cold_with_cache.md" \
        --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
        --command-name "rawgrep" "$cmd_rawgrep" \
        --command-name "ripgrep" "$cmd_rg" \
        --command-name "hypergrep" "$cmd_hypergrep"

    # suite done -- put the previous fragment cache back before the next
    # suite starts (also covered by the exit trap if we never get here).
    restore_fragment_cache

    SUITES+=("$suite_label")
}

# --- fff correctness check ---
# Confirms fffq agrees with rg for one dir/pattern pair. Deliberately does
# NOT touch rawgrep or the fragment cache, and does NOT run any hyperfine
# benchmarking -- that's the whole point of splitting this out from the
# timing benchmark below. Does NOT start or stop fffd itself: the caller
# is expected to have it already up (via ensure_fffd) in "cache" mode,
# and to keep it up across every pattern for a given directory rather
# than restarting it per pattern -- see the driving loop at the bottom of
# the script for why.
check_fff_correctness() {
    local suite_label="$1"
    local search_dir="$2"
    local pattern="$3"

    local out_dir="$RESULTS_DIR/$suite_label"
    mkdir -p "$out_dir"

    local cmd_fffq="$FFFQ_BIN '$pattern'"
    local cmd_rg="rg '$pattern' '$search_dir' --no-heading --no-ignore --color=never -n --threads $THREADS"

    echo ""
    echo "########################################"
    echo "# $suite_label correctness check (pattern: $pattern)"
    echo "########################################"

    check_correctness "fffq" "$cmd_fffq" "$cmd_rg" "$search_dir" "$out_dir/correctness_fffq_${pattern//[^a-zA-Z0-9]/_}.txt"
}

# --- fff timing benchmark ---
# fff entirely on its own: each hyperfine call below benchmarks a single
# command (fffq) -- there is no rawgrep comparison here at all, unlike
# run_search_benchmarks above. Correctness is NOT re-checked here -- that
# already happened in check_fff_correctness, earlier in the run.
#
# Does NOT start, stop, or switch the mode of fffd itself: the caller is
# expected to have already put it in the right mode (ensure_fffd) before
# calling this for a "with_cache" phase vs a "no_cache" phase. Grouping
# every pattern's with-cache phases together, then switching fffd to
# --no-cache once for every pattern's no-cache phases (see the driving
# loop below), means fffd is only killed and reindexed twice per
# directory -- once to come up in "cache" mode, once to flip to
# "nocache" -- instead of once per pattern.
run_fff_phase() {
    local suite_label="$1"
    local phase="$2"    # warm_with_cache | cold_with_cache | warm_no_cache | cold_no_cache
    local pattern="$3"
    local cold="$4"      # "cold" or "warm"

    local out_dir="$RESULTS_DIR/$suite_label"
    mkdir -p "$out_dir"

    local cmd_fffq="$FFFQ_BIN '$pattern'"

    echo ""
    echo "=== [$suite_label] $phase ==="

    if [[ "$cold" == "cold" ]]; then
        hyperfine \
            --runs "$RUNS" \
            --export-json "$out_dir/$phase.json" \
            --export-markdown "$out_dir/$phase.md" \
            --prepare "sync && echo 3 | sudo tee /proc/sys/vm/drop_caches > /dev/null && sleep 1" \
            --command-name "fff" "$cmd_fffq"
    else
        eval "$cmd_fffq" > /dev/null 2>&1 || true
        hyperfine \
            --warmup "$WARMUP" \
            --runs "$WARM_RUNS" \
            --export-json "$out_dir/$phase.json" \
            --export-markdown "$out_dir/$phase.md" \
            --command-name "fff" "$cmd_fffq"
    fi
}

# --- run everything ---

SUITES=()

# fff dir/pattern combos, shared between the early correctness pass and
# the final timing pass below so they're only defined in one place.
# Grouped by directory (not flattened into one list of 4) because both
# passes below iterate per-directory to keep fffd's kill+reindex count
# down: everything for a given directory happens while fffd is up once,
# rather than restarting it per pattern.
FFF_DIRS=("$CHROMIUM_DIR" "$LINUX_DIR")
FFF_DIR_NAMES=("chromium" "linux")
FFF_PATTERNS=("$PATTERN_TODO" "$PATTERN_TODO_REGEX")
FFF_PATTERN_NAMES=("todo" "regex")

# # --- fff correctness checks (early, fast, and isolated from timing) ---
# # Confirms fffq's output matches rg's for each dir/pattern combo this
# # script cares about. No hyperfine benchmarking happens here. fffd is
# # started once per directory (both patterns share that one instance,
# # since neither check changes its indexing mode) and killed again before
# # the main suites below -- it does not stay up into them.
# echo ""
# echo "=== fff correctness checks ==="
# if $DO_CORRECTNESS_CHECK; then
#     for d in "${!FFF_DIRS[@]}"; do
#         dir="${FFF_DIRS[$d]}"
#         dir_name="${FFF_DIR_NAMES[$d]}"
#         ensure_fffd "$dir" "cache" || continue
#         for p in "${!FFF_PATTERNS[@]}"; do
#             label="${dir_name}_fffd_${FFF_PATTERN_NAMES[$p]}"
#             check_fff_correctness "$label" "$dir" "${FFF_PATTERNS[$p]}"
#         done
#     done
# else
#     echo "skipping (--no-correctness-check)"
# fi

# # make sure nothing's left resident before the main suites -- same
# # reasoning as the stop_fffd at the top of run_search_benchmarks.
# stop_fffd

# --- main suites: rawgrep vs rg vs hypergrep, no fff involved at all ---

# chromium: literal TODO pattern
run_search_benchmarks "chromium_todo" "$CHROMIUM_DIR" "$PATTERN_TODO"

# chromium: the TODO(...) convention regex
run_search_benchmarks "chromium_regex" "$CHROMIUM_DIR" "$PATTERN_TODO_REGEX"

# same two patterns, now against the linux tree ($LINUX_VERSION)
run_search_benchmarks "linux_todo" "$LINUX_DIR" "$PATTERN_TODO"
run_search_benchmarks "linux_regex" "$LINUX_DIR" "$PATTERN_REGEX"

# --- fff timing benchmarks: run last, fully on their own ---
# Correctness was already checked above; this pass is purely about
# timing, and it's fff alone -- no rawgrep in the mix. fffd only gets
# started back up now, once every other suite has finished, so the fff
# numbers are never measured alongside -- or right after -- anything
# else competing for CPU/RAM/disk.
#
# Per directory: fffd comes up once in "cache" mode and runs the
# with-cache phase (warm + cold) for every pattern before it's touched
# again, then it's switched to "nocache" once and runs the no-cache
# phase (warm + cold) for every pattern. That's 2 kill+reindex cycles
# per directory (4 total), instead of one per pattern.
# echo ""
# echo "=== fff benchmarks (isolated, run last) ==="
# for d in "${!FFF_DIRS[@]}"; do
#     dir="${FFF_DIRS[$d]}"
#     dir_name="${FFF_DIR_NAMES[$d]}"
#
#     ensure_fffd "$dir" "cache" || continue
#     for p in "${!FFF_PATTERNS[@]}"; do
#         label="${dir_name}_fffd_${FFF_PATTERN_NAMES[$p]}"
#         pattern="${FFF_PATTERNS[$p]}"
#         run_fff_phase "$label" "warm_with_cache" "$pattern" "warm"
#         run_fff_phase "$label" "cold_with_cache" "$pattern" "cold"
#     done
#
#     ensure_fffd "$dir" "nocache" || continue
#     for p in "${!FFF_PATTERNS[@]}"; do
#         label="${dir_name}_fffd_${FFF_PATTERN_NAMES[$p]}"
#         pattern="${FFF_PATTERNS[$p]}"
#         run_fff_phase "$label" "warm_no_cache" "$pattern" "warm"
#         run_fff_phase "$label" "cold_no_cache" "$pattern" "cold"
#     done
#
#     for pname in "${FFF_PATTERN_NAMES[@]}"; do
#         SUITES+=("${dir_name}_fffd_${pname}")
#     done
# done

# fff suites are done with fffd for good -- kill it rather than leaving
# it resident past the end of the script.
# stop_fffd

# --- ram usage ---
# hyperfine's --export-json already captured peak RSS per run in
# memory_usage_byte, just pull it back out and report mean/max per command
# across every JSON file we wrote above. Written straight to a file and
# only ever cat'd once, at the bottom, instead of being printed here too.

compute_ram_usage() {
    local out_file="$1"
    {
        echo "=== ram usage (peak RSS, from hyperfine's own measurements) ==="
        for f in "$RESULTS_DIR"/*/*.json; do
            jq -r '
                .results[]
                | select(.memory_usage_byte != null)
                | [.command,
                   (([.memory_usage_byte[]] | add / length) / 1048576 | floor),
                   (([.memory_usage_byte[]] | max) / 1048576 | floor)]
                | @tsv
            ' "$f" 2>/dev/null
        done | awk -F'\t' '{printf "%-40s mean %6s MiB   max %6s MiB\n", $1, $2, $3}'
    } > "$out_file"
}

compute_ram_usage "$RESULTS_DIR/ram.txt"

# --- summary ---

echo ""
echo "========================================"
echo "results"
echo "========================================"

for suite in "${SUITES[@]}"; do
    out_dir="$RESULTS_DIR/$suite"
    echo ""
    echo "--- $suite ---"
    for phase in warm_with_cache warm_no_cache cold_no_cache cold_with_cache; do
        if [ -f "$out_dir/$phase.md" ]; then
            echo ""
            echo "$phase:"
            cat "$out_dir/$phase.md"
        fi
    done
done

echo ""
echo "ram usage:"
cat "$RESULTS_DIR/ram.txt"

echo ""
echo "full results in $RESULTS_DIR/"
