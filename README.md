# rawgrep

**Grep at the speed of raw disk** - search text by reading data directly from raw block devices.

## Benchmarks

benchmark script: [`bench.sh`](bench.sh)
```
corpus: 674,283 files across mixed C/C++/Rust/Python projects
pattern: `TODO` (literal)
system: Intel i5-13400F, 16 threads, NVMe SSD, 16GB RAM (10GB free), Debian 6.12
rawgrep 0.1.4 vs ripgrep 15.1.0
```

| scenario | rawgrep | ripgrep | speedup |
|---|---|---|---|
| cold cache + fragment cache | 1.26s ± 0.02s | 11.08s ± 0.50s | **8.8x** |
| cold cache, no fragment cache | 6.24s ± 0.08s | 11.03s ± 0.97s | **1.8x** |
| warm cache + fragment cache | 173ms ± 9ms | 436ms ± 45ms | **2.5x** |
| warm cache, no fragment cache | 389ms ± 9ms | 454ms ± 73ms | 1.2x |

fragment cache stores per-file search metadata to skip unchanged files on repeat searches.

### Correctness notes

`rawgrep` and `ripgrep` differ in which files they search by design:

| | count |
|---|---|
| files matched by ripgrep only | 60 |
| files matched by rawgrep only | 257 |

**files ripgrep found that rawgrep missed:** mostly `.github/` yaml files, python venv files,
and large test data files. these are gitignore/binary detection policy differences rather than missed matches.

**files rawgrep found that ripgrep missed:** `.recording` files and other files ripgrep
treats as binary. rawgrep searches these by default.

no text file that ripgrep searched was missed by rawgrep.

## How is `rawgrep` so fast?

- `rawgrep` reads files DIRECTLY from your partition, completely bypassing the filesystem.
- `rawgrep` is cache-friendly and insanely memory efficient, simply streaming through your device and outputting the matches.
- `rawgrep` uses work-stealing parallel traversal to keep all CPU cores busy during directory scanning.
- `rawgrep` uses a sophisticated fragment-based caching system (inspired by [nowgrep](https://github.com/asbott/nowgrep)) that learns which files can be skipped for repeated searches.

## Installation

### Prerequisites

- Linux (contribute to make rawgrep support Windows) system with ext4/ntfs filesystem
- Rust toolchain (for building from source)
- Root access or be able to set capabilities

### Option 1: One-Time Setup with Capabilities (Recommended)

```bash
git clone https://github.com/rakivo/rawgrep
cd rawgrep

cargo build --profile=release-fast

# If you want maximum speed possible (requires nightly):
# cargo +nightly build --profile=release-fast --target=<your_target> --features=use_nightly

# Run the one-time setup command. Why? Read "Why Elevated Permissions?" section
sudo setcap cap_dac_read_search=eip ./target/release-fast/rawgrep
```

Now you can run it without `sudo`:
```bash
rawgrep "search pattern"
```

### Option 2: Use `sudo` Every Time

If you prefer not to use capabilities, just build and run with `sudo`:

```bash
cargo build --profile=release-fast

# Again, if you want maximum speed possible (requires nightly):
# cargo +nightly build --profile=release-fast --target=<your_target> --features=use_nightly

# Run with sudo each time
sudo ./target/release-fast/rawgrep "search pattern"
```

## Usage

### Basic Search
```bash
# Search current directory
rawgrep "error"

# Search specific directory
rawgrep "TODO" /var/log

# Regex patterns
rawgrep "error|warning|critical" .
```

### Advanced Options
```bash
# Specify device manually (auto-detected by default)
rawgrep "pattern" /home --device=/dev/sda1

# Print statistics at the end of the search
rawgrep "pattern" . --stats

# Disable filtering (search everything)
rawgrep "pattern" . -uuu
# or
rawgrep "pattern" . --all

# Disable specific filters
rawgrep "pattern" . --no-ignore # Don't use .gitignore
rawgrep "pattern" . --binary    # Search binary files
```

### Filtering Levels
```bash
# Default: respects .gitignore, skips binaries and large files (> 5 MB)
rawgrep "pattern"

# -u: ignore .gitignore
rawgrep "pattern" -u

# -uu: also search binary files
rawgrep "pattern" -uu

# -uuu: search everything, including large files
rawgrep "pattern" -uuu
```

## Why Elevated Permissions?

`rawgrep` reads raw block devices (e.g., `/dev/sda1`), which are protected by the OS. Instead of requiring full root access via `sudo` every time, we use Linux capabilities to grant **only** the specific permission needed.

### What is `CAP_DAC_READ_SEARCH`?

This capability grants exactly **one** permission: bypass file read permission checks.

**`rawgrep` only reads data, it never writes anything to disk.**

### Verifying Capabilities

You can verify what capabilities the binary has:

```bash
getcap ./target/release-fast/rawgrep
# Output: ./target/release-fast/rawgrep = cap_dac_read_search+eip
```

### Removing Capabilities

If you want to revoke the capability and go back to using `sudo`:

```bash
sudo setcap -r ./target/release-fast/rawgrep
```

## Limitations (IMPORTANT)

- **ext4/ntfs only:** Currently only supports ext4/ntfs filesystems.

## Development

**Note:** Capabilities are tied to the binary file itself, so you'll need to re-run `setcap` after each rebuild.

> **Why no automation script?** I intentionally decide not to provide a script that runs `sudo` commands. If you want automation, write your own script, it's just a few lines of bash code and you'll understand exactly what it does.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Roadmap

- [ ] Support for Windows. (Some physical partition stuff needs to get fixed on Windows, besides that everything should be already working)
- [ ] Support for OSX+APFS.
- [ ] Symlink support

## Emacs Integration

To use rawgrep from Emacs with jumpable locations:

1. Download `emacs/rawgrep.el` and place it in your load path
2. Add to your `.emacs` or `init.el`:
```elisp
(require 'rawgrep)
(global-set-key (kbd "M-e") 'rawgrep)
```

Or if you use `use-package`:
```elisp
(use-package rawgrep
  :load-path "path/to/rawgrep.el"
  :bind ("M-e" . rawgrep))
```

Works exactly like `'grep-find` but better.

## FAQ

**Q: Is this safe to use?**
A: Yes. The tool only reads data and never writes. The `CAP_DAC_READ_SEARCH` capability is narrowly scoped.

**Q: Is rawgrep faster than [ripgrep](https://github.com/BurntSushi/ripgrep)?**
A: Yeah.

**Q: Why am I missing some matches?**
A: By default, rawgrep respects `.gitignore` and skips binary/large files. Use `-u` to ignore `.gitignore`, `-uu` to also search binaries, or `-uuu` to search everything. This matches ripgrep's behavior.

**Q: Can I use this on other filesystems?**
A: Currently only ext4/ntfs is supported. Support for other filesystems may be added in the future. (Motivate me with stars)

**Q: Will this damage my filesystem?**
A: No. The tool only performs read operations. It cannot modify your filesystem.

**Q: What if partition auto-detection fails?**
A: Specify the device manually with `--device=/dev/sdXY`. Use `df -Th` to find your partition.

## Acknowledgments

Inspired by [ripgrep](https://github.com/BurntSushi/ripgrep) and [nowgrep](https://github.com/asbott/nowgrep), and the need for high-quality software in the big 25.
