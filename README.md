# rawgrep

**Grep at the speed of raw disk** - search text by reading data directly from raw block devices.

## How is `rawgrep` so fast?

- `rawgrep` reads files DIRECTLY from your partition, completely bypassing the filesystem.
- `rawgrep` is cache-friendly and INSANELY memory efficient, simply streaming through your device and outputting the matches.
- `rawgrep` uses a sophisticated fragment-based caching system (inspired by [nowgrep](https://github.com/asbott/nowgrep)) that learns which files can be skipped for repeated searches.

## Installation

### Prerequisites

- Linux system with ext4 filesystem
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
cargo build --release

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

- **ext4 only:** Currently only supports ext4 filesystems, and most likely only Linux (didn't test that)

## Development

**Note:** Capabilities are tied to the binary file itself, so you'll need to re-run `setcap` after each rebuild.

> **Why no automation script?** I intentionally decide not to provide a script that runs `sudo` commands. If you want automation, write your own script, it's just a few lines of bash code and you'll understand exactly what it does.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## Roadmap

- [ ] Daemon mode with eBPF filesystem hooks for hot cache performance
- [ ] Symlink support
- [ ] Support for more filesystems (btrfs, maybe even NTFS/APFS)

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
A: Currently only ext4 is supported. Support for other filesystems may be added in the future. (Motivate me with stars)

**Q: Will this damage my filesystem?**
A: No. The tool only performs read operations. It cannot modify your filesystem.

**Q: What if partition auto-detection fails?**
A: Specify the device manually with `--device=/dev/sdXY`. Use `df -Th` to find your partition.

## Acknowledgments

Inspired by [ripgrep](https://github.com/BurntSushi/ripgrep) and [nowgrep](https://github.com/asbott/nowgrep), and the need for high-quality software in the big 25.
