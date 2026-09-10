//! Walks a directory tree the same way the real crawler would (building up
//! a GitignoreChain depth-by-depth), computing ignored/not-ignored status
//! for every file and directory, and cross-checks that result against the
//! `ignore` crate (the same gitignore engine ripgrep uses).
//!
//! Only mismatches are printed, a one-line summary goes to stderr at the end and the
//! process exits non-zero if any mismatch was found.
//!
//! Usage: gitignore_oracle_check <repo-root>

use std::collections::HashSet;
use std::env;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use ignore::WalkBuilder;
use rawgrep::ignore::{build_gitignore_from_bytes, GitignoreChain};

fn main() -> ExitCode {
    let root = env::args()
        .nth(1)
        .expect("usage: gitignore_oracle_check <repo-root>");

    let root = PathBuf::from(root);

    let included = collect_included_set(&root);

    let base_chain = GitignoreChain::default();
    let mut total = 0usize;
    let mut mismatches = 0usize;
    let mut rel_bytes = Vec::with_capacity(256);

    walk(
        &root,
        &root,
        0,
        0,
        base_chain,
        false,  // Root has no ignored ancestor
        &included,
        &mut rel_bytes,
        &mut total,
        &mut mismatches,
    );

    eprintln!("checked {total} paths, {mismatches} mismatch(es)");

    if mismatches > 0 {
        ExitCode::FAILURE
    } else {
        ExitCode::SUCCESS
    }
}

/// Runs a full tree walk with the `ignore` crate and returns the set of
/// relative paths (as raw forward-slash byte slices) it did NOT prune.
fn collect_included_set(root: &Path) -> HashSet<Vec<u8>> {
    let mut included = HashSet::new();

    let walker = WalkBuilder::new(root)
        .hidden(false)
        .parents(false)
        .git_ignore(true)
        .git_global(false)
        .git_exclude(false)
        .ignore(false)
        .require_git(false)
        .build();

    for result in walker.flatten() {
        let path = result.path();
        if path == root {
            continue;
        }

        if let Ok(rel) = path.strip_prefix(root) {
            included.insert(path_to_slash_bytes(rel));
        }
    }

    included
}

fn walk(
    root: &Path,
    dir: &Path,
    depth: u16,
    prefix_len: u32,
    mut chain: GitignoreChain,
    ancestor_ignored: bool,
    included: &HashSet<Vec<u8>>,
    rel_bytes: &mut Vec<u8>,
    total: &mut usize,
    mismatches: &mut usize,
) {
    let gi_path = dir.join(".gitignore");

    let mut initialized = false;
    if let Ok(content) = fs::read(&gi_path) {
        let gi = build_gitignore_from_bytes(&content);
        chain = if depth == 0 {
            GitignoreChain::from_root(gi)
        } else {
            chain.with_gitignore(depth, prefix_len, gi)
        };
        initialized = true;
    }

    if depth == 0 && !initialized {
        chain = GitignoreChain::from_root(build_gitignore_from_bytes(b""));
    }

    //
    // Read directory children
    //
    let entries = match fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return,
    };

    let mut children: Vec<_> = entries.filter_map(|e| e.ok()).collect();
    children.sort_by_key(|e| e.file_name());

    let base_len = rel_bytes.len();

    for entry in children {
        let name = entry.file_name();
        if name == ".git" {
            continue;
        }

        let is_dir = match entry.file_type() {
            Ok(ft) => ft.is_dir(),
            Err(_) => continue,
        };

        //
        // Re-use scratch buffer for relative path calculation (push/truncate)
        //
        rel_bytes.truncate(base_len);
        if base_len > 0 {
            rel_bytes.push(b'/');
        }
        append_os_str_bytes(rel_bytes, name.as_os_str());

        //
        // Evaluation
        //

        let ours = ancestor_ignored || chain.is_ignored(rel_bytes, is_dir);
        let oracle = !included.contains(rel_bytes);

        *total += 1;
        if ours != oracle {
            *mismatches += 1;
            println!(
                "MISMATCH\t{}\tours={}\tignore-crate={}\t{}",
                String::from_utf8_lossy(rel_bytes),
                ours as u8,
                oracle as u8,
                if is_dir { "dir" } else { "file" },
            );
        }

        if is_dir {
            let child_path = entry.path();
            let new_prefix_len = rel_bytes.len() as u32;
            walk(
                root,
                &child_path,
                depth + 1,
                new_prefix_len,
                chain.clone(),
                ours,
                included,
                rel_bytes,
                total,
                mismatches,
            );
        }
    }

    //
    // Reset buffer to parent state before returning up the stack
    //
    rel_bytes.truncate(base_len);
}

/// Normalizes a `Path` to forward-slash byte representation.
fn path_to_slash_bytes(path: &Path) -> Vec<u8> {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        path.as_os_str().as_bytes().to_vec()
    }

    #[cfg(not(unix))]
    {
        path.to_string_lossy().replace('\\', "/").into_bytes()
    }
}

fn append_os_str_bytes(buf: &mut Vec<u8>, os_str: &std::ffi::OsStr) {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        buf.extend_from_slice(os_str.as_bytes());
    }

    #[cfg(not(unix))]
    {
        buf.extend_from_slice(os_str.to_string_lossy().as_bytes());
    }
}
