//! Property-based invariant tests.
//!
//! These don't compare against git or the `ignore` crate -- they check that
//! this implementation agrees with *itself* across the different code paths
//! it maintains for performance (the has_negations fast path vs the
//! order-walking slow path, the two public entry points, and the Arc
//! CoW logic in GitignoreChain). Divergence here is always a bug, with no
//! need to reason about gitignore semantics at all.

use proptest::prelude::*;
use rawgrep::ignore::{Gitignore, GitignoreChain};

// A small, hand-picked alphabet biased toward patterns that exercise every
// branch (literals, suffix/prefix wildcards, char classes, anchors,
// negation, dir-only, mid `**`) rather than uniform-random bytes, which
// mostly produce uninteresting single-char literals.
fn pattern_line_strategy() -> impl Strategy<Value = String> {
    prop_oneof![
        "[a-z]{1,6}\\.[a-z]{1,4}",
        "\\*\\.[a-z]{1,4}",
        "[a-z]{1,6}\\*",
        "/[a-z]{1,6}",
        "![a-z]{1,6}",
        "[a-z]{1,6}/",
        "[a-z]{1,4}/\\*\\*/[a-z]{1,4}",
        "\\[a-c\\][a-z]{1,4}",
    ]
}

fn gitignore_src_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec(pattern_line_strategy(), 0..12).prop_map(|lines| lines.join("\n"))
}

fn path_strategy() -> impl Strategy<Value = String> {
    prop::collection::vec("[a-z]{1,6}(\\.[a-z]{1,4})?", 1..5).prop_map(|segs| segs.join("/"))
}

fn filename_of(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

proptest! {
    /// `is_ignored_with_filename` must never panic regardless of input shape,
    /// including degenerate empty paths/filenames and paths shorter than
    /// patterns -- this is the property that would catch the kind of
    /// off-by-one that `get_unchecked` turns into UB instead of a panic in
    /// release builds, so it's worth having even though ASan-fuzzing (see
    /// fuzz/) is the stronger check.
    #[test]
    fn never_panics(src in gitignore_src_strategy(), path in path_strategy(), is_dir in any::<bool>()) {
        let gi = Gitignore::from_bytes(src.as_bytes());
        let filename = filename_of(&path);
        let _ = gi.is_ignored_with_filename(path.as_bytes(), filename.as_bytes(), is_dir);
        let _ = gi.is_ignored_with_filename(b"", b"", is_dir);
    }

    /// For a negation-free gitignore, is_ignored_with_filename_hashed takes
    /// the has_negations == false fast path (literal hash table + anchored
    /// literal scan + wildcard scan). Deleting all `!` lines from a ruleset
    /// and re-adding them one at a time should never flip an already-true
    /// result back to false purely due to *ordering* -- with no negations
    /// present, match order is irrelevant by construction, so any-match
    /// must equal the fast path's answer for every prefix of the ruleset.
    #[test]
    fn fast_path_agrees_with_incremental_addition(
        lines in prop::collection::vec(pattern_line_strategy(), 1..10)
            .prop_filter("no negations", |v| v.iter().all(|l| !l.starts_with('!'))),
        path in path_strategy(),
        is_dir in any::<bool>(),
    ) {
        let filename = filename_of(&path).to_string();
        let mut any_true = false;
        for i in 0..lines.len() {
            let src = lines[..=i].join("\n");
            let gi = Gitignore::from_bytes(src.as_bytes());
            let result = gi.is_ignored_with_filename(path.as_bytes(), filename.as_bytes(), is_dir);
            any_true |= result;
            // Once ANY prefix matches, the full ruleset (superset of patterns,
            // still no negations) must also match -- a match can never be
            // "un-matched" by adding more non-negating patterns.
            if any_true {
                let full = lines.join("\n");
                let full_gi = Gitignore::from_bytes(full.as_bytes());
                prop_assert!(full_gi.is_ignored_with_filename(path.as_bytes(), filename.as_bytes(), is_dir));
            }
        }
    }

    /// GitignoreChain::with_gitignore must only ever retain stack entries
    /// with depth <= the newly-inserted depth, whether it takes the
    /// exclusive-ownership (Arc::try_unwrap Ok) or shared-clone (Err) path.
    /// We force both paths for the *same* logical sequence of operations by
    /// cloning the chain right before the call that would otherwise be
    /// exclusive, and check both chains agree afterward.
    #[test]
    fn cow_exclusive_and_shared_paths_agree(
        base in gitignore_src_strategy(),
        added in gitignore_src_strategy(),
        depth in 0u16..8,
        path in path_strategy(),
        is_dir in any::<bool>(),
    ) {
        let root = Gitignore::from_bytes(base.as_bytes());
        let chain_exclusive = GitignoreChain::from_root(Gitignore::from_bytes(base.as_bytes()));
        let chain_shared = GitignoreChain::from_root(root);

        // Force the shared/Err(Arc::try_unwrap) branch by holding a second
        // reference alive across the call.
        let _keep_alive = chain_shared.clone();

        let filename = filename_of(&path).to_string();
        let a = chain_exclusive
            .with_gitignore(depth, 0, Gitignore::from_bytes(added.as_bytes()))
            .is_ignored(path.as_bytes(), is_dir);
        let b = chain_shared
            .with_gitignore(depth, 0, Gitignore::from_bytes(added.as_bytes()))
            .is_ignored(path.as_bytes(), is_dir);

        prop_assert_eq!(a, b, "CoW exclusive vs shared path diverged for path={:?}", (path, filename));
    }

    /// Adding a gitignore at a shallower-or-equal depth than an existing
    /// entry must prune everything strictly deeper than the new depth --
    /// verified indirectly: a marker pattern installed at depth `deep`
    /// must stop matching once we insert a new gitignore at `shallow <= deep`.
    #[test]
    fn shallower_insert_prunes_deeper_entries(
        shallow in 0u16..4,
        extra in 1u16..4, // deep = shallow + extra, guarantees deep > shallow
    ) {
        let deep = shallow + extra;
        let chain = GitignoreChain::from_root(Gitignore::from_bytes(b""));
        let chain = chain.with_gitignore(deep, 0, Gitignore::from_bytes(b"marker.txt\n"));
        prop_assert!(chain.is_ignored(b"marker.txt", false));

        let chain = chain.with_gitignore(shallow, 0, Gitignore::from_bytes(b"other.txt\n"));
        prop_assert!(!chain.is_ignored(b"marker.txt", false), "deeper entry should have been pruned");
        prop_assert!(chain.is_ignored(b"other.txt", false));
    }
}

#[cfg(test)]
mod chain_tests {
    use super::*;

    //
    // BASIC CHAIN OPERATIONS
    //

    #[test]
    fn test_empty_chain() {
        let chain = GitignoreChain::default();

        assert!(chain.is_empty());
        assert!(!chain.is_ignored(b"anything", false));
        assert!(!chain.is_ignored(b"file.txt", false));
        assert!(!chain.is_ignored(b"node_modules", true));
    }

    #[test]
    fn test_chain_from_root() {
        let gi = Gitignore::from_bytes(b"*.log\ntarget/\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(!chain.is_empty());
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"target", true));
        assert!(!chain.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_chain_single_gitignore() {
        let gi = Gitignore::from_bytes(b"node_modules\n*.tmp\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"node_modules", true));
        assert!(chain.is_ignored(b"src/node_modules", true));
        assert!(chain.is_ignored(b"file.tmp", false));
        assert!(chain.is_ignored(b"deep/path/file.tmp", false));
    }

    //
    // CHAIN DEPTH AND STACKING
    //

    #[test]
    fn test_chain_with_gitignore_adds_depth() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let sub = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, 0, sub);

        // Both patterns should match
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(!chain.is_ignored(b"test.txt", false));
    }

    #[test]
    fn test_chain_multiple_depths() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth1 = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, 0, depth1);

        let depth2 = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(2, 0, depth2);

        // All three patterns should match
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(chain.is_ignored(b"test.bak", false));
        assert!(!chain.is_ignored(b"test.txt", false));
    }

    #[test]
    fn test_chain_depth_pruning() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth2 = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(2, 0, depth2);

        let depth3 = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(3, 0, depth3);

        // Now add at depth 1 - should prune depth 2 and 3
        let depth1_new = Gitignore::from_bytes(b"*.cache\n");
        let chain = chain.with_gitignore(1, 0, depth1_new);

        // Root (depth 0) and new depth 1 should remain
        assert!(chain.is_ignored(b"test.log", false));    // depth 0
        assert!(chain.is_ignored(b"test.cache", false));  // depth 1

        // These were pruned
        assert!(!chain.is_ignored(b"test.tmp", false));   // was depth 2
        assert!(!chain.is_ignored(b"test.bak", false));   // was depth 3
    }

    #[test]
    fn test_chain_same_depth_replaces() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let first = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, 0, first);

        // Add another at same depth - first one should be pruned
        let second = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(1, 0, second);

        assert!(chain.is_ignored(b"test.log", false));   // root remains
        assert!(chain.is_ignored(b"test.bak", false));   // new depth 1
    }

    #[test]
    fn test_chain_deeper_depth_doesnt_prune() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth1 = Gitignore::from_bytes(b"*.tmp\n");
        let chain = chain.with_gitignore(1, 0, depth1);

        // Add at deeper depth - shouldn't prune anything
        let depth5 = Gitignore::from_bytes(b"*.bak\n");
        let chain = chain.with_gitignore(5, 0, depth5);

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(chain.is_ignored(b"test.bak", false));
    }

    //
    // NEGATION HANDLING IN CHAIN
    //

    #[test]
    fn test_chain_negation_in_same_gitignore() {
        let gi = Gitignore::from_bytes(b"*.log\n!important.log\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"debug.log", false));
        assert!(!chain.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_chain_negation_across_depths() {
        // Root ignores all .log files
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Subdirectory negates important.log
        let sub = Gitignore::from_bytes(b"!important.log\n");
        let chain = chain.with_gitignore(1, 0, sub);

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"debug.log", false));
        assert!(!chain.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_chain_negation_then_reignore() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        let depth1 = Gitignore::from_bytes(b"!important.log\n");
        let chain = chain.with_gitignore(1, 0, depth1);

        // Re-ignore at deeper level
        let depth2 = Gitignore::from_bytes(b"important.log\n");
        let chain = chain.with_gitignore(2, 0, depth2);

        // Last match wins
        assert!(chain.is_ignored(b"important.log", false));
    }

    #[test]
    fn test_chain_no_negations_early_exit() {
        // When no negations exist, chain can early-exit on first match
        let root = Gitignore::from_bytes(b"target\n");
        let chain = GitignoreChain::from_root(root);

        let sub = Gitignore::from_bytes(b"node_modules\n");
        let chain = chain.with_gitignore(1, 0, sub);

        // Both should match
        assert!(chain.is_ignored(b"target", true));
        assert!(chain.is_ignored(b"node_modules", true));

        // Verify has_any_negations is false (can't directly test, but behavior should be correct)
        assert!(!chain.is_ignored(b"src", true));
    }

    #[test]
    fn test_chain_with_negations_checks_all() {
        let root = Gitignore::from_bytes(b"*.txt\n");
        let chain = GitignoreChain::from_root(root);

        // This gitignore has negation
        let sub = Gitignore::from_bytes(b"!readme.txt\n*.md\n");
        let chain = chain.with_gitignore(1, 0, sub);

        assert!(chain.is_ignored(b"test.txt", false));
        assert!(!chain.is_ignored(b"readme.txt", false));  // Negated
        assert!(chain.is_ignored(b"doc.md", false));
    }

    //
    // CLONING AND ARC BEHAVIOR
    //

    #[test]
    fn test_chain_clone_is_cheap() {
        let root = Gitignore::from_bytes(b"*.log\nnode_modules\ntarget\n");
        let chain = GitignoreChain::from_root(root);

        // Clone should be O(1) - just Arc refcount bump
        let chain2 = chain.clone();
        let chain3 = chain.clone();

        // All clones should work identically
        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain2.is_ignored(b"test.log", false));
        assert!(chain3.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_cow_behavior_exclusive() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // No other references - should mutate in place (COW)
        let chain = chain.with_gitignore(1, 0, Gitignore::from_bytes(b"*.tmp\n"));

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
    }

    #[test]
    fn test_chain_cow_behavior_shared() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Create a clone (now refcount > 1)
        let chain_clone = chain.clone();

        // This should clone the stack (COW)
        let chain_modified = chain.with_gitignore(1, 0, Gitignore::from_bytes(b"*.tmp\n"));

        // Original clone unchanged
        assert!(chain_clone.is_ignored(b"test.log", false));
        assert!(!chain_clone.is_ignored(b"test.tmp", false));

        // Modified chain has both
        assert!(chain_modified.is_ignored(b"test.log", false));
        assert!(chain_modified.is_ignored(b"test.tmp", false));
    }

    //
    // REAL-WORLD SCENARIOS
    //

    #[test]
    fn test_chain_typical_project_structure() {
        // Root .gitignore
        let root = Gitignore::from_bytes(b"
target/
*.log
.env
node_modules/
");
        let chain = GitignoreChain::from_root(root);

        // src/.gitignore
        let src = Gitignore::from_bytes(b"
generated/
*.generated.rs
");
        let chain = chain.with_gitignore(1, 0, src);

        // src/tests/.gitignore
        let tests = Gitignore::from_bytes(b"
fixtures/
*.snapshot
!important.snapshot
");
        let chain = chain.with_gitignore(2, 0, tests);

        // Test root patterns
        assert!(chain.is_ignored(b"target", true));
        assert!(chain.is_ignored(b"app.log", false));
        assert!(chain.is_ignored(b".env", false));
        assert!(chain.is_ignored(b"node_modules", true));

        // Test src patterns
        assert!(chain.is_ignored(b"generated", true));
        assert!(chain.is_ignored(b"types.generated.rs", false));

        // Test tests patterns
        assert!(chain.is_ignored(b"fixtures", true));
        assert!(chain.is_ignored(b"test.snapshot", false));
        assert!(!chain.is_ignored(b"important.snapshot", false));

        // Non-ignored files
        assert!(!chain.is_ignored(b"main.rs", false));
        assert!(!chain.is_ignored(b"Cargo.toml", false));
    }

    #[test]
    fn test_chain_monorepo_structure() {
        // Root
        let root = Gitignore::from_bytes(b"
.git/
*.log
.env*
");
        let chain = GitignoreChain::from_root(root);

        // packages/frontend
        let frontend = Gitignore::from_bytes(b"
dist/
node_modules/
.next/
");
        let frontend_chain = chain.clone().with_gitignore(2, 0, frontend);

        // packages/backend
        let backend = Gitignore::from_bytes(b"
target/
*.pyc
__pycache__/
");
        let backend_chain = chain.clone().with_gitignore(2, 0, backend);

        // Frontend chain
        assert!(frontend_chain.is_ignored(b"dist", true));
        assert!(frontend_chain.is_ignored(b"node_modules", true));
        assert!(frontend_chain.is_ignored(b".next", true));
        assert!(!frontend_chain.is_ignored(b"target", true));

        // Backend chain
        assert!(backend_chain.is_ignored(b"target", true));
        assert!(backend_chain.is_ignored(b"app.pyc", false));
        assert!(backend_chain.is_ignored(b"__pycache__", true));
        assert!(!backend_chain.is_ignored(b"node_modules", true));

        // Both have root patterns
        assert!(frontend_chain.is_ignored(b".git", true));
        assert!(backend_chain.is_ignored(b".git", true));
        assert!(frontend_chain.is_ignored(b"debug.log", false));
        assert!(backend_chain.is_ignored(b"debug.log", false));
    }

    #[test]
    fn test_chain_deep_nesting() {
        let chain = GitignoreChain::from_root(Gitignore::from_bytes(b"*.log\n"));

        let chain = chain.with_gitignore(1, 0, Gitignore::from_bytes(b"*.tmp\n"));
        let chain = chain.with_gitignore(2, 0, Gitignore::from_bytes(b"*.bak\n"));
        let chain = chain.with_gitignore(3, 0, Gitignore::from_bytes(b"*.old\n"));
        let chain = chain.with_gitignore(4, 0, Gitignore::from_bytes(b"*.cache\n"));
        let chain = chain.with_gitignore(5, 0, Gitignore::from_bytes(b"*.swp\n"));

        assert!(chain.is_ignored(b"test.log", false));
        assert!(chain.is_ignored(b"test.tmp", false));
        assert!(chain.is_ignored(b"test.bak", false));
        assert!(chain.is_ignored(b"test.old", false));
        assert!(chain.is_ignored(b"test.cache", false));
        assert!(chain.is_ignored(b"test.swp", false));
        assert!(!chain.is_ignored(b"test.txt", false));
    }

    #[test]
    fn test_chain_directory_traversal_simulation() {
        // Simulate walking: root -> src -> src/lib -> src/lib/utils
        let root = Gitignore::from_bytes(b"target/\n*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Enter src/ (no .gitignore here, but we pass the chain along)
        let chain_src = chain.clone();

        // Enter src/lib/ (has .gitignore)
        let lib_gi = Gitignore::from_bytes(b"generated/\n");
        let chain_lib = chain_src.clone().with_gitignore(2, 0, lib_gi);

        // Enter src/lib/utils/ (has .gitignore)
        let utils_gi = Gitignore::from_bytes(b"*.generated.rs\n");
        let chain_utils = chain_lib.clone().with_gitignore(3, 0, utils_gi);

        // Now go back up to src/tests/ (should NOT have lib's patterns)
        let tests_gi = Gitignore::from_bytes(b"fixtures/\n");
        let chain_tests = chain_src.clone().with_gitignore(2, 0, tests_gi);

        // chain_utils has: root + lib + utils
        assert!(chain_utils.is_ignored(b"target", true));
        assert!(chain_utils.is_ignored(b"generated", true));
        assert!(chain_utils.is_ignored(b"types.generated.rs", false));

        // chain_tests has: root + tests (NOT lib or utils)
        assert!(chain_tests.is_ignored(b"target", true));
        assert!(chain_tests.is_ignored(b"fixtures", true));
        assert!(!chain_tests.is_ignored(b"generated", true));
        assert!(!chain_tests.is_ignored(b"types.generated.rs", false));
    }

    //
    // EDGE CASES
    //

    #[test]
    fn test_chain_empty_gitignore() {
        let empty = Gitignore::from_bytes(b"");
        let chain = GitignoreChain::from_root(empty);

        // Should not be empty (has a gitignore, just with no patterns)
        // Actually, is_empty checks stack.is_empty(), and we pushed one
        assert!(!chain.is_empty());
        assert!(!chain.is_ignored(b"anything", false));
    }

    #[test]
    fn test_chain_comments_only_gitignore() {
        let comments = Gitignore::from_bytes(b"# Just a comment\n# Another comment\n");
        let chain = GitignoreChain::from_root(comments);

        assert!(!chain.is_ignored(b"file.txt", false));
    }

    #[test]
    fn test_chain_with_gitignore_on_empty() {
        let chain = GitignoreChain::default();

        let gi = Gitignore::from_bytes(b"*.log\n");
        let chain = chain.with_gitignore(5, 0, gi);

        assert!(!chain.is_empty());
        assert!(chain.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_depth_zero() {
        let chain = GitignoreChain::default();

        let gi = Gitignore::from_bytes(b"*.log\n");
        let chain = chain.with_gitignore(0, 0, gi);

        assert!(chain.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_max_depth() {
        let chain = GitignoreChain::default();

        let gi = Gitignore::from_bytes(b"*.log\n");
        let chain = chain.with_gitignore(u16::MAX, 0, gi);

        assert!(chain.is_ignored(b"test.log", false));
    }

    #[test]
    fn test_chain_filename_extraction() {
        let gi = Gitignore::from_bytes(b"secret.txt\n");
        let chain = GitignoreChain::from_root(gi);

        // Should match filename regardless of path depth
        assert!(chain.is_ignored(b"secret.txt", false));
        assert!(chain.is_ignored(b"a/secret.txt", false));
        assert!(chain.is_ignored(b"a/b/secret.txt", false));
        assert!(chain.is_ignored(b"a/b/c/d/e/secret.txt", false));
    }

    #[test]
    fn test_chain_dir_vs_file() {
        let gi = Gitignore::from_bytes(b"build/\nbuild.rs\n");
        let chain = GitignoreChain::from_root(gi);

        // build/ only matches directories
        assert!(chain.is_ignored(b"build", true));
        assert!(!chain.is_ignored(b"build", false));  // file named "build"

        // build.rs matches files
        assert!(chain.is_ignored(b"build.rs", false));
        assert!(chain.is_ignored(b"src/build.rs", false));
    }

    #[test]
    fn test_chain_unicode_paths() {
        let gi = Gitignore::from_bytes("日本語.txt\n*.中文\n".as_bytes());
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored("日本語.txt".as_bytes(), false));
        assert!(chain.is_ignored("test.中文".as_bytes(), false));
    }

    #[test]
    fn test_chain_special_characters_in_path() {
        let gi = Gitignore::from_bytes(b"file with spaces.txt\nfile-with-dashes.log\n");
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"file with spaces.txt", false));
        assert!(chain.is_ignored(b"file-with-dashes.log", false));
    }

    //
    // PERFORMANCE-RELATED TESTS
    //

    #[test]
    fn test_chain_many_gitignores() {
        let mut chain = GitignoreChain::default();

        for i in 0..100u16 {
            let pattern = format!("pattern{}.txt\n", i);
            let gi = Gitignore::from_bytes(pattern.as_bytes());
            chain = chain.with_gitignore(i, 0, gi);
        }

        assert!(chain.is_ignored(b"pattern0.txt", false));
        assert!(chain.is_ignored(b"pattern50.txt", false));
        assert!(chain.is_ignored(b"pattern99.txt", false));
        assert!(!chain.is_ignored(b"pattern100.txt", false));
    }

    #[test]
    fn test_chain_many_patterns_per_gitignore() {
        let mut patterns = String::new();
        for i in 0..500 {
            patterns.push_str(&format!("file{}.txt\n", i));
        }

        let gi = Gitignore::from_bytes(patterns.as_bytes());
        let chain = GitignoreChain::from_root(gi);

        assert!(chain.is_ignored(b"file0.txt", false));
        assert!(chain.is_ignored(b"file250.txt", false));
        assert!(chain.is_ignored(b"file499.txt", false));
        assert!(!chain.is_ignored(b"file500.txt", false));
    }

    #[test]
    fn test_chain_long_paths() {
        let gi = Gitignore::from_bytes(b"target\n");
        let chain = GitignoreChain::from_root(gi);

        let long_path = b"a/b/c/d/e/f/g/h/i/j/k/l/m/n/o/p/q/r/s/t/u/v/w/x/y/z/target";
        assert!(chain.is_ignored(long_path, true));
    }

    #[test]
    fn test_chain_repeated_clone_and_extend() {
        let root = Gitignore::from_bytes(b"*.log\n");
        let chain = GitignoreChain::from_root(root);

        // Simulate many parallel directory traversals
        let mut chains = Vec::new();
        for i in 0..10u16 {
            let gi = Gitignore::from_bytes(format!("dir{}/\n", i).as_bytes());
            chains.push(chain.clone().with_gitignore(i + 1, 0, gi));
        }

        // Each chain should have root + its own pattern
        for (i, c) in chains.iter().enumerate() {
            assert!(c.is_ignored(b"test.log", false));
            assert!(c.is_ignored(format!("dir{}", i).as_bytes(), true));
        }
    }
}
