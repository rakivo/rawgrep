use rawgrep::cache::*;
use proptest::prelude::*;

// --- Helpers --------------------------------------------------------------

fn key(n: u64)              -> FileKey  { FileKey::new(1, n) }
fn meta(mtime: i64, sz: u64) -> FileMeta { FileMeta::new(mtime, sz) }

fn absent_presence(n: usize) -> Vec<bool> { vec![false; n] }
fn present_presence(n: usize) -> Vec<bool> { vec![true; n] }

// --- can_skip_file --------------------------------------------------------

#[test]
fn absent_fragment_allows_skip() {
    let hash_a = 0xAAAA_AAAA_u32;
    let hash_b = 0xBBBB_BBBB_u32;

    let cache = FragmentCache::with_test_data(
        vec![hash_a, hash_b],
        vec![key(1)],
        vec![meta(100, 200)],
        vec![vec![true, false]], // A present, B absent
    );

    assert!(cache.can_skip_file(key(1), meta(100, 200), &[hash_b]));
}

#[test]
fn present_fragment_prevents_skip() {
    let hash_a = 0xAAAA_AAAA_u32;

    let cache = FragmentCache::with_test_data(
        vec![hash_a],
        vec![key(1)],
        vec![meta(100, 200)],
        vec![present_presence(1)],
    );

    assert!(!cache.can_skip_file(key(1), meta(100, 200), &[hash_a]));
}

#[test]
fn unknown_file_is_not_skipped() {
    let cache = FragmentCache::new_in_memory(64, 64);
    assert!(!cache.can_skip_file(key(999), meta(1, 1), &[0xDEAD]));
}

#[test]
fn stale_metadata_invalidates() {
    let hash = 0xDEAD_BEEF_u32;

    let cache = FragmentCache::with_test_data(
        vec![hash],
        vec![key(1)],
        vec![meta(100, 200)],
        vec![absent_presence(1)],
    );

    assert!(!cache.can_skip_file(key(1), meta(999, 200), &[hash]));
}

#[test]
fn unknown_fragment_does_not_skip() {
    let cache = FragmentCache::with_test_data(
        vec![0x1111],
        vec![key(1)],
        vec![meta(1, 1)],
        vec![absent_presence(1)],
    );

    assert!(!cache.can_skip_file(key(1), meta(1, 1), &[0x9999_9999]));
}

// --- merge_updates --------------------------------------------------------

#[test]
fn merge_updates_absent_fragment_skippable() {
    let mut cache = FragmentCache::new_in_memory(64, 64);
    let hash = 0xCAFE_BABE_u32;

    cache.merge_updates_bool(
        vec![key(42)],
        vec![meta(1234, 5678)],
        &[hash],
        vec![false],
    ).unwrap();

    assert!(cache.can_skip_file(key(42), meta(1234, 5678), &[hash]));
}

#[test]
fn merge_updates_present_fragment_not_skippable() {
    let mut cache = FragmentCache::new_in_memory(64, 64);
    let hash = 0x1234_5678_u32;

    cache.merge_updates_bool(
        vec![key(1)],
        vec![meta(1, 1)],
        &[hash],
        vec![true],
    ).unwrap();

    assert!(!cache.can_skip_file(key(1), meta(1, 1), &[hash]));
}

#[test]
fn lookup_table_consistent_after_many_inserts() {
    let mut cache = FragmentCache::new_in_memory(32, 1024);
    let hash = 0xABCD_EF01_u32;

    let file_keys:  Vec<FileKey>  = (0..500).map(key).collect();
    let file_metas: Vec<FileMeta> = (0..500).map(|i| meta(i, i as u64)).collect();
    let presences: Vec<bool> = (0..500).map(|_| false).collect();

    cache.merge_updates_bool(file_keys.clone(), file_metas.clone(), &[hash], presences).unwrap();

    for (i, &k) in file_keys.iter().enumerate() {
        assert!(
            cache.can_skip_file(k, file_metas[i], &[hash]),
            "file {i} not skippable after bulk insert"
        );
    }
}

// --- ring buffer ---------------------------------------------------------

#[test]
fn ring_buffer_eviction_clears_evicted_slot() {
    let mut cache = FragmentCache::new_in_memory(4, 64);
    let k = key(1);
    let m = meta(1, 1);

    let hashes: Vec<u32> = (0..4).map(|i| i as u32 * 0x1111).collect();
    cache.merge_updates_bool(
        vec![k], vec![m], &hashes,
        vec![false, false, false, false],
    ).unwrap();

    // 5th fragment evicts slot 0
    let new_hash = 0xDEAD_DEAD_u32;
    cache.merge_updates_bool(
        vec![k], vec![m], &[new_hash],
        vec![false],
    ).unwrap();

    // evicted fragment -> unknown -> cannot skip
    assert!(!cache.can_skip_file(k, m, &[hashes[0]]));
    // new fragment -> absent -> can skip
    assert!(cache.can_skip_file(k, m, &[new_hash]));
}

#[test]
fn ring_buffer_wrap_does_not_panic() {
    const MAX: usize = 8;
    let mut cache = FragmentCache::new_in_memory(MAX, 32);

    for round in 0u32..3 {
        let k = key(round as u64);
        let m = meta(round as i64, round as u64);
        let hashes: Vec<u32> = (0..MAX).map(|i| round * 100 + i as u32).collect();
        let presence: Vec<bool> = hashes.iter().map(|_| false).collect();

        cache.merge_updates_bool(vec![k], vec![m], &hashes, presence).unwrap();
    }

    let _ = cache.memory_usage(); // just assert no corruption
}

// --- proptest -------------------------------------------------------------

proptest! {
    #[test]
    fn prop_ring_buffer_no_panic(
        max_frags in 1usize..=64,
        num_rounds in 1usize..=8,
        hashes in prop::collection::vec(any::<u32>(), 1..=16),
    ) {
        let mut cache = FragmentCache::new_in_memory(max_frags, 128);
        let k = key(1);
        let m = meta(1, 1);

        for _ in 0..num_rounds {
            let presence: Vec<bool> = hashes.iter().map(|_| false).collect();
            cache.merge_updates_bool(vec![k], vec![m], &hashes, presence).unwrap();
        }

        let _ = cache.memory_usage();
    }

    #[test]
    fn prop_random_insertions_lookup_consistent(
        num_files in 1usize..=256,
        seed in any::<u64>(),
    ) {
        let mut cache = FragmentCache::new_in_memory(32, 1024);
        let hash = 0xFEED_FACE_u32;

        let keys:   Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
        let metas:  Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();
        let presences: Vec<bool> = (0..num_files).map(|_| false).collect();

        cache.merge_updates_bool(keys.clone(), metas.clone(), &[hash], presences).unwrap();

        for i in 0..num_files {
            prop_assert!(
                cache.can_skip_file(keys[i], metas[i], &[hash]),
                "file {i} missing from lookup"
            );
        }
    }

    #[test]
    fn prop_bitset_absent_vs_present(
        frag_count in 1usize..=32,
        absent_mask in any::<u32>(),
    ) {
        let hashes: Vec<u32> = (0..frag_count).map(|i| (i as u32).wrapping_mul(0x1111_1111)).collect();
        let presence: Vec<bool> = (0..frag_count)
            .map(|i| (absent_mask >> (i % 32)) & 1 == 0)
            .collect();

        let cache = FragmentCache::with_test_data(
            hashes.clone(),
            vec![key(1)],
            vec![meta(1, 1)],
            vec![presence.clone()],
        );

        for (i, &hash) in hashes.iter().enumerate() {
            let is_absent  = !presence[i];
            let skippable  = cache.can_skip_file(key(1), meta(1, 1), &[hash]);
            prop_assert_eq!(
                skippable, is_absent,
                "frag {}: absent={} skippable={}", i, is_absent, skippable
            );
        }
    }
}

// --- disk roundtrip (DiskStorage) ----------------------------------------

#[test]
fn disk_roundtrip_preserves_data() {
    let dir = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        max_fragments: 64,
        max_files: 256,
        cache_dir: Some(dir.path().into()),
        ignore_cache: false,
    };

    let hash = 0xDEAD_BEEF_u32;
    let k    = key(77);
    let m    = meta(999, 1234);

    {
        let mut cache = FragmentCache::new(&config).unwrap();
        cache.merge_updates_bool(
            vec![k], vec![m], &[hash],
            vec![false],
        ).unwrap();
        cache.save_to_disk().unwrap();
    }

    {
        let cache = FragmentCache::new(&config).unwrap();
        assert!(cache.can_skip_file(k, m, &[hash]));
    }
}

#[test]
fn disk_roundtrip_alignment_odd_fragment_counts() {
    for num_frags in [1, 3, 7, 63, 64, 65] {
        let dir = tempfile::tempdir().unwrap();
        let config = CacheConfig {
            max_fragments: 128,
            max_files: 64,
            cache_dir: Some(dir.path().into()),
            ignore_cache: false,
        };

        let hashes: Vec<u32> = (0..num_frags).map(|i| i as u32 * 3).collect();
        let k = key(1);
        let m = meta(1, 1);

        {
            let mut cache = FragmentCache::new(&config).unwrap();
            let presence: Vec<bool> = hashes.iter().map(|_| false).collect();
            cache.merge_updates_bool(vec![k], vec![m], &hashes, presence).unwrap();
            cache.save_to_disk().unwrap();
        }

        {
            let cache = FragmentCache::new(&config).unwrap();
            assert!(
                cache.can_skip_file(k, m, &[hashes[0]]),
                "round-trip failed for num_frags={num_frags}"
            );
        }
    }
}

#[test]
fn disk_roundtrip_cow_preserves_old_data() {
    let dir = tempfile::tempdir().unwrap();
    let config = CacheConfig {
        max_fragments: 32,
        max_files: 128,
        cache_dir: Some(dir.path().into()),
        ignore_cache: false,
    };

    let hash1 = 0xAAAA_AAAA_u32;
    let k1    = key(1);
    let m1    = meta(1, 1);

    {
        let mut cache = FragmentCache::new(&config).unwrap();
        cache.merge_updates_bool(
            vec![k1], vec![m1], &[hash1],
            vec![false],
        ).unwrap();
        cache.save_to_disk().unwrap();
    }

    {
        let mut cache = FragmentCache::new(&config).unwrap();

        // insert new file -> triggers CoW
        let hash2 = 0xBBBB_BBBB_u32;
        let k2    = key(2);
        let m2    = meta(2, 2);
        cache.merge_updates_bool(
            vec![k2], vec![m2], &[hash2],
            vec![false],
        ).unwrap();

        assert!(cache.can_skip_file(k1, m1, &[hash1]), "old file lost after CoW");
        assert!(cache.can_skip_file(k2, m2, &[hash2]), "new file missing after CoW");
    }
}

// --- False-positive absent: targeted regression tests ---------------------

#[test]
fn no_false_absent_basic() {
    // Simplest possible case: file has fragment, cache must not say absent
    let hash = 0xDEAD_BEEF_u32;
    let k = key(1);
    let m = meta(1, 1);

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash],
        vec![true], // PRESENT
    ).unwrap();

    assert!(!cache.can_skip_file(k, m, &[hash]),
            "false absent: fragment is present but cache says skip");
}

#[test]
fn no_false_absent_after_second_merge() {
    // File seen twice: first absent, then present (file changed)
    // After second merge, must NOT be skippable
    let hash = 0xAAAA_u32;
    let k = key(1);
    let m1 = meta(1, 100);
    let m2 = meta(2, 100); // mtime changed

    let mut cache = FragmentCache::new_in_memory(64, 64);

    // First scan: absent
    cache.merge_updates_bool(
        vec![k], vec![m1], &[hash],
        vec![false],
    ).unwrap();

    assert!(cache.can_skip_file(k, m1, &[hash]), "should be skippable after absent");

    // Second scan: present (file was modified)
    cache.merge_updates_bool(
        vec![k], vec![m2], &[hash],
        vec![true],
    ).unwrap();

    assert!(!cache.can_skip_file(k, m2, &[hash]),
            "false absent: fragment became present but cache still skips");
}

#[test]
fn no_false_absent_stride_consistency_across_fragment_additions() {
    // Add files, then add MORE fragments - the stride changes.
    // Existing files must not become falsely skippable for fragments they have.
    let hash_a = 0x1111_u32;
    let hash_b = 0x2222_u32;
    let k = key(1);
    let m = meta(1, 1);

    let mut cache = FragmentCache::new_in_memory(64, 64);

    // Register file with fragment A present
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_a],
        vec![true],
    ).unwrap();

    assert!(!cache.can_skip_file(k, m, &[hash_a]),
            "false absent before adding fragment B");

    // Now add fragment B in a second merge (different search pattern)
    // This changes num_fragments and potentially bits_per_file_u64
    cache.merge_updates_bool(
        vec![key(99)], vec![meta(99, 99)], &[hash_b],
        vec![false],
    ).unwrap();

    // File 1 still has fragment A present - must NOT be skippable
    assert!(!cache.can_skip_file(k, m, &[hash_a]),
            "false absent after adding unrelated fragment B: stride corruption?");
}

#[test]
fn no_false_absent_when_fragment_index_crosses_u64_boundary() {
    // Put fragments at positions 63 and 64 - straddles the u64 boundary
    // Wrong bit indexing would cause false absent here
    let mut cache = FragmentCache::new_in_memory(128, 64);
    let k = key(1);
    let m = meta(1, 1);

    // Fill 63 fragments as absent to push indexes to boundary
    let filler: Vec<u32> = (0u32..63).map(|i| i * 7 + 1).collect();
    let filler_presence: Vec<bool> = filler.iter().map(|_| false).collect();
    cache.merge_updates_bool(vec![k], vec![m], &filler, filler_presence).unwrap();

    // Fragment at index 63 (last bit of first u64) - present
    let hash_63 = 0xBEEF_0063_u32;
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_63],
        vec![true],
    ).unwrap();

    // Fragment at index 64 (first bit of second u64) - present
    let hash_64 = 0xBEEF_0064_u32;
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_64],
        vec![true],
    ).unwrap();

    assert!(!cache.can_skip_file(k, m, &[hash_63]),
            "false absent at bit 63 (u64 boundary)");
    assert!(!cache.can_skip_file(k, m, &[hash_64]),
            "false absent at bit 64 (start of second u64)");
}

#[test]
fn no_false_absent_after_capacity_growth() {
    // Force a capacity grow (ensure_capacity) and verify no files become
    // falsely skippable for fragments they have present
    let mut cache = FragmentCache::new_in_memory(32, 8);
    let hash = 0xCAFE_u32;

    // Insert files up to initial capacity to trigger growth
    let file_count = 200usize;
    let keys:   Vec<FileKey>  = (0..file_count).map(|i| key(i as u64)).collect();
    let metas:  Vec<FileMeta> = (0..file_count).map(|i| meta(i as i64, i as u64)).collect();
    // All files have fragment present
    let presences: Vec<bool> = (0..file_count).map(|_| true).collect();

    cache.merge_updates_bool(keys.clone(), metas.clone(), &[hash], presences).unwrap();

    for i in 0..file_count {
        assert!(!cache.can_skip_file(keys[i], metas[i], &[hash]),
                "false absent for file {i} after capacity growth");
    }
}

#[test]
fn no_false_absent_ring_buffer_does_not_corrupt_present_bits() {
    // Fill ring buffer to capacity, then overflow it.
    // The evicted fragment slot is reused - if the clear-on-evict
    // incorrectly clears a PRESENT bit for another file, we get false absent.
    const MAX_FRAGS: usize = 8;
    let mut cache = FragmentCache::new_in_memory(MAX_FRAGS, 32);

    let target_hash = 0xDEAD_1234_u32; // fragment we care about
    let target_key  = key(1);
    let target_meta = meta(1, 1);

    // Register target file with target fragment PRESENT
    cache.merge_updates_bool(
        vec![target_key], vec![target_meta], &[target_hash],
        vec![true],
    ).unwrap();

    // Now flood with other fragments to force ring buffer eviction of target_hash's slot
    for i in 0u32..(MAX_FRAGS as u32 * 3) {
        let filler_hash = 0xF000_0000 + i;
        let filler_key  = key(100 + i as u64);
        let filler_meta = meta(i as i64, i as u64);
        cache.merge_updates_bool(
            vec![filler_key], vec![filler_meta], &[filler_hash],
            vec![false],
        ).unwrap();
    }

    // target_hash was evicted from the ring buffer, so it's "unknown" now -
    // can_skip_file should return FALSE (can't prove absent) not TRUE (false absent)
    assert!(!cache.can_skip_file(target_key, target_meta, &[target_hash]),
            "false absent after ring buffer evicted the fragment: \
             eviction should make result unknown (no-skip), not absent (skip)");
}

#[test]
fn no_false_absent_multiple_fragments_one_present() {
    // Query requires [A, B, C]. File has B present, A and C absent.
    // can_skip_file should return false because B might match.
    // (skip only happens when we can prove ALL required are absent -
    // actually the logic skips if ANY is absent. So this tests the
    // semantics: if A is absent, we skip even though B is present.
    // That's correct for OR-semantics grep but would be wrong for AND-semantics.
    // This test documents the actual semantics.)
    let hash_a = 0xAAAA_u32;
    let hash_b = 0xBBBB_u32;
    let hash_c = 0xCCCC_u32;
    let k = key(1);
    let m = meta(1, 1);

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_a, hash_b, hash_c],
        vec![false, true, false], // A absent, B present, C absent
    ).unwrap();

    // A is absent -> can_skip returns true (skip because A definitely not in file)
    // This is correct for literal pattern fragments: if fragment A (part of pattern)
    // is absent, the full pattern can't match
    assert!(cache.can_skip_file(k, m, &[hash_a]),
            "should skip: fragment A is absent");

    // B is present -> cannot skip
    assert!(!cache.can_skip_file(k, m, &[hash_b]),
            "false absent: fragment B is present");

    // Querying [A, B] together: A is absent so should return true (skip)
    // because finding ANY absent fragment is enough to skip
    assert!(cache.can_skip_file(k, m, &[hash_a, hash_b]),
            "should skip when at least one required fragment is absent");
}

// --- Proptest: no false absents under random merges -----------------------

proptest! {
    #[test]
    fn prop_no_false_absent_random_merges(
        num_files in 1usize..=50,
        num_frags in 1usize..=20,
        // presence[file][frag] packed as bits in a u64
        presence_bits in prop::collection::vec(any::<u64>(), 1..=50),
        seed in any::<u64>(),
    ) {
        let mut cache = FragmentCache::new_in_memory(num_frags.max(1), num_files.max(1));

        let hashes: Vec<u32> = (0..num_frags)
            .map(|i| (seed as u32).wrapping_add(i as u32).wrapping_mul(0x9e37_9769))
            .collect();

        let keys:   Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
        let metas:  Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

        // Build presence table: presence[file][frag]
        let presence_table: Vec<Vec<bool>> = (0..num_files)
            .map(|fi| {
                let bits = presence_bits.get(fi % presence_bits.len()).copied().unwrap_or(0);
                (0..num_frags).map(|fr| (bits >> (fr % 64)) & 1 == 1).collect()
            })
            .collect();

        let presences: Vec<bool> = presence_table.iter().flat_map(|p| p.iter().copied()).collect();

        cache.merge_updates_bool(keys.clone(), metas.clone(), &hashes, presences).unwrap();

        // For every file+fragment that is PRESENT, can_skip must be false
        for fi in 0..num_files {
            for fr in 0..num_frags {
                if presence_table[fi][fr] {
                    let skippable = cache.can_skip_file(keys[fi], metas[fi], &[hashes[fr]]);
                    prop_assert!(
                        !skippable,
                        "false absent: file {} frag {} is present but can_skip=true",
                        fi, fr
                    );
                }
            }
        }
    }

    #[test]
    fn prop_no_false_absent_across_multiple_merges(
        num_rounds in 2usize..=5,
        num_frags in 1usize..=16,
        seed in any::<u64>(),
    ) {
        let mut cache = FragmentCache::new_in_memory(num_frags * num_rounds, 64);

        // ground truth: file_id -> frag_hash -> is_present
        let mut ground_truth: std::collections::HashMap<u64, std::collections::HashMap<u32, bool>>
            = std::collections::HashMap::new();

        for round in 0..num_rounds {
            let k = key(round as u64);
            let m = meta(round as i64, round as u64);
            let round_hashes: Vec<u32> = (0..num_frags)
                .map(|i| seed.wrapping_add(round as u64 * 1000 + i as u64) as u32)
                .collect();

            // Alternate: even rounds present, odd rounds absent
            let present = round % 2 == 0;
            let presences: Vec<bool> = round_hashes.iter().map(|_| present).collect();

            cache.merge_updates_bool(vec![k], vec![m], &round_hashes, presences).unwrap();

            let entry = ground_truth.entry(round as u64).or_default();
            for &h in &round_hashes {
                entry.insert(h, present);
            }
        }

        // Verify: no present fragment is falsely reported absent
        for (file_id, frags) in &ground_truth {
            let k = key(*file_id);
            let m = meta(*file_id as i64, *file_id);
            for (&hash, &present) in frags {
                if present {
                    prop_assert!(
                        !cache.can_skip_file(k, m, &[hash]),
                        "false absent: file {} hash {:#x} is present but skipped",
                        file_id, hash
                    );
                }
            }
        }
    }
}

// --- Stride boundary stress tests -----------------------------------------

#[test]
fn no_false_absent_stride_jumps_at_64_boundary() {
    // Explicitly cross the 64-fragment boundary and verify no corruption.
    // This is the exact scenario that triggered the original bug.
    let mut cache = FragmentCache::new_in_memory(128, 32);

    let num_files = 8usize;
    let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64)).collect();
    let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

    // Register all files with a known present fragment
    let anchor_hash = 0xA1C4_0000_u32;
    let anchor_presence: Vec<bool> = (0..num_files).map(|_| true).collect();
    cache.merge_updates_bool(keys.clone(), metas.clone(), &[anchor_hash], anchor_presence).unwrap();

    // Add fragments one at a time, crossing the 64-boundary
    // Each addition must not corrupt the anchor_hash present bits
    for i in 0u32..70 {
        let filler_hash = 0xF000_0000u32.wrapping_add(i);
        // use a different file for each filler so we don't affect the anchor
        let filler_key  = key(1000 + i as u64);
        let filler_meta = meta(1000 + i as i64, 1000 + i as u64);
        cache.merge_updates_bool(
            vec![filler_key], vec![filler_meta], &[filler_hash],
            vec![false],
        ).unwrap();

        // After every addition, all original files must still report anchor present
        for fi in 0..num_files {
            assert!(
                !cache.can_skip_file(keys[fi], metas[fi], &[anchor_hash]),
                "false absent after adding filler fragment {i}: \
                 file {fi} anchor present but can_skip=true \
                 (num_fragments now ~{})", i + 2
            );
        }
    }
}

#[test]
fn no_false_absent_all_files_all_fragments_present_at_each_boundary() {
    // For each multiple-of-64 boundary, verify correctness right before,
    // at, and right after the crossing.
    for boundary in [64usize, 128, 192] {
        let mut cache = FragmentCache::new_in_memory(boundary + 4, 16);
        let num_files = 4usize;
        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64 + boundary as u64 * 100)).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, boundary as u64 + i as u64)).collect();

        let mut present_hashes: Vec<u32> = Vec::new();

        // Fill up to boundary-2 with absent fragments to push count near boundary
        for i in 0u32..(boundary as u32 - 2) {
            let h = 0x0100_0000u32.wrapping_add(boundary as u32 * 1000).wrapping_add(i);
            let filler_key  = key(5000 + boundary as u64 * 1000 + i as u64);
            let filler_meta = meta(i as i64, i as u64);
            cache.merge_updates_bool(
                vec![filler_key], vec![filler_meta], &[h],
                vec![false],
            ).unwrap();
        }

        // Now add fragments at boundary-1, boundary, boundary+1 as PRESENT for all files
        for offset in [0u32, 1, 2, 3] {
            let h = 0xBEEF_0000u32.wrapping_add(boundary as u32).wrapping_add(offset);
            present_hashes.push(h);
            let presences: Vec<bool> = (0..num_files).map(|_| true).collect();
            cache.merge_updates_bool(keys.clone(), metas.clone(), &[h], presences).unwrap();

            // Immediately verify all previously-added present hashes still not skippable
            for &ph in &present_hashes {
                for fi in 0..num_files {
                    assert!(
                        !cache.can_skip_file(keys[fi], metas[fi], &[ph]),
                        "false absent at boundary {boundary}+{offset}: \
                         file {fi} hash {ph:#010x} present but skipped"
                    );
                }
            }
        }
    }
}

#[test]
fn no_false_absent_interleaved_files_and_fragments() {
    // Interleave adding new files and new fragments in alternating merges.
    // This is the hardest pattern: stride grows while file count also grows.
    let mut cache = FragmentCache::new_in_memory(200, 200);

    // ground truth: key_id -> hash -> present
    let mut ground_truth: Vec<(FileKey, FileMeta, u32, bool)> = Vec::new();

    for step in 0u32..80 {
        let k = key(step as u64);
        let m = meta(step as i64, step as u64);
        // Each step introduces a new fragment
        let h = 0x1000u32.wrapping_add(step.wrapping_mul(7919)); // prime multiplier
        let present = step % 3 != 0; // every 3rd file has it absent

        let presences = vec![present];
        cache.merge_updates_bool(vec![k], vec![m], &[h], presences).unwrap();
        ground_truth.push((k, m, h, present));

        // After every step, verify ALL ground truth entries
        for &(gk, gm, gh, gpresent) in &ground_truth {
            if gpresent {
                assert!(
                    !cache.can_skip_file(gk, gm, &[gh]),
                    "false absent at step {step}: previously present fragment {gh:#x} \
                     became skippable"
                );
            }
        }
    }
}

#[test]
fn no_false_absent_same_file_updated_across_stride_boundary() {
    // The same file is updated multiple times, with the stride crossing
    // 64 between updates. The final present state must be respected.
    let mut cache = FragmentCache::new_in_memory(130, 64);
    let k = key(42);
    let m = meta(1, 1);

    // Round 1: register file with hash_a present (stride=1, num_frags < 64)
    let hash_a = 0xAAAA_u32;
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_a],
        vec![true],
    ).unwrap();

    // Push num_fragments past 64 using other files
    for i in 0u32..65 {
        let fk = key(100 + i as u64);
        let fm = meta(i as i64, i as u64);
        let fh = 0xF000u32.wrapping_add(i);
        cache.merge_updates_bool(
            vec![fk], vec![fm], &[fh],
            vec![false],
        ).unwrap();
    }

    // Now stride=2. Re-register the same file with hash_a still present
    let hash_b = 0xBBBB_u32;
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_a, hash_b],
        vec![true, true],
    ).unwrap();

    assert!(!cache.can_skip_file(k, m, &[hash_a]),
            "false absent: hash_a present across stride boundary");
    assert!(!cache.can_skip_file(k, m, &[hash_b]),
            "false absent: hash_b present after stride boundary");
}

// --- Proptest: exhaustive stride stress -----------------------------------

proptest! {
    #[test]
    fn prop_no_false_absent_stride_stress(
        num_files in 1usize..=20,
        // Drive num_fragments through multiple 64-boundaries
        num_rounds in 1usize..=6,
        frags_per_round in 10usize..=25,
        seed in any::<u64>(),
        // which files have their fragment present in each round
        present_mask in any::<u32>(),
    ) {
        let max_frags = num_rounds * frags_per_round + 4;
        let mut cache = FragmentCache::new_in_memory(max_frags, num_files + 100);

        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

        // ground_truth[file_id][hash] = present
        let mut ground_truth: Vec<std::collections::HashMap<u32, bool>> =
            (0..num_files).map(|_| std::collections::HashMap::new()).collect();

        for round in 0..num_rounds {
            let hashes: Vec<u32> = (0..frags_per_round)
                .map(|i| {
                    let v = seed
                        .wrapping_add(round as u64 * 10000)
                        .wrapping_add(i as u64);
                    v as u32
                })
                .collect();

            // Each file's presence is determined by its bit in present_mask
            let presences: Vec<bool> = (0..num_files)
                .flat_map(|fi| {
                    let present = (present_mask >> (fi % 32)) & 1 == 1;
                    hashes.iter().map(move |_| present)
                })
                .collect();

            cache.merge_updates_bool(keys.clone(), metas.clone(), &hashes, presences).unwrap();

            for (file_index, file) in ground_truth.iter_mut().enumerate().take(num_files) {
                let present = (present_mask >> (file_index % 32)) & 1 == 1;
                for &h in &hashes {
                    file.insert(h, present);
                }
            }

            // Verify after every round - catches corruption the moment it happens
            for fi in 0..num_files {
                for (&h, &present) in &ground_truth[fi] {
                    if present {
                        prop_assert!(
                            !cache.can_skip_file(keys[fi], metas[fi], &[h]),
                            "false absent: round={round} file={fi} hash={h:#010x} \
                             present but skipped (num_fragments may have crossed 64-boundary)"
                        );
                    }
                }
            }
        }
    }

    #[test]
    fn prop_no_false_absent_dense_cross_boundary(
        // Force num_fragments to land exactly on multiples of 64
        files_before_boundary in 1usize..=8,
        files_after_boundary in 1usize..=8,
        seed in any::<u64>(),
    ) {
        // Fill exactly to 63 fragments, then add files with present fragments
        // that straddle the boundary (63, 64, 65)
        let max_frags = 130usize;
        let mut cache = FragmentCache::new_in_memory(max_frags, 200);

        // Fill 62 slots with absent filler
        for i in 0u32..62 {
            let fk = key(9000 + i as u64);
            let fm = meta(i as i64, i as u64);
            let fh = 0xDEAD_0000u32.wrapping_add(seed as u32).wrapping_add(i);
            cache.merge_updates_bool(
                vec![fk], vec![fm], &[fh],
                vec![false],
            ).unwrap();
        }

        prop_assert_eq!(
            cache.num_fragments, 62,
            "setup: expected 62 fragments"
        );

        // Register files_before_boundary files with a present hash at index 62
        let hash_62 = 0xB062u32.wrapping_add(seed as u32);
        let before_keys:  Vec<FileKey>  = (0..files_before_boundary).map(|i| key(200 + i as u64)).collect();
        let before_metas: Vec<FileMeta> = (0..files_before_boundary).map(|i| meta(200 + i as i64, 200)).collect();
        let before_presences: Vec<bool> =
            (0..files_before_boundary).map(|_| true).collect();
        cache.merge_updates_bool(before_keys.clone(), before_metas.clone(), &[hash_62], before_presences).unwrap();

        // This pushes num_fragments to 63. Now add hash at index 63 (crosses u64 boundary)
        let hash_63 = 0xB063u32.wrapping_add(seed as u32);
        let after_keys:  Vec<FileKey>  = (0..files_after_boundary).map(|i| key(300 + i as u64)).collect();
        let after_metas: Vec<FileMeta> = (0..files_after_boundary).map(|i| meta(300 + i as i64, 300)).collect();
        let after_presences: Vec<bool> =
            (0..files_after_boundary).map(|_| true).collect();
        cache.merge_updates_bool(after_keys.clone(), after_metas.clone(), &[hash_63], after_presences).unwrap();

        // Verify before-boundary files still not skippable on hash_62
        for fi in 0..files_before_boundary {
            prop_assert!(
                !cache.can_skip_file(before_keys[fi], before_metas[fi], &[hash_62]),
                "false absent: before-boundary file {fi} hash_62 present but skipped \
                 after stride crossed 64"
            );
        }

        // Verify after-boundary files not skippable on hash_63
        for fi in 0..files_after_boundary {
            prop_assert!(
                !cache.can_skip_file(after_keys[fi], after_metas[fi], &[hash_63]),
                "false absent: after-boundary file {fi} hash_63 present but skipped"
            );
        }
    }
}

// --- False present: cache must correctly identify absent fragments ---------

#[test]
fn absent_fragment_skips_correctly_basic() {
    let hash = 0xDEAD_BEEF_u32;
    let k = key(1);
    let m = meta(1, 1);

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash],
        vec![false], // explicitly absent
    ).unwrap();

    assert!(cache.can_skip_file(k, m, &[hash]),
            "fragment is absent but cache failed to skip");
}

#[test]
fn absent_verified_independently_for_each_file() {
    // 10 files. Odd-indexed have fragment absent, even-indexed have it present.
    // Verify each file independently.
    let hash = 0x1234_5678_u32;
    let num_files = 10usize;
    let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64)).collect();
    let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();
    let presences: Vec<bool> = (0..num_files)
        .map(|i| i % 2 == 0) // even=present, odd=absent
        .collect();

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(keys.clone(), metas.clone(), &[hash], presences).unwrap();

    for i in 0..num_files {
        if i % 2 == 0 {
            assert!(!cache.can_skip_file(keys[i], metas[i], &[hash]),
                    "file {i}: present fragment falsely skipped");
        } else {
            assert!(cache.can_skip_file(keys[i], metas[i], &[hash]),
                    "file {i}: absent fragment not skipped");
        }
    }
}

#[test]
fn absent_only_for_specific_fragment_not_others() {
    // File has [A=present, B=absent, C=present].
    // Must skip on B, must not skip on A or C.
    let hash_a = 0xAAAA_u32;
    let hash_b = 0xBBBB_u32;
    let hash_c = 0xCCCC_u32;
    let k = key(1);
    let m = meta(1, 1);

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_a, hash_b, hash_c],
        vec![true, false, true],
    ).unwrap();

    assert!(!cache.can_skip_file(k, m, &[hash_a]), "A is present, must not skip");
    assert!( cache.can_skip_file(k, m, &[hash_b]), "B is absent, must skip");
    assert!(!cache.can_skip_file(k, m, &[hash_c]), "C is present, must not skip");

    // Query with all three: B is absent so should skip
    assert!( cache.can_skip_file(k, m, &[hash_a, hash_b, hash_c]),
             "B absent in multi-fragment query, must skip");

    // Query with only present fragments: must not skip
    assert!(!cache.can_skip_file(k, m, &[hash_a, hash_c]),
            "all queried fragments present, must not skip");
}

#[test]
fn absent_bits_survive_capacity_growth() {
    // Insert many files with absent fragments, force capacity growth,
    // verify all absent bits are still intact.
    let mut cache = FragmentCache::new_in_memory(32, 8); // small initial capacity

    let hash = 0xABCD_u32;
    let num_files = 300usize;
    let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(i as u64)).collect();
    let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();
    // All absent
    let presences: Vec<bool> =
        (0..num_files).map(|_| false).collect();

    cache.merge_updates_bool(keys.clone(), metas.clone(), &[hash], presences).unwrap();

    for i in 0..num_files {
        assert!(cache.can_skip_file(keys[i], metas[i], &[hash]),
                "file {i}: absent bit lost after capacity growth");
    }
}

#[test]
fn absent_bits_survive_stride_boundary_crossing() {
    // Files registered as absent before the 64-fragment boundary
    // must still be skippable after the boundary is crossed.
    let mut cache = FragmentCache::new_in_memory(130, 64);

    let hash = 0x4853_0000_u32;  // this file has fragment absent
    let k = key(1);
    let m = meta(1, 1);

    cache.merge_updates_bool(
        vec![k], vec![m], &[hash],
        vec![false],
    ).unwrap();

    assert!(cache.can_skip_file(k, m, &[hash]), "absent before boundary crossing");

    // Push past 64-fragment boundary
    for i in 0u32..70 {
        let fk = key(100 + i as u64);
        let fm = meta(i as i64, i as u64);
        let fh = 0xF000_0000u32.wrapping_add(i);
        cache.merge_updates_bool(
            vec![fk], vec![fm], &[fh],
            vec![false],
        ).unwrap();
    }

    assert!(cache.can_skip_file(k, m, &[hash]),
            "absent bit lost after stride crossed 64-fragment boundary");
}

#[test]
fn absent_bits_correct_at_each_u64_boundary_position() {
    // For fragment indexes 0, 63, 64, 127, 128 - the boundary positions -
    // verify absent bits are set and read correctly.
    let boundary_indexes = [0usize, 62, 63, 64, 65, 126, 127];
    let max_frags = 130;

    for &target_index in &boundary_indexes {
        let mut cache = FragmentCache::new_in_memory(max_frags, 32);
        let k = key(target_index as u64);
        let m = meta(target_index as i64, target_index as u64);

        // Fill fragments up to target_index with absent filler (different files)
        for i in 0u32..target_index as u32 {
            let fk = key(1000 + target_index as u64 * 200 + i as u64);
            let fm = meta(i as i64, i as u64);
            let fh = 0xF100_0000u32
                .wrapping_add(target_index as u32 * 1000)
                .wrapping_add(i);
            cache.merge_updates_bool(
                vec![fk], vec![fm], &[fh],
                vec![false],
            ).unwrap();
        }

        // Now add the target fragment as ABSENT for our file
        let target_hash = 0x7670_0000u32
            .wrapping_add(target_index as u32);
        cache.merge_updates_bool(
            vec![k], vec![m], &[target_hash],
            vec![false],
        ).unwrap();

        assert!(
            cache.can_skip_file(k, m, &[target_hash]),
            "absent bit wrong at fragment index {target_index} (u64 boundary position)"
        );
    }
}

#[test]
fn absent_preserved_after_same_file_re_registered() {
    // File is registered absent, then re-registered with same meta.
    // Must still be skippable.
    let hash = 0x9999_u32;
    let k = key(7);
    let m = meta(42, 42);

    let mut cache = FragmentCache::new_in_memory(64, 64);

    cache.merge_updates_bool(
        vec![k], vec![m], &[hash],
        vec![false],
    ).unwrap();

    assert!(cache.can_skip_file(k, m, &[hash]), "absent after first registration");

    // Re-register same file, same meta, same fragment absent
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash],
        vec![false],
    ).unwrap();

    assert!(cache.can_skip_file(k, m, &[hash]),
            "absent bit cleared after re-registration of same file");
}

#[test]
fn absent_not_confused_between_adjacent_files() {
    // File A has fragment absent. File B (adjacent in storage) has it present.
    // Must not mix up their bits.
    let hash = 0x5555_5555_u32;
    let ka = key(0);
    let kb = key(1);
    let ma = meta(1, 1);
    let mb = meta(2, 2);

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(
        vec![ka, kb], vec![ma, mb], &[hash],
        vec![
            false, // A: absent
            true,  // B: present
        ],
    ).unwrap();

    assert!( cache.can_skip_file(ka, ma, &[hash]), "file A: absent, must skip");
    assert!(!cache.can_skip_file(kb, mb, &[hash]), "file B: present, must not skip");
}

#[test]
fn absent_not_confused_between_adjacent_fragments() {
    // Fragment at index N is absent, N-1 and N+1 are present.
    // Must only skip on N.
    let hash_prev = 0x0001_u32;
    let hash_mid  = 0x0002_u32;
    let hash_next = 0x0003_u32;
    let k = key(1);
    let m = meta(1, 1);

    let mut cache = FragmentCache::new_in_memory(64, 64);
    cache.merge_updates_bool(
        vec![k], vec![m], &[hash_prev, hash_mid, hash_next],
        vec![true, false, true], // mid absent
    ).unwrap();

    assert!(!cache.can_skip_file(k, m, &[hash_prev]), "prev present, must not skip");
    assert!( cache.can_skip_file(k, m, &[hash_mid]),  "mid absent, must skip");
    assert!(!cache.can_skip_file(k, m, &[hash_next]), "next present, must not skip");
}

// --- Proptest: absent correctness -----------------------------------------

proptest! {
    #[test]
    fn prop_absent_bits_survive_everything(
        num_files  in 1usize..=30,
        num_frags  in 1usize..=80, // deliberately crosses 64-boundary
        seed       in any::<u64>(),
        absent_mask in any::<u64>(), // bit fi*num_frags+fr = absent if 1
    ) {
        let mut cache = FragmentCache::new_in_memory(num_frags + 4, num_files + 4);

        let hashes: Vec<u32> = (0..num_frags)
            .map(|i| (seed as u32).wrapping_add(i as u32).wrapping_mul(0x9e37_9769))
            .collect();
        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ (i as u64 * 0x1111))).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

        // Build presence: absent_mask bit (fi + fr) % 64 drives absence
        let presence_table: Vec<Vec<bool>> = (0..num_files)
            .map(|fi| (0..num_frags)
                 .map(|fr| (absent_mask >> ((fi * num_frags + fr) % 64)) & 1 == 0)
                 .collect())
            .collect();

        let presences: Vec<bool> = presence_table.iter()
            .flat_map(|p| p.iter().copied())
            .collect();

        cache.merge_updates_bool(keys.clone(), metas.clone(), &hashes, presences).unwrap();

        for fi in 0..num_files {
            for fr in 0..num_frags {
                let absent  = !presence_table[fi][fr];
                let skipped = cache.can_skip_file(keys[fi], metas[fi], &[hashes[fr]]);
                if absent {
                    prop_assert!(skipped,
                                 "false present: file={fi} frag={fr} absent but can_skip=false \
                                  (missed skip opportunity - could cause missed matches if inverted)");
                } else {
                    prop_assert!(!skipped,
                                 "false absent: file={fi} frag={fr} present but can_skip=true \
                                  (correctness bug - matches would be missed)");
                }
            }
        }
    }

    #[test]
    fn prop_absent_bits_survive_stride_crossings(
        rounds in 2usize..=8,
        frags_per_round in 8usize..=20,
        num_files in 1usize..=16,
        seed in any::<u64>(),
    ) {
        let max_frags = rounds * frags_per_round + 4;
        let mut cache = FragmentCache::new_in_memory(max_frags, num_files + 4);

        let keys:  Vec<FileKey>  = (0..num_files).map(|i| key(seed ^ i as u64)).collect();
        let metas: Vec<FileMeta> = (0..num_files).map(|i| meta(i as i64, i as u64)).collect();

        // ground truth: (file_id, hash) -> absent
        let mut ground_truth: Vec<(usize, u32, bool)> = Vec::new();

        for round in 0..rounds {
            let hashes: Vec<u32> = (0..frags_per_round)
                .map(|i| (seed as u32)
                     .wrapping_add(round as u32 * 10000)
                     .wrapping_add(i as u32)
                     .wrapping_mul(0x517c_c1b7))
                .collect();

            // Alternate absent/present per file based on round parity
            let presences: Vec<bool> = (0..num_files)
                .flat_map(|fi| {
                    let present = (round + fi) % 2 == 0;
                    hashes.iter().map(move |_| present)
                })
                .collect();

            cache.merge_updates_bool(keys.clone(), metas.clone(), &hashes, presences).unwrap();

            for fi in 0..num_files {
                let present = (round + fi) % 2 == 0;
                for &h in &hashes {
                    ground_truth.push((fi, h, !present)); // absent = !present
                }
            }

            // Verify after every round
            for &(fi, h, absent) in &ground_truth {
                let skipped = cache.can_skip_file(keys[fi], metas[fi], &[h]);
                if absent {
                    prop_assert!(skipped,
                                 "round={round} file={fi} hash={h:#x}: absent but not skipped");
                } else {
                    prop_assert!(!skipped,
                                 "round={round} file={fi} hash={h:#x}: present but skipped");
                }
            }
        }
    }
}
