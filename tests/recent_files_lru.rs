//! v1.1.10 recent-files LRU semantics.
//!
//! Both `Pumpbin` (Generator) and `Maker` keep a recent-files list. The
//! original implementation capped each at 10 entries with manual code at
//! every call site. v1.1.10 centralizes the cap in `pumpbin::RECENT_FILES_CAP`
//! and bumps it to 20. This test asserts the public constant value and the
//! basic LRU contract — dedup-on-reinsert + oldest-eviction.
//!
//! The `add_recent_file` methods themselves are private (they live behind
//! GUI event handlers), so this is a constant-and-invariant test rather
//! than an integration test against the GUI state.

use pumpbin::RECENT_FILES_CAP;

#[test]
fn recent_files_cap_is_documented_constant() {
    // Locked at 20 for the 1.x line. The v2.0 plan called for 20; anything
    // smaller (the pre-1.1.10 value of 10) regresses operator UX, anything
    // larger makes the dropdown unscannable.
    assert_eq!(RECENT_FILES_CAP, 20);
}

#[test]
fn lru_dedup_drops_older_entry_on_reinsert() {
    // Mirror of the `add_recent_file` logic both Pumpbin and Maker apply,
    // verified against the shared cap constant.
    let mut list: Vec<&str> = Vec::new();
    let insert = |list: &mut Vec<&str>, p: &'static str| {
        list.retain(|x| *x != p);
        list.insert(0, p);
        list.truncate(RECENT_FILES_CAP);
    };

    insert(&mut list, "a");
    insert(&mut list, "b");
    insert(&mut list, "c");
    insert(&mut list, "a"); // re-insert "a" — should move to front, not duplicate.

    assert_eq!(list, vec!["a", "c", "b"]);
}

#[test]
fn lru_eviction_drops_oldest_when_over_cap() {
    let mut list: Vec<String> = Vec::new();
    let insert = |list: &mut Vec<String>, p: String| {
        list.retain(|x| *x != p);
        list.insert(0, p);
        list.truncate(RECENT_FILES_CAP);
    };

    // Insert 25 distinct paths into the cap-20 list.
    for i in 0..25 {
        insert(&mut list, format!("/tmp/file-{i:02}.b1n"));
    }

    // List must be exactly RECENT_FILES_CAP long, most-recently-inserted
    // at the front, oldest entries evicted.
    assert_eq!(list.len(), RECENT_FILES_CAP);
    assert_eq!(list[0], "/tmp/file-24.b1n");
    assert_eq!(
        list[RECENT_FILES_CAP - 1],
        format!("/tmp/file-{:02}.b1n", 25 - RECENT_FILES_CAP)
    );
    // The first 5 entries (0..4) should have been evicted.
    for i in 0..5 {
        let dropped = format!("/tmp/file-{i:02}.b1n");
        assert!(!list.contains(&dropped), "expected {dropped} to be evicted");
    }
}
