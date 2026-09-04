//! Cleanup-mode resolver tests - a child module of `smart` so smart.rs
//! keeps its size-gate baseline (same pattern as pool/unit_tests.rs).

use super::*;

#[test]
fn cleanup_mode_resolves_against_the_download_setting() {
    use CleanupMode as M;
    let _g = one_trash_test_at_a_time();
    let was_trash = delete_to_trash();
    let was_mode = cleanup_mode();
    for (mode, dl_trash, expect) in [
        // follow rides delete_to_trash, exactly the old behavior
        (M::Follow, true, true),
        (M::Follow, false, false),
        // trash/delete stand on their own, whatever downloads do
        (M::Trash, false, true),
        (M::Trash, true, true),
        (M::Delete, true, false),
        (M::Delete, false, false),
    ] {
        set_delete_to_trash(dl_trash);
        set_cleanup_mode(mode);
        assert_eq!(
            cleanup_recoverable(),
            expect,
            "mode {mode:?} with delete_to_trash={dl_trash}"
        );
    }
    // The string forms round-trip and reject garbage - the settings
    // arm leans on parse to refuse a typo rather than defaulting it
    // into permanent deletes.
    for m in [M::Follow, M::Trash, M::Delete] {
        assert_eq!(M::parse(m.as_str()), Some(m));
    }
    assert_eq!(M::parse("recycle"), None);
    set_delete_to_trash(was_trash);
    set_cleanup_mode(was_mode);
}
