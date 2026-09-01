//! A queue save the disk refused is a CONDITION, and this is where it
//! becomes visible.
//!
//! Until it did, a daemon whose queue.json had stopped reaching disk
//! looked entirely healthy from the outside: every add was accepted,
//! every download ran, `mode=queue` answered normally, and the only
//! trace was one `error!` line in a log nobody is watching. The next
//! restart then came back to whatever the last save that landed held -
//! jobs the user had added simply gone, with no warning before or after.
//!
//! Its own file rather than `sabcompat.rs`'s, for the size gate
//! (TODO 106): test code moves out of `sabcompat.rs`, the baseline does
//! not move up.

use super::*;

/// The whole cycle: a refused save raises the condition, and the next
/// save that lands takes it away again.
///
/// The refusal is a REAL one - the spool directory is made unwritable,
/// so `write_atomic`'s temp file cannot be created - rather than the
/// `storecut` kill-here seam, which returns before the write and models
/// a process that died rather than a disk that said no.
#[test]
fn a_refused_queue_save_is_a_warning_until_one_lands() {
    use std::os::unix::fs::PermissionsExt;
    let dir = std::env::temp_dir().join(format!("nzbfast-savewarn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("create temp dir");
    let d = crate::serve::testutil::test_daemon(&dir);
    let cfg = dir.join("nzbfast.toml");
    let warnings = |d: &Arc<Daemon>| {
        sab_warnings(d, &cfg, false, None)
            .iter()
            .filter_map(|w| w.get("text").and_then(Value::as_str).map(str::to_string))
            .collect::<Vec<_>>()
            .join("\n")
    };

    assert!(d.save_queue(), "the first save must land");
    assert!(
        !warnings(&d).contains("could not be saved"),
        "a healthy daemon must not carry the condition"
    );

    let was = std::fs::metadata(&d.spool)
        .expect("spool")
        .permissions()
        .mode();
    std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(0o555)).expect("chmod");
    let refused = d.save_queue();
    std::fs::set_permissions(&d.spool, std::fs::Permissions::from_mode(was)).expect("chmod back");
    assert!(!refused, "a read-only spool cannot take the write");
    let text = warnings(&d);
    assert!(
        text.contains("The queue could not be saved at "),
        "a refused save said nothing anyone could see: {text}"
    );

    assert!(d.save_queue(), "the directory is writable again");
    assert!(
        !warnings(&d).contains("could not be saved"),
        "the condition outlived the state it reports"
    );
    let _ = std::fs::remove_dir_all(&dir);
}
