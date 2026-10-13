//! A solid RAR 5 member whose FINAL match runs past the member's declared
//! size (claim `nzbfast-rars-solid-match-overruns-member-27sep`, found by
//! rarkit's fuzz lane on 27 Sep 2026). The vendored engine refused it with
//! "RAR 5 match exceeds output limit", so the native rung failed and the
//! job leaned on the external unrar - which a box without one (the Docker
//! image ships none) does not have. Reference unrar 7.23 writes the
//! declared bytes and keeps the whole match as solid window; the digests
//! below are its output.
//!
//! The archives are `vendor/rars`'s own fixtures, read at run time the
//! way `named_payload_tests` reads one: this crate is not published, so
//! the path out of the package is not the escape
//! `tools/package-escape-gate.py` refuses. Both of this crate's
//! extraction routes are driven: the native rung on a finished
//! directory, and the one-pass extractor fed the volume as articles.

use super::*;
use std::sync::Arc;

/// What unrar 7.23 extracts from `solid_match_overruns_member.rar`:
/// name, size, CRC32.
const MEMBERS: [(&str, usize, u32); 3] = [
    ("m0.bin", 5231, 0x690a_fe78),
    ("m1.bin", 37, 0xa32d_8b56),
    ("m2.bin", 4610, 0x2a9d_d970),
];

fn fixture(name: &str) -> Vec<u8> {
    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../vendor/rars/tests/fixtures/rar50")
        .join(name);
    std::fs::read(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()))
}

fn temp_dir(tag: &str) -> PathBuf {
    let dir = std::env::temp_dir().join(format!("nzbfast-overrun-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

fn assert_members(dir: &std::path::Path, what: &str) {
    for (name, len, crc) in MEMBERS {
        let data = std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("{what}: {name}: {e}"));
        assert_eq!(
            (data.len(), crc32fast::hash(&data)),
            (len, crc),
            "{what}: {name}"
        );
    }
}

/// The native rung alone, so an external unrar on the test box cannot
/// stand in for it: `try_rars_native` is the in-process engine and
/// nothing else.
#[test]
fn native_rung_extracts_a_solid_member_whose_final_match_overruns_it() {
    let dir = temp_dir("native");
    let first = dir.join("release.rar");
    std::fs::write(&first, fixture("solid_match_overruns_member.rar")).unwrap();
    try_rars_native(&dir, &first, None).unwrap();
    assert_members(&dir, "native");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The negative case: the same archive with a CRC32 on m2 that does not
/// match its declared bytes. Tolerating the overrun excuses nothing about
/// the member's own integrity - unrar 7.23 refuses this file too.
#[test]
fn native_rung_still_refuses_that_member_under_a_wrong_crc() {
    let dir = temp_dir("badcrc");
    let first = dir.join("release.rar");
    std::fs::write(&first, fixture("solid_match_overruns_member_bad_crc.rar")).unwrap();
    let error = try_rars_native(&dir, &first, None).expect_err("a wrong CRC32 must refuse");
    assert!(
        error.to_string().contains("m2.bin"),
        "the refusal names the member: {error}"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The one-pass route: the volume arrives as articles, in order and in
/// reverse, and the extractor decodes it in-stream. No fallback may be
/// recorded - a fallback is the extractor handing the volume to the disk
/// ladder, which is the route this item exists to take off.
#[test]
fn one_pass_extracts_a_solid_member_whose_final_match_overruns_it() {
    let arch = fixture("solid_match_overruns_member.rar");
    let art = 1500usize;
    let n_arts = arch.len().div_ceil(art);
    for (t, order) in [(0..n_arts).collect::<Vec<_>>(), (0..n_arts).rev().collect()]
        .iter()
        .enumerate()
    {
        let dir = temp_dir(&format!("onepass{t}"));
        let ex = Arc::new(nzbkit::extract::Extractor::new(&dir, 1, true));
        ex.anchor();
        for &i in order {
            let s = i * art;
            let e = (s + art).min(arch.len());
            ex.write(0, "release.rar", arch.len() as u64, s as u64, &arch[s..e])
                .unwrap();
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_members(&dir, &format!("one-pass order {t}"));
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
