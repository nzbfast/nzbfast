//! No-RAR matrix, the checksum-sidecar DIALECT rows M4-35 and M4-36
//! (research/NORAR-DEOBF-MATRIX-2026-08-29.md, third extreme pass).
//!
//! A sibling-dir child of e2e.rs like `e2e_norar`, and split OFF that
//! module for the ordinary reason: two lanes' test growth landed there
//! within an hour on 30 Aug 2026 and put it at 3,049 lines against the
//! size gate's 3,000-line ceiling. The fixture VOCABULARY is not
//! duplicated - `run_norar` and `out_tree` come from `e2e_norar` (they
//! are `pub(crate)` for exactly this), because two hand-copied fixture
//! builders drifting apart is the failure this repo keeps writing gates
//! about.
//!
//! Neither row needs par2, so neither carries a `have_par2()` guard:
//! the sidecar is the only name source in both, which is the whole
//! point of the tier they exercise.

use super::e2e_norar::{out_tree, run_norar};
use super::*;

/// Row M4-35 (30 Aug 2026): the CRC-first SFV dialects. QuickCRC and
/// several Windows tools put the CRC on the LEFT, some borrow md5sum's
/// `*` binary marker for the name beside it, and a name with spaces gets
/// quoted. `parse_sfv` took the LAST whitespace token as the CRC, so
/// `AABBCCDD filename.mkv` parsed as name `AABBCCDD` with a CRC of
/// `filename.mkv` - not 8 hex, line skipped, and the whole sidecar became
/// a no-op with every payload keeping its posted hash at rc=0.
///
/// Three one-line sidecars, one per dialect, which is also what proves
/// the dialect is decided per FILE: each is read on its own terms.
#[tokio::test(flavor = "multi_thread")]
async fn crc_first_and_quoted_sfv_dialects_name_the_post() {
    let mut fx = Fixture::new("norarsfvdialect");
    let one = payload(60_000, 91);
    let two = payload(45_000, 92);
    let three = payload(50_000, 93);
    fx.add_file_obfuscated("Qa4tYu18ZbN", "Qa4tYu18ZbN", &one, 40_000);
    fx.add_file_obfuscated("Wd7hJk52McR", "Wd7hJk52McR", &two, 40_000);
    fx.add_file_obfuscated("Ev1sPo39XgT", "Ev1sPo39XgT", &three, 40_000);
    // QuickCRC: bare CRC-first.
    fx.add_file(
        "one.sfv",
        format!(
            "; QuickCRC\r\n{:08X} Real.Quick.mkv\r\n",
            crc32fast::hash(&one)
        )
        .as_bytes(),
        40_000,
    );
    // CRC-first carrying md5sum's binary-mode marker on the name.
    fx.add_file(
        "two.sfv",
        format!("{:08X} *Real.Star.mkv\r\n", crc32fast::hash(&two)).as_bytes(),
        40_000,
    );
    // Name-first, quoted - the quotes are the tool's, not the name's.
    fx.add_file(
        "three.sfv",
        format!(
            "\"Real Quoted Name.mkv\" {:08X}\r\n",
            crc32fast::hash(&three)
        )
        .as_bytes(),
        40_000,
    );
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "crc-first sfv post failed outright:\n{log}");
    for (name, want) in [
        ("Real.Quick.mkv", &one),
        ("Real.Star.mkv", &two),
        ("Real Quoted Name.mkv", &three),
    ] {
        let got = std::fs::read(out.join(name)).unwrap_or_else(|e| {
            let tree: Vec<String> = out_tree(&out).into_iter().map(|(n, _)| n).collect();
            panic!(
                "M4-35: {name} never landed - the sidecar dialect was read as \
                 junk and the payload kept its hash: {e}; tree: {tree:?}\n{log}"
            )
        });
        assert!(got == *want, "{name} not byte-exact\n{log}");
    }
    assert!(
        !out.join("Qa4tYu18ZbN").exists()
            && !out.join("Wd7hJk52McR").exists()
            && !out.join("Ev1sPo39XgT").exists(),
        "a posted hash survived beside its SFV name:\n{log}"
    );
}

/// Row M4-36 (30 Aug 2026) - a PASS pin, measured green rather than
/// fixed. A Windows-authored SFV spells its tree with `\`
/// (`VIDEO_TS\VTS_01_1.VOB`), and the row predicted a flat
/// `VIDEO_TS_VTS_01_1.VOB` or a refused path because the SFV name never
/// went through the relpath rules. It does: this tier publishes through
/// `publish_weak_name`, which claims `nzbkit::disk::sanitize_out_name` -
/// THE member-name policy (relpath-preserve-tree, 30 Aug 2026), which
/// counts `\` as a separator exactly as a PAR2 FileDesc path does. So a
/// disc tree named only by a sidecar plays.
///
/// Pinned because that is a property of a function two modules away: the
/// day some lane spells this publish with `sanitize_filename` instead,
/// nothing else in the tree reports it.
#[tokio::test(flavor = "multi_thread")]
async fn an_sfv_name_with_a_windows_tree_lands_as_a_tree() {
    let mut fx = Fixture::new("norarsfvtree");
    let vob = payload(60_000, 94);
    let evil = payload(45_000, 95);
    fx.add_file_obfuscated("Rn6bTk84WzQ", "Rn6bTk84WzQ", &vob, 40_000);
    fx.add_file_obfuscated("Uc3xVm70JdL", "Uc3xVm70JdL", &evil, 40_000);
    let sfv = format!(
        "VIDEO_TS\\VTS_01_1.VOB {:08X}\r\n..\\..\\evil.bin {:08X}\r\n",
        crc32fast::hash(&vob),
        crc32fast::hash(&evil)
    );
    fx.add_file("release.sfv", sfv.as_bytes(), 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "windows-tree sfv post failed outright:\n{log}");
    let tree = out_tree(&out);
    let got = std::fs::read(out.join("VIDEO_TS").join("VTS_01_1.VOB")).unwrap_or_else(|e| {
        let names: Vec<String> = tree.iter().map(|(n, _)| n.clone()).collect();
        panic!(
            "M4-36: the SFV tree did not survive the rename - a disc named \
             only by a sidecar does not play: {e}; tree: {names:?}\n{log}"
        )
    });
    assert!(got == vob, "the tree member is not byte-exact\n{log}");
    // ...and the traversal spelling in the same sidecar still flattens
    // and stays inside the job directory, which is the half a tree
    // policy must never give up.
    let landed = tree
        .iter()
        .find(|(_, bytes)| *bytes == evil)
        .unwrap_or_else(|| panic!("the traversal-named payload left the job:\n{log}"));
    assert!(
        !landed.0.contains('/'),
        "an SFV name built a directory out of a traversal, landing at {:?}\n{log}",
        landed.0
    );
}

/// Row M4-49 (30 Aug 2026, CONFIRMED RED then fixed): a sidecar that
/// lists one file TWICE, with the same checksum both times, declined the
/// mapping outright. `land_sfv_names` grouped entries by checksum and
/// kept only the checksums claiming exactly one NAME, which is the right
/// rule for two DIFFERENT names on one checksum and the wrong one for a
/// duplicate identical pair - a post that says one thing twice has still
/// said one thing.
///
/// Measured on the baseline: `Real.Dup.mkv` never landed, the payload
/// kept its posted hash, and the job was rc=0 with the answer sitting in
/// the file beside it.
///
/// The second payload is the CONTROL and is the half that says the fix is
/// the collapse rather than "the ambiguity decline removed": its two
/// entries carry the same checksum and DIFFERENT names, so it must still
/// keep its hash. A fix that simply took the first name would land it.
#[tokio::test(flavor = "multi_thread")]
async fn a_sidecar_that_repeats_itself_still_names_the_post() {
    let mut fx = Fixture::new("norarsfvdup");
    let dup = payload(60_000, 94);
    let amb = payload(45_000, 95);
    fx.add_file_obfuscated("Qa4tYu18ZbN", "Qa4tYu18ZbN", &dup, 40_000);
    fx.add_file_obfuscated("Wd7hJk52McR", "Wd7hJk52McR", &amb, 40_000);
    let (dc, ac) = (crc32fast::hash(&dup), crc32fast::hash(&amb));
    fx.add_file(
        "release.sfv",
        format!(
            "; generated twice\r\nReal.Dup.mkv {dc:08X}\r\nReal.Dup.mkv {dc:08X}\r\n\
             Contested.One.mkv {ac:08X}\r\nContested.Two.mkv {ac:08X}\r\n"
        )
        .as_bytes(),
        40_000,
    );
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the repeated-line post failed outright:\n{log}");
    let tree: Vec<String> = out_tree(&out).into_iter().map(|(n, _)| n).collect();
    let got = std::fs::read(out.join("Real.Dup.mkv")).unwrap_or_else(|e| {
        panic!(
            "M4-49: a checksum claimed twice by the SAME name declined a unique \
             mapping - the payload kept its hash: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == dup, "Real.Dup.mkv not byte-exact\n{log}");
    assert!(
        !out.join("Qa4tYu18ZbN").exists(),
        "the posted hash survived beside its own name: {tree:?}\n{log}"
    );
    assert!(
        out.join("Wd7hJk52McR").exists()
            && !out.join("Contested.One.mkv").exists()
            && !out.join("Contested.Two.mkv").exists(),
        "two DIFFERENT names on one checksum must still be declined - the \
         collapse is for identical entries only: {tree:?}\n{log}"
    );
}

/// Row M4-50 (30 Aug 2026, CONFIRMED RED then fixed): a well-formed
/// sidecar over the 1 MiB ceiling was dropped WHOLE, so a post whose only
/// name map happened to be large got none of it. Measured on the
/// baseline: `... is over the sidecar size ceiling - not read for names`,
/// `Real.Big.mkv` never landed, rc=0.
///
/// The cap is not deleted and must never be - a 200 MB `.sfv` that is
/// itself the payload is M4-33's furniture-extension shape. What replaced
/// it is a second, far higher hard ceiling plus an 8 KiB head probe, so
/// what earns a long read is the file READING as a checksum list rather
/// than its size or its extension.
///
/// The 14k padding entries are the row's own shape: a disc rip with long
/// paths crosses a megabyte without being anything unusual.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_but_well_formed_sidecar_still_names_the_post() {
    let mut fx = Fixture::new("norarsfvbig");
    let one = payload(60_000, 96);
    fx.add_file_obfuscated("Ev1sPo39XgT", "Ev1sPo39XgT", &one, 40_000);
    let mut body = String::from("; a disc rip's full checksum list\r\n");
    for i in 0..14_000u32 {
        body.push_str(&format!(
            "Some.Very.Long.Directory.Name.For.A.Disc.Rip/Track.{i:05}.Of.The.Set.flac \
             {:08X}\r\n",
            0x1000_0000u32 + i
        ));
    }
    body.push_str(&format!("Real.Big.mkv {:08X}\r\n", crc32fast::hash(&one)));
    assert!(
        body.len() > (1 << 20),
        "the fixture must actually cross the old ceiling, got {}",
        body.len()
    );
    fx.add_file("release.sfv", body.as_bytes(), 400_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the oversize-sidecar post failed outright:\n{log}");
    let tree: Vec<String> = out_tree(&out).into_iter().map(|(n, _)| n).collect();
    let got = std::fs::read(out.join("Real.Big.mkv")).unwrap_or_else(|e| {
        panic!(
            "M4-50: a well-formed sidecar was dropped for its SIZE and the payload \
             kept its hash: {e}; tree: {tree:?}\n{log}"
        )
    });
    assert!(got == one, "Real.Big.mkv not byte-exact\n{log}");
    assert!(
        !out.join("Ev1sPo39XgT").exists(),
        "the posted hash survived: {tree:?}\n{log}"
    );
}

/// M4-50's control, and the half that says the cap was RAISED rather than
/// removed. Same post, same size, one difference: the large file beside
/// the payload is not a checksum list. It must be refused on its content
/// - which is also what keeps the ordinary covered release from paying a
/// second full read of its payload, the cost the module doc measures.
///
/// Written with a `.sfv` extension deliberately: M4-33's shape is a
/// payload wearing a furniture extension, so the extension must not be
/// what earns the read.
#[tokio::test(flavor = "multi_thread")]
async fn an_oversize_file_that_is_not_a_list_is_still_refused() {
    let mut fx = Fixture::new("norarsfvbignotalist");
    let one = payload(60_000, 97);
    fx.add_file_obfuscated("Ep2vBn94XhT", "Ep2vBn94XhT", &one, 40_000);
    // Over a megabyte of prose under a `.sfv` name, ending in a line that
    // carries the payload's real CRC32 - so the only thing that can
    // refuse it is the parse, never a lucky miss.
    let mut body = String::new();
    while body.len() < (1 << 20) + 4096 {
        body.push_str("Release notes for something, written at some length.\r\n");
    }
    body.push_str(&format!(
        "Greets to everyone {:08X}\r\n",
        crc32fast::hash(&one)
    ));
    fx.add_file("notes.sfv", body.as_bytes(), 400_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "the prose post failed outright:\n{log}");
    let tree: Vec<String> = out_tree(&out).into_iter().map(|(n, _)| n).collect();
    assert!(
        out.join("Ep2vBn94XhT").exists(),
        "prose over the ceiling must not name anything: {tree:?}\n{log}"
    );
}
