//! End-to-end differential test of the native repair driver against
//! par2cmdline: create a real PAR2 set with the reference tool, damage
//! the files, repair natively, and require byte-identical restoration -
//! then apply the SAME damage to a second copy, let par2cmdline repair
//! it, and require our outputs to match its outputs file-for-file.
//!
//! Skips (like the nzbfast e2e suite) when no `par2` is on PATH.

use nzbkit::par2repair::{RepairStatus, repair_dir};
use std::path::{Path, PathBuf};
use std::process::Command;

fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    // CI installs par2 on purpose (see pr-check.yml, both legs), so there a
    // missing one is a broken job, not a reason to quietly cover less. Every
    // caller of this SKIPS when it is false, which is exactly the shape that
    // reads as a green run with silently reduced coverage - the failure mode
    // this whole Windows pass kept turning up.
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the PAR2 tests \
         would have skipped and the run would have looked green"
    );
    ok
}

struct TempDir(PathBuf);
impl TempDir {
    fn new(tag: &str) -> TempDir {
        let p =
            std::env::temp_dir().join(format!("nzbkit-par2repair-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        TempDir(p)
    }
}
impl Drop for TempDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Deterministic, NON-periodic file contents (xorshift64). A repeating
/// pattern lets par2cmdline's sliding-window scan "find" a damaged
/// block's content intact elsewhere in the file, sidestepping RS repair
/// and breaking the differential comparison.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut s = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            s ^= s << 13;
            s ^= s >> 7;
            s ^= s << 17;
            (s >> 24) as u8
        })
        .collect()
}

/// par2-create over `files` in `dir` with block size 4096.
fn par2_create(dir: &Path, files: &[&str], extra: &[&str]) {
    let st = Command::new("par2")
        .arg("create")
        .arg("-s4096")
        .args(extra)
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(dir)
        .status()
        .expect("run par2 create");
    assert!(st.success(), "par2 create failed");
}

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// The damage pattern both dirs receive: two corrupt blocks in a.bin,
/// b.bin truncated mid-block, c.bin deleted outright.
fn inflict_damage(dir: &Path) {
    let a = dir.join("a.bin");
    let mut bytes = std::fs::read(&a).unwrap();
    bytes[100..300].fill(0xEE); // block 0
    bytes[9000..9100].fill(0x11); // block 2
    std::fs::write(&a, bytes).unwrap();
    let b = std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("b.bin"))
        .unwrap();
    b.set_len(5000).unwrap(); // loses blocks 1 and 2 (tail)
    drop(b);
    std::fs::remove_file(dir.join("c.bin")).unwrap();
}

#[test]
fn native_repair_matches_par2cmdline_byte_for_byte() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // a.bin spans 9 blocks with a tail; b.bin 3 blocks with a tail;
    // c.bin is smaller than one block.
    let names = ["a.bin", "b.bin", "c.bin"];
    let pristine = [payload(33_000, 1), payload(10_000, 2), payload(700, 3)];

    let ours = TempDir::new("native");
    let theirs = TempDir::new("reference");
    for dir in [&ours.0, &theirs.0] {
        for (n, d) in names.iter().zip(&pristine) {
            std::fs::write(dir.join(n), d).unwrap();
        }
    }
    // One set, copied verbatim to the reference dir so both repair the
    // exact same recovery data.
    par2_create(&ours.0, &names, &["-r40"]);
    for e in std::fs::read_dir(&ours.0).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "par2") {
            std::fs::copy(&p, theirs.0.join(p.file_name().unwrap())).unwrap();
        }
    }
    inflict_damage(&ours.0);
    inflict_damage(&theirs.0);

    // Native repair restores the pristine bytes…
    match repair_dir(&ours.0).expect("native repair runs") {
        RepairStatus::Repaired(r) => {
            // 2 corrupt in a.bin + 2 lost in b.bin + 1 whole-file c.bin.
            assert_eq!(r.blocks_rebuilt, 5, "5 blocks needed rebuilding");
            assert_eq!(r.files_created, vec!["c.bin"]);
            let mut patched = r.files_patched.clone();
            patched.sort();
            assert_eq!(patched, vec!["a.bin", "b.bin", "c.bin"]);
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    for (n, d) in names.iter().zip(&pristine) {
        assert_eq!(&read(&ours.0, n), d, "{n} restored to pristine bytes");
    }

    // …and par2cmdline, given identical damage, produces identical files.
    let st = Command::new("par2")
        .arg("repair")
        .arg("-q")
        .arg("testset.par2")
        .current_dir(&theirs.0)
        .status()
        .expect("run par2 repair");
    assert!(st.success(), "reference repair failed");
    for n in &names {
        assert_eq!(
            read(&ours.0, n),
            read(&theirs.0, n),
            "{n}: native output differs from par2cmdline output"
        );
    }
}

#[test]
fn clean_set_reports_no_damage_and_writes_nothing() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("clean");
    let data = payload(20_000, 4);
    std::fs::write(t.0.join("only.bin"), &data).unwrap();
    par2_create(&t.0, &["only.bin"], &["-r10"]);
    let before = std::fs::metadata(t.0.join("only.bin"))
        .unwrap()
        .modified()
        .unwrap();
    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage, got {other:?}"),
    }
    let after = std::fs::metadata(t.0.join("only.bin"))
        .unwrap()
        .modified()
        .unwrap();
    assert_eq!(before, after, "clean file untouched");
}

#[test]
fn damage_beyond_recovery_reports_unrepairable_counts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("unrep");
    let data = payload(33_000, 5);
    std::fs::write(t.0.join("big.bin"), &data).unwrap();
    par2_create(&t.0, &["big.bin"], &["-c1"]); // one recovery block only
    let mut bytes = std::fs::read(t.0.join("big.bin")).unwrap();
    bytes[100] ^= 0xFF; // block 0
    bytes[5000] ^= 0xFF; // block 1
    std::fs::write(t.0.join("big.bin"), bytes).unwrap();
    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Unrepairable { needed, have } => {
            assert_eq!((needed, have), (2, 1));
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    }
    // par2cmdline agrees this set is unrepairable.
    let st = Command::new("par2")
        .arg("repair")
        .arg("-q")
        .arg("testset.par2")
        .current_dir(&t.0)
        .status()
        .expect("run par2 repair");
    assert!(!st.success(), "reference tool must also fail");
}

/// Not part of the suite - perf sanity vs par2cmdline on a ~200 MB set:
/// `cargo test -p nzbkit --release --test par2repair_dir -- --ignored perf`
#[test]
#[ignore]
fn perf_smoke_200mb_vs_par2cmdline() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let _names = ["big.bin"];
    let data = payload(200 << 20, 42);
    let bs = 768_000usize;
    let ours = TempDir::new("perf-native");
    let theirs = TempDir::new("perf-reference");
    for dir in [&ours.0, &theirs.0] {
        std::fs::write(dir.join("big.bin"), &data).unwrap();
    }
    let st = Command::new("par2")
        .args([
            "create",
            &format!("-s{bs}"),
            "-r5",
            "-q",
            "testset",
            "big.bin",
        ])
        .current_dir(&ours.0)
        .status()
        .unwrap();
    assert!(st.success());
    for e in std::fs::read_dir(&ours.0).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "par2") {
            std::fs::copy(&p, theirs.0.join(p.file_name().unwrap())).unwrap();
        }
    }
    // 12 damaged blocks scattered through the file.
    for dir in [&ours.0, &theirs.0] {
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(dir.join("big.bin"))
            .unwrap();
        for i in 0..12u64 {
            let off = i * 17 * bs as u64 + 100;
            use std::io::{Seek, SeekFrom, Write};
            let mut f2 = &f;
            f2.seek(SeekFrom::Start(off)).unwrap();
            f2.write_all(&[0xEE; 256]).unwrap();
        }
    }
    let t0 = std::time::Instant::now();
    match repair_dir(&ours.0).unwrap() {
        RepairStatus::Repaired(r) => assert_eq!(r.blocks_rebuilt, 12),
        other => panic!("expected Repaired, got {other:?}"),
    }
    let native = t0.elapsed();
    let t0 = std::time::Instant::now();
    let st = Command::new("par2")
        .args(["repair", "-q", "testset.par2"])
        .current_dir(&theirs.0)
        .status()
        .unwrap();
    assert!(st.success());
    let reference = t0.elapsed();
    assert_eq!(read(&ours.0, "big.bin"), data, "native restored pristine");
    assert_eq!(read(&ours.0, "big.bin"), read(&theirs.0, "big.bin"));
    println!("perf 200MB/12 blocks: native {native:.2?} vs par2cmdline {reference:.2?}");
}

#[test]
fn overlong_file_is_truncated_back_to_spec() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("overlong");
    let data = payload(9_000, 6);
    std::fs::write(t.0.join("f.bin"), &data).unwrap();
    par2_create(&t.0, &["f.bin"], &["-r10"]);
    let mut longer = data.clone();
    longer.extend_from_slice(&[0xAB; 4096]);
    std::fs::write(t.0.join("f.bin"), &longer).unwrap();
    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Repaired(r) => {
            assert_eq!(r.blocks_rebuilt, 0, "no RS work - pure truncation");
            assert_eq!(r.files_patched, vec!["f.bin"]);
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(read(&t.0, "f.bin"), data);
}

/// The obfuscated post: NOTHING on disk is named `.par2`, and the data
/// files carry hashes rather than the names PAR2 knows them by.
///
/// This is public issue #9. A post like that reaches the repair path with
/// every file classified as payload, because classification runs off the
/// NZB's subject lines and those say nothing. `repair_dir` itself has
/// always been able to cope - it magic-sniffs packets and hash-matches
/// obfuscated data files during its adoption scan - so the fix upstream
/// is to CALL it, and this pins the capability it is being called for.
#[test]
fn a_fully_obfuscated_set_still_repairs() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("obfusc");
    let a = payload(30_000, 11);
    let b = payload(12_000, 12);
    std::fs::write(t.0.join("a.bin"), &a).unwrap();
    std::fs::write(t.0.join("b.bin"), &b).unwrap();
    par2_create(&t.0, &["a.bin", "b.bin"], &["-r40"]);

    // Damage BEFORE renaming: a corrupt run in a.bin, b.bin deleted
    // outright. Deleting one is the important half - it can only come
    // back if the set was understood well enough to recreate it under
    // its real name.
    let mut bytes = std::fs::read(t.0.join("a.bin")).unwrap();
    bytes[200..900].fill(0xAB);
    std::fs::write(t.0.join("a.bin"), bytes).unwrap();
    std::fs::remove_file(t.0.join("b.bin")).unwrap();

    // Now obfuscate everything: hash-ish stems, no extension anywhere.
    // The index, every recovery volume and the surviving data file.
    let mut renamed = 0;
    let mut entries: Vec<_> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for (i, p) in entries.iter().enumerate() {
        let to = t.0.join(format!("k7Xq{i:02}mZr9"));
        std::fs::rename(p, &to).unwrap();
        renamed += 1;
    }
    assert!(renamed >= 3, "expected an index, volumes and data");
    assert!(
        std::fs::read_dir(&t.0)
            .unwrap()
            .flatten()
            .all(|e| e.path().extension().is_none()),
        "the point of this test is that no name carries a hint"
    );

    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Repaired(r) => {
            assert!(r.blocks_rebuilt > 0, "nothing was actually rebuilt");
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    // Both files back, byte-exact, under their true PAR2 names - the
    // deleted one had to be recreated from the FileDesc packets.
    assert_eq!(read(&t.0, "a.bin"), a, "corrupt file not restored");
    assert_eq!(read(&t.0, "b.bin"), b, "deleted file not recreated");
}

/// The library contract callers must not mistake for a verdict on a
/// directory: a repair is scoped to its own recovery set, so a damaged
/// file the set never named leaves the verdict at `NoDamage`.
///
/// nzbfast's no-PAR2 disk fallback took exactly that verdict as proof
/// the whole download was whole - job filed Completed, journal deleted,
/// a `.nfo` still a zero-filled hole beside the payload. Pinned here so
/// nobody "fixes" the contract at this end: the coverage test belongs to
/// the caller, and `covered_names` is what it asks with.
#[test]
fn no_damage_says_nothing_about_files_outside_the_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("uncovered");
    let data = payload(20_000, 9);
    std::fs::write(t.0.join("data.bin"), &data).unwrap();
    par2_create(&t.0, &["data.bin"], &["-r10"]);
    // The shape a fully-430'd uncovered file leaves behind.
    std::fs::write(t.0.join("release.nfo"), vec![0u8; 20_000]).unwrap();

    match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage over an uncovered hole, got {other:?}"),
    }
    let covered = nzbkit::par2repair::covered_names(&t.0).expect("covered names");
    assert!(
        covered.iter().any(|n| n == "data.bin"),
        "the set's own file must be listed: {covered:?}"
    );
    assert!(
        !covered.iter().any(|n| n == "release.nfo"),
        "a file outside the set must NOT read as covered: {covered:?}"
    );
}

/// The two presence entry points, contrasted on issue #9's worst shape:
/// a WHOLLY renamed set, not one FileDesc name on disk. The plain
/// `repair_present_sets` must keep skipping it - the nested disk
/// post-pass leans on that name-only gate to skip an outer index whose
/// volumes never touched disk, and an early cut of the fallback that
/// changed the default regressed exactly that. The obfuscated no-set
/// arm's `repair_present_or_renamed_sets` is where the fallback lives:
/// it attempts the sets and lets the verdicts speak.
#[test]
fn a_wholly_renamed_set_repairs_only_via_the_renamed_fallback() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("renamedfallback");
    let a = payload(30_000, 21);
    std::fs::write(t.0.join("a.bin"), &a).unwrap();
    par2_create(&t.0, &["a.bin"], &["-r40"]);

    // Mid-file damage, then rename EVERYTHING - data file, index,
    // recovery volumes - to extensionless hash stems.
    let mut bytes = std::fs::read(t.0.join("a.bin")).unwrap();
    bytes[20_000..20_700].fill(0xAB);
    std::fs::write(t.0.join("a.bin"), bytes).unwrap();
    let mut entries: Vec<_> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for (i, p) in entries.iter().enumerate() {
        std::fs::rename(p, t.0.join(format!("w2Pf{i:02}qLn4"))).unwrap();
    }
    assert!(
        std::fs::read_dir(&t.0)
            .unwrap()
            .flatten()
            .all(|e| e.path().extension().is_none()),
        "the point of this test is that no name carries a hint"
    );

    // The name-only gate stays blind to it, by design.
    let skipped = nzbkit::par2repair::repair_present_sets(&t.0).expect("repair runs");
    assert!(
        skipped.is_empty(),
        "repair_present_sets must keep its name-only gate: {skipped:?}"
    );
    assert!(
        !t.0.join("a.bin").exists(),
        "the skipped path must not have touched the directory"
    );

    // The fallback entry point is what serves this shape.
    let results = nzbkit::par2repair::repair_present_or_renamed_sets(&t.0).expect("repair runs");
    assert_eq!(results.len(), 1, "the renamed set must be attempted");
    match &results[0].status {
        Ok(RepairStatus::Repaired(r)) => {
            assert!(r.blocks_rebuilt > 0, "nothing was actually rebuilt");
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(read(&t.0, "a.bin"), a, "payload not restored byte-exact");
}

/// The gate's purpose, pinned from the other side: packets describing
/// files that never touched this dir (the nested-layer shape - the
/// downloaded set's index beside an in-stream extracted payload) stay
/// skipped by `repair_present_sets`, even with a same-length bystander
/// sitting right there.
#[test]
fn a_set_whose_files_never_landed_stays_skipped() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("absentset");
    std::fs::write(t.0.join("inner.bin"), payload(20_000, 5)).unwrap();
    par2_create(&t.0, &["inner.bin"], &["-r10"]);
    std::fs::remove_file(t.0.join("inner.bin")).unwrap();
    // Same length, different bytes - the extracted payload standing in
    // for data the packets describe but that only ever existed upstream.
    std::fs::write(t.0.join("extracted.mkv"), payload(20_000, 6)).unwrap();

    let results = nzbkit::par2repair::repair_present_sets(&t.0).expect("repair runs");
    assert!(
        results.is_empty(),
        "a set with no data here must not be repaired: {results:?}"
    );
    assert!(
        !t.0.join("inner.bin").exists(),
        "the skipped set must not resurrect its files"
    );
}

/// The fallback must not depend on any part of the renamed file being
/// pristine - damage INSIDE the first 16k included. That pins the
/// design choice: presence-by-content schemes keyed on the FileDesc
/// md5_16k (the adoption fast path's signal) go blind exactly here,
/// which is why the fallback attempts the set and lets the engine's
/// sliding scan plus recovery slices decide instead. If a future
/// "optimization" swaps in a head-hash probe, this is the test that
/// catches its residual gap.
#[test]
fn the_renamed_fallback_survives_damage_in_the_first_16k() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("renamedhead");
    let a = payload(30_000, 23);
    std::fs::write(t.0.join("a.bin"), &a).unwrap();
    par2_create(&t.0, &["a.bin"], &["-r40"]);

    // Damage in block 0 - inside the first 16k - AND past it, then
    // rename everything to extensionless hash stems.
    let mut bytes = std::fs::read(t.0.join("a.bin")).unwrap();
    bytes[100..800].fill(0xCD);
    bytes[20_000..20_700].fill(0xAB);
    std::fs::write(t.0.join("a.bin"), bytes).unwrap();
    let mut entries: Vec<_> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .collect();
    entries.sort();
    for (i, p) in entries.iter().enumerate() {
        std::fs::rename(p, t.0.join(format!("j5Tn{i:02}wBc8"))).unwrap();
    }

    let results = nzbkit::par2repair::repair_present_or_renamed_sets(&t.0).expect("repair runs");
    assert_eq!(results.len(), 1, "the renamed set must be attempted");
    match &results[0].status {
        Ok(RepairStatus::Repaired(r)) => {
            assert!(r.blocks_rebuilt > 0, "nothing was actually rebuilt");
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(read(&t.0, "a.bin"), a, "payload not restored byte-exact");
}

/// The fallback's candidate gate: a directory holding NOTHING but the
/// recovery set's own packet files is not attempted, even though 100%
/// redundancy could recreate the data purely from recovery slices.
/// Materializing files out of packets alone is `repair_dir`'s job for
/// callers that want it; the no-set arm asking "is the renamed payload
/// here?" must answer no when only packets are.
#[test]
fn the_renamed_fallback_needs_a_non_packet_candidate() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("packetsonly");
    std::fs::write(t.0.join("a.bin"), payload(20_000, 25)).unwrap();
    par2_create(&t.0, &["a.bin"], &["-r100"]);
    std::fs::remove_file(t.0.join("a.bin")).unwrap();

    let results = nzbkit::par2repair::repair_present_or_renamed_sets(&t.0).expect("repair runs");
    assert!(
        results.is_empty(),
        "packets alone must not trigger the fallback: {results:?}"
    );
    assert!(
        !t.0.join("a.bin").exists(),
        "the data file must not be resurrected from recovery slices"
    );
}

/// The renamed fallback is deliberately all-or-nothing: when even ONE
/// set matched by name, an unmatched set stays skipped exactly as the
/// plain gate would leave it. Otherwise every job with a nested index
/// beside a healthy named set would pay an attempt on - and possibly
/// materialize - files it never needed.
#[test]
fn the_renamed_fallback_stands_down_when_any_set_matches_by_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("mixedsets");
    std::fs::write(t.0.join("aaa_ep01.bin"), payload(20_000, 1)).unwrap();
    std::fs::write(t.0.join("zzz_ep02.bin"), payload(20_000, 2)).unwrap();
    for (base, file) in [("aaa_ep01", "aaa_ep01.bin"), ("zzz_ep02", "zzz_ep02.bin")] {
        let st = Command::new("par2")
            .args(["create", "-s4096", "-r10", "-q", base, file])
            .current_dir(&t.0)
            .status()
            .expect("run par2 create");
        assert!(st.success(), "par2 create failed for {base}");
    }
    // The second set goes wholly obfuscated: its data file and every one
    // of its packet files lose their names.
    let mut renamed: Vec<_> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with("zzz_ep02"))
        })
        .collect();
    renamed.sort();
    for (i, p) in renamed.iter().enumerate() {
        std::fs::rename(p, t.0.join(format!("v8Km{i:02}xRd3"))).unwrap();
    }

    let results = nzbkit::par2repair::repair_present_or_renamed_sets(&t.0).expect("repair runs");
    assert_eq!(
        results.len(),
        1,
        "only the name-matched set may be attempted: {results:?}"
    );
    assert!(
        matches!(&results[0].status, Ok(RepairStatus::NoDamage)),
        "the named set is clean: {results:?}"
    );
    assert!(
        !t.0.join("zzz_ep02.bin").exists(),
        "the unmatched set must stay skipped, not repaired via the fallback"
    );
}

/// `covered_names` spans every set in the directory, not just the first
/// in packet-sorted order the way `repair_dir` binds - the season-pack
/// shape, one recovery set per episode.
#[test]
fn covered_names_spans_every_set_in_the_directory() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("multiset");
    std::fs::write(t.0.join("aaa_ep01.bin"), payload(20_000, 1)).unwrap();
    std::fs::write(t.0.join("zzz_ep02.bin"), payload(20_000, 2)).unwrap();
    for (base, file) in [("aaa_ep01", "aaa_ep01.bin"), ("zzz_ep02", "zzz_ep02.bin")] {
        let st = Command::new("par2")
            .args(["create", "-s4096", "-r10", "-q", base, file])
            .current_dir(&t.0)
            .status()
            .expect("run par2 create");
        assert!(st.success(), "par2 create failed for {base}");
    }

    let covered = nzbkit::par2repair::covered_names(&t.0).expect("covered names");
    assert!(
        covered.iter().any(|n| n == "aaa_ep01.bin") && covered.iter().any(|n| n == "zzz_ep02.bin"),
        "both sets' files must be listed: {covered:?}"
    );
}

/// A skipped set's declared names are NOT evidence that its files are
/// healthy. The verdict and the names it speaks for travel together, so
/// a caller building completion coverage can only ever count a set that
/// actually reported.
///
/// The shape that made this data loss: a season pack posted with one
/// recovery set per episode, one episode taken down so not a single
/// article of it arrives. Its set has no data file on disk, is skipped,
/// and the directory-wide `covered_names` union nonetheless declared its
/// name covered - so the missing-file scan passed, the job reached
/// Completed, and the journal recording what was still missing went
/// with it.
#[test]
fn a_skipped_set_speaks_for_nothing() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("skippedset");
    std::fs::write(t.0.join("aaa_ep01.bin"), payload(20_000, 1)).unwrap();
    std::fs::write(t.0.join("zzz_ep02.bin"), payload(20_000, 2)).unwrap();
    for (base, file) in [("aaa_ep01", "aaa_ep01.bin"), ("zzz_ep02", "zzz_ep02.bin")] {
        let st = Command::new("par2")
            .args(["create", "-s4096", "-r10", "-q", base, file])
            .current_dir(&t.0)
            .status()
            .expect("run par2 create");
        assert!(st.success(), "par2 create failed for {base}");
    }
    // Episode 2 never arrived at all - only its packets did.
    std::fs::remove_file(t.0.join("zzz_ep02.bin")).unwrap();

    let results = nzbkit::par2repair::repair_present_sets(&t.0).expect("repair runs");
    assert_eq!(
        results.len(),
        1,
        "only ep01's set has data here: {results:?}"
    );
    assert!(
        matches!(&results[0].status, Ok(RepairStatus::NoDamage)),
        "ep01 is clean: {results:?}"
    );
    assert!(
        results[0].names.iter().any(|n| n == "aaa_ep01.bin"),
        "the verdict must carry the names it verified: {:?}",
        results[0].names
    );
    assert!(
        !results[0].names.iter().any(|n| n == "zzz_ep02.bin"),
        "a set that never ran must not lend its names to one that did: {:?}",
        results[0].names
    );
    // The union is still the union - it answers a different question
    // (whose payload is this file), and the cleanup pass needs it.
    let covered = nzbkit::par2repair::covered_names(&t.0).expect("covered names");
    assert!(
        covered.iter().any(|n| n == "zzz_ep02.bin"),
        "covered_names still spans every set: {covered:?}"
    );
}

/// Adopting a block from a file does not make that file disposable.
///
/// A PAR2 block can be four bytes; CRC32 plus MD5 proves the window that
/// matched and nothing else. Promoting "one slice was reused" into
/// "delete this whole path" - which the job tail does with
/// `consumed_sources` - destroyed complete files that merely shared a
/// block: padding, a common header, or a neighbouring set's payload.
#[test]
fn a_partial_donor_is_never_reported_as_spent() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("partialdonor");
    let a = payload(20_000, 7);
    std::fs::write(t.0.join("a.bin"), &a).unwrap();
    par2_create(&t.0, &["a.bin"], &["-r40"]);
    // a.bin is gone; a LONGER file holds its bytes plus payload of its
    // own, so blocks are adoptable from it but it is not a duplicate of
    // anything the set describes.
    std::fs::remove_file(t.0.join("a.bin")).unwrap();
    let mut donor = a.clone();
    donor.extend_from_slice(&payload(5_000, 99));
    std::fs::write(t.0.join("donor.bin"), &donor).unwrap();

    let r = match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert!(r.blocks_adopted > 0, "the donor should have donated blocks");
    assert_eq!(r.adopted_from, vec!["donor.bin"]);
    assert_eq!(read(&t.0, "a.bin"), a, "payload not restored byte-exact");
    assert!(
        r.consumed_sources.is_empty(),
        "a donor holding bytes of its own is not spent: {:?}",
        r.consumed_sources
    );
    assert_eq!(
        read(&t.0, "donor.bin"),
        donor,
        "the donor must still be here, whole"
    );
}

/// The other half of the same rule: the case the sweep exists for still
/// works. On a wholly renamed post the hash-named file IS the payload
/// byte for byte, the repair lands those same bytes under the FileDesc
/// name, and the leftover duplicate - 8.2 GB of one on the report that
/// raised issue #9 - is proven spent by whole-file MD5.
#[test]
fn a_whole_file_donor_is_still_reported_as_spent() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("wholedonor");
    let a = payload(20_000, 7);
    std::fs::write(t.0.join("a.bin"), &a).unwrap();
    par2_create(&t.0, &["a.bin"], &["-r40"]);
    std::fs::rename(t.0.join("a.bin"), t.0.join("9f2c1d4e")).unwrap();

    let r = match repair_dir(&t.0).expect("repair runs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(read(&t.0, "a.bin"), a, "payload not restored byte-exact");
    assert_eq!(
        r.consumed_sources,
        vec![t.0.join("9f2c1d4e")],
        "the byte-for-byte duplicate must still be swept"
    );
}

/// Two recovery sets in one directory that name the same destination for
/// DIFFERENT content must not share it. Each set is repaired on its own,
/// with its own destination registry, so both picked the same path: the
/// second verified its rebuild and renamed it over the first's verified
/// bytes, and both verdicts came back green with one file gone.
#[test]
fn two_sets_claiming_one_name_keep_both_files() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = TempDir::new("namecollision");
    let a = payload(20_000, 11);
    let b = payload(20_000, 22);
    // Two sets, same declared name, different content. 100% recovery so
    // either set can rebuild its file from slices alone.
    std::fs::write(t.0.join("readme.txt"), &a).unwrap();
    for (base, content) in [("seta", &a), ("setb", &b)] {
        std::fs::write(t.0.join("readme.txt"), content).unwrap();
        let st = Command::new("par2")
            .args(["create", "-s4096", "-r100", "-q", base, "readme.txt"])
            .current_dir(&t.0)
            .status()
            .expect("run par2 create");
        assert!(st.success(), "par2 create failed for {base}");
    }
    // What actually landed is set A's content.
    std::fs::write(t.0.join("readme.txt"), &a).unwrap();

    let results = nzbkit::par2repair::repair_present_sets(&t.0).expect("repair runs");
    assert_eq!(results.len(), 2, "both sets name a file that is here");
    for r in &results {
        assert!(
            r.status.is_ok(),
            "both sets have the redundancy to succeed: {:?}",
            r.status
        );
    }
    let here: Vec<Vec<u8>> = std::fs::read_dir(&t.0)
        .unwrap()
        .flatten()
        .map(|e| e.path())
        .filter(|p| {
            p.extension()
                .is_none_or(|x| !x.eq_ignore_ascii_case("par2"))
        })
        .filter_map(|p| std::fs::read(p).ok())
        .collect();
    assert!(
        here.contains(&a),
        "set A's verified content was overwritten by set B"
    );
    assert!(here.contains(&b), "set B's content never landed");
}
