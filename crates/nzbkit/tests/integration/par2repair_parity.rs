//! Parity harness: native repair vs par2cmdline over a matrix of damage
//! scenarios - missing blocks, renamed (obfuscated) files, truncation,
//! byte-shifted and concatenated data, and damage beyond recovery
//! capacity (which must fail on both engines). Each scenario builds one
//! recovery set, applies identical damage to two directories, repairs
//! one natively and one with par2cmdline *invoked exactly as nzbfast's
//! fallback invokes it* (bare set name, cwd = the dir, every non-par2
//! file passed as an extra data source), and requires the recovery-set
//! files to come out byte-identical.
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
            std::env::temp_dir().join(format!("nzbkit-par2parity-{tag}-{}", std::process::id()));
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

/// Deterministic, NON-periodic contents (xorshift64), so a damaged
/// block's bytes can't accidentally exist intact elsewhere.
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

fn read(dir: &Path, name: &str) -> Vec<u8> {
    std::fs::read(dir.join(name)).unwrap_or_else(|e| panic!("read {name}: {e}"))
}

/// par2cmdline invoked the way nzbfast's fallback invokes it: bare set
/// name, cwd = dir, every non-par2 file as an extra data source.
fn par2cmdline_repair(dir: &Path) -> bool {
    let mut extra: Vec<PathBuf> = std::fs::read_dir(dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.ok()?.path();
            (p.is_file() && !p.extension().is_some_and(|x| x == "par2"))
                .then(|| p.file_name().map(PathBuf::from))?
        })
        .collect();
    extra.sort();
    Command::new("par2")
        .arg("repair")
        .arg("-q")
        .arg("testset.par2")
        .args(&extra)
        .current_dir(dir)
        .status()
        .expect("run par2 repair")
        .success()
}

/// Build the standard 3-file set in two directories (identical bytes,
/// identical .par2 files), returning (native dir, reference dir,
/// pristine contents). a.bin: 9 blocks + tail, b.bin: 3 blocks + tail,
/// c.bin: sub-block. Block size 4096, recovery per `par2_args`
/// (e.g. "-r40" or "-c2").
fn build_pair(tag: &str, par2_args: &[&str]) -> (TempDir, TempDir, [Vec<u8>; 3]) {
    let names = ["a.bin", "b.bin", "c.bin"];
    let pristine = [payload(33_000, 1), payload(10_000, 2), payload(700, 3)];
    let ours = TempDir::new(&format!("{tag}-native"));
    let theirs = TempDir::new(&format!("{tag}-reference"));
    for (n, d) in names.iter().zip(&pristine) {
        std::fs::write(ours.0.join(n), d).unwrap();
    }
    let st = Command::new("par2")
        .args(["create", "-s4096"])
        .args(par2_args)
        .args(["-q", "testset"])
        .args(names)
        .current_dir(&ours.0)
        .status()
        .expect("run par2 create");
    assert!(st.success(), "par2 create failed");
    for (n, d) in names.iter().zip(&pristine) {
        std::fs::write(theirs.0.join(n), d).unwrap();
    }
    for e in std::fs::read_dir(&ours.0).unwrap() {
        let p = e.unwrap().path();
        if p.extension().is_some_and(|x| x == "par2") {
            std::fs::copy(&p, theirs.0.join(p.file_name().unwrap())).unwrap();
        }
    }
    (ours, theirs, pristine)
}

/// Run both engines and require the recovery-set files byte-identical to
/// each other and to the pristine content. Returns the native report.
fn assert_parity(
    ours: &TempDir,
    theirs: &TempDir,
    pristine: &[Vec<u8>; 3],
) -> nzbkit::par2repair::RepairReport {
    let report = match repair_dir(&ours.0).expect("native repair runs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert!(par2cmdline_repair(&theirs.0), "reference repair failed");
    for (n, d) in ["a.bin", "b.bin", "c.bin"].iter().zip(pristine) {
        assert_eq!(&read(&ours.0, n), d, "{n}: native output not pristine");
        assert_eq!(
            read(&ours.0, n),
            read(&theirs.0, n),
            "{n}: native differs from par2cmdline"
        );
    }
    report
}

fn damage_both(ours: &TempDir, theirs: &TempDir, f: impl Fn(&Path)) {
    f(&ours.0);
    f(&theirs.0);
}

#[test]
fn missing_blocks_and_truncation() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (ours, theirs, pristine) = build_pair("plain", &["-r40"]);
    damage_both(&ours, &theirs, |d| {
        let a = d.join("a.bin");
        let mut b = std::fs::read(&a).unwrap();
        b[100..300].fill(0xEE);
        b[9000..9100].fill(0x11);
        std::fs::write(&a, b).unwrap();
        let f = std::fs::OpenOptions::new()
            .write(true)
            .open(d.join("b.bin"))
            .unwrap();
        f.set_len(5000).unwrap(); // loses blocks 1 and 2
    });
    let r = assert_parity(&ours, &theirs, &pristine);
    assert_eq!(r.blocks_rebuilt, 4);
    assert_eq!(r.blocks_adopted, 0, "everyday damage must not scan");
}

#[test]
fn renamed_file_is_adopted_whole() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (ours, theirs, pristine) = build_pair("renamed", &["-r40"]);
    damage_both(&ours, &theirs, |d| {
        std::fs::rename(d.join("c.bin"), d.join("0af3.dat")).unwrap();
    });
    let r = assert_parity(&ours, &theirs, &pristine);
    assert_eq!(r.blocks_rebuilt, 0, "whole file present - pure adoption");
    assert_eq!(r.blocks_adopted, 1);
    assert_eq!(r.adopted_from, vec!["0af3.dat"]);
    assert_eq!(r.files_created, vec!["c.bin"]);
}

#[test]
fn renamed_and_damaged_mixes_adoption_and_rs() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (ours, theirs, pristine) = build_pair("mixed", &["-r40"]);
    damage_both(&ours, &theirs, |d| {
        // b.bin hides under an obfuscated name AND has a corrupt block;
        // a.bin has ordinary block damage on top.
        std::fs::rename(d.join("b.bin"), d.join("x9.dat")).unwrap();
        let p = d.join("x9.dat");
        let mut b = std::fs::read(&p).unwrap();
        b[4200..4300].fill(0xDD); // b.bin block 1
        std::fs::write(&p, b).unwrap();
        let a = d.join("a.bin");
        let mut b = std::fs::read(&a).unwrap();
        b[100..200].fill(0xEE); // a.bin block 0
        std::fs::write(&a, b).unwrap();
    });
    let r = assert_parity(&ours, &theirs, &pristine);
    // b.bin blocks 0 and 2 (tail, matched at the candidate's padded end)
    // adopted from x9.dat; b.bin block 1 + a.bin block 0 RS-rebuilt.
    assert_eq!(r.blocks_adopted, 2);
    assert_eq!(r.blocks_rebuilt, 2);
    assert_eq!(r.adopted_from, vec!["x9.dat"]);
}

#[test]
fn shifted_in_place_recovered_by_scan() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (ours, theirs, pristine) = build_pair("shifted", &["-r40"]);
    damage_both(&ours, &theirs, |d| {
        // 1000 junk bytes prepended under the SAME name: every aligned
        // block fails, all content lives at offset +1000.
        let p = d.join("a.bin");
        let orig = std::fs::read(&p).unwrap();
        let mut shifted = payload(1000, 99);
        shifted.extend_from_slice(&orig);
        std::fs::write(&p, shifted).unwrap();
    });
    let r = assert_parity(&ours, &theirs, &pristine);
    // All 9 blocks of a.bin found at shifted offsets in its own file.
    assert_eq!(r.blocks_adopted, 9);
    assert_eq!(r.blocks_rebuilt, 0);
}

#[test]
fn concatenated_extra_recovers_deleted_files() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (ours, theirs, pristine) = build_pair("concat", &["-r40"]);
    damage_both(&ours, &theirs, |d| {
        // a.bin ++ b.bin under one junk name, originals gone. a.bin's
        // tail block content (tail + zero padding) does NOT exist in the
        // concatenation - b.bin's bytes follow it - so that one block
        // must be RS-rebuilt; every other block is found at an offset.
        let mut joined = std::fs::read(d.join("a.bin")).unwrap();
        joined.extend(std::fs::read(d.join("b.bin")).unwrap());
        std::fs::write(d.join("joined.bin"), joined).unwrap();
        std::fs::remove_file(d.join("a.bin")).unwrap();
        std::fs::remove_file(d.join("b.bin")).unwrap();
    });
    let r = assert_parity(&ours, &theirs, &pristine);
    assert_eq!(r.blocks_rebuilt, 1, "only a.bin's padded tail needs RS");
    assert_eq!(r.blocks_adopted, 11, "8 of a.bin + all 3 of b.bin");
    assert_eq!(r.adopted_from, vec!["joined.bin"]);
    let mut created = r.files_created.clone();
    created.sort();
    assert_eq!(created, vec!["a.bin", "b.bin"]);
}

#[test]
fn renamed_recovery_volumes_are_sniffed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Obfuscated posts rename the .par2 volumes too. Keep the bare index
    // (it carries no recovery slices), hide every volume under a junk
    // name, and corrupt one block - repair must find the recovery data
    // by packet magic. NOT a parity scenario: par2cmdline only loads
    // packets from extra files whose NAME contains ".par2" (verified on
    // 1.2.0 - junk-named volumes report "no data found"), so this is a
    // case the native engine repairs and the fallback cannot.
    let (ours, theirs, pristine) = build_pair("sniffvol", &["-r40"]);
    damage_both(&ours, &theirs, |d| {
        let mut i = 0;
        for e in std::fs::read_dir(d).unwrap() {
            let p = e.unwrap().path();
            let n = p.file_name().unwrap().to_string_lossy().into_owned();
            if n.starts_with("testset.vol") {
                i += 1;
                std::fs::rename(&p, d.join(format!("blob{i}.dat"))).unwrap();
            }
        }
        assert!(i > 0, "expected renamed volumes");
        let a = d.join("a.bin");
        let mut b = std::fs::read(&a).unwrap();
        b[100..200].fill(0xEE);
        std::fs::write(&a, b).unwrap();
    });
    let r = match repair_dir(&ours.0).expect("native repair runs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        r.blocks_rebuilt, 1,
        "recovery slices came from sniffed volumes"
    );
    assert_eq!(r.blocks_adopted, 0);
    for (n, d) in ["a.bin", "b.bin", "c.bin"].iter().zip(&pristine) {
        assert_eq!(&read(&ours.0, n), d, "{n}: native output not pristine");
    }
    assert!(
        !par2cmdline_repair(&theirs.0),
        "par2cmdline should NOT see junk-named volumes - if this starts \
         passing, the installed par2 learned to sniff and this can become \
         a parity scenario"
    );
}

#[test]
fn mid_file_insertion_escalates_to_target_scan() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // 100 junk bytes inserted inside a.bin's block 2 with only TWO
    // recovery blocks on disk: blocks 0-1 still verify (identified), but
    // blocks 2..8 all fail - 7 missing > 2 recovery. Only the escalation
    // scan of the half-verified file itself finds blocks 3..8 shifted
    // +100; block 2 (its bytes split around the insertion) is the one RS
    // rebuild. par2cmdline's own target scan handles this case - parity
    // must hold.
    let (ours, theirs, pristine) = build_pair("insert", &["-c2"]);
    damage_both(&ours, &theirs, |d| {
        let p = d.join("a.bin");
        let mut b = std::fs::read(&p).unwrap();
        let junk = payload(100, 77);
        b.splice(9000..9000, junk);
        std::fs::write(&p, b).unwrap();
    });
    let r = assert_parity(&ours, &theirs, &pristine);
    assert_eq!(r.blocks_adopted, 6, "blocks 3..8 found at +100 in a.bin");
    assert_eq!(
        r.blocks_rebuilt, 1,
        "only the insertion-split block needs RS"
    );
    assert_eq!(r.adopted_from, vec!["a.bin"]);
}

#[test]
fn beyond_capacity_fails_on_both_engines() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // 1 recovery block only; rename c.bin (so the adoption scan runs)
    // and corrupt two a.bin blocks whose content then exists nowhere.
    let (ours, theirs, _) = build_pair("overcap", &["-r40"]);
    for p in std::fs::read_dir(&ours.0)
        .unwrap()
        .chain(std::fs::read_dir(&theirs.0).unwrap())
    {
        let p = p.unwrap().path();
        let n = p.file_name().unwrap().to_string_lossy().into_owned();
        // Keep the index + the single-slice volume; drop bigger volumes
        // (names are volX+Y.par2 where Y is the slice count).
        let one_slice = n
            .strip_prefix("testset.vol")
            .and_then(|r| r.split('+').nth(1))
            .and_then(|r| r.strip_suffix(".par2"))
            .is_some_and(|c| c.parse::<u32>() == Ok(1));
        if n.starts_with("testset.vol") && !one_slice {
            std::fs::remove_file(&p).unwrap();
        }
    }
    damage_both(&ours, &theirs, |d| {
        std::fs::rename(d.join("c.bin"), d.join("0af3.dat")).unwrap();
        let a = d.join("a.bin");
        let mut b = std::fs::read(&a).unwrap();
        b[100..200].fill(0xEE);
        b[5000..5100].fill(0x22);
        std::fs::write(&a, b).unwrap();
    });
    match repair_dir(&ours.0).expect("native repair runs") {
        RepairStatus::Unrepairable { needed, have } => {
            assert_eq!((needed, have), (2, 1), "c.bin adopted, 2 blocks short");
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    }
    assert!(
        !par2cmdline_repair(&theirs.0),
        "reference engine must also fail"
    );
}
