//! `par2gen` against the reference implementation.
//!
//! The unit tests beside the creator judge it with OUR OWN reader, which
//! proves the two agree and nothing more: a creator and a parser that
//! share a mistake pass those together. This is the half that cannot be
//! self-consistent - par2cmdline reads what we wrote, verifies the
//! members it names, and REPAIRS damage from the Reed-Solomon slices we
//! computed. Nothing about our own code is on the answering side.
//!
//! Interop is the point rather than a nicety: `nzbfast post`'s no-RAR
//! mode exists so the ecosystem gains a second producer of the shape the
//! Reddit thread is asking every tool to share
//! (`research/REDDIT-NORAR-FOLLOWUP-2026-08-31.md`), and a set only our
//! own client can read would be a private format wearing PAR2's name.

use std::path::{Path, PathBuf};
use std::process::Command;

use nzbkit::par2gen::{Member, Par2Spec, create_into};

/// par2cmdline is not installed everywhere - some development machines
/// in this fleet have none - so every test here opens by asking. CI
/// installs it on purpose.
fn have_par2() -> bool {
    Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success())
}

/// Deterministic and NON-PERIODIC, and the second half is load-bearing
/// rather than tidy.
///
/// This was `i * 37 + seed * 13` truncated to a byte, whose period is
/// 256 - and every block size these tests use is a multiple of 256, so
/// EVERY full block of the fixture was byte-identical to every other
/// one. A file made of duplicate blocks is the worst possible input to
/// a PAR2 repairer's sliding scan, which looks for a block's content
/// anywhere in the damaged file: it defeats the "damage well past one
/// block, so the repair genuinely has to solve" intent stated below,
/// and par2cmdline 0.8.1 - which is what `apt-get install par2` gives
/// an ubuntu runner, two majors behind every box in this fleet - gets
/// it WRONG, reporting more intact blocks than exist and writing a file
/// that verifies worse than the one it replaced.
///
/// That is a par2cmdline defect and not ours: measured 31 Aug 2026,
/// 0.8.1 fails identically on sets IT created and on 1.3.0's, while
/// 1.3.0 repairs ours and 0.8.1's alike, and 0.8.1 repairs
/// non-periodic data of the same size, block size, redundancy and
/// damage without complaint. But it reached us as a nightly failure
/// whose message accused OUR Reed-Solomon constants of disagreeing
/// with the spec, which is the wrong diagnosis in the loudest possible
/// place. A fixture that is degenerate enough to trip a repairer's
/// duplicate-block handling is not testing what this file is for.
/// `research/PAR2-NIGHTLY-TWO-REDS-RESOLVED-2026-08-31.md` carries the
/// measurement; `par2repair_namepath::payload` next door is the same
/// generator, and its comment gives the same reason from the adoption
/// side.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = (seed as u64) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-interop-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, name: &str, data: &[u8]) -> Member {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
        std::fs::write(&path, data).unwrap();
        Member {
            name: name.to_string(),
            path,
        }
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn par2(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("par2")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("par2 runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

#[test]
fn par2cmdline_verifies_a_set_we_created() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = Tmp::new("verify");
    let a = payload(120_000, 3);
    let b = payload(9_001, 11);
    let members = vec![t.write("Show.S01E01.mkv", &a), t.write("readme.nfo", &b)];
    let names = create_into(
        &t.0,
        &members,
        "testset",
        &Par2Spec {
            redundancy_pct: 20,
            block_size: Some(8192),
        },
    )
    .expect("create");
    let (ok, text) = par2(&t.0, &["verify", "-q", &names[0]]);
    assert!(ok, "par2 refused a set we wrote:\n{text}");
    // A pass is not enough on its own: par2 also exits 0 for a set whose
    // files it could not find, so pin that both members were judged.
    for m in &members {
        assert!(
            !text.contains(&format!("{}\" - missing", m.name)),
            "par2 could not find {}:\n{text}",
            m.name
        );
    }
}

#[test]
fn par2cmdline_repairs_from_the_recovery_slices_we_computed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = Tmp::new("repair");
    let a = payload(120_000, 5);
    let members = vec![t.write("payload.bin", &a)];
    let names = create_into(
        &t.0,
        &members,
        "rset",
        &Par2Spec {
            redundancy_pct: 50,
            block_size: Some(8192),
        },
    )
    .expect("create");
    assert!(names.len() > 1, "50% must emit volumes: {names:?}");

    // Damage well past one block, so the repair genuinely has to solve
    // rather than adopt an intact copy from somewhere.
    let mut broken = a.clone();
    broken[10_000..40_000].fill(0x5A);
    std::fs::write(&members[0].path, &broken).unwrap();

    let (ok, text) = par2(&t.0, &["repair", "-q", &names[0]]);
    assert!(ok, "par2 could not repair from our parity:\n{text}");
    assert_eq!(
        std::fs::read(&members[0].path).unwrap(),
        a,
        "par2 repaired to the wrong bytes - our RS constants disagree with the spec"
    );
}

#[test]
fn par2cmdline_reads_the_directory_tree_out_of_our_filedesc_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // The tree is the whole reason the FileDesc name is a relative PATH
    // and not a basename: under obfuscation it is the only place the
    // layout exists.
    let t = Tmp::new("tree");
    let members = vec![
        t.write("VIDEO_TS/VTS_01_1.VOB", &payload(50_000, 7)),
        t.write("VIDEO_TS/VTS_01_0.IFO", &payload(3_000, 9)),
    ];
    let names = create_into(
        &t.0,
        &members,
        "dvd",
        &Par2Spec {
            redundancy_pct: 10,
            block_size: Some(4096),
        },
    )
    .expect("create");
    let (ok, text) = par2(&t.0, &["verify", &names[0]]);
    assert!(ok, "par2 refused the tree set:\n{text}");
    assert!(
        text.contains("VTS_01_1.VOB") && text.contains("VTS_01_0.IFO"),
        "par2 did not name both tree members:\n{text}"
    );
}
