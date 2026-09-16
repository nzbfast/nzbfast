//! TODO 334: the repair's load prints from the engine's scan report
//! (`verify::load_scanned`) instead of reading and hashing every
//! recovery volume for itself. The property that makes that safe is
//! that the two loads print the SAME BYTES and leave the SAME FILES,
//! and `NZBFAST_PARFAST_LOAD=whole` keeps the old load reachable so a
//! test can hold the two side by side.
//!
//! And since 10 Sep 2026 the VERIFY's load answers the same arm. It
//! has no scan report to print from - nothing else in the process has
//! read the set - so it frames each volume by seeking and reads the
//! recovery packets one span at a time, which is what stopped `parfast
//! v` holding the whole recovery set in memory (2.30 GB of peak RSS on
//! a 2 GiB / 100%-parity set, against 0.10 GB). Its property is the
//! same property, so it is tested here the same way: `v` on both arms,
//! and the counts the default level prints are the part that has to
//! agree.
//!
//! Drives the built binary rather than `parfast::run_with`: the arm is
//! an environment variable read at call time, and a process-wide
//! variable cannot be flipped per test thread.
//!
//! Scratch lives under `CARGO_TARGET_TMPDIR`, as `engine_fold` does.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::scratch::scratch;

fn parfast(dir: &Path, args: &[&str], load: Option<&str>) -> (i32, String, String) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_parfast"));
    cmd.args(args)
        .current_dir(dir)
        .env("NZBFAST_NO_ENRICH", "1");
    match load {
        Some(v) => cmd.env("NZBFAST_PARFAST_LOAD", v),
        None => cmd.env_remove("NZBFAST_PARFAST_LOAD"),
    };
    let out = cmd.output().expect("parfast runs");
    (
        out.status.code().unwrap_or(-1),
        String::from_utf8_lossy(&out.stdout).into_owned(),
        String::from_utf8_lossy(&out.stderr).into_owned(),
    )
}

fn payload(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(seed | 1).wrapping_add(i >> 3)) as u8)
        .collect()
}

/// Every file under `dir`, with its bytes' digest.
fn snapshot(dir: &Path) -> Vec<(String, u64)> {
    let mut v: Vec<(String, u64)> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| {
            let bytes = std::fs::read(e.path()).unwrap();
            // A cheap digest is enough to say "same bytes" here.
            let h = bytes.iter().fold(0xcbf2_9ce4_8422_2325u64, |h, &b| {
                (h ^ u64::from(b)).wrapping_mul(0x0100_0000_01b3)
            });
            (e.file_name().to_string_lossy().into_owned(), h)
        })
        .collect();
    v.sort();
    v
}

fn copy_dir(from: &Path, to: &Path) {
    std::fs::create_dir_all(to).unwrap();
    for e in std::fs::read_dir(from).unwrap().flatten() {
        std::fs::copy(e.path(), to.join(e.file_name())).unwrap();
    }
}

/// What a terminal would be left showing: the text after the last
/// carriage return on each line, which is `tools/conformance/run.py`'s
/// own rule. The binary's progress meter (`control.rs`, 12 Sep 2026)
/// draws `Scanning: 12.3%\r` fragments from the engine's workers while
/// this thread prints the load lines, so WHERE a fragment lands between
/// two lines is timing, not behaviour - and what this test holds is the
/// lines.
fn shown(text: &str) -> String {
    text.split('\n')
        .map(|raw| raw.rsplit('\r').next().unwrap_or(""))
        .collect::<Vec<_>>()
        .join("\n")
}

/// One shape, two arms, one verdict: exit code, stdout, stderr and the
/// directory afterwards must all agree. Hands back what they agreed
/// on, so a caller that also has something to say about the CONTENT
/// (that a corruption actually bit, say) can say it without running a
/// third arm.
fn same_on_both_arms(tag: &str, build: impl FnOnce(&Path), args: &[&str]) -> (i32, String, String) {
    let root = scratch(tag);
    let src = root.join("src");
    std::fs::create_dir_all(&src).unwrap();
    build(&src);
    let scanned = root.join("scanned");
    let whole = root.join("whole");
    copy_dir(&src, &scanned);
    copy_dir(&src, &whole);
    let a = parfast(&scanned, args, None);
    let b = parfast(&whole, args, Some("whole"));
    assert_eq!(
        a.0, b.0,
        "exit codes differ:\n--- scanned\n{}\n{}--- whole\n{}\n{}",
        a.1, a.2, b.1, b.2
    );
    assert_eq!(shown(&a.1), shown(&b.1), "stdout differs ({tag})");
    assert_eq!(a.2, b.2, "stderr differs ({tag})");
    assert_eq!(
        snapshot(&scanned),
        snapshot(&whole),
        "the directories differ ({tag})"
    );
    a
}

fn create(dir: &Path, name: &str, files: &[&str], extra: &[&str]) {
    let mut args = vec!["c"];
    args.extend_from_slice(extra);
    args.push(name);
    args.extend_from_slice(files);
    let (code, out, err) = parfast(dir, &args, None);
    assert_eq!(code, 0, "create failed: {out}{err}");
}

/// The first recovery packet in `path` with room for [`damage`] to sit
/// wholly inside its body, as `(offset, len)`.
///
/// A test that corrupts a recovery packet must corrupt its BODY and
/// nothing else. A fixed offset does not do that: the volumes this
/// suite builds open with a run of 220-byte RecvSlic packets, so
/// offset 700 lands 40 bytes into the fourth packet's HEADER and takes
/// the type field with it - the packet stops being a recovery packet at
/// all, both walks then reject it as an unparsable critical, and the
/// test passes whatever the loads do with recovery packets. Measured
/// 10 Sep 2026, by flipping the census back to the headers' claims and
/// watching the test stay green.
fn first_recovery_body(path: &Path) -> Option<usize> {
    let b = std::fs::read(path).ok()?;
    let mut off = 0usize;
    while off + 64 <= b.len() {
        if &b[off..off + 8] != b"PAR2\x00PKT" {
            return None;
        }
        let len = usize::try_from(u64::from_le_bytes(b[off + 8..off + 16].try_into().unwrap()))
            .ok()
            .filter(|n| *n >= 64 && off + n <= b.len())?;
        // Past the header AND past the four exponent bytes, so what
        // breaks is the packet's MD5 and not what its header claims.
        if &b[off + 48..off + 64] == b"PAR 2.0\x00RecvSlic" && len >= 64 + 8 + 64 {
            return Some(off + 64 + 8);
        }
        off += len;
    }
    None
}

fn damage(path: &Path, at: usize) {
    let mut b = std::fs::read(path).unwrap();
    for x in &mut b[at..at + 64] {
        *x ^= 0x5a;
    }
    std::fs::write(path, b).unwrap();
}

/// The everyday damaged repair, at the default level: `Loading` lines,
/// per-file `Loaded N new packets including M recovery blocks`, the
/// block count and the backup, from both loads.
#[test]
fn a_damaged_repair_prints_and_writes_the_same_from_the_scan_report() {
    same_on_both_arms(
        "scan-load-damaged",
        |d| {
            std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
            std::fs::write(d.join("b.bin"), payload(120_000, 9)).unwrap();
            create(d, "set.par2", &["a.bin", "b.bin"], &["-r10"]);
            damage(&d.join("a.bin"), 5000);
        },
        &["r", "set.par2"],
    );
}

/// A corrupt packet in a recovery volume is skipped by both walks, so
/// the `Loaded` count under that file - which the reference derives from
/// the packets that VERIFY - must agree; and a duplicate volume under a
/// second name prints `No new packets found` from both.
#[test]
fn corrupt_and_duplicate_volumes_count_the_same_from_the_scan_report() {
    same_on_both_arms(
        "scan-load-corrupt-dup",
        |d| {
            std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
            create(d, "set.par2", &["a.bin"], &["-r20"]);
            damage(&d.join("a.bin"), 5000);
            let mut vols: Vec<PathBuf> = std::fs::read_dir(d)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().contains(".vol"))
                .collect();
            vols.sort();
            // Inside a recovery packet's payload of the largest volume.
            let big = vols.last().unwrap();
            let mut b = std::fs::read(big).unwrap();
            let mid = b.len() / 2;
            b[mid] ^= 0xff;
            std::fs::write(big, b).unwrap();
            std::fs::copy(&vols[0], d.join("set.volcopy.par2")).unwrap();
        },
        &["r", "set.par2"],
    );
}

/// A sibling the seeking walk cannot frame (leading garbage) sends the
/// load down the whole-read path: the fallback is exercised, and it
/// prints what the whole read prints because it IS the whole read.
#[test]
fn an_unframeable_volume_falls_back_and_still_agrees() {
    same_on_both_arms(
        "scan-load-unframeable",
        |d| {
            std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
            create(d, "set.par2", &["a.bin"], &["-r20"]);
            damage(&d.join("a.bin"), 5000);
            let v = d.join("set.vol00+01.par2");
            let v = if v.exists() {
                v
            } else {
                std::fs::read_dir(d)
                    .unwrap()
                    .flatten()
                    .map(|e| e.path())
                    .find(|p| p.to_string_lossy().contains(".vol"))
                    .unwrap()
            };
            let mut b = b"GARBAGE!".repeat(9);
            b.extend(std::fs::read(&v).unwrap());
            std::fs::write(&v, b).unwrap();
        },
        &["r", "set.par2"],
    );
}

/// Two sets under prefix-colliding stems in one directory: membership
/// is settled by the packets and not the glob, from both loads, and the
/// one named is the one repaired.
#[test]
fn a_prefix_colliding_neighbour_is_filtered_the_same_from_the_scan_report() {
    same_on_both_arms(
        "scan-load-prefix",
        |d| {
            std::fs::write(d.join("a.bin"), payload(200_000, 5)).unwrap();
            create(d, "Show.S01E01.par2", &["a.bin"], &["-r10"]);
            std::fs::write(d.join("b.bin"), payload(150_000, 6)).unwrap();
            create(d, "Show.S01E01E02.par2", &["b.bin"], &["-r10"]);
            damage(&d.join("a.bin"), 3000);
        },
        &["r", "Show.S01E01.par2"],
    );
}

/// Quiet and verbose print different lines; both come out identical.
#[test]
fn the_quiet_and_verbose_ladders_agree_from_the_scan_report() {
    for (tag, level) in [("scan-load-q", "-q"), ("scan-load-v", "-v")] {
        same_on_both_arms(
            tag,
            |d| {
                std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
                create(d, "set.par2", &["a.bin"], &["-r10"]);
                damage(&d.join("a.bin"), 5000);
            },
            &["r", level, "set.par2"],
        );
    }
}

/// The everyday damaged verify at the DEFAULT level, which is the one
/// that prints `Loaded N new packets including M recovery blocks` and
/// `You have N recovery blocks available.` - the two counts the seeking
/// load has to re-derive, because its parse never sees a recovery
/// packet.
#[test]
fn a_damaged_verify_counts_the_same_from_the_seeking_load() {
    same_on_both_arms(
        "sparse-verify-damaged",
        |d| {
            std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
            std::fs::write(d.join("b.bin"), payload(120_000, 9)).unwrap();
            create(d, "set.par2", &["a.bin", "b.bin"], &["-r10"]);
            damage(&d.join("a.bin"), 5000);
        },
        &["v", "set.par2"],
    );
}

/// A corrupt packet inside a recovery volume is the whole reason the
/// default level cannot defer: the reference counts the packets that
/// VERIFY, so a walk that took the headers' word for it would print a
/// count nobody hashed. Both arms must drop the same packet, in the
/// per-file line and in the set's recovery block count.
#[test]
fn a_corrupt_recovery_packet_is_dropped_by_both_verify_loads() {
    let build = |hurt: bool| {
        move |d: &Path| {
            std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
            create(d, "set.par2", &["a.bin"], &["-r30"]);
            damage(&d.join("a.bin"), 5000);
            if !hurt {
                return;
            }
            let v = std::fs::read_dir(d)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().contains(".vol"))
                .max()
                .expect("a recovery volume");
            let at = first_recovery_body(&v).expect("a recovery packet with a body to hurt");
            damage(&v, at);
        }
    };
    let intact = same_on_both_arms("sparse-verify-intact", build(false), &["v", "set.par2"]);
    let holed = same_on_both_arms("sparse-verify-corrupt", build(true), &["v", "set.par2"]);
    // And the corruption has to have BITTEN, or the agreement above is
    // an agreement about nothing.
    let blocks = |out: &str| {
        out.lines()
            .find_map(|l| {
                l.strip_prefix("You have ")?
                    .strip_suffix(" recovery blocks available.")
            })
            .expect("the recovery block count")
            .parse::<u32>()
            .expect("a number")
    };
    assert_eq!(
        blocks(&holed.1) + 1,
        blocks(&intact.1),
        "corrupting one recovery packet should cost exactly one recovery block\n--- intact\n{}\n--- holed\n{}",
        intact.1,
        holed.1
    );
}

/// A volume the seeking walk cannot frame sends the whole load down the
/// whole read, before a line is printed. Leading garbage is the shape
/// that does it: the first header is not at offset 0.
#[test]
fn an_unframeable_volume_falls_back_on_verify_too() {
    same_on_both_arms(
        "sparse-verify-unframeable",
        |d| {
            std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
            create(d, "set.par2", &["a.bin"], &["-r20"]);
            damage(&d.join("a.bin"), 5000);
            let v = std::fs::read_dir(d)
                .unwrap()
                .flatten()
                .map(|e| e.path())
                .filter(|p| p.to_string_lossy().contains(".vol"))
                .min()
                .expect("a recovery volume");
            let mut b = b"GARBAGE!".repeat(9);
            b.extend(std::fs::read(&v).unwrap());
            std::fs::write(&v, b).unwrap();
        },
        &["v", "set.par2"],
    );
}

/// The three rungs of the ladder, on a clean set and a damaged one:
/// `-q` defers the recovery packets and a clean set never reads its
/// parity at all, the default level counts them, `-v` adds the census.
#[test]
fn every_verify_ladder_rung_agrees_between_the_two_loads() {
    for (tag, level, hurt) in [
        ("sparse-verify-q", "-q", true),
        ("sparse-verify-v", "-v", true),
        ("sparse-verify-clean", "", false),
        ("sparse-verify-clean-q", "-q", false),
    ] {
        let args: Vec<&str> = if level.is_empty() {
            vec!["v", "set.par2"]
        } else {
            vec!["v", level, "set.par2"]
        };
        same_on_both_arms(
            tag,
            |d| {
                std::fs::write(d.join("a.bin"), payload(300_000, 7)).unwrap();
                create(d, "set.par2", &["a.bin"], &["-r10"]);
                if hurt {
                    damage(&d.join("a.bin"), 5000);
                }
            },
            &args,
        );
    }
}
