//! The evidence behind the 27 `:files` waivers in
//! `tools/conformance/allow/par2.txt`.
//!
//! Those waivers say a set parfast creates carries the SAME PACKETS,
//! byte for byte, as par2cmdline's over the same input - every Main,
//! FileDesc, IFSC and recovery slice - and differs only in the Creator
//! packet, which is free-form ASCII naming the program that wrote the
//! set. A waiver is a claim somebody verified, and a claim nobody
//! re-checks decays into a mute button, so this re-proves it: create the
//! same set with both binaries, walk both files packet by packet, and
//! compare the MULTISETS of packet digests.
//!
//! # What is compared
//!
//! Two tests, and the second is the strict one.
//!
//! `only_the_creator_packet_differs_from_par2cmdlines_set` compares the
//! DISTINCT packets each file holds. It caught two real spec bugs the
//! day it was written - a file id hashed over the NULL-PADDED name, and
//! a Main list sorted lexicographically where the spec sorts
//! little-endian - and it is the thing standing between the `:files`
//! waivers and a real regression hiding behind them. What it cannot see
//! is MULTIPLICITY: a set holding the right packets the wrong number of
//! times passes it.
//!
//! That blindspot hid a real divergence for a day. par2cmdline repeats
//! the whole critical block through every volume - so a volume truncated
//! anywhere still yields a nameable set - and par2gen wrote it once at
//! the head, which made every volume a different SIZE. Four e2e fixtures
//! read that size, and all four failed the day parfast stood in for
//! `par2` (research/CLI-SUBSTITUTION-2026-09-03.md, G2). parfast now
//! creates under `CriticalLayout::Interleaved` and nzbfast's own posting
//! path keeps `Head`, so
//! `every_volume_is_byte_identical_but_for_the_creator_packet` compares
//! the BYTES: splice the Creator packet out of both files - it is the
//! one packet that names its writer, and naming par2cmdline would be
//! claiming to be it - and the remainder must be equal, in every file,
//! index and volumes alike.
//!
//! Needs `par2` on PATH, or `NZBFAST_PAR2_BIN` pointing at one. Skips
//! when neither is there, which is how every other interop suite in this
//! repository handles a reference that not every box has;
//! `NZBFAST_REQUIRE_PAR2=1` turns the skip into a failure.

use std::path::{Path, PathBuf};
use std::process::Command;

/// PAR2's packet header: magic, 8-byte length, packet MD5, set id, type.
const MAGIC: &[u8; 8] = b"PAR2\0PKT";
const TYPE_CREATOR: &[u8; 16] = b"PAR 2.0\0Creator\0";

/// `(type, md5-of-the-hashed-region)` for every structurally plausible
/// packet in `bytes`.
///
/// A deliberately DUMB walk, and it must stay dumb: this is a test's
/// second opinion, so borrowing the engine's own parser would let one
/// mistake agree with itself. It hops by declared length and gives up on
/// anything malformed, which is enough for two well-formed sets.
fn packets(bytes: &[u8]) -> Vec<([u8; 16], [u8; 16])> {
    let mut out = Vec::new();
    let mut i = 0usize;
    while i + 64 <= bytes.len() {
        if &bytes[i..i + 8] != MAGIC {
            i += 1;
            continue;
        }
        let len = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap()) as usize;
        if len < 64 || i + len > bytes.len() {
            i += 8;
            continue;
        }
        let mut md5 = [0u8; 16];
        md5.copy_from_slice(&bytes[i + 16..i + 32]);
        let mut ptype = [0u8; 16];
        ptype.copy_from_slice(&bytes[i + 48..i + 64]);
        out.push((ptype, md5));
        i += len;
    }
    out
}

fn reference() -> Option<PathBuf> {
    let named = std::env::var_os("NZBFAST_PAR2_BIN").map(PathBuf::from);
    let candidates: Vec<PathBuf> = named.into_iter().chain([PathBuf::from("par2")]).collect();
    candidates.into_iter().find(|c| {
        Command::new(c)
            .arg("-V")
            .output()
            .is_ok_and(|o| o.status.success())
    })
}

/// The built `parfast`, beside this test binary.
fn parfast_bin() -> PathBuf {
    let mut p = std::env::current_exe().expect("test binary has a path");
    p.pop(); // deps/
    p.pop();
    p.join("parfast")
}

/// Deterministic and non-periodic: a payload of repeating blocks is the
/// worst input to a PAR2 tool's duplicate-block handling and proves
/// nothing about the arithmetic. Same generator, and the same reason, as
/// `par2gen_interop`'s next door.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = u64::from(seed) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn write_inputs(dir: &Path) {
    std::fs::create_dir_all(dir).unwrap();
    std::fs::write(dir.join("a.bin"), payload(40_000, 7)).unwrap();
    std::fs::write(dir.join("b.bin"), payload(17_000, 29)).unwrap();
}

/// One set built twice, by the reference and by parfast, in two
/// directories: `(reference dir, our dir, the reference's file names)`.
///
/// `None` is the skip - no reference on the box, or no parfast built
/// beside this test binary - reported the same way every other interop
/// suite here reports it.
fn build_both(tag: &str, args: &[&str]) -> Option<(PathBuf, PathBuf, Vec<String>)> {
    let Some(reference) = reference() else {
        assert!(
            std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
            "NZBFAST_REQUIRE_PAR2 is set and no par2 binary answered"
        );
        eprintln!("no par2 on PATH - skipping (set NZBFAST_PAR2_BIN, or NZBFAST_REQUIRE_PAR2=1)");
        return None;
    };
    let parfast = parfast_bin();
    if !parfast.exists() {
        eprintln!("parfast binary not built beside this test - skipping");
        return None;
    }

    let root = std::env::temp_dir().join(format!("parfast-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&root);
    let (ref_dir, our_dir) = (root.join("reference"), root.join("ours"));
    write_inputs(&ref_dir);
    write_inputs(&our_dir);

    let r = Command::new(&reference)
        .args(args)
        .current_dir(&ref_dir)
        .output()
        .expect("reference runs");
    assert!(r.status.success(), "reference create failed: {r:?}");
    let o = Command::new(&parfast)
        .args(args)
        .current_dir(&our_dir)
        .output()
        .expect("parfast runs");
    assert!(o.status.success(), "parfast create failed: {o:?}");

    let mut names: Vec<String> = std::fs::read_dir(&ref_dir)
        .unwrap()
        .flatten()
        .filter_map(|e| e.file_name().into_string().ok())
        .filter(|n| n.ends_with(".par2"))
        .collect();
    names.sort();
    assert!(!names.is_empty(), "the reference wrote no recovery files");
    Some((ref_dir, our_dir, names))
}

/// `bytes` with every Creator packet spliced out, so what remains is
/// comparable between two tools that name themselves differently.
///
/// The same deliberately dumb walk as [`packets`], and dumb for the same
/// reason: a test's second opinion must not borrow the engine's parser.
fn without_creator(bytes: &[u8]) -> Vec<u8> {
    let mut out = Vec::with_capacity(bytes.len());
    let mut i = 0usize;
    while i + 64 <= bytes.len() {
        if &bytes[i..i + 8] != MAGIC {
            i += 1;
            continue;
        }
        let len = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap()) as usize;
        if len < 64 || i + len > bytes.len() {
            i += 8;
            continue;
        }
        if &bytes[i + 48..i + 64] != TYPE_CREATOR {
            out.extend_from_slice(&bytes[i..i + len]);
        }
        i += len;
    }
    out
}

/// The whole of parfast's drop-in claim about `create`, at byte
/// resolution: for every file the reference writes, ours holds the same
/// bytes in the same order once the Creator packet is removed.
///
/// This is the test that has to see the volume interleave. The packet
/// comparison below it cannot: it is over a SET of digests, so a
/// critical block written once where the reference writes it seven times
/// looks identical to it. Four shapes, chosen to move the two things
/// the interleave depends on - the volume split (`-n`, `-u`, and the
/// exponential default) and the per-volume slice count, which is what
/// decides how many copies of the block a volume carries.
#[test]
fn every_volume_is_byte_identical_but_for_the_creator_packet() {
    let shapes: [(&str, &[&str]); 4] = [
        (
            "default",
            &["c", "-q", "-b64", "-r20", "set.par2", "a.bin", "b.bin"],
        ),
        (
            "nfiles",
            &[
                "c", "-q", "-s2000", "-c20", "-n4", "set.par2", "a.bin", "b.bin",
            ],
        ),
        (
            "uniform",
            &[
                "c", "-q", "-s2000", "-c20", "-u", "set.par2", "a.bin", "b.bin",
            ],
        ),
        // 150 blocks reaches a 64-slice volume, where the reference
        // writes 7 copies of the block and a proportional spread that a
        // small set never exercises.
        (
            "wide",
            &["c", "-q", "-s4096", "-c150", "set.par2", "a.bin", "b.bin"],
        ),
    ];
    for (tag, args) in shapes {
        let Some((ref_dir, our_dir, names)) = build_both(tag, args) else {
            return;
        };
        for name in &names {
            let ours = our_dir.join(name);
            assert!(ours.exists(), "{tag}: parfast did not write {name}");
            let a = without_creator(&std::fs::read(ref_dir.join(name)).unwrap());
            let b = without_creator(&std::fs::read(&ours).unwrap());
            let at = (0..a.len().min(b.len())).find(|&i| a[i] != b[i]);
            assert!(
                a == b,
                "{tag}/{name}: parfast's bytes differ from par2cmdline's outside the                  Creator packet ({} bytes against {}, first difference at {at:?}). If the                  sizes differ by a multiple of the critical block, the volume INTERLEAVE                  has drifted - fix par2gen's writer, never this assertion",
                b.len(),
                a.len()
            );
        }
        let _ = std::fs::remove_dir_all(ref_dir.parent().unwrap());
    }
}

#[test]
fn only_the_creator_packet_differs_from_par2cmdlines_set() {
    // `-b64 -r20` is the shape the conformance harness's own `intact`
    // fixture uses.
    let args = ["c", "-q", "-b64", "-r20", "set.par2", "a.bin", "b.bin"];
    let Some((ref_dir, our_dir, names)) = build_both("creator", &args) else {
        return;
    };
    let root = ref_dir.parent().unwrap().to_path_buf();

    for name in &names {
        let ours = our_dir.join(name);
        assert!(
            ours.exists(),
            "parfast did not write {name}, so the volume NAMING has drifted from the \
             reference's - the whole `:files` waiver family assumes the names match and \
             only the bytes of one packet do not"
        );
        let mut a = packets(&std::fs::read(ref_dir.join(name)).unwrap());
        let mut b = packets(&std::fs::read(&ours).unwrap());
        a.sort();
        b.sort();
        let only_ref: Vec<_> = a.iter().filter(|p| !b.contains(p)).collect();
        let only_ours: Vec<_> = b.iter().filter(|p| !a.contains(p)).collect();
        let offenders: Vec<&[u8; 16]> = only_ref
            .iter()
            .chain(only_ours.iter())
            .map(|(t, _)| t)
            .filter(|t| *t != TYPE_CREATOR)
            .collect();
        assert!(
            offenders.is_empty(),
            "{name}: packets other than Creator differ between the reference's set and \
             ours ({:?}). The 27 `:files` waivers in tools/conformance/allow/par2.txt rest \
             on exactly this being false - fix the engine, do not widen the waiver",
            offenders
                .iter()
                .map(|t| String::from_utf8_lossy(&t[..]).to_string())
                .collect::<Vec<_>>()
        );
        assert_eq!(
            only_ref.len(),
            1,
            "{name}: expected exactly one differing packet (Creator), got {}",
            only_ref.len()
        );
    }
    let _ = std::fs::remove_dir_all(&root);
}
