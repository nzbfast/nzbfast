//! The ceiling, the failure split, and a source scan over the settle
//! subtree.
//!
//! The gauge itself is deliberately NOT asserted here, and the reason is
//! sharper than "process-global state is awkward". EVERY test below
//! MOVES `Sub::RepairScan` already - indirectly, through
//! `VolumeBytes::new`, which is a path `tools/test-global-gate.py`
//! cannot see, since it resolves calls to `memgauge`'s own doors and
//! these go through this module. So a seventh test that also READ the
//! gauge would turn this file into a contested family on its own, and
//! the serializer that fixes one - `memgauge::one_gauge_test_at_a_time`
//! - is `pub(crate)` to NZBKIT and cannot be taken from this crate.
//! Exporting it is the right fix if a reader is ever wanted; do that
//! before writing one, rather than asserting a value six neighbours can
//! move.
//!
//! (`serve::api::system::mem_floor_at_peak_carries_the_gauge_snapshot`
//! is the other nzbfast test that moves a gauge and is NOT in this
//! family: it moves `Sub::Holds`, and its assertions are presence
//! checks. Nothing here can reach it.)
//!
//! What is specific to this module is that a charge is taken at all, and
//! that is what the HOME arm below pins from source; the RAII pairing
//! itself is `memgauge::Charge`'s own contract and is tested there.

use super::*;

fn scratch(tag: &str) -> crate::testscratch::ScratchDir {
    let d = std::env::temp_dir().join(format!("nzbfast-volbytes-{tag}-{}", std::process::id()));
    crate::testscratch::ScratchDir::attach(&d)
}

/// An ordinary volume comes back whole, because that is the whole point:
/// `usable_slices_of` counts slices across every byte and a short read
/// silently undercounts parity.
#[test]
fn a_volume_under_the_ceiling_comes_back_whole() {
    let d = scratch("whole");
    let p = d.join("vol.par2");
    let body: Vec<u8> = (0u32..4096).map(|i| (i % 251) as u8).collect();
    std::fs::write(&p, &body).unwrap();

    let got = read_volume_bounded(&p, 1 << 20).expect("a readable file");
    assert_eq!(&*got, &body[..], "the reader must not truncate the volume");
}

/// Past the ceiling is `Some(empty)` and NOT a slurp, and not `None`
/// either: the two answers mean different things to the parent. This is
/// the arm that keeps settle's parity arithmetic honest with the engine,
/// which skips the same file - `collect_packet_files` by name and by
/// sniff, `PacketCatalog::build_lazy` on its relist.
#[test]
fn a_volume_past_the_ceiling_reads_as_zero_parity_rather_than_being_slurped() {
    let d = scratch("oversize");
    let p = d.join("huge.par2");
    std::fs::write(&p, vec![0xABu8; 4096]).unwrap();

    let got = read_volume_bounded(&p, 1024).expect("a file that exists is not a read failure");
    assert!(
        got.is_empty(),
        "past the ceiling the answer must be zero parity, so `on_hand` \
         never credits slices the repair will refuse to load"
    );
}

/// A file that cannot be read at all is `None`, which is what leaves each
/// call site's existing failure path alone - `replace_bootstrap_slice_counts`
/// must NOT replace a set's `recovery_blocks_seen` with zero just because
/// a disk read failed.
#[test]
fn an_unreadable_path_is_none_and_not_an_empty_volume() {
    let d = scratch("missing");
    assert!(
        read_volume_bounded(&d.join("nothing-here.par2"), 1 << 20).is_none(),
        "a read failure and a file past the ceiling are different answers"
    );
}

/// The uncapped door charges too, and stays uncapped.
///
/// `set_id_at`'s whole-file fallback is the one caller: it exists because
/// a volume whose first complete packet runs past the id head would
/// otherwise answer `None`, which reads at `main_par2_for` as "not this
/// set's index" - silently wrong. A ceiling here would restore that
/// silence at a different size.
#[test]
fn the_uncapped_door_reads_whole_however_large() {
    let d = scratch("uncapped");
    let p = d.join("big.par2");
    let body = vec![0x5Au8; 8192];
    std::fs::write(&p, &body).unwrap();

    let got = read_whole_charged(&p).expect("a readable file");
    assert_eq!(&*got, &body[..]);
    assert!(read_whole_charged(&d.join("gone.par2")).is_none());
}

/// EVERY whole-file read on the settle path goes through this module.
///
/// No test in here can see a CALLER that went back to `std::fs::read`,
/// and that is the shape the class actually regrows in: these sites are
/// hand-copied siblings, so the next one is a copy of one of them - fine
/// if it copies the charged reader, silently wrong if it does not, and
/// silently wrong here means one whole recovery volume held uncharged and
/// uncapped, invisible to the `[mem-floor]` line and crediting parity the
/// repair engine will refuse to load.
///
/// It is a WALK and not a list of today's files, because a list is a scan
/// that cannot see the sixth module: `settle/` gained `setid.rs` on
/// 31 Aug 2026 and this file the same day. Measured on that tree - four
/// bare reads before this landed (three in `settle.rs`, one in
/// `setid.rs`), ZERO after - so there is no baseline and a hit must not
/// get one. FIX A HIT by calling `read_volume_for_slices` (or
/// `read_whole_charged` where a ceiling would be wrong, and say why); a
/// read that genuinely is not a recovery volume says so at the site with
/// `settle-read-charge: <reason>` on its own line or the one above.
///
/// Deliberately narrow: this judges the settle subtree, which was swept
/// to zero, and says nothing about the rest of the tree. Whether the
/// CLASS is worth a `tools/` gate is residue item 2 of
/// `research/SET-ID-READ-BOUNDS-MEASURED-2026-08-31.md` and wants its
/// false-positive rate priced first - do not read this test as that gate.
#[test]
fn no_settle_module_reads_a_file_whole_except_this_one() {
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src/get");
    let mut files: Vec<std::path::PathBuf> = vec![root.join("settle.rs")];
    let mut stack = vec![root.join("settle")];
    while let Some(dir) = stack.pop() {
        for e in std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display())) {
            let p = e.expect("a directory entry").path();
            if p.is_dir() {
                stack.push(p);
            } else if p.extension().is_some_and(|x| x == "rs") {
                files.push(p);
            }
        }
    }
    // Failing to find is failing: a walk that reached nothing would
    // report a clean subtree forever, which is the shape
    // `web/i18n/nav-regen.py`'s picker arm sat in for months. TEN files
    // on the tree that landed this, so the floor carries two of slack -
    // enough that a module merged away does not redden it for a reason
    // nobody can act on, and far above what an inert walk (0 or 1)
    // reads.
    assert!(
        files.len() >= 8,
        "the settle subtree walk reached only {} file(s) - it has stopped \
         seeing the modules it is supposed to judge",
        files.len()
    );

    let mut hits: Vec<String> = Vec::new();
    let mut reached = 0usize;
    for f in &files {
        // This module IS the one place the read is allowed, and a test
        // file is fixture setup rather than a settle-path read.
        let name = f.file_name().unwrap_or_default().to_string_lossy();
        if name == "volbytes.rs" || name.ends_with("_tests.rs") {
            continue;
        }
        reached += 1;
        let src = std::fs::read_to_string(f).unwrap_or_else(|e| panic!("{}: {e}", f.display()));
        let lines: Vec<&str> = src.lines().collect();
        for (i, line) in lines.iter().enumerate() {
            let code = line.split_once("//").map_or(*line, |(c, _)| c);
            if !code.contains("fs::read(") {
                continue;
            }
            let waived = line.contains("settle-read-charge:")
                || (i > 0 && lines[i - 1].contains("settle-read-charge:"));
            if !waived {
                hits.push(format!("{}:{}", f.display(), i + 1));
            }
        }
    }
    // FIVE production files today (settle.rs, dupenote, noset, repair,
    // setid); the floor is one below so that folding a child back into
    // the parent is not a red, while a skip list that has started
    // matching everything still shows as 0 or 1.
    assert!(
        reached >= 4,
        "only {reached} production file(s) judged - the skip list has \
         swallowed the subtree"
    );
    assert!(
        hits.is_empty(),
        "whole-file reads on the settle path that are neither charged to \
         memgauge nor held to the packet-file ceiling: {hits:?}"
    );
}

/// THE HOME ARM. A source scan over the callers is worth nothing if the
/// reader itself stopped charging or stopped holding the ceiling:
/// narrowed back HERE, the class returns at every call site at once with
/// no call-site diff anywhere to show it. That is
/// `tools/iface-excess-gate.py`'s third-arm argument, one module over.
///
/// Comments are stripped first and that is load-bearing rather than
/// tidy: this module's own header quotes all three tokens in prose, so a
/// scan that read them would pass over a reader that had lost every one
/// of them.
#[test]
fn the_reader_itself_still_charges_and_still_holds_the_engines_ceiling() {
    let src = include_str!("../volbytes.rs");
    let code: String = src
        .lines()
        .filter(|l| !l.trim_start().starts_with("//"))
        .collect::<Vec<_>>()
        .join("\n");
    for token in [
        "memgauge::Charge::new(",
        "Sub::RepairScan",
        "MAX_PACKET_FILE_BYTES",
    ] {
        assert!(
            code.contains(token),
            "volbytes.rs no longer names `{token}` in CODE - the charge or \
             the ceiling has been narrowed away, and every call site loses \
             it at once with nothing in their own diffs to say so"
        );
    }
}
