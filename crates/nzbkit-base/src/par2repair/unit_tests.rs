//! Lib-level unit tests for the DIRECTORY repair path (coverage §122.5).
//!
//! A child module of `par2repair` (the pool/unit_tests.rs pattern) so
//! par2repair.rs itself stays inside its size-gate entry while the
//! private internals remain reachable through `super::*`. The inline
//! `mod tests` exercises the math and the mapped driver; everything
//! here goes through the on-disk entry points - `repair_dir`,
//! `repair_present_sets`, `covered_names`, `sniffed_packet_files` -
//! with real serialized packet files, because those paths were only
//! ever reached from the nzbfast binaries and a --lib measurement
//! cannot see that.

use super::*;
use crate::gf16::MulTable;

/// Wrap a body in a valid packet (magic, length, body MD5) - the same
/// shape par2.rs's own tests build. Header is 64 bytes per spec.
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]); // md5 patched below
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

fn fid(i: usize) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = i as u8 + 1;
    f
}

/// Serialized index file: Main + per-file FileDesc + IFSC packets.
fn par2_index(set_id: [u8; 16], bs: usize, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut main = Vec::new();
    main.extend_from_slice(&(bs as u64).to_le_bytes());
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for i in 0..files.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(set_id, par2::TYPE_MAIN, &main);
    for (i, (name, data)) in files.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
        // Short files: md5_16k IS the whole-file MD5, not zero-padded.
        let head = &data[..data.len().min(16384)];
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(head)));
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        let mut nb = name.as_bytes().to_vec();
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, par2::TYPE_FILEDESC, &desc));
        let mut body = fid(i).to_vec();
        for chunk in data.chunks(bs) {
            let mut padded = chunk.to_vec();
            padded.resize(bs, 0);
            body.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
            body.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        out.extend(pkt(set_id, par2::TYPE_IFSC, &body));
    }
    out
}

/// The set's global input slices: files in Main order, zero-padded.
fn global_slices(files: &[(&str, &[u8])], bs: usize) -> Vec<Vec<u8>> {
    let mut slices = Vec::new();
    for (_, data) in files {
        for c in data.chunks(bs) {
            let mut v = c.to_vec();
            v.resize(bs, 0);
            slices.push(v);
        }
    }
    slices
}

/// One recovery slice's data for exponent `e` - the same generator the
/// inline math tests validate against the Reconstructor.
fn generate_recovery(slices: &[Vec<u8>], bs: usize, e: u32) -> Vec<u8> {
    let logs = input_base_logs(slices.len()).unwrap();
    let mut acc = vec![0u16; bs / 2];
    for (d, &k) in slices.iter().zip(&logs) {
        MulTable::new(gf16::pow2(k as u64 * e as u64)).xor_mul_into(&mut acc, d);
    }
    acc.iter().flat_map(|w| w.to_le_bytes()).collect()
}

/// Serialized recovery volume holding one RecvSlic packet per exponent.
fn par2_volume(set_id: [u8; 16], bs: usize, files: &[(&str, &[u8])], exps: &[u32]) -> Vec<u8> {
    let slices = global_slices(files, bs);
    let mut out = Vec::new();
    for &e in exps {
        let mut body = e.to_le_bytes().to_vec();
        body.extend_from_slice(&generate_recovery(&slices, bs, e));
        out.extend(pkt(set_id, par2::TYPE_RECVSLIC, &body));
    }
    out
}

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

fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!(
        "nzbfast-par2dir-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

const BS: usize = 64;
const SET: [u8; 16] = [9u8; 16];

/// Y2 and Y3 (wave-4 follow-ups): the padded-window fixtures, a child
/// module so they reach the helpers above while this file stays inside
/// its size-gate ceiling.
mod padded_windows;

/// G1 (wave-4 follow-up): where the donor-vanish pin stops - a child
/// module for the same two reasons as `padded_windows` above.
mod donor_pin_bounds;

/// `Unrepairable`-carries-no-per-file-report reproduction (claim
/// `unrepairable-per-file-publish`) - a child module for the same two
/// reasons as `padded_windows` above.
mod unrepairable_partial;

/// The disambiguating `.dup-<fid>` tag on a name already AT the
/// component cap - a child module for the same two reasons.
mod dup_name_cap;

/// §293's donor directory - twelve tests through
/// `repair_dir_with_donors`, moved out whole on 31 Aug 2026 - a
/// child module for the same two reasons as `padded_windows` above.
mod donor_dir;

/// The donor copy's `.<leaf>.donating` staging name on a leaf already AT
/// the component cap - a child module for the same two reasons.
mod donate_name_cap;

/// Donor PARITY - a donor directory's own recovery volumes harvested
/// as slices for this set (claim `donor-parity-catalog-harvest`) - a
/// child module for the same two reasons as `padded_windows` above.
/// Distinct subject from `donor_dir` beside it: that one is TODO 293,
/// which adopts a donor's PAYLOAD and excludes its par2.
mod donor_parity;

/// Codex sweep 10 Aug M4: the packet-file ceiling is a bound on how much
/// attacker-chosen input one directory entry becomes in memory, and every
/// packet file below is read WHOLE. The extension is the poster's choice,
/// so a bound only extensionless volumes had to clear was no bound at
/// all - renaming the file to `*.par2` walked straight past it.
///
/// Driven through the private bounded form rather than a real gigabyte:
/// the predicate is what regressed, and the constant only picks where it
/// sits.
#[test]
fn the_packet_file_ceiling_binds_by_size_not_by_name() {
    let dir = tmpdir("packet-ceiling");
    let a = payload(200, 1);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let index = par2_index(SET, BS, files);
    let vol = par2_volume(SET, BS, files, &[0]);
    // The same oversized volume twice: once named, once bare. Both are
    // past the ceiling, and neither may be collected.
    std::fs::write(dir.join("set.par2"), &index).unwrap();
    std::fs::write(dir.join("big.par2"), &vol).unwrap();
    std::fs::write(dir.join("bigbare"), &vol).unwrap();
    let cap = (index.len().min(vol.len()) - 1) as u64;
    assert!(cap >= 64, "the sniff floor still has to be clearable");
    let (collected, sniffed) = collect_packet_files_bounded(&dir, cap).expect("walk");
    assert!(
        collected.is_empty() && sniffed.is_empty(),
        "an oversized file was collected: {collected:?}"
    );
    // ...and under a ceiling they clear, both come back - so the test
    // above is the bound talking, not a name or a parse failure.
    let (collected, sniffed) = collect_packet_files_bounded(&dir, u64::MAX).expect("walk");
    assert_eq!(
        collected.len(),
        3,
        "all three are packet files: {collected:?}"
    );
    assert_eq!(sniffed.len(), 1, "only the bare one needs a sniff");
    let _ = std::fs::remove_dir_all(&dir);
}

/// The SAME rule on the path that actually reads packet bytes today.
///
/// `collect_packet_files_bounded` above is still live (it is what
/// `sniffed_packet_files` walks), but the repair pass moved to
/// `PacketCatalog` on 20 Aug 2026, and the catalog carries its own copy of
/// the by-name/by-sniff ceiling in `relist`. `build_lazy_bounded` was
/// added as the test seam for it and no test ever used it, so the M4 rule
/// was pinned on one of the two sites while the other - the one whose
/// `scan_file` does the whole-file `std::fs::read` - was pinned nowhere
/// (23 Aug 2026, dispositioning the 3 Aug "named `.par2` whole-file
/// reads" item).
#[test]
fn the_catalogs_packet_file_ceiling_binds_by_size_not_by_name() {
    let dir = tmpdir("catalog-ceiling");
    let a = payload(200, 1);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let index = par2_index(SET, BS, files);
    let vol = par2_volume(SET, BS, files, &[0]);
    std::fs::write(dir.join("set.par2"), &index).unwrap();
    std::fs::write(dir.join("big.par2"), &vol).unwrap();
    std::fs::write(dir.join("bigbare"), &vol).unwrap();
    let cap = (index.len().min(vol.len()) - 1) as u64;
    assert!(cap >= 64, "the sniff floor still has to be clearable");
    let cat = PacketCatalog::build_lazy_bounded(&dir, cap, PacketScope::Flat).expect("list");
    assert_eq!(
        cat.packet_paths().count(),
        0,
        "an oversized file was cataloged: {:?}",
        cat.packet_paths().collect::<Vec<_>>()
    );
    // The bound talking, not a name or a parse failure.
    let cat = PacketCatalog::build_lazy_bounded(&dir, u64::MAX, PacketScope::Flat).expect("list");
    assert_eq!(cat.packet_paths().count(), 3);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn clean_set_reads_no_damage_and_names_its_files() {
    let dir = tmpdir("clean");
    let a = payload(200, 1); // 4 slices, 8-byte tail
    let b = payload(97, 2); // 2 slices, 33-byte tail
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("a.bin"), &a).unwrap();
    std::fs::write(dir.join("b.bin"), &b).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();
    match repair_dir(&dir).expect("clean set verifies") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage, got {other:?}"),
    }
    let mut names = covered_names(&dir).expect("names parse");
    names.sort();
    assert_eq!(names, ["a.bin", "b.bin"]);
    assert!(
        sniffed_packet_files(&dir).expect("sniff walks").is_empty(),
        "every packet file here is named *.par2"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn damage_and_a_missing_file_rebuild_from_recovery_slices() {
    let dir = tmpdir("rebuild");
    let a = payload(200, 3);
    let b = payload(97, 4);
    let files: &[(&str, &[u8])] = &[("a.bin", &a), ("b.bin", &b)];
    // a.bin: slice 1 corrupted in place. b.bin: gone entirely.
    let mut a_damaged = a.clone();
    for x in &mut a_damaged[64..128] {
        *x ^= 0x5a;
    }
    std::fs::write(dir.join("a.bin"), &a_damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // Four recovery slices for three missing blocks - and the volume is a
    // SECOND packet file, so the critical-complete break routes its scan
    // through the background thread overlapped with target verify.
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    let report = match repair_dir(&dir).expect("repairable set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.blocks_rebuilt, 3,
        "one a.bin slice + two b.bin slices"
    );
    assert_eq!(report.blocks_adopted, 0);
    assert_eq!(report.files_created, ["b.bin"], "absent file recreated");
    let mut patched = report.files_patched.clone();
    patched.sort();
    assert_eq!(patched, ["a.bin", "b.bin"]);
    assert!(report.consumed_sources.is_empty());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    // A second pass over the repaired dir is the NoDamage path.
    match repair_dir(&dir).expect("repaired set re-verifies") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage after repair, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn too_little_recovery_reports_the_shortfall() {
    let dir = tmpdir("short");
    let c = payload(200, 5);
    let files: &[(&str, &[u8])] = &[("c.bin", &c)];
    let mut damaged = c.clone();
    for x in &mut damaged[0..128] {
        *x ^= 0x77; // slices 0 and 1 both bad
    }
    std::fs::write(dir.join("c.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();
    // Two missing, one slice on disk. The last-resort escalation slides
    // over the identified-but-damaged target itself, finds nothing (the
    // corrupt bytes are gone), and the verdict states the arithmetic.
    match repair_dir(&dir).expect("shortfall is a verdict, not an error") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!((needed, have), (2, 1));
        }
        other => panic!("expected Unrepairable, got {other:?}"),
    }
    assert_eq!(
        std::fs::read(dir.join("c.bin")).unwrap(),
        damaged,
        "an unrepairable set must not touch the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn sliding_scan_adopts_shifted_block_content_from_a_fragment() {
    let dir = tmpdir("slide");
    let c = payload(200, 6);
    let files: &[(&str, &[u8])] = &[("c.bin", &c)];
    let mut damaged = c.clone();
    for x in &mut damaged[64..128] {
        *x ^= 0x33; // slice 1 bad
    }
    std::fs::write(dir.join("c.bin"), &damaged).unwrap();
    // No recovery slices at all - but a junk-named fragment carries the
    // lost block's bytes at an UNALIGNED offset only the rolling-CRC
    // window can find.
    let mut frag = vec![0xEEu8; 10];
    frag.extend_from_slice(&c[64..128]);
    std::fs::write(dir.join("frag"), &frag).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_rebuilt, 0);
    assert_eq!(report.blocks_adopted, 1);
    assert_eq!(report.adopted_from, ["frag"]);
    assert!(
        report.consumed_sources.is_empty(),
        "a fragment is not a byte-for-byte copy of any target - never swept"
    );
    assert_eq!(std::fs::read(dir.join("c.bin")).unwrap(), c);
    let _ = std::fs::remove_dir_all(&dir);
}

/// M4-01 (30 Aug 2026): one set naming the split PARTS *and* the JOIN.
/// The parts land intact under their own FileDescs, so they are
/// IDENTIFIED targets - which `adoption_candidates` excludes on purpose
/// and the escalation only re-admits when they are DAMAGED - and the
/// join is a wholly missing file whose every block is on disk next
/// door. This set carries no recovery slices at all, so a repair here
/// can only come from the in-set harvest, and the report has to show
/// it: zero blocks rebuilt.
#[test]
fn the_in_set_harvest_rebuilds_a_join_from_its_own_intact_parts() {
    let dir = tmpdir("insetjoin");
    let join = payload(BS * 6, 41);
    let files: &[(&str, &[u8])] = &[
        ("j.bin.001", &join[..BS * 3]),
        ("j.bin.002", &join[BS * 3..]),
        ("j.bin", &join),
    ];
    std::fs::write(dir.join("j.bin.001"), &join[..BS * 3]).unwrap();
    std::fs::write(dir.join("j.bin.002"), &join[BS * 3..]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let report = match repair_dir(&dir).expect("the harvest repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(
        report.blocks_rebuilt, 0,
        "no recovery data exists here, so a nonzero rebuild is impossible - \
         and at a redundancy where it IS possible, spending it on bytes \
         already on disk is the defect this row pins"
    );
    assert_eq!(report.blocks_adopted, 6, "every block of the join");
    assert_eq!(report.adopted_from, ["j.bin.001", "j.bin.002"]);
    assert_eq!(std::fs::read(dir.join("j.bin")).unwrap(), join);
    // The parts are declared names of this set: intact targets are never
    // adoption sweep candidates, whatever they donated.
    assert!(
        report.consumed_sources.is_empty(),
        "a declared, intact target must never be swept as a spent source"
    );
    assert_eq!(
        std::fs::read(dir.join("j.bin.001")).unwrap(),
        join[..BS * 3]
    );
    assert_eq!(
        std::fs::read(dir.join("j.bin.002")).unwrap(),
        join[BS * 3..]
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The harvest's proof bar, from the other side, and the reason the
/// declared block checksums are not by themselves evidence about the
/// disk: verify prices a slice present from a WHOLE-FILE MD5 whenever
/// that matches, without ever checking a block. Here `d.bin` holds junk
/// its own FileDesc describes correctly, while its IFSC claims
/// `c.bin`'s block checksums - a shape a hostile or simply broken
/// creator can emit, and one par2cmdline itself would never produce.
/// The harvest must re-prove `d.bin`'s bytes and refuse them; this set
/// has no recovery slices, so refusing means an honest shortfall
/// verdict rather than a `c.bin` full of junk that fails the final
/// whole-file proof.
#[test]
fn the_in_set_harvest_reproves_the_source_bytes_before_adopting_them() {
    let dir = tmpdir("insetproof");
    let c = payload(BS * 2, 42);
    let junk = payload(BS * 2, 43);
    let mut index = par2_index(SET, BS, &[("c.bin", &c), ("d.bin", &junk)]);
    lend_ifsc_entries(&mut index, fid(0), fid(1));
    std::fs::write(dir.join("d.bin"), &junk).unwrap();
    std::fs::write(dir.join("set.par2"), index).unwrap();
    match repair_dir(&dir).expect("a refused source is a verdict, not an error") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!((needed, have), (2, 0), "this set carries no recovery data");
        }
        other => panic!(
            "expected Unrepairable - a harvest that trusted the lying IFSC \
             would write junk and die at the final whole-file proof, got {other:?}"
        ),
    }
    assert!(
        !dir.join("c.bin").exists(),
        "a refused harvest must leave no half-written target behind"
    );
    assert_eq!(
        std::fs::read(dir.join("d.bin")).unwrap(),
        junk,
        "the source is untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The bound on the harvest, and the reason it is not optional (W4-14,
/// 30 Aug 2026): a target that is not on disk AND is byte-identical to
/// one that is, is a DUPLICATE DESCRIPTOR asking to be materialized -
/// a copy decision `land_duplicate_filedescs` already makes under
/// `DUPLICATE_FANOUT_CAP`, because a kilobyte of packet naming
/// hundreds of aliases for one posted payload is otherwise hundreds of
/// full-file reads and writes bounded by nothing. Harvesting them here
/// would be a second, uncapped door onto the same amplification.
/// Measured: without the decline,
/// `e2e_norar::a_dedupe_fanout_past_the_cap_refuses_the_remainder`
/// materializes all 200.
#[test]
fn the_in_set_harvest_declines_to_materialize_a_duplicate_descriptor() {
    let dir = tmpdir("insetclone");
    let d = payload(BS * 3, 44);
    let files: &[(&str, &[u8])] = &[("a.bin", &d), ("b.bin", &d)];
    std::fs::write(dir.join("a.bin"), &d).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    match repair_dir(&dir).expect("a declined clone is a verdict, not an error") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!((needed, have), (3, 0), "this set carries no recovery data");
        }
        other => panic!(
            "expected Unrepairable - materializing an alias is the capped \
             caller's decision, never the repair's, got {other:?}"
        ),
    }
    assert!(
        !dir.join("b.bin").exists(),
        "the repair materialized a byte-identical alias of a landed file"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rewrite `to`'s IFSC entries with `from`'s, so one file's descriptor
/// claims another's block checksums, and reseal both packets' MD5s
/// (offset 16 covers setid+type+body - the spec header in par2.rs).
/// The stored file id is left alone: readers key Main/FileDesc/IFSC by
/// the STORED id and never recompute it.
fn lend_ifsc_entries(data: &mut [u8], from: [u8; 16], to: [u8; 16]) {
    let mut ifsc: Vec<(usize, usize)> = Vec::new();
    let mut off = 0usize;
    while off + 64 <= data.len() {
        let len = u64::from_le_bytes(data[off + 8..off + 16].try_into().unwrap()) as usize;
        assert!(
            len >= 64 && off + len <= data.len(),
            "malformed test packet"
        );
        if &data[off + 48..off + 64] == par2::TYPE_IFSC {
            ifsc.push((off, len));
        }
        off += len;
    }
    let body = |d: &[u8], (s, l): (usize, usize)| d[s + 64..s + l].to_vec();
    let find = |fid: [u8; 16]| {
        *ifsc
            .iter()
            .find(|&&(s, _)| data[s + 64..s + 80] == fid)
            .expect("no IFSC packet for that file id")
    };
    let (src, dst) = (find(from), find(to));
    let entries = body(data, src)[16..].to_vec();
    assert_eq!(
        entries.len(),
        body(data, dst).len() - 16,
        "block counts differ"
    );
    let (ds, _) = dst;
    data[ds + 80..ds + 80 + entries.len()].copy_from_slice(&entries);
    let sum: [u8; 16] = Md5::digest(&data[ds + 32..ds + dst.1]).into();
    data[ds + 16..ds + 32].copy_from_slice(&sum);
}

#[test]
fn a_sniffed_extensionless_volume_serves_its_slices() {
    let dir = tmpdir("sniff");
    let d = payload(200, 8);
    let files: &[(&str, &[u8])] = &[("d.bin", &d)];
    let mut damaged = d.clone();
    for x in &mut damaged[128..192] {
        *x ^= 0x0f; // slice 2 bad
    }
    std::fs::write(dir.join("d.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // The recovery volume ships under a junk name with no extension -
    // only the packet-magic sniff can find it.
    std::fs::write(dir.join("qq"), par2_volume(SET, BS, files, &[0])).unwrap();
    assert_eq!(
        sniffed_packet_files(&dir).expect("sniff walks"),
        [dir.join("qq")],
        "the extensionless volume is the one sniff-only packet file"
    );
    match repair_dir(&dir).expect("sniffed slices repair") {
        RepairStatus::Repaired(r) => assert_eq!(r.blocks_rebuilt, 1),
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("d.bin")).unwrap(), d);
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn recovery_slice_locators_report_only_the_wanted_set() {
    let files_data = payload(200, 9);
    let files: &[(&str, &[u8])] = &[("e.bin", &files_data)];
    let vol = par2_volume(SET, BS, files, &[0, 5]);
    let locs = recovery_slice_locators(&vol, &SET);
    assert_eq!(locs.len(), 2);
    assert_eq!(locs[0].0, 0);
    assert_eq!(locs[1].0, 5);
    for &(_, off, len) in &locs {
        assert_eq!(len, BS, "slice data length is the block size");
        assert!(off + len <= vol.len());
    }
    // A foreign set id sees nothing.
    assert!(recovery_slice_locators(&vol, &[1u8; 16]).is_empty());
    // Slice data at the reported offset is the slice the generator made.
    let slices = global_slices(files, BS);
    let want = generate_recovery(&slices, BS, 0);
    assert_eq!(&vol[locs[0].1..locs[0].1 + locs[0].2], &want[..]);
}

#[test]
fn the_slice_census_answers_every_set_in_one_pass() {
    let files_data = payload(200, 9);
    let files: &[(&str, &[u8])] = &[("e.bin", &files_data)];
    let mut vol = par2_volume(SET, BS, files, &[0, 5]);
    // A SECOND set's volume in the same buffer - which is exactly the
    // shape a census walks past on a per-file-set post's job dir.
    let other = [3u8; 16];
    vol.extend_from_slice(&par2_volume(other, BS, files, &[7]));

    let census = recovery_slice_census(&vol);
    // Grouped by (set, slice length): both sets present, each with its
    // own count, off ONE pass. Calling the singular once per adopted set
    // is what this replaces - it reads the same bytes N times to answer
    // 0 for every set but the one that owns the volume.
    let mut got: Vec<([u8; 16], usize, usize)> = census.clone();
    got.sort_unstable();
    let mut want = vec![(SET, BS, 2), (other, BS, 1)];
    want.sort_unstable();
    assert_eq!(got, want);

    // And it agrees with the singular, set for set - the property that
    // lets a caller swap one for the other.
    for (id, _, n) in &census {
        assert_eq!(
            recovery_slice_locators(&vol, id)
                .into_iter()
                .filter(|(_, _, l)| *l == BS)
                .count(),
            *n
        );
    }
    // A set with nothing here is absent rather than zero-counted, which
    // is what lets a caller read "0 slices" off a miss.
    assert!(!census.iter().any(|(id, _, _)| *id == [1u8; 16]));
}

// --- §129: block-parallel hashing --------------------------------------
//
// Every payload below is non-repeating (the xorshift `payload`) - a
// periodic payload lets a sliding-window scanner "find" a block at the
// wrong offset and would mask an indexing bug in the pool.

/// The Par2File that parsing a real index would yield for `data`:
/// whole-file MD5 plus per-block IFSC MD5+CRC over zero-padded blocks.
fn meta_for(name: &str, data: &[u8], bs: usize) -> Par2File {
    let blocks = data
        .chunks(bs)
        .map(|c| {
            let mut padded = c.to_vec();
            padded.resize(bs, 0);
            BlockCheck {
                md5: Md5::digest(&padded).into(),
                crc32: crc32fast::hash(&padded),
            }
        })
        .collect();
    Par2File {
        file_id: fid(0),
        name: name.into(),
        length: data.len() as u64,
        md5: Md5::digest(data).into(),
        md5_16k: Md5::digest(&data[..data.len().min(16384)]).into(),
        blocks,
    }
}

/// The worker pool must reproduce the serial scanner's PRESENCE bitmap
/// exactly across damage shapes: pristine, mid-file damage, damaged
/// tail, trailing junk (still clean), truncation. Small file, so this
/// drives `hash_blocks_par` directly - the size gate is exercised
/// separately. Presence is all the pool decides; the clean verdict is
/// the FileDesc MD5's alone (H7).
#[test]
fn block_hash_pool_matches_serial_scanner_presence() {
    let dir = tmpdir("hashpool");
    let pristine = payload(BS * 37 + 9, 21);
    let meta = meta_for("h.bin", &pristine, BS);
    let mut damaged = pristine.clone();
    for x in &mut damaged[BS * 5..BS * 6] {
        *x ^= 0x5a;
    }
    for x in &mut damaged[BS * 37..] {
        *x ^= 0x11; // the 9-byte tail block too
    }
    let mut junk = pristine.clone();
    junk.extend_from_slice(&payload(31, 22));
    let truncated = &pristine[..BS * 12 + 7];
    let cases: [(&str, &[u8]); 4] = [
        ("pristine", &pristine),
        ("damaged", &damaged),
        ("junk", &junk),
        ("trunc", truncated),
    ];
    for (tag, bytes) in cases {
        let p = dir.join(tag);
        std::fs::write(&p, bytes).unwrap();
        // threads=1 never takes the pool path: serial ground truth.
        let serial = verify_pass1(&p, &meta, BS, 1).unwrap();
        let f = File::open(&p).unwrap();
        let disk_len = bytes.len() as u64;
        let limit = meta.length.min(disk_len);
        let crc_ok = hash_blocks_par(&p, &f, limit, meta.length, &meta.blocks, BS, 4).unwrap();
        match serial.present {
            None => {
                assert!(serial.clean, "{tag}: only a clean file drops the bitmap");
                assert!(crc_ok.iter().all(|&b| b), "{tag}: clean means every block");
            }
            Some(want) => assert_eq!(crc_ok, want, "{tag}: presence bitmap"),
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn block_hash_pool_counts_the_caller_in_its_worker_budget() {
    assert_eq!(hash_range_geometry(0, 8), (0, 0));
    assert_eq!(hash_range_geometry(8, 0), (0, 0));
    for blocks in 1..=257usize {
        for workers in 1..=128usize {
            let (per, ranges) = hash_range_geometry(blocks, workers);
            assert!(per > 0);
            assert_eq!(ranges, blocks.div_ceil(per));
            assert!(ranges <= workers.min(blocks));
            assert_eq!(
                ranges.saturating_sub(1),
                blocks.saturating_sub(per).div_ceil(per)
            );
        }
    }

    for machine in 1..=128usize {
        for outer in 1..=machine {
            let inner = machine / outer;
            let (_, ranges) = hash_range_geometry(4096, inner);
            let peak_nested_threads = outer + outer * (ranges - 1);
            assert!(peak_nested_threads <= machine);
        }
    }

    assert_eq!(bounded_hash_workers(usize::MAX, 0, 4096), 0);
    assert_eq!(bounded_hash_workers(usize::MAX, 1, 4096), 1);
    assert_eq!(bounded_hash_workers(0, 1, 4096), 1);
    let one_proved_at_end = 1 << 20;
    let workers = bounded_hash_workers(usize::MAX, 1, 4096);
    assert_eq!(hash_range_geometry(one_proved_at_end, workers).1, 1);
    assert_eq!(
        bounded_hash_workers(usize::MAX, usize::MAX, 1),
        HASH_POOL_BYTES
    );
    assert_eq!(
        bounded_hash_workers(usize::MAX, usize::MAX, HASH_CHUNK),
        HASH_POOL_BYTES / HASH_CHUNK
    );
}

#[test]
fn block_hash_pool_sizes_coalescing_only_for_proved_runs() {
    const SMALL: usize = 4096;
    let proved = BlockCheck {
        md5: [1u8; 16],
        crc32: 7,
    };
    assert_eq!(
        hash_positioned_buffer_len(&[proved; 200], SMALL),
        HASH_POSITIONED_WINDOW
    );

    let mut isolated = [BlockCheck::UNPROVEN; 31];
    for check in isolated.iter_mut().step_by(2) {
        *check = proved;
    }
    assert_eq!(hash_positioned_buffer_len(&isolated, SMALL), SMALL);

    let mut three = [BlockCheck::UNPROVEN; 9];
    three[3..6].fill(proved);
    assert_eq!(hash_positioned_buffer_len(&three, SMALL), 3 * SMALL);
    assert_eq!(
        hash_positioned_buffer_len(&[proved], HASH_POSITIONED_WINDOW),
        HASH_POSITIONED_WINDOW
    );
    assert_eq!(
        hash_positioned_buffer_len(&[proved], 2 * HASH_CHUNK),
        HASH_CHUNK
    );

    let hostile_gap = [proved, proved, BlockCheck::UNPROVEN, proved, proved];
    assert_eq!(hash_proven_run_len(&hostile_gap, hostile_gap.len()), 2);
    assert_eq!(hash_proven_run_len(&hostile_gap[2..], 3), 0);
    assert_eq!(hash_proven_run_len(&hostile_gap[3..], 1), 1);

    // Clamp while the quotient is still u64: narrowing this first would wrap
    // on 32-bit targets and could turn a valid run into zero progress.
    let over_u32_blocks = u64::from(u32::MAX) + 17;
    assert_eq!(
        hash_full_run_limit(8, over_u32_blocks * 4096, over_u32_blocks * 4096, 4096),
        8
    );
    assert_eq!(hash_full_run_limit(8, 3 * 4096, 9 * 4096, 4096), 3);
}

#[test]
fn block_hash_pool_coalescing_preserves_gaps_and_padded_tail() {
    const BLOCK: usize = 64 << 10;
    let dir = tmpdir("hash-coalesced-gaps");
    let path = dir.join("gapped.bin");
    let data = payload(BLOCK * 10 + 137, 118);
    std::fs::write(&path, &data).unwrap();
    let mut meta = meta_for("gapped.bin", &data, BLOCK);
    meta.blocks[2] = BlockCheck::UNPROVEN;
    meta.blocks[6] = BlockCheck::UNPROVEN;
    meta.blocks[8].crc32 ^= 1;

    let source = File::open(&path).unwrap();
    let got = hash_blocks_par(
        &path,
        &source,
        data.len() as u64,
        data.len() as u64,
        &meta.blocks,
        BLOCK,
        4,
    )
    .unwrap();
    let mut want = vec![true; 11];
    want[2] = false;
    want[6] = false;
    want[8] = false;
    assert_eq!(got, want);
    let _ = std::fs::remove_dir_all(dir);
}

#[test]
fn block_hash_pool_does_not_read_an_unproven_suffix() {
    const BLOCK: usize = 64 << 10;
    let dir = tmpdir("hash-unproven-suffix");
    let path = dir.join("short.bin");
    let data = payload(BLOCK, 88);
    std::fs::write(&path, &data).unwrap();
    let source = File::open(&path).unwrap();
    let checks = [
        BlockCheck {
            md5: Md5::digest(&data).into(),
            crc32: crc32fast::hash(&data),
        },
        BlockCheck::UNPROVEN,
        BlockCheck::UNPROVEN,
    ];

    // `limit` deliberately claims three readable blocks while the backing
    // file contains one. Reading either fixed-false suffix entry would make
    // this return UnexpectedEof.
    let got = hash_blocks_par(
        &path,
        &source,
        (3 * BLOCK) as u64,
        (3 * BLOCK) as u64,
        &checks,
        BLOCK,
        usize::MAX,
    )
    .unwrap();
    assert_eq!(got, [true, false, false]);
    let _ = std::fs::remove_dir_all(dir);
}

/// The reserved all-zero IFSC MD5 makes a cell unprovable even when its CRC32
/// happens to equal the bytes on disk. The serial pass may omit that CRC walk,
/// but it must still freeze the resume boundary there and restart cleanly for
/// a later proved cell.
#[test]
fn serial_pass_keeps_unproven_crc_cells_false_without_losing_later_blocks() {
    let dir = tmpdir("serial-unproven-crc");
    let bs = RESUME_MIN_BLOCK;
    let data = payload(bs * 4 + 17, 23);
    let mut meta = meta_for("u.bin", &data, bs);
    let matching_crc = meta.blocks[1].crc32;
    meta.blocks[1] = BlockCheck {
        md5: BlockCheck::UNPROVEN.md5,
        crc32: matching_crc,
    };
    let path = dir.join("u.bin");
    std::fs::write(&path, &data).unwrap();

    let out = verify_pass1(&path, &meta, bs, 1).unwrap();
    assert_eq!(
        out.present,
        Some(vec![true, false, true, true, true]),
        "the placeholder stays false and the next proved block starts fresh"
    );
    assert!(out.md5_unfinished, "the unprovable cell stops the live MD5");
    assert_eq!(
        out.resume
            .as_ref()
            .expect("failure leaves a snapshot")
            .offset,
        bs as u64,
        "the post-patch proof resumes at the placeholder's boundary"
    );
    let _ = std::fs::remove_dir_all(dir);
}

/// Above HASH_PAR_MIN_BYTES a truncated target routes `verify_pass1`
/// through the pool; the verdict must agree with the serial pass on
/// pristine, damaged and truncated shapes alike.
#[test]
fn parallel_gate_agrees_with_serial_above_threshold() {
    let dir = tmpdir("hashgate");
    let bs = 4096usize;
    let len = (HASH_PAR_MIN_BYTES as usize) + bs * 3 + 137; // odd tail
    let pristine = payload(len, 31);
    let meta = meta_for("big.bin", &pristine, bs);
    let mut damaged = pristine.clone();
    for w in 0..3usize {
        let at = w * len / 3 + w * 17;
        for x in &mut damaged[at..at + 64] {
            *x ^= 0xa5;
        }
    }
    let truncated = &pristine[..len - bs - 5];
    let cases: [(&str, &[u8]); 3] = [
        ("pristine", &pristine),
        ("damaged", &damaged),
        ("trunc", truncated),
    ];
    for (tag, bytes) in cases {
        let p = dir.join(tag);
        std::fs::write(&p, bytes).unwrap();
        let serial = verify_pass1(&p, &meta, bs, 1).unwrap();
        let par = verify_pass1(&p, &meta, bs, 8).unwrap();
        assert_eq!(par.exists, serial.exists, "{tag}: exists");
        assert_eq!(par.intact, serial.intact, "{tag}: intact");
        assert_eq!(par.clean, serial.clean, "{tag}: clean");
        assert_eq!(par.present, serial.present, "{tag}: presence bitmap");
        assert_eq!(
            md5_matches(&p, &meta).unwrap(),
            serial.intact,
            "{tag}: md5_matches verdict"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// H7 (08-08 sweep, closed 10 Aug): a PAR2 whose FileDesc and IFSC
/// describe DIFFERENT bytes under one file id. Both packets are
/// well-formed and the entry count agrees with the declared length, so
/// every structural gate in par2.rs passes them; only hashing the data
/// can tell them apart. Bytes B are on disk, so the IFSC is satisfied
/// and the FileDesc whole-file MD5 is not.
///
/// The two verify paths must not disagree about that. Before the fix
/// the pool branch answered "every padded block MD5 matched" and called
/// the file clean, while the serial branch computed the FileDesc MD5
/// and called it damaged - one verdict per file size and per core
/// count, from identical metadata.
#[test]
fn ifsc_contradicting_the_filedesc_md5_is_rejected_by_both_paths() {
    let dir = tmpdir("h7split");
    let bs = 4096usize;
    let len = (HASH_PAR_MIN_BYTES as usize) + bs * 2 + 77;
    let a = payload(len, 61);
    let b = payload(len, 62); // same length: the count gate cannot see it
    let desc_a = meta_for("split.bin", &a, bs);
    let ifsc_b = meta_for("split.bin", &b, bs);
    let meta = Par2File {
        blocks: ifsc_b.blocks,
        ..desc_a
    };
    let p = dir.join("split.bin");
    std::fs::write(&p, &b).unwrap();

    let serial = verify_pass1(&p, &meta, bs, 1).unwrap();
    let par = verify_pass1(&p, &meta, bs, 8).unwrap();
    assert!(
        !serial.clean,
        "the bytes on disk do not carry the FileDesc MD5"
    );
    assert_eq!(par.clean, serial.clean, "clean verdict");
    assert_eq!(par.intact, serial.intact, "intact verdict");
    assert!(
        !md5_matches(&p, &meta).unwrap(),
        "a repair may not report success on bytes the FileDesc MD5 denies"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// H7's MIRROR, which had no coverage until `7f195ff27` (2 Sep 2026)
/// made it reachable: the same two-claims-in-one-set shape, but with
/// the bytes on disk satisfying the FileDesc whole-file MD5 and the
/// IFSC list describing the OTHER payload.
///
/// `verify_pass1`'s early stop drops the whole-file digest at the first
/// block the IFSC denies, so `clean`/`intact` come back false for a
/// file that hashes byte-exact. That is deliberate and it is why
/// `md5_unfinished` exists: under it those two are IFSC verdicts, "not
/// proven" rather than "disproven", and `repair_dir_set_inner`'s
/// arbitration finishes the digest before a shortfall can turn on it.
/// The contract this pins is the shape of that tri-state - the flag
/// only ever WITHHOLDS a positive, it always leaves a snapshot the
/// proof can be finished from, and finishing it recovers the truth.
/// Found by `par2_verify_diff` (fuzz-smoke run 33678333481) reading the
/// withheld verdict as a decided one; the target now exempts it.
#[test]
fn filedesc_md5_over_bytes_the_ifsc_denies_is_unproven_not_damaged() {
    let dir = tmpdir("h7mirror");
    // The early stop only arms at or above RESUME_MIN_BLOCK - below it
    // no snapshot is taken and the digest runs to the end, so a smaller
    // block size would pass this test without exercising anything.
    let bs = RESUME_MIN_BLOCK;
    let len = bs * 2 + 77;
    let a = payload(len, 71);
    let b = payload(len, 72); // same length: the count gate cannot see it
    let desc_b = meta_for("mirror.bin", &b, bs);
    let ifsc_a = meta_for("mirror.bin", &a, bs);
    let meta = Par2File {
        blocks: ifsc_a.blocks,
        ..desc_b
    };
    let p = dir.join("mirror.bin");
    std::fs::write(&p, &b).unwrap();

    let serial = verify_pass1(&p, &meta, bs, 1).unwrap();
    assert!(
        serial.md5_unfinished,
        "the first denied block must stop the digest"
    );
    assert!(
        !serial.clean && !serial.intact,
        "an unfinished digest may only withhold a positive verdict"
    );
    assert_eq!(
        serial.present,
        Some(vec![false; len.div_ceil(bs)]),
        "the IFSC denies every block of the other payload"
    );
    // The bytes ARE the file the FileDesc describes, and both routes
    // back to that fact - the full reread the arbitration takes and the
    // resumed proof the patch takes - must say so.
    assert!(
        md5_matches(&p, &meta).unwrap(),
        "the bytes on disk carry the FileDesc MD5"
    );
    let resume = serial
        .resume
        .as_ref()
        .expect("an unfinished digest always leaves a snapshot");
    assert!(
        md5_matches_resumed(&p, &meta, resume).unwrap(),
        "resuming from the snapshot must reach the same digest"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The IFSC placeholder rule, at the level `verify_pass1` decides it -
/// the gap a 30.7M-execution `par2_verify_diff` campaign found on
/// 2 Sep 2026 (`46bd58e51`). An all-zero MD5 is `BlockCheck::UNPROVEN`,
/// the cell a SHORT IFSC packet is padded out with, and it vouches for
/// no bytes at all; the CRC32 beside it is not the guard, because every
/// u32 is somebody's CRC32. `crc_matches` is what refuses it and every
/// CRC-only site in the tree goes through that rather than the field -
/// `a_crafted_zero_crc_does_not_verify_an_unproven_slice` pins the rule
/// on the type, and `fit_ifsc` pins where the placeholders come from.
///
/// What had no coverage was the pass-1 SCAN enforcing it, over either
/// of the two places it decides a slice: the whole-block path and the
/// ZERO-PADDED TAIL, which is the one the fuzzer landed on. The entry
/// below is the shape a hostile wire IFSC can spell and libFuzzer
/// reached by solving the comparison with its CMP instrumentation - an
/// all-zero MD5 beside the slice's EXACT CRC32, so a comparison against
/// the field alone answers present and only the MD5 guard refuses.
#[test]
fn a_zero_md5_ifsc_entry_never_reads_as_present_even_with_the_right_crc() {
    let dir = tmpdir("unprovenslice");
    let bs = 4096usize;
    // Three slices, the last one partial - so this covers the padded
    // tail as well as a whole block.
    let data = payload(bs * 2 + 1895, 91);
    let p = dir.join("unproven.bin");
    std::fs::write(&p, &data).unwrap();

    let honest = meta_for("unproven.bin", &data, bs);
    assert!(
        verify_pass1(&p, &honest, bs, 1).unwrap().clean,
        "the file is byte-exact for its FileDesc"
    );

    // The bitmap is dropped for a file the FileDesc MD5 proves clean, so
    // deny that claim to keep it - the IFSC list stays honest.
    let mut ifsc_only = honest.clone();
    ifsc_only.md5 = [0xab; 16];
    assert_eq!(
        verify_pass1(&p, &ifsc_only, bs, 1).unwrap().present,
        Some(vec![true; 3]),
        "control arm: the honest IFSC proves every slice, tail included"
    );

    // Now zero the MD5 on a whole block and on the tail, keeping each
    // CRC32 field exactly right.
    let mut crafted = ifsc_only.clone();
    for i in [1usize, 2] {
        crafted.blocks[i].md5 = [0u8; 16];
        assert_eq!(
            crafted.blocks[i].crc32, ifsc_only.blocks[i].crc32,
            "the crafted entry keeps the slice's real CRC32 - that is the point"
        );
    }
    assert_eq!(
        verify_pass1(&p, &crafted, bs, 1).unwrap().present,
        Some(vec![true, false, false]),
        "an all-zero MD5 vouches for nothing, whatever its CRC32 says"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Why recomputing the spec's file id at parse time does NOT close H7,
/// recorded so it stops being re-proposed. The id is
/// `MD5(hash16k ‖ length ‖ name)` - it binds the descriptor's IDENTITY
/// triple and says nothing about the whole-file MD5 beside it, nor
/// about which IFSC list travels under that id. A poster who picks the
/// triple first can compute the matching id and still ship a FileDesc
/// MD5 for A with an IFSC for B, exactly the fixture above. Recomputing
/// is worth doing for garbled descriptors; it is not the H7 fix, which
/// has to be a verdict rule (see `md5_matches`).
#[test]
fn spec_file_id_does_not_bind_the_ifsc_to_the_filedesc() {
    let bs = 4096usize;
    let a = payload(bs * 3 + 11, 71);
    let b = payload(a.len(), 72);
    let name = "split.bin";
    let md5_16k: [u8; 16] = Md5::digest(&a[..a.len().min(16384)]).into();

    // The PAR2 2.0 file id, computed exactly as the spec defines it.
    let mut idsrc = md5_16k.to_vec();
    idsrc.extend_from_slice(&(a.len() as u64).to_le_bytes());
    idsrc.extend_from_slice(name.as_bytes());
    let file_id: [u8; 16] = Md5::digest(&idsrc).into();

    let mut main = Vec::new();
    main.extend_from_slice(&(bs as u64).to_le_bytes());
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&file_id);

    let mut desc = Vec::new();
    desc.extend_from_slice(&file_id);
    desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&a))); // A's whole-file MD5
    desc.extend_from_slice(&md5_16k);
    desc.extend_from_slice(&(a.len() as u64).to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    while !nb.len().is_multiple_of(4) {
        nb.push(0);
    }
    desc.extend_from_slice(&nb);

    let mut ifsc = file_id.to_vec(); // B's blocks, under A's id
    for chunk in b.chunks(bs) {
        let mut padded = chunk.to_vec();
        padded.resize(bs, 0);
        ifsc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
        ifsc.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
    }

    let mut buf = pkt(SET, par2::TYPE_MAIN, &main);
    buf.extend(pkt(SET, par2::TYPE_FILEDESC, &desc));
    buf.extend(pkt(SET, par2::TYPE_IFSC, &ifsc));

    let set = par2::Par2Set::parse(&[&buf]).expect("well-formed packets");
    let f = &set.files[0];
    assert_eq!(f.file_id, file_id, "the id is the spec's own value");
    assert_eq!(f.md5, <[u8; 16]>::from(Md5::digest(&a)));
    assert_eq!(
        f.blocks[0].md5,
        <[u8; 16]>::from(Md5::digest(&{
            let mut p = b[..bs].to_vec();
            p.resize(bs, 0);
            p
        })),
        "a spec-correct file id still carries the other file's blocks"
    );
}

/// End to end above the gate: a big damaged file goes through the
/// pool-hashed verify, the rebuild, and the pool-hashed post-patch
/// proof, and the bytes land identical to the pristine payload.
#[test]
fn big_damaged_file_repairs_identically_through_the_pool() {
    let dir = tmpdir("bigrepair");
    let bs = 4096usize;
    let len = (HASH_PAR_MIN_BYTES as usize) + 5 * bs + 999;
    let big = payload(len, 41);
    let files: &[(&str, &[u8])] = &[("big.bin", &big)];
    let mut damaged = big.clone();
    for w in 0..3usize {
        let at = (w * 7 + 2) * bs + w; // three distinct blocks
        for x in &mut damaged[at..at + 96] {
            *x ^= 0x3c;
        }
    }
    std::fs::write(dir.join("big.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, bs, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume(SET, bs, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    match repair_dir(&dir).expect("big set repairs") {
        RepairStatus::Repaired(r) => assert_eq!(r.blocks_rebuilt, 3),
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("big.bin")).unwrap(), big);
    match repair_dir(&dir).expect("repaired set re-verifies") {
        RepairStatus::NoDamage => {}
        other => panic!("expected NoDamage after repair, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The mapped driver's self-prove on a big rebuilt file (full IFSC,
/// above the pool gate): the repair must succeed, the bytes must land
/// identical, and a write that corrupts a byte OUTSIDE the rebuilt
/// blocks must still fail the prove - the FileDesc MD5 covers every
/// byte, not just the patched ones.
#[test]
fn mapped_self_prove_covers_bytes_outside_the_rebuilt_blocks() {
    let bs = 4096usize;
    let len = (HASH_PAR_MIN_BYTES as usize) + 3 * bs + 501;
    let big = payload(len, 51);
    let meta = meta_for("big.bin", &big, bs);
    let n = meta.length.div_ceil(bs as u64) as usize;
    let gfiles: &[(&str, &[u8])] = &[("big.bin", &big)];
    let slices = global_slices(gfiles, bs);
    let recovery: Vec<(u32, Vec<u8>)> = (0..3u32)
        .map(|e| (e, generate_recovery(&slices, bs, e)))
        .collect();
    struct BufIo(
        std::sync::Mutex<Vec<u8>>,
        Option<usize>,
        std::sync::atomic::AtomicBool,
    );
    impl VolumeIo for BufIo {
        fn read(&self, _f: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            let d = self.0.lock().unwrap();
            let off = off as usize;
            buf.copy_from_slice(&d[off..off + buf.len()]);
            Ok(())
        }
        fn write(&self, _f: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
            let mut d = self.0.lock().unwrap();
            let off = off as usize;
            d[off..off + data.len()].copy_from_slice(data);
            if let Some(rot) = self.1
                && !self.2.swap(true, std::sync::atomic::Ordering::Relaxed)
            {
                d[rot] ^= 0xff; // one silent corruption far from the patch
            }
            Ok(())
        }
    }
    for (rot, want_ok) in [(None, true), (Some(7 * bs + 11), false)] {
        let mut present = vec![true; n];
        let mut damaged = big.clone();
        for blk in [1usize, 3] {
            present[blk] = false;
            for x in &mut damaged[blk * bs..(blk + 1) * bs] {
                *x = 0;
            }
        }
        let io = BufIo(
            std::sync::Mutex::new(damaged),
            rot,
            std::sync::atomic::AtomicBool::new(false),
        );
        let files = vec![(meta.clone(), present)];
        let res = repair_mapped(&files, bs, &recovery, &io, true);
        if want_ok {
            assert_eq!(res.expect("mapped repair proves itself"), 2);
            assert_eq!(io.0.into_inner().unwrap(), big, "bytes identical");
        } else {
            assert!(
                matches!(res, Err(RepairError::VerifyFailed(_))),
                "corruption outside the rebuilt blocks must fail the prove, got {res:?}"
            );
        }
    }
}

/// The resumed self-prove (TODO 133.1) against the full one, across
/// every damage position that moves the snapshot boundary: block 0
/// (resume covers the whole file - degenerate, nothing saved), a
/// middle block, the last full block, the padded tail, a mid-block
/// truncation, a truncation exactly on a block boundary, and no damage
/// at all with trailing junk (the `needs_resize` shape, where the
/// resume boundary is EOF and the proof costs no reread). For each:
/// the snapshot lands on the first unproven block's start, and after
/// an in-place "patch" that restores the pristine bytes the resumed
/// verdict equals the full `md5_matches` one. A wrong patch must fail
/// both.
#[test]
fn resumed_self_prove_matches_full_across_damage_positions() {
    let dir = tmpdir("resume-positions");
    let bs = RESUME_MIN_BLOCK; // smallest snapshotting block size
    let len = bs * 6 + bs / 3; // 7 blocks, padded tail
    let pristine = payload(len, 97);
    let meta = meta_for("big.bin", &pristine, bs);
    let p = dir.join("big.bin");

    // (tag, damage) -> expected resume boundary (first unproven block).
    let cases: Vec<(&str, Box<dyn Fn(&mut Vec<u8>)>, u64)> = vec![
        ("block0", Box::new(move |d: &mut Vec<u8>| d[5] ^= 0x5a), 0),
        (
            "middle",
            Box::new(move |d: &mut Vec<u8>| d[3 * bs + 100] ^= 0x5a),
            3 * bs as u64,
        ),
        (
            "last-full",
            Box::new(move |d: &mut Vec<u8>| d[5 * bs + 1] ^= 0x5a),
            5 * bs as u64,
        ),
        (
            "tail",
            Box::new(move |d: &mut Vec<u8>| {
                let n = d.len();
                d[n - 1] ^= 0x5a;
            }),
            6 * bs as u64,
        ),
        (
            "trunc-mid-block",
            Box::new(move |d: &mut Vec<u8>| d.truncate(4 * bs + 7)),
            4 * bs as u64,
        ),
        (
            "trunc-on-boundary",
            Box::new(move |d: &mut Vec<u8>| d.truncate(4 * bs)),
            4 * bs as u64,
        ),
        (
            "trailing-junk",
            Box::new(move |d: &mut Vec<u8>| d.extend_from_slice(&[7u8; 123])),
            len as u64,
        ),
    ];
    for (tag, damage, want_off) in cases {
        let mut damaged = pristine.clone();
        damage(&mut damaged);
        std::fs::write(&p, &damaged).unwrap();
        let out = verify_pass1(&p, &meta, bs, 1).unwrap();
        let res = out
            .resume
            .as_ref()
            .unwrap_or_else(|| panic!("{tag}: serial verify must carry a resume snapshot"));
        assert_eq!(res.offset, want_off, "{tag}: resume boundary");
        // The in-place patch: what write_blocks does - size the file,
        // then rewrite everything from the boundary on with the
        // pristine bytes (a real patch only writes the unproven
        // blocks; rewriting the whole suffix is a superset with the
        // same prefix-untouched property).
        let mut fixed = damaged.clone();
        fixed.resize(len, 0);
        fixed[want_off as usize..].copy_from_slice(&pristine[want_off as usize..]);
        std::fs::write(&p, &fixed).unwrap();
        assert!(
            md5_matches_resumed(&p, &meta, res).unwrap(),
            "{tag}: resumed prove on a correct patch"
        );
        assert!(md5_matches(&p, &meta).unwrap(), "{tag}: full prove agrees");
        // And a WRONG patch fails the resumed prove exactly like the
        // full one - flip one byte at the boundary. Only meaningful
        // when a patch can write at all: with the boundary at EOF
        // (trailing-junk) there is no patched byte to get wrong, and
        // bytes BEFORE the boundary are the verified prefix the
        // resumed prove deliberately does not reread.
        if (want_off as usize) < len {
            let bad_at = want_off as usize;
            let mut wrong = fixed.clone();
            wrong[bad_at] ^= 0xff;
            std::fs::write(&p, &wrong).unwrap();
            assert!(
                !md5_matches_resumed(&p, &meta, res).unwrap(),
                "{tag}: resumed prove must reject a wrong patch"
            );
            assert!(
                !md5_matches(&p, &meta).unwrap(),
                "{tag}: full prove agrees on wrong"
            );
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// The gates around the snapshot: a block size under RESUME_MIN_BLOCK
/// must not snapshot (the per-block clone would dominate tiny blocks),
/// the pool branch never snapshots (it has no MD5 state to save), and
/// a set with no IFSC packets cannot place a boundary at all.
#[test]
fn resume_snapshot_gates() {
    let dir = tmpdir("resume-gates");
    let pristine = payload(HASH_PAR_MIN_BYTES as usize + 4096 * 3 + 17, 98);
    let p = dir.join("t.bin");

    // Small blocks: no snapshot, damaged or not.
    let meta_small = meta_for("t.bin", &pristine, 4096);
    let mut damaged = pristine.clone();
    damaged[9000] ^= 1;
    std::fs::write(&p, &damaged).unwrap();
    let out = verify_pass1(&p, &meta_small, 4096, 1).unwrap();
    assert!(!out.clean);
    assert!(out.resume.is_none(), "4 KiB blocks must not snapshot");

    // Pool branch (short file, threads > 1): no snapshot.
    let meta_big = meta_for("t.bin", &pristine, RESUME_MIN_BLOCK);
    std::fs::write(&p, &pristine[..pristine.len() - 4096]).unwrap();
    let out = verify_pass1(&p, &meta_big, RESUME_MIN_BLOCK, 8).unwrap();
    assert!(out.present.is_some());
    assert!(out.resume.is_none(), "the pool branch has no MD5 to resume");

    // No IFSC list: nothing to place a boundary with.
    let mut meta_no_ifsc = meta_big.clone();
    meta_no_ifsc.blocks = Vec::new();
    std::fs::write(&p, &damaged).unwrap();
    let out = verify_pass1(&p, &meta_no_ifsc, RESUME_MIN_BLOCK, 1).unwrap();
    assert!(out.resume.is_none(), "no IFSC means no resume boundary");
    let _ = std::fs::remove_dir_all(&dir);
}

/// End to end through `repair_dir`: a damaged big-block member repairs
/// from real recovery slices and self-proves through the resumed path
/// (in place), and the repaired bytes are byte-identical to pristine.
/// The temp-file arm (a wholly missing member) still proves through
/// the full reread and lands correct bytes too.
#[test]
fn repair_dir_resumed_prove_lands_identical_bytes() {
    let dir = tmpdir("resume-e2e");
    let bs = RESUME_MIN_BLOCK;
    let set_id = [9u8; 16];
    let a = payload(bs * 4 + 1000, 61); // in-place arm
    let b = payload(bs * 2 + 17, 62); // missing-member arm (temp path)
    let files: Vec<(&str, &[u8])> = vec![("a.bin", &a), ("b.bin", &b)];
    std::fs::write(dir.join("set.par2"), par2_index(set_id, bs, &files)).unwrap();
    std::fs::write(
        dir.join("set.vol0.par2"),
        par2_volume(set_id, bs, &files, &[0, 1, 2, 3]),
    )
    .unwrap();
    let mut damaged = a.clone();
    for x in &mut damaged[2 * bs + 5..2 * bs + 40] {
        *x ^= 0xa5;
    }
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    // b.bin absent entirely.
    let st = repair_dir(&dir).expect("repair runs");
    match st {
        RepairStatus::Repaired(r) => {
            assert_eq!(r.blocks_rebuilt, 4, "one damaged + three missing blocks");
            assert!(r.files_created.contains(&"b.bin".to_string()));
        }
        other => panic!("expected Repaired, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "a.bin bytes");
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b, "b.bin bytes");
    let _ = std::fs::remove_dir_all(&dir);
}

/// B2: the settle-tail sequence (multi-set repair, then covered_names,
/// then the sniffed sweep) against ONE catalog reads the packet corpus
/// exactly once, and every answer matches what the rescanning free
/// functions say about the same directory.
#[test]
fn one_catalog_scan_serves_repairs_names_and_sniff() {
    let dir = tmpdir("catalog-once");
    let mut corpus_bytes = 0u64;
    let mut write = |name: &str, bytes: &[u8]| {
        std::fs::write(dir.join(name), bytes).unwrap();
        corpus_bytes += bytes.len() as u64;
    };
    // Three sets, one damaged data file each; the third set's volume is
    // an extensionless sniffed file.
    let mut payloads = Vec::new();
    for s in 0..3u8 {
        payloads.push(payload(200, 10 + s as u64));
    }
    for (s, data) in payloads.iter().enumerate() {
        let set = [40 + s as u8; 16];
        let name = format!("f{s}.bin");
        let files: &[(&str, &[u8])] = &[(&name, data)];
        let mut damaged = data.clone();
        damaged[70] ^= 0x5a;
        std::fs::write(dir.join(&name), &damaged).unwrap();
        write(&format!("set{s}.par2"), &par2_index(set, BS, files));
        let vol = par2_volume(set, BS, files, &[0, 1]);
        if s == 2 {
            write("0badc0ffee", &vol);
        } else {
            write(&format!("set{s}.vol0+2.par2"), &vol);
        }
    }
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    let results = cat.repair_present_sets().expect("sets walk");
    assert_eq!(results.len(), 3, "every set's file is on disk");
    for r in &results {
        match &r.status {
            Ok(RepairStatus::Repaired(rep)) => assert_eq!(rep.blocks_rebuilt, 1),
            other => panic!("expected Repaired, got {other:?}"),
        }
    }
    for (s, data) in payloads.iter().enumerate() {
        assert_eq!(&std::fs::read(dir.join(format!("f{s}.bin"))).unwrap(), data);
    }
    let mut names = cat.covered_names().expect("names replay");
    names.sort();
    assert_eq!(names, ["f0.bin", "f1.bin", "f2.bin"]);
    assert_eq!(
        cat.sniffed_packet_files().expect("sniff replay"),
        [dir.join("0badc0ffee")]
    );
    // The free functions agree with the catalog's replayed answers.
    let mut free_names = covered_names(&dir).unwrap();
    free_names.sort();
    assert_eq!(free_names, names);
    assert_eq!(
        sniffed_packet_files(&dir).unwrap(),
        [dir.join("0badc0ffee")]
    );
    // One corpus scan total: three repairs, a name query and a sniff
    // sweep did not reread a single unchanged packet file.
    assert_eq!(
        cat.bytes_scanned(),
        corpus_bytes,
        "the catalog read each packet file exactly once"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Rewrite `bytes` inside `path` while restoring its mtime, so size,
/// identity and mtime all read unchanged - the below-stat-granularity
/// mutation the pread re-proof exists for.
fn mutate_silently(path: &Path, off: u64, xor: u8) {
    use std::io::{Read as _, Seek as _, SeekFrom, Write as _};
    let mtime = std::fs::metadata(path).unwrap().modified().unwrap();
    let mut f = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .open(path)
        .unwrap();
    let mut b = [0u8; 1];
    f.seek(SeekFrom::Start(off)).unwrap();
    f.read_exact(&mut b).unwrap();
    b[0] ^= xor;
    f.seek(SeekFrom::Start(off)).unwrap();
    f.write_all(&b).unwrap();
    f.set_modified(mtime).unwrap();
}

/// W4-10, disk-repair half. Two individually valid FileDesc packets
/// under one set id and one file id, contradicting each other about the
/// name, length and digest. `SetReplay` took the first one it reached,
/// and the order it reaches them in is the order the packet FILES sort
/// on disk - so the same malformed set repaired one way off one machine
/// and another way off the next, and could disagree with what live
/// verification made of the identical bytes.
///
/// The bar is the DIFFERENTIAL, not the verdict: what must never happen
/// is that the two orders answer differently. That they now both answer
/// `Malformed` is the second assertion, and it is the SAME route a
/// wholly missing FileDesc already took - a file id we cannot name is a
/// file we cannot lay onto the slice index space.
#[test]
fn contradictory_filedescs_do_not_repair_differently_by_packet_order() {
    let a = payload(200, 21);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let mut damaged = a.clone();
    damaged[10] ^= 0x77;

    // A second, disagreeing descriptor for the SAME file id: different
    // name, different length, different digests.
    let rival = {
        let mut d = Vec::new();
        d.extend_from_slice(&fid(0));
        d.extend_from_slice(&[0xBB; 16]); // md5
        d.extend_from_slice(&[0xB1; 16]); // md5_16k
        d.extend_from_slice(&(a.len() as u64 + 4096).to_le_bytes());
        d.extend_from_slice(b"rival.bin");
        while !d.len().is_multiple_of(4) {
            d.push(0);
        }
        pkt(SET, par2::TYPE_FILEDESC, &d)
    };

    // The two orders differ ONLY in where the rival descriptor sits.
    let index = par2_index(SET, BS, files);
    let mut rival_last = index.clone();
    rival_last.extend_from_slice(&rival);
    let mut rival_first = rival.clone();
    rival_first.extend_from_slice(&index);

    let verdict = |tag: &str, par2_bytes: &[u8]| -> String {
        let dir = tmpdir(tag);
        std::fs::write(dir.join("a.bin"), &damaged).unwrap();
        std::fs::write(dir.join("set.par2"), par2_bytes).unwrap();
        std::fs::write(
            dir.join("set.vol0+2.par2"),
            par2_volume(SET, BS, files, &[0, 1]),
        )
        .unwrap();
        let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
        let results = cat.repair_present_sets().expect("sets walk");
        let out = format!(
            "{:?}",
            results.iter().map(|r| &r.status).collect::<Vec<_>>()
        );
        let _ = std::fs::remove_dir_all(&dir);
        out
    };

    let last = verdict("w410-rival-last", &rival_last);
    let first = verdict("w410-rival-first", &rival_first);
    assert_eq!(
        last, first,
        "which descriptor sits first in the packet file decided what the \
         set was taken to say: `{last}` against `{first}`"
    );
    assert!(
        last.contains("Malformed"),
        "a file id with two contradictory descriptors must not be \
         repaired against either reading, got `{last}`"
    );
}

/// B2 mutation safety: a recovery packet whose bytes changed under an
/// unchanged size+mtime+identity stamp is caught by the packet-MD5
/// re-proof at pread, dropped, and the repair completes from the next
/// exponent up.
#[test]
fn reused_catalog_reproves_a_silently_mutated_recovery_slice() {
    let dir = tmpdir("catalog-reprove");
    let a = payload(200, 21);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let mut damaged = a.clone();
    damaged[10] ^= 0x77;
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let vol = dir.join("set.vol0+2.par2");
    std::fs::write(&vol, par2_volume(SET, BS, files, &[0, 1])).unwrap();
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    // Corrupt one byte of exponent 0's slice payload (64-byte header +
    // 4-byte exponent + 3), stamp restored.
    mutate_silently(&vol, 64 + 4 + 3, 0xff);
    let results = cat.repair_present_sets().expect("sets walk");
    assert_eq!(results.len(), 1);
    match &results[0].status {
        Ok(RepairStatus::Repaired(rep)) => {
            assert_eq!(rep.blocks_rebuilt, 1, "exponent 1 carried the repair")
        }
        other => panic!("expected Repaired via the surviving exponent, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);

    // Same shape with EVERY slice mutated: the drops leave the selection
    // short and the verdict is the Unrepairable arithmetic a fresh scan
    // of the mutated file would also have reached.
    let dir2 = tmpdir("catalog-reprove-all");
    std::fs::write(dir2.join("a.bin"), &damaged).unwrap();
    std::fs::write(dir2.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let vol2 = dir2.join("set.vol0+2.par2");
    std::fs::write(&vol2, par2_volume(SET, BS, files, &[0, 1])).unwrap();
    let mut cat2 = PacketCatalog::build(&dir2).expect("catalog builds");
    let slice_stride = (64 + 4 + BS) as u64;
    mutate_silently(&vol2, 64 + 4 + 3, 0xff);
    mutate_silently(&vol2, slice_stride + 64 + 4 + 3, 0xff);
    let results = cat2.repair_present_sets().expect("sets walk");
    match &results[0].status {
        Ok(RepairStatus::Unrepairable {
            needed: 1,
            have: 0,
            adopted: 0,
            ..
        }) => {}
        other => panic!("expected Unrepairable {{1, 0}}, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
}

/// B2 refresh: files that appear, change (with a visible stamp), or
/// vanish after build are picked up by the identity/size/mtime recheck -
/// the catalog's answers track the directory, not the snapshot.
#[test]
fn refresh_tracks_new_changed_and_removed_packet_files() {
    let dir = tmpdir("catalog-refresh");
    let a = payload(200, 31);
    let files_a: &[(&str, &[u8])] = &[("a.bin", &a)];
    std::fs::write(dir.join("a.bin"), &a).unwrap();
    std::fs::write(dir.join("seta.par2"), par2_index(SET, BS, files_a)).unwrap();
    let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
    assert_eq!(cat.covered_names().unwrap(), ["a.bin"]);
    // A second set lands after build.
    let b = payload(97, 32);
    let files_b: &[(&str, &[u8])] = &[("b.bin", &b)];
    let mut b_damaged = b.clone();
    b_damaged[5] ^= 0x11;
    std::fs::write(dir.join("b.bin"), &b_damaged).unwrap();
    std::fs::write(dir.join("setb.par2"), par2_index([7u8; 16], BS, files_b)).unwrap();
    std::fs::write(
        dir.join("setb.vol0+1.par2"),
        par2_volume([7u8; 16], BS, files_b, &[0]),
    )
    .unwrap();
    let mut names = cat.covered_names().unwrap();
    names.sort();
    assert_eq!(names, ["a.bin", "b.bin"], "refresh adopted the new set");
    let results = cat.repair_present_sets().expect("sets walk");
    assert_eq!(results.len(), 2);
    assert!(
        matches!(&results[1].status, Ok(RepairStatus::Repaired(_))),
        "the set that landed after build repairs from the refreshed catalog"
    );
    assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b);
    // And its packet files leaving takes its names with them.
    std::fs::remove_file(dir.join("setb.par2")).unwrap();
    std::fs::remove_file(dir.join("setb.vol0+1.par2")).unwrap();
    assert_eq!(cat.covered_names().unwrap(), ["a.bin"]);
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO §282 item 15, the half that is NOT a defect: a partially
/// fetched recovery volume DOES contribute the slices it holds.
///
/// The live shape (a real daemon against one provider, 24 Aug 2026
/// 00:36Z) is a volume whose
/// articles mostly never arrived, so the file on disk is full-length
/// with holes in it. Two damage shapes come out of that, and the packet
/// scan has to survive both without losing what is still good:
///
/// - a hole that swallows a whole packet, HEADER INCLUDED, so nothing
///   at that offset looks like a packet at all;
/// - a hole that starts inside the payload, leaving a structurally
///   valid header over bytes that no longer hash to it.
///
/// Both were measured on the incident's leftover volumes: five partial
/// volumes carrying 0.9% to 5.5% of their bytes held 6 torn RecvSlic
/// packets between them and not one valid slice, while the surviving
/// critical packets scattered through the same files scanned fine. The
/// intact slices here are the ones AFTER both holes, which is the part
/// worth pinning - the serial scan's `start + 1` resume is what finds
/// them, and a scanner that gave up on the first bad MD5 would throw
/// away recovery data that was already paid for.
#[test]
fn a_holey_recovery_volume_still_yields_its_intact_slices() {
    let dir = tmpdir("holey-volume");
    let a = payload(BS * 8, 61);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let mut damaged = a.clone();
    damaged[BS * 2] ^= 0x5a;
    damaged[BS * 5] ^= 0x5a;
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    let mut vol = par2_volume(SET, BS, files, &[0, 1, 2, 3]);
    let stride = 64 + 4 + BS;
    assert_eq!(vol.len(), stride * 4, "four slices, one packet each");
    // Exponent 1: the whole packet is a hole.
    vol[stride..stride * 2].fill(0);
    // Exponent 2: header survives, payload does not.
    vol[stride * 2 + 64 + 4..stride * 3].fill(0);
    std::fs::write(dir.join("set.vol0+4.par2"), &vol).unwrap();

    match repair_dir(&dir).expect("the surviving exponents carry the repair") {
        RepairStatus::Repaired(rep) => assert_eq!(
            rep.blocks_rebuilt, 2,
            "exponents 0 and 3 survived the holes and rebuilt both blocks"
        ),
        other => panic!("expected Repaired from the intact slices, got {other:?}"),
    }
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other half of TODO §282 item 15: when the surviving slices do
/// not cover the damage, say WHICH condition that is.
///
/// The live line read `recovery set malformed: 0 recovery slice(s) for
/// 163 missing block(s)` over a set that was not malformed at all - a
/// 1024 MB recovery fetch had come back 68.9 MB with 1206 article
/// failures, and at a 5.25 MB block size no slice landed whole. Reading
/// that as a malformed set is what sends the next reader after the PAR2
/// parser instead of after the provider. `have` is the count of slices
/// that are both present AND MD5-valid, so this asserts the number the
/// incident made worth asserting: a volume that is PARTLY there reports
/// what it holds, never zero.
#[test]
fn a_torn_recovery_volume_reports_how_many_slices_are_usable() {
    struct BufIo(std::sync::Mutex<Vec<u8>>);
    impl VolumeIo for BufIo {
        fn read(&self, _f: usize, off: u64, buf: &mut [u8]) -> std::io::Result<()> {
            let d = self.0.lock().unwrap();
            let off = off as usize;
            buf.copy_from_slice(&d[off..off + buf.len()]);
            Ok(())
        }
        fn write(&self, _f: usize, off: u64, data: &[u8]) -> std::io::Result<()> {
            let mut d = self.0.lock().unwrap();
            let off = off as usize;
            d[off..off + data.len()].copy_from_slice(data);
            Ok(())
        }
    }

    let a = payload(BS * 8, 62);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let meta = meta_for("a.bin", &a, BS);
    let stride = 64 + 4 + BS;

    // (how many of the two slices are torn) -> the count reported.
    for (torn, want_have) in [(1usize, 1usize), (2, 0)] {
        let dir = tmpdir(&format!("torn-volume-{torn}"));
        let mut damaged = a.clone();
        let mut present = vec![true; 8];
        for blk in [2usize, 5] {
            present[blk] = false;
            damaged[blk * BS] ^= 0x5a;
        }
        std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
        let mut vol = par2_volume(SET, BS, files, &[0, 1]);
        // Tear from the BACK, so the `torn == 1` case leaves exponent 0
        // usable and the selection is short rather than absent.
        for s in (2 - torn)..2 {
            vol[s * stride + 64 + 4..(s + 1) * stride].fill(0);
        }
        std::fs::write(dir.join("set.vol0+2.par2"), &vol).unwrap();

        let mut cat = PacketCatalog::build(&dir).expect("catalog builds");
        let io = BufIo(std::sync::Mutex::new(damaged));
        let err = repair_mapped_catalog(&[(meta.clone(), present)], BS, &mut cat, &SET, &io, false)
            .expect_err("two missing blocks cannot be covered");
        assert!(
            matches!(err, RepairError::RecoveryShort { have, need: 2 } if have == want_have),
            "expected RecoveryShort {{ have: {want_have}, need: 2 }}, got {err:?}"
        );
        let said = err.to_string();
        assert!(
            said.contains("recovery data short") && said.contains("usable"),
            "the verdict must name the shortfall: {said}"
        );
        assert!(
            !said.contains("malformed"),
            "a short recovery set is not a malformed one: {said}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    // The in-memory sibling of the same arithmetic (`repair_mapped`,
    // the corpus form the catalog path replaced) reports it identically.
    let slices = global_slices(files, BS);
    let recovery = vec![(0u32, generate_recovery(&slices, BS, 0))];
    let mut present = vec![true; 8];
    let mut damaged = a.clone();
    for blk in [2usize, 5] {
        present[blk] = false;
        damaged[blk * BS] ^= 0x5a;
    }
    let io = BufIo(std::sync::Mutex::new(damaged));
    match repair_mapped(&[(meta, present)], BS, &recovery, &io, false) {
        Err(RepairError::RecoveryShort { have: 1, need: 2 }) => {}
        other => panic!("expected RecoveryShort {{ have: 1, need: 2 }}, got {other:?}"),
    }
}

/// TODO §283 item 14: the disk route is the one the mapped planner FALLS
/// THROUGH TO when it declines at `MAX_REPAIR_DIM`, and item 14's reading
/// of the code was that nothing capped the dimension once you were on it -
/// only `MAX_INPUT_SLICES` and the recovery-shortfall arithmetic. This is
/// that claim driven rather than read: a set declaring one block more than
/// the cap, with enough recovery slices on disk to clear the shortfall
/// check, is refused by name.
///
/// The volume's slice bodies are ZERO rather than real recovery data, and
/// that is the point of the fixture: the refusal has to land before any of
/// it is read, so generating 8193 real slices over 8193 inputs (~67M field
/// multiplies) would only prove the test was slow. The packets are
/// otherwise well formed - real header, real body MD5 - so the catalog
/// counts them and the shortfall check passes on them.
///
/// 16-byte blocks, not the smallest legal 2: extra-file adoption verifies
/// a candidate window against the block's own MD5, and at a 4-byte block a
/// chance match anywhere in the directory would adopt a slice, drop
/// `missing` to exactly the cap and turn this into a test of nothing.
///
/// Verified to BITE rather than observed green: with `check_repair_dim`
/// short-circuited to `Ok`, the disk route runs the whole 8193-dimension
/// solve and comes back `VerifyFailed("over.bin")` after 8.4 s in a debug
/// build - which is also the shape of the answer item 14 was worried
/// about, at the one dimension small enough to watch.
#[test]
fn the_disk_route_refuses_a_set_one_block_over_the_repair_matrix_cap() {
    const DIM_BS: usize = 16;
    let over = MAX_REPAIR_DIM + 1;
    let dir = tmpdir("dimcap");
    // Never written to disk, so every one of its slices is missing.
    let big = payload(over * DIM_BS, 11);
    let files: &[(&str, &[u8])] = &[("over.bin", &big)];
    std::fs::write(dir.join("set.par2"), par2_index(SET, DIM_BS, files)).unwrap();
    let mut vol = Vec::new();
    for e in 0..over as u32 {
        let mut body = e.to_le_bytes().to_vec();
        body.extend_from_slice(&[0u8; DIM_BS]);
        vol.extend(pkt(SET, par2::TYPE_RECVSLIC, &body));
    }
    std::fs::write(dir.join("set.vol0+8193.par2"), &vol).unwrap();
    match repair_dir(&dir) {
        Err(RepairError::Malformed(m)) => {
            assert!(
                m.contains(&format!("{over} missing blocks")) && m.contains("repair-matrix cap"),
                "the dimension cap must be the stated reason: {m}"
            );
        }
        other => panic!("expected the repair-matrix cap refusal, got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// v1.2.4 sweep R5: the digest that earns a donation its rename is
/// taken off the COPY, not off the read that chose it.
///
/// The window R5 names is a mutation between the two - a donor is a
/// directory this job does not own, so a retention sweep, a user
/// delete-and-replace or the predecessor's own repair patch can land
/// between the screen and `std::fs::copy`. That race is not reproducible
/// from a test without a hook inside the loop, so what is pinned here is
/// the GUARD it turns on, driven directly: bytes that are not the
/// member's must not be renamed into place, whatever chose them.
///
/// It bites. Delete the digest comparison in `copy_verified` and the
/// wrong-bytes half of this returns `true`.
#[test]
fn a_donated_copy_is_verified_by_its_own_bytes_and_not_by_the_screen() {
    let dir = tmpdir("copy-verified");
    let data = payload(300_000, 51);
    let src = dir.join("src.bin");
    std::fs::write(&src, &data).unwrap();
    let right = <[u8; 16]>::from(Md5::digest(&data));
    let wrong = <[u8; 16]>::from(Md5::digest(payload(300_000, 52)));

    let good = dir.join("good.tmp");
    assert!(
        donate::copy_verified(&src, &good, right).expect("a readable donor copies"),
        "the member's own digest must pass"
    );
    assert_eq!(
        std::fs::read(&good).unwrap(),
        data,
        "and the copy is byte-exact"
    );

    let bad = dir.join("bad.tmp");
    assert!(
        !donate::copy_verified(&src, &bad, wrong).expect("a readable donor copies"),
        "bytes that are not the member's must be REFUSED, however the \
         screen judged the file a moment earlier"
    );

    // A vanished source is an error, never a silent success: the caller
    // drops the member and the fetch plan keeps its articles.
    assert!(
        donate::copy_verified(&dir.join("no-such-file"), &dir.join("x.tmp"), right).is_err(),
        "an unreadable donor must not answer `true`"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// v1.2.4 sweep R6: donors with nothing to give must not end the pass
/// before it can see a PREVIOUS pass's own donation.
///
/// A donated file has no journal placements - its articles were never
/// fetched - so nothing on the crash-resume path can recognise it. The
/// already-here arm is the only thing that can, and the old
/// `cands.is_empty()` early return took it out exactly when it was
/// needed: a successor resuming after its predecessor was swept
/// re-downloaded a file whole and byte-exact in its own `out_dir`.
///
/// It bites. Put the early return back and `still_reported` is empty.
#[test]
fn a_swept_donor_still_finds_the_members_a_previous_pass_placed() {
    let donor = tmpdir("swept-src");
    let dir = tmpdir("swept-dst");
    let data = payload(260, 61);
    let files: &[(&str, &[u8])] = &[("f1.bin", &data)];
    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");

    // The predecessor's directory is still there and holds nothing: the
    // retention sweep got to it between the two runs.
    assert_eq!(donor_candidates(std::slice::from_ref(&donor), &dir), 0);
    // ...and the earlier pass's placement is sitting in out_dir.
    std::fs::write(dir.join("f1.bin"), &data).unwrap();

    let still_reported = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);
    assert_eq!(
        still_reported.len(),
        1,
        "the member already placed must still be reported so the plan \
         strikes its articles: {still_reported:?}"
    );
    assert_eq!(still_reported[0].from, dir.join("f1.bin"));
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), data);

    // The cheap question the caller asks first, on the same directory.
    assert_eq!(
        placed_names(&dir),
        ["f1.bin"],
        "and out_dir's own walk is what tells the caller to look at all"
    );
    assert!(
        placed_names(&donor).is_empty(),
        "a swept directory offers no name"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// v1.2.4 sweep R7: two FileDesc packets naming one file identify no
/// member, so neither may be placed and neither may be reported.
///
/// Both would land on one path. The first in set order wins the name,
/// the second finds a destination that is not itself and is left alone -
/// so the successor's file carries whichever came first and its
/// articles are struck out either way, which is a coin flip on bytes
/// there is no way back from. `probe_recovery_set` refuses the same
/// shape one rung narrower (it only judges the length); this judges
/// every fact the donation turns on.
///
/// It bites. Delete the `ambiguous.contains` skip and the donor's
/// `dup.bin` is placed and reported, on evidence that names two files.
#[test]
fn two_members_under_one_name_donate_nothing_on_either_arm() {
    let donor = tmpdir("ambig-src");
    let dir = tmpdir("ambig-dst");
    let first = payload(260, 71);
    let second = payload(260, 72);
    let clear = payload(200, 73);
    // `par2_index` gives each entry its own file id, so the same NAME
    // twice is two members that disagree about everything else - the
    // malformed set this guard is for.
    let files: &[(&str, &[u8])] = &[
        ("dup.bin", &first),
        ("dup.bin", &second),
        ("clear.bin", &clear),
    ];
    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");
    std::fs::write(donor.join("dup.bin"), &first).unwrap();
    std::fs::write(donor.join("clear.bin"), &clear).unwrap();

    let placed = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);
    assert_eq!(
        placed.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        ["clear.bin"],
        "only the unambiguous member may be donated: {placed:?}"
    );
    assert!(
        !dir.join("dup.bin").exists(),
        "an ambiguous name must place NOTHING"
    );

    // The already-here arm answers the same way: a member sitting in
    // out_dir under an ambiguous name is not reported either, because
    // reporting it strikes the articles out just as surely as placing
    // it would.
    std::fs::write(dir.join("dup.bin"), &first).unwrap();
    let again = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);
    assert_eq!(
        again.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        ["clear.bin"],
        "and an ambiguous name already in place is still not reported: {again:?}"
    );

    // A set that names one file twice with the SAME facts is not
    // ambiguous - there is one answer to give, and refusing it would
    // refuse a duplicated packet, which real sets carry.
    let twice: &[(&str, &[u8])] = &[("clear.bin", &clear), ("clear.bin", &clear)];
    let dir2 = tmpdir("ambig-dst2");
    let idx2 = par2_index(SET, BS, twice);
    let set2 = par2::Par2Set::parse(&[&idx2]).expect("fixture parses");
    let dupe_ok = donate_whole_files(&set2, std::slice::from_ref(&donor), &dir2);
    assert_eq!(
        dupe_ok.len(),
        2,
        "two identical descriptions of one file are one answer, not a \
         disagreement: {dupe_ok:?}"
    );
    assert_eq!(std::fs::read(dir2.join("clear.bin")).unwrap(), clear);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&dir2);
    let _ = std::fs::remove_dir_all(&donor);
}

/// PLAN M31's bench-gate geometry to scale, and the two facts a bench
/// round on 28 Aug 2026 could not tell apart.
///
/// A failed predecessor and its successor were seeded from ONE posting
/// with complementary stride-2 ARTICLE masks, disjoint by construction
/// and verified overlap 0. The successor still failed, and no
/// `block(s) adopted from` line appeared anywhere in the daemon log,
/// which reads as "the donor bridged nothing". Both halves of that
/// reading were wrong, and this pins each.
///
/// FIRST: article-disjoint is not block-disjoint. That set's PAR2
/// block was exactly two articles wide, so every block spanning an
/// eligible article pair is damaged in BOTH postings - the two logs
/// report the identical `13/14 blocks bad` on every volume. The only
/// block a donor can offer is the one at the edge of the damaged
/// range, and here that is one per file. Adoption is behaving
/// correctly; the SEEDING cannot produce the pair the gate wants.
///
/// SECOND: the count was invisible, not zero. The set is still short
/// afterwards, so the verdict is `Unrepairable`, and
/// `RepairReport::blocks_adopted` is only reachable through
/// `Repaired`. The donation is legible now because that verdict
/// carries `adopted` - which is what this asserts, and what makes the
/// difference between the two readings measurable from a log.
#[test]
fn a_donor_damaged_at_the_complementary_article_phase_donates_almost_nothing() {
    let (art, nart, tail, nfiles) = (64usize, 27usize, 32usize, 4usize);
    let bs = 2 * art; // the field's 1_536_000 over 768_000 articles
    let len = (nart - 1) * art + tail;
    let (dir, donor, truth, names) = field_shape(art, nart, len, nfiles, |a| a % 2 == 1);
    std::fs::write(
        dir.join("set.par2"),
        par2_index([3u8; 16], bs, &named(&names, &truth)),
    )
    .unwrap();

    // Baseline: what the successor is missing with no donor at all.
    let base = match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!(have, 0, "no recovery on disk, as in the field");
            needed
        }
        other => panic!("baseline must be unrepairable, got {other:?}"),
    };
    assert_eq!(base, 13 * nfiles, "13 of this file's 14 blocks, per file");

    match repair_dir_with_donors(&dir, std::slice::from_ref(&donor)).expect("donor repair runs") {
        RepairStatus::Unrepairable {
            needed,
            have,
            adopted,
            ..
        } => {
            println!(
                "field geometry: {base} missing, {adopted} adopted, {needed} still needed, \
                 {have} recovery held"
            );
            assert_eq!(adopted, nfiles, "one edge block per file and no more");
            assert_eq!(needed, base - adopted, "adoption is already subtracted");
            assert!(
                adopted > 0,
                "the donation is REPORTED on the shortfall verdict - the whole point"
            );
        }
        other => panic!("still short after adoption, so unrepairable: got {other:?}"),
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// The control, and the shape a future round has to seed to test §293
/// at all: the same two postings damaged in BLOCK-aligned pairs rather
/// than at alternating article positions. Nothing about the adoption
/// code changes - only the mask - and every missing block is now
/// intact in the donor, so the set that could not be repaired above
/// repairs completely with no recovery data whatsoever.
#[test]
fn a_donor_damaged_at_the_complementary_block_phase_donates_everything() {
    let (art, nart, tail, nfiles) = (64usize, 27usize, 32usize, 4usize);
    let bs = 2 * art;
    let len = (nart - 1) * art + tail;
    // Poison whole BLOCKS: both articles of every other block-aligned
    // pair, so the complement leaves those blocks whole in the donor.
    let (dir, donor, truth, names) = field_shape(art, nart, len, nfiles, |a| (a / 2) % 2 == 1);
    std::fs::write(
        dir.join("set.par2"),
        par2_index([4u8; 16], bs, &named(&names, &truth)),
    )
    .unwrap();
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("donor repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("a block-disjoint donor completes the set: got {other:?}"),
    };
    println!(
        "block-aligned mask: {} adopted, {} rebuilt",
        report.blocks_adopted, report.blocks_rebuilt
    );
    assert!(
        report.blocks_adopted > 0,
        "every missing block came off disk"
    );
    assert_eq!(
        report.blocks_rebuilt, 0,
        "no recovery data exists to rebuild from"
    );
    for (f, name) in names.iter().enumerate() {
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            truth[f],
            "{name} landed byte-exact"
        );
    }
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// Build the two-posting shape both legs above share: `poisoned(a)`
/// picks the predecessor's articles, its complement the successor's,
/// and article 0 is never picked (the seeding tool skips each file's
/// first segment so headers stay resolvable). The donor's files carry
/// the `.nzbfast-partial` suffix a failed job's quarantine leaves.
fn field_shape(
    art: usize,
    nart: usize,
    len: usize,
    nfiles: usize,
    poisoned: impl Fn(usize) -> bool,
) -> (PathBuf, PathBuf, Vec<Vec<u8>>, Vec<String>) {
    let truth: Vec<Vec<u8>> = (0..nfiles).map(|f| payload(len, 200 + f as u64)).collect();
    let names: Vec<String> = (0..nfiles).map(|f| format!("v{f:02}.rar")).collect();
    let hole = |data: &[u8], want: bool| -> Vec<u8> {
        let mut v = data.to_vec();
        for a in 1..nart {
            if poisoned(a) == want {
                let (s, e) = (a * art, ((a + 1) * art).min(len));
                v[s..e].fill(0);
            }
        }
        v
    };
    let donor = tmpdir("m31-field-donor");
    let dir = tmpdir("m31-field-dst");
    for f in 0..nfiles {
        std::fs::write(
            donor.join(format!("{}.nzbfast-partial", names[f])),
            hole(&truth[f], true),
        )
        .unwrap();
        std::fs::write(dir.join(&names[f]), hole(&truth[f], false)).unwrap();
    }
    (dir, donor, truth, names)
}

/// `(name, bytes)` pairs for [`par2_index`] out of the two vectors
/// [`field_shape`] returns.
fn named<'a>(names: &'a [String], truth: &'a [Vec<u8>]) -> Vec<(&'a str, &'a [u8])> {
    names
        .iter()
        .zip(truth)
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect()
}

/// M4-65 (30 Aug 2026): the content sniff is the ONLY way to find an
/// obfuscated post's recovery volumes - they carry a hash name and no
/// `.par2` extension - and it used to demand the magic at byte 0
/// exactly. Any prefix at all defeated it: a 3-byte UTF-8 BOM from a
/// producer that touched the file as text was enough. The volume was
/// never a packet file, the inner set never activated, and the payload
/// stayed hashed with its parity sitting unread beside it.
///
/// Both disk sniff sites, because they are hand-copied siblings of each
/// other - the directory walk `sniffed_packet_files` uses, and the
/// repair catalog's incremental `relist`, which is the one whose
/// `scan_file` does the whole-file read. They share
/// `par2::head_is_packet_file` now; this is what says so.
///
/// The CONTROL is the far side of the window: a prefix longer than
/// [`par2::SNIFF_WINDOW`] is still not sniffed, because the sniff
/// decides whether to read a file WHOLE and how far it looks is how much
/// attacker-chosen input one directory entry becomes.
#[test]
fn a_short_prefix_in_front_of_the_magic_does_not_hide_a_volume() {
    let dir = tmpdir("sniff-prefix");
    let a = payload(200, 3);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let vol = par2_volume(SET, BS, files, &[0]);

    let with_prefix = |n: usize| -> Vec<u8> {
        let mut v = vec![0xEFu8; n];
        v.extend_from_slice(&vol);
        v
    };
    // A real UTF-8 BOM, and the exact window edge either side of it.
    std::fs::write(dir.join("bom"), {
        let mut v = vec![0xEF, 0xBB, 0xBF];
        v.extend_from_slice(&vol);
        v
    })
    .unwrap();
    std::fs::write(dir.join("edge"), with_prefix(par2::SNIFF_WINDOW)).unwrap();
    std::fs::write(dir.join("past"), with_prefix(par2::SNIFF_WINDOW + 1)).unwrap();

    let (collected, sniffed) = collect_packet_files_bounded(&dir, u64::MAX).expect("walk");
    let names: Vec<String> = collected
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        names.contains(&"bom".to_string()) && names.contains(&"edge".to_string()),
        "a volume behind a short prefix is still a volume: {names:?}"
    );
    assert!(
        !names.contains(&"past".to_string()),
        "past the window the sniff must not commit to a whole-file read: {names:?}"
    );
    assert_eq!(sniffed.len(), 2, "both are sniffed, neither is named");

    // The catalog carries its own copy of the walk - the one whose
    // scan_file does the whole-file read - so it is pinned separately.
    let cat =
        PacketCatalog::build_lazy_bounded(&dir, u64::MAX, PacketScope::Flat).expect("catalog");
    let seen: Vec<String> = cat
        .packet_paths()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    assert!(
        seen.contains(&"bom".to_string()) && seen.contains(&"edge".to_string()),
        "the catalog sniff must not have drifted from the walk: {seen:?}"
    );
    assert!(!seen.contains(&"past".to_string()), "{seen:?}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wave-4 row M4-53's shape test and the interior-hole follow-on: a
/// child module so they reach the helpers above while this file stays
/// inside its size-gate ceiling.
mod volshape_tests;

/// M4-38, the catalog reader. A descriptor that BINDS its file id
/// outranks one that merely carries a copy, and `par2.rs`'s own
/// `a_forged_file_id_never_beats_the_descriptor_that_binds_it` drives
/// that rule in the parser (`Claim::offer_desc`). This drives the OTHER
/// reader: the directory catalog's `claim_desc_or_contradict`, which
/// feeds descriptors packet by packet in scan order and used to keep
/// whichever it saw first - and which, once W4-10 landed, would empty
/// the claim and lose the honest member instead.
///
/// The forgery is planted in `aa-evil.par2`, ahead of the index in a
/// sorted listing, so the pre-fix answer really is the wrong one rather
/// than the right one by luck.
#[test]
fn a_forged_file_id_does_not_take_another_files_main_slot() {
    let dir = tmpdir("catalog-forged-fid");
    let set = [0x51u8; 16];
    let data = payload(200, 77);
    let name = "real.bin";
    std::fs::write(dir.join(name), &data).unwrap();

    // The honest descriptor, with the spec's id: MD5 of its own 16k
    // hash, length and name.
    let head = &data[..data.len().min(16384)];
    let mut idsrc: Vec<u8> = <[u8; 16]>::from(Md5::digest(head)).to_vec();
    idsrc.extend_from_slice(&(data.len() as u64).to_le_bytes());
    idsrc.extend_from_slice(name.as_bytes());
    let fid: [u8; 16] = Md5::digest(&idsrc).into();

    let desc = |n: &str, bytes: &[u8]| {
        let mut b = fid.to_vec();
        b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(bytes)));
        b.extend_from_slice(&<[u8; 16]>::from(Md5::digest(
            &bytes[..bytes.len().min(16384)],
        )));
        b.extend_from_slice(&(bytes.len() as u64).to_le_bytes());
        let mut nb = n.as_bytes().to_vec();
        nb.resize(nb.len().next_multiple_of(4), 0);
        b.extend_from_slice(&nb);
        b
    };

    let mut main = (BS as u64).to_le_bytes().to_vec();
    main.extend_from_slice(&1u32.to_le_bytes());
    main.extend_from_slice(&fid);
    let mut index = pkt(set, par2::TYPE_MAIN, &main);
    index.extend(pkt(set, par2::TYPE_FILEDESC, &desc(name, &data)));
    std::fs::write(dir.join("set.par2"), &index).unwrap();

    let evil = vec![0xABu8; 64];
    std::fs::write(
        dir.join("aa-evil.par2"),
        pkt(set, par2::TYPE_FILEDESC, &desc("evil.bin", &evil)),
    )
    .unwrap();

    // `covered_names` is deliberately NOT the probe: it walks every
    // FileDesc packet in the directory, so both names are things this
    // corpus spoke for and both come back. The Main slot is what the
    // forgery was after, and `repair_present_sets` is what resolves it.
    let out = repair_present_sets(&dir).expect("sets walk");
    assert_eq!(out.len(), 1, "one set");
    assert!(
        matches!(out[0].status, Ok(RepairStatus::NoDamage)),
        "the set should have verified `real.bin` on disk, got {:?}",
        out[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
}

// ---------------------------------------------------------------------
// Wave-4 matrix read, FOURTH extreme pass: rows M4-56 and M4-62. Both
// were PREDICTIONS and both were measured on the 30 Aug 2026 baseline
// before an assertion was written; both came back RED and land with
// their fixes. See `slice_fits_block` and `adopt::proven_spent`.
// ---------------------------------------------------------------------

/// [`par2_volume`] whose RecvSlic bodies carry `pad` EXTRA bytes past
/// the block, or `-pad` fewer. The packet MD5 is resealed either way,
/// so every packet here is intact - the length is the only thing wrong
/// with it, which is the whole point of the row.
fn par2_volume_sized(
    set_id: [u8; 16],
    bs: usize,
    files: &[(&str, &[u8])],
    exps: &[u32],
    delta: isize,
) -> Vec<u8> {
    let slices = global_slices(files, bs);
    let mut out = Vec::new();
    for &e in exps {
        let mut body = e.to_le_bytes().to_vec();
        body.extend_from_slice(&generate_recovery(&slices, bs, e));
        let want = (body.len() as isize + delta) as usize;
        body.resize(want, 0);
        out.extend(pkt(set_id, par2::TYPE_RECVSLIC, &body));
    }
    out
}

/// One file, one corrupt slice, four recovery slices - the
/// [`damage_and_a_missing_file_rebuild_from_recovery_slices`] shape
/// reduced to a single missing block so the arithmetic in an
/// Unrepairable verdict is readable.
fn one_bad_block_dir(tag: &str, a: &[u8]) -> PathBuf {
    let dir = tmpdir(tag);
    let mut damaged = a.to_vec();
    for x in &mut damaged[64..128] {
        *x ^= 0x5a;
    }
    std::fs::write(dir.join("a.bin"), &damaged).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, &[("a.bin", a)])).unwrap();
    dir
}

/// M4-56 - a RecvSlic whose payload is not exactly `block_size` was
/// dropped by both selection sites, silently. The row predicted
/// "Unrepairable at r that should have covered"; MEASURED RED on the
/// 30 Aug 2026 baseline, and the measurement is the shape below: four
/// intact recovery packets for ONE missing block reported
/// `Unrepairable { needed: 1, have: 0 }`.
///
/// The fix accepts an over-long packet and cuts it to the block on
/// load. Its three arms are the rule: the padded volume repairs, it
/// repairs to the SAME bytes the unpadded control does (so the cut is
/// taken from the right end), and the padding is the only difference
/// between them.
#[test]
fn a_recovery_slice_longer_than_the_block_still_serves_it() {
    let a = payload(200, 3);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let padded = one_bad_block_dir("m456pad", &a);
    std::fs::write(
        padded.join("set.vol0+4.par2"),
        par2_volume_sized(SET, BS, files, &[0, 1, 2, 3], 4),
    )
    .unwrap();
    let report = match repair_dir(&padded).expect("a padded volume is not an error") {
        RepairStatus::Repaired(r) => r,
        other => panic!(
            "four intact recovery packets for one missing block, refused for \
             carrying four bytes of padding: {other:?}"
        ),
    };
    assert_eq!(report.blocks_rebuilt, 1);
    assert_eq!(report.blocks_adopted, 0, "this is recovery, not adoption");
    assert_eq!(
        std::fs::read(padded.join("a.bin")).unwrap(),
        a,
        "the slice was cut from the wrong end of the packet"
    );
    // The control: the identical fixture with conforming volumes. It
    // must reach the same verdict, or the row's fixture is measuring
    // something other than the length predicate.
    let plain = one_bad_block_dir("m456ctl", &a);
    std::fs::write(
        plain.join("set.vol0+4.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3]),
    )
    .unwrap();
    match repair_dir(&plain).expect("the control repairs") {
        RepairStatus::Repaired(r) => assert_eq!(r.blocks_rebuilt, 1),
        other => panic!("the unpadded control did not repair: {other:?}"),
    }
    assert_eq!(std::fs::read(plain.join("a.bin")).unwrap(), a);
    let _ = std::fs::remove_dir_all(&padded);
    let _ = std::fs::remove_dir_all(&plain);
}

/// The other half of M4-56's rule, and the half that must NOT be
/// "fixed" the same way. A packet SHORTER than the block cannot be
/// zero-extended into one: that feeds bytes nobody has into the solve,
/// which is M4-40's defect on the input side and destructive there. So
/// it is refused - and the verdict is the honest arithmetic rather than
/// a rebuild that has to be rolled back by the final MD5 check.
///
/// The file must come out untouched, which is what separates "refused"
/// from "used and then reverted".
#[test]
fn a_recovery_slice_shorter_than_the_block_is_refused_not_zero_extended() {
    let a = payload(200, 3);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    let dir = one_bad_block_dir("m456short", &a);
    let mut damaged = a.clone();
    for x in &mut damaged[64..128] {
        *x ^= 0x5a;
    }
    std::fs::write(
        dir.join("set.vol0+4.par2"),
        par2_volume_sized(SET, BS, files, &[0, 1, 2, 3], -4),
    )
    .unwrap();
    match repair_dir(&dir).expect("a short volume is a verdict, not an error") {
        RepairStatus::Unrepairable { needed, have, .. } => {
            assert_eq!(
                (needed, have),
                (1, 0),
                "a short packet must count as no parity at all"
            );
        }
        other => panic!("a recovery packet too short to carry a block was used anyway: {other:?}"),
    }
    assert_eq!(
        std::fs::read(dir.join("a.bin")).unwrap(),
        damaged,
        "a refused set must not touch the file"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// M4-62 - a real file whose entire contents are a target's PADDED
/// last-block window. The row predicted the block "claimed from junk;
/// spend/delete; or a green verify of zeros".
///
/// MEASURED on the 30 Aug 2026 baseline and the prediction splits in
/// two. The ADOPTION is correct and stays: every byte of that window
/// really is on disk in the candidate, `a.bin` comes back byte-exact at
/// its full length, and refusing it would be a strictly worse engine.
/// The SPEND was red - `consumed_sources: ["junkZq62.bin"]` for a
/// 64-byte file of which 8 bytes were ever wanted, the other 56 being
/// the target's zero padding, which is not in the target at all. That
/// is M4-40's harm on the proof side, and `sweep_spent_sources` unlinks
/// what it is handed.
///
/// Both halves are asserted here, because "never adopt a padded window"
/// would pass the row and lose a legitimate donor.
#[test]
fn a_padded_last_block_donor_serves_its_bytes_and_is_not_spent() {
    let dir = tmpdir("m462");
    // 200 bytes at BS=64: slices 0..2 full, slice 3 is 8 real bytes
    // followed by 56 of pad.
    let a = payload(200, 61);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    // TRUNCATED, so the last block is genuinely absent from disk. A
    // damaged one would not do: a hole reads as zeros and an all-zero
    // block verifies PRESENT off the target's own file, so no candidate
    // is ever consulted (M4-40 records the same trap).
    std::fs::write(dir.join("a.bin"), &a[..192]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let mut decoy = a[192..].to_vec();
    decoy.resize(BS, 0);
    std::fs::write(dir.join("junkZq62.bin"), &decoy).unwrap();
    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 1);
    assert_eq!(report.adopted_from, ["junkZq62.bin"]);
    assert_eq!(
        std::fs::read(dir.join("a.bin")).unwrap(),
        a,
        "the target must come back whole, at its full length"
    );
    assert!(
        report.consumed_sources.is_empty(),
        "a donor whose window ran into the target's PADDING was reported \
         spent - {} of its {BS} bytes are absent from the target and \
         sweep_spent_sources unlinks what it is handed: {:?}",
        BS - 8,
        report.consumed_sources
    );
    assert!(dir.join("junkZq62.bin").exists());
    let _ = std::fs::remove_dir_all(&dir);
}

/// M4-62's control, and the reason the bound is a `min` rather than a
/// ban on spending a block-sized donor. A candidate that is exactly one
/// FULL interior block of the target has every one of its bytes in the
/// target, so merged coverage really is a proof about all of them and
/// the fully-donated arm must still fire. A bound that turned that off
/// would pass the row above and quietly restore the pre-F9 clutter this
/// arm exists to sweep.
#[test]
fn a_full_block_donor_is_still_proven_spent() {
    let dir = tmpdir("m462ctl");
    // A length that is a WHOLE number of blocks, so no slice of this
    // target is padded and every byte of the candidate below is one the
    // target genuinely carries. Writing the control any other way tests
    // the bound rather than the arm - the first cut of it gave the
    // candidate a padded tail of its own and correctly went unspent.
    let a = payload(BS * 4, 61);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    std::fs::write(dir.join("a.bin"), &a[..BS * 2]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // The split-post shape the fully-donated arm exists for: the back
    // half of the payload under a name no set speaks for.
    std::fs::write(dir.join("junkZq62full.bin"), &a[BS * 2..]).unwrap();
    let report = match repair_dir(&dir).expect("adoption repairs without recovery") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 2);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    assert_eq!(
        report.consumed_sources.len(),
        1,
        "a candidate every byte of which the target now carries must \
         still be reported spent: {:?}",
        report.consumed_sources
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// Wave-4 row M4-83 (31 Aug 2026): the content sniff's SIZE band in
/// [`collect_packet_files_bounded`], both ends of it.
///
/// The row predicted a FAIL - "a 48-byte hash-named index (hostile
/// truncated Main, or a tiny Creator-only file some tools emit) is
/// invisible" - and it is invisible, measured below. What the row did
/// not have is why that costs nothing: 64 IS [`par2::HEADER_LEN`], the
/// size of a packet header on its own, so a file one byte short of the
/// floor cannot carry a whole packet under any reading and collecting
/// it would add a file with nothing in it. Both halves are asserted
/// together on purpose - the floor and the parse - because the floor is
/// only defensible while the parse agrees with it, and a lane that
/// moves either number should have to look at the other.
///
/// So this is a PASS PIN and not a fix, and the row's own asymmetry
/// ("named `x.par2` of the same bytes still loads") stays exactly as it
/// is: a `.par2` under the floor loads and parses to nothing, which is
/// the same nothing, reached by a shorter route.
///
/// The other end is the row's second half, kept in a unit as it asked:
/// the ceiling is exercised through the `_bounded` entry with a small
/// `max_bytes` rather than by writing a gigabyte. Both arms of the
/// band are checked - extension AND sniff - because they are two
/// separate `if` limbs and a ceiling that lapsed on one of them would
/// still read as bounded from the other.
#[test]
fn the_sniff_size_band_is_the_packet_header_at_one_end_and_the_ceiling_at_the_other() {
    let dir = tmpdir("sniffband");
    // One byte short of a packet header, opening with the magic.
    let mut short = par2::MAGIC.to_vec();
    short.extend_from_slice(&[0u8; 55]);
    assert_eq!(short.len(), 63);
    std::fs::write(dir.join("Bq3fJm77ZsK"), &short).unwrap();
    let (files, sniffed) = collect_packet_files_bounded(&dir, MAX_PACKET_FILE_BYTES).unwrap();
    assert!(files.is_empty() && sniffed.is_empty(), "under the floor");
    // And nothing was lost by declining it: those bytes are not a
    // packet, whatever collected them.
    assert!(
        par2::Par2Set::set_id_of(&short).is_none(),
        "63 bytes cannot frame a packet, so the floor gives up nothing"
    );

    // A whole header with a self-consistent length IS collected.
    let mut exact = par2::MAGIC.to_vec();
    exact.extend_from_slice(&64u64.to_le_bytes());
    exact.extend_from_slice(&[0u8; 48]);
    assert_eq!(exact.len(), 64);
    std::fs::write(dir.join("Gx7tPz4Qe"), &exact).unwrap();
    let (files, sniffed) = collect_packet_files_bounded(&dir, MAX_PACKET_FILE_BYTES).unwrap();
    assert_eq!(files.len(), 1, "the floor is inclusive");
    assert_eq!(sniffed.len(), 1, "and it was found by content");

    // The ceiling, both limbs. 64 bytes is now over `max_bytes`.
    std::fs::write(dir.join("Nn5vQw2r.par2"), &exact).unwrap();
    let (files, sniffed) = collect_packet_files_bounded(&dir, 63).unwrap();
    assert!(
        files.is_empty() && sniffed.is_empty(),
        "past the ceiling nothing is taken, by extension or by content, got {files:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

#[cfg(test)]
mod slice_len_tests;

#[cfg(test)]
mod volshape_prefix_tests;

// The racing pin for the donation commit, in a child of this module
// rather than inline: unit_tests.rs sits 36 lines under the flat
// size-gate ceiling, and the child reaches the fixtures above through
// `use super::*` with no re-export.
#[path = "donate_claim_tests.rs"]
mod donate_claim_tests;

/// Wave-4 row X6-02: the adoption scan under a tree-named set - a child
/// module for the same two reasons as `padded_windows` above.
#[cfg(test)]
mod tree_adopt;
