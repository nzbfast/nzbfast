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
    let cat = PacketCatalog::build_lazy_bounded(&dir, cap).expect("list");
    assert_eq!(
        cat.packet_paths().count(),
        0,
        "an oversized file was cataloged: {:?}",
        cat.packet_paths().collect::<Vec<_>>()
    );
    // The bound talking, not a name or a parse failure.
    let cat = PacketCatalog::build_lazy_bounded(&dir, u64::MAX).expect("list");
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
        RepairStatus::Unrepairable { needed, have } => {
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

/// §293, the offline experiment: a DONOR directory - a failed
/// predecessor's output - completes a repair its own recovery set
/// cannot. The successor is a DIFFERENT post of the same release: its
/// own set id, its own block size (so not one checksum is shared with
/// whatever set the predecessor carried), a download that landed no
/// data files at all, and one recovery slice against thirteen missing
/// blocks. Baseline leg: Unrepairable, 13 needed, 1 held. Treatment
/// leg: every block adopted out of the donor - two files through the
/// whole-file fast path, the third found INSIDE a junk-named file at
/// an unaligned offset (the different-volume-cut shape only the
/// rolling-CRC scan can see) - and the donor's own files are
/// untouched and never reported consumed, because a donor is another
/// job's payload and the sweep is scoped to the repair dir.
#[test]
fn a_donor_directory_completes_a_repair_the_recovery_set_cannot() {
    let donor = tmpdir("donor-src");
    let dir = tmpdir("donor-dst");
    let f1 = payload(200, 11);
    let f2 = payload(300, 12);
    let f3 = payload(500, 13);
    std::fs::write(donor.join("f1.bin"), &f1).unwrap();
    std::fs::write(donor.join("f2.bin"), &f2).unwrap();
    // The third travels under a different cut: junk prefix, junk name.
    let mut cut = payload(37, 99);
    cut.extend_from_slice(&f3);
    std::fs::write(donor.join("9a3d1c.dat"), &cut).unwrap();

    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2), ("f3.bin", &f3)];
    let set_b = [7u8; 16];
    let bs = 96usize;
    std::fs::write(dir.join("set.par2"), par2_index(set_b, bs, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(set_b, bs, files, &[0]),
    )
    .unwrap();

    // Baseline: without the donor, the set is short by twelve slices.
    match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have } => {
            println!("§293 A/B baseline: Unrepairable, {needed} needed, {have} held");
            assert_eq!((needed, have), (13, 1));
        }
        other => panic!("baseline must be unrepairable, got {other:?}"),
    }

    // Treatment: the donor directory completes it.
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("donor repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    println!(
        "§293 A/B treatment: {} of 13 blocks adopted from the donor, {} rebuilt",
        report.blocks_adopted, report.blocks_rebuilt
    );
    assert_eq!(report.blocks_adopted, 13, "every block found on the donor");
    assert_eq!(
        report.blocks_rebuilt, 0,
        "the one recovery slice was never needed"
    );
    assert_eq!(
        report.consumed_sources,
        Vec::<PathBuf>::new(),
        "donor files are another job's payload - never offered for sweeping"
    );
    for (name, data) in files {
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap(),
            *data,
            "{name} landed byte-exact"
        );
    }
    assert_eq!(std::fs::read(donor.join("f1.bin")).unwrap(), f1);
    assert_eq!(std::fs::read(donor.join("f2.bin")).unwrap(), f2);
    assert_eq!(std::fs::read(donor.join("9a3d1c.dat")).unwrap(), cut);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// §293's do-not-hinder half: a donor carrying the WRONG bytes - the
/// repack shape, same file names, different content - donates nothing
/// and changes nothing. The verdict with the poisoned donor must be
/// BYTE-IDENTICAL to the verdict without any donor (same Unrepairable
/// arithmetic), the donor's own file untouched, and an unreadable
/// donor path in the same list is skipped rather than fatal. This is
/// the case that proves a wrong guess costs one scan and nothing else:
/// every adoption needs a per-block CRC32 match confirmed by MD5, so
/// foreign bytes cannot be adopted, and the whole-file MD5 backstop
/// stands behind even that.
#[test]
fn a_donor_with_wrong_bytes_donates_nothing_and_changes_nothing() {
    let donor = tmpdir("poison-src");
    let dir = tmpdir("poison-dst");
    let real = payload(260, 21);
    let files: &[(&str, &[u8])] = &[("f1.bin", &real)];
    // The repack: same name, same length, different bytes.
    let wrong = payload(260, 22);
    std::fs::write(donor.join("f1.bin"), &wrong).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();

    let baseline = match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have } => (needed, have),
        other => panic!("5 blocks missing, 1 slice held - must be short, got {other:?}"),
    };
    let ghost = donor.join("no-such-subdir");
    let with_poison =
        match repair_dir_with_donors(&dir, &[donor.clone(), ghost]).expect("poisoned run") {
            RepairStatus::Unrepairable { needed, have } => (needed, have),
            other => panic!("wrong bytes must not repair anything, got {other:?}"),
        };
    assert_eq!(
        with_poison, baseline,
        "a poisoned donor must leave the arithmetic exactly as it found it"
    );
    assert_eq!(
        std::fs::read(donor.join("f1.bin")).unwrap(),
        wrong,
        "and the donor's own file untouched"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// §293 plan-side arm: a WHOLE member found on a donor is placed in the
/// job's own directory under the SET's name, before a byte is fetched.
///
/// The three files are the three answers a real switch gets: one whole
/// and byte-exact (donated), one the same length with different bytes -
/// the repack shape - and one absent from the donor entirely. Only the
/// first may be placed, and the other two must leave the destination
/// untouched, because a plan that struck their articles out on a wrong
/// donor would have no way back: the payload would never be fetched.
#[test]
fn whole_members_are_donated_and_a_repack_shaped_donor_is_refused() {
    let donor = tmpdir("donate-src");
    let dir = tmpdir("donate-dst");
    let good = payload(260, 31);
    let repack_real = payload(320, 32);
    let repack_wrong = payload(320, 33);
    let absent = payload(200, 34);
    let files: &[(&str, &[u8])] = &[
        ("good.bin", &good),
        ("repack.bin", &repack_real),
        ("absent.bin", &absent),
    ];
    std::fs::write(donor.join("good.bin"), &good).unwrap();
    std::fs::write(donor.join("repack.bin"), &repack_wrong).unwrap();
    // A .par2 on the donor is never a candidate - the successor fetches
    // its own set, and the predecessor's is a different one.
    std::fs::write(donor.join("set.par2"), par2_index(SET, BS, files)).unwrap();

    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");
    let placed = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);

    assert_eq!(
        placed.iter().map(|d| d.name.as_str()).collect::<Vec<_>>(),
        ["good.bin"],
        "only the byte-exact member may be donated: {placed:?}"
    );
    assert_eq!(std::fs::read(dir.join("good.bin")).unwrap(), good);
    assert!(
        !dir.join("repack.bin").exists(),
        "a same-name same-length donor with different bytes must place NOTHING"
    );
    assert!(!dir.join("absent.bin").exists());
    assert_eq!(
        std::fs::read(donor.join("repack.bin")).unwrap(),
        repack_wrong,
        "and the donor's own files are read-only to this pass"
    );
    // No half-written temporaries survive a run.
    let leftovers: Vec<String> = std::fs::read_dir(&dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.ends_with(".donating"))
        .collect();
    assert!(
        leftovers.is_empty(),
        "temporaries left behind: {leftovers:?}"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// An absent donor directory, an unreadable one, and a destination that
/// already holds the member: all three donate nothing new and change
/// nothing. The first two are the §293 ownership rule - a donor is a
/// directory this job does not own, so a racing cleanup degrades to no
/// donation and never to an error - and the third is the re-run: the
/// member already in place is REPORTED (the plan must still strike its
/// articles) and copied nowhere.
#[test]
fn an_absent_donor_donates_nothing_and_a_member_already_in_place_is_reported_once() {
    let donor = tmpdir("donate-idem-src");
    let dir = tmpdir("donate-idem-dst");
    let data = payload(260, 41);
    let files: &[(&str, &[u8])] = &[("f1.bin", &data)];
    let index = par2_index(SET, BS, files);
    let set = par2::Par2Set::parse(&[&index]).expect("fixture parses");

    let ghost = donor.join("no-such-subdir");
    assert!(
        donate_whole_files(&set, std::slice::from_ref(&ghost), &dir).is_empty(),
        "an absent donor directory must donate nothing"
    );
    assert!(!dir.join("f1.bin").exists());

    std::fs::write(donor.join("f1.bin"), &data).unwrap();
    let first = donate_whole_files(&set, &[ghost.clone(), donor.clone()], &dir);
    assert_eq!(first.len(), 1, "the readable donor beside the ghost wins");
    assert_eq!(first[0].from, donor.join("f1.bin"));

    // Second pass over the same destination: same answer, and the
    // donor is not read again for it (the file is already right).
    let again = donate_whole_files(&set, std::slice::from_ref(&donor), &dir);
    assert_eq!(again.len(), 1, "a re-run reports the member already held");
    assert_eq!(
        again[0].from,
        dir.join("f1.bin"),
        "and credits it to the destination, not to a second copy"
    );
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), data);

    // A destination file that is NOT the member is left alone: an
    // in-flight fetch owns that inode.
    std::fs::write(dir.join("f1.bin"), payload(260, 42)).unwrap();
    assert!(
        donate_whole_files(&set, std::slice::from_ref(&donor), &dir).is_empty(),
        "a wrong-bytes destination is never overwritten by a donation"
    );
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// Sweep S3: the directory-level tolerance above, held at FILE level.
/// A donor file the walk listed but the read cannot open (the racing
/// delete-files cleanup, one step later; an unreadable file is its
/// deterministic stand-in - same `File::open` error, no timing) must
/// degrade to "no donation": the repair still completes when its own
/// recovery suffices, and lands on the ordinary shortfall arithmetic
/// when it does not - never on an I/O error. Both donor roads are
/// exercised: the whole-file fast path (candidate length matches the
/// missing target, so the head hash is what trips) and the sliding
/// scan (length matches nothing, so `scan_candidate`'s open is what
/// trips). Run as root the chmod bites nothing and the candidate is
/// just wrong bytes - every assertion still holds, only the error
/// path goes unexercised.
#[cfg(unix)]
#[test]
fn an_unreadable_donor_file_degrades_to_no_donation() {
    use std::os::unix::fs::PermissionsExt;
    let real = payload(260, 21);
    let files: &[(&str, &[u8])] = &[("f1.bin", &real)];

    // Recovery suffices: five slices missing, five held - the dead
    // donor file (length == the target's, so the fast path hashes it)
    // must not stop the rebuild.
    let donor = tmpdir("deadfile-src");
    let dir = tmpdir("deadfile-dst");
    let dead = donor.join("aaaa.dat");
    std::fs::write(&dead, payload(260, 99)).unwrap();
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+5.par2"),
        par2_volume(SET, BS, files, &[0, 1, 2, 3, 4]),
    )
    .unwrap();
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("a dead donor file must not fail the repair")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("recovery covers all five slices, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 0, "nothing readable to adopt");
    assert_eq!(report.blocks_rebuilt, 5, "recovery did the whole job");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), real);
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);

    // Recovery short: the same dead donor (length matching no target,
    // so it reaches the sliding scan) must leave the verdict at the
    // ordinary needed/have arithmetic, exactly as with no donor.
    let donor = tmpdir("deadfile2-src");
    let dir = tmpdir("deadfile2-dst");
    let dead = donor.join("aaaa.dat");
    std::fs::write(&dead, payload(100, 99)).unwrap();
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();
    match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("a dead donor file must not fail the shortfall verdict either")
    {
        RepairStatus::Unrepairable { needed, have } => {
            assert_eq!((needed, have), (5, 1), "the no-donor arithmetic, untouched")
        }
        other => panic!("one slice held against five missing, got {other:?}"),
    }
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// And the drop is per-FILE, not per-donation: a dead donor file
/// sorted ahead of a good copy in the same donor directory costs only
/// itself - the scan moves on and the good copy still donates
/// everything.
#[cfg(unix)]
#[test]
fn an_unreadable_donor_file_does_not_block_a_readable_one() {
    use std::os::unix::fs::PermissionsExt;
    let donor = tmpdir("deadpair-src");
    let dir = tmpdir("deadpair-dst");
    let real = payload(260, 21);
    let files: &[(&str, &[u8])] = &[("f1.bin", &real)];
    let dead = donor.join("aaaa.dat");
    std::fs::write(&dead, payload(260, 99)).unwrap();
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o000)).unwrap();
    std::fs::write(donor.join("zzzz.dat"), &real).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+1.par2"),
        par2_volume(SET, BS, files, &[0]),
    )
    .unwrap();
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("the dead file costs itself, not the repair")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("the good copy covers everything, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 5, "adopted from the readable copy");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), real);
    std::fs::set_permissions(&dead, std::fs::Permissions::from_mode(0o644)).unwrap();
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// Sweep S3's residue, the patch-time half: the adoption decision is
/// final, the donor file is then DELETED (the racing delete-files
/// cleanup landing one phase later, during the solve or the patch), and
/// the read that wants the donor's bytes must still be served - through
/// the handle [`adopt::pin_donor_sources`] held open at decision time.
/// The delete is issued between the pin and the read, which is the exact
/// window, made deterministic. No cfg arm on purpose: the platform claim
/// the pin rests on is that BOTH unix (an unlinked inode stays readable)
/// and Windows (std opens with FILE_SHARE_DELETE) serve a deleted file
/// through an open handle, so the same test body pins both.
#[test]
fn a_donor_vanishing_after_the_adoption_decision_still_serves_its_bytes() {
    let donor = tmpdir("pinwin-src");
    let bytes = payload(2 * BS, 41);
    let path = donor.join("gone.dat");
    std::fs::write(&path, &bytes).unwrap();
    let cands: Vec<(PathBuf, u64)> = vec![(path.clone(), bytes.len() as u64)];
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    adopted.insert(0, AdoptSrc { cand: 0, offset: 0 });
    adopted.insert(
        1,
        AdoptSrc {
            cand: 0,
            offset: BS as u64,
        },
    );
    let mut missing: Vec<usize> = Vec::new();
    let open = adopt::pin_donor_sources(&cands, &(0..1), &mut adopted, &mut missing);
    assert_eq!(open.len(), 1, "the referenced donor is pinned");
    assert_eq!(adopted.len(), 2, "nothing degraded");
    assert!(missing.is_empty());
    std::fs::remove_file(&path).unwrap();
    assert!(!path.exists(), "the path is really gone");
    let mut reader = CandReader {
        cands: &cands,
        open,
    };
    let got = reader
        .read(
            AdoptSrc {
                cand: 0,
                offset: BS as u64,
            },
            BS,
        )
        .expect("the held handle serves the unlinked bytes");
    assert_eq!(&got[..], &bytes[BS..2 * BS]);
    let _ = std::fs::remove_dir_all(&donor);
}

/// A donor that vanished BETWEEN the scan and the pin degrades exactly
/// as a scan-time vanish does (§293's ownership rule): the adoption is
/// dropped, its slices rejoin `missing` in ascending order (the solve's
/// row mapping consumes that order), and nothing errors - the caller's
/// needed/have arithmetic judges the shortfall from there.
#[test]
fn a_donor_unopenable_at_pin_time_degrades_to_no_donation() {
    let donor = tmpdir("pinmiss-src");
    let path = donor.join("never-there.dat");
    let cands: Vec<(PathBuf, u64)> = vec![(path, 4 * BS as u64)];
    let mut adopted: HashMap<usize, AdoptSrc> = HashMap::new();
    adopted.insert(7, AdoptSrc { cand: 0, offset: 0 });
    adopted.insert(
        3,
        AdoptSrc {
            cand: 0,
            offset: BS as u64,
        },
    );
    let mut missing: Vec<usize> = vec![1, 5];
    let open = adopt::pin_donor_sources(&cands, &(0..1), &mut adopted, &mut missing);
    assert!(open.is_empty(), "nothing to hold");
    assert!(adopted.is_empty(), "the vanished donor's adoptions dropped");
    assert_eq!(missing, vec![1, 3, 5, 7], "slices rejoin missing, sorted");
    let _ = std::fs::remove_dir_all(&donor);
}

/// End-to-end: the pin is WIRED into the directory driver - a donor
/// deleted while the repair is mid-patch no longer fails it. Two
/// junk-named donor files each carry a whole missing target, so the
/// fast path adopts every slice, nothing needs Reed-Solomon, and the
/// PATCH is the first reader of the donor bytes; a helper thread
/// deletes both donor files the moment the patch's first temp file
/// appears in the repair dir. With the pin the deletion is a non-event
/// at any interleaving, so this passes deterministically; without it
/// the patch's lazy open lands on an unlinked path (verified to bite
/// with the pin neutered - see the landing commit).
#[test]
fn a_donor_deleted_during_the_patch_no_longer_fails_the_repair() {
    use std::sync::atomic::{AtomicBool, Ordering};
    let donor = tmpdir("pinrace-src");
    let dir = tmpdir("pinrace-dst");
    let f1 = payload(5 * BS, 51);
    let f2 = payload(5 * BS, 52);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1), ("f2.bin", &f2)];
    std::fs::write(donor.join("aaaa.dat"), &f1).unwrap();
    std::fs::write(donor.join("zzzz.dat"), &f2).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    let done = std::sync::Arc::new(AtomicBool::new(false));
    let killer = {
        let (donor, dir, done) = (donor.clone(), dir.clone(), done.clone());
        std::thread::spawn(move || {
            while !done.load(Ordering::Relaxed) {
                let tmp_seen = std::fs::read_dir(&dir).is_ok_and(|rd| {
                    rd.flatten()
                        .any(|e| e.file_name().to_string_lossy().contains(".nzbfast-repair."))
                });
                if tmp_seen {
                    break;
                }
                std::hint::spin_loop();
            }
            let _ = std::fs::remove_file(donor.join("aaaa.dat"));
            let _ = std::fs::remove_file(donor.join("zzzz.dat"));
        })
    };
    let res = repair_dir_with_donors(&dir, std::slice::from_ref(&donor));
    done.store(true, Ordering::Relaxed);
    killer.join().unwrap();
    let report = match res.expect("a donor deleted mid-patch must not fail the repair") {
        RepairStatus::Repaired(r) => r,
        other => panic!("both files adoptable from the donor, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 10, "every slice adopted");
    assert_eq!(report.blocks_rebuilt, 0, "none rebuilt");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
    assert_eq!(std::fs::read(dir.join("f2.bin")).unwrap(), f2);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

/// §293: adoption and Reed-Solomon COMPOSE. A truncated donor covers
/// the head of the missing file, the recovery slices cover the tail,
/// and neither alone is enough - four blocks adopted, two rebuilt, the
/// landed file byte-exact. Pins that adopted blocks feed the solve as
/// present rather than crowding it out.
#[test]
fn adoption_and_recovery_slices_compose_on_one_file() {
    let donor = tmpdir("compose-src");
    let dir = tmpdir("compose-dst");
    let f1 = payload(6 * BS - 20, 31);
    let files: &[(&str, &[u8])] = &[("f1.bin", &f1)];
    // The donor carries only the first four blocks' bytes, junk-named.
    std::fs::write(donor.join("7fa2c1.dat"), &f1[..4 * BS]).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    std::fs::write(
        dir.join("set.vol0+2.par2"),
        par2_volume(SET, BS, files, &[0, 1]),
    )
    .unwrap();

    match repair_dir(&dir).expect("baseline runs") {
        RepairStatus::Unrepairable { needed, have } => assert_eq!((needed, have), (6, 2)),
        other => panic!("six missing, two held - must be short alone, got {other:?}"),
    }
    let report = match repair_dir_with_donors(&dir, std::slice::from_ref(&donor))
        .expect("composed repair runs")
    {
        RepairStatus::Repaired(r) => r,
        other => panic!("donor head + recovery tail must compose, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "the donor's four blocks");
    assert_eq!(report.blocks_rebuilt, 2, "and the recovery's two");
    assert_eq!(std::fs::read(dir.join("f1.bin")).unwrap(), f1);
    let _ = std::fs::remove_dir_all(&dir);
    let _ = std::fs::remove_dir_all(&donor);
}

#[test]
fn a_wholly_renamed_copy_is_adopted_and_reported_consumed() {
    let dir = tmpdir("adopt");
    let a = payload(200, 7);
    let files: &[(&str, &[u8])] = &[("a.bin", &a)];
    // The obfuscated-post shape: the payload exists only under a hash
    // name, the FileDesc name is absent, no recovery slices anywhere.
    std::fs::write(dir.join("0f9a7c"), &a).unwrap();
    std::fs::write(dir.join("set.par2"), par2_index(SET, BS, files)).unwrap();
    // The name gate skips the set (no FileDesc name on disk)...
    assert!(
        repair_present_sets(&dir)
            .expect("present-set walk")
            .is_empty(),
        "no declared name on disk means the plain entry point skips"
    );
    // ...and the renamed fallback attempts it anyway and succeeds.
    let outcomes = repair_present_or_renamed_sets(&dir).expect("fallback runs");
    assert_eq!(outcomes.len(), 1);
    assert_eq!(outcomes[0].names, ["a.bin"]);
    let report = match outcomes[0].status.as_ref().expect("set repairs") {
        RepairStatus::Repaired(r) => r,
        other => panic!("expected Repaired, got {other:?}"),
    };
    assert_eq!(report.blocks_adopted, 4, "every slice found in the copy");
    assert_eq!(report.files_created, ["a.bin"]);
    assert_eq!(
        report.consumed_sources,
        [dir.join("0f9a7c")],
        "the donor is a proven byte-for-byte copy, so the caller may sweep it"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
    // With the payload landed, the plain entry point now sees the set
    // and reports it clean.
    let again = repair_present_sets(&dir).expect("present-set walk");
    assert_eq!(again.len(), 1);
    assert!(
        matches!(again[0].status, Ok(RepairStatus::NoDamage)),
        "{:?}",
        again[0].status
    );
    let _ = std::fs::remove_dir_all(&dir);
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
        let crc_ok = hash_blocks_par(
            &|off, buf| crate::disk::read_exact_at(&f, buf, off),
            limit,
            meta.length,
            &meta.blocks,
            BS,
            4,
        )
        .unwrap();
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
        Ok(RepairStatus::Unrepairable { needed: 1, have: 0 }) => {}
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
