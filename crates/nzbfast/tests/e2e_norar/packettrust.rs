//! What a PAR2 packet has to EARN before it is believed (M4-64, M4-65).
//!
//! Two rows, one seam, opposite ends of it. M4-64 is a complete FileDesc
//! that was ignored because the Main packet never mentioned its file id;
//! M4-65 is a complete recovery volume that was never even read, because
//! a three-byte prefix sat in front of its magic. In both the evidence
//! was on the wire, was well formed, and went unread - so an obfuscated
//! post kept its posted hash while the thing that could name it lay
//! beside it.
//!
//! M4-69 is the third: an IFSC entry that contradicts ITSELF about one
//! block, honest CRC beside a forged MD5, which turned a byte-exact file
//! into 100% damage and spent a reconstruct on intact bytes.
//!
//! A child of e2e_norar rather than a sibling, for that module's own two
//! reasons: the fixtures need its builders (`run_norar`, `payload`,
//! `Fixture::add_file_renamed_by_par2`), which a sibling could not
//! reach, and `mod.rs` was at 2,912 of its size-gate 3,000-line ceiling
//! on 30 Aug 2026 with several lanes appending to it. The M4-64 fixture reuses `par2dialect`'s packet
//! sealer rather than copying it: that module is the M4-21 half of this
//! same seam and the two must not drift into hand-copied siblings.

use super::*;

/// Add a FileDesc packet for `name`/`payload` to every blob, and to NO
/// Main packet's id list - an ORPHAN descriptor (M4-64).
///
/// par2cmdline cannot produce this: every file it is handed goes into
/// the recovery set and into Main. MultiPar and some rebuild tools emit
/// extra descriptors natively; this stands in for them. The Main packets
/// are untouched, which is the whole point - the row is about a
/// descriptor Main is SILENT about, as against M4-21's, which Main lists
/// in its verify-only half.
fn add_orphan_filedesc(data: &mut Vec<u8>, name: &str, payload: &[u8]) {
    let set_id = par2dialect::blob_set_id(data);
    let mut body = par2_file_id(payload, name).to_vec();
    let whole: [u8; 16] = md5::Md5::digest(payload).into();
    body.extend_from_slice(&whole);
    let h16: [u8; 16] = md5::Md5::digest(&payload[..payload.len().min(16384)]).into();
    body.extend_from_slice(&h16);
    body.extend_from_slice(&(payload.len() as u64).to_le_bytes());
    body.extend_from_slice(name.as_bytes());
    while !body.len().is_multiple_of(4) {
        body.push(0);
    }
    data.extend(par2dialect::par2_packet(
        set_id,
        b"PAR 2.0\0FileDesc",
        &body,
    ));
}

/// `par2 create`, then post every blob under an OBFUSCATED name - a
/// hash, no `.par2` extension - with `patch` applied to its bytes first.
///
/// The obfuscated post's real shape, and the only one where the content
/// sniff is load-bearing: nothing in the NZB, in a subject or in a yEnc
/// header says these articles are parity. Returns false when par2 is
/// not installed.
fn add_par2_obfuscated(
    fx: &mut Fixture,
    files: &[&str],
    art_size: usize,
    patch: impl Fn(&mut Vec<u8>),
) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg("-r20")
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for (i, p) in par2s.iter().enumerate() {
        let mut data = std::fs::read(p).unwrap();
        patch(&mut data);
        // A fixed-alphabet hash name, the shape an obfuscated poster
        // uses: no extension for any rule to key on.
        let posted = format!("Wt5nBq93Kd{i}");
        let tag = format!("{posted}-{}", fx.nzb_files.len());
        let segs =
            nzbkit::mock::make_file_articles(&posted, &data, art_size, &tag, &mut fx.articles);
        fx.nzb_files.push((posted, segs));
        std::fs::remove_file(p).unwrap();
    }
    true
}

/// M4-64 (30 Aug 2026): a FileDesc packet whose file id appears in
/// NEITHER half of the Main packet. `Par2Set::parse` walked Main's id
/// lists and resolved descriptors out of a map, so a complete, sealed,
/// self-consistent descriptor - name, length, whole-file MD5, md5-16k -
/// was parsed and then dropped on the floor because Main was silent
/// about it. An obfuscated post whose only honest name sat in one stayed
/// hashed, and nothing said a name had been read and discarded.
///
/// Measured red on the 30 Aug 2026 baseline at the parser: `Par2Set` for
/// a Main listing one id beside two extra FileDescs came back with one
/// file and an empty `nonrecovery`.
///
/// The fix gives it M4-21's answer, because the evidence is M4-21's: a
/// name plus a whole-file MD5 is a nomination the content finalizes, so
/// it joins `Par2Set::nonrecovery` and reaches `get::sfvname` under that
/// tier's own ambiguity and never-overwrite rules. Never `files` - that
/// list is the global slice index space repair lays exponents onto
/// positionally, and a member Main never counted has no slices in it.
#[tokio::test(flavor = "multi_thread")]
async fn an_orphan_filedesc_names_the_payload_it_describes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("nororphan");
    let covered = payload(120_000, 71);
    let extra = payload(90_000, 72);
    fx.add_file_renamed_by_par2("Covered.bin", "Jd4pWn62Xq0", &covered, 40_000);
    // On disk under its real name but NOT handed to `par2 create`, so
    // the set carries no parity for it and Main never counts it - which
    // is what makes its descriptor an orphan rather than M4-21's
    // verify-only member.
    fx.add_file_renamed_by_par2("Orphan.bin", "Sv8mHt31Zc4", &extra, 40_000);
    let staged = extra.clone();
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["Covered.bin"],
        40_000,
        move |d| {
            add_orphan_filedesc(d, "Orphan.bin", &staged);
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "orphan-descriptor post failed:\n{log}");
    // The recovery member is unaffected - a red above must not read as
    // "the whole post fell over".
    let got_c = std::fs::read(out.join("Covered.bin"))
        .unwrap_or_else(|e| panic!("the recovery member is missing: {e}\n{log}"));
    assert!(got_c == covered, "Covered.bin not byte-exact\n{log}");
    let got_o = std::fs::read(out.join("Orphan.bin")).unwrap_or_else(|e| {
        panic!(
            "the payload kept its posted hash - its FileDesc was parsed and \
             dropped because Main never listed the id: {e}\n{log}"
        )
    });
    assert!(got_o == extra, "Orphan.bin not byte-exact\n{log}");
    assert!(
        !out.join("Sv8mHt31Zc4").exists(),
        "the obfuscated source name survived beside the published one\n{log}"
    );
}

/// M4-65 (30 Aug 2026): an obfuscated post's recovery volumes carry a
/// hash name and no `.par2` extension, so a CONTENT sniff is the only
/// thing that can find them - and it demanded the packet magic at byte 0
/// exactly. A three-byte UTF-8 BOM in front of the index was enough: the
/// volume was never a packet file, the set never activated, and the
/// payload stayed hashed with its own parity sitting unread beside it.
///
/// Measured red on the 30 Aug 2026 baseline: `Covered.bin` did not exist
/// in the output and the hash name did.
///
/// The fix is a WINDOW rather than byte 0 - `par2::head_is_packet_file`,
/// one predicate shared by the in-stream sniff, the repair directory
/// walk and the repair catalog's relist, so the three cannot drift. A
/// gzipped volume is deliberately still out of reach; the reason is at
/// `par2::SNIFF_WINDOW`.
///
/// The CONTROL below is the same fixture with no prefix, so a red here
/// is attributable to the prefix and not to the fixture.
#[tokio::test(flavor = "multi_thread")]
async fn a_bom_in_front_of_a_hash_named_volume_still_activates_the_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for (case, prefix) in [("control", &[][..]), ("BOM", &[0xEF, 0xBB, 0xBF][..])] {
        let mut fx = Fixture::new(&format!("norarbom{}", prefix.len()));
        let data = payload(120_000, 73);
        fx.add_file_renamed_by_par2("Covered.bin", "Kp7vRt58Nb2", &data, 40_000);
        assert!(add_par2_obfuscated(
            &mut fx,
            &["Covered.bin"],
            40_000,
            |d| {
                let mut out = prefix.to_vec();
                out.extend_from_slice(d);
                *d = out;
            }
        ));
        let (log, ok, out) = run_norar(&fx).await;
        assert!(ok, "{case}: post failed:\n{log}");
        let got = std::fs::read(out.join("Covered.bin")).unwrap_or_else(|e| {
            panic!(
                "{case}: the payload kept its posted hash - the recovery set \
                 was never sniffed, so nothing could name it: {e}\n{log}"
            )
        });
        assert!(got == data, "{case}: not byte-exact\n{log}");
        assert!(
            !out.join("Kp7vRt58Nb2").exists(),
            "{case}: the obfuscated source name survived\n{log}"
        );
    }
}

/// Forge every IFSC entry's block MD5 while leaving its CRC32 - and the
/// FileDesc's whole-file MD5 - honest (M4-69).
///
/// par2cmdline cannot produce this: it computes both digests over the
/// same bytes. The shape stands in for a hostile or broken producer, and
/// it is the one an intact download cannot tell from total damage - the
/// CRC32s are true of the file on disk, so nothing in stream complains,
/// and every full check then fails on the MD5.
///
/// The IFSC body is a file id followed by 20-byte entries (MD5 then
/// CRC32 little-endian), so only the first 16 bytes of each entry move;
/// the packet is resealed, so every structural gate still passes it.
fn forge_ifsc_block_md5s(data: &mut Vec<u8>) -> usize {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0IFSC\0\0\0\0" || len < 64 + 16 + 20 {
            continue;
        }
        let body = start + 64 + 16;
        for e in (body..start + len).step_by(20) {
            data[e..e + 16].fill(0xAB);
        }
        reseal(data, start, len);
        hits += 1;
    }
    hits
}

/// M4-69 (30 Aug 2026): an IFSC entry carries a CRC32 and an MD5 of the
/// SAME block, so a file whose bytes satisfy one and not the other has
/// been handed an entry that describes two different blocks and
/// therefore describes neither. Every full block check required both, so
/// a set with honest CRCs and forged block MD5s reported a byte-exact
/// download as 100% damaged - a full reconstruct spent on intact bytes,
/// and Unrepairable where the parity fell short.
///
/// The answer is the authority rule this family runs on: the FileDesc
/// whole-file MD5 covers every byte of every block, so where it matches
/// it settles the question and no per-block claim may outrank it.
///
/// `NZBFAST_FAST_VERIFY=0` is not a contrivance, it is the CONFIGURATION
/// THE DEFECT LIVES IN, and saying which one is the point of running it.
/// In-stream fast verify is CRC32-only by design, so on the default
/// setting these forged MD5s are never consulted in stream and the row
/// does not fire there; what does consult them is every full check -
/// this knob, disk-fed and backfilled spans, and settle read-back of any
/// block no trusted span covered. Measured red here on the 30 Aug 2026
/// baseline: `[verify] ✘ Covered.bin - 2000/2000 blocks bad` over a
/// byte-exact file.
///
/// The assertion is on that LINE and not on the exit code, because the
/// exit code is not where this costs: the run still finished 0, having
/// summoned a whole repair over a file that needed none. What the row
/// predicts and this fixture is too small to reach is the far end of
/// that spend - a set whose parity cannot cover the damage it was told
/// about answers Unrepairable on an intact post.
///
/// The CONTROL is the same fixture with the IFSC left alone, so a red
/// here is attributable to the forgery and not to the configuration.
#[tokio::test(flavor = "multi_thread")]
async fn forged_block_md5s_do_not_repair_a_byte_exact_download() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for forge in [false, true] {
        let case = if forge { "forged IFSC" } else { "control" };
        let mut fx = Fixture::new(&format!("norarifsc{}", u8::from(forge)));
        let data = payload(120_000, 74);
        fx.add_file_renamed_by_par2("Covered.bin", "Bq3wLm76Tv9", &data, 40_000);
        assert!(add_par2_patched(
            &mut fx,
            20,
            &["Covered.bin"],
            40_000,
            move |d| {
                if forge {
                    assert!(forge_ifsc_block_md5s(d) > 0, "no IFSC packet to forge");
                }
            }
        ));
        let srv = nzbkit::mock::MockServer::start(fx.articles.clone(), Chaos::default()).await;
        let cfg = fx.write_config(&[&srv]);
        let nzb = fx.write_nzb();
        let out = fx.dir.join("out");
        let (log, ok) = tokio::task::spawn_blocking({
            let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
            move || run_get(&cfg, &nzb, &out, &[("NZBFAST_FAST_VERIFY", "0")])
        })
        .await
        .unwrap();
        assert!(ok, "{case}: post failed:\n{log}");
        let got = std::fs::read(out.join("Covered.bin"))
            .unwrap_or_else(|e| panic!("{case}: payload missing: {e}\n{log}"));
        assert!(got == data, "{case}: not byte-exact\n{log}");
        assert!(
            !log.contains("blocks bad"),
            "{case}: an intact file was reported damaged - the whole-file MD5 \
             covers every byte of every block and matched\n{log}"
        );
    }
}

/// Forge every IFSC entry's block CRC32 while leaving its MD5 - and the
/// FileDesc's whole-file MD5 - honest: the MIRROR of
/// [`forge_ifsc_block_md5s`] (M4-69's stated limit, closed 31 Aug 2026).
///
/// Same 20-byte entries; this moves the trailing 4 rather than the
/// leading 16, and the packet is resealed so every structural gate still
/// passes it.
fn forge_ifsc_block_crcs(data: &mut Vec<u8>) -> usize {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0IFSC\0\0\0\0" || len < 64 + 16 + 20 {
            continue;
        }
        let body = start + 64 + 16;
        for e in (body..start + len).step_by(20) {
            for b in &mut data[e + 16..e + 20] {
                *b ^= 0x5a;
            }
        }
        reseal(data, start, len);
        hits += 1;
    }
    hits
}

/// M4-69's stated limit, and it turned out to be the WORSE half.
///
/// Honest block MD5s beside forged CRC32s. Every block fails on the CRC,
/// so `check_block` returns before reaching the MD5 that would have
/// disagreed with it and nothing latches. The row predicted the outcome
/// would stay correct and cost only a wasted reconstruct. Measured
/// 31 Aug 2026 on the 30 Aug baseline, it does not: this fixture carries
/// 400 recovery blocks against 2000 slices, and the run ENDS -
/// `[verify] x Covered.bin - 2000/2000 blocks bad`,
/// `[repair] unrepairable: 2000 blocks needed, only 400 recovery blocks
/// in the NZB`, exit non-zero - with the byte-exact payload sitting in
/// the output directory. Any set under 100% redundancy fails that way,
/// which is very nearly all of them.
///
/// BOTH SETTINGS OF `NZBFAST_FAST_VERIFY` ARE RUN, and that is the point
/// of the loop rather than thoroughness. Its sibling above lives only at
/// `0`, because in-stream fast verify is CRC32-only and never consults
/// the MD5 those forge. This one is the other way round: the forged half
/// IS the CRC32, so it bites on the DEFAULT setting too, and was
/// measured red at both.
///
/// The CONTROL is the same fixture with the IFSC left alone, so a red is
/// attributable to the forgery and not to the configuration.
#[tokio::test(flavor = "multi_thread")]
async fn forged_block_crcs_do_not_fail_a_byte_exact_download() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for fast in ["0", "1"] {
        for forge in [false, true] {
            let case = format!(
                "{} at NZBFAST_FAST_VERIFY={fast}",
                if forge { "forged IFSC CRCs" } else { "control" }
            );
            let mut fx = Fixture::new(&format!("norarifsccrc{fast}{}", u8::from(forge)));
            let data = payload(120_000, 74);
            fx.add_file_renamed_by_par2("Covered.bin", "Bq3wLm76Tv9", &data, 40_000);
            assert!(add_par2_patched(
                &mut fx,
                20,
                &["Covered.bin"],
                40_000,
                move |d| {
                    if forge {
                        assert!(forge_ifsc_block_crcs(d) > 0, "no IFSC packet to forge");
                    }
                }
            ));
            let srv = nzbkit::mock::MockServer::start(fx.articles.clone(), Chaos::default()).await;
            let cfg = fx.write_config(&[&srv]);
            let nzb = fx.write_nzb();
            let out = fx.dir.join("out");
            let (log, ok) = tokio::task::spawn_blocking({
                let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
                move || run_get(&cfg, &nzb, &out, &[("NZBFAST_FAST_VERIFY", fast)])
            })
            .await
            .unwrap();
            assert!(
                ok,
                "{case}: a byte-exact download was failed on its own set's \
                 block checksums\n{log}"
            );
            let got = std::fs::read(out.join("Covered.bin"))
                .unwrap_or_else(|e| panic!("{case}: payload missing: {e}\n{log}"));
            assert!(got == data, "{case}: not byte-exact\n{log}");
            assert!(
                !log.contains("unrepairable"),
                "{case}: the job summoned a repair it could not fund, over a \
                 file the FileDesc MD5 proves intact\n{log}"
            );
            assert!(
                !log.contains("blocks bad"),
                "{case}: an intact file was reported damaged - every block \
                 arrived and every one failed, and the whole-file MD5 covers \
                 every byte of every block and matched\n{log}"
            );
        }
    }
}

/// The INODE of `p`, where the platform has one. `None` on Windows,
/// which builds these tests too - `std::os::unix::fs::MetadataExt` is a
/// unix path and `tools/win-portability-gate.py` refuses one in code
/// Windows compiles, so the cfg here is the exemption that gate names
/// rather than a way of hiding a portability problem. Every assertion
/// the caller makes with this has a portable twin beside it.
#[cfg(unix)]
fn inode_of(p: &std::path::Path) -> Option<u64> {
    use std::os::unix::fs::MetadataExt;
    std::fs::metadata(p).ok().map(|m| m.ino())
}
#[cfg(not(unix))]
fn inode_of(_p: &std::path::Path) -> Option<u64> {
    None
}

/// Every path under `root`, recursively. `remove_swept_file` parks a
/// recoverable delete by RENAMING into `<job>/.nzbfast-trash`, so this
/// is where a wrongly swept payload would be - inode intact, because a
/// rename keeps one.
fn walk_all(root: &std::path::Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(root) else {
        return out;
    };
    for e in rd.flatten() {
        let p = e.path();
        if p.is_dir() {
            out.extend(walk_all(&p));
        } else {
            out.push(p);
        }
    }
    out
}

/// M4-65's RESIDUE, measured and closed 31 Aug 2026: the widened sniff
/// FINDS a prefixed recovery volume and the sweep could not DELETE it.
///
/// The two rows landed within hours of each other. M4-65 moved the
/// content sniff to "the magic begins within `par2::SNIFF_WINDOW`";
/// M4-53 gave `par_cleanup` a shape test before it removes a spent
/// sniffed volume, and that walk began its packet chain at offset 0. So
/// a BOM-prefixed volume was collected, its parity used, and then kept
/// for ever under its posted hash name.
///
/// Verified at the predicate before anything was built: on the 31 Aug
/// tree `is_recovery_volume_shape` answered `false` for a BOM-prefixed
/// `par2 create` volume and `true` for the byte-identical unprefixed
/// one. The pin one level down is
/// `nzbkit::par2repair::unit_tests::volshape_prefix_tests::the_shape_test_draws_the_same_window_as_the_sniff_that_nominated_it`,
/// which is where the window edges and the payload-survives arms live;
/// this is the wire half, and it is the only one that can see the
/// engine's own deferral in the same run.
///
/// THE CONTROL IS THE ASSERTION, not decoration. What must be true is
/// that a prefix makes NO difference to what survives a finished job -
/// so both cases are held to the same surviving name set, and a red is
/// attributable to the prefix rather than to the fixture. The row is
/// not "some volumes went": it is "these two runs end identically".
///
/// A LEFTOVER KEPT WOULD NOT BE AN UNTOUCHED FILE, which is why the
/// safe-looking answer was the wrong one. `get::workers` reclassifies on
/// the same widened predicate and CANCELS the volume's remaining
/// articles, so what the old code left behind is a file this engine
/// holed itself and then abandoned in the output directory.
///
/// THE PAYLOAD PIN is M4-53's own ask - "the file is gone" and "the file
/// was swept and rebuilt from parity" look identical from outside,
/// because a par2 rebuild is byte-exact. Three things separate them and
/// none is the bytes: the trash staging directory must be empty of the
/// payload (a recoverable sweep RENAMES into it, so the original would
/// be sitting there), the surviving inode must not be one of the parked
/// ones where the platform has inodes at all, and the job must have
/// repaired nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_prefixed_recovery_volume_is_swept_like_an_unprefixed_one() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut survivors: Vec<(String, Vec<String>)> = Vec::new();
    for (case, prefix) in [("control", &[][..]), ("BOM", &[0xEF, 0xBB, 0xBF][..])] {
        let mut fx = Fixture::new(&format!("norarsweep65{}", prefix.len()));
        let data = payload(300_000, 74);
        fx.add_file_renamed_by_par2("Covered.bin", "Kp7vRt58Nb2", &data, 40_000);
        assert!(add_par2_obfuscated(
            &mut fx,
            &["Covered.bin"],
            40_000,
            |d| {
                let mut out = prefix.to_vec();
                out.extend_from_slice(d);
                *d = out;
            }
        ));
        let (log, ok, out) = run_norar(&fx).await;
        assert!(ok, "{case}: post failed:\n{log}");

        let got = std::fs::read(out.join("Covered.bin")).unwrap_or_else(|e| {
            panic!("{case}: the payload is not under its FileDesc name: {e}\n{log}")
        });
        assert!(got == data, "{case}: payload not byte-exact\n{log}");

        // Nothing was swept and rebuilt: the staging directory a
        // recoverable delete renames into holds no copy of the payload,
        // and the inode that survived is not one that was parked.
        let trash = fx.dir.join(".nzbfast-trash");
        let parked = walk_all(&trash);
        let live = inode_of(&out.join("Covered.bin"));
        for p in &parked {
            assert!(
                std::fs::read(p).map(|b| b != data).unwrap_or(true),
                "{case}: the payload itself was swept into {}\n{log}",
                p.display()
            );
            assert!(
                live.is_none() || inode_of(p) != live,
                "{case}: the surviving payload is a parked inode\n{log}"
            );
        }

        let mut names: Vec<String> = walk_all(&out)
            .iter()
            .map(|p| {
                p.strip_prefix(&out)
                    .unwrap_or(p)
                    .to_string_lossy()
                    .into_owned()
            })
            .collect();
        names.sort();
        assert!(
            !names.iter().any(|n| n.starts_with("Wt5nBq93Kd")),
            "{case}: a spent recovery volume survived under its posted \
             hash name - the sniff found it and the sweep could not see \
             it: {names:?}\n{log}"
        );
        survivors.push((case.to_string(), names));
    }
    let (a, b) = (&survivors[0], &survivors[1]);
    assert_eq!(
        a.1, b.1,
        "a prefix in front of the magic changed what a finished job \
         leaves behind: {} {:?} vs {} {:?}",
        a.0, a.1, b.0, b.1
    );
}

/// Forge every OTHER IFSC entry's block CRC32 - the PARTIAL half of
/// [`forge_ifsc_block_crcs`], and the shape the settle-side escalation
/// cannot reach by design.
fn forge_half_the_ifsc_block_crcs(data: &mut Vec<u8>) -> usize {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0IFSC\0\0\0\0" || len < 64 + 16 + 20 {
            continue;
        }
        let body = start + 64 + 16;
        for (k, e) in (body..start + len).step_by(20).enumerate() {
            if k % 2 == 0 {
                for b in &mut data[e + 16..e + 20] {
                    *b ^= 0x5a;
                }
            }
        }
        reseal(data, start, len);
        hits += 1;
    }
    hits
}

/// M4-69's mirror direction where the forgery is PARTIAL, which the
/// settle-side escalation cannot reach and which the row twice recorded
/// as costing only wasted spend. It does not.
///
/// That escalation (`live::LiveVerifier::finish_slot_from`) fires only
/// where EVERY block of a file is bad, which is the one shape whose
/// price is bounded by what it prevents. Forge HALF the entries and the
/// grid reports half the file damaged, the job asks for 1000 blocks
/// against the 400 the NZB carries, and `repair::shortfall_is_final`
/// decides on that arithmetic and returns BEFORE `verify_pass1` ever
/// takes a whole-file MD5. Measured 31 Aug 2026 on the tree that closed
/// the total case:
///
///     [verify] x Covered.bin - 1000/2000 blocks bad
///     [repair] unrepairable: 1000 blocks needed, only 400 recovery
///              blocks in the NZB
///
/// exit non-zero, with the payload byte-exact in the output directory.
/// The answer is the same authority rule one seam further on: a fourth
/// arm on that gate consults the FileDesc whole-file MD5 of the members
/// the grid claims damaged, and where they match, falls through to the
/// disk path - which then arbitrates correctly, as it always could have.
///
/// THE PAYLOAD AND THE ASSERTION ON THE ARM ARE BOTH LOAD-BEARING, and
/// each of them is a way this fixture would otherwise pass while the
/// defect was live.
///
/// `payloads::unique_payload` rather than the module's ordinary
/// `payload`, and this is a THIRD consequence of that helper's
/// periodicity, beside the two its own header already names (self-period
/// 131,072 and cross-seed sharing). `shortfall_is_final`'s THIRD arm
/// falls through wherever the set declares as many blocks twice as the
/// shortfall is wide, and `payload` is periodic enough to do exactly
/// that at par2's default 2000 blocks: measured 31 Aug 2026, the same
/// half-forgery built on it survives on `repeated_block_donor_possible`
/// alone, with the arm this fixture is about never consulted. A test
/// that passes for another arm's reason is a test that stops noticing -
/// and the 30 Aug fixture for the TOTAL case did exactly that for a day,
/// which is the whole reason this row was reopened.
///
/// The log assertion below is the other half: it proves it was THIS arm
/// that answered, so the fixture cannot quietly go back to passing for a
/// donor arm's reason if the payload is ever changed.
///
/// BOTH SETTINGS OF `NZBFAST_FAST_VERIFY`, for its sibling's reason:
/// the forged half is the CRC32, and in-stream fast verify is
/// CRC32-only, so this direction bites on the default setting too.
#[tokio::test(flavor = "multi_thread")]
async fn a_partial_crc_forgery_does_not_fail_a_byte_exact_download() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    for fast in ["0", "1"] {
        for forge in [false, true] {
            let case = format!(
                "{} at NZBFAST_FAST_VERIFY={fast}",
                if forge {
                    "half-forged IFSC CRCs"
                } else {
                    "control"
                }
            );
            let mut fx = Fixture::new(&format!("norarhalfcrc{fast}{}", u8::from(forge)));
            let data = payloads::unique_payload(120_000, 0x5b13_a401);
            fx.add_file_renamed_by_par2("Covered.bin", "Bq3wLm76Tv9", &data, 40_000);
            assert!(add_par2_patched(
                &mut fx,
                20,
                &["Covered.bin"],
                40_000,
                move |d| {
                    if forge {
                        assert!(
                            forge_half_the_ifsc_block_crcs(d) > 0,
                            "no IFSC packet to forge"
                        );
                    }
                }
            ));
            let srv = nzbkit::mock::MockServer::start(fx.articles.clone(), Chaos::default()).await;
            let cfg = fx.write_config(&[&srv]);
            let nzb = fx.write_nzb();
            let out = fx.dir.join("out");
            let (log, ok) = tokio::task::spawn_blocking({
                let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
                move || run_get(&cfg, &nzb, &out, &[("NZBFAST_FAST_VERIFY", fast)])
            })
            .await
            .unwrap();
            assert!(
                ok,
                "{case}: a byte-exact download was failed on arithmetic its \
                 own descriptor contradicts\n{log}"
            );
            let got = std::fs::read(out.join("Covered.bin"))
                .unwrap_or_else(|e| panic!("{case}: payload missing: {e}\n{log}"));
            assert!(got == data, "{case}: not byte-exact\n{log}");
            assert!(
                !log.contains("unrepairable"),
                "{case}: the job gave up over a file the FileDesc MD5 proves \
                 intact\n{log}"
            );
            if forge {
                assert!(
                    log.contains("whole-file MD5s their descriptors carry"),
                    "{case}: the run survived, but not through the arm this \
                     fixture is about - a donor arm answering first is how \
                     the total-forgery fixture passed for a day while this \
                     case was live\n{log}"
                );
            }
        }
    }
}
