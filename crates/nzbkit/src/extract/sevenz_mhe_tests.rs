//! TODO 358 item 9: header-encrypted (`-mhe`) STORED 7z sets, direct
//! mapped, and the in-stream candidate probe over a 7z's encrypted end
//! header. A child of `sevenz_map` so it reaches [`plan`] and
//! [`direct_mapped_parts`] the way that module's own tests do.
//!
//! Two kinds of fixture. The vendored writer builds the parametric ones
//! at test time (its `ArchiveWriter` encrypts the header by default once
//! AES is among the content methods). The committed ones are REAL 7-Zip
//! output, because what 7-Zip writes is the shape the field posts:
//! `crates/nzbkit-base/tests/fixtures/sevenz/mhe-store.7z.00{1,2,3}` and
//! `mhe-lzma2.7z.00{1,2,3}`, made on 9 Nov 2026 with 7-Zip 26.03 from the
//! two payloads [`fx_a`] and [`fx_b`] regenerate:
//!
//! ```text
//! 7zz a -mhe=on -pwp9-mhe-key -mx=0 -v20k  mhe-store.7z a.bin b.nfo
//! 7zz a -mhe=on -pwp9-mhe-key -mx=5 -v600b mhe-lzma2.7z a.bin b.nfo
//! ```
//!
//! `-mx=0` gives `Copy 7zAES:19`, non-solid, one folder per file (the
//! shape the map takes); `-mx=5` gives one solid `LZMA2 7zAES` folder
//! (the shape it leaves to the worker). The disk pass reads the same
//! committed sets in `nzbfast-unpack`'s `rarfix::sevenz` tests.

use super::*;

use crate::extract::testutil::*;

/// The committed fixtures' password.
const FX_PW: &str = "wp9-mhe-key";

/// The parametric fixtures' password.
const PW: &str = "wp9-writer-key";

/// `a.bin` of the committed sets: 50,001 bytes, so neither its length
/// nor its folder's padding sits on a cipher block.
fn fx_a() -> Vec<u8> {
    (0..50_001u32)
        .map(|i| (i.wrapping_mul(2_654_435_761) >> 13) as u8)
        .collect()
}

/// `b.nfo` of the committed sets: 1,234 bytes.
fn fx_b() -> Vec<u8> {
    (0..1_234u32)
        .map(|i| i.wrapping_mul(31).wrapping_add(7) as u8)
        .collect()
}

/// The committed split set `stem.7z.001..`, in part order.
fn fx_parts(stem: &str) -> Vec<Vec<u8>> {
    let dir = concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nzbkit-base/tests/fixtures/sevenz"
    );
    let mut out = Vec::new();
    for i in 1.. {
        match std::fs::read(format!("{dir}/{stem}.7z.{i:03}")) {
            Ok(b) => out.push(b),
            Err(_) => break,
        }
    }
    assert!(out.len() >= 2, "{stem}: the committed fixture must split");
    out
}

/// A header-encrypted Copy container from the vendored writer: Copy
/// under AES-256, header encrypted, `solid` choosing one folder for every
/// member or one per member.
fn mhe_copy(entries: &[(&str, &[u8])], pw: &str, solid: bool) -> Vec<u8> {
    mhe_with(
        entries,
        vec![
            sevenz_rust2::EncoderConfiguration::new(sevenz_rust2::EncoderMethod::COPY),
            sevenz_rust2::encoder_options::AesEncoderOptions::new(sevenz_rust2::Password::from(pw))
                .into(),
        ],
        solid,
    )
}

fn mhe_with(
    entries: &[(&str, &[u8])],
    methods: Vec<sevenz_rust2::EncoderConfiguration>,
    solid: bool,
) -> Vec<u8> {
    let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    w.set_encrypt_header(true);
    w.set_content_methods(methods);
    if solid {
        let ents = entries
            .iter()
            .map(|&(n, _)| sevenz_rust2::ArchiveEntry::new_file(n))
            .collect();
        let readers = entries
            .iter()
            .map(|&(_, d)| sevenz_rust2::SourceReader::new(d))
            .collect();
        w.push_archive_entries(ents, readers).unwrap();
    } else {
        for &(n, d) in entries {
            w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(n), Some(d))
                .unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

/// Feed every part of a split set in `order`, articles shuffled within
/// each part.
fn feed_parts(ex: &Extractor, stem: &str, parts: &[Vec<u8>], order: &[usize], seed: u64) {
    for &i in order {
        feed(
            ex,
            i,
            &format!("{stem}.7z.{:03}", i + 1),
            &parts[i],
            4096,
            seed + i as u64,
        );
    }
}

fn wait_until(what: &str, secs: u64, mut done: impl FnMut() -> bool) {
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    while !done() {
        assert!(std::time::Instant::now() < deadline, "{what}");
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
}

/// The base case: one header-encrypted Copy member whose length is not a
/// multiple of 16, password known up front. Mapped, decrypted span by
/// span, byte-exact, and nothing but the payload on disk.
#[test]
fn an_mhe_copy_container_maps_direct_and_decrypts() {
    let f = payload(300_001, 171);
    let arch = mhe_copy(&[("F.bin", &f)], PW, false);
    let dir = tmpdir("7z-mhe-one");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_password(PW);
    feed(&ex, 0, "release.7z", &arch, 7000, 171);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        direct_mapped_parts(&ex),
        1,
        "the map never took the AES chain"
    );
    assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
    assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Split, two members (two folders, two CBC streams), every arrival
/// order - including the ones where a part classifies after the promote
/// and takes `direct_attach`. A member's ciphertext crossing a part seam
/// becomes two pieces whose base is in ciphertext space, exactly like an
/// encrypted stored RAR member spanning two volumes.
#[test]
fn an_mhe_copy_split_set_maps_direct_in_every_order() {
    let a = payload(700_003, 172);
    let b = payload(90_017, 173);
    let arch = mhe_copy(&[("A.bin", &a), ("B.bin", &b)], PW, false);
    let parts = split_7z(&arch, 4);
    assert_eq!(parts.len(), 4, "fixture must really split");
    for (t, order) in [vec![0, 1, 2, 3], vec![3, 2, 1, 0], vec![1, 3, 0, 2]]
        .iter()
        .enumerate()
    {
        let dir = tmpdir(&format!("7z-mhe-split{t}"));
        let ex = Arc::new(Extractor::new(&dir, 4, true));
        ex.anchor();
        ex.set_password(PW);
        feed_parts(&ex, "big", &parts, order, 172);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 4, "order {t}");
        assert_eq!(std::fs::read(dir.join("A.bin")).unwrap(), a, "order {t}");
        assert_eq!(std::fs::read(dir.join("B.bin")).unwrap(), b, "order {t}");
        assert_eq!(
            dir_files(&dir),
            vec!["A.bin".to_string(), "B.bin".to_string()],
            "order {t}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Real 7-Zip output: the committed `-mhe -mx=0 -v20k` set, in three
/// orders, byte-exact against payloads regenerated here.
#[test]
fn a_7zz_mhe_store_split_set_maps_direct_byte_exact() {
    let parts = fx_parts("mhe-store");
    let (a, b) = (fx_a(), fx_b());
    for (t, order) in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0]]
        .iter()
        .enumerate()
    {
        let dir = tmpdir(&format!("7z-mhe-7zz{t}"));
        let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
        ex.anchor();
        ex.set_password(FX_PW);
        feed_parts(&ex, "mhe-store", &parts, order, 174);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), parts.len(), "order {t}");
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
        assert_eq!(std::fs::read(dir.join("b.nfo")).unwrap(), b, "order {t}");
        assert_eq!(
            dir_files(&dir),
            vec!["a.bin".to_string(), "b.nfo".to_string()],
            "order {t}"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The committed COMPRESSED `-mhe` set (solid LZMA2 under AES) is not
/// the map's shape: it decodes through the worker, one-pass, byte-exact.
#[test]
fn a_7zz_mhe_lzma2_split_set_extracts_through_the_worker() {
    let parts = fx_parts("mhe-lzma2");
    let dir = tmpdir("7z-mhe-lzma2");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    ex.set_password(FX_PW);
    let order: Vec<usize> = (0..parts.len()).rev().collect();
    feed_parts(&ex, "mhe-lzma2", &parts, &order, 175);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        direct_mapped_parts(&ex),
        0,
        "the map took a compressed chain"
    );
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), fx_a());
    assert_eq!(std::fs::read(dir.join("b.nfo")).unwrap(), fx_b());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// [`plan`] asked directly: an AES + Copy folder is placed only under a
/// password the header PROVED, as its whole padded ciphertext, with a
/// record that verifies the proven key and nothing else; the AES shapes
/// it cannot place keep declining.
#[test]
fn plan_takes_an_aes_copy_folder_only_under_a_proven_password() {
    let f = payload(40_001, 176);
    let open = |arch: &[u8], pw: &str| {
        sevenz_rust2::ArchiveReader::new(
            std::io::Cursor::new(arch.to_vec()),
            sevenz_rust2::Password::from(pw),
        )
        .unwrap()
        .archive()
        .clone()
    };
    let arch = mhe_copy(&[("F.bin", &f)], PW, false);
    let total = arch.len() as u64;
    let parsed = open(&arch, PW);

    // No proof, no AES folder - whatever the password in hand.
    assert!(
        plan(&parsed, 0, total, None).is_none(),
        "unproven AES planned"
    );

    let members = plan(&parsed, 0, total, Some(PW)).expect("the proven archive must plan");
    let [m] = &members[..] else {
        panic!("{members:?}");
    };
    assert_eq!(m.size, f.len() as u64);
    assert_eq!(m.packed, (f.len() as u64).next_multiple_of(16));
    assert!(m.start + m.packed <= total);
    assert!(
        m.crc.is_some(),
        "the stored CRC must ride to the settle gate"
    );
    let c = m.crypt.as_ref().expect("an AES member carries its record");
    assert!(c.check_verifies(&c.derive(PW).unwrap()), "the proven key");
    assert!(
        !c.check_verifies(&c.derive("some other password").unwrap()),
        "a different password's key must not verify"
    );

    // Two members in ONE AES folder: the second starts mid-chain.
    let g = payload(5_000, 177);
    let solid = mhe_copy(&[("F.bin", &f), ("G.bin", &g)], PW, true);
    let parsed = open(&solid, PW);
    assert_eq!(parsed.blocks.len(), 1, "the fixture must be solid");
    assert!(
        plan(&parsed, 0, solid.len() as u64, Some(PW)).is_none(),
        "a multi-member AES folder was planned"
    );

    // A compressed chain under AES: not Copy, whatever the proof.
    let lz = mhe_with(
        &[("F.bin", &f)],
        vec![
            sevenz_rust2::EncoderConfiguration::new(sevenz_rust2::EncoderMethod::LZMA2),
            sevenz_rust2::encoder_options::AesEncoderOptions::new(sevenz_rust2::Password::from(PW))
                .into(),
        ],
        false,
    );
    let parsed = open(&lz, PW);
    assert!(
        plan(&parsed, 0, lz.len() as u64, Some(PW)).is_none(),
        "LZMA2 under AES was planned"
    );

    // A member that does not fill its AES folder: the unclaimed tail
    // would be kept in RAM as header bytes, and the padding rule no
    // longer describes the stream.
    let mut m2 = open(&arch, PW);
    m2.files[0].size -= 1;
    assert!(
        plan(&m2, 0, total, Some(PW)).is_none(),
        "a member short of its folder was planned"
    );
}

/// The wrong password up front, no probe: the worker reports the
/// password verdict it always reported, and every part materializes
/// byte-exact for the disk pass - which is the fallback route's input.
#[test]
fn a_wrong_password_demotes_with_the_password_verdict() {
    let parts = fx_parts("mhe-store");
    let dir = tmpdir("7z-mhe-wrong");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    ex.set_password("not-the-password");
    feed_parts(&ex, "mhe-store", &parts, &[0, 1, 2], 178);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(!rep.fallbacks.is_empty(), "a wrong password shipped");
    assert!(
        rep.fallbacks
            .iter()
            .all(|(_, why)| why.contains("encrypted (password rejected)")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(direct_mapped_parts(&ex), 0);
    for (i, p) in parts.iter().enumerate() {
        let name = format!("mhe-store.7z.{:03}", i + 1);
        assert_eq!(&std::fs::read(dir.join(&name)).unwrap(), p, "{name}");
    }
    assert!(!dir.join("a.bin").exists(), "a member survived the demote");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// No password and no probe hook (a nested level, a CLI run without
/// one): exactly the pre-item-9 outcome.
#[test]
fn no_password_and_no_probe_demotes_as_before() {
    let parts = fx_parts("mhe-store");
    let dir = tmpdir("7z-mhe-nopw");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    feed_parts(&ex, "mhe-store", &parts, &[2, 0, 1], 179);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(
        !rep.fallbacks.is_empty()
            && rep
                .fallbacks
                .iter()
                .all(|(_, why)| why.contains("encrypted (no password)")),
        "{:?}",
        rep.fallbacks
    );
    for (i, p) in parts.iter().enumerate() {
        let name = format!("mhe-store.7z.{:03}", i + 1);
        assert_eq!(&std::fs::read(dir.join(&name)).unwrap(), p, "{name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// THE PROBE, IN-STREAM. No password in hand; the hook knows the
/// candidates. The head part and the tail part arrive first - the tail
/// is what a real download front-loads - and the map must fire BEFORE
/// the middle part arrives, which is the claim that the probe runs off
/// the tail rather than at finish. The hook sees the header's work factor
/// (7-Zip's 19) and a wrong candidate is tried and refused on the way.
#[test]
fn the_probe_finds_the_password_in_stream() {
    let parts = fx_parts("mhe-store");
    let dir = tmpdir("7z-mhe-probe");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    let depth = Arc::new(AtomicU64::new(u64::MAX));
    let d2 = depth.clone();
    ex.set_password_probe(Arc::new(move |probe| {
        d2.store(probe.kdf_depth() as u64, Ordering::SeqCst);
        ["wrong-first", FX_PW]
            .into_iter()
            .find(|c| probe.verify(c) == crate::rar::PwVerdict::Verified)
            .map(str::to_string)
    }));
    feed_parts(&ex, "mhe-store", &parts, &[0, 2], 180);
    wait_until("the probe never unlocked the set off its tail", 60, || {
        direct_mapped_parts(&ex) > 0
    });
    feed_parts(&ex, "mhe-store", &parts, &[1], 180);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(
        depth.load(Ordering::SeqCst),
        19,
        "the hook saw the KDF depth"
    );
    assert_eq!(direct_mapped_parts(&ex), parts.len());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), fx_a());
    assert_eq!(std::fs::read(dir.join("b.nfo")).unwrap(), fx_b());
    assert_eq!(
        dir_files(&dir),
        vec!["a.bin".to_string(), "b.nfo".to_string()]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A candidate that only turns up at the END (a sidecar or a typed
/// password that lands after the last article): every mid-run probe
/// misses, and `sevenz_finish`'s signal makes the parked worker probe
/// once more, unlock, and map before the set settles.
#[test]
fn a_late_candidate_still_unlocks_at_finish() {
    let parts = fx_parts("mhe-store");
    let dir = tmpdir("7z-mhe-late");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    let landed = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let l2 = landed.clone();
    ex.set_password_probe(Arc::new(move |probe| {
        if !l2.load(Ordering::SeqCst) {
            return None;
        }
        (probe.verify(FX_PW) == crate::rar::PwVerdict::Verified).then(|| FX_PW.to_string())
    }));
    feed_parts(&ex, "mhe-store", &parts, &[1, 2, 0], 181);
    assert_eq!(direct_mapped_parts(&ex), 0, "mapped with no candidate");
    landed.store(true, Ordering::SeqCst);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(direct_mapped_parts(&ex), parts.len());
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), fx_a());
    assert_eq!(std::fs::read(dir.join("b.nfo")).unwrap(), fx_b());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The probe also rescues the COMPRESSED shape: the password unlocks the
/// header and the worker decodes the set one-pass (no map - not Copy).
#[test]
fn the_probe_unlocks_a_compressed_mhe_set_for_the_worker() {
    let parts = fx_parts("mhe-lzma2");
    let dir = tmpdir("7z-mhe-probe-lz");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    ex.set_password_probe(Arc::new(|probe| {
        (probe.verify(FX_PW) == crate::rar::PwVerdict::Verified).then(|| FX_PW.to_string())
    }));
    let order: Vec<usize> = (0..parts.len()).collect();
    feed_parts(&ex, "mhe-lzma2", &parts, &order, 182);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
    assert_eq!(direct_mapped_parts(&ex), 0);
    assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), fx_a());
    assert_eq!(std::fs::read(dir.join("b.nfo")).unwrap(), fx_b());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A hook that hands back a candidate the archive does NOT accept (a
/// buggy or hostile hook): the worker's own re-check refuses it, nothing
/// is keyed with it, and the set demotes with the password verdict once
/// the download finishes - parts byte-exact.
#[test]
fn an_unverified_candidate_from_the_hook_is_refused() {
    let parts = fx_parts("mhe-store");
    let dir = tmpdir("7z-mhe-liar");
    let ex = Arc::new(Extractor::new(&dir, parts.len(), true));
    ex.anchor();
    ex.set_password_probe(Arc::new(|_| Some("a guess".to_string())));
    feed_parts(&ex, "mhe-store", &parts, &[0, 1, 2], 183);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(
        !rep.fallbacks.is_empty()
            && rep
                .fallbacks
                .iter()
                .all(|(_, why)| why.contains("encrypted (no password)")),
        "{:?}",
        rep.fallbacks
    );
    assert_eq!(direct_mapped_parts(&ex), 0);
    for (i, p) in parts.iter().enumerate() {
        let name = format!("mhe-store.7z.{:03}", i + 1);
        assert_eq!(&std::fs::read(dir.join(&name)).unwrap(), p, "{name}");
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 358 sweep, lane 3 item 4: an encrypted end header that could not
/// be READ is damage, not a password verdict. With the right password in
/// hand and one article inside the header's packed (encrypted) stream
/// never arriving, the open fails on a read the finish seal refuses -
/// and the library reports every read error under a password as
/// `MaybeBadPassword`, so the demote reason said "password rejected" and
/// sent the finish ladder after a password that was correct all along.
#[test]
fn a_missing_encrypted_header_article_is_not_a_password_verdict() {
    let f = payload(40_001, 185);
    let arch = mhe_copy(&[("F.bin", &f)], PW, false);
    let hc = crate::nameprobe::sevenz_encrypted_header(&mut std::io::Cursor::new(&arch))
        .expect("fixture is header-encrypted");
    let art = 16usize;
    let mid = (hc.pack_off + hc.pack_len / 2) as usize;
    let lost = mid / art;
    assert!(
        lost * art >= hc.pack_off as usize
            && (lost + 1) * art <= (hc.pack_off + hc.pack_len) as usize,
        "the lost article must sit wholly inside the packed header: {hc:?}"
    );
    let dir = tmpdir("7z-mhe-lost-header");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_password(PW);
    // The head in one piece, so the offset-0 sniff sees a whole start
    // header; the packed header lies far past it.
    assert!(hc.pack_off > 4096);
    ex.write(0, "release.7z", arch.len() as u64, 0, &arch[..4096])
        .unwrap();
    for i in 4096 / art..arch.len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let (s, e) = (i * art, ((i + 1) * art).min(arch.len()));
        ex.write(0, "release.7z", arch.len() as u64, s as u64, &arch[s..e])
            .unwrap();
    }
    let rep = finish_within(&ex, 60).unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "an incomplete set cannot extract: {:?} {:?}",
        rep.extracted,
        shape_of(&ex)
    );
    for (_, why) in &rep.fallbacks {
        assert!(
            !why.contains("password"),
            "missing bytes reported as a password verdict: {why}"
        );
    }
    assert!(!dir.join("F.bin").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The wider face of the same defect: the library also calls a failed
/// ENTRY read `MaybeBadPassword` whenever a password is set, plain
/// archive or not. A job password in hand plus one payload article that
/// never arrives, in an unencrypted container, must demote as missing
/// bytes - a password verdict here would be about a password the
/// archive never asked for.
#[test]
fn a_missing_payload_article_under_a_job_password_is_not_a_password_verdict() {
    // Noisy, so the packed container stays big enough to lose an article
    // from the middle of its payload.
    let f = noisy(300_001, 186);
    let arch = sevenz_archive(&[("F.bin", &f)], None, false);
    let art = 4096usize;
    let lost = arch.len() / art / 2;
    assert!(lost > 0 && arch.len() > 100_000, "{}", arch.len());
    let dir = tmpdir("7z-lost-payload-pw");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_password("a job password");
    for i in 0..arch.len().div_ceil(art) {
        if i == lost {
            continue;
        }
        let (s, e) = (i * art, ((i + 1) * art).min(arch.len()));
        ex.write(0, "release.7z", arch.len() as u64, s as u64, &arch[s..e])
            .unwrap();
    }
    let rep = finish_within(&ex, 60).unwrap();
    assert!(
        !rep.fallbacks.is_empty(),
        "an incomplete set cannot extract: {:?} {:?}",
        rep.extracted,
        shape_of(&ex)
    );
    for (_, why) in &rep.fallbacks {
        assert!(
            !why.contains("password"),
            "missing bytes reported as a password verdict: {why}"
        );
    }
    assert!(!dir.join("F.bin").exists());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 358 sweep, lane 3 item 1: the decompression-bomb gate's CONTENT
/// half reaches behind an encrypted header. The pre-open gate reads raw
/// end-header bytes and stands aside on ciphertext, so before this a
/// header-encrypted container decoded whatever its hidden blocks
/// declared - here an LZMA2 dictionary of 128 MiB out of ~1 KB of pack
/// (the committed `mhe-content-dict.7z`, pinned by nzbkit-base's
/// `the_committed_mhe_content_bomb_is_the_builders`). The worker must
/// refuse it by name once the header has decrypted, and demote with the
/// container byte-exact for the equally gated disk pass.
#[test]
fn an_encrypted_header_content_bomb_is_refused_after_the_header_decrypts() {
    let arch = std::fs::read(concat!(
        env!("CARGO_MANIFEST_DIR"),
        "/../nzbkit-base/tests/fixtures/sevenz/mhe-content-dict.7z"
    ))
    .unwrap();
    let dir = tmpdir("7z-mhe-content-bomb");
    let ex = Arc::new(Extractor::new(&dir, 1, true));
    ex.anchor();
    ex.set_password("mhe-bomb-key");
    feed(&ex, 0, "release.7z", &arch, 700, 184);
    let rep = finish_within(&ex, 60).unwrap();
    assert!(
        rep.fallbacks
            .iter()
            .any(|(_, w)| w.contains(crate::nameprobe::SEVENZ_REFUSE_CONTENT)),
        "the content gate's refusal must be the demote reason: {:?}",
        rep.fallbacks
    );
    assert!(!dir.join("a.bin").exists(), "nothing decoded");
    assert_eq!(std::fs::read(dir.join("release.7z")).unwrap(), arch);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// `windows-unit`, 9 Nov 2026: the test above failed there with the hole
/// read back as "password rejected" while it passed on the dev Mac. The
/// tag on the refused read was LOST, not misread: lzma-rust2's
/// `RangeReader::read_u8` drops its source's error and returns 1, so a
/// hole met by the range decoder surfaces as a short encoded header and
/// an untagged `MaybeBadPassword(UnexpectedEof)`, and which path meets
/// the hole is timing. This pins the mechanism without the timing: the
/// set itself remembers the refusal, so the verdict cannot depend on an
/// error surviving the decoder.
#[test]
fn a_refused_read_is_remembered_by_the_set_when_a_decoder_swallows_its_error() {
    use crate::extract::sevenz::{ChainedSeekReader, SevenZSet, sevenz_worker_reason};
    use std::io::Read;
    use std::sync::atomic::AtomicU64;

    let set = Arc::new(SevenZSet::new(1024, 4096));
    set.abort();
    assert!(!set.bytes_refused(), "nothing has been read yet");
    let mut r = ChainedSeekReader {
        set: set.clone(),
        pos: 0,
        base: 0,
        total: 4096,
        low_water: Arc::new(AtomicU64::new(0)),
    };
    // What the range decoder does with its source: the error is dropped.
    let _ = r.read(&mut [0u8; 16]).is_err();
    assert!(
        set.bytes_refused(),
        "a read the byte space refused must be recorded on the set itself"
    );

    // The library's own verdict after the swallow: untagged.
    let swallowed = || {
        sevenz_rust2::Error::MaybeBadPassword(std::io::Error::from(
            std::io::ErrorKind::UnexpectedEof,
        ))
    };
    let why = sevenz_worker_reason(swallowed(), set.bytes_refused());
    assert!(
        !why.contains("password"),
        "a refused read reported as a password verdict: {why}"
    );
    // Control: the same error with nothing refused is still a password
    // verdict - the record narrows the arm, it does not remove it.
    assert!(sevenz_worker_reason(swallowed(), false).contains("password rejected"));
}
