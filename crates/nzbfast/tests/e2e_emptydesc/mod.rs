//! Zero-length FileDescs - the VIDEO_TS placeholder shape of the no-RAR
//! deobfuscation family: a 0-byte placeholder (VIDEO_TS trees ship
//! them) whose real name lives ONLY in a PAR2 FileDesc. No content tier can ever claim it - there is no head to
//! hash - and it contributes zero damage, so before `get/emptydesc.rs`
//! the job finished "clean" with the name never landing and a "file
//! missing entirely" warning about a file that costs nothing to produce.
//!
//! A sibling-dir child of e2e.rs (the e2e_repair pattern); helpers via
//! `super::*`.
//!
//! THE FIXTURE IS PACKET SURGERY, NOT `par2 create` ALONE, and that is a
//! fact about the tool rather than a shortcut: par2cmdline SKIPS 0-byte
//! files on create ("Skipping 0 byte file", verified on this box), while
//! MultiPar - the creator most Windows posters use - includes them. So
//! the set is created over the real payload and a zero-length FileDesc
//! is then spliced in by hand: one new FileDesc packet, and the Main
//! packet's recovery-set list patched to name it. A zero-length member
//! adds no slices, so the recovery data and every other packet stay
//! valid exactly as written.

use super::*;
use md5::Digest;

const PKT_MAGIC: &[u8; 8] = b"PAR2\0PKT";
const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";

fn md5(b: &[u8]) -> [u8; 16] {
    md5::Md5::digest(b).into()
}

/// Splice a zero-length member named `name` into one .par2 file's bytes:
/// every Main packet copy gains its file id (inserted at the END of the
/// recovery-set id list, BEFORE any non-recovery ids, count bumped), and
/// one FileDesc packet for it is appended.
///
/// `whole` is the descriptor's WHOLE-FILE digest. An honest zero-length
/// descriptor declares the empty digest there, the same constant as its
/// first-16k hash; row M4-45 passes something else, which no zero-length
/// file can ever hash to. The 16k hash stays the empty digest either
/// way, so the FILE ID - which the spec derives from the 16k hash, the
/// length and the name, never from the whole-file hash - is the one an
/// honest descriptor for this name would carry. The malformed packet is
/// therefore well-formed in every respect except the single claim it
/// cannot possibly satisfy.
fn splice_zero_member_md5(par2: &[u8], name: &str, whole: [u8; 16]) -> Vec<u8> {
    let empty = md5(b"");
    let mut idsrc = Vec::new();
    idsrc.extend_from_slice(&empty);
    idsrc.extend_from_slice(&0u64.to_le_bytes());
    idsrc.extend_from_slice(name.as_bytes());
    let fid = md5(&idsrc);

    let mut desc = Vec::new();
    desc.extend_from_slice(&fid);
    desc.extend_from_slice(&whole); // whole-file md5
    desc.extend_from_slice(&empty); // md5 of the first min(16k, 0) bytes
    desc.extend_from_slice(&0u64.to_le_bytes());
    let mut nb = name.as_bytes().to_vec();
    while !nb.len().is_multiple_of(4) {
        nb.push(0);
    }
    desc.extend_from_slice(&nb);

    let repack = |set_id: &[u8; 16], ptype: &[u8; 16], body: &[u8]| -> Vec<u8> {
        let mut p = Vec::with_capacity(64 + body.len());
        p.extend_from_slice(PKT_MAGIC);
        p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
        p.extend_from_slice(&[0u8; 16]);
        p.extend_from_slice(set_id);
        p.extend_from_slice(ptype);
        p.extend_from_slice(body);
        let d = md5(&p[32..]);
        p[16..32].copy_from_slice(&d);
        p
    };

    let mut out = Vec::with_capacity(par2.len() + 128);
    let mut set_id: Option<[u8; 16]> = None;
    let mut off = 0usize;
    while off < par2.len() {
        assert_eq!(
            &par2[off..off + 8],
            PKT_MAGIC,
            "packet walk lost framing at {off}"
        );
        let len = u64::from_le_bytes(par2[off + 8..off + 16].try_into().unwrap()) as usize;
        let pkt = &par2[off..off + len];
        let sid: [u8; 16] = pkt[32..48].try_into().unwrap();
        set_id.get_or_insert(sid);
        if &pkt[48..64] == TYPE_MAIN {
            let mut body = pkt[64..].to_vec();
            let n = u32::from_le_bytes(body[8..12].try_into().unwrap());
            body[8..12].copy_from_slice(&(n + 1).to_le_bytes());
            // Insert after the last RECOVERY-set id: the count only
            // covers the front of the list, so appending at the very end
            // would land the new id among any non-recovery ids.
            let at = 12 + 16 * n as usize;
            body.splice(at..at, fid.iter().copied());
            out.extend(repack(&sid, TYPE_MAIN, &body));
        } else {
            out.extend_from_slice(pkt);
        }
        off += len;
    }
    let sid = set_id.expect("no packet in par2 bytes");
    out.extend(repack(&sid, b"PAR 2.0\0FileDesc", &desc));
    out
}

/// `Fixture::add_par2_obfuscated`, with a zero-length member spliced
/// into every produced .par2 file before it is posted. Hash subjects and
/// hash yEnc names, exactly like the parent builder - nothing reaching
/// the client says par2 anywhere.
fn add_par2_obfuscated_with_empty(
    fx: &mut Fixture,
    redundancy: u32,
    files: &[&str],
    empty_name: &str,
    art_size: usize,
) -> bool {
    add_par2_obfuscated_with_empty_md5(fx, redundancy, files, empty_name, md5(b""), art_size)
}

/// [`add_par2_obfuscated_with_empty`] with the spliced descriptor's
/// whole-file digest chosen by the caller - see
/// [`splice_zero_member_md5`].
fn add_par2_obfuscated_with_empty_md5(
    fx: &mut Fixture,
    redundancy: u32,
    files: &[&str],
    empty_name: &str,
    whole: [u8; 16],
    art_size: usize,
) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
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
        let data = splice_zero_member_md5(&std::fs::read(p).unwrap(), empty_name, whole);
        let hash = format!("Vd4{i:02}mRq7yWz");
        let tag = format!("obf-par2-{i}");
        let segs = make_file_articles(&hash, &data, art_size, &tag, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
        std::fs::remove_file(p).unwrap();
    }
    true
}

/// The commenter's second field case (r/usenet, 29 Aug 2026): a VIDEO_TS
/// placeholder - 0 bytes, real name only in the FileDesc, and here not
/// posted as articles AT ALL, which is what par2cmdline-less posters
/// produce (you cannot usefully post an empty file). The payload rides
/// fully obfuscated beside it, so the whole set exercises the
/// deobfuscation path: the payload is adopted by content hash and
/// renamed, and the zero-length member is MATERIALIZED - the MD5 of an
/// empty file is the descriptor's own, so creating it is the proof.
#[tokio::test(flavor = "multi_thread")]
async fn a_zero_length_filedesc_materializes_under_its_real_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("emptydesc");
    let data = payload(600_000, 41);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "w7RkQp2xVd9", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty(
        &mut fx,
        20,
        &["Real.Movie.2026.mkv"],
        "VTS_02_0.VOB",
        40_000
    ));
    assert!(
        !fx.nzb_files.iter().any(|(n, _)| n.contains(".par2")),
        "the test is void if any subject says par2"
    );

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        ok,
        "get failed on a clean post with an empty member:\n{log}"
    );
    let vts = std::fs::metadata(out.join("VTS_02_0.VOB"))
        .unwrap_or_else(|e| panic!("VTS_02_0.VOB never landed: {e}\n{log}"));
    assert_eq!(vts.len(), 0, "the placeholder must be empty\n{log}");
    assert!(
        log.contains("zero-length in the set"),
        "the zero-length tier never spoke:\n{log}"
    );
    assert!(
        !log.contains("file missing entirely"),
        "a file that landed must not be reported missing:\n{log}"
    );
    let moved = std::fs::read(out.join("Real.Movie.2026.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its real name: {e}\n{log}"));
    assert!(moved == data, "payload not byte-exact\n{log}");
}

/// The same set with the placeholder also POSTED - one empty yEnc
/// article under a hash name, the shape a poster who does ship empties
/// produces. The pairing tier should satisfy the descriptor from the
/// arrived file rather than minting a second one, and the directory must
/// end holding the real name.
#[tokio::test(flavor = "multi_thread")]
async fn a_posted_empty_file_pairs_with_the_zero_length_filedesc() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("emptydescpair");
    let data = payload(600_000, 43);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "g2LnXw8pKf5", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty(
        &mut fx,
        20,
        &["Real.Movie.2026.mkv"],
        "VTS_02_0.VOB",
        40_000
    ));
    // One 0-byte article, hash subject and hash yEnc name.
    let art = nzbkit::yenc::encode("n0ByTeQq7wX", 0, Some((1, 1)), 1, &[]);
    fx.articles
        .insert("<n0byte-1@mock>".to_string(), art.clone());
    fx.nzb_files.push((
        "n0ByTeQq7wX".to_string(),
        vec![("n0byte-1@mock".to_string(), art.len() as u64, 1)],
    ));

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        ok,
        "get failed on a clean post with a posted empty file:\n{log}"
    );
    let vts = std::fs::metadata(out.join("VTS_02_0.VOB"))
        .unwrap_or_else(|e| panic!("VTS_02_0.VOB never landed: {e}\n{log}"));
    assert_eq!(vts.len(), 0, "the placeholder must be empty\n{log}");
    assert!(
        log.contains("satisfied by the empty file posted as"),
        "the descriptor should pair with the ARRIVED empty file, not mint a second one:\n{log}"
    );
    assert!(
        !std::path::Path::new(&out.join("n0ByTeQq7wX")).exists(),
        "the posted hash name must be gone once the descriptor's name took its file:\n{log}"
    );
    assert!(
        !log.contains("file missing entirely"),
        "a file that landed must not be reported missing:\n{log}"
    );
}

/// X6-03 (CONFIRMED red at `5ecf41e10`, 31 Aug 2026): GH #63's rule
/// correctly keeps a slot's own TRUTHFUL posted name over a HASH-shaped
/// FileDesc name - but the pairing loop then marked the descriptor
/// landed anyway, with no file ever created under its OWN declared path.
/// The comment removed by the fix argued the descriptor was satisfied
/// either way because the slot's file IS its (empty) content - true
/// about the content and false about the OUTPUT: nothing lands at the
/// descriptor's own name, and on a disc-placeholder shape that name is
/// exactly the path a player opens.
///
/// The empty slot is posted under a real subject
/// (`hint_is_posted_name && stem_is_a_name`), and the spliced descriptor
/// declares an obfuscated name that `stem_is_a_name` refuses - GH #63's
/// own losing direction, so `filedesc_name_is_better` returns false and
/// the pairing gate refuses the rename. Both names must end up on disk,
/// empty, once the fix lands.
#[tokio::test(flavor = "multi_thread")]
async fn a_refused_rename_still_materializes_the_descriptors_own_path() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const HASH_NAME: &str = "aQ7wRp3ZmK9Ln5vXb2Tq";
    const TRUTHFUL_NAME: &str = "Bonus.Featurette.mp4";
    let mut fx = Fixture::new("emptydescrefuse");
    let data = payload(600_000, 59);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "hK4wRp92LnQ", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty(
        &mut fx,
        20,
        &["Real.Movie.2026.mkv"],
        HASH_NAME,
        40_000
    ));
    // The empty file, posted under a real subject - GH #63's own shape,
    // the truthful record the descriptor's hash name must not overwrite.
    let art = nzbkit::yenc::encode(TRUTHFUL_NAME, 0, Some((1, 1)), 1, &[]);
    fx.articles
        .insert("<emptytruthful-1@mock>".to_string(), art.clone());
    fx.nzb_files.push((
        TRUTHFUL_NAME.to_string(),
        vec![("emptytruthful-1@mock".to_string(), art.len() as u64, 1)],
    ));

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        ok,
        "get failed on a post whose subject beats the FileDesc name:\n{log}"
    );
    let truthful = std::fs::metadata(out.join(TRUTHFUL_NAME)).unwrap_or_else(|e| {
        panic!("{TRUTHFUL_NAME} (the slot's own kept name) never landed: {e}\n{log}")
    });
    assert_eq!(truthful.len(), 0, "the kept file must stay empty\n{log}");
    let descriptors_own = std::fs::metadata(out.join(HASH_NAME)).unwrap_or_else(|e| {
        panic!("{HASH_NAME} - the descriptor's OWN declared path - never landed: {e}\n{log}")
    });
    assert_eq!(
        descriptors_own.len(),
        0,
        "the descriptor's own path must be an empty file\n{log}"
    );
    assert!(
        !log.contains("file missing entirely"),
        "a descriptor materialized under its own name must not be reported missing:\n{log}"
    );
    let moved = std::fs::read(out.join("Real.Movie.2026.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its real name: {e}\n{log}"));
    assert!(moved == data, "payload not byte-exact\n{log}");
}

/// X6-05, the sibling above reached through the OTHER arm: the gate
/// ACCEPTS the descriptor's name, the rename runs - and
/// `PublishedNames::claim` pushes it onto a `{slot:03}-` form, so the
/// file lands somewhere the descriptor never declared. The pairing loop
/// marked it landed on the strength of the rename alone, the name left
/// the missing list, it was never charged so it never reached `unpriced`,
/// and the finish-time re-read had nothing to look for: rc=0 with the
/// structure file a player opens absent from its declared path.
///
/// The contest here is W4-17's file/directory topology clash, and it is
/// chosen over a fold twin on purpose - a twin needs a case-insensitive
/// volume to bite, and this bites on every filesystem. Two valid
/// FileDesc members that share no complete string: the real payload is a
/// flat member named `VIDEO_TS`, published as a LEAF by the settle pass
/// before this tier runs, and the placeholder is `VIDEO_TS/VTS_02_0.VOB`
/// underneath it. `free_for` refuses the placeholder because an ANCESTOR
/// of it is somebody's leaf, `claim` disambiguates, the rename succeeds,
/// and nothing is recorded in `failed` - so `unlanded_why` cannot see it
/// either. The empty slot is posted under a hash subject, which is what
/// keeps `filedesc_name_is_better` on the accepted side.
///
/// Both halves are asserted: the payload leaf must survive untouched
/// (nothing here may truncate a real file for a member that claims no
/// bytes) AND the job must not report success while the placeholder's
/// own path holds nothing.
#[tokio::test(flavor = "multi_thread")]
async fn an_accepted_rename_disambiguated_elsewhere_must_not_green_the_job() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // A flat member that is also the placeholder's parent directory.
    // `stem_is_a_name("VIDEO_TS")` is true (two tokens), so the settle
    // pass really does rename the payload onto it.
    const ANCESTOR: &str = "VIDEO_TS";
    const PLACEHOLDER: &str = "VIDEO_TS/VTS_02_0.VOB";
    let mut fx = Fixture::new("emptydescdisamb");
    let data = payload(600_000, 67);
    fx.add_file_renamed_by_par2(ANCESTOR, "Rq83wKp2Zn5", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty(
        &mut fx,
        20,
        &[ANCESTOR],
        PLACEHOLDER,
        40_000
    ));
    // The empty file, posted under a HASH subject - the accepted arm's
    // own shape, so the gate lets the descriptor's name win the rename.
    let art = nzbkit::yenc::encode("n0ByTeQq7wX", 0, Some((1, 1)), 1, &[]);
    fx.articles
        .insert("<n0bytedisamb-1@mock>".to_string(), art.clone());
    fx.nzb_files.push((
        "n0ByTeQq7wX".to_string(),
        vec![("n0bytedisamb-1@mock".to_string(), art.len() as u64, 1)],
    ));

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        std::fs::read(out.join(ANCESTOR)).unwrap_or_default() == data,
        "the real payload at the placeholder's ancestor name was destroyed or \
         never landed - a zero-length descriptor must never cost a file that \
         carries bytes\n{log}"
    );
    let own = std::fs::symlink_metadata(out.join(PLACEHOLDER));
    assert!(
        !own.is_ok_and(|m| m.is_file() && m.len() == 0),
        "the fixture is void: {PLACEHOLDER} really did land at its own path, so \
         the claim never disambiguated\n{log}"
    );
    assert!(
        !ok,
        "the job reported success with {PLACEHOLDER} published somewhere else \
         under a disambiguated name - a zero-length member charges no damage, so \
         its absence from its OWN path was invisible to the verdict\n{log}"
    );
    // Pinned by REASON and not only by rc, the same way W4-09's arm is.
    assert!(
        log.contains("never delivered") && log.contains(PLACEHOLDER),
        "the verdict must name the member it is failing for:\n{log}"
    );
}

/// X6-04 (CONFIRMED red at `5ecf41e10`, 31 Aug 2026): the materialize
/// arm's `AlreadyExists` probe used `std::fs::metadata`, which FOLLOWS a
/// symlink. A symlink preplanted at the descriptor's own path, pointing
/// at an empty file OUTSIDE the job, therefore answered `len() == 0`,
/// the descriptor was marked landed with nothing ever written inside the
/// job directory, and the outside sentinel was left as the job's only
/// record of the placeholder - the shape `land_duplicate_filedescs`
/// (X5-07, forty lines away in the same file) was already hardened
/// against with `symlink_metadata`.
///
/// Grade by inode, not by path: the fix must either refuse (leaving the
/// link and the descriptor unsatisfied) or replace it with a private
/// regular inode - never adopt the outside file as this job's own.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn a_symlink_at_the_materialize_path_is_never_followed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("emptydescsymlink");
    let data = payload(600_000, 61);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "wP83RqXn5tK", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty(
        &mut fx,
        20,
        &["Real.Movie.2026.mkv"],
        "VTS_02_0.VOB",
        40_000
    ));

    let out = fx.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    let outside = fx.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let sentinel = outside.join("sentinel.empty");
    std::fs::write(&sentinel, b"").unwrap();
    std::os::unix::fs::symlink(&sentinel, out.join("VTS_02_0.VOB")).unwrap();

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert!(
        !ok || {
            let md = std::fs::symlink_metadata(out.join("VTS_02_0.VOB")).unwrap();
            md.is_file() && !md.file_type().is_symlink() && md.len() == 0
        },
        "the job reported success (ok={ok}) while VTS_02_0.VOB is still a symlink \
         rather than a real in-output empty file:\n{log}"
    );
    let sentinel_md = std::fs::symlink_metadata(&sentinel).unwrap();
    assert!(
        sentinel_md.is_file() && sentinel_md.len() == 0,
        "the outside sentinel was touched - it must never be adopted as, or \
         corrupted through, the job's own file\n{log}"
    );
}

// ---------------------------------------------------------------- X5-07
//
// The OTHER tier in `get/emptydesc.rs`: the F10 duplicate-descriptor
// rescue, where two FileDescs declare identical `(MD5, length)` and only
// one copy is posted. Wave-5 row X5-07 - `land_duplicate_group` proved
// the SOURCE by path, tested the destination with `Path::exists`, which
// FOLLOWS symlinks, and so a DANGLING link planted at the duplicate's
// canonical name answered false and the plain-copy fallback wrote the
// file it pointed at: 180 KB OUTSIDE the job's output directory, at
// rc=0, under a log line saying the bytes had been verified. Measured
// red on origin/main 30 Aug 2026; the seam and the fix are written up at
// `land_duplicate_group`.
//
// The destination is post-derivable - descriptor names are the POST's to
// choose - so every arm here plants something at `out/Copy.Two.bin`
// before the job starts. What they hold the fix to is NOT "refuse when
// the name is occupied": a previous run's copy sitting there is the
// ordinary case and the duplicate still has to LAND. It is that the name
// is only ever reached by `rename`, which follows nothing and publishes
// nothing partial.

/// The F10 dedupe fixture: two FileDescs over identical content, one
/// obfuscated copy actually posted, `out/` made but left for the caller
/// to plant in. Returns the fixture and the payload bytes.
fn dedupe_fixture(tag: &str) -> (Fixture, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    let data = payload(180_000, 93);
    std::fs::write(fx.dir.join("Copy.One.bin"), &data).unwrap();
    std::fs::write(fx.dir.join("Copy.Two.bin"), &data).unwrap();
    assert!(fx.add_par2_opts(10, Some(10_000), &["Copy.One.bin", "Copy.Two.bin"], 40_000));
    std::fs::remove_file(fx.dir.join("Copy.One.bin")).unwrap();
    std::fs::remove_file(fx.dir.join("Copy.Two.bin")).unwrap();
    fx.add_file_obfuscated("Vd2wRq85XnB", "Vd2wRq85XnB", &data, 40_000);
    std::fs::create_dir_all(fx.dir.join("out")).unwrap();
    (fx, data)
}

/// One `get` run with the output directory left exactly as the caller
/// prepared it - the plant has to survive into the job.
async fn run_planted(fx: &Fixture) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    (log, ok, out)
}

/// Staging names this pass leaves behind on any path it does not clean
/// up. A landed job must leave none: the proof copy and every per-alias
/// temp are removed, and the only thing that reaches a descriptor's own
/// name is the rename.
fn staging_leftovers(out: &Path) -> Vec<String> {
    let Ok(rd) = std::fs::read_dir(out) else {
        return Vec::new();
    };
    rd.flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .filter(|n| n.starts_with(".nzbfast-dup-"))
        .collect()
}

/// X5-07, the arm that was red: a DANGLING symlink at the duplicate's
/// canonical name must not be followed, and the duplicate must still
/// land - as a regular inode inside the output directory, replacing the
/// link.
///
/// Both halves matter and the first without the second is not a fix. A
/// pass that simply refused an occupied name would keep the outside file
/// from being written and would also leave `Copy.Two.bin` on the missing
/// list, which is the row's other requirement - rc=0 means every
/// descriptor was satisfied - failed instead.
#[tokio::test(flavor = "multi_thread")]
#[cfg(unix)]
async fn a_dangling_alias_at_the_duplicate_name_is_replaced_and_never_followed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, data) = dedupe_fixture("dupebinddangle");
    let outside = fx.dir.join("outside");
    std::fs::create_dir_all(&outside).unwrap();
    let escape = outside.join("new.bin");
    std::os::unix::fs::symlink(&escape, fx.dir.join("out").join("Copy.Two.bin")).unwrap();

    let (log, ok, out) = run_planted(&fx).await;

    assert!(
        !escape.exists(),
        "the dedupe copy followed a dangling symlink at its destination and \
         created {} outside the output directory (rc ok={ok})\n{log}",
        escape.display()
    );
    assert!(ok, "the dedupe post failed with the alias planted:\n{log}");
    let md = std::fs::symlink_metadata(out.join("Copy.Two.bin"))
        .unwrap_or_else(|e| panic!("Copy.Two.bin is not there at all: {e}\n{log}"));
    assert!(
        md.is_file(),
        "the job reported success while Copy.Two.bin is not a regular \
         in-output file (still {md:?})\n{log}"
    );
    let got = std::fs::read(out.join("Copy.Two.bin")).unwrap();
    assert!(got == data, "the landed duplicate is not byte-exact\n{log}");
    assert_eq!(
        staging_leftovers(&out),
        Vec::<String>::new(),
        "staging copies survived the run\n{log}"
    );
}

/// The half a refuse-if-occupied "fix" would break, pinned so nobody
/// reaches for one: a file ALREADY at the duplicate's name is the
/// ordinary case - a previous run's copy - and the duplicate still has to
/// end up carrying the descriptor's declared content.
///
/// Planted with the right LENGTH and the wrong BYTES on purpose. Identical
/// content would let an earlier tier claim the descriptor off the disk
/// pass, and the test would then pass without the dedupe rescue running
/// at all; wrong bytes keep the name on the missing list, so this really
/// does exercise the landing.
#[tokio::test(flavor = "multi_thread")]
async fn a_stale_file_at_the_duplicate_name_is_replaced_by_the_proven_bytes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, data) = dedupe_fixture("dupebindstale");
    let stale = vec![0x5Au8; data.len()];
    assert!(stale != data);
    std::fs::write(fx.dir.join("out").join("Copy.Two.bin"), &stale).unwrap();

    let (log, ok, out) = run_planted(&fx).await;

    assert!(ok, "the dedupe post failed over a stale duplicate:\n{log}");
    let got = std::fs::read(out.join("Copy.Two.bin"))
        .unwrap_or_else(|e| panic!("Copy.Two.bin missing: {e}\n{log}"));
    assert!(
        got == data,
        "the stale file survived instead of being replaced by the \
         descriptor's declared content\n{log}"
    );
    assert_eq!(
        staging_leftovers(&out),
        Vec::<String>::new(),
        "staging copies survived the run\n{log}"
    );
}

/// The fault arm the row asks for, driven by a real failure rather than
/// by an injection hook: a DIRECTORY at the duplicate's name cannot be
/// renamed over, so the landing fails at its last step with the staged
/// bytes already written.
///
/// What must hold is that the failure is contained - no partial file
/// under the descriptor's name (the directory is still a directory), no
/// staging copy left in the output directory, and nothing written
/// outside it. The name stays on the missing list, which is the honest
/// answer: the job did not satisfy that descriptor.
#[tokio::test(flavor = "multi_thread")]
async fn a_landing_that_cannot_finish_leaves_no_partial_file_and_no_staging_copy() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (fx, _data) = dedupe_fixture("dupebindblocked");
    std::fs::create_dir_all(fx.dir.join("out").join("Copy.Two.bin")).unwrap();

    let (log, _ok, out) = run_planted(&fx).await;

    let md = std::fs::symlink_metadata(out.join("Copy.Two.bin"))
        .unwrap_or_else(|e| panic!("the blocking directory vanished: {e}\n{log}"));
    assert!(
        md.is_dir(),
        "a duplicate was published over the name a failed landing could not \
         reach ({md:?})\n{log}"
    );
    assert_eq!(
        staging_leftovers(&out),
        Vec::<String>::new(),
        "a failed landing left its staging copy behind\n{log}"
    );
}

/// Wave-4 row W4-09 (CONFIRMED red against origin/main, 30 Aug 2026):
/// a DIRTY output directory already holding a NONEMPTY file at the path
/// the set declares as a zero-length member.
///
/// The materialize tier refuses to truncate the occupant, which is
/// correct and is not the bug. The bug is the ACCOUNTING behind it: a
/// zero-length descriptor prices at `0.div_ceil(block_size)` = zero
/// blocks of damage, so its absence is invisible to every verdict.
/// Measured before the fix, the log said it in full - `already exists
/// and is not empty - left alone`, then `✘ VIDEO_TS/VTS_02_0.VOB - file
/// missing entirely` - and the job returned **rc=0**.
///
/// Both halves are asserted, because either one alone can be satisfied
/// by the wrong fix: the occupant must survive (never truncate a file
/// for a descriptor that claims no bytes) AND the job must not report
/// success while the descriptor is unsatisfied.
#[tokio::test(flavor = "multi_thread")]
async fn a_dirty_directory_must_not_green_an_unsatisfied_zero_length_member() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const PLACEHOLDER: &str = "VIDEO_TS/VTS_02_0.VOB";
    const OCCUPANT: &[u8] = b"an earlier run, or the user, left real bytes here\n";
    let mut fx = Fixture::new("emptydescdirty");
    let data = payload(600_000, 47);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "Kq7wZm31Tb9", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty(
        &mut fx,
        20,
        &["Real.Movie.2026.mkv"],
        PLACEHOLDER,
        40_000
    ));

    // The dirty half.
    let out = fx.dir.join("out");
    std::fs::create_dir_all(out.join("VIDEO_TS")).unwrap();
    let occupant = out.join(PLACEHOLDER);
    std::fs::write(&occupant, OCCUPANT).unwrap();

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert_eq!(
        std::fs::read(&occupant).unwrap_or_default(),
        OCCUPANT,
        "the pre-existing nonempty file at the placeholder path was destroyed - a \
         zero-length descriptor must never truncate a file\n{log}"
    );
    assert!(
        !ok,
        "the job reported success with the zero-length descriptor {PLACEHOLDER} \
         unsatisfied - a zero-length member charges no damage, so its absence was \
         invisible to the verdict\n{log}"
    );
    // Pinned by REASON and not only by rc: a job can fail for a dozen
    // things, and a fix that failed this one by accident is not a fix.
    assert!(
        log.contains("never delivered") && log.contains(PLACEHOLDER),
        "the verdict must name the member it is failing for:\n{log}"
    );
    // The other half of the ruling, on BOTH arms and not just M4-45's:
    // the payload that DID arrive is not collateral. Never Completed,
    // but never a lost download either. This arm takes the same path as
    // `a_lying_zero_length_descriptor_must_not_green_the_job` and
    // asserted nothing about it until 31 Aug 2026, so a later hardening
    // of the failure path that started quarantining the honest payload
    // would have been caught on one arm and not the other.
    assert!(
        std::fs::read(out.join("Real.Movie.2026.mkv")).unwrap_or_default() == data,
        "the honest payload beside the unsatisfied placeholder must still land \
         byte-exact\n{log}"
    );
}

/// Wave-4 row M4-45 - W4-09's hole reached from the other side, and the
/// reason the two are one lane. A MALFORMED descriptor: length 0 with a
/// whole-file MD5 that is not the empty digest, which no zero-length
/// file can ever hash to.
///
/// `land_zero_length_filedescs` correctly declines it (creating an empty
/// file would NOT be the proof its digest asks for), so it stays on the
/// missing list - and there it prices at zero blocks exactly as W4-09's
/// does, so the job could green with a member it never delivered and
/// never could. The ruling: nonzero completion, or
/// materialize-and-fail-verify. Never Completed.
///
/// AN EMPTY FILE IS PLANTED AT THE DESCRIPTOR'S PATH, and that is the
/// whole point of the fixture rather than set dressing. Without it the
/// probe passes on the weaker fact that nothing is there at all - which
/// is W4-09's arm, not this row's - and deleting the digest test
/// entirely leaves it green. Measured: with the plant, deleting that
/// test reddens this; without it, it does not. The plant is a shape a
/// real resume produces anyway (an earlier run's zero-length tier put
/// the placeholder there, and the descriptor is STILL lying about it),
/// and it is what forces the answer to come from the one arm this row
/// is about: no file of any kind can carry that digest at length 0.
#[tokio::test(flavor = "multi_thread")]
async fn a_lying_zero_length_descriptor_must_not_green_the_job() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("emptydesclying");
    let data = payload(600_000, 53);
    fx.add_file_renamed_by_par2("Real.Movie.2026.mkv", "Tz8bWn41Xk2", &data, 40_000);
    assert!(add_par2_obfuscated_with_empty_md5(
        &mut fx,
        20,
        &["Real.Movie.2026.mkv"],
        "VTS_03_0.VOB",
        // Not the empty digest, and not any digest of anything here -
        // the point is only that a 0-byte file cannot hash to it.
        [0x5au8; 16],
        40_000
    ));

    // See the note above: an EMPTY file already at the member's own path,
    // so "nothing is there" cannot be what fails this job.
    let out = fx.dir.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("VTS_03_0.VOB"), b"").unwrap();

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    assert_eq!(
        std::fs::metadata(out.join("VTS_03_0.VOB"))
            .map(|m| m.len())
            .ok(),
        Some(0),
        "the planted empty file must still be there - this row is about the VERDICT, \
         and nothing here may write, truncate or remove a thing\n{log}"
    );
    assert!(
        log.contains("malformed descriptor"),
        "the zero-length tier must decline a descriptor whose digest no empty file \
         can satisfy:\n{log}"
    );
    assert!(
        !ok,
        "the job reported success with a malformed zero-length descriptor never \
         satisfied - length 0 priced it at no damage\n{log}"
    );
    assert!(
        log.contains("never delivered") && log.contains("VTS_03_0.VOB"),
        "the verdict must name the member it is failing for:\n{log}"
    );
    // The other half of the ruling: the payload that DID arrive is not
    // collateral. Never Completed, but never a lost download either.
    assert!(
        std::fs::read(out.join("Real.Movie.2026.mkv")).unwrap_or_default() == data,
        "the honest payload beside the lying descriptor must still land byte-exact\n{log}"
    );
}
