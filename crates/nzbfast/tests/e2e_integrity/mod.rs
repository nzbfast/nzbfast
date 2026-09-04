//! Wire-integrity conflict fixtures (30 Aug 2026).
//!
//! The no-RAR / nested corpora exercise NAMING almost exclusively: what
//! the engine calls a file. This module attacks the other axis - the
//! INTEGRITY signals on the wire (yEnc part CRC, `=ypart` ranges, NZB
//! segment structure) - by posting articles that are internally
//! inconsistent or that lie about coverage while some other article's
//! bytes are fine. None of these shapes appears in the capability corpus.
//!
//! Sibling-dir child of e2e.rs (the e2e_norar pattern); helpers via
//! `super::*`. Set `NORAR_DUMP_LOG=1` for the engine log + delivered
//! tree per case.

use super::*;

/// Overwrite the `pcrc32=`/`crc32=` hex in a built yEnc article's `=yend`
/// trailer with `lie` (8 hex chars), leaving the payload BYTES untouched.
/// A byte-perfect article that fails CRC verification - the "bytes right,
/// checksum lies" shape, which the mock's `Chaos::corrupt` (flips a
/// payload byte) cannot express.
fn lie_about_crc(article: &mut [u8], lie: &str) {
    assert_eq!(lie.len(), 8, "crc lie must be 8 hex chars");
    let needle = b"crc32=";
    let pos = article
        .windows(needle.len())
        .rposition(|w| w == needle)
        .expect("article has a crc32= field");
    let hex = pos + needle.len();
    article[hex..hex + 8].copy_from_slice(lie.as_bytes());
}

/// Build one truthful multi-part post, returning the per-part article
/// bytes so a caller can corrupt a trailer before insertion.
fn build_parts(name: &str, data: &[u8], art_size: usize) -> Vec<(u32, Vec<u8>)> {
    let total = data.len().div_ceil(art_size).max(1) as u32;
    data.chunks(art_size.max(1))
        .enumerate()
        .map(|(i, chunk)| {
            let part = i as u32 + 1;
            let begin = (i * art_size) as u64 + 1;
            (
                part,
                nzbkit::yenc::encode(name, data.len() as u64, Some((part, total)), begin, chunk),
            )
        })
        .collect()
}

/// Insert (part, article) pairs as one NZB file. Returns the message-ids
/// (with angle brackets) in part order, so a caller can target one for
/// `Chaos`.
fn push_file(fx: &mut Fixture, subject: &str, parts: &[(u32, Vec<u8>)]) -> Vec<String> {
    let tag = format!("{}-{}", subject.replace('.', "_"), fx.nzb_files.len());
    let mut segs = Vec::new();
    let mut ids = Vec::new();
    for (part, article) in parts {
        let id = format!("{tag}-{part}@mock");
        segs.push((id.clone(), article.len() as u64, *part));
        fx.articles.insert(format!("<{id}>"), article.clone());
        ids.push(format!("<{id}>"));
    }
    fx.nzb_files.push((subject.to_string(), segs));
    ids
}

/// Manifest-only PAR2 (FileDesc + IFSC, ZERO recovery volumes) over
/// `files`. The lightest full name+integrity source; nothing here can
/// repair, so a corrupted block is either caught (fail) or delivered
/// silently - exactly the discriminator these tests need.
fn add_index_only_par2(fx: &mut Fixture, files: &[&str], art_size: usize) -> bool {
    // par2cmdline refuses -r0, so create real recovery and then post ONLY
    // the index file (the same trick the no-RAR manifest-only fixtures
    // use): the index carries FileDesc + IFSC (block checksums) for
    // in-stream verification, and dropping the recovery volumes means
    // nothing on the wire can repair.
    let st = Command::new("par2")
        .args(["create", "-r5", "-q", "intgset"])
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let idx = fx.dir.join("intgset.par2");
    if !idx.exists() {
        return false;
    }
    let data = std::fs::read(&idx).unwrap();
    let tag = format!("intgset_par2-{}", fx.nzb_files.len());
    let segs = make_file_articles("intgset.par2", &data, art_size, &tag, &mut fx.articles);
    fx.nzb_files.push(("intgset.par2".to_string(), segs));
    // Drop every .par2 from disk so nothing is re-collected and only the
    // index we just posted is on the wire.
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "par2") {
            let _ = std::fs::remove_file(p);
        }
    }
    true
}

async fn run_chaos(fx: &Fixture, chaos: Chaos) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    if std::env::var("NORAR_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
        if let Ok(rd) = std::fs::read_dir(&out) {
            eprintln!("---- out dir ----");
            for e in rd.flatten() {
                let len = std::fs::metadata(e.path()).map(|m| m.len()).unwrap_or(0);
                eprintln!("  {} ({len} bytes)", e.file_name().to_string_lossy());
            }
            eprintln!("---- end ----");
        }
    }
    (log, ok, out)
}

async fn run(fx: &Fixture) -> (String, bool, PathBuf) {
    run_chaos(fx, Chaos::default()).await
}

fn delivered(out: &Path, name: &str) -> Option<Vec<u8>> {
    std::fs::read(out.join(name)).ok()
}

fn ramp(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(2654435761).wrapping_add(seed) >> 24) as u8)
        .collect()
}

// ---------------------------------------------------------------------
// I1: truthful bytes, LYING pcrc32, NO recovery, no other name source.
// The decoder rejects the article before its bytes reach any verifier;
// with nothing to repair from, the job must fail CLEANLY - no success,
// no full-length file masquerading as complete.
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn a_lying_crc_with_no_recovery_fails_cleanly() {
    let mut fx = Fixture::new("intg-crclie-nopar");
    let data = ramp(80_000, 7);
    let mut parts = build_parts("Liar.Crc.bin", &data, 20_000);
    lie_about_crc(&mut parts[1].1, "deadbeef");
    push_file(&mut fx, "abc123hash", &parts);

    let (_log, ok, out) = run(&fx).await;
    assert!(
        !ok,
        "a post that cannot be assembled must not report success"
    );
    assert!(
        delivered(&out, "Liar.Crc.bin").is_none(),
        "the unverified payload must be quarantined, not delivered under its name"
    );
}

// ---------------------------------------------------------------------
// I2: truthful bytes, lying pcrc32 on ONE small part, PAR2 with recovery
// that comfortably covers it. The lied part is dropped as damage; repair
// rebuilds it and the file lands byte-exact. Confirms the CRC-lie path
// composes with repair the way ordinary damage does.
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn a_lying_crc_under_recovery_repairs_byte_exact() {
    if !have_par2() {
        return;
    }
    let mut fx = Fixture::new("intg-crclie-par");
    // 12 parts of 10k; one lied part is ~8% of the file, well under r=40.
    let data = ramp(120_000, 11);
    std::fs::write(fx.dir.join("Liar.Crc.bin"), &data).unwrap();
    if !fx.add_par2(40, &["Liar.Crc.bin"], 10_000) {
        return;
    }
    let mut parts = build_parts("Liar.Crc.bin", &data, 10_000);
    lie_about_crc(&mut parts[4].1, "0badc0de");
    push_file(&mut fx, "zzz999hash", &parts);

    let (_log, ok, out) = run(&fx).await;
    assert!(
        ok,
        "an intact post with one CRC lie under r=40 must complete"
    );
    assert_eq!(
        delivered(&out, "Liar.Crc.bin").as_deref(),
        Some(data.as_slice()),
        "must land byte-exact"
    );
}

// ---------------------------------------------------------------------
// I3: THE SILENT-CORRUPTION PROBE.
//
// A well-formed post plus one ROGUE duplicate of part 2 (a distinct
// message-id, self-consistent CRC, GARBAGE bytes, same file range) - the
// shape a malformed or malicious NZB produces. The rogue is STALLED so
// the good part 2 lands and is verified Ok in-stream FIRST; the rogue
// then arrives and pwrites its garbage over the now-Ok blocks. PAR2 is
// manifest-only (zero recovery) so nothing can repair or mask the write.
//
// Correct outcome: the engine ignores the rogue and delivers the real
// file byte-exact. The bug this pins is the opposite - the raw write is
// unconditional and settle trusts the stale in-stream Ok, so a file the
// engine reports CLEAN is corrupt on disk.
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn a_stalled_rogue_duplicate_cannot_corrupt_a_verified_block() {
    if !have_par2() {
        return;
    }
    let mut fx = Fixture::new("intg-silentcorrupt");
    let data = ramp(90_000, 23);
    std::fs::write(fx.dir.join("Payload.bin"), &data).unwrap();
    if !add_index_only_par2(&mut fx, &["Payload.bin"], 30_000) {
        return;
    }
    let parts = build_parts("Payload.bin", &data, 30_000);
    let ids = push_file(&mut fx, "sil000hash", &parts);
    // Rogue duplicate of part 2: same yEnc name/size (same slot), same
    // [30000,60000) range, garbage bytes, its own consistent CRC.
    let garbage = vec![0xA5u8; 30_000];
    let rogue = nzbkit::yenc::encode(
        "Payload.bin",
        data.len() as u64,
        Some((2, 3)),
        30_001,
        &garbage,
    );
    let rogue_id = "<sil000hash-rogue2@mock>";
    fx.articles.insert(rogue_id.to_string(), rogue.clone());
    fx.nzb_files.last_mut().unwrap().1.push((
        rogue_id.trim_matches(|c| c == '<' || c == '>').to_string(),
        rogue.len() as u64,
        2,
    ));

    // Stall the rogue's first request so the good part 2 (`ids[1]`) is
    // fetched, written and verified before the rogue's bytes ever land.
    let chaos = Chaos {
        stall: [rogue_id.to_string()].into_iter().collect(),
        ..Default::default()
    };
    let (log, ok, out) = run_chaos(&fx, chaos).await;

    // The safety invariant: the job must NEVER report a clean download of
    // corrupt bytes. Before the settle force-readback (disk.rs had_rewrite
    // -> live.rs force_readback), the rogue's garbage overwrote a block the
    // in-stream verifier had already marked Ok from the good copy, verify
    // reported "0 bad", and the corrupt file shipped at rc=0 - measured
    // deterministically under this stall. Now the overlapping write forces
    // a read-back that re-hashes the actual disk bytes, so the outcome is
    // either the good bytes delivered (ok, byte-exact) or a clean failure
    // (rc!=0, corrupt payload quarantined) - never clean-but-wrong.
    let landed = delivered(&out, "Payload.bin");
    assert!(
        !(ok && landed.as_deref() != Some(data.as_slice())),
        "SILENT CORRUPTION: reported a clean download but the delivered bytes are wrong \
         (a rogue duplicate overwrote a verified-Ok block). log tail: {}",
        log.lines().last().unwrap_or("")
    );
    let _ = ids;
}

// ---------------------------------------------------------------------
// I4 (observational): a NO-PAR2 file whose yEnc `size=` is truthful, plus
// one rogue trailing part declaring `begin=` past the declared size. With
// no FileDesc there is nothing to hold the length to but the yEnc `size=`.
// Pins whether settle truncates an over-long no-set file to its declared
// size, or delivers the sparse tail (the no-PAR2 analogue of F5).
// ---------------------------------------------------------------------
#[tokio::test(flavor = "multi_thread")]
async fn a_no_par2_over_long_part_is_held_to_the_declared_size() {
    let mut fx = Fixture::new("intg-nopar-overlong");
    let data = ramp(60_000, 41);
    // Truthful post: size=60000, 2 parts of 30000.
    let mut parts = build_parts("Nopar.Over.bin", &data, 30_000);
    // Rogue trailing part: declares begin far past the declared size,
    // writing 4096 extra bytes at offset 1_000_000 (size stays 60000).
    let tail = vec![0xEEu8; 4096];
    let rogue = nzbkit::yenc::encode(
        "Nopar.Over.bin",
        data.len() as u64,
        Some((3, 3)),
        1_000_001,
        &tail,
    );
    parts.push((3, rogue));
    push_file(&mut fx, "novr00hash", &parts);

    let (_log, ok, out) = run(&fx).await;
    let landed = delivered(&out, "Nopar.Over.bin");
    assert!(
        ok,
        "an intact post must complete despite a self-contradictory extra part"
    );
    // The rogue part declared `=ybegin size=60000` yet wrote at offset
    // 1_000_000: self-contradictory, so its out-of-range bytes are dropped
    // and the delivered file is held to the declared size, byte-exact.
    // Before the workers.rs clamp this delivered 1,004,096 bytes at rc=0.
    assert_eq!(
        landed.as_deref(),
        Some(data.as_slice()),
        "a part writing past its own declared size must not balloon the delivered file"
    );
}

// ---------------------------------------------------------------------
// M4-14: OVERLAPPING `=ypart` ranges. Every other shape in this module
// is an article that lies about ITSELF; this is two articles that are
// each internally perfect and disagree with EACH OTHER about a stretch
// of the file. I3 above is the degenerate case - two articles claiming
// the IDENTICAL range - and the yEnc part header can express far more
// than that: `begin`/`end` are free byte offsets, so a poster's tooling
// can (and buggy tooling does) emit part 2 starting inside part 1.
//
// Two questions, and they are genuinely different:
//   * CONFLICTING bytes in the overlap, with no recovery set to break
//     the tie. Nothing on the wire can say which article is right, so
//     the one thing that must not happen is an answer that depends on
//     which one arrived last. `arrival_ordered` runs the SAME fixture
//     twice with the two orderings forced by stalling one article, and
//     compares the outcomes - a real oracle, where a single run could
//     only ever pin whatever this box happened to schedule.
//   * IDENTICAL bytes in the overlap. There is no conflict at all here,
//     so the file must simply complete byte-exact at its declared size -
//     the 10,000 bytes delivered twice must not become 10,000 bytes of
//     length, of progress, or of anything else.
// ---------------------------------------------------------------------

/// Build the overlap fixture: part 1 covers `[0, 40_000)`, part 2 covers
/// `[30_000, 60_000)`, and `clash` decides whether part 2's copy of the
/// shared 10,000 bytes agrees with part 1's. Both articles carry a
/// truthful `size=`, truthful `=ypart` ranges and their own correct CRC -
/// nothing here is malformed, which is the whole difficulty.
fn overlap_fixture(tag: &str, clash: bool) -> (Fixture, Vec<u8>, Vec<String>) {
    let mut fx = Fixture::new(tag);
    let data = ramp(60_000, 51);
    let mut second = data[30_000..].to_vec();
    if clash {
        for b in &mut second[..10_000] {
            *b = !*b;
        }
    }
    let parts = vec![
        (
            1u32,
            nzbkit::yenc::encode("Ovl.Range.bin", 60_000, Some((1, 2)), 1, &data[..40_000]),
        ),
        (
            2u32,
            nzbkit::yenc::encode("Ovl.Range.bin", 60_000, Some((2, 2)), 30_001, &second),
        ),
    ];
    let ids = push_file(&mut fx, "ovl000hash", &parts);
    (fx, data, ids)
}

/// M4-14a - CONFLICTING overlap with no recovery set. MEASURED RED on
/// the 30 Aug 2026 baseline (origin/main 8fbe1c3bd), exactly as the row
/// predicted: rc=0, 60,000 bytes delivered, and WHICH bytes depends on
/// which article was written last. The engine cannot tell which article
/// is right - both carry a truthful `size=`, an in-range `=ypart` and
/// their own correct CRC - and with no recovery set there is no third
/// opinion, so it silently keeps whichever landed last.
///
/// CLOSED 30 Aug 2026 as claim `ypart-overlap-conflict`. The paragraph
/// below still describes what the containment half asserts and why it
/// was written to survive the fix - it did, unedited. What CHANGED is
/// the last assertion: `ok` is now required to be FALSE.
///
/// WHAT THIS TEST ASSERTS is the half that was true then AND stays true
/// now the row is closed: the overlap resolves to ONE article's copy
/// whole, never to a torn mix of the two, and the delivered length is
/// the declared one. Those are the containment claims, and they are
/// deterministic. It still does NOT force an arrival ORDER - the fix is
/// order-independent by construction and `Chaos::stall` cannot pin one
/// without flaking, so the refusal below is simply required of every
/// run.
///
/// THE MEASUREMENT, and it needs no ordering control at all: this exact
/// fixture was run six times UNFORCED on 30 Aug 2026 and delivered
/// article 2's copy of the contested range five times and article 1's
/// once, every run rc=0 and 60,000 bytes. A completed download whose
/// CONTENTS depend on how the box was loaded. (Forcing the order by
/// stalling one article reproduces it too, but only most of the time -
/// `Chaos::stall` delays an article's FIRST request and the pool may
/// still fetch it on another connection, so an ordering assertion would
/// be a flake in the suite where the unforced count above is simply a
/// fact.)
///
/// HOW IT WAS FIXED, because the obvious version is wrong twice over.
/// The signal already existed - `disk::FileWriter::had_rewrite`,
/// written > covered - and settle already consulted it to force a PAR2
/// read-back. It is not enough on its own: a same-article hedge
/// duplicate re-writes IDENTICAL bytes and trips it too, so failing on
/// it would fail ordinary healthy jobs, and M4-14b below (an overlap
/// that agrees with itself, which must succeed) is the pin that says so.
/// Telling the two apart means COMPARING the overlapped bytes, which is
/// `FileWriter::write_article_at`: a coverage peek on the
/// article-delivery write that falls straight through when nothing
/// overlaps, and reads back and compares only when something does.
///
/// FIRST, the check must NOT go inside `write_at`. Two of that method's
/// six call sites legitimately rewrite a range with DIFFERENT bytes -
/// `extract/crypto.rs` writes plaintext over ciphertext, and the repair
/// path patches blocks - so a check there fails every encrypted or
/// repaired download. Hence a second door, taken by the delivery path
/// alone.
///
/// SECOND, the peek cannot be lock-free. Coverage is published by
/// `note_written` AFTER the pwrite, so two decode threads delivering the
/// two halves of an overlapping pair both peek an empty map and neither
/// sees the other - a 5-in-12 flake, measured, before
/// `FileWriter::article_gates` made the peek atomic with the span's own
/// pwrite. This test is the thing that caught it.
#[tokio::test(flavor = "multi_thread")]
async fn a_conflicting_ypart_overlap_resolves_whole_and_stays_in_range() {
    let (fx, data, _ids) = overlap_fixture("intg-ovlclash", true);
    let (log, ok, out) = run(&fx).await;
    let landed = delivered(&out, "Ovl.Range.bin");
    assert_eq!(
        landed.as_deref().map(<[u8]>::len),
        Some(60_000),
        "M4-14a: a conflicting overlap changed the delivered length\n{log}"
    );
    let got = landed.expect("a length was just asserted");
    // Outside the overlap both articles agree, so those bytes are the
    // payload whatever happened in the middle.
    assert!(
        got[..30_000] == data[..30_000] && got[40_000..] == data[40_000..],
        "M4-14a: bytes OUTSIDE the contested range were disturbed\n{log}"
    );
    // Inside it, the answer must be one article's copy WHOLE. A mix
    // would mean the two writes interleaved at sub-article granularity,
    // which no verifier downstream could ever unpick.
    let theirs: Vec<u8> = data[30_000..40_000].iter().map(|b| !b).collect();
    let mid = &got[30_000..40_000];
    assert!(
        mid == &data[30_000..40_000] || mid == theirs.as_slice(),
        "M4-14a: the contested range is a TORN mix of both articles, not \
         either one of them\n{log}"
    );
    // Honest exit - and this is the half the row was open for. On the
    // 30 Aug 2026 baseline `ok` was always true: the engine delivered
    // one of two different files, chosen by whichever article landed
    // last, and called it a clean download. Nothing here can adjudicate
    // the disagreement - no recovery set, no second opinion - so the
    // only honest verdict is a refusal. Closed by
    // `FileWriter::write_article_at` (claim `ypart-overlap-conflict`),
    // which compares the overlapped bytes and latches the contested
    // range for settle to fail on, in EITHER arrival order.
    assert!(
        !ok,
        "M4-14a: a post whose own articles disagree about a byte range \
         reported a clean download\n{log}"
    );
    drop(fx);
}

/// M4-14b - IDENTICAL bytes in the overlap. MEASURED GREEN on the
/// 30 Aug 2026 baseline: 60,000 bytes delivered byte-exact at rc=0. No
/// conflict exists, so the only ways to get this wrong are to let the
/// duplicated 10,000 bytes lengthen the file, or to count them twice
/// and call a 60,000-byte file 70,000 bytes' worth of progress - which
/// is what the length assertion below is really testing.
#[tokio::test(flavor = "multi_thread")]
async fn an_identical_ypart_overlap_completes_without_double_counting() {
    let (fx, data, _ids) = overlap_fixture("intg-ovlsame", false);
    let (log, ok, out) = run(&fx).await;
    assert!(
        ok,
        "an overlap that agrees with itself must complete:\n{log}"
    );
    let landed = delivered(&out, "Ovl.Range.bin");
    assert_eq!(
        landed.as_deref().map(<[u8]>::len),
        Some(60_000),
        "M4-14b: a re-sent 10,000-byte range changed the delivered \
         length\n{log}"
    );
    assert_eq!(
        landed.as_deref(),
        Some(data.as_slice()),
        "M4-14b: the delivered bytes are not the payload\n{log}"
    );
    drop(fx);
}

// ---------------------------------------------------------------- W4-11
//
// W4-11 (30 Aug 2026 Wave-4 adversarial matrix, CONFIRMED and then
// CORRECTED by measurement): an article that under-declares the file's
// total size. It belongs in this file rather than beside a naming
// corpus - the lie is a coverage claim on the wire, made by an article
// whose own `=ypart` range and CRC are perfectly consistent, exactly the
// axis this module's header names.
//
// The row predicted a static latch and the probes found an in-stream
// arrival RACE: the pipeline kept the FIRST NONZERO `size=` it saw, and
// that sizes the slot's head, whose MD5 is the only identity an
// obfuscated post has. Decoded first, `size=8192` on a 120 KB post gave
// an 8 KiB head against a FileDesc md5_16k covering 16 KiB, so the slot
// matched nothing and an INTACT file was priced `file missing entirely`
// - its bytes recovered only through a full-file adoption plus 2000
// blocks of parity spent for nothing.
//
// The stalled leg below IS an ordering assertion, which the note further
// up this file says `Chaos::stall` cannot pin without flaking. It can
// here, and the difference is the fix rather than the fixture: the
// answer no longer depends on which article wins, so a stall that fails
// to hold costs the leg nothing. The unstalled permutation beside it is
// the pin for exactly that - measured red about 1 run in 5 before the
// fix and 10/10 green after, fixture unchanged.

/// Post `data` as yEnc articles under a HASH yEnc name, with article
/// `lying_part` (1-based) declaring `size=` as `lie` while every other
/// part declares the true total. Every `=ypart` range and article CRC
/// stays self-consistent - only the declared TOTAL differs, which is
/// exactly what a real poster's tool gets wrong.
///
/// `lying_part = 0` is no part at all: the honest control.
///
/// Returns the message-ids in part order so a `Chaos` arm can stall the
/// honest ones and force the liar to decode first.
fn add_file_with_one_lying_size(
    fx: &mut Fixture,
    hash_name: &str,
    data: &[u8],
    art_size: usize,
    lying_part: u32,
    lie: u64,
) -> Vec<String> {
    let total_parts = data.len().div_ceil(art_size) as u32;
    let mut segs = Vec::new();
    let mut ids = Vec::new();
    for p in 0..total_parts {
        let off = p as usize * art_size;
        let chunk = &data[off..(off + art_size).min(data.len())];
        let declared = if p + 1 == lying_part {
            lie
        } else {
            data.len() as u64
        };
        let art = nzbkit::yenc::encode(
            hash_name,
            declared,
            Some((p + 1, total_parts)),
            off as u64 + 1,
            chunk,
        );
        let id = format!("{hash_name}-w411-{}@mock", p + 1);
        fx.articles.insert(format!("<{id}>"), art.clone());
        segs.push((id.clone(), art.len() as u64, p + 1));
        ids.push(format!("<{id}>"));
    }
    fx.nzb_files.push((hash_name.to_string(), segs));
    ids
}

/// W4-11: one non-head article under-declares the file's total size, and
/// it decodes FIRST. The honest articles are stalled, so the lie is
/// deterministically what the pipeline sees first.
///
/// The declared size is what sizes the slot's head, and the head's MD5
/// is the identity an obfuscated post has instead of a name: at 8192 the
/// head is 8 KiB where the FileDesc's md5_16k covers 16 KiB, so the slot
/// matched nothing and its file was priced WHOLLY MISSING. The bytes
/// still came back - through a full-file adoption plus 2000 blocks of
/// parity spent for nothing - which is why the `file missing entirely`
/// assertion is the one that carries this row rather than the byte
/// comparison above it.
#[tokio::test(flavor = "multi_thread")]
async fn an_under_declared_size_must_not_win_by_arrival_order() {
    if !have_par2() {
        eprintln!("w4_11: par2 unavailable - skipping");
        return;
    }
    // `unique_payload` at 40%, where this was `payload` at 10% until
    // 4 Sep 2026. The lying part-2 leaves 668 bad blocks of 2,000
    // (33.4%) and 10% is 200 recovery blocks, so the `ok` assertion
    // below was carried by `payload`'s 131,072-byte self-period rather
    // than by the set - `73 block(s) rebuilt, 595 adopted`. 40% is 800
    // blocks, 132 clear of the damage
    // (research/PAYLOAD-TRAP-PATH-DEPENDENT-CENSUS-2026-09-04.md).
    let data = crate::payloads::unique_payload(120_000, 61);
    let mut fx = Fixture::new("w411lie");
    std::fs::write(fx.dir.join("Real.Name.mkv"), &data).unwrap();
    assert!(fx.add_par2_obfuscated(40, &["Real.Name.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Real.Name.mkv")).unwrap();
    // Part 2 lies; parts 1 and 3 tell the truth and are stalled.
    let ids = add_file_with_one_lying_size(&mut fx, "Nq8xTr52Wm", &data, 40_000, 2, 8192);
    let mut chaos = Chaos::default();
    for (i, id) in ids.iter().enumerate() {
        if i != 1 {
            chaos.stall.insert(id.clone());
        }
    }

    let (log, ok, out) = run_chaos(&fx, chaos).await;

    let landed = std::fs::read(out.join("Real.Name.mkv")).unwrap_or_default();
    assert!(
        ok && landed == data,
        "an under-declared non-head article that decoded FIRST changed \
         the outcome: rc ok={ok}, Real.Name.mkv is {} bytes (want {})\n{log}",
        landed.len(),
        data.len()
    );
    assert!(
        !log.contains("file missing entirely"),
        "the intact obfuscated slot was priced WHOLLY MISSING because one \
         non-head article under-declared the total size; the bytes are \
         only recovered by a full-file adoption + rebuild\n{log}"
    );
}

/// W4-11 (order permutation): the same lie with NOTHING stalled.
///
/// This arm is codex's arrival-order half stated directly, and it is the
/// one whose behaviour the fix CHANGED IN KIND rather than in degree: on
/// the tree that confirmed the row it was measured red roughly 1 run in
/// 5 on an idle box - a genuine race, green only on the runs where the
/// honest head happened to win. It is kept unstalled deliberately, as
/// the pin that the answer no longer depends on who wins: measured 10/10
/// green after the fix, where the fixture is unchanged.
#[tokio::test(flavor = "multi_thread")]
async fn the_same_lie_with_no_order_control_is_no_longer_a_race() {
    if !have_par2() {
        eprintln!("w4_11 perm: par2 unavailable - skipping");
        return;
    }
    let data = payload(120_000, 61);
    let mut fx = Fixture::new("w411race");
    std::fs::write(fx.dir.join("Real.Name.mkv"), &data).unwrap();
    assert!(fx.add_par2_obfuscated(10, &["Real.Name.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Real.Name.mkv")).unwrap();
    add_file_with_one_lying_size(&mut fx, "Nq8xTr52Wm", &data, 40_000, 2, 8192);

    let (log, _ok, _out) = run_chaos(&fx, Chaos::default()).await;
    assert!(
        !log.contains("file missing entirely"),
        "the slot is priced wholly missing when the articles are left to \
         race, so the size lie still decides the outcome on some \
         orders\n{log}"
    );
}

/// W4-11 (baseline control): the SAME post with NO lying part - every
/// article declares the true total.
///
/// This is what isolates the size lie from the ordinary obfuscated-post
/// path. Without it the two legs above prove only that the fixture
/// fails, not that the DECLARED SIZE is the thing that moved.
#[tokio::test(flavor = "multi_thread")]
async fn control_no_lie_claims_the_slot_by_identity() {
    if !have_par2() {
        eprintln!("w4_11 control: par2 unavailable - skipping");
        return;
    }
    let data = payload(120_000, 61);
    let mut fx = Fixture::new("w411ctl");
    std::fs::write(fx.dir.join("Real.Name.mkv"), &data).unwrap();
    assert!(fx.add_par2_obfuscated(10, &["Real.Name.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Real.Name.mkv")).unwrap();
    // lying_part = 0 is no part at all: every article tells the truth.
    add_file_with_one_lying_size(&mut fx, "Nq8xTr52Wm", &data, 40_000, 0, 0);

    let (log, ok, out) = run_chaos(&fx, Chaos::default()).await;
    let landed = std::fs::read(out.join("Real.Name.mkv")).unwrap_or_default();
    assert!(ok && landed == data, "honest post failed\n{log}");
    assert!(
        !log.contains("file missing entirely"),
        "even the HONEST post loses the slot identity - the lying-size \
         legs prove nothing about the size lie\n{log}"
    );
}
