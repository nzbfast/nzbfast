//! Regression pins for the journal's IDENTITY invariants - Extreme Wave
//! 5 rows X5-01, X5-02, X5-04 and X5-05, verified red against
//! origin/main on 30 Aug 2026 and fixed the same day.
//!
//! One concern, written four ways: **the journal must identify itself by
//! INODE rather than by path, and must authenticate the bytes a resume
//! admits rather than measuring their length.** The four rows and the
//! seam each was measured at:
//!
//! * **X5-04** - [`Journal::open`] did a `File::open`, then an
//!   append-open, then a `File::create`, all by path and all following
//!   whatever the name resolved to. With a symlink planted at the
//!   journal leaf an outside file's bytes afterwards were literally
//!   `nzbfast-journal v1 <fingerprint>`; a hardlink did the same with no
//!   symlink anywhere to notice.
//! * **X5-05** - the same `File::open` blocked in the kernel, unbounded,
//!   on a FIFO at that path, before the job reached any networking.
//! * **X5-01** - [`Journal::remove`] was an unconditional path-based
//!   unlink, so a STALE generation retiring took the LIVE generation's
//!   journal with it: the restart parsed `completed = {}` and every
//!   recorded article refetched.
//! * **X5-02** - `restore` admitted an identity fragment on (path,
//!   length) alone. Bytes replaced at the same length were admitted and
//!   shipped, and so was a PREALLOCATED HOLE - which needs no adversary
//!   at all, being what a crash between the preallocation and the write
//!   leaves behind.
//!
//! The assertions are the verification probes' own, moved here from
//! `crates/nzbfast/tests/e2e_wave5/` (they reached these seams through
//! nzbkit's public surface anyway, so nothing is lost by pinning them
//! beside the code) plus the CONTROLS the probes did not carry. Those
//! controls are the half that keeps the file honest: every X5-02 pin
//! below asserts a refusal, and a refusal is also what a gate that
//! refuses EVERYTHING produces, so each is paired with the unmodified
//! case that must still be admitted.

use super::tests::frags_crc;
use super::*;

/// A scratch directory with `out/` (the job's) and `outside/`
/// (everything the job must never reach).
/// The guard comes back with the two paths because both live under it:
/// handing back bare `PathBuf`s left one `$TMPDIR` entry per tag per run
/// forever, 3,501 of the 66,095 leaked entries measured on the dev Mac
/// on 31 Aug 2026. See `crates/nzbkit/tests/scratch/mod.rs`.
fn dirs(tag: &str) -> (crate::testscratch::ScratchDir, PathBuf, PathBuf) {
    let base = crate::testscratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbfast-jid-{tag}-{}", std::process::id())),
    );
    let out = base.join("out");
    let outside = base.join("outside");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::create_dir_all(&outside).unwrap();
    (base, out, outside)
}

/// Bytes an X5-04 sentinel starts with. Any change to the file is the
/// failure, so the content only has to be recognisable.
///
/// `#[cfg(unix)]` because every one of its five uses is inside one of
/// the two symlink tests below, which are unix-only - a symlink is how
/// the sentinel is reached at all. Without it this is `dead_code` on
/// Windows, and `dead_code` is a rustc lint judged in every build, so
/// it took windows-clippy red on main (run 33337951404, 30 Aug 2026)
/// while every host gate stayed green. Not `#[expect]`: the lint fires
/// only in a configuration this box is not.
#[cfg(unix)]
const SENTINEL: &[u8] = b"SENTINEL - nothing in the job may touch this inode\n";

/// A payload with NO repeating period inside the sizes used here. The
/// obvious `(i as u8) * 31 + seed` wraps every 256 bytes, so a 8 KiB
/// buffer built that way has two byte-identical halves - and the
/// multi-fragment ordering pin below cannot see a reversed hash order
/// over halves that are the same bytes. Measured: that fixture left the
/// reversal mutation alive.
fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| {
            let i = i as u64;
            (i.wrapping_mul(2_654_435_761) >> 13) as u8 ^ seed
        })
        .collect()
}

// ---------------------------------------------------------------- X5-04

/// A journal path that is a SYMLINK to an outside file must be refused
/// before anything is written.
#[cfg(unix)]
#[test]
fn a_symlinked_journal_path_must_not_reach_an_outside_inode() {
    let (_scratch, out, outside) = dirs("sym");
    let sentinel = outside.join("sentinel.txt");
    std::fs::write(&sentinel, SENTINEL).unwrap();
    std::os::unix::fs::symlink(&sentinel, out.join(JOURNAL_LEAF)).unwrap();

    let opened = Journal::open(&out, b"<nzb/>").is_ok();

    let after = std::fs::read(&sentinel).unwrap_or_default();
    assert_eq!(
        after,
        SENTINEL,
        "the outside sentinel was rewritten through the journal symlink \
         (Journal::open returned ok={opened}); its bytes are now {:?}",
        String::from_utf8_lossy(&after)
    );
    assert!(!opened, "a symlinked journal leaf must be a typed refusal");
}

/// A HARDLINK is a second directory entry for one inode, so no open flag
/// can see it - the link count is the only tell, and a truncate through
/// the alias destroys the sentinel with nothing anywhere to notice.
#[cfg(unix)]
#[test]
fn a_hardlinked_journal_path_must_not_reach_an_outside_inode() {
    use std::os::unix::fs::MetadataExt as _;
    let (_scratch, out, outside) = dirs("hard");
    let sentinel = outside.join("sentinel.txt");
    std::fs::write(&sentinel, SENTINEL).unwrap();
    let ino_before = std::fs::metadata(&sentinel).unwrap().ino();
    std::fs::hard_link(&sentinel, out.join(JOURNAL_LEAF)).unwrap();

    let opened = Journal::open(&out, b"<nzb/>").is_ok();

    let md = std::fs::metadata(&sentinel).unwrap();
    assert_eq!(md.ino(), ino_before, "sentinel inode changed");
    assert_eq!(
        std::fs::read(&sentinel).unwrap_or_default(),
        SENTINEL,
        "the outside sentinel was rewritten through a hardlinked journal path"
    );
    assert!(!opened, "a hardlinked journal leaf must be a typed refusal");
}

/// The CONTROL for both arms above: an ordinary directory still opens,
/// so the two refusals are about the alias and not about the guard
/// having become a blanket no.
#[test]
fn an_ordinary_journal_path_still_opens() {
    let (_scratch, out, _outside) = dirs("ok");
    let (j, resume) = Journal::open(&out, b"<nzb/>").expect("a clean directory must open");
    assert!(resume.completed.is_empty());
    drop(j);
    assert!(out.join(JOURNAL_LEAF).is_file(), "the leaf was created");
}

/// The SECOND control, and the one the first cannot stand in for: a
/// journal already on disk for a DIFFERENT NZB must be restarted in
/// place, which is the only arm that truncates a non-empty file.
///
/// X5-04 made that truncation a `set_len` on the append descriptor
/// `open_private_leaf` hands back, and Windows spells append as
/// `FILE_GENERIC_WRITE & !FILE_WRITE_DATA` while `set_len` REQUIRES
/// `FILE_WRITE_DATA` - so every `Journal::open` on Windows failed with
/// `Access is denied. (os error 5)` and all six `windows-unit` shards
/// went red on 30 Aug 2026 (run 33337377615). `truncate_leaf` is the
/// fix. The test above catches the FRESH case, where the file is empty
/// and the truncate is a no-op that still fails the access check; this
/// one catches the case where bytes must genuinely go, so a fix that
/// only skipped the no-op would still be red here.
///
/// The assertion is on the CONTENT and not merely on the open: a
/// truncation that silently did nothing would leave the old NZB's
/// records to be parsed as this NZB's, which is the resume-a-stranger's-
/// journal defect the fingerprint exists to stop.
#[test]
fn a_journal_for_another_nzb_is_restarted_in_place() {
    let (_scratch, out, _outside) = dirs("restart");
    let leaf = out.join(JOURNAL_LEAF);

    let (j, _) = Journal::open(&out, b"<first/>").expect("first NZB must open");
    j.record("<a@example.invalid>");
    j.record("<b@example.invalid>");
    j.flush();
    drop(j);
    let before = std::fs::read(&leaf).expect("the first journal is on disk");
    assert!(
        before.len() > 40,
        "the fixture needs a non-empty journal to truncate, got {} bytes",
        before.len()
    );

    let (j2, resume) = Journal::open(&out, b"<second/>").expect(
        "a journal belonging to another NZB must be restarted in place, not refused - \
         an `Access is denied` here is the Windows append-vs-set_len trap",
    );
    assert!(
        resume.completed.is_empty(),
        "the other NZB's records must not be resumed as this one's, got {:?}",
        resume.completed
    );
    drop(j2);

    let after = String::from_utf8(std::fs::read(&leaf).expect("read back")).expect("utf-8");
    assert!(
        !after.contains("<a@example.invalid>") && !after.contains("<b@example.invalid>"),
        "the first NZB's records survived the restart: {after:?}"
    );
    assert!(
        after.starts_with("nzbfast-journal v1 "),
        "the restarted journal must lead with its own header: {after:?}"
    );
}

// ---------------------------------------------------------------- X5-05

/// A FIFO at the journal path must be refused as a non-regular file,
/// IMMEDIATELY. The oracle is not an unbounded test timeout: the open
/// runs on its own thread against a deadline, so the test reports the
/// wedge itself rather than hanging the suite.
#[cfg(unix)]
#[test]
fn a_fifo_journal_path_must_not_wedge_the_open() {
    let (_scratch, out, _outside) = dirs("fifo");
    let jpath = out.join(JOURNAL_LEAF);
    let made = std::process::Command::new("mkfifo")
        .arg(&jpath)
        .status()
        .map(|s| s.success())
        .unwrap_or(false);
    if !made {
        eprintln!("mkfifo unavailable - skipping");
        return;
    }

    let (tx, rx) = std::sync::mpsc::channel::<bool>();
    let probe = out.clone();
    std::thread::spawn(move || {
        let _ = tx.send(Journal::open(&probe, b"<nzb/>").is_ok());
    });
    // `Journal::open` does no I/O that can take seconds on a fresh
    // directory, so anything past this deadline is the block.
    let verdict = rx.recv_timeout(std::time::Duration::from_secs(5));
    if verdict.is_err() {
        // Release the parked thread so the scratch dir can be removed.
        let _ = std::fs::OpenOptions::new().write(true).open(&jpath);
        std::thread::sleep(std::time::Duration::from_millis(200));
    }
    assert!(
        verdict.is_ok(),
        "Journal::open blocked on a FIFO at the journal path - startup \
         wedges before any network work, with no typed rejection"
    );
    assert!(!verdict.unwrap(), "a FIFO must be a typed refusal");
}

// ---------------------------------------------------------------- X5-01

/// A STALE generation's successful retirement must not unlink a LIVE
/// generation's journal.
///
/// The full row holds two daemon generations behind barriers; the
/// mechanism it names - path-based, unconditional `remove_file` - is
/// reproducible with two handles on one directory, deterministically and
/// in one process. Generation N+1 records an article and flushes it;
/// generation N then retires.
#[test]
fn a_stale_generation_must_not_unlink_a_live_journal() {
    let (_scratch, out, _outside) = dirs("gen");
    let nzb = b"<nzb>one</nzb>";

    // Generation N: opened first, still holding its handle.
    let (gen_n, _) = Journal::open(&out, nzb).unwrap();
    // Generation N+1: the live retry. Its record is durable before N ends.
    let (gen_n1, _) = Journal::open(&out, nzb).unwrap();
    gen_n1.record("<live-article@mock>");
    gen_n1.flush();

    // N reaches successful retirement and retires the journal.
    gen_n.remove();

    gen_n1.record("<second-article@mock>");
    gen_n1.flush();
    drop(gen_n1);

    let (_gen_n2, resume) = Journal::open(&out, nzb).unwrap();
    assert!(
        resume.completed.contains("<live-article@mock>"),
        "the live generation's resume record was lost when a stale \
         generation retired the journal by path (completed = {:?})",
        resume.completed
    );
}

/// The CONTROL: the LAST generation - the ordinary single-run case, and
/// the one every finished job takes - must still retire the file. A
/// guard that never unlinks would pass the pin above and leave a journal
/// in every output directory forever.
#[test]
fn the_last_generation_still_retires_the_journal() {
    let (_scratch, out, _outside) = dirs("retire");
    let (j, _) = Journal::open(&out, b"<nzb/>").unwrap();
    assert!(out.join(JOURNAL_LEAF).exists());
    j.remove();
    assert!(
        !out.join(JOURNAL_LEAF).exists(),
        "the current generation must still be able to retire its journal"
    );
}

// ---------------------------------------------------------------- X5-02

/// Write `name` with `bytes` and journal ONE identity placement covering
/// all of it, committed to those bytes. Returns the resume state a
/// restart would parse back.
fn one_committed_identity_record(
    out: &Path,
    nzb: &[u8],
    id: &str,
    name: &str,
    bytes: &[u8],
) -> ResumeState {
    std::fs::write(out.join(name), bytes).unwrap();
    let frags = [Frag::identity(name, 0, bytes.len() as u64)];
    {
        let (j, _) = Journal::open(out, nzb).unwrap();
        j.record_placed(
            0,
            id,
            None,
            name,
            bytes.len() as u64,
            &frags,
            frags_crc(out, &frags),
        );
        j.flush();
    }
    Journal::open(out, nzb).unwrap().1
}

/// The CONTROL, and it comes first because every pin below asserts a
/// REFUSAL: bytes that did not move are still admitted. Without this the
/// two tests under it are equally satisfied by a check that refuses
/// everything, which would turn every resume in the product into a full
/// refetch and pass the suite.
#[test]
fn an_untouched_identity_span_is_still_admitted() {
    let (_scratch, out, _outside) = dirs("x502ok");
    let resume = one_committed_identity_record(
        &out,
        b"<nzb>ok</nzb>",
        "<a@mock>",
        "movie.bin",
        &payload(4096, 3),
    );
    let restored = restore(&out, &resume, None);
    assert!(
        restored.ids.contains("<a@mock>"),
        "an identity span whose bytes are exactly what was recorded must \
         still resume without a refetch"
    );
    assert_eq!(restored.dropped_unauthenticated, (0, 0));
}

/// A resume record may suppress a refetch only if the persisted bytes
/// are AUTHENTICATED. Length was the whole test ("a shorter file cannot
/// be holding these bytes, whatever the journal says"), so bytes swapped
/// for different bytes of the same length were admitted and shipped - on
/// a no-PAR2 job with nothing downstream able to notice.
#[test]
fn equal_length_replacement_bytes_must_not_be_admitted() {
    let (_scratch, out, _outside) = dirs("x502swap");
    let resume = one_committed_identity_record(
        &out,
        b"<nzb>x502</nzb>",
        "<a@mock>",
        "movie.bin",
        &payload(4096, 3),
    );

    // The crash-window edit: same path, same length, different bytes.
    std::fs::write(out.join("movie.bin"), payload(4096, 200)).unwrap();

    let restored = restore(&out, &resume, None);
    assert!(
        !restored.ids.contains("<a@mock>"),
        "restore admitted an identity span whose on-disk bytes were \
         replaced at the same length - the resumed run will skip the \
         refetch and ship the replacement"
    );
    assert_eq!(
        restored.dropped_unauthenticated,
        (1, 4096),
        "the refusal must be counted under its own cause, so the resume \
         banner can say why the bytes went back on the wire"
    );
}

/// The same admission reached WITHOUT an adversary, which is why this
/// row matters more than the one above it. A preallocated slot file has
/// the right length and holes where the bytes have not landed, so an
/// interrupted run leaves exactly this state: the article was marked
/// complete and its bytes are zero.
#[test]
fn a_preallocated_hole_must_not_be_admitted_as_written_bytes() {
    let (_scratch, out, _outside) = dirs("x502hole");
    let resume = one_committed_identity_record(
        &out,
        b"<nzb>x502h</nzb>",
        "<a@mock>",
        "movie.bin",
        &payload(4096, 3),
    );

    // Power loss after preallocation, before the bytes: full length, holes.
    let f = std::fs::OpenOptions::new()
        .write(true)
        .open(out.join("movie.bin"))
        .unwrap();
    f.set_len(0).unwrap();
    f.set_len(4096).unwrap();
    drop(f);

    let restored = restore(&out, &resume, None);
    assert!(
        !restored.ids.contains("<a@mock>"),
        "restore admitted an identity span over a preallocated hole - a \
         crash between preallocation and the write leaves the article \
         marked complete and its bytes zero"
    );
    assert_eq!(restored.dropped_unauthenticated, (1, 4096));
}

/// A record with NO commitment - which is every record a journal written
/// before this check carries - must refetch rather than be trusted. The
/// cost is one resume, once, after an upgrade; the cost of the other
/// answer is shipping whatever happens to be at the right offsets with
/// the right length.
#[test]
fn a_record_with_no_commitment_refetches() {
    let (_scratch, out, _outside) = dirs("x502old");
    let nzb = b"<nzb>old</nzb>";
    std::fs::write(out.join("movie.bin"), payload(4096, 3)).unwrap();
    {
        let (j, _) = Journal::open(&out, nzb).unwrap();
        j.record_placed(
            0,
            "<a@mock>",
            None,
            "movie.bin",
            4096,
            &[Frag::identity("movie.bin", 0, 4096)],
            None,
        );
        j.flush();
    }
    let resume = Journal::open(&out, nzb).unwrap().1;
    let restored = restore(&out, &resume, None);
    assert!(
        !restored.ids.contains("<a@mock>"),
        "an unauthenticated record must refetch - the bytes on disk are \
         the right length and nothing says they are the right bytes"
    );
    assert_eq!(restored.dropped_unauthenticated, (1, 4096));
}

/// The commitment must survive the round trip through the file, so a
/// record's `H` line binds to ITS OWN `R` line and to no other. Two
/// articles in one slot, one of them corrupted afterwards: the intact
/// one is admitted and the corrupted one is not, which no single-article
/// fixture can distinguish from a check that happens to read the wrong
/// record.
#[test]
fn a_commitment_binds_to_its_own_record() {
    let (_scratch, out, _outside) = dirs("x502pair");
    let nzb = b"<nzb>pair</nzb>";
    let bytes = payload(8192, 7);
    std::fs::write(out.join("movie.bin"), &bytes).unwrap();
    let a = [Frag::identity("movie.bin", 0, 4096)];
    let b = [Frag::identity("movie.bin", 4096, 4096)];
    {
        let (j, _) = Journal::open(&out, nzb).unwrap();
        j.record_placed(
            0,
            "<a@mock>",
            None,
            "movie.bin",
            8192,
            &a,
            frags_crc(&out, &a),
        );
        j.record_placed(
            0,
            "<b@mock>",
            None,
            "movie.bin",
            8192,
            &b,
            frags_crc(&out, &b),
        );
        j.flush();
    }
    let resume = Journal::open(&out, nzb).unwrap().1;

    // Corrupt only the SECOND article's half, in place.
    let mut edited = bytes.clone();
    edited[4096..].copy_from_slice(&payload(4096, 99));
    std::fs::write(out.join("movie.bin"), &edited).unwrap();

    let restored = restore(&out, &resume, None);
    assert!(
        restored.ids.contains("<a@mock>"),
        "the untouched article keeps its record"
    );
    assert!(
        !restored.ids.contains("<b@mock>"),
        "the corrupted article must refetch, and only it"
    );
    assert_eq!(restored.dropped_unauthenticated, (1, 4096));
}

/// A MULTI-FRAGMENT article must be hashed in VOLUME order, which is
/// payload order - a yEnc part covers one contiguous range of the posted
/// file and its fragments partition exactly that range. The record's own
/// fragment order is not that and must never be assumed to be, so this
/// one records its two fragments DESCENDING.
///
/// Its own pin because every other X5-02 test here places a single
/// fragment, and a single fragment cannot tell any ordering rule from
/// any other: reversing the sort in `article_authentic` leaves all of
/// them green (measured 30 Aug 2026).
#[test]
fn a_multi_fragment_article_hashes_in_volume_order() {
    let (_scratch, out, _outside) = dirs("x502order");
    let nzb = b"<nzb>order</nzb>";
    let bytes = payload(8192, 11);
    std::fs::write(out.join("movie.bin"), &bytes).unwrap();
    // Recorded high-offset-first: the halves differ, so a reader that
    // takes them in record order hashes the payload backwards.
    let frags = [
        Frag::identity("movie.bin", 4096, 4096),
        Frag::identity("movie.bin", 0, 4096),
    ];
    {
        let (j, _) = Journal::open(&out, nzb).unwrap();
        j.record_placed(
            0,
            "<a@mock>",
            None,
            "movie.bin",
            8192,
            &frags,
            Some(crc32fast::hash(&bytes)),
        );
        j.flush();
    }
    let resume = Journal::open(&out, nzb).unwrap().1;
    let restored = restore(&out, &resume, None);
    assert!(
        restored.ids.contains("<a@mock>"),
        "the commitment is over the payload in volume order, whatever \
         order the record lists its fragments in"
    );
    assert_eq!(restored.dropped_unauthenticated, (0, 0));
}
