//! §106: `journal.rs`'s own `#[cfg(test)] mod tests` body, moved out
//! whole to relieve the file's line-count ceiling. Everything here was
//! written as an inline module of `journal.rs` and is unchanged apart
//! from the mechanical one-level dedent the move required; `super::*`
//! still resolves to `crate::journal`, exactly as it did inline.
//!
//! This is the ordinary unit-test suite for the journal's public API
//! (write/read/resume/compaction). The two narrower test modules beside
//! it stay separate on purpose: `identity_tests` is the X5-01/02/04/05
//! inode-identity family, and `journal_bench_tests` times the hot path
//! rather than asserting behaviour - neither belongs folded in here.

use super::*;

/// The commitment for an article on a slot that will DEMOTE. After
/// the `M` rewrite its fragments name the VOLUME file at their
/// volume offsets, so the bytes to hash are the reconstruction's and
/// not the inner file's. Production records the same number by a
/// different route: the crc it records is the POSTED bytes' own, and
/// the reconstruction writes posted bytes - which is exactly the
/// premise the `M` rewrite already rests on.
fn mat_crc(dir: &Path, vol: &str, frags: &[Frag]) -> Option<u32> {
    let rewritten: Vec<Frag> = frags
        .iter()
        .map(|f| frag(vol, f.vol_off, f.vol_off, f.len))
        .collect();
    frags_crc(dir, &rewritten)
}

/// The X5-02 commitment a fixture on disk implies: the crc32 over
/// exactly the bytes these fragments name, read in VOLUME order from
/// where they sit right now.
///
/// This is the same question [`restore`] asks of the same fragments,
/// so a test records the number its OWN files justify rather than a
/// fabricated one - which is the only way a test of the admission
/// path proves anything. `None` when a fragment names a file the
/// fixture has not written, which is itself the truthful answer: no
/// bytes, no commitment, and the article refetches.
pub(crate) fn frags_crc(dir: &Path, frags: &[Frag]) -> Option<u32> {
    let mut order: Vec<&Frag> = frags.iter().collect();
    order.sort_by_key(|f| f.vol_off);
    let mut h = crc32fast::Hasher::new();
    for f in order {
        let bytes = std::fs::read(dir.join(&f.file)).ok()?;
        let s = usize::try_from(f.file_off).ok()?;
        let e = s.checked_add(usize::try_from(f.len).ok()?)?;
        h.update(bytes.get(s..e)?);
    }
    Some(h.finalize())
}

/// [`Journal::peek`] is what the demotion watchdog reads (TODO
/// 309(d)), and the whole of its value is that it agrees with
/// [`Journal::open`] without WRITING - `open` creates the file,
/// opens it for append and truncates it on a fingerprint mismatch,
/// none of which may happen to a journal a running job still holds.
///
/// So the three claims: it agrees on `placement_bytes`, it leaves
/// M4-70 across a crash: a contested slot's name tally has to come back
/// out of the journal the way it went in, or the resumed run rebuilds it
/// empty, reads "every article agreed", and leaves the decoy name run 1
/// latched on the disk.
///
/// The grammar's rule is LAST WINS per `(slot, name)` - every line
/// carries a running total, not an increment - so a re-record overwrites
/// and a replayed line cannot double-count a vote.
#[test]
fn a_contested_slots_name_tally_survives_the_journal() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-votes-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let (j, _) = Journal::open(&dir, b"<nzb/>").unwrap();
    // A yEnc header name is the poster's own bytes: it may hold spaces,
    // so it rides last and the parser splits three ways.
    j.record_name_votes(2, &[("x.dat".into(), 1), ("My Movie 2024.mkv".into(), 3)]);
    // ...and a later article moves the running total, not an increment.
    j.record_name_votes(2, &[("My Movie 2024.mkv".into(), 4)]);
    j.record_name_votes(7, &[("other.bin".into(), 2)]);
    // Nothing to say writes no line at all - the ordinary slot's answer.
    j.record_name_votes(9, &[]);
    // A name that would end the record early is dropped rather than
    // written, so the tally is short by a vote instead of corrupt.
    j.record_name_votes(9, &[("bad\nname".into(), 5)]);
    drop(j);

    let (_j2, resume) = Journal::open(&dir, b"<nzb/>").unwrap();
    let mut two = resume.name_votes.get(&2).cloned().unwrap_or_default();
    two.sort();
    assert_eq!(
        two,
        vec![
            ("My Movie 2024.mkv".to_string(), 4),
            ("x.dat".to_string(), 1)
        ]
    );
    assert_eq!(
        resume.name_votes.get(&7).cloned().unwrap_or_default(),
        vec![("other.bin".to_string(), 2)]
    );
    assert!(!resume.name_votes.contains_key(&9), "slot 9 wrote nothing");
    // And the lines are OURS: they must not be mistaken for v1 article
    // ids, which is what an older binary reading them does with them.
    assert!(
        resume.completed.iter().all(|c| !c.starts_with("V ")),
        "a vote line was taken for a completed article: {:?}",
        resume.completed
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// the file byte-identical, and it refuses a file that is not a
/// journal rather than parsing it as an empty one - which is what
/// stops a stray file in an out_dir reading as "nothing restored".
#[test]
fn peek_agrees_with_open_and_writes_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-peek-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    assert!(Journal::peek(&dir).is_none(), "no journal, no answer");

    let (j, _) = Journal::open(&dir, b"<nzb/>").unwrap();
    for i in 0..3u64 {
        j.record_placed(
            0,
            &format!("<a{i}@x>"),
            None,
            "vol.part01.rar",
            3_000,
            &[Frag::identity("vol.part01.rar", i * 1_000, 1_000)],
            frags_crc(&dir, &[Frag::identity("vol.part01.rar", i * 1_000, 1_000)]),
        );
    }
    j.flush();
    let path = dir.join(".nzbfast.journal");
    let before = std::fs::read(&path).unwrap();

    let peeked = Journal::peek(&dir).expect("a journal we just wrote");
    assert_eq!(peeked.placement_bytes(), 3_000);
    assert_eq!(
        std::fs::read(&path).unwrap(),
        before,
        "a peek must not touch the file the running job is appending to"
    );
    // And it agrees with the reader the rerun itself will use.
    drop(j);
    let (_j2, resume) = Journal::open(&dir, b"<nzb/>").unwrap();
    assert_eq!(resume.placement_bytes(), peeked.placement_bytes());

    // Not a journal: refused, not read as empty.
    std::fs::write(&path, b"hello\nR 0 <a@x>\n").unwrap();
    assert!(Journal::peek(&dir).is_none(), "no v1 header, no answer");
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn journal_roundtrip_and_fingerprint() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let nzb = b"<nzb>fake</nzb>";
    let (j, resume) = Journal::open(&dir, nzb).unwrap();
    assert!(resume.completed.is_empty());
    j.record("<a@x>");
    j.record("<b@x>");
    drop(j);

    // Same NZB: completed ids come back.
    let (j2, resume) = Journal::open(&dir, nzb).unwrap();
    assert_eq!(resume.completed.len(), 2);
    assert!(resume.completed.contains("<a@x>"));
    j2.record("<c@x>");
    drop(j2);
    let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
    assert_eq!(resume.completed.len(), 3);

    // Different NZB: journal resets.
    let (_j4, resume) = Journal::open(&dir, b"<nzb>other</nzb>").unwrap();
    assert!(resume.completed.is_empty());

    std::fs::remove_dir_all(&dir).unwrap();
}

/// TODO 309(a): `largest_slot_bytes` reports the widest slot's FULL
/// recorded size, and `placement_bytes` the sum of the fragments -
/// two numbers a resumed run needs separately, because the replay's
/// held bytes track the first and the admission gate used to be
/// written against only the second.
#[test]
fn the_widest_slot_is_its_recorded_size_and_not_its_restored_bytes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-wide-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    let nzb = b"<nzb>wide</nzb>";

    let (j, resume) = Journal::open(&dir, nzb).unwrap();
    assert_eq!(resume.placement_bytes(), 0);
    assert_eq!(resume.largest_slot_bytes(), 0, "no placements, no slots");

    // Slot 0 is a big volume with a SMALL restored fragment; slot 1 a
    // small volume that happens to be fully restored. The sum of the
    // fragments makes slot 1 look like the larger of the two, and it
    // is the one that can hold less.
    j.record_placed(
        0,
        "<a@x>",
        None,
        "big.part01.rar",
        256_000_000,
        &[Frag::identity("big.part01.rar", 0, 1_000)],
        frags_crc(&dir, &[Frag::identity("big.part01.rar", 0, 1_000)]),
    );
    j.record_placed(
        1,
        "<b@x>",
        None,
        "small.part01.rar",
        8_000_000,
        &[Frag::identity("small.part01.rar", 0, 8_000)],
        frags_crc(&dir, &[Frag::identity("small.part01.rar", 0, 8_000)]),
    );
    drop(j);

    let (_j, resume) = Journal::open(&dir, nzb).unwrap();
    assert_eq!(resume.placement_bytes(), 9_000);
    assert_eq!(
        resume.largest_slot_bytes(),
        256_000_000,
        "the widest slot is the 256 MB volume, however little of it is on disk"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// One record torn mid-multibyte (ENOSPC, power loss) must not hide
/// the valid records appended after it. `lines()` +
/// `map_while(Result::ok)` stopped permanently at the first
/// invalid-UTF-8 line, so every later completion was re-fetched on
/// every retry, forever.
#[test]
fn a_torn_journal_line_does_not_hide_the_records_after_it() {
    // NOT "-torn-": `malformed_and_torn_lines_are_ignored` already
    // owns that directory, and two tests sharing one journal dir in
    // one process clobber each other's records (found 27 Aug 2026
    // as a parallel-run flake, len 3 vs 2).
    let dir =
        std::env::temp_dir().join(format!("nzbfast-journal-tornafter-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);

    let nzb = b"<nzb>torn</nzb>";
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record("<a@x>");
    drop(j);
    {
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(".nzbfast.journal"))
            .unwrap();
        f.write_all(b"F 0 \xff\xfe torn\n").unwrap();
    }
    // This open must still see <a@x>, and the record IT appends
    // lands after the torn line.
    let (j2, resume) = Journal::open(&dir, nzb).unwrap();
    assert!(resume.completed.contains("<a@x>"));
    j2.record("<c@x>");
    drop(j2);

    let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
    assert!(
        resume.completed.contains("<c@x>"),
        "a record appended after a torn line must restore: {:?}",
        resume.completed
    );
    assert_eq!(resume.completed.len(), 2);
    std::fs::remove_dir_all(&dir).unwrap();
}

fn qdir(name: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-quarantine-{name}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// The unquarantine's occupancy guard is a CLAIM, so a base name
/// that arrives while the walk is running cannot be renamed over.
///
/// The cases below ask WHICH QUESTION the guard asks, and the
/// `symlink_metadata` this door carried until 31 Aug 2026 answers
/// that exactly as `create_new` does. What separates them is the gap
/// behind the answer, so this has to race: see
/// `crate::renameclaim` for the measurement and for why the arrival
/// hunts the rename rather than sweeping a fixed span. VERIFIED red
/// with this door alone reverted to the `lstat`.
///
/// What a lost window costs here is the sharpest of the nine on that
/// census after the two that reach a user folder: whatever held the
/// base name is gone, and `restore` then trusts the quarantined
/// bytes as the volume file.
#[test]
fn a_base_name_created_beside_the_unquarantine_is_never_renamed_over() {
    let d = qdir("claim-race");
    let held = d.join(format!("movie.mkv{PARTIAL_SUFFIX}"));
    let target = d.join("movie.mkv");
    crate::renameclaim::never_renames_over_a_neighbour(
        &target,
        300,
        || std::fs::write(&held, b"holed payload").unwrap(),
        || {
            unquarantine_partials(&d);
        },
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The round trip that makes the rename free: a failed job's payload
/// goes aside under a name nothing imports, and the next attempt
/// gets the ORIGINAL name back with the bytes untouched. If either
/// half broke, a retry would refetch the whole post instead of the
/// one article it is missing.
#[test]
fn a_quarantined_partial_comes_back_under_its_own_name_with_its_bytes() {
    let d = qdir("roundtrip");
    std::fs::write(d.join("movie.mkv"), b"holed payload").unwrap();
    let (done, failed) = quarantine_partials(&d, &["movie.mkv".to_string()]);
    assert_eq!(done, vec!["movie.mkv".to_string()]);
    assert!(failed.is_empty());
    assert!(
        !d.join("movie.mkv").exists(),
        "the payload name must not survive a failed job"
    );
    assert!(d.join(format!("movie.mkv{PARTIAL_SUFFIX}")).exists());

    assert_eq!(unquarantine_partials(&d), vec!["movie.mkv".to_string()]);
    assert_eq!(
        std::fs::read(d.join("movie.mkv")).unwrap(),
        b"holed payload",
        "the bytes are the resume state - they must survive the round trip"
    );
    assert!(!d.join(format!("movie.mkv{PARTIAL_SUFFIX}")).exists());
    let _ = std::fs::remove_dir_all(&d);
}

/// Volume files and every other resident are none of this pass's
/// business: they are the classic resume target and nothing mistakes
/// a holed `.part02.rar` for a finished download. Only the names the
/// caller passes - the direct-extracted payload - move.
#[test]
fn quarantine_touches_only_the_named_payload() {
    let d = qdir("scope");
    for f in ["a.part01.rar", "a.par2", ".nzbfast.journal", "inner.mkv"] {
        std::fs::write(d.join(f), b"x").unwrap();
    }
    let (done, _) = quarantine_partials(&d, &["inner.mkv".to_string()]);
    assert_eq!(done, vec!["inner.mkv".to_string()]);
    for f in ["a.part01.rar", "a.par2", ".nzbfast.journal"] {
        assert!(d.join(f).exists(), "{f} must be left exactly where it is");
    }
    let _ = std::fs::remove_dir_all(&d);
}

/// A payload the extractor reported but never wrote (a group that
/// fell back, a name that lost a race) is not an error: there is
/// nothing on disk to mislead anyone.
#[test]
fn a_payload_that_was_never_written_is_not_a_failure() {
    let d = qdir("absent");
    let (done, failed) = quarantine_partials(&d, &["never-written.mkv".to_string()]);
    assert!(done.is_empty() && failed.is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

/// A traversal name cannot reach outside the output directory -
/// the same rule `drop_spared_metadata` relies on, and it matters
/// more here because this end RENAMES rather than deletes.
#[test]
fn a_traversal_payload_name_stays_inside_the_out_dir() {
    let parent = qdir("traverse");
    let out = parent.join("out");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(parent.join("evil.mkv"), b"keep me").unwrap();
    quarantine_partials(&out, &["../evil.mkv".to_string()]);
    assert!(
        parent.join("evil.mkv").exists(),
        "sanitize_filename must keep the rename inside the output dir"
    );
    let _ = std::fs::remove_dir_all(&parent);
}

/// The live file wins. If something else already owns the base name
/// - a re-add into an occupied directory, a copy the user made -
/// the quarantined bytes must NOT clobber it, and must not vanish
/// either: guessing between two candidates is how a resume gets
/// seeded with the wrong bytes.
#[test]
fn unquarantine_never_clobbers_a_file_that_already_holds_the_name() {
    let d = qdir("clobber");
    std::fs::write(d.join(format!("m.mkv{PARTIAL_SUFFIX}")), b"old").unwrap();
    std::fs::write(d.join("m.mkv"), b"live").unwrap();
    assert!(unquarantine_partials(&d).is_empty());
    assert_eq!(std::fs::read(d.join("m.mkv")).unwrap(), b"live");
    assert!(
        d.join(format!("m.mkv{PARTIAL_SUFFIX}")).exists(),
        "the loser is kept, not deleted"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The same promise, held to an ENTRY rather than to a name that
/// RESOLVES (31 Aug 2026 rename-occupancy census). This walk already
/// asks `symlink_metadata` on the way IN - "a symlink is never ours
/// to restore" - and the destination test was the one line in the
/// function that asked the other question, so a link at the base
/// name read as free and the rename removed it. Declining costs a
/// refetch of the articles whose bytes are in the quarantined file,
/// which is the ordinary consequence this function's header already
/// describes; the link's target string is not recoverable at all.
#[cfg(unix)]
#[test]
fn unquarantine_never_clobbers_an_entry_that_already_holds_the_name() {
    let d = qdir("clobber-link");
    std::fs::write(d.join(format!("m.mkv{PARTIAL_SUFFIX}")), b"old").unwrap();
    std::os::unix::fs::symlink(d.join("on-the-nas"), d.join("m.mkv")).unwrap();
    assert!(unquarantine_partials(&d).is_empty());
    assert!(
        std::fs::symlink_metadata(d.join("m.mkv"))
            .unwrap()
            .file_type()
            .is_symlink(),
        "the user's link must still be a link"
    );
    assert!(
        d.join(format!("m.mkv{PARTIAL_SUFFIX}")).exists(),
        "the loser is kept, not deleted"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// A FOREIGN file at a declined base name IS what [`restore`]'s length
/// probe reads for an identity fragment - reachable, but X5-02's crc32
/// check refuses the mismatch (`restore-for-foreign-identity-fragments`).
#[test]
fn identity_against_a_foreign_file_at_the_base_name_still_refuses_on_crc() {
    let d = qdir("foreign-identity");
    let nzb = b"<nzb>foreign</nzb>";
    std::fs::write(d.join("data.bin"), vec![7u8; 1_000]).unwrap();
    let (j, _) = Journal::open(&d, nzb).unwrap();
    let frags = [frag("data.bin", 0, 0, 1_000)];
    let crc = frags_crc(&d, &frags);
    j.record_placed(
        0,
        "<a@x>",
        Some(("data.bin".to_string(), 1_000)),
        "",
        0,
        &frags,
        crc,
    );
    drop(j);
    // Quarantined, then a same-length FOREIGN file took the base name.
    let partial = d.join(format!("data.bin{PARTIAL_SUFFIX}"));
    std::fs::rename(d.join("data.bin"), &partial).unwrap();
    std::fs::write(d.join("data.bin"), vec![9u8; 1_000]).unwrap();
    assert!(unquarantine_partials(&d).is_empty());
    let (_j2, resume) = Journal::open(&d, nzb).unwrap();
    let restored = restore(&d, &resume, None);
    assert!(restored.ids.is_empty()); // never admitted on a stranger's bytes
    assert_eq!(std::fs::read(d.join("data.bin")).unwrap(), vec![9u8; 1_000]);
    let _ = std::fs::remove_dir_all(&d);
}

/// The OTHER side of that decision, and it goes the other way on
/// purpose (31 Aug 2026 rename-occupancy census). `quarantine_paths`
/// makes no occupancy test at all, so the NEWEST partial takes the
/// name and an earlier one is replaced. The full argument is at the
/// rename in `quarantine_paths`; the short form is that the loser
/// only ever survives an unquarantine that DECLINED, `restore`
/// addresses payloads by their recorded base name and never the
/// suffixed one, so its bytes were refetched by the attempt that is
/// now failing - where refusing would leave the holed payload
/// wearing its real name, which is the false artifact the whole
/// mechanism exists to prevent.
///
/// Pinned so this reads as a decision rather than as the missing
/// guard its neighbours above have.
#[test]
fn quarantine_replaces_an_earlier_partial_rather_than_refusing_the_name() {
    let d = qdir("requarantine");
    std::fs::write(d.join(format!("m.mkv{PARTIAL_SUFFIX}")), b"older").unwrap();
    std::fs::write(d.join("m.mkv"), b"newer").unwrap();
    let (done, failed) = quarantine_partials(&d, &["m.mkv".to_string()]);
    assert_eq!(done, vec!["m.mkv".to_string()]);
    assert!(failed.is_empty());
    assert!(
        !d.join("m.mkv").exists(),
        "the false artifact must not keep its real name"
    );
    assert_eq!(
        std::fs::read(d.join(format!("m.mkv{PARTIAL_SUFFIX}"))).unwrap(),
        b"newer",
        "the newest partial is the one this job's records describe"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// The one destination shape the kernel refuses, and the caller has
/// to HEAR about it: a directory already holding the suffixed name
/// makes the rename fail, and the payload is then still sitting
/// there wearing its real name, which is exactly what the `failed`
/// list is for - `quarantine_failed_payload` warns per name that the
/// file is incomplete despite looking real.
#[test]
fn quarantine_reports_a_destination_it_cannot_take() {
    let d = qdir("requarantine-dir");
    std::fs::create_dir_all(d.join(format!("m.mkv{PARTIAL_SUFFIX}"))).unwrap();
    std::fs::write(d.join("m.mkv"), b"newer").unwrap();
    let (done, failed) = quarantine_partials(&d, &["m.mkv".to_string()]);
    assert!(done.is_empty());
    assert_eq!(failed, vec!["m.mkv".to_string()], "never swallowed");
    assert!(
        d.join("m.mkv").exists(),
        "the bytes are still there to report"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// An ordinary directory has nothing to undo, and a bare suffix with
/// no base name in front of it is not ours to rename to "".
#[test]
fn unquarantine_is_a_no_op_without_quarantined_files() {
    let d = qdir("noop");
    std::fs::write(d.join("a.mkv"), b"x").unwrap();
    std::fs::write(d.join(PARTIAL_SUFFIX), b"x").unwrap();
    assert!(unquarantine_partials(&d).is_empty());
    assert!(d.join("a.mkv").exists() && d.join(PARTIAL_SUFFIX).exists());
    assert!(unquarantine_partials(Path::new("/nonexistent/nzbfast-q")).is_empty());
    let _ = std::fs::remove_dir_all(&d);
}

/// The name budget and the walk that has to find what it wrote are
/// ONE number, `disk::MAX_DEPTH`. The deepest name
/// `sanitize_out_name` will ever hand back is MAX_DEPTH components,
/// the last of which is the leaf, so the deepest directory a
/// quarantined partial can sit in is at MAX_DEPTH - 1.
///
/// Both ends are pinned deliberately, and both are written in terms
/// of the constant rather than of a number: moving the budget
/// without the walk, or the walk without the budget, reddens here.
/// The failure it stands in front of is silent - a partial the walk
/// cannot reach is invisible to `restore`, so every article whose
/// bytes live in it refetches and the `.nzbfast-partial` is left
/// behind for good, which is verbatim the 30 Aug 2026 defect
/// `unquarantine_partials` was written to fix.
#[test]
fn the_unquarantine_walk_reaches_exactly_as_deep_as_a_name_can_be() {
    let d = qdir("depth");
    let dirs: Vec<String> = (0..crate::disk::MAX_DEPTH - 1)
        .map(|i| format!("d{i}"))
        .collect();
    let deepest = dirs.iter().fold(d.clone(), |p, c| p.join(c));
    std::fs::create_dir_all(&deepest).unwrap();
    std::fs::write(deepest.join(format!("deep.mkv{PARTIAL_SUFFIX}")), b"bytes").unwrap();

    // One directory PAST what any preserved name can spell. Nothing
    // in this pipeline writes here; the walk must stop, which is
    // what keeps a symlinked or hostile tree finite.
    let past = deepest.join("over");
    std::fs::create_dir_all(&past).unwrap();
    std::fs::write(past.join(format!("past.mkv{PARTIAL_SUFFIX}")), b"bytes").unwrap();

    let mut want = dirs.join("/");
    want.push_str("/deep.mkv");
    assert_eq!(
        unquarantine_partials(&d),
        vec![want],
        "a partial at MAX_DEPTH - 1 directories deep is inside the deepest \
         name sanitize_out_name can produce, so the walk has to find it"
    );
    assert_eq!(std::fs::read(deepest.join("deep.mkv")).unwrap(), b"bytes");
    assert!(
        past.join(format!("past.mkv{PARTIAL_SUFFIX}")).exists(),
        "the walk must not run past the budget it shares with the name"
    );
    let _ = std::fs::remove_dir_all(&d);
}

/// §94 A: `restore_for(.., materialize_volumes = false)` must not
/// write the volume file at all, and must say where each span's
/// bytes actually are so the replay can read them from there.
///
/// This is the whole disk saving. Materialising first writes a full
/// extra copy of the resumed fraction and the replay then reads it
/// back - the difference between a resumed job costing 2.02x
/// payload of device I/O and 1.5x. If this test ever passes with a
/// volume file on disk, that saving has been quietly given back.
#[test]
fn a_no_materialise_restore_writes_no_volume_and_names_the_real_source() {
    let dir = qdir("nomat");
    let inner: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("inner.bin"), &inner).unwrap();
    let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
    std::fs::write(dir.join("plain.bin"), &plain).unwrap();

    let nzb = b"<nzb>nomat</nzb>";
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    // Direct-extracted: volume bytes [5000,15000) live in inner.bin
    // at [10000,20000). Under materialisation this is the copy.
    j.record_placed(
        0,
        "<vol@x>",
        None,
        "vol.part1.rar",
        25_000,
        &[frag("inner.bin", 10_000, 5_000, 10_000)],
        frags_crc(&dir, &[frag("inner.bin", 10_000, 5_000, 10_000)]),
    );
    // Identity: the bytes never moved, so this one reports its own
    // file either way - which is also every PAR2 recovery volume,
    // and why the issue-#14 resume sniff still finds them on disk.
    j.record_placed(
        1,
        "<pl@x>",
        Some(("plain.bin".to_string(), 30_000)),
        "ignored",
        0,
        &[frag("plain.bin", 2_000, 2_000, 4_000)],
        frags_crc(&dir, &[frag("plain.bin", 2_000, 2_000, 4_000)]),
    );
    // A source that is too SHORT for its span must still fail its
    // article. The read happens later under no-materialise, so an
    // article admitted here would never refetch and the replay
    // would simply lose those bytes.
    j.record_placed(
        2,
        "<short@x>",
        None,
        "short.rar",
        9_000,
        &[frag("plain.bin", 29_000, 0, 8_000)],
        frags_crc(&dir, &[frag("plain.bin", 29_000, 0, 8_000)]),
    );
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore_for(&dir, &resume, None, false);
    assert!(restored.ids.contains("<vol@x>"));
    assert!(restored.ids.contains("<pl@x>"));
    assert!(
        !restored.ids.contains("<short@x>"),
        "a source too short for its span must drop its article"
    );
    assert!(
        !dir.join("vol.part1.rar").exists(),
        "the volume was materialised anyway - the replay's saving is gone"
    );

    let vol = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
    assert_eq!(vol.spans, [(5_000, 10_000)]);
    assert_eq!(
        vol.sources
            .iter()
            .map(|(f, o)| (&**f, *o))
            .collect::<Vec<_>>(),
        [("inner.bin", 10_000)],
        "the span must name the file its bytes are really in"
    );
    let pl = restored.seeds.iter().find(|s| s.slot == 1).unwrap();
    assert_eq!(
        pl.sources
            .iter()
            .map(|(f, o)| (&**f, *o))
            .collect::<Vec<_>>(),
        [("plain.bin", 2_000)],
        "an identity span stays in its own file at its own offset"
    );

    // 27 Aug 2026 sweep F1: a §293 donation lands AFTER the
    // map-shape restore and forces the run onto the adopt shape,
    // whose seeds assert their spans are in the volume files - so
    // `get()` re-runs the restore MATERIALISING on the SAME state
    // the no-materialise pass already walked. Pin what that re-run
    // relies on: same admissions, and the volume bytes really land.
    let redone = restore_for(&dir, &resume, None, true);
    assert_eq!(
        redone.ids, restored.ids,
        "the re-run admits the same articles"
    );
    assert_eq!(
        std::fs::read(dir.join("vol.part1.rar")).unwrap()[5_000..15_000],
        inner[10_000..20_000],
        "the re-run put the span's bytes into the volume"
    );
    assert!(
        redone.seeds.iter().all(|s| s.sources.is_empty()),
        "re-run seeds are volume-resident, exactly what the adopt path asserts"
    );

    // And the twin: with materialisation ON, nothing changes from
    // what every earlier caller has always got.
    let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
    let mat = restore(&dir, &resume, None);
    assert!(dir.join("vol.part1.rar").exists(), "the volume is rebuilt");
    assert_eq!(
        std::fs::read(dir.join("vol.part1.rar")).unwrap()[5_000..15_000],
        inner[10_000..20_000],
        "and holds the bytes the placement points at"
    );
    assert!(
        mat.seeds.iter().all(|s| s.sources.is_empty()),
        "materialised seeds carry no source list - every span is in the volume"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// TODO 309(b), 28 Aug 2026: a refused article is COUNTED, so the
/// resume can say the bytes went back on the wire.
///
/// The refusal itself is right and is pinned above; what was wrong
/// is that it was invisible. `get/plan.rs` reports what it
/// restored, so an out-dir something outside nzbfast had moved,
/// truncated or deleted resumed looking exactly like an ordinary
/// resume with less on disk.
///
/// Both directions, and the zero side is the one that matters: a
/// counter that fires on a clean resume would put a "your files
/// moved" warning in front of every user who ever pauses, which is
/// worse than the silence it replaces.
#[test]
fn a_refused_article_is_counted_so_the_resume_can_say_the_bytes_refetch() {
    let dir = qdir("dropcount");
    let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
    std::fs::write(dir.join("plain.bin"), &plain).unwrap();
    let nzb = b"<nzb>dropcount</nzb>";

    let (j, _) = Journal::open(&dir, nzb).unwrap();
    // Admitted: an identity span wholly inside the file.
    j.record_placed(
        0,
        "<ok@x>",
        Some(("plain.bin".to_string(), 30_000)),
        "ignored",
        0,
        &[frag("plain.bin", 2_000, 2_000, 4_000)],
        frags_crc(&dir, &[frag("plain.bin", 2_000, 2_000, 4_000)]),
    );
    drop(j);
    let (_j, resume) = Journal::open(&dir, nzb).unwrap();
    let clean = restore_for(&dir, &resume, None, false);
    assert!(clean.ids.contains("<ok@x>"));
    assert_eq!(
        clean.dropped_source,
        (0, 0),
        "an ordinary resume must report nothing dropped, or every pause warns"
    );
    assert_eq!(clean.dropped_crypto, 0);

    // Now the shape the disclosure exists for: a second article
    // whose bytes are past the end of the file they were written
    // into. Two fragments, one of them fine, because an article is
    // admitted only whole - the honest figure is BOTH fragments,
    // since the whole article refetches.
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record_placed(
        1,
        "<gone@x>",
        None,
        "vol.part1.rar",
        40_000,
        &[
            frag("plain.bin", 1_000, 0, 500),
            frag("plain.bin", 29_000, 500, 8_000),
        ],
        frags_crc(
            &dir,
            &[
                frag("plain.bin", 1_000, 0, 500),
                frag("plain.bin", 29_000, 500, 8_000),
            ],
        ),
    );
    drop(j);
    let (_j, resume) = Journal::open(&dir, nzb).unwrap();
    let dropped = restore_for(&dir, &resume, None, false);
    assert!(
        dropped.ids.contains("<ok@x>") && !dropped.ids.contains("<gone@x>"),
        "the readable article still restores - one bad article is not a failed resume"
    );
    assert_eq!(
        dropped.dropped_source,
        (1, 8_500),
        "the refused article is counted whole, both fragments"
    );
    assert_eq!(
        dropped.dropped_crypto, 0,
        "a source that moved is not a password problem - the two causes stay apart"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

fn frag(file: &str, file_off: u64, vol_off: u64, len: u64) -> Frag {
    Frag {
        file: file.to_string(),
        file_off,
        vol_off,
        len,
    }
}

/// N5 moved record composition out of the shared lock into reused
/// thread-local buffers. The grammar is a compatibility surface (an
/// old binary resumes from these bytes), so pin the exact lines: S
/// before any placement of its slot, every F before the first line
/// that references its index, one record per line.
#[test]
fn record_letter_emits_the_exact_line_grammar() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-golden-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let (j, _) = Journal::open(&dir, b"<nzb>golden</nzb>").unwrap();
    j.record_placed(
        3,
        "<a@x>",
        None,
        "vol.rar",
        100,
        &[frag("in.bin", 1, 2, 3), frag("in2.bin", 40, 50, 60)],
        frags_crc(
            &dir,
            &[frag("in.bin", 1, 2, 3), frag("in2.bin", 40, 50, 60)],
        ),
    );
    j.record_placed_crypto(
        3,
        "<b@x>",
        None,
        "vol.rar",
        100,
        &[frag("in.bin", 7, 8, 9)],
        &[false],
        frags_crc(&dir, &[frag("in.bin", 7, 8, 9)]),
    );
    j.record("<c@x>");
    let path = j.path.clone();
    drop(j);
    let text = std::fs::read_to_string(path).unwrap();
    let mut lines = text.lines();
    assert!(lines.next().unwrap().starts_with("nzbfast-journal v1 "));
    // X5-01's generation claim rides directly behind the header, on
    // every open, and is pinned HERE rather than skipped: it is part
    // of the grammar now, and a `G` line that stopped being written
    // would take `Journal::remove`'s ownership test with it while
    // every other assertion in this test still passed.
    let g = lines.next().unwrap();
    assert!(g.starts_with("G ") && g.len() > 2, "generation line: {g:?}");
    assert_eq!(lines.next(), Some("S 3 100 vol.rar"));
    assert_eq!(lines.next(), Some("F 0 in.bin"));
    assert_eq!(lines.next(), Some("F 1 in2.bin"));
    assert_eq!(lines.next(), Some("R 3 0:1:2:3,1:40:50:60 <a@x>"));
    assert_eq!(lines.next(), Some("D 3 0:7:8:9:0 <b@x>"));
    assert_eq!(lines.next(), Some("<c@x>"));
    assert_eq!(lines.next(), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The `S` destination is what [`parse_lines`] runs
/// `sanitize_out_name` over again on load, so a disambiguated name
/// has to be a FIXED POINT of that function or the record stops
/// naming the file it describes. It was not: `sanitize_out_name`
/// caps a long posted name at exactly 255 bytes, and a raw
/// `{slot:03}-` prefix on top of that is 259 - re-spelled by the
/// reader, and unwritable in any case.
#[test]
fn a_disambiguated_s_destination_survives_its_own_reload() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-capname-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let long = format!("{}.bin", "y".repeat(400));
    assert_eq!(
        crate::disk::sanitize_out_name(&long).len(),
        255,
        "the premise moved"
    );
    let (j, _) = Journal::open(&dir, b"<nzb>capname</nzb>").unwrap();
    // Two slots posting one name is what the disambiguator is for.
    for slot in [0usize, 1] {
        j.record_placed(
            slot,
            &format!("<a{slot}@x>"),
            None,
            &long,
            100,
            &[frag("in.bin", 1, 2, 3)],
            frags_crc(&dir, &[frag("in.bin", 1, 2, 3)]),
        );
    }
    let path = j.path.clone();
    drop(j);
    let text = std::fs::read_to_string(path).unwrap();
    let dests: Vec<&str> = text
        .lines()
        .filter_map(|l| l.strip_prefix("S "))
        .filter_map(|r| r.splitn(3, ' ').nth(2))
        .collect();
    assert_eq!(dests.len(), 2, "both slots must get an S line: {text:?}");
    assert_ne!(dests[0], dests[1], "the second slot was not disambiguated");
    for d in &dests {
        assert_eq!(
            *d,
            crate::disk::sanitize_out_name(d),
            "the reader re-spells this destination"
        );
        for c in d.split('/') {
            assert!(c.len() <= 255, "component of {} bytes", c.len());
        }
    }
    let _ = std::fs::remove_dir_all(&dir);
}

#[test]
fn placement_roundtrip_restore_and_copyback() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-v2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // "Run 1": inner.bin carries a direct-extracted article's bytes at
    // a translated offset; plain.bin holds an identity article.
    let inner: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("inner.bin"), &inner).unwrap();
    let plain: Vec<u8> = (0..30_000u32).map(|i| (i % 13) as u8).collect();
    std::fs::write(dir.join("plain.bin"), &plain).unwrap();

    let nzb = b"<nzb>v2</nzb>";
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    // Direct-extracted: volume bytes [5000, 15000) live in inner.bin
    // at [10000, 20000).
    j.record_placed(
        0,
        "<vol@x>",
        None,
        "vol.part1.rar",
        25_000,
        &[frag("inner.bin", 10_000, 5_000, 10_000)],
        frags_crc(&dir, &[frag("inner.bin", 10_000, 5_000, 10_000)]),
    );
    // Identity (plain slot, writer existed).
    j.record_placed(
        1,
        "<pl@x>",
        Some(("plain.bin".to_string(), 30_000)),
        "ignored",
        0,
        &[frag("plain.bin", 2_000, 2_000, 4_000)],
        frags_crc(&dir, &[frag("plain.bin", 2_000, 2_000, 4_000)]),
    );
    // Fragment pointing at a file that will not exist → must drop.
    j.record_placed(
        2,
        "<gone@x>",
        None,
        "ghost.rar",
        9_000,
        &[frag("deleted.bin", 0, 0, 100)],
        frags_crc(&dir, &[frag("deleted.bin", 0, 0, 100)]),
    );
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    assert_eq!(resume.slots.len(), 3);
    let restored = restore(&dir, &resume, None);
    assert!(
        restored.ids.contains("<vol@x>"),
        "copy-back article restored"
    );
    assert!(restored.ids.contains("<pl@x>"), "identity article restored");
    assert!(
        !restored.ids.contains("<gone@x>"),
        "missing source must drop"
    );

    // The copied bytes really moved: vol.part1.rar[5000..15000] ==
    // inner.bin[10000..20000], and the file spans the recorded size.
    let vol = std::fs::read(dir.join("vol.part1.rar")).unwrap();
    assert_eq!(vol.len(), 25_000);
    assert_eq!(&vol[5_000..15_000], &inner[10_000..20_000]);

    let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
    assert_eq!(seed.name, "vol.part1.rar");
    assert_eq!(seed.spans, vec![(5_000, 10_000)]);
    // Identity slot seeds too (its spans are trusted in place).
    assert!(restored.seeds.iter().any(|s| s.slot == 1));

    std::fs::remove_dir_all(&dir).unwrap();
}

/// The materialized-volume gap, measured 13 Aug 2026: a job whose
/// direct extraction fell back to volumes-on-disk left complete
/// volume files in the output directory, but its R records named the
/// inner files the fallback had just deleted - so a retry refetched
/// the ENTIRE post. The `M` line records that the fallback put those
/// bytes at final offsets in the volume file, and parse rewrites the
/// slot's placements to identity form.
#[test]
fn materialized_slot_restores_placements_as_identity() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-m-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>mat</nzb>";
    // Written BEFORE the records: X5-02 makes a placement commit to
    // the bytes a resume will read, and after the demote those are
    // the volume's. Production reaches the same number the other way
    // round - it records the POSTED bytes' crc, and the
    // reconstruction writes posted bytes, which is the premise the
    // `M` rewrite already rests on.
    std::fs::write(dir.join("vol.part01.rar"), vec![0xAAu8; 20_000]).unwrap();

    let (j, _) = Journal::open(&dir, nzb).unwrap();
    // Two direct-extracted articles whose fragments name an inner
    // file; a third on a slot that never demotes.
    j.record_placed(
        0,
        "<a@x>",
        None,
        "vol.part01.rar",
        20_000,
        &[frag("inner.bin", 7_000, 3_000, 5_000)],
        mat_crc(
            &dir,
            "vol.part01.rar",
            &[frag("inner.bin", 7_000, 3_000, 5_000)],
        ),
    );
    j.record_placed(
        0,
        "<b@x>",
        None,
        "vol.part01.rar",
        20_000,
        &[frag("inner.bin", 12_000, 8_000, 5_000)],
        mat_crc(
            &dir,
            "vol.part01.rar",
            &[frag("inner.bin", 12_000, 8_000, 5_000)],
        ),
    );
    j.record_placed(
        1,
        "<c@x>",
        None,
        "vol.part02.rar",
        20_000,
        &[frag("inner.bin", 0, 0, 100)],
        frags_crc(&dir, &[frag("inner.bin", 0, 0, 100)]),
    );
    // The demote: slot 0's bytes reconstructed into the volume file,
    // inner.bin deleted right after (so it does NOT exist here).
    j.record_materialized(0, "vol.part01.rar", 20_000);
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(
        restored.ids.contains("<a@x>") && restored.ids.contains("<b@x>"),
        "materialized slot's articles restore as identity, no inner file needed"
    );
    assert!(
        !restored.ids.contains("<c@x>"),
        "a slot that never demoted still needs its copy source"
    );
    let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
    assert_eq!(seed.name, "vol.part01.rar");
    let mut spans = seed.spans.clone();
    spans.sort();
    assert_eq!(spans, vec![(3_000, 5_000), (8_000, 5_000)]);
    // Identity means trusted in place: the volume's bytes are untouched.
    assert_eq!(
        std::fs::read(dir.join("vol.part01.rar")).unwrap(),
        vec![0xAAu8; 20_000]
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The rewrite is positional, mirroring `X`: a record appended after
/// the `M` line describes the file as it is now and is NOT rewritten,
/// and an `X` retiring the volume file after the `M` drops the
/// rewritten placements (which now name it).
/// Codex sweep D, 13 Aug 2026: a PAR2 report renames a writerless
/// slot after its `S` line landed, and the volume materializes
/// under the VERIFIED name. Replay must rewrite the slot's
/// placements onto the file that exists - the stale posted name
/// restored nothing and the retry refetched the whole post.
#[test]
fn a_materialized_slot_renamed_after_its_s_line_restores_under_the_new_name() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-mren-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>matren</nzb>";
    // Written BEFORE the records: X5-02 makes a placement commit to
    // the bytes a resume will read, and after the demote those are
    // the volume's. Production reaches the same number the other way
    // round - it records the POSTED bytes' crc, and the
    // reconstruction writes posted bytes, which is the premise the
    // `M` rewrite already rests on.
    std::fs::write(dir.join("verified.part01.rar"), vec![0xAAu8; 20_000]).unwrap();

    let (j, _) = Journal::open(&dir, nzb).unwrap();
    // Recorded under the obfuscated posted name…
    j.record_placed(
        0,
        "<a@x>",
        None,
        "0Bf3qZlM8kTn4dWx",
        20_000,
        &[frag("inner.bin", 7_000, 3_000, 5_000)],
        mat_crc(
            &dir,
            "verified.part01.rar",
            &[frag("inner.bin", 7_000, 3_000, 5_000)],
        ),
    );
    // …renamed from a PAR2 report while still writerless, then
    // materialized under that verified name.
    j.record_materialized(0, "verified.part01.rar", 20_000);
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(
        restored.ids.contains("<a@x>"),
        "the article is on disk under the verified name"
    );
    let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
    assert_eq!(seed.name, "verified.part01.rar");
    assert_eq!(seed.spans, vec![(3_000, 5_000)]);
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Codex sweep 13 Aug R3: the reverse ordering - the slot
/// MATERIALIZES under its posted name, and the PAR2 verify renames
/// it afterwards. The extractor re-fires the materialized hook on
/// that rename, which lands here as a second `S new-name` + `M`
/// pair: last-S-wins retargets the destination and the positional
/// rewrite carries every earlier placement onto the file that now
/// exists. Replay against a directory holding ONLY the verified
/// name must restore every placement - it used to find nothing and
/// refetch the whole post.
#[test]
fn a_rename_after_materialize_restores_under_the_new_name() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-renm-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>renafter</nzb>";
    // Written BEFORE the records: X5-02 makes a placement commit to
    // the bytes a resume will read, and after the demote those are
    // the volume's. Production reaches the same number the other way
    // round - it records the POSTED bytes' crc, and the
    // reconstruction writes posted bytes, which is the premise the
    // `M` rewrite already rests on.
    std::fs::write(dir.join("verified.part01.rar"), vec![0xAAu8; 20_000]).unwrap();

    let (j, _) = Journal::open(&dir, nzb).unwrap();
    // Placed under the obfuscated posted name, demoted under it...
    j.record_placed(
        0,
        "<a@x>",
        None,
        "0Bf3qZlM8kTn4dWx",
        20_000,
        &[frag("inner.bin", 7_000, 3_000, 5_000)],
        mat_crc(
            &dir,
            "verified.part01.rar",
            &[frag("inner.bin", 7_000, 3_000, 5_000)],
        ),
    );
    j.record_materialized(0, "0Bf3qZlM8kTn4dWx", 20_000);
    // ...one more placement while the demote-time name stands...
    j.record_placed(
        0,
        "<b@x>",
        None,
        "0Bf3qZlM8kTn4dWx",
        20_000,
        &[frag("0Bf3qZlM8kTn4dWx", 20_000, 9_000, 1_000)],
        mat_crc(
            &dir,
            "verified.part01.rar",
            &[frag("0Bf3qZlM8kTn4dWx", 20_000, 9_000, 1_000)],
        ),
    );
    // ...and then the verified-name publish (the re-fired hook).
    j.record_materialized(0, "verified.part01.rar", 20_000);
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(
        restored.ids.contains("<a@x>") && restored.ids.contains("<b@x>"),
        "every placement is on disk under the verified name: {:?}",
        restored.ids
    );
    let seed = restored.seeds.iter().find(|s| s.slot == 0).unwrap();
    assert_eq!(seed.name, "verified.part01.rar");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Append the retirement lines an older build's finish decrypt
/// would have written. Its producer (`Journal::invalidate`) went
/// with TODO 27 phase 3 - nothing mutates an output under live
/// records any more - but the PARSER stays, because a journal that
/// build left behind must still resume correctly. So the tests that
/// cover the parser write the record by hand.
///
/// Append mode, and every caller DROPS its `Journal` first. Two
/// reasons, and both bite: placement records sit in
/// [`WriteState::pending`] behind the batch rule until a flush, so
/// an `X` written past a live journal lands AHEAD of records that
/// were composed before it and the retirement stops being
/// positional; and the open handle's own offset does not move with
/// these writes either, so a record appended through it afterwards
/// would land on top of them.
fn append_retirement(dir: &Path, files: &[&str]) {
    use std::io::Write;
    let mut f = std::fs::OpenOptions::new()
        .append(true)
        .open(dir.join(".nzbfast.journal"))
        .unwrap();
    for n in files {
        writeln!(f, "X {n}").unwrap();
    }
}

#[test]
fn materialized_rewrite_is_positional_and_x_still_retires() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-mx-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>matx</nzb>";

    // Before-M and after-M articles on the demoting slot.
    // Written BEFORE the records: X5-02 makes a placement commit to
    // the bytes a resume will read, and after the demote those are
    // the volume's. Production reaches the same number the other way
    // round - it records the POSTED bytes' crc, and the
    // reconstruction writes posted bytes, which is the premise the
    // `M` rewrite already rests on.
    std::fs::write(dir.join("vol.rar"), vec![0u8; 10_000]).unwrap();
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record_placed(
        0,
        "<pre@x>",
        None,
        "vol.rar",
        10_000,
        &[frag("gone.bin", 500, 100, 400)],
        mat_crc(&dir, "vol.rar", &[frag("gone.bin", 500, 100, 400)]),
    );
    j.record_materialized(0, "vol.rar", 10_000);
    j.record_placed(
        0,
        "<post@x>",
        None,
        "vol.rar",
        10_000,
        &[frag("gone.bin", 500, 4_000, 400)],
        frags_crc(&dir, &[frag("gone.bin", 500, 4_000, 400)]),
    );
    {
        let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
        let r = restore(&dir, &resume, None);
        assert!(r.ids.contains("<pre@x>"), "pre-M record rewrites");
        assert!(
            !r.ids.contains("<post@x>"),
            "post-M record keeps its own fragment sources"
        );
    }
    // Retire the volume file itself: the rewritten placements name it
    // now, so they must drop with it.
    drop(j);
    append_retirement(&dir, &["vol.rar"]);
    let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
    let r = restore(&dir, &resume, None);
    assert!(
        !r.ids.contains("<pre@x>"),
        "X after M retires the rewritten identity placements"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A `D` (plaintext-once) record on a materialized slot rewrites to
/// PLAIN identity: the fallback reconstruction wrote POSTED bytes
/// into the volume, so no crypt facts or password are needed.
#[test]
fn materialized_slot_restores_crypto_placements_as_plain_identity() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-md-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>matd</nzb>";
    // Written BEFORE the records: X5-02 makes a placement commit to
    // the bytes a resume will read, and after the demote those are
    // the volume's. Production reaches the same number the other way
    // round - it records the POSTED bytes' crc, and the
    // reconstruction writes posted bytes, which is the premise the
    // `M` rewrite already rests on.
    std::fs::write(dir.join("vol.rar"), vec![0u8; 10_000]).unwrap();

    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record_placed_crypto(
        0,
        "<d@x>",
        None,
        "vol.rar",
        10_000,
        &[frag("secret.mkv", 2_000, 1_000, 3_000)],
        &[true],
        mat_crc(&dir, "vol.rar", &[frag("secret.mkv", 2_000, 1_000, 3_000)]),
    );
    j.record_materialized(0, "vol.rar", 10_000);
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    // No password, no E facts on disk - identity needs neither.
    let r = restore(&dir, &resume, None);
    assert!(
        r.ids.contains("<d@x>"),
        "D record restores as plain identity after materialization"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// An `M` line for a slot with no records (or a truncated volume
/// file) must not fabricate restores: identity is still gated on the
/// pre-restore file length.
#[test]
fn materialized_identity_still_respects_the_length_ceiling() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-ml-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>matl</nzb>";

    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record_materialized(9, "", 0); // no S line for slot 9: harmless no-op
    j.record_placed(
        0,
        "<t@x>",
        None,
        "vol.rar",
        10_000,
        &[frag("gone.bin", 0, 6_000, 4_000)],
        frags_crc(&dir, &[frag("gone.bin", 0, 6_000, 4_000)]),
    );
    j.record_materialized(0, "vol.rar", 10_000);
    // The volume survived only truncated: the identity span [6000,
    // 10000) is past the end, so the bytes cannot be there.
    std::fs::write(dir.join("vol.rar"), vec![0u8; 5_000]).unwrap();
    drop(j);

    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let r = restore(&dir, &resume, None);
    assert!(
        !r.ids.contains("<t@x>"),
        "identity past the pre-restore length must refetch"
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Finding A8, the restart half. A run that publishes decrypted
/// plaintext over an encrypted store output stops that file from being
/// the ciphertext its placement records describe. The next run must
/// refetch those articles from the provider rather than copy the
/// mutated bytes into the volume files and call them restored - which
/// is what poisoned the retry loop, since without PAR2 nothing was
/// ever going to notice.
#[test]
fn retired_claim_refetches_instead_of_restoring_mutated_bytes() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-x-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>retire</nzb>";

    // Run 1 direct-extracts two articles into movie.mkv (ciphertext at
    // store offsets) and one into an untouched sibling.
    let cipher: Vec<u8> = (0..40_000u32).map(|i| (i % 251) as u8).collect();
    std::fs::write(dir.join("movie.mkv"), &cipher).unwrap();
    std::fs::write(dir.join("extra.bin"), &cipher).unwrap();
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    for (id, off) in [("<a@x>", 0u64), ("<b@x>", 10_000)] {
        j.record_placed(
            0,
            id,
            None,
            "v.part1.rar",
            30_000,
            &[frag("movie.mkv", off, off, 10_000)],
            frags_crc(&dir, &[frag("movie.mkv", off, off, 10_000)]),
        );
    }
    j.record_placed(
        1,
        "<c@x>",
        None,
        "v.part2.rar",
        30_000,
        &[frag("extra.bin", 0, 0, 10_000)],
        frags_crc(&dir, &[frag("extra.bin", 0, 0, 10_000)]),
    );

    // Without the barrier those all come back - the intact-ciphertext
    // resume, the fast path a crash before the publish still gets.
    // (Records are batched - land them, as a decoder's idle flush
    // would have, before modelling the crash with a re-open.)
    j.flush();
    {
        let (_j, resume) = Journal::open(&dir, nzb).unwrap();
        let r = restore(&dir, &resume, None);
        assert!(r.ids.contains("<a@x>") && r.ids.contains("<b@x>") && r.ids.contains("<c@x>"));
        // Clear that probe's copy-back so the run below measures only
        // what the retirement allows.
        std::fs::remove_file(dir.join("v.part1.rar")).unwrap();
        std::fs::remove_file(dir.join("v.part2.rar")).unwrap();
    }

    // Now the decrypt publishes: the claim over movie.mkv is retired,
    // and only then do its bytes change.
    drop(j);
    append_retirement(&dir, &["movie.mkv"]);
    let plaintext: Vec<u8> = (0..40_000u32).map(|i| (i % 97) as u8).collect();
    std::fs::write(dir.join("movie.mkv"), &plaintext).unwrap();

    let (j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(
        !restored.ids.contains("<a@x>") && !restored.ids.contains("<b@x>"),
        "articles recorded into a mutated file were treated as restored"
    );
    assert!(
        restored.ids.contains("<c@x>"),
        "retiring one file must not cost every other file its resume"
    );
    // Nothing was copied out of the mutated file either.
    assert!(!dir.join("v.part1.rar").exists());

    // Retirement is positional: the refetched articles re-record and
    // are trusted again, so a second crash still resumes locally.
    j2.record_placed(
        0,
        "<a@x>",
        None,
        "v.part1.rar",
        30_000,
        &[frag("movie.mkv", 0, 0, 10_000)],
        frags_crc(&dir, &[frag("movie.mkv", 0, 0, 10_000)]),
    );
    drop(j2);
    let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(
        restored.ids.contains("<a@x>"),
        "a placement recorded AFTER the retirement must still count"
    );
    assert!(
        !restored.ids.contains("<b@x>"),
        "the stale one stays retired"
    );

    std::fs::remove_dir_all(&dir).unwrap();
}

/// An older binary reading a journal that carries retirement lines
/// must not mistake them for message ids (it refetches everything,
/// which is safe in both directions - the journal's forward/backward
/// compatibility contract).
#[test]
fn retirement_lines_are_never_read_as_message_ids() {
    let mut resume = ResumeState::default();
    parse_lines(
        ["X movie.mkv".to_string(), "<real@id>".to_string()].into_iter(),
        &mut resume,
    );
    assert_eq!(resume.completed.len(), 1);
    assert!(resume.completed.contains("<real@id>"));
}

#[test]
fn identity_without_existing_file_refetches() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-id-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>id</nzb>";
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record_placed(
        0,
        "<a@x>",
        Some(("data.bin".to_string(), 1_000)),
        "",
        0,
        &[frag("data.bin", 0, 0, 1_000)],
        frags_crc(&dir, &[frag("data.bin", 0, 0, 1_000)]),
    );
    drop(j);
    // data.bin was deleted between runs (user cleanup): the identity
    // fragment must NOT be trusted against a file we'd create fresh.
    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(restored.ids.is_empty());
    assert!(!dir.join("data.bin").exists(), "restore must not create it");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The path surviving is not the bytes surviving. A destination that
/// was truncated between runs (a partial write, an interrupted move, an
/// external tool) still passes an existence probe, so presence alone
/// would accept its identity fragments; `seed_slot` then grows the file
/// back to the recorded size and marks those spans covered, and with no
/// PAR2 behind the job the zeros ship. Refetch instead.
#[test]
fn identity_against_truncated_file_refetches() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-trunc-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>trunc</nzb>";
    // Run 1 placed two identity articles into a 1,000-byte data.bin.
    std::fs::write(dir.join("data.bin"), vec![7u8; 1_000]).unwrap();
    let (j, _) = Journal::open(&dir, nzb).unwrap();
    j.record_placed(
        0,
        "<a@x>",
        Some(("data.bin".to_string(), 1_000)),
        "",
        0,
        &[frag("data.bin", 0, 0, 400)],
        frags_crc(&dir, &[frag("data.bin", 0, 0, 400)]),
    );
    j.record_placed(
        0,
        "<b@x>",
        Some(("data.bin".to_string(), 1_000)),
        "",
        0,
        &[frag("data.bin", 400, 400, 600)],
        frags_crc(&dir, &[frag("data.bin", 400, 400, 600)]),
    );
    drop(j);

    // Between runs the file is truncated to 400 bytes: only the first
    // article's span survives.
    std::fs::OpenOptions::new()
        .write(true)
        .open(dir.join("data.bin"))
        .unwrap()
        .set_len(400)
        .unwrap();
    let (_j2, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(
        restored.ids.contains("<a@x>"),
        "a span the file still holds stays restored"
    );
    assert!(
        !restored.ids.contains("<b@x>"),
        "a span past the end of the file must refetch"
    );
    // Nothing past the truncation is handed to `seed_slot` as covered.
    let seeded: Vec<(u64, u64)> = restored
        .seeds
        .iter()
        .flat_map(|s| s.spans.iter().copied())
        .collect();
    assert_eq!(seeded, vec![(0, 400)]);
    assert!(
        seeded.iter().all(|&(off, len)| off + len <= 400),
        "no uncovered byte may be marked complete"
    );
    assert_eq!(
        std::fs::metadata(dir.join("data.bin")).unwrap().len(),
        400,
        "restore must not grow the file back"
    );

    // Truncated to nothing at all is the same verdict for both.
    std::fs::write(dir.join("data.bin"), b"").unwrap();
    let (_j3, resume) = Journal::open(&dir, nzb).unwrap();
    let restored = restore(&dir, &resume, None);
    assert!(restored.ids.is_empty(), "an empty file holds no span");
    assert!(restored.seeds.is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
fn malformed_and_torn_lines_are_ignored() {
    let dir = std::env::temp_dir().join(format!("nzbfast-journal-torn-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let nzb = b"<nzb>torn</nzb>";
    {
        let (j, _) = Journal::open(&dir, nzb).unwrap();
        j.record("<good@x>");
        drop(j);
    }
    // Simulate a torn tail + garbage placement lines.
    {
        use std::io::Write;
        let mut f = std::fs::OpenOptions::new()
            .append(true)
            .open(dir.join(".nzbfast.journal"))
            .unwrap();
        write!(f, "R 0 0:1:2:3 <no-ftable@x>\nS x y\nR 1 junk\nF 0\n<torn@").unwrap();
    }
    let (_j, resume) = Journal::open(&dir, nzb).unwrap();
    assert!(resume.completed.contains("<good@x>"));
    assert!(resume.slots.is_empty());
    // The torn bare line parses as a (harmless, never-matching) id.
    assert!(resume.completed.contains("<torn@"));
    std::fs::remove_dir_all(&dir).unwrap();
}
