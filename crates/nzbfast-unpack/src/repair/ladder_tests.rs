//! Which demote reasons reach the on-disk unpack ladder, and what that
//! ladder says when it refuses.
//!
//! Split out of `repair_tests` when the refusal-wording cases took that
//! file past the size gate's 3,000-line ceiling (TODO 106). Four cases
//! moved verbatim and the fifth arrived with the split; they belong
//! together because every one of them is about the ROUTING of a
//! fallback reason - which demotes must reach `try_unrar_spent_why`,
//! which are already owned by somebody else, and which wording the job
//! ends up wearing when the ladder refuses.

use super::*;

/// A demoted group whose volumes nobody else unpacks must reach the
/// on-disk pass, or the job "completes" over a directory of loose .rar
/// volumes with no payload in it. Both directions matter: the reasons
/// somebody else owns must stay out, because sending those to unrar
/// fails jobs that are fine today.
#[test]
fn demoted_volumes_nobody_owns_reach_the_disk_unpack() {
    // Reason strings as extract.rs emits them.
    for why in [
        // The f9983fa tiling gate: headers that do not describe a whole
        // file. Note "complete file" is IN this string - the near-miss
        // that made it look handled by the old "incomplete mapping" arm.
        "inner file's headers do not describe a complete file",
        // MapBlocker::Corrupt, via blocker_reason.
        "data area exceeds volume",
        "block length does not advance",
        // The reasons the ladder already knew.
        "inner file failed its stored CRC",
        "inner file carries only a hash the fast path can't verify",
        "held-bytes cap: header stash",
        "incomplete mapping at end of download",
        "routed span lost its destination",
        "chase failed: worker died",
    ] {
        assert!(
            fallback_needs_disk_unpack(why),
            "'{why}' would ship a job with no payload and exit 0"
        );
    }
    // Owned by somebody else - handing these to unrar breaks jobs that
    // work today.
    for why in [
        // The caller's own encrypted/password/compressed branches.
        "encrypted headers (password required)",
        "encrypted entries (password required)",
        "wrong archive password",
        "compressed or encrypted entries",
        "encrypted data incomplete",
        "encrypted data failed its checksum (wrong password)",
        // The nested post-pass repairs the inner layer before unpacking.
        "nested fallback: inner file failed its stored CRC",
        "nested fallback: inner mapping unfinished at end of download",
        // Not an archive at all: there is no set for unrar to open.
        "not a RAR volume",
        "never classified",
        "unclassified-holds budget",
        // The PAR2 path re-extracts these itself and removes them.
        "materialized for repair",
    ] {
        assert!(
            !fallback_needs_disk_unpack(why),
            "'{why}' is already owned - unpacking it again fails a good job"
        );
    }
}

/// The one demote that must NOT reach the disk unpack: the bomb guard's.
///
/// Every rung under a demote exists because the demote was about the
/// ARCHIVE, and a second engine may do better on an archive. A bomb
/// verdict is about the DISK, where no engine does better - and the
/// last rung, the external `unrar` subprocess, carries no budget at
/// all. Measured 22 Aug 2026 on a 2 GB APFS image with ~730 MB free:
/// a 2 GB-of-zeros RAR5 (88 KB posted) was refused in-stream, refused
/// again by `BombGuardWriter`, and then written by unrar until the
/// device said ENOSPC - so a refused bomb filled the disk once anyway,
/// and the job blamed the archive ("encrypted or damaged?").
///
/// Note the first assertion: the reason IS an unowned demote by every
/// other rule in this file, which is exactly why the bomb arm has to
/// sit AHEAD of the ladder rather than inside it.
///
/// The last blocks cover the one route where no verdict can be reached
/// at all. Under `nzbkit::extract::prefer_external_unrar` no budgeted
/// engine runs, so nothing raises the text these arms read - and the
/// floor there is a preflight against the headers instead. It is
/// asserted here rather than only beside itself because "the ladder has
/// a floor" is one property, and it was true of three rungs out of four
/// for a day.
///
/// …and the last block of all covers what the floor SAYS. A refusal
/// that stops the ladder still has to word the job failure, and until
/// this test grew that section the two refusals INSIDE the ladder had
/// no way to: `try_unrar_spent` answered a bare `None`, and the tail
/// composed "the verified volumes could not be unpacked (compressed
/// set, or the password is wrong)" - the archive blamed for the disk,
/// one layer down from where the arm above had already fixed exactly
/// that. Both halves are asserted: the reason a refusal names must
/// carry the verdict and must not read as a disk-full, and the generic
/// sentences must NOT carry the verdict, because a generic that
/// happened to say "decompression bomb" would make preferring the
/// reason unobservable.
///
/// That list grew on 22 Aug 2026 with the sentences of the two arms
/// that were reading the ladder through its BOOL wrappers and so still
/// dropped the verdict: the nested-archive pass, whose refusal reached
/// the user as "damaged, encrypted, or an unsupported compression
/// method", and the password unlock, which reported a full disk as a
/// whole passwords file of wrong guesses. They belong in this list and
/// not in a parallel test - the contract is one contract, and a
/// sentence that starts reading as a bomb (or as a disk-full) breaks it
/// wherever it lives.
#[test]
fn a_bomb_verdict_forecloses_the_unpack_ladder() {
    for why in [
        nzbkit::disk::BOMB_VERDICT.to_string(),
        // As chase.rs composes a failed compressed chase - the shape the
        // 22 Aug repro actually took.
        format!("chase failed: {}", nzbkit::disk::BOMB_VERDICT),
    ] {
        assert!(
            fallback_needs_disk_unpack(&why),
            "'{why}' reads as unowned, so only the bomb arm can stop it"
        );
        let msg = bomb_fallback([why.as_str()])
            .unwrap_or_else(|| panic!("'{why}' would be handed to an unpacker with no budget"));
        assert!(
            nzbkit::disk::bomb_verdict(&msg),
            "the job must fail with the verdict it reached: {msg}"
        );
        // Deliberately not a "disk full" for the daemon's classifier:
        // that arms the min-free hold, which returns the job to the
        // queue to wait for space it can never have enough of.
        assert!(
            !crate::failkind::disk_full_failure(&msg),
            "a bomb must not be held for free space: {msg}"
        );
    }
    // Every ordinary demote keeps its ladder.
    for why in [
        "inner file failed its stored CRC",
        "held-bytes cap: header stash",
        "compressed or encrypted entries",
        "chase failed: worker died",
    ] {
        assert!(
            bomb_fallback([why]).is_none(),
            "'{why}' would lose the unpack that finishes the job"
        );
    }
    // …including the reason a `prefer_external_unrar` job demotes with,
    // which is the point: on that route the native pass is skipped, so
    // no guard has measured anything and no arm above can stop the set
    // reaching a subprocess with no ceiling. The preflight is what
    // stands there, and it draws the line at the 22 Aug numbers - 2 GB
    // declared, 730 MB free.
    use crate::rarfix::preflight::declared_exceeds_free;
    assert!(
        bomb_fallback(["compressed or encrypted entries"]).is_none(),
        "the route with no verdict must keep its ladder - the preflight is its floor"
    );
    assert!(
        declared_exceeds_free(2_000_000_000, Some(730_000_000)),
        "the engine setting must not decide whether the guard exists"
    );
    assert!(
        !declared_exceeds_free(50_000_000_000, Some(60_000_000_000)),
        "a real release that fits must still be handed to unrar"
    );

    // What a refusal inside the ladder says. `try_unrar_spent_why`'s two
    // bomb rungs - the native pass's verdict and the preflight ahead of
    // the unrar spawn - return this sentence, and it is the same one
    // `bomb_fallback` fails a demote with, deliberately: a user who hits
    // the guard from either side reads the same thing.
    let named = crate::diag::bomb_failure();
    assert_eq!(
        Some(&named),
        bomb_fallback([nzbkit::disk::BOMB_VERDICT]).as_ref(),
        "the in-ladder refusal and the demote arm must say one thing"
    );
    assert!(nzbkit::disk::bomb_verdict(&named), "{named}");
    assert!(
        !crate::failkind::disk_full_failure(&named),
        "a bomb must not be held for free space: {named}"
    );

    // The sentences the reading sites fall back to when a refusal named
    // nothing - every ordinary failure, which is nearly all of them.
    // Each blames the archive, correctly, for the failure it was written
    // for; none of them may be reached by a bomb.
    //
    // Two of them are formatted at their site, around the name of the
    // archive that stopped the pass, so they are formatted here too -
    // the sentence the user reads is the whole string, not the literal
    // it was built from.
    let stopped_at = "inner.part01.rar";
    for generic in [
        // get/tail.rs, the compressed / wrong-password arm…
        "the verified volumes could not be unpacked \
         (compressed set, or the password is wrong)"
            .to_string(),
        // …its unowned-demote twin…
        "the verified volumes could not be unpacked after a fallback".to_string(),
        // …the resumed-job re-extract…
        "resumed job: the verified volumes on disk could not be extracted".to_string(),
        // …get/settle.rs after a repair…
        "PAR2 repair succeeded but re-extraction failed".to_string(),
        // …the nested-archive pass's three, which read the ladder
        // through `try_unrar` until 22 Aug 2026 and so blamed the
        // archive for the disk one pass further out…
        format!(
            "the payload {stopped_at} could not be unpacked \
             (damaged, encrypted, or an unsupported compression method)"
        ),
        format!("{stopped_at} in the output directory could not be unpacked"),
        "an archive in the output directory could not be unpacked".to_string(),
        // …and the manual unlock, whose sweep siblings now stand down
        // rather than word anything at all.
        "password did not unlock the archive".to_string(),
    ] {
        let generic = generic.as_str();
        assert!(
            !nzbkit::disk::bomb_verdict(generic),
            "'{generic}' already reads as a bomb, so preferring the reason proves nothing"
        );
        assert!(
            !crate::failkind::disk_full_failure(generic),
            "'{generic}' would arm the min-free hold"
        );
        // The rule itself: a named reason wins, and nothing else does.
        assert_eq!(
            crate::diag::unpack_failure(Some(named.clone()), generic),
            named
        );
        assert_eq!(crate::diag::unpack_failure(None, generic), generic);
    }
}

/// A refusal must not INVENT a reason. Everything the ladder fails on
/// that is not the disk - a compressed set, a wrong password, a damaged
/// volume, or (here) a directory with no archive in it at all - has to
/// arrive as `Err(None)`, so the caller's own wording still stands.
///
/// The bomb side of the same contract cannot be reached from a unit
/// test: both rungs that raise it measure the REAL filesystem
/// (`serve::free_bytes`), and the seam that now injects that reading is
/// an env var a unit test cannot use safely - `cargo test --bin
/// nzbfast` runs every test as a thread of ONE process, which is why
/// `external_unrar_closed` is a cfg and not a variable. It is asserted
/// as message composition in `a_bomb_verdict_forecloses_the_unpack_ladder`
/// above, and end to end - all five routes, off `mode=history` - by the
/// daemon suite's `daemon_bomb`, which spawns a daemon per route with
/// `NZBFAST_TEST_FREE_BYTES` set (TODO 222). Before that seam the only
/// end-to-end record was the 22 Aug repro recipe, run by hand on a
/// 1.5 GB sparse image.
///
/// All FIVE entry points into the disk ladder are asserted here, which
/// is the point of doing it in one test: they are the same ladder seen
/// from five distances, and the three that used to read it through a
/// bool could therefore only ever have answered "no reason" by accident
/// - the two added on 22 Aug 2026, and the recovery-record rung, which
/// was the last one left and closed on 23 Aug (TODO §249 item 1).
#[test]
fn an_ordinary_unpack_failure_carries_no_reason() {
    let dir = std::env::temp_dir().join(format!("nzbfast-noreason-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    // Not an archive, and not named like one: no group forms, nothing
    // unpacks, and the ladder has nothing to say about why.
    std::fs::write(dir.join("readme.nfo"), b"nothing to unpack here").unwrap();
    assert_eq!(crate::rarfix::try_unrar_spent_why(&dir, None), Err(None));
    // …and a directory with nothing packed in it is a legitimate no-op
    // success on the repair-side entry point, unchanged by any of this.
    assert_eq!(crate::reextract_dir_why(&dir, None).unwrap(), Ok(()));
    // A `.rar` that is not one: a group DOES form, every engine
    // declines it, and that is still not a reason - on both entry
    // points, since the repair one ends at the same ladder.
    std::fs::write(dir.join("film.rar"), b"Rar!\x1a\x07\x01\x00 truncated").unwrap();
    assert_eq!(crate::rarfix::try_unrar_spent_why(&dir, None), Err(None));
    assert_eq!(crate::reextract_dir_why(&dir, None).unwrap(), Err(None));
    // The nested pass one level out. It fails - a file with a RAR head
    // that no arm could claim is not a completed job - and it must fail
    // with the channel still empty, because the tail prefers whatever is
    // in it over its own three sentences.
    let mut why: Option<String> = None;
    let nested = crate::unpack::extract_nested_why(&dir, None, 0, &mut why).unwrap();
    assert!(!nested.produced(), "{nested:?}");
    assert_eq!(why, None, "the nested pass invented a reason");
    // …and the unlock, whose Err(None) is what keeps a wrong password
    // being reported as a wrong password.
    assert_eq!(crate::unlockpw::unlock(&dir, "sesame"), Err(None));
    // The recovery-record rung, the fifth and last entry point. Its
    // refusal here is the FIRST of the two it can give - no volume
    // carried a record, so "could not save the set", which is squarely
    // about the archive and must arrive unworded. The bomb side is the
    // same unreachable-from-a-unit-test case as the four above, and by
    // the same mechanism: the verdict is raised by the extraction this
    // rung runs AFTER a repair, which is `try_unrar_spent_why` again.
    assert_eq!(crate::rarfix::try_rar_rr_repair_why(&dir, None), Err(None));
    // Its hinted twin is the same function with the PAR2 verdict in
    // hand, and an empty hint must not change the answer. The two
    // settle-side callers take one arm each: the hinted one in
    // `get/settle/repair.rs`, the plain one in `get/settle/noset.rs`.
    assert_eq!(
        crate::rarfix::try_rar_rr_repair_hinted_why(&dir, None, None),
        Err(None)
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// A top-level 7z chase that demoted is owned by the 7z post-pass,
/// and its reason must not reach the RAR ladder at all - not the
/// unowned arm, not the encrypted arm. Both wordings are pinned
/// because both occur (the retention cap, and an archive whose
/// header needs a password), and both would otherwise end at
/// `try_unrar` over a directory holding one .7z, which fails.
#[test]
fn a_demoted_top_level_7z_stays_out_of_the_rar_ladder() {
    for why in [
        "held-bytes cap: chase memory",
        "inner 7z is encrypted (no password)",
        "inner 7z codec unsupported: 30101",
        "materialized for repair",
    ] {
        let marked = format!("{}{why}", nzbkit::extract::SEVENZ_DISK_FALLBACK_PREFIX);
        assert!(sevenz_disk_fallback(&marked), "'{marked}'");
        // The underlying reason stays readable inside it - the
        // "held-bytes cap" substring other callers key off included.
        assert!(marked.contains(why));
    }
    // A RAR volume demote is untouched by the marker check.
    assert!(!sevenz_disk_fallback("held-bytes cap: chase memory"));
    assert!(!sevenz_disk_fallback(
        "nested fallback: inner 7z decode failed"
    ));
}

/// The SFX twin (TODO 94 C): a volume the offset-0 sniff started inside a
/// launcher stub materializes as the posted `.exe`, which the get tail's
/// SFX arm owns. A COMPRESSED SFX RAR reaches this every time - the chase
/// declines a non-zero archive base - and unmarked its "compressed" reason
/// ran the ladder's first arm, `unrar` over a directory holding one `.exe`,
/// which cannot succeed and failed the whole job.
#[test]
fn a_demoted_sfx_volume_stays_out_of_the_rar_ladder() {
    for why in [
        "compressed or encrypted entries",
        "held-bytes cap: header stash",
        "incomplete mapping at end of download",
        "encrypted entries (password required)",
    ] {
        let marked = format!("{}{why}", nzbkit::extract::SFX_DISK_FALLBACK_PREFIX);
        assert!(sevenz_disk_fallback(&marked), "'{marked}'");
        assert!(marked.contains(why));
    }
    // Unmarked, every one of those is an ordinary RAR volume demote and
    // the ladder must still claim it.
    assert!(!sevenz_disk_fallback("compressed or encrypted entries"));
}

/// The one SFX demote the arm must NOT be handed: locked with no password.
/// `MapBlocker::NotStore` carries the word "encrypted" as well as
/// "compressed", so the compressed test has to come first - a bare
/// "encrypted" match printed a password prompt for an archive needing none.
#[test]
fn only_a_locked_sfx_demote_takes_the_password_prompt() {
    let mark = |w: &str| format!("{}{w}", nzbkit::extract::SFX_DISK_FALLBACK_PREFIX);
    assert!(sfx_locked_fallback(&mark(
        "encrypted entries (password required)"
    )));
    assert!(sfx_locked_fallback(&mark(
        "encrypted headers (password required)"
    )));
    assert!(sfx_locked_fallback(&mark("wrong archive password")));
    // The both-words blocker is a COMPRESSED set, and the SFX arm carves
    // and unpacks it - no prompt.
    assert!(!sfx_locked_fallback(&mark(
        "compressed or encrypted entries"
    )));
    assert!(!sfx_locked_fallback(&mark("held-bytes cap: header stash")));
    // An unmarked demote is some other slot's, whatever it says.
    assert!(!sfx_locked_fallback(
        "encrypted entries (password required)"
    ));
}

/// The zip twin: a demoted top-level zip chase leaves a `.zip` the
/// disk post-pass's own ladder step owns, and its reason text -
/// which carries "password"/"compression" wordings - must stay out
/// of the RAR ladder for the same reason.
#[test]
fn a_demoted_top_level_zip_stays_out_of_the_rar_ladder() {
    for why in [
        "held-bytes cap: chase memory",
        "movie.mkv is password-protected and encrypted zip is not supported",
        "movie.mkv uses bzip2 compression, which is not built in",
    ] {
        let marked = format!("{}{why}", nzbkit::extract::ZIP_DISK_FALLBACK_PREFIX);
        assert!(sevenz_disk_fallback(&marked), "'{marked}'");
        assert!(marked.contains(why));
    }
}

/// The tar twin (TODO 163 item 6). A demoted tar leaves a `.tar` in
/// the output directory - which is what a posted tar left there before
/// the chase arm existed - so the RAR ladder must not see its reason
/// and conclude it has volumes to remediate.
#[test]
fn a_demoted_top_level_tar_stays_out_of_the_rar_ladder() {
    for why in [
        "held-bytes cap: chase memory",
        "entry \"link\" is a symlink, which is not extracted",
        "the tar holds a sparse member, which is not extracted",
    ] {
        let marked = format!("{}{why}", nzbkit::extract::TAR_DISK_FALLBACK_PREFIX);
        assert!(sevenz_disk_fallback(&marked), "'{marked}'");
        assert!(marked.contains(why));
    }
}
