//! The blocking half of a completed job's finalization: unlock, the
//! identity ladder, the cleanup sweeps, and the rename/TV filing.
//!
//! Lifted out of `job.rs::finalize_completed_gen` whole under the size
//! gate (TODO 106). It is a verbatim move: the body ran inside a
//! `spawn_blocking` closure that captured exactly these values and
//! returned exactly these fields, so the cut is where the thread
//! boundary already was. Nothing here decides when it runs, what fence
//! it runs under, or what is written back - all three stay with the
//! caller.
//!
//! It advances the queue row's activity token as it goes
//! (`Daemon::note_tail_stage`). That is the whole reason this stretch
//! is worth naming: it is minutes of work on someone else's machine -
//! a password try-order walk, two third-party identity requests at ten
//! seconds apiece, a sweep, a rename - and until it did, every second
//! of it rendered as "unpacking" on the row.

use super::*;

/// Everything the blocking pass hands back, in the order the caller
/// writes it onto the record. A struct rather than the nine-tuple this
/// was, because the tuple had already outgrown being readable at the
/// call site and `clippy::type_complexity` says so.
pub struct FinalizeOutcome {
    pub(super) needs_pw: bool,
    /// The unlock ladder's own reason for refusing, when it named one.
    ///
    /// Today only a bomb verdict, and it is not a password story at
    /// all: the set may well open with the first candidate once there is
    /// room, so `needs_pw` stays false and the row must not send the
    /// user off to find a password that was never the problem. Written
    /// onto `fail_message` by the caller, which is where a *arr reads
    /// the job's verdict.
    pub(super) unlock_refused: Option<String>,
    pub(super) pw_used: Option<String>,
    pub(super) blocked_by: String,
    pub(super) moved: Option<PathBuf>,
    pub(super) filed_sfx: Option<String>,
    pub(super) filed_ttl: Option<String>,
    pub(super) ident: crate::identity::Identity,
    pub(super) identified: String,
    pub(super) cleaned: (usize, usize, bool),
}

impl FinalizeOutcome {
    /// What a PANICKED pass leaves behind. The files are untouched -
    /// the panic aborted the body before or during them - so every
    /// field is the "nothing happened" value and the note points the
    /// user at Retry, which re-runs this whole tail.
    pub(super) fn crashed() -> Self {
        FinalizeOutcome {
            needs_pw: false,
            unlock_refused: None,
            pw_used: None,
            blocked_by:
                "post-processing did not finish (internal error) - retry the job to re-run it"
                    .to_string(),
            moved: None,
            filed_sfx: None,
            filed_ttl: None,
            ident: crate::identity::Identity::default(),
            identified: String::new(),
            cleaned: (0, 0, false),
        }
    }
}

/// The pass itself. Runs on a blocking thread; takes owned values only,
/// exactly as the closure it replaces did.
#[expect(clippy::too_many_arguments)]
pub(super) fn finalize_payload(
    d3: Arc<Daemon>,
    nzo3: String,
    out2: PathBuf,
    repl2: Option<PathBuf>,
    pw2: Option<String>,
    nzb2: PathBuf,
    site2: String,
    name2: String,
    crc2: u32,
    exts: Vec<String>,
    cat2: String,
    tv2: bool,
) -> FinalizeOutcome {
    // Test hook: hold this job's tail open the way the field
    // does (a Finder-trash stall, a NAS move), so the queue
    // suite can pin the window where the NEXT job has drained
    // but is still Downloading behind this tail. No effect
    // unless the suite sets it.
    if let Some(ms) = std::env::var("NZBFAST_TEST_STALL_FINALIZE_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        std::thread::sleep(std::time::Duration::from_millis(ms));
    }
    // A6: this job downloaded beside a previous
    // successful result of the same name. It verified,
    // so it takes the canonical directory over now -
    // before the unlock / still-packed / cleanup /
    // rename steps below, every one of which reads the
    // finished directory and must see the final one.
    let mut out2 = out2;
    let mut moved = repl2.and_then(|canon| publish_over_previous(&out2, &canon));
    if let Some(dest) = &moved {
        out2 = dest.clone();
    }
    let mut needs_pw = false;
    let mut unlock_refused: Option<String> = None;
    let mut pw_used: Option<String> = None;
    let mut locked_name = String::new();
    if let Some(vol) = crate::unlockpw::encrypted_archive(&out2) {
        // A password try-order walk can be a long stretch of real
        // work (every candidate is an extraction attempt), and it
        // is the one tail stage a user can act on - so name it
        // rather than let it read as "unpacking" like everything
        // else used to.
        d3.note_tail_stage(&nzo3, "unlocking");
        locked_name = vol
            .file_name()
            .map(|n| n.to_string_lossy().to_string())
            .unwrap_or_default();
        // §99 try-order keys, read once per locked job: which
        // site supplied the NZB, and who posted it.
        let poster2 = crate::smart::nzb_poster(&nzb2);
        // A refusal that NAMED itself ends the whole walk below rather
        // than being read as "this password did not work" once per
        // candidate. See [`crate::unlockpw::unlock`]. The reason travels in
        // an argument rather than a capture so that the walk can read it
        // between attempts.
        let mut refused: Option<String> = None;
        let spend =
            |pw: &str, refused: &mut Option<String>| match crate::unlockpw::unlock(&out2, pw) {
                Ok(()) => true,
                Err(why) => {
                    *refused = why;
                    false
                }
            };
        match pw2.as_deref() {
            Some(pw) if spend(pw, &mut refused) => {
                // The job's own password worked - refresh the
                // §99 association so the next job from this
                // site or poster tries it first.
                d3.record_unlock_password(&site2, &poster2, pw);
            }
            _ => {
                // SAB/NZBGet-parity passwords file: the job's
                // own password is absent (or just failed), so
                // try the file's candidates - read fresh, so a
                // line added minutes ago counts, in §99 order
                // (site association, poster association, then
                // the file top to bottom). The winner is
                // recorded onto the job below - history then
                // shows has_password, and a retry of this job
                // reuses it directly.
                //
                // A loop rather than `find`, for the stand-down: the
                // walk stops at a named refusal, including one the job's
                // own password already raised above. It is the disk, and
                // every candidate below meets the same one - a full disk
                // used to burn the entire file and then blame the
                // passwords in it.
                let mut winner: Option<String> = None;
                for pw in d3.read_unpack_passwords_for(&site2, &poster2) {
                    if refused.is_some() {
                        break;
                    }
                    if spend(&pw, &mut refused) {
                        winner = Some(pw);
                        break;
                    }
                }
                match winner {
                    Some(pw) => {
                        info!(
                            target: "unlock",
                            "{name2:?}: unlocked with a password from the passwords file"
                        );
                        d3.record_unlock_password(&site2, &poster2, &pw);
                        pw_used = Some(pw);
                    }
                    None if refused.is_some() => {
                        // Not a password story: nothing here was ever
                        // tested against the archive. The reason is the
                        // job's verdict and the 🔑 is not raised.
                        warn!(target: "unlock", "{name2:?}: the unlock was refused - {}",
                            refused.as_deref().unwrap_or_default());
                        unlock_refused = refused.take();
                    }
                    None => {
                        info!(
                            target: "unlock",
                            "{name2:?}: volumes are password-protected - set a password to unpack"
                        );
                        needs_pw = true;
                    }
                }
            }
        }
    }
    // Something in a SUCCESSFUL job is still packed
    // and we have no unpacker for it (today: any
    // zip). Read off the finished directory rather
    // than threaded out of the engine, exactly like
    // the encrypted-volume check above - which also
    // means a resumed or retried job reports it
    // just the same.
    //
    // Sidecars only. A zip that IS the payload
    // fails the job outright now, so it arrives
    // here as a fail_message and never reaches
    // this block; what is left is the
    // `Subs/subs.zip` beside a feature that
    // unpacked fine, which is worth saying and is
    // not worth failing over.
    let mut blocked_by = crate::unsupported_archive_present(&out2)
        .filter(|u| !u.blocking)
        .map(|u| u.display)
        .unwrap_or_default();
    // "never ask" prompt mode: the job completes with the set
    // left packed for manual extraction, and since no failure
    // text will say so, the amber still-packed note has to
    // carry the WHY - the locked archive's own name.
    if needs_pw && blocked_by.is_empty() && d3.password_prompt.lock_ok().as_str() == "never" {
        blocked_by = locked_name;
    }
    // BEFORE the sweeps: the .par2 sidecars the fingerprint
    // rung reads are exactly what a cleanup rule deletes, and
    // `keep_media_only` inside finalize_names deletes them
    // whether or not one is configured.
    // Up to two third-party requests (srrdb, xREL), ten seconds
    // apiece before they give up. On a machine that cannot reach
    // either, this stage alone is twenty seconds of a row that
    // used to say "unpacking".
    d3.note_tail_stage(&nzo3, "identifying");
    let ident = if needs_pw {
        // A still-locked job has no unpacked payload to inspect
        // and no name to teach anything, and its archive headers
        // never parsed - so there is nothing to ask about.
        crate::identity::Identity::default()
    } else {
        crate::naming::resolve_identity(&d3, &nzo3, &out2, &name2, crc2)
    };
    // The counts survive into the job record now (see
    // Job::cleaned_files): these sweeps delete files out of a
    // finished download under settings and defaults, and nothing
    // in the UI ever said so. Whether the deletes were
    // recoverable is read AFTER the sweeps run - the setting is
    // live and the drawer renders later, so only this moment
    // knows - and reading it after means a Trash that latched
    // unresponsive mid-sweep reports "removed", never a Trash
    // that was not really used.
    d3.note_tail_stage(&nzo3, "renaming");
    let mut cleaned = (0usize, 0usize);
    if !exts.is_empty() {
        cleaned = crate::smart::cleanup(&out2, &exts);
    }
    // Auto-rename & cleanup run only once the payload is
    // actually unpacked (a still-locked job has no media
    // to rename or non-junk to keep).
    // `.or(moved)`: a renamed/relocated folder wins,
    // but an A6 hand-over with no rename still has to
    // report its new directory.
    //
    // The suffix comes back with it: it is what filing
    // wrote onto the files, and only this moment knows
    // it. A still-locked job never got that far, so it
    // has none to record (None, not "").
    let mut filed_sfx = None;
    let mut filed_ttl = None;
    let mut identify = String::new();
    // UX §18: set only when the relocation stopped part way and
    // left the payload in two directories. Nothing else in the
    // record can say so - `moved` follows the bytes that made
    // it, which is exactly what makes the other half invisible.
    if !needs_pw {
        // Rename off the canonical name when an oracle supplied
        // one: `name2` is what the submitter called this and
        // stays on the record, but it is not necessarily what
        // the release IS.
        let naming = if ident.name.is_empty() {
            name2.as_str()
        } else {
            ident.name.as_str()
        };
        let post_year = match post_year_of(&nzb2) {
            0 => crate::identify::current_year(),
            y => y,
        };
        let done = crate::naming::finalize_names(
            &d3,
            &out2,
            &FinalizeJob {
                name: naming,
                cat: &cat2,
                tv_sort: tv2,
                post_year,
            },
        );
        moved = done.moved.or(moved);
        filed_sfx = Some(done.suffix);
        filed_ttl = Some(done.filed_title);
        identify = done.identify;
        cleaned.0 += done.swept;
    }
    let cleaned = (
        cleaned.0,
        cleaned.1,
        crate::smart::delete_to_trash() && !crate::smart::trash_unresponsive(),
    );
    FinalizeOutcome {
        needs_pw,
        unlock_refused,
        pw_used,
        blocked_by,
        moved,
        filed_sfx,
        filed_ttl,
        ident,
        identified: identify,
        cleaned,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The defect these stage tokens exist for.
    ///
    /// The pipeline's last activity word is `"extracting"`, written when
    /// the disk-unpack ladder begins, and only `park` ever removes the
    /// entry. Nothing wrote to the map in between, so this whole pass -
    /// unlock, identity, sweeps, rename - reported itself as an unpack,
    /// and so did the post-job script and the history write behind it.
    /// A tester watched four to five minutes of that on a 389 MB
    /// release and reported the job as hung, which is the only sensible
    /// reading of a word that never changes.
    ///
    /// Asserted as "not extracting" rather than as one exact token: the
    /// point is that the pass stops making a claim that has become
    /// false, not that it ends on any particular stage.
    #[test]
    fn the_tail_stops_calling_itself_an_unpack() {
        let dir = std::env::temp_dir().join(format!("nzbfast-tailstage-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let d = crate::testutil::test_daemon(&dir);
        // Exactly where `get/tail.rs` leaves it.
        d.hub
            .activity
            .lock_ok()
            .insert("nzo-tailstage".into(), "extracting");
        // The identity ladder reaches srrdb and xREL, which a unit test
        // has no business calling. Off: the stage token is stamped
        // before the ladder either way, which is what is under test.
        d.identity_lookup.store(false, Ordering::Relaxed);
        let out = finalize_payload(
            d.clone(),
            "nzo-tailstage".into(),
            dir.clone(),
            None,
            None,
            dir.join("job.nzb"),
            String::new(),
            "Some.Release.S01E01.1080p-GRP".into(),
            0,
            Vec::new(),
            String::new(),
            false,
        );
        assert!(!out.needs_pw, "an empty directory holds no locked archive");
        assert_ne!(
            d.hub.activity.lock_ok().get("nzo-tailstage").copied(),
            Some("extracting"),
            "the tail must stop reporting an unpack once unpacking is over"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}
