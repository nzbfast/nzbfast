//! What one download run is asked to do: the twenty inputs
//! [`super::get_with_progress`] takes, as one value.
//!
//! A struct rather than a parameter list, and the reason is the size
//! gate rather than taste (31 Aug 2026). The orchestrator sat at
//! EXACTLY 500 of the 500-line function ceiling, sixty-four of those
//! lines were its own signature, and roughly fifty of the sixty-four
//! were the notes below - so an ordinary lane threading one more option
//! through it had nowhere to put the option OR its note, and the next
//! line anybody added reddened main for whoever pushed next.
//! `seed_donated_slots` in `get/mod.rs` already carries that complaint
//! in its own doc comment; this is the answer to it. A field added here
//! costs the orchestrator nothing, however long its explanation runs.
//!
//! Named fields are worth having at the three call sites in their own
//! right: `run_cmds.rs` used to pass a bare `true` and a bare `false`
//! into a run of six positional `bool`s with a comment beside each one
//! to say which was which, and two of those swapped would have compiled
//! clean.
//!
//! This is NOT the bundle `finish_run`'s doc talks itself out of, and
//! the difference is what makes it worth having: there the cost being
//! weighed was the CALL SITE, where a bundle spends the lines it saves.
//! Here the cost was the SIGNATURE - fifty lines of notes that no call
//! site ever paid for and that the size gate counted against the
//! orchestrator on every one of them.
//!
//! What belongs here: an input the CALLER decides, per run. What does
//! not: anything the run works out for itself - the clamped
//! concurrency, the parsed NZB, the journal, the fleet. Those are the
//! phase bundles (`Intake`, `FetchPlan`, `Rig`, `Fleet`, `Counters`,
//! `TailWatchers`), and they are built inside the orchestrator because
//! nobody outside it can supply them.

use crate::*;
use std::path::Path;

/// Who retires the article journal when a run finishes clean.
///
/// X5-03 of the 30 Aug 2026 adversarial-row set: journal retirement and
/// terminal completion must be ONE crash transaction. The journal is the
/// only durable record of what ARRIVED, so whoever unlinks it is
/// asserting that the run's outcome is now recorded somewhere a restart
/// can read - and that assertion is true for exactly one of the two
/// front ends.
///
/// A `nzbfast get` has no other record, so its own good finish IS the
/// last durable word and [`Self::Run`] is correct: a second `get` over
/// the same directory could not know the file is complete (a plain
/// no-PAR2 post leaves nothing on disk that certifies bytes after the
/// fact), so refetching is the only honest thing it can do and there is
/// nothing for a deferred journal to protect.
///
/// The DAEMON does have one - the queue row - and it commits it LATER,
/// in its own post-processing tail. Retiring the journal at the engine's
/// finish therefore opened a window with no durable terminal state on
/// either side of it: measured 31 Aug 2026, a SIGKILL there left the
/// payload byte-exact on disk, the journal gone and the persisted row
/// saying `Finishing`, which `serve::job_wire`'s wildcard state arm
/// restores as `Queued` - so the job re-ran, had nothing to resume from,
/// asked for 44 bodies that were all refused, and filed `Failed` over an
/// output directory holding the finished release. That is what an *arr
/// reads. [`Self::Caller`] closes it.
///
/// See `research/X5-03-CRASH-TRANSACTION-2026-08-31.md` section 7 for
/// the measurement and `crates/nzbfast/tests/daemon_crashtx/` for the
/// probe.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(crate) enum JournalOwner {
    /// This RUN retires it, in `get::tail::finish_job`, the moment the
    /// finish verifies. The CLI's answer.
    Run,
    /// The CALLER retires it, after it has committed a durable terminal
    /// record of its own. The daemon's answer: `serve::job::
    /// finalize_completed_gen` does it immediately after the `save_queue`
    /// that persists the `finalizing` marker - the first durable write
    /// past the resume-from-journal regime, and a window the marker
    /// itself makes exclusive (`retry` refuses a record carrying it, so
    /// no new generation can appear across it).
    ///
    /// A crash between that write and the unlink costs a lingering
    /// journal and nothing else, which `nzbkit::journal::Journal::remove`
    /// already calls always safe: "at worst a file the next run resumes
    /// correctly from".
    Caller,
}

/// One download run's inputs. See the module note for what belongs in
/// it; the orchestrator destructures it onto the same names the inline
/// parameters used, so nothing downstream of that line changed when it
/// landed.
pub(crate) struct JobSpec<'a> {
    pub(crate) config: &'a Path,
    pub(crate) nzb_path: &'a Path,
    pub(crate) out_dir: &'a Path,
    pub(crate) connections: usize,
    pub(crate) window: usize,
    pub(crate) decoders: usize,
    /// PAR2 fast verify (TODO §10): CRC32-only in-stream block claims.
    /// NZBFAST_FAST_VERIFY=0/1 overrides for bench A/Bs.
    pub(crate) fast_verify: bool,
    /// M32 "lean" verify (slow-CPU boost): with fast verify on, also skip
    /// the per-article yEnc CRC once PAR2 covers a file - in-stream
    /// integrity rests on the PAR2 block CRC32 alone (one CRC32 layer
    /// instead of two). Settle read-back + repair authority unchanged;
    /// PAR2-less downloads keep full article CRCs automatically.
    pub(crate) verify_lean: bool,
    pub(crate) no_extract: bool,
    /// Who unlinks the article journal on a clean finish - see
    /// [`JournalOwner`]. `Run` on the CLI, `Caller` on both daemon
    /// paths, whose tails commit the terminal record this run's finish
    /// is only half of.
    pub(crate) journal_owner: JournalOwner,
    /// Delete the spent recovery set once a repair has VERIFIED: the
    /// daemon's `par_cleanup`, threaded in because the only place that
    /// reads it today (the job tail's extension sweep) cannot see the
    /// files this one deletes. Bears solely on the obfuscated disk-side
    /// arm, which removes magic-sniffed volumes no extension rule can
    /// ever match; named `*.par2` stays the job tail's business.
    pub(crate) par_cleanup: bool,
    /// PLAN M32 leftover (sabnzbd#3475): leave a job's sample/proof
    /// clips unfetched instead of downloading them and deleting them
    /// afterwards. Off by default - see the setting's own note for why
    /// ours differs from SABnzbd's.
    pub(crate) skip_samples: bool,
    /// Explicit archive password (CLI/API). NZB `<meta type="password">`
    /// and the `Name{{password}}.nzb` filename convention are picked up
    /// automatically; this overrides both.
    pub(crate) password: Option<String>,
    /// TODO 101: this job's own yes to the volume-eating unpack, given in
    /// the disk-full drawer. Consulted only in `low_disk` mode - `always`
    /// is itself the consent and `off` cannot be talked into it - and
    /// never enough on its own: the set must still have verified.
    pub(crate) eat_consent: bool,
    /// §293: directories whose files the disk repair's adoption scan may
    /// read as block sources - a failed predecessor's output, resolved
    /// by the daemon when this job is a switch (`alt_from`). Read-only
    /// everywhere downstream; empty on the CLI, the sidecar and every
    /// ordinary job.
    pub(crate) donor_dirs: Vec<PathBuf>,
    /// PLAN M31: NZBs of DUPLICATE POSTINGS whose ARTICLES may fill a bad
    /// block - see `get::dupefill`. Empty on the CLI and wherever no
    /// alternative is held, which is the pass's whole no-op test.
    pub(crate) donor_nzbs: Vec<PathBuf>,
    pub(crate) progress: Option<Arc<AtomicU64>>,
    pub(crate) hub: Option<Arc<StreamHub>>,
    /// The nzo_id that owns this run's hub extractor (daemon jobs); empty
    /// for CLI downloads. Tags the installed extractor so /stream
    /// ownership is checked atomically with the clone (finding 11).
    pub(crate) stream_owner: &'a str,
    /// net_done fires when the network phase is done (all articles
    /// terminal, consumers drained) - the daemon starts the next job's
    /// download then, while this job's tail (settle/repair/extract) runs.
    /// Carries the instant, because the runner may only READ it later:
    /// since the cross-job hand-over it can be holding a predecessor's
    /// drain when this job's network ends, and a wall time taken at the
    /// read would bill that wait to this job's average speed.
    pub(crate) net_done: Option<tokio::sync::oneshot::Sender<std::time::Instant>>,
    pub(crate) budget: nzbkit::mem::MemBudget,
}

#[cfg(test)]
mod tests {
    /// EVERY `JobSpec` IN THE DAEMON NAMES `Caller`, and every one
    /// outside it names `Run`. X5-03's roster arm.
    ///
    /// The fix is one field at three call sites, and the compiler will
    /// make a fourth site CHOOSE - `JournalOwner` has no `Default` - but
    /// it cannot make it choose right, and choosing wrong is silent in
    /// every way that matters: the build passes, every test passes, the
    /// product works, and the only symptom is a crash window nobody can
    /// see from the outside. That is exactly what a mutation found: the
    /// sidecar's site reverted to `Run` left the crash probe GREEN,
    /// because reaching the prefetch path needs two servers, a warm-up
    /// and a speed limit and no test drives it.
    ///
    /// So the invariant is asserted where it can be: a run built under
    /// `src/serve/` is a DAEMON run, and a daemon run's outcome is
    /// recorded by the queue row in a post-processing tail that has not
    /// happened yet, so its journal is never its own to unlink. A run
    /// built anywhere else is the CLI, which has no other record and
    /// must retire its own.
    ///
    /// NO FROZEN COUNT, deliberately: a new call site is covered by the
    /// rule the day it is written, with no edit here - the shape
    /// `settings_catalogue`'s `settings_survive_a_restart` uses and for
    /// the same reason. What IS floored is how many sites the scan
    /// REACHED, because a matcher that has quietly stopped matching
    /// reads as a clean tree forever.
    #[test]
    fn every_daemon_job_spec_leaves_the_journal_to_its_caller() {
        // Built rather than written, so this file does not match its own
        // scan and need an exclusion that could hide a real site.
        let needle = format!("journal_{}: ", "owner");
        let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("src");
        let mut stack = vec![root.clone()];
        let mut seen = 0usize;
        while let Some(d) = stack.pop() {
            for e in std::fs::read_dir(&d)
                .expect("the crate source is readable")
                .flatten()
            {
                let p = e.path();
                if p.is_dir() {
                    stack.push(p);
                    continue;
                }
                if p.extension().is_none_or(|x| x != "rs") {
                    continue;
                }
                let src = std::fs::read_to_string(&p).unwrap_or_default();
                for line in src.lines() {
                    let t = line.trim_start();
                    // A field INIT, never the declaration (no `::`) and
                    // never prose about one (comments carry the name).
                    if t.starts_with("//") || !t.starts_with(&needle) {
                        continue;
                    }
                    // `rsplit` alone is not enough: it hands back the
                    // WHOLE line when the marker is absent, which is
                    // what a bare `journal_owner: JournalOwner,`
                    // PARAMETER declaration looks like - and reading one
                    // of those as a site is a failure with no defect
                    // behind it. Require the `::`.
                    let Some((_, variant)) = t.split_once("JournalOwner::") else {
                        continue;
                    };
                    let variant = variant.trim_end_matches([',', ' ']);
                    seen += 1;
                    let rel = p.strip_prefix(&root).unwrap_or(&p);
                    let daemon = rel.starts_with("serve");
                    let want = if daemon { "Caller" } else { "Run" };
                    assert_eq!(
                        variant,
                        want,
                        "{}: a run built {} the daemon must name JournalOwner::{want} - {}",
                        rel.display(),
                        if daemon { "inside" } else { "outside" },
                        if daemon {
                            "the queue row is the durable terminal record and its \
                             post-processing tail has not written it yet, so this \
                             run's journal is not its own to unlink (X5-03)"
                        } else {
                            "there is no other durable record of what arrived, so \
                             nothing else can ever retire it"
                        }
                    );
                }
            }
        }
        assert!(
            seen >= 3,
            "the scan reached only {seen} JobSpec journal_owner site(s) - it has \
             stopped matching, and an inert scan reads as a clean tree forever"
        );
    }
}
