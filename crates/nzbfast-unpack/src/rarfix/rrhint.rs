//! Damaged-volume hint for the recovery-record rung (TODO §11 (b)).
//!
//! [`try_rar_rr_repair`](super::try_rar_rr_repair) used to run the RR
//! stream-copy over EVERY volume blind: each one read end to end, shard
//! CRCs checked, a repaired copy built in a temp and renamed over the
//! original - for intact volumes too, which on a 60 x 1 GB set is 59 GB
//! of reading to fix one volume. By the time the rung runs, the PAR2
//! verifier has already proved most of those volumes block by block
//! ([`nzbkit::live::SlotReport`]: every block of a claimed slot ends
//! `Ok` or `Bad`, pending ones read back at settle). A [`DamageHint`]
//! carries that verdict, keyed by on-disk file name, and the hinted pass
//! skips what PAR2 proved intact.
//!
//! The hint is an OPTIMISATION, never a proof:
//!
//! - a volume the hint does not name (no PAR2 set, an obfuscated set that
//!   never activated, a file whose published name differs from its PAR2
//!   name) is [`Verdict::Unknown`] and gets the full pass exactly as
//!   before;
//! - a named volume whose on-disk length differs from the PAR2 length is
//!   `Unknown` too - the proof was taken over different bytes;
//! - the post-repair extraction is the real verification, and if it
//!   fails after a pass that skipped anything, the skipped volumes get
//!   the full pass once and extraction is retried. So a wrong hint costs
//!   time, never a repair.
//!
//! Bad BYTE ranges ride along (block index x block size, clipped to the
//! file) and are logged, but the skip is per volume: the RS rebuild has
//! to read every intact shard of a damaged volume anyway, so a range
//! cannot shrink that read - it can only say which volumes to open.

use super::{RrRepair, collect_rar_volumes, rr_repair_volume_in, try_unrar_spent_why};
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use tracing::{info, warn};

/// PAR2's verdict on one file: its length per the set, and the byte
/// ranges (half-open) whose blocks failed. Empty = proven intact.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) struct VolumeVerdict {
    pub length: u64,
    pub bad_ranges: Vec<(u64, u64)>,
}

/// PAR2's per-file verdicts, keyed by file name as the set names it -
/// which is the on-disk name once settle has published the PAR2 names.
#[derive(Debug, Clone, Default)]
pub struct DamageHint {
    files: HashMap<String, VolumeVerdict>,
}

/// What the hint says about one volume on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Verdict {
    /// Every PAR2 block verified and the on-disk length matches.
    Intact,
    /// PAR2 found these byte ranges bad.
    Damaged(Vec<(u64, u64)>),
    /// PAR2 never spoke for this file (or spoke about a different length).
    Unknown,
}

impl DamageHint {
    /// Build from the verifier's settled reports. `block_size` is the
    /// set's; a no-IFSC file (`total_blocks == 0`) that failed its
    /// whole-file MD5 is damaged over its whole length.
    pub fn from_reports(reports: &[(usize, nzbkit::live::SlotReport)], block_size: u64) -> Self {
        let mut hint = DamageHint::default();
        for (_, r) in reports {
            let Some(name) = &r.par2_name else { continue };
            let bad_ranges = if r.total_blocks == 0 {
                if r.bad_blocks.is_empty() {
                    Vec::new()
                } else {
                    vec![(0, r.length)]
                }
            } else {
                r.bad_blocks
                    .iter()
                    .map(|&bi| {
                        let start = (bi as u64).saturating_mul(block_size).min(r.length);
                        let end = start.saturating_add(block_size).min(r.length);
                        (start, end)
                    })
                    .collect()
            };
            hint.insert(name, r.length, bad_ranges);
        }
        hint
    }

    pub(crate) fn insert(&mut self, name: &str, length: u64, bad_ranges: Vec<(u64, u64)>) {
        self.files
            .insert(name.to_string(), VolumeVerdict { length, bad_ranges });
    }

    pub(crate) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    /// The verdict for a volume on disk. Name match is exact; a length
    /// mismatch downgrades a named file to `Unknown`.
    pub(crate) fn verdict(&self, path: &Path) -> Verdict {
        let Some(name) = path.file_name().and_then(|n| n.to_str()) else {
            return Verdict::Unknown;
        };
        let Some(v) = self.files.get(name) else {
            return Verdict::Unknown;
        };
        let Ok(meta) = std::fs::metadata(path) else {
            return Verdict::Unknown;
        };
        if meta.len() != v.length {
            return Verdict::Unknown;
        }
        if v.bad_ranges.is_empty() {
            Verdict::Intact
        } else {
            Verdict::Damaged(v.bad_ranges.clone())
        }
    }
}

/// What one RR pass over a volume list did.
#[derive(Debug, Default, Clone, PartialEq, Eq)]
pub(crate) struct RrPassStats {
    /// Volumes the RR pass opened and rewrote from their record.
    pub rewritten: usize,
    /// Volumes opened whose record proved the protected prefix already
    /// intact - the original file was kept, nothing was rewritten.
    pub intact: usize,
    /// Volumes opened that carried no record (clean skip).
    pub no_record: usize,
    /// Volumes with a record whose repair failed.
    pub hard_failures: usize,
    /// Volumes the hint proved intact - never opened.
    pub skipped: Vec<PathBuf>,
    /// On-disk bytes of every volume handed to the RR pass.
    pub bytes_scanned: u64,
    /// On-disk bytes of every volume the hint let us skip.
    pub bytes_skipped: u64,
    /// Why the pass ended before its last volume, if it did.
    pub stopped: Option<RrStopped>,
}

/// Why an RR pass ended early - issue 115.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum RrStopped {
    /// A volume carried a record that could not repair it. The pass's
    /// verdict is already "could not save the set" whatever the volumes
    /// after it do, so reading them only spends the time.
    Unrepairable,
    /// The owner cancelled (the job was deleted).
    Cancelled,
    /// One volume ran past [`volume_deadline`] and the pass walked away
    /// from it.
    Wedged,
}

/// The owner's "stop now" for the RR pass: the job's
/// [`SideCancel`](crate::streamhub::SideCancel) in the daemon, never set on
/// the CLI and in tests.
pub(crate) type RrCancel<'a> = Option<&'a crate::streamhub::SideCancel>;

/// How long one volume's RR repair may run before the pass stops waiting
/// for it: five minutes plus a second per MiB, so a 117 MB volume gets
/// about seven minutes and a 4 GiB one a little over an hour.
///
/// The repair reads the volume about twice and writes it once, which on
/// the slowest storage this runs on (a NAS share, a USB disk) is well under
/// a second per MiB - the bound is there for a repair that has STOPPED,
/// not one that is slow. Issue 115 is the case it exists for: a volume's
/// repair that never returned held the job in Repairing for 14 hours, and
/// with it the heavy-CPU permit every other job's repair and unpack tail
/// waits on.
pub(crate) fn volume_deadline(len: u64) -> std::time::Duration {
    std::time::Duration::from_secs(300 + len / (1 << 20))
}

/// How often a wait on the volume worker looks up to check the cancel and
/// the deadline. Well inside a user's patience after a delete; one wakeup
/// a quarter-second for the length of a repair costs nothing.
const RR_POLL: std::time::Duration = std::time::Duration::from_millis(250);

/// The thread one group's volumes are repaired on, so the pass can WALK
/// AWAY from a volume that does not come back (issue 115).
///
/// The repair is synchronous library code with no cancel of its own, and a
/// thread blocked inside it cannot be interrupted - so the only way to stop
/// waiting is not to be the thread doing the work. The pass hands volumes
/// over one at a time and waits with a timeout; on a cancel or a deadline
/// it raises `walked_away` and leaves. The worker is then detached: if the
/// repair ever returns, `rr_repair_volume_in` sees the flag before it
/// publishes and deletes its temp instead, and the next send fails so the
/// thread exits. If it never returns it stays parked until the process
/// does, which is what the alternative already cost - a job, a permit and
/// a queue behind it - minus the job, the permit and the queue.
///
/// ONE thread per group rather than per volume because the group shares one
/// parse session (one RAR 5 key derivation per set, see
/// `rr_repair_volume_in`), and the session borrows the password, so both
/// have to live on the thread that uses them. The group's password is
/// RESOLVED there too, because resolving opens the volumes - and an open
/// that never returns is exactly what the pass must be able to leave. The
/// caller's log subscriber and span go with it, so the worker's lines land
/// where the pass's do.
pub(crate) struct VolumeWorker {
    jobs: std::sync::mpsc::Sender<PathBuf>,
    done: std::sync::mpsc::Receiver<std::result::Result<RrRepair, String>>,
    walked_away: std::sync::Arc<std::sync::atomic::AtomicBool>,
}

pub(crate) enum VolumeWait {
    Done(std::result::Result<RrRepair, String>),
    Cancelled,
    Wedged,
}

impl VolumeWorker {
    pub(crate) fn start(
        dir: PathBuf,
        group: Vec<PathBuf>,
        password: Option<String>,
    ) -> std::io::Result<Self> {
        let (jobs, job_rx) = std::sync::mpsc::channel::<PathBuf>();
        let (done_tx, done) = std::sync::mpsc::channel();
        let walked_away = std::sync::Arc::new(std::sync::atomic::AtomicBool::new(false));
        let gone = walked_away.clone();
        let dispatch = tracing::dispatcher::get_default(|d| d.clone());
        let span = tracing::Span::current();
        std::thread::Builder::new()
            .name("rr-repair".into())
            .spawn(move || {
                tracing::dispatcher::with_default(&dispatch, || {
                    let _entered = span.enter();
                    let group_pw = crate::rarfix::passwords::resolve_rar_group_password(
                        &dir,
                        &group,
                        password.as_deref(),
                    );
                    let pw = group_pw.as_deref().or(password.as_deref());
                    let mut session = rars::ReadSession::new(
                        rars::ArchiveReadOptions::with_optional_password(pw.map(str::as_bytes)),
                    );
                    for path in job_rx {
                        let out = rr_repair_volume_in(&mut session, &path, pw, Some(&gone))
                            .map_err(|e| e.to_string());
                        if done_tx.send(out).is_err() {
                            return;
                        }
                    }
                })
            })?;
        Ok(VolumeWorker {
            jobs,
            done,
            walked_away,
        })
    }

    /// Repair `path` on the worker and wait for it - or for `cancel`, or
    /// for `deadline`, whichever comes first.
    pub(crate) fn repair(
        &self,
        path: &Path,
        cancel: RrCancel<'_>,
        deadline: std::time::Duration,
    ) -> VolumeWait {
        use std::sync::mpsc::RecvTimeoutError;
        if self.jobs.send(path.to_path_buf()).is_err() {
            return VolumeWait::Done(Err("the repair worker is gone".into()));
        }
        let started = std::time::Instant::now();
        loop {
            match self.done.recv_timeout(RR_POLL) {
                Ok(out) => return VolumeWait::Done(out),
                // The worker died (a panic inside the repair): report it as
                // this volume's failure, not as a hang.
                Err(RecvTimeoutError::Disconnected) => {
                    return VolumeWait::Done(Err("the repair worker stopped".into()));
                }
                Err(RecvTimeoutError::Timeout) => {}
            }
            let stop = if cancel.is_some_and(|c| c.is_cancelled()) {
                VolumeWait::Cancelled
            } else if started.elapsed() >= deadline {
                VolumeWait::Wedged
            } else {
                continue;
            };
            self.walked_away
                .store(true, std::sync::atomic::Ordering::Release);
            return stop;
        }
    }
}

/// `volumes` grouped into sets, one entry per set, for the RR pass.
///
/// Keyed by release stem, EXCEPT a bare-numeric RAR volume
/// (`movie.001`, `movie.002`, ...), which `release_stem` leaves whole -
/// it only strips a digit tail after `.7z`/`.zip` - so each volume of
/// such a set used to land in a group of its own (Gemini 14 Oct sweep
/// M10). The group is the unit the password resolves over, so a damaged
/// volume whose own crypt record no longer parses lost the password its
/// intact siblings would have resolved, and every volume paid its own
/// candidate harvest and key derivation. Those fold by
/// [`super::numeric_vol_base`] behind the `Rar!` magic, in a namespace
/// no release stem can collide with - the same key `packed_groups` and
/// `stem_volume_set` use.
pub(crate) fn rr_groups(volumes: &[PathBuf]) -> std::collections::BTreeMap<String, Vec<&PathBuf>> {
    use nzbkit::extract::release_stem;
    let mut by_stem: std::collections::BTreeMap<String, Vec<&PathBuf>> = Default::default();
    for p in volumes {
        let name = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let key = match super::numeric_vol_base(&name) {
            Some(base) if super::rar_magic(p) => format!("\u{0}num:{base}"),
            _ => release_stem(&name).to_string(),
        };
        by_stem.entry(key).or_default().push(p);
    }
    by_stem
}

/// Run the RR pass over `volumes`, grouped by release stem with the
/// password resolved per group (the per-group resolve is what the nested
/// password-chain shape needs - see the 14 Aug note on
/// [`try_rar_rr_repair`](super::try_rar_rr_repair)). With a hint,
/// volumes it proves intact are skipped and counted in `skipped`.
///
/// The pass ENDS EARLY, with the reason in `stopped`, on three things
/// (issue 115): the first volume whose record could not repair it - both
/// callers read any hard failure as "could not save the set", so every
/// volume after it was read for nothing, on a set that by this rung is
/// usually far past saving - a `cancel`, and a volume that outlives
/// [`volume_deadline`]. Each volume is repaired on a [`VolumeWorker`], so
/// the last two hold even when the repair itself never returns.
pub(crate) fn rr_repair_volumes(
    dir: &Path,
    volumes: &[PathBuf],
    password: Option<&str>,
    hint: Option<&DamageHint>,
    cancel: RrCancel<'_>,
) -> RrPassStats {
    let by_stem = rr_groups(volumes);
    let mut stats = RrPassStats::default();
    'groups: for group in by_stem.values() {
        if cancel.is_some_and(|c| c.is_cancelled()) {
            stats.stopped = Some(RrStopped::Cancelled);
            break;
        }
        let owned: Vec<PathBuf> = group.iter().map(|p| (*p).clone()).collect();
        // One worker, and so one password resolve and one parse session,
        // per GROUP: the group is one set under one password, so its RAR 5
        // key derives once there rather than once per volume (see
        // `rr_repair_volume_in`).
        let worker = match VolumeWorker::start(
            dir.to_path_buf(),
            owned,
            password.map(str::to_owned),
        ) {
            Ok(worker) => worker,
            Err(e) => {
                warn!(target: "repair", "✘ recovery-record repair could not start a worker: {e}");
                stats.hard_failures += 1;
                stats.stopped = Some(RrStopped::Unrepairable);
                break;
            }
        };
        for path in group {
            let name = path
                .file_name()
                .unwrap_or_default()
                .to_string_lossy()
                .to_string();
            let len = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
            match hint.map(|h| h.verdict(path)) {
                Some(Verdict::Intact) => {
                    info!(target: "repair", "{name} - PAR2 proved it intact, skipped");
                    stats.skipped.push((*path).clone());
                    stats.bytes_skipped += len;
                    continue;
                }
                Some(Verdict::Damaged(ranges)) => {
                    info!(
                        target: "repair",
                        "{name} - PAR2 found {} bad byte range(s) ({} bytes)",
                        ranges.len(),
                        ranges.iter().map(|(a, b)| b - a).sum::<u64>()
                    );
                }
                Some(Verdict::Unknown) | None => {}
            }
            stats.bytes_scanned += len;
            let deadline = volume_deadline(len);
            match worker.repair(path, cancel, deadline) {
                VolumeWait::Done(Ok(RrRepair::Rebuilt)) => {
                    info!(target: "repair", "✔ {name} - rewritten from recovery record");
                    stats.rewritten += 1;
                }
                VolumeWait::Done(Ok(RrRepair::PrefixIntact)) => {
                    // Not counted as rewritten: the record proved the
                    // prefix intact, the original was kept untouched.
                    info!(target: "repair", "{name} - recovery record shows the protected prefix intact");
                    stats.intact += 1;
                }
                VolumeWait::Done(Ok(RrRepair::NoRecord)) => {
                    info!(target: "repair", "{name} - no recovery record");
                    stats.no_record += 1;
                }
                VolumeWait::Done(Err(e)) => {
                    warn!(target: "repair", "✘ {name} - {e}");
                    stats.hard_failures += 1;
                    stats.stopped = Some(RrStopped::Unrepairable);
                    break 'groups;
                }
                VolumeWait::Cancelled => {
                    info!(target: "repair", "{name} - recovery-record repair cancelled");
                    stats.stopped = Some(RrStopped::Cancelled);
                    break 'groups;
                }
                VolumeWait::Wedged => {
                    warn!(
                        target: "repair",
                        "✘ {name} - recovery-record repair made no answer in {} s; giving up on it",
                        deadline.as_secs()
                    );
                    stats.hard_failures += 1;
                    stats.stopped = Some(RrStopped::Wedged);
                    break 'groups;
                }
            }
        }
    }
    if stats.stopped == Some(RrStopped::Unrepairable) {
        info!(
            target: "repair",
            "stopped the recovery-record pass at the first volume it could not repair"
        );
    }
    stats
}

/// [`try_rar_rr_repair`](super::try_rar_rr_repair) with PAR2's verdict in
/// hand: volumes the hint proves intact are not opened. If extraction
/// still fails after a pass that skipped anything, the skipped volumes
/// get the full pass and extraction is retried once - the hint is an
/// optimisation, and the extraction is the only proof.
///
/// Returns true only when extraction afterwards succeeds. The bool form,
/// kept for the tests; everything that composes a job message takes
/// [`try_rar_rr_repair_hinted_why`] and keeps the reason, which since
/// TODO §249 item 1 is every production caller - hence `cfg(test)`, the
/// same shape [`crate::repair::reextract_dir`] settled into.
#[cfg(test)]
pub(crate) fn try_rar_rr_repair_hinted(
    dir: &Path,
    password: Option<&str>,
    hint: Option<&DamageHint>,
) -> bool {
    try_rar_rr_repair_hinted_why(dir, password, hint, None).is_ok()
}

/// `try_rar_rr_repair_hinted` that also carries OUT the ladder's own
/// reason for refusing, on the one class of refusal that has one - a
/// bomb verdict, which is about the DISK and not the archive.
///
/// Same contract as `try_unrar_spent_why`, which this rung's two
/// extraction attempts delegate to: `Err(None)` is the ordinary failure
/// the caller words itself (the records could not save the set, or the
/// repaired set still does not open), `Err(Some(why))` is a verdict that
/// must be quoted rather than paraphrased.
///
/// This was the third and last rung of the named-RAR arm still answering
/// a bare bool (TODO §249 item 1). It is a NARROW rung - reached only
/// when both attempts above it failed for a reason that was not the
/// disk, so a verdict here means the repaired set bombs where the
/// damaged one never got far enough to - but the blame it dropped was
/// the same wrong blame the 22 Aug 2026 incident was reported as: the
/// job named the archive for what was a full disk.
///
/// The rung has TWO extraction attempts and the reason that comes out is
/// the LAST one's, which is the control flow this rung always had - §249
/// item 1 changed what it carries, not when it stops. A first-pass
/// verdict is therefore dropped when a second pass follows, on purpose:
/// the hint can be wrong, and a volume it wrongly vouched for is exactly
/// what that pass repairs, so its answer is the later and
/// better-informed one.
///
/// `cancel` is the owning job's handle where there is one (the daemon's
/// settle repair); a cancelled pass refuses here, before any extraction.
pub fn try_rar_rr_repair_hinted_why(
    dir: &Path,
    password: Option<&str>,
    hint: Option<&DamageHint>,
    cancel: Option<&crate::streamhub::SideCancel>,
) -> std::result::Result<(), Option<String>> {
    let volumes = match collect_rar_volumes(dir) {
        Ok(volumes) if !volumes.is_empty() => volumes,
        _ => return Err(None),
    };
    let hint = hint.filter(|h| !h.is_empty());
    info!(
        target: "repair",
        "PAR2 exhausted - trying embedded RAR recovery records on {} volume(s){}…",
        volumes.len(),
        if hint.is_some() {
            " (PAR2 verdict in hand)"
        } else {
            ""
        }
    );
    let stats = rr_repair_volumes(dir, &volumes, password, hint, cancel);
    if stats.stopped == Some(RrStopped::Cancelled) {
        // Not "could not save the set": nobody asked it to any more.
        return Err(None);
    }
    if !stats.skipped.is_empty() {
        info!(
            target: "repair",
            "skipped {} volume(s) PAR2 proved intact ({:.1} MB not read), scanned {:.1} MB",
            stats.skipped.len(),
            stats.bytes_skipped as f64 / 1e6,
            stats.bytes_scanned as f64 / 1e6
        );
    }
    // With nothing skipped this is the old test exactly: some volume must
    // have carried a record and none may have failed. With skips and
    // nothing rewritten, the rung goes on to extract only when every
    // volume it OPENED was rewritten too - i.e. nothing was opened. A
    // damaged volume that turned out to carry no record is exactly the
    // old "could not save the set", and skipping its intact neighbours
    // must not turn that into an extraction attempt over the damage
    // (pinned by e2e `a_missing_external_par2_still_reaches_the_native_escalation`,
    // whose fixture volumes carry neither a record nor a CRC).
    // `intact` counts with `rewritten` here: a record that PROVED the
    // prefix intact is a record that answered, and the old accounting
    // (which called those rewritten) went on to extract.
    let nothing_done = stats.rewritten == 0
        && stats.intact == 0
        && (stats.skipped.is_empty() || stats.no_record > 0);
    if nothing_done || stats.hard_failures > 0 {
        warn!(target: "repair", "recovery-record repair could not save the set");
        return Err(None);
    }
    let first = try_unrar_spent_why(dir, password);
    if first.is_ok() {
        return Ok(());
    }
    // Nothing was skipped, so there is no second pass to run and no
    // better-informed answer coming: this attempt's reason IS the rung's
    // reason. It used to be dropped for a bare `Err(None)` here, which
    // made §249 item 1's plumbing unreachable on the blind form - and the
    // blind form is the ONLY one `unpack::unpack_named_rar` calls, so a
    // bomb verdict raised by the named-RAR arm's third rung never once
    // reached a job message. Measured 24 Aug 2026 by
    // `daemon_bomb::a_bomb_on_the_recovery_record_rung_reaches_the_job_message`,
    // which is red against this line restored: the job read "an archive
    // in the output directory could not be unpacked" while the console
    // three lines up named the disk. That is the same wrong blame §249
    // and the 22 Aug 2026 incident are about, one rung further down.
    //
    // The HINTED form keeps the old behaviour below, and deliberately.
    if stats.skipped.is_empty() {
        return first.map(|_| ());
    }
    // Deliberately NOT `return first.map(|_| ())` here, even on a named
    // reason. This rung has a SECOND attempt below and the control flow
    // is unchanged by §249 item 1 - only the reason it carries out is
    // new. Ending the rung on a first-pass verdict was written and
    // backed out: it is defensible (the pass below rewrites volumes and
    // hands them to an engine that just refused for want of space, which
    // is the rule `unpack::unpack_named_rar` states for the rungs below
    // IT), but it is a behaviour change that would fail a job the second
    // pass can still save. The narrow case is real: the hint can be
    // wrong, and a volume it wrongly vouched for is exactly what the
    // second pass repairs. So the second attempt's answer is the one
    // that goes out, as it always was, and the disk-fill question is
    // registered in §249 rather than settled in passing.
    // The hint was wrong somewhere (or the damage sits in a volume it
    // vouched for - a write that never landed reads differently from
    // the bytes the verifier saw). Full pass over what was skipped.
    warn!(
        target: "repair",
        "extraction failed after the hinted pass - running the recovery records over the {} \
         skipped volume(s) too",
        stats.skipped.len()
    );
    let second = rr_repair_volumes(dir, &stats.skipped, password, None, cancel);
    if (second.rewritten == 0 && second.intact == 0)
        || second.hard_failures > 0
        || second.stopped == Some(RrStopped::Cancelled)
    {
        warn!(target: "repair", "recovery-record repair could not save the set");
        return Err(None);
    }
    try_unrar_spent_why(dir, password).map(|_| ())
}
