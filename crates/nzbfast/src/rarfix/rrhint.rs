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

use super::{RrRepair, collect_rar_volumes, rr_repair_volume, try_unrar_spent_why};
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
pub(crate) struct DamageHint {
    files: HashMap<String, VolumeVerdict>,
}

/// What the hint says about one volume on disk.
#[derive(Debug, Clone, PartialEq, Eq)]
pub(crate) enum Verdict {
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
    pub(crate) fn from_reports(
        reports: &[(usize, nzbkit::live::SlotReport)],
        block_size: u64,
    ) -> Self {
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
}

/// Run the RR pass over `volumes`, grouped by release stem with the
/// password resolved per group (the per-group resolve is what the nested
/// password-chain shape needs - see the 14 Aug note on
/// [`try_rar_rr_repair`](super::try_rar_rr_repair)). With a hint,
/// volumes it proves intact are skipped and counted in `skipped`.
pub(crate) fn rr_repair_volumes(
    dir: &Path,
    volumes: &[PathBuf],
    password: Option<&str>,
    hint: Option<&DamageHint>,
) -> RrPassStats {
    let mut by_stem: std::collections::BTreeMap<String, Vec<&PathBuf>> = Default::default();
    {
        use nzbkit::extract::release_stem;
        for p in volumes {
            let stem = release_stem(
                &p.file_name()
                    .unwrap_or_default()
                    .to_string_lossy()
                    .to_lowercase(),
            )
            .to_string();
            by_stem.entry(stem).or_default().push(p);
        }
    }
    let mut stats = RrPassStats::default();
    for group in by_stem.values() {
        let owned: Vec<PathBuf> = group.iter().map(|p| (*p).clone()).collect();
        let group_pw = crate::unpack::resolve_rar_group_password(dir, &owned, password);
        let pw = group_pw.as_deref().or(password);
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
            match rr_repair_volume(path, pw) {
                Ok(RrRepair::Rebuilt) => {
                    info!(target: "repair", "✔ {name} - rewritten from recovery record");
                    stats.rewritten += 1;
                }
                Ok(RrRepair::PrefixIntact) => {
                    // Not counted as rewritten: the record proved the
                    // prefix intact, the original was kept untouched.
                    info!(target: "repair", "{name} - recovery record shows the protected prefix intact");
                    stats.intact += 1;
                }
                Ok(RrRepair::NoRecord) => {
                    info!(target: "repair", "{name} - no recovery record");
                    stats.no_record += 1;
                }
                Err(e) => {
                    warn!(target: "repair", "✘ {name} - {e}");
                    stats.hard_failures += 1;
                }
            }
        }
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
    try_rar_rr_repair_hinted_why(dir, password, hint).is_ok()
}

/// [`try_rar_rr_repair_hinted`] that also carries OUT the ladder's own
/// reason for refusing, on the one class of refusal that has one - a
/// bomb verdict, which is about the DISK and not the archive.
///
/// Same contract as [`try_unrar_spent_why`], which this rung's two
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
pub(crate) fn try_rar_rr_repair_hinted_why(
    dir: &Path,
    password: Option<&str>,
    hint: Option<&DamageHint>,
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
    let stats = rr_repair_volumes(dir, &volumes, password, hint);
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
    let second = rr_repair_volumes(dir, &stats.skipped, password, None);
    if (second.rewritten == 0 && second.intact == 0) || second.hard_failures > 0 {
        warn!(target: "repair", "recovery-record repair could not save the set");
        return Err(None);
    }
    try_unrar_spent_why(dir, password).map(|_| ())
}
