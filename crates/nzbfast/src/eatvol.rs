//! TODO 101: the on-disk unpack that eats its own volumes.
//!
//! The shapes one-pass cannot serve materialize every volume on disk and
//! unpack afterwards, so the disk holds the volumes AND the extracted
//! payload at once (the arithmetic lives in
//! `serve::job::unpack_space_needed`). An ENCRYPTED set used to pay a
//! THIRD copy on top, because the finish decrypt wrote its plaintext
//! into a temp beside the ciphertext before renaming - the ~3x that
//! failed a 13.85 GB job on a 15.6 GB-free drive. TODO 27 phase 3
//! deleted that pass, so encryption costs no extra copy now; the 2x
//! below is what remains, and it is enough to fail the same job.
//!
//! With eating armed, each volume is HARD-deleted - `remove_file`,
//! deliberately not the Trash, since the entire point is freeing real
//! space this instant - the moment the extractor has read past its last
//! byte. Peak usage then approaches `max(volume, largest inner file)`
//! headroom instead of two or three whole copies.
//!
//! This is the DISK sibling of the RAM-side chase drop-behind (§87) and
//! must not be conflated with it: that one drops bytes out of a frontier
//! buffer while a set is still arriving, this one deletes files that have
//! fully landed.
//!
//! # What makes it safe
//!
//! 1. **Verified first.** The set must have verified before extraction
//!    starts - PAR2 green across it, or its per-volume CRCs proven. An
//!    unverified set is NEVER eaten, in any mode: eating forfeits the
//!    retry-without-refetch property, and forfeiting it over bytes we are
//!    not sure of is the one trade with no upside.
//! 2. **Spent, precisely.** A volume goes only once the reader has
//!    advanced past its last byte and no back-reference can reach into
//!    it. rars is ours, so that is knowable rather than guessable:
//!    `rars::extract_volumes_to_with_progress` reports each volume as the
//!    walk leaves it - including, since the H1 residual closed, each
//!    volume of a SPLIT member as its chain reads the fragment out, so
//!    the one-film-across-every-volume shape frees space progressively
//!    too. The engine keeps the report off any path that could read a
//!    fragment twice (the buffered filter-bail retry), so the promise
//!    behind the delete is unconditional.
//! 3. **Consent.** `low_disk` arms only on a job whose forecast says it
//!    cannot otherwise fit AND whose user said yes in the disk-full
//!    drawer. `always` is itself the consent.
//!
//! # What it costs
//!
//! Losing volumes mid-extract means a retry re-downloads. That is already
//! what happens when the disk fills instead (§100), so the mode never
//! makes the failure case worse than the status quo - it only makes the
//! success case cheaper.

use std::cell::Cell;
use std::path::Path;

/// The `unpack_eat_volumes` setting.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub(crate) enum EatMode {
    /// Today's behaviour: volumes are swept only AFTER a successful
    /// extraction, never during one.
    #[default]
    Off,
    /// Arm only when the forecast says the job cannot otherwise fit, and
    /// only with this job's own consent.
    LowDisk,
    /// Every on-disk unpack, for a machine that would rather never hold
    /// both copies. Still subject to the verified gate.
    Always,
}

impl EatMode {
    pub(crate) fn parse(s: &str) -> Option<EatMode> {
        match s.trim().to_ascii_lowercase().as_str() {
            "off" => Some(EatMode::Off),
            "low_disk" => Some(EatMode::LowDisk),
            "always" => Some(EatMode::Always),
            _ => None,
        }
    }

    pub(crate) fn as_str(self) -> &'static str {
        match self {
            EatMode::Off => "off",
            EatMode::LowDisk => "low_disk",
            EatMode::Always => "always",
        }
    }
}

/// Process-global mode, mirrored from the daemon setting exactly the way
/// `prefer_external_unrar` is - the unpack ladder runs several layers
/// below anything holding a `Daemon`.
static MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);

pub(crate) fn set_mode(mode: EatMode) {
    MODE.store(
        match mode {
            EatMode::Off => 0,
            EatMode::LowDisk => 1,
            EatMode::Always => 2,
        },
        std::sync::atomic::Ordering::Relaxed,
    );
}

pub(crate) fn mode() -> EatMode {
    match MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => EatMode::LowDisk,
        2 => EatMode::Always,
        _ => EatMode::Off,
    }
}

/// What the forecast knows at the moment the disk unpack is about to
/// start. Every field is measured, not projected: the volumes are already
/// on the disk by now, so this is the real arithmetic rather than the
/// queue-row estimate.
#[derive(Clone, Copy, Debug)]
pub(crate) struct Forecast {
    /// Bytes free on the output filesystem right now.
    pub(crate) free: u64,
    /// Bytes the volume files occupy - what eating them would give back.
    pub(crate) volumes: u64,
    /// Does this set need the encrypted third copy (the decrypt temp)?
    pub(crate) encrypted: bool,
}

impl Forecast {
    /// Room the unpack needs on top of the volumes already written: the
    /// extracted payload (approximated by the volume bytes - posted
    /// archives are near-incompressible media), plus the decrypt temp for
    /// an encrypted set. The same shape as
    /// `serve::job::unpack_space_needed` with nothing left to fetch.
    pub(crate) fn needed(&self) -> u64 {
        if self.encrypted {
            self.volumes.saturating_mul(2)
        } else {
            self.volumes
        }
    }

    /// Would the unpack fit without eating anything?
    pub(crate) fn fits(&self) -> bool {
        self.free >= self.needed().saturating_add(MARGIN)
    }
}

/// Headroom the forecast insists on beyond the arithmetic. A disk that
/// fits the payload to the last byte is not a disk the unpack should be
/// told to go ahead on: the staging directory, the filesystem's own
/// metadata and whatever else on the machine is writing all land in the
/// same place.
pub(crate) const MARGIN: u64 = 512 * 1024 * 1024;

/// Why the decision went the way it did - carried so the log line can say
/// it, and so the tests assert on a reason rather than a bare bool.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub(crate) enum EatVerdict {
    /// The setting is off.
    ModeOff,
    /// The set did not verify. Never eaten, whatever the mode says.
    Unverified,
    /// `low_disk`, and this job has not been consented to.
    NoConsent,
    /// `low_disk`, consented, but the job fits as it is - so keep the
    /// retry-without-refetch property.
    Fits,
    /// Eat the volumes as they are consumed.
    Eat,
}

impl EatVerdict {
    pub(crate) fn eats(self) -> bool {
        self == EatVerdict::Eat
    }
}

/// The whole decision, as a pure function of the four inputs. No I/O, so
/// the gates can be pinned by unit tests rather than by a live disk.
///
/// `verified` is the caller's proof that every volume is good (the
/// download's `all_good`, or a repair pass that vouched for the bytes).
/// `consented` is this job's own yes from the disk-full drawer, which
/// only `low_disk` consults - `always` IS the consent, and `off` cannot
/// be talked into it by either.
pub(crate) fn decide(
    mode: EatMode,
    verified: bool,
    consented: bool,
    forecast: Forecast,
) -> EatVerdict {
    if mode == EatMode::Off {
        return EatVerdict::ModeOff;
    }
    // Ahead of every other gate on purpose: an unverified set is refused
    // in `always` too, and reading the refusal in that order is what
    // stops someone later "simplifying" it into a mode check.
    if !verified {
        return EatVerdict::Unverified;
    }
    if mode == EatMode::Always {
        return EatVerdict::Eat;
    }
    if !consented {
        return EatVerdict::NoConsent;
    }
    if forecast.fits() {
        return EatVerdict::Fits;
    }
    EatVerdict::Eat
}

/// Measure the forecast for a directory whose volumes are on disk.
/// `volume_bytes` is what the caller already knows about the set (the
/// files it is about to hand the extractor); `encrypted` comes from the
/// archive shape.
pub(crate) fn forecast(dir: &Path, volume_bytes: u64, encrypted: bool) -> Forecast {
    Forecast {
        // No answer from the platform means no forecast, and a `low_disk`
        // job then reads as "fits" and is left alone. Refusing to eat is
        // the safe direction for an unknown.
        //
        // §129 lane: two tails can unpack at once now, and each one's
        // free-bytes read would count the same space. Subtract what the
        // OTHER finishing jobs have registered they still need on this
        // filesystem (`lanegate`); a job's own registration is excluded,
        // so the single-tail arithmetic is unchanged.
        free: crate::serve::free_bytes(dir)
            .map(|f| f.saturating_sub(crate::lanegate::other_need(dir)))
            .unwrap_or(u64::MAX),
        volumes: volume_bytes,
        encrypted,
    }
}

thread_local! {
    /// Armed for the duration of ONE job's disk unpack ladder, on that
    /// job's own thread.
    ///
    /// Thread-local rather than global because two jobs' tails can
    /// overlap, and a global would have one job's consent eat the other
    /// job's volumes. Read only from the driving thread - the extractor's
    /// worker threads never consult it.
    static ARMED: Cell<bool> = const { Cell::new(false) };
}

/// Is the unpack running on this thread allowed to eat its volumes?
pub(crate) fn armed() -> bool {
    ARMED.with(|a| a.get())
}

/// RAII arming for one job's unpack ladder. Restores the previous value
/// on drop, so a nested pass inside an armed ladder cannot leave the flag
/// standing for whatever this thread does next.
pub(crate) struct EatArm(bool);

impl EatArm {
    pub(crate) fn new(on: bool) -> EatArm {
        EatArm(ARMED.with(|a| a.replace(on)))
    }
}

impl Drop for EatArm {
    fn drop(&mut self) {
        ARMED.with(|a| a.set(self.0));
    }
}

/// Total size of a volume set on disk. Unreadable entries count zero -
/// the forecast is then pessimistic about how much eating would give
/// back, which errs towards not eating.
pub(crate) fn volume_bytes(paths: &[std::path::PathBuf]) -> u64 {
    paths
        .iter()
        .filter_map(|p| std::fs::metadata(p).ok().map(|m| m.len()))
        .fold(0u64, u64::saturating_add)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn fc(free: u64, volumes: u64, encrypted: bool) -> Forecast {
        Forecast {
            free,
            volumes,
            encrypted,
        }
    }

    const GB: u64 = 1_000_000_000;

    #[test]
    fn off_never_eats_however_tight_the_disk() {
        assert_eq!(
            decide(EatMode::Off, true, true, fc(0, 50 * GB, true)),
            EatVerdict::ModeOff
        );
    }

    #[test]
    fn an_unverified_set_is_never_eaten_in_any_mode() {
        for mode in [EatMode::LowDisk, EatMode::Always] {
            assert_eq!(
                decide(mode, false, true, fc(0, 50 * GB, false)),
                EatVerdict::Unverified,
                "{mode:?} ate an unverified set"
            );
        }
    }

    #[test]
    fn always_eats_a_verified_set_even_on_a_roomy_disk() {
        assert_eq!(
            decide(EatMode::Always, true, false, fc(10_000 * GB, GB, false)),
            EatVerdict::Eat
        );
    }

    #[test]
    fn low_disk_needs_this_jobs_consent() {
        assert_eq!(
            decide(EatMode::LowDisk, true, false, fc(0, 50 * GB, false)),
            EatVerdict::NoConsent
        );
    }

    #[test]
    fn low_disk_leaves_a_job_that_fits_alone() {
        // 10 GB of volumes, plain set: needs 10 GB + margin, has 40.
        assert_eq!(
            decide(EatMode::LowDisk, true, true, fc(40 * GB, 10 * GB, false)),
            EatVerdict::Fits
        );
    }

    #[test]
    fn low_disk_eats_the_job_that_cannot_fit() {
        // The 3 Aug report: 13.85 GB encrypted set, 1.75 GB free once the
        // volumes are down. Needs 27.7 GB, has 1.75.
        let f = fc(1_750_000_000, 13_850_000_000, true);
        assert_eq!(f.needed(), 27_700_000_000);
        assert_eq!(decide(EatMode::LowDisk, true, true, f), EatVerdict::Eat);
    }

    #[test]
    fn the_encrypted_third_copy_is_what_tips_a_borderline_job() {
        // 10 GB of volumes, 12 GB free. A plain set fits (10 + margin
        // 0.5 < 12); the same bytes encrypted need 20 and do not.
        assert!(fc(12 * GB, 10 * GB, false).fits());
        assert!(!fc(12 * GB, 10 * GB, true).fits());
    }

    #[test]
    fn the_margin_refuses_a_disk_that_fits_to_the_last_byte() {
        assert!(!fc(10 * GB, 10 * GB, false).fits());
        assert!(fc(10 * GB + MARGIN, 10 * GB, false).fits());
    }

    #[test]
    fn an_unmeasurable_disk_reads_as_fitting() {
        // free_bytes() answering None must not become "the disk is full".
        let f = Forecast {
            free: u64::MAX,
            volumes: 50 * GB,
            encrypted: true,
        };
        assert!(f.fits());
        assert_eq!(decide(EatMode::LowDisk, true, true, f), EatVerdict::Fits);
    }

    #[test]
    fn arming_is_scoped_and_restores_what_it_replaced() {
        assert!(!armed());
        {
            let _outer = EatArm::new(true);
            assert!(armed());
            {
                let _inner = EatArm::new(false);
                assert!(!armed());
            }
            assert!(armed());
        }
        assert!(!armed());
    }

    #[test]
    fn mode_round_trips_through_its_wire_name() {
        for mode in [EatMode::Off, EatMode::LowDisk, EatMode::Always] {
            assert_eq!(EatMode::parse(mode.as_str()), Some(mode));
        }
        assert_eq!(EatMode::parse("LOW_DISK"), Some(EatMode::LowDisk));
        assert_eq!(EatMode::parse("yes"), None);
        assert_eq!(EatMode::parse(""), None);
    }
}
