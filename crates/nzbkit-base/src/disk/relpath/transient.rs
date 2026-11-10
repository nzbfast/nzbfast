//! Riding out a BRIEF Windows denial at the output leaf's open, so only
//! a lasting one reaches the write halt (TODO 358 item 6 follow-up).
//!
//! Since item 6 a destination refusal halts the whole fetch and fails
//! the job as Local, with no automatic retry - and on Windows
//! `ERROR_ACCESS_DENIED` (5) and `ERROR_SHARING_VIOLATION` (32) are not
//! only a folder that refuses. They are also what an antivirus scanner
//! holding a freshly created file for a moment returns, and what a name
//! whose previous file is DELETE-PENDING returns
//! (`STATUS_DELETE_PENDING` maps to 5 through `RtlNtStatusToDosError`).
//! Both clear by themselves within a few hundred milliseconds, and a job
//! failed over one is a job the user has to start again for nothing.
//!
//! So [`super::open_out_leaf_under`]'s Windows arm reopens on exactly
//! those two codes for about half a second before it lets the error out.
//! A refusal that is still there at the end is a real one and halts as
//! before; every other error (an alias in the way, a missing parent, a
//! taken `CreateNew` name) comes back on the first attempt, unchanged.
//!
//! Compiled into the product on the non-unix arm only, which in
//! practice is Windows. Unix has no such
//! transient: EACCES/EPERM/EISDIR there are the folder's answer, and
//! raw codes 5 and 32 mean EIO and EPIPE, which this must never retry -
//! so the unix build reaches this file only in its unit tests, which
//! pin the POLICY with an injected error source and an injected sleep.
//! Whether the codes really arrive as 5 and 32 on a live Windows box is
//! NOT proved by those tests.
//!
//! In a child file rather than inline in `relpath.rs` for the ordinary
//! size-gate reason, the same as `disambiguate.rs` beside it.

use std::io;
use std::time::Duration;

/// `ERROR_ACCESS_DENIED`: a refusing folder, a scanner's brief hold, or
/// a delete-pending file at the name.
const ERROR_ACCESS_DENIED: i32 = 5;
/// `ERROR_SHARING_VIOLATION`: another handle (a scanner, an indexer, a
/// preview handler) opened the file without sharing write.
const ERROR_SHARING_VIOLATION: i32 = 32;

/// The waits between attempts: seven attempts over 500 ms in all, short
/// first because the common scanner hold is the shortest.
pub(super) const BACKOFF_MS: [u64; 6] = [25, 50, 75, 100, 125, 125];

/// Is `e` one of the two Windows codes a transient hold returns?
pub(super) fn transient_denial(e: &io::Error) -> bool {
    matches!(
        e.raw_os_error(),
        Some(ERROR_ACCESS_DENIED) | Some(ERROR_SHARING_VIOLATION)
    )
}

/// Run `open`, and while it fails with a [`transient_denial`], wait out
/// the next step of [`BACKOFF_MS`] through `sleep` and run it again. The
/// last attempt's result comes back whatever it is, so a lasting denial
/// still reaches the caller - and the halt - with its own error.
pub(super) fn open_riding_out_denial<T>(
    mut open: impl FnMut() -> io::Result<T>,
    mut sleep: impl FnMut(Duration),
) -> io::Result<T> {
    for ms in BACKOFF_MS {
        match open() {
            Err(e) if transient_denial(&e) => sleep(Duration::from_millis(ms)),
            done => return done,
        }
    }
    open()
}

#[cfg(test)]
mod tests {
    use super::*;

    /// An open that fails with `codes` in turn and then succeeds, plus
    /// the sleeps it was asked for.
    fn run(codes: &[i32]) -> (io::Result<u32>, usize, Vec<Duration>) {
        let mut calls = 0usize;
        let mut slept = Vec::new();
        let r = open_riding_out_denial(
            || {
                calls += 1;
                match codes.get(calls - 1) {
                    Some(&c) => Err(io::Error::from_raw_os_error(c)),
                    None => Ok(7),
                }
            },
            |d| slept.push(d),
        );
        (r, calls, slept)
    }

    #[test]
    fn a_brief_denial_is_ridden_out() {
        let (r, calls, slept) = run(&[5, 32, 5]);
        assert_eq!(r.unwrap(), 7, "the fourth open succeeds and is returned");
        assert_eq!(calls, 4);
        assert_eq!(slept.len(), 3);
    }

    #[test]
    fn a_lasting_denial_comes_back_after_about_half_a_second() {
        let (r, calls, slept) = run(&[5; 64]);
        let e = r.unwrap_err();
        assert_eq!(e.raw_os_error(), Some(5), "the real error, unchanged");
        assert_eq!(calls, BACKOFF_MS.len() + 1);
        let total: Duration = slept.iter().sum();
        assert_eq!(total, Duration::from_millis(500));
    }

    #[test]
    fn every_other_error_comes_back_on_the_first_attempt() {
        // 2 not found, 3 path not found, 80 file exists, 183 already
        // exists: none is a hold that clears by itself.
        for c in [2, 3, 80, 183] {
            let (r, calls, slept) = run(&[c]);
            assert_eq!(r.unwrap_err().raw_os_error(), Some(c));
            assert_eq!(calls, 1, "code {c} must not be retried");
            assert!(slept.is_empty());
        }
        // A refusal this module raises itself carries no OS code.
        let mut calls = 0;
        let r: io::Result<()> = open_riding_out_denial(
            || {
                calls += 1;
                Err(io::Error::other(
                    "refusing to write output x: an alias is in the way",
                ))
            },
            |_| panic!("an alias refusal must not wait"),
        );
        assert!(r.is_err());
        assert_eq!(calls, 1);
    }

    #[test]
    fn success_on_the_first_attempt_never_sleeps() {
        let (r, calls, slept) = run(&[]);
        assert_eq!(r.unwrap(), 7);
        assert_eq!(calls, 1);
        assert!(slept.is_empty());
    }
}
