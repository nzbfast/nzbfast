//! [`super::retry_space_needed`]: what a Retry of a history row needs
//! free, and the one row where the parts are NOT all on the disk.

use super::Job;
use super::history::retry_space_needed;
use super::job_from_json;
use serde_json::json;

const GB: u64 = 1_000_000_000;

fn failed_row(fail_message: &str, total: u64, downloaded: u64) -> Job {
    job_from_json(&json!({
        "nzo_id": "SABnzbd_nzo_space",
        "name": "Some.Release",
        "nzb_path": "/spool/some.nzb",
        "out_dir": "/out/Some.Release",
        "state": "Failed",
        "total_bytes": total,
        "downloaded_bytes": downloaded,
        "fail_message": fail_message,
        "archive_shape": "rar5 store on-disk",
    }))
    .expect("the fixture carries every required key")
}

/// The common case, and the one the figure was tuned for: the unpack ran
/// out of room with every volume already down, so the retry re-runs the
/// unpack alone and owes the payload only.
#[test]
fn an_unpack_phase_full_disk_owes_the_payload_only() {
    let j = failed_row("unpack failed: No space left on device", 10 * GB, 10 * GB);
    assert_eq!(retry_space_needed(&j), 10 * GB);
}

/// The row this exists for. `out of disk space` is the MID-DOWNLOAD halt
/// (`disk_full_mid_download`), so 3 of the 10 GB are down and 7 have yet
/// to be fetched before there is anything to unpack. Reporting the
/// payload alone named a figure a whole unfetched remainder too small,
/// and the drawer gates Retry on it - so the user frees exactly what we
/// asked for and fails a second time.
#[test]
fn a_mid_download_full_disk_owes_the_unfetched_remainder_too() {
    let j = failed_row("out of disk space while writing", 10 * GB, 3 * GB);
    assert_eq!(
        retry_space_needed(&j),
        7 * GB + 10 * GB,
        "the remainder to fetch, plus the payload it unpacks into"
    );
    assert!(
        retry_space_needed(&j) > 10 * GB,
        "and strictly more than the unpack-only figure this used to report"
    );
}

/// A mid-download halt that had fetched nothing yet owes the whole set
/// plus the payload - and never less than the set.
#[test]
fn a_mid_download_full_disk_with_nothing_down_owes_the_whole_set() {
    let j = failed_row("out of disk space while writing", 10 * GB, 0);
    assert_eq!(retry_space_needed(&j), 20 * GB);
}

/// `downloaded_bytes` is this RUN's fetch, so a resumed job can report
/// more than the set is long. That must not underflow into a nonsense
/// figure - it saturates to "nothing left to fetch".
#[test]
fn a_resumed_row_reporting_more_than_the_set_does_not_underflow() {
    let j = failed_row("out of disk space while writing", 10 * GB, 12 * GB);
    assert_eq!(retry_space_needed(&j), 10 * GB);
}

/// Any other failure keeps exactly the number it had: the parts are on
/// disk, and the mid-download arm must not widen to rows whose failure
/// message already promises "nothing is re-downloaded".
#[test]
fn an_unrelated_failure_is_unchanged_even_with_bytes_outstanding() {
    let j = failed_row("download incomplete: 3 articles missing", 10 * GB, GB);
    assert_eq!(retry_space_needed(&j), 10 * GB);
}

/// The nested arm of `unpack_space_needed` still applies on top - a
/// nested set peaks one payload higher, remainder or no remainder.
#[test]
fn the_nested_peak_still_rides_on_the_remainder() {
    let mut j = failed_row("out of disk space while writing", 10 * GB, 4 * GB);
    j.archive_shape = "rar5 store on-disk inner-rar".to_string();
    assert_eq!(retry_space_needed(&j), 6 * GB + 10 * GB + 10 * GB);
}
