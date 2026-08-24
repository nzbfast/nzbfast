//! B5: the queue payload's start/limit window, pushed into the
//! walk that builds the rows.
//!
//! `queue_json` used to build a slot body for every job in the queue and
//! then hand the vector to `paginate`, which threw all but the page
//! away - under the queue lock, once a second, for a dashboard that
//! sent no limit at all. The rows outside the window are no longer
//! built. Everything here pins the properties that must survive that:
//! the header still describes the WHOLE queue, the pages still partition
//! it exactly, `nzo_ids` still ignores the window, and every row that
//! does come back is byte-identical to the row the unpaged body had.
//!
//! A child of daemon_tests, out here for the size gate (TODO 106); the
//! module is named for its file so size-gate.py's CFG_TEST_MOD resolver
//! still reads it as test code, and `use super::*` brings `with_daemon`
//! and `jv`.

use super::*;

/// `queue_json` with the given query, as the caller would send it.
fn qj(d: &Arc<Daemon>, kv: &[(&str, &str)]) -> Value {
    let params: std::collections::HashMap<String, String> = kv
        .iter()
        .map(|(k, v)| ((*k).to_string(), (*v).to_string()))
        .collect();
    super::super::sabcompat::queue_json(d, &params)["queue"].clone()
}

fn ids_of(q: &Value) -> Vec<String> {
    q["slots"]
        .as_array()
        .expect("slots array")
        .iter()
        .map(|s| s["nzo_id"].as_str().unwrap_or_default().to_string())
        .collect()
}

/// Ten jobs, mixed enough that every header total has something to say:
/// one downloading, one paused, one duplicate-held, one whose shape
/// unpacks on disk (so the space forecast is not just the remainder),
/// and six plain queued rows.
fn seed(d: &Arc<Daemon>) {
    let mut q = d.queue.lock_ok();
    for i in 0..10 {
        let mut extra = serde_json::json!({
            "total_bytes": 1_000_000_000u64 + i as u64 * 1_000_000,
            "downloaded_bytes": 100_000_000u64,
            "category": if i % 2 == 0 { "tv" } else { "movies" },
        });
        match i {
            3 => extra["paused"] = serde_json::json!(true),
            // A duplicate hold is priority -3 AND paused (see
            // `apply_priority`), which is what makes the row explain
            // itself as held rather than merely stopped.
            5 => {
                extra["paused"] = serde_json::json!(true);
                extra["priority"] = serde_json::json!(-3);
                extra["dupe_key"] = serde_json::json!("some.release.key");
            }
            7 => extra["archive_shape"] = serde_json::json!("rar on-disk"),
            _ => {}
        }
        let job = jv(
            &format!("SABnzbd_nzo_win{i:02}"),
            &format!("Release.S01E{i:02}.1080p-GRP"),
            extra,
        );
        // The one on the wire, deliberately at the END of the queue:
        // `pick_job` runs Force and High out of queue order and skips
        // paused, held and deferred rows wherever they sit (only a
        // priority WRITE moves a row - `reposition_for_priority`), so
        // this is a shape the real daemon reaches,
        // and it is the whole reason `pin_live` exists. Set on the job
        // rather than through the wire value - `job_from_json` reads a
        // persisted Downloading back as Queued on purpose (a job caught
        // by a shutdown goes back through the scheduler).
        if i == 9 {
            job.lock_ok().state = JobState::Downloading;
        }
        q.push_back(job);
    }
}

/// The header is a statement about the queue, not about the page. Every
/// total must read the same however the rows are sliced - which is the
/// property that let the walk stop building rows in the first place.
#[test]
fn a_window_leaves_every_header_total_alone() {
    with_daemon("qwin-totals", |d| {
        seed(d);
        let full = qj(d, &[]);
        // Every key here is a whole-queue fact; `noofslots` is the
        // filtered count taken BEFORE the window, which is exactly what
        // it was when pagination happened after every row was built.
        let totals = [
            "mb",
            "mbleft",
            "size",
            "sizeleft",
            "mbleft_runnable",
            "space_need_bytes",
            "noofslots",
            "noofslots_total",
            "timeleft",
            "status",
        ];
        for win in [
            vec![("limit", "3")],
            vec![("start", "4"), ("limit", "3")],
            vec![("start", "9"), ("limit", "50")],
            // Past the end: an empty page, and still the same header.
            vec![("start", "99"), ("limit", "5")],
        ] {
            let paged = qj(d, &win);
            for k in totals {
                assert_eq!(paged[k], full[k], "{k} changed under window {win:?}");
            }
        }
        // ...and the totals are not trivially zero, or the assertions
        // above would pass on an empty header.
        assert_eq!(full["noofslots"], 10);
        assert!(full["mbleft"].as_str().and_then(|s| s.parse::<f64>().ok()) > Some(0.0));
        assert!(full["space_need_bytes"].as_u64().unwrap_or(0) > 0);
        // The runnable remainder EXCLUDES the paused and duplicate-held
        // rows, which is the filter the dashboard's header ETA meant.
        let all = full["mbleft"]
            .as_str()
            .unwrap_or("0")
            .parse::<f64>()
            .unwrap_or(0.0);
        let run = full["mbleft_runnable"]
            .as_str()
            .unwrap_or("0")
            .parse::<f64>()
            .unwrap_or(0.0);
        assert!(run > 0.0 && run < all, "runnable {run} of {all}");
    });
}

/// Consecutive pages partition the queue exactly: no row seen twice, no
/// row skipped, and the order is the queue's own.
#[test]
fn pages_partition_the_queue_exactly() {
    with_daemon("qwin-pages", |d| {
        seed(d);
        let all = ids_of(&qj(d, &[]));
        assert_eq!(all.len(), 10);
        let mut walked: Vec<String> = Vec::new();
        for start in [0usize, 4, 8, 12] {
            let page = qj(d, &[("start", &start.to_string()), ("limit", "4")]);
            walked.extend(ids_of(&page));
        }
        assert_eq!(walked, all, "the pages must rebuild the queue in order");
        // limit=0 is SAB's "everything from here", not "nothing".
        assert_eq!(ids_of(&qj(d, &[("start", "8"), ("limit", "0")])), all[8..]);
        // And a client that sends no window at all - every SAB remote
        // that never learned about paging, and every *arr - still gets
        // the whole queue.
        assert_eq!(ids_of(&qj(d, &[])).len(), 10);
    });
}

/// A row inside the window is the SAME row the unpaged body carried -
/// every field, including the ones that explain a pause or a hold. The
/// window may only decide WHICH rows are built, never what they say.
#[test]
fn rows_inside_a_window_keep_every_field_they_had() {
    with_daemon("qwin-rows", |d| {
        seed(d);
        let full = qj(d, &[]);
        let rows = full["slots"].as_array().expect("slots").clone();
        // The paused row and the duplicate-held row both sit past the
        // first page, so they are only reachable through a window.
        let page = qj(d, &[("start", "3"), ("limit", "4")]);
        let paged = page["slots"].as_array().expect("slots");
        assert_eq!(paged.len(), 4);
        for (i, row) in paged.iter().enumerate() {
            assert_eq!(*row, rows[3 + i], "row {} differs under a window", 3 + i);
        }
        // Named, so a future edit to `seed` cannot quietly stop covering
        // the explanations this test exists for.
        assert_eq!(paged[0]["status"], "Paused", "the paused row");
        assert_eq!(paged[2]["priority"], "Duplicate", "the held row");
        assert_eq!(paged[2]["duplicate_key"], "some.release.key");
        // `index` is the row's place in the QUEUE, not in the page.
        assert_eq!(paged[0]["index"], 3);
        assert_eq!(paged[3]["index"], 6);
    });
}

/// SAB's `nzo_ids` selector has no window at all: Sonarr reconciles a
/// download weeks after the grab, and an id hidden behind a limit reads
/// as "gone". The walk must turn the window OFF for an id request
/// rather than intersect the two.
#[test]
fn an_id_selection_ignores_the_window() {
    with_daemon("qwin-ids", |d| {
        seed(d);
        let sel = qj(
            d,
            &[
                ("nzo_ids", "SABnzbd_nzo_win02,SABnzbd_nzo_win08"),
                ("start", "5"),
                ("limit", "1"),
            ],
        );
        assert_eq!(
            ids_of(&sel),
            vec![
                "SABnzbd_nzo_win02".to_string(),
                "SABnzbd_nzo_win08".to_string()
            ],
            "both requested ids come back despite start=5&limit=1"
        );
        // The header still describes the whole queue, and `noofslots`
        // is the count the FILTER matched - two, not ten and not one.
        assert_eq!(sel["noofslots"], 2);
        assert_eq!(sel["noofslots_total"], 10);
        assert_eq!(sel["mbleft"], qj(d, &[])["mbleft"]);
    });
}

/// The category filter is applied before the window, and `noofslots`
/// counts what it matched - so a client can page a filtered queue and
/// still be told how long it is.
#[test]
fn the_category_filter_counts_before_the_window() {
    with_daemon("qwin-cat", |d| {
        seed(d);
        let cat = qj(d, &[("category", "tv"), ("limit", "2")]);
        assert_eq!(cat["noofslots"], 5, "five tv jobs matched");
        assert_eq!(cat["noofslots_total"], 10, "ten in the queue");
        assert_eq!(ids_of(&cat).len(), 2, "two of them asked for");
        for id in ids_of(&cat) {
            let n: usize = id[id.len() - 2..].parse().expect("suffix");
            assert_eq!(n % 2, 0, "{id} is not a tv job");
        }
        // Whole-queue totals stay whole-queue: SAB's `mb` header is not
        // filtered, and neither were ours before this change.
        assert_eq!(cat["mbleft"], qj(d, &[])["mbleft"]);
    });
}

/// `pin_live=1` (ours, off unless asked for): the job on the wire rides
/// the page wherever it sits. Without it a client paging from the top
/// of a long queue draws "what is running" off a page with nothing
/// running in it, because `pick_job` never moves the row it picks.
#[test]
fn pin_live_keeps_the_running_row_in_the_page() {
    with_daemon("qwin-pin", |d| {
        seed(d);
        let running = "SABnzbd_nzo_win09";
        let plain = qj(d, &[("limit", "2")]);
        assert_eq!(ids_of(&plain).len(), 2);
        assert!(
            !ids_of(&plain).iter().any(|i| i == running),
            "without the flag the window is exactly the window"
        );
        let pinned = qj(d, &[("limit", "2"), ("pin_live", "1")]);
        let got = ids_of(&pinned);
        assert_eq!(got.len(), 3, "the page, plus the live row");
        assert_eq!(got[2], running, "and it keeps its place in queue order");
        assert_eq!(pinned["slots"][2]["status"], "Downloading");
        // A pinned row does not change what the header counts.
        assert_eq!(pinned["noofslots"], plain["noofslots"]);
        assert_eq!(pinned["mbleft"], plain["mbleft"]);
        // No SAB client sends the flag, and anything but `1` is not it.
        assert_eq!(
            ids_of(&qj(d, &[("limit", "2"), ("pin_live", "0")])).len(),
            2
        );
        // It is a widening, never a filter: with no window it changes
        // nothing at all.
        assert_eq!(ids_of(&qj(d, &[("pin_live", "1")])), ids_of(&qj(d, &[])));
    });
}
