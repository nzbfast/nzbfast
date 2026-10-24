//! NZBGet JSON-RPC `append` by URL, and `editqueue GroupMoveTop`, held
//! to what the call asked for (Gemini 14 Oct sweep M16 and L6).
//!
//! Its own file rather than `sabcompat.rs`'s, for the size gate
//! (TODO 106): test code moves out of `sabcompat.rs`.

use super::*;
use nzbfast_daemon::testutil::{one_file_nzb, test_daemon};

/// One loopback HTTP answer carrying `body`, on a thread; the URL it
/// listens on comes back with the handle.
fn serve_once(body: String) -> (String, std::thread::JoinHandle<()>) {
    use std::io::{Read, Write};
    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let url = format!("http://{}/g/1", listener.local_addr().unwrap());
    let t = std::thread::spawn(move || {
        let (mut sock, _) = listener.accept().unwrap();
        let mut buf = [0u8; 4096];
        let _ = sock.read(&mut buf);
        let _ = sock.write_all(
            format!(
                "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{body}",
                body.len()
            )
            .as_bytes(),
        );
    });
    (url, t)
}

fn scratch(tag: &str) -> std::path::PathBuf {
    let dir = std::env::temp_dir().join(format!(
        "nzbfast-jrappend-{tag}-{}-{:?}",
        std::process::id(),
        std::thread::current().id()
    ));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    dir
}

/// A URL add in the v13+ shape, with a DupeKey LONGER than the URL, an
/// AddToTop and a `drone` PPParameter - the three things the URL arm
/// lost. The longest-string reading took the DupeKey for the Content and
/// answered 0; and even a URL that won that reading returned before the
/// PPParameters and AddToTop were applied, so the *arrs could never
/// match the job by its `drone` tag.
#[test]
fn a_url_append_keeps_its_parameters_and_add_to_top() {
    let dir = scratch("url");
    let d = test_daemon(&dir);
    d.enqueue(
        one_file_nzb("first-seg").as_bytes(),
        "Already.Queued",
        "",
        0,
        None,
        None,
        "test",
        true,
    )
    .expect("seed job");
    let (url, t) = serve_once(one_file_nzb("url-seg"));
    let dupe_key = format!("{}-dupekey-longer-than-the-url", "x".repeat(url.len()));
    let params: Vec<Value> = json!([
        "From.Url.nzb",
        url,
        "",
        0,
        true,
        false,
        dupe_key,
        0,
        "SCORE",
        [{"Name": "drone", "Value": "guid-123"}]
    ])
    .as_array()
    .unwrap()
    .clone();
    let id = jr_append(&d, &params, "").as_i64().expect("an integer id");
    // Asserted BEFORE the join: an add that never fetched leaves the
    // server thread parked in `accept`, and joining it would hang the
    // test instead of failing it.
    assert_ne!(id, 0, "the URL add must be accepted");
    t.join().unwrap();

    let q = d.queue.lock_ok();
    let head = q.front().expect("a queue").lock_ok();
    assert_eq!(nzo_int(&head.nzo_id), id, "AddToTop puts it first");
    assert!(
        head.pp_params
            .iter()
            .any(|(k, v)| k == "drone" && v == "guid-123"),
        "the drone tag must survive a URL add: {:?}",
        head.pp_params
    );
    drop(head);
    drop(q);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// `GroupMoveTop` on a watchdog-deferred job clears the deferral, as
/// SAB's `switch` does. `pick_job` sorts a deferred job LAST whatever its
/// position, so the move answered true and changed nothing.
#[test]
fn group_move_top_clears_a_watchdog_deferral() {
    let dir = scratch("movetop");
    let d = test_daemon(&dir);
    for seg in ["a-seg", "b-seg"] {
        d.enqueue(
            one_file_nzb(seg).as_bytes(),
            seg,
            "",
            0,
            None,
            None,
            "test",
            true,
        )
        .expect("seed job");
    }
    let last = {
        let q = d.queue.lock_ok();
        let j = q.back().unwrap().clone();
        j.lock_ok().deferred = true;
        nzo_int(&j.lock_ok().nzo_id)
    };
    let params: Vec<Value> = json!(["GroupMoveTop", "", [last]])
        .as_array()
        .unwrap()
        .clone();
    let mut err = None;
    assert_eq!(jr_editqueue(&d, &params, &mut err), json!(true));
    let q = d.queue.lock_ok();
    let head = q.front().unwrap().lock_ok();
    assert_eq!(nzo_int(&head.nzo_id), last, "moved to the top");
    assert!(
        !head.deferred,
        "a manual move to the top lifts the deferral"
    );
    drop(head);
    drop(q);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Standard base64 with padding, for an `append` Content. The handler's
/// own `b64_decode` is the reader under test, so the writer is a few
/// lines here rather than a dependency.
fn b64(bytes: &[u8]) -> String {
    const A: &[u8; 64] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    let mut out = String::new();
    for c in bytes.chunks(3) {
        let n = (u32::from(c[0]) << 16)
            | (u32::from(*c.get(1).unwrap_or(&0)) << 8)
            | u32::from(*c.get(2).unwrap_or(&0));
        for i in 0..4 {
            if i <= c.len() {
                out.push(A[((n >> (18 - 6 * i)) & 63) as usize] as char);
            } else {
                out.push('=');
            }
        }
    }
    out
}

/// A base64 `append` in the v13+ shape carrying a `drone` PPParameter.
fn b64_append(d: &Arc<Daemon>, name: &str, seg: &str, drone: &str) -> i64 {
    let params: Vec<Value> = json!([
        name,
        b64(one_file_nzb(seg).as_bytes()),
        "",
        0,
        false,
        false,
        "",
        0,
        "SCORE",
        ["drone", drone]
    ])
    .as_array()
    .unwrap()
    .clone();
    jr_append(d, &params, "").as_i64().expect("an integer id")
}

/// The record `id` answers to, from history, with its parameters.
fn history_params(d: &Arc<Daemon>, id: i64) -> Option<(JobState, Vec<(String, String)>)> {
    d.history
        .lock_ok()
        .iter()
        .find(|j| nzo_int(&j.lock_ok().nzo_id) == id)
        .map(|j| {
            let g = j.lock_ok();
            (g.state, g.pp_params.clone())
        })
}

fn has_drone(pp: &[(String, String)], drone: &str) -> bool {
    pp.iter().any(|(k, v)| k == "drone" && v == drone)
}

/// Codex 22 Oct sweep F4: an append that `dupe_action = "fail"` files
/// straight to history kept its PPParameters only if a scan of the LIVE
/// QUEUE found the job after `enqueue` returned - and a job filed to
/// history is not in the queue. The *arrs match a failed grab by its
/// `drone` tag, so the accepted id answered to a Failed record they
/// could never claim. Both arms, base64 and URL, and across a restart;
/// the ordinary queued append keeps its tag too.
#[test]
fn an_append_failed_as_a_duplicate_keeps_its_parameters() {
    let dir = scratch("dupefail");
    let d = test_daemon(&dir);
    // The original, by base64 append: the queued case, unchanged.
    let first = b64_append(&d, "Show.S01E02.1080p.nzb", "one", "guid-queued");
    assert_ne!(first, 0, "the original add must be accepted");
    {
        let q = d.queue.lock_ok();
        let j = q
            .iter()
            .find(|j| nzo_int(&j.lock_ok().nzo_id) == first)
            .expect("the original is queued")
            .lock_ok();
        assert!(has_drone(&j.pp_params, "guid-queued"), "{:?}", j.pp_params);
    }
    *d.dupe_action.lock_ok() = "fail".into();

    // base64: the duplicate is accepted and filed to history as Failed.
    let dup = b64_append(&d, "Show.S01E02.720p.nzb", "two", "guid-b64");
    assert_ne!(dup, 0, "a failed duplicate is still an accepted add");
    let (state, pp) = history_params(&d, dup).expect("filed to history");
    assert_eq!(state, JobState::Failed);
    assert!(
        has_drone(&pp, "guid-b64"),
        "base64 arm lost the drone: {pp:?}"
    );

    // URL: the same, through `enqueue_fetched`.
    let (url, t) = serve_once(one_file_nzb("three"));
    let params: Vec<Value> = json!([
        "Show.S01E02.480p.nzb",
        url,
        "",
        0,
        false,
        false,
        "",
        0,
        "SCORE",
        ["drone", "guid-url"]
    ])
    .as_array()
    .unwrap()
    .clone();
    let via_url = jr_append(&d, &params, "").as_i64().expect("an integer id");
    assert_ne!(via_url, 0, "the URL add must be accepted");
    t.join().unwrap();
    let (state, pp) = history_params(&d, via_url).expect("filed to history");
    assert_eq!(state, JobState::Failed);
    assert!(has_drone(&pp, "guid-url"), "URL arm lost the drone: {pp:?}");

    // ...and what a restart reads back off history.jsonl.
    let d2 = nzbfast_daemon::testutil::restart(&d);
    for (id, drone) in [(dup, "guid-b64"), (via_url, "guid-url")] {
        let (_, pp) = history_params(&d2, id).expect("still in history after restart");
        assert!(has_drone(&pp, drone), "lost across restart: {pp:?}");
    }
    drop(d2);
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The other never-queued arm (Codex 22 Oct sweep F4): a pre-queue
/// script that REJECTS files the add to history as Failed, and that
/// record has to carry the `drone` tag the *arr sent with it.
#[cfg(unix)]
#[test]
fn an_append_rejected_by_the_pre_queue_script_keeps_its_parameters() {
    use std::os::unix::fs::PermissionsExt;
    let dir = scratch("prequeue");
    let d = test_daemon(&dir);
    let hook = dir.join("reject.sh");
    std::fs::write(&hook, "#!/bin/sh\nprintf '0\\n'\n").unwrap();
    std::fs::set_permissions(&hook, std::fs::Permissions::from_mode(0o755)).unwrap();
    *d.pre_queue_script.lock_ok() = Some(hook);

    let id = b64_append(&d, "Rejected.Release.nzb", "rj", "guid-rejected");
    assert_ne!(id, 0, "a rejected add is still an accepted add");
    let (state, pp) = history_params(&d, id).expect("filed to history");
    assert_eq!(state, JobState::Failed);
    assert!(has_drone(&pp, "guid-rejected"), "{pp:?}");
    drop(d);
    let _ = std::fs::remove_dir_all(&dir);
}
