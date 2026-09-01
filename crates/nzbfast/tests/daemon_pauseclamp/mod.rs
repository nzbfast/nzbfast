//! The 23 Aug 2026 bug sweep's F8: a pause length no `Instant` can hold
//! must be clamped, not panicked on, on every route that accepts one.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//! It also keeps daemon.rs under the size gate - which has 17 lines of
//! headroom over its baseline, and this case is 150.

use super::*;

/// Seconds in the year `arm_pause_timer` clamps to, as whole minutes -
/// what `pause_int` reports for a clamped pause. `div_ceil(60)` of the
/// deadline's remaining seconds, so a pause armed a moment ago reads
/// exactly this and one armed a minute ago reads one less.
const ONE_YEAR_MINS: u64 = 365 * 24 * 60;

/// Bug sweep 23 Aug 2026, F8: an absurd pause length must leave the
/// HTTP surface whole.
///
/// The defect: `arm_pause_timer` did `Instant::now() + dur` with a
/// duration built straight from a caller-supplied u64, and
/// `Instant::add` PANICS on overflow rather than saturating. The HTTP
/// pool is eight `spawn_blocking` workers with no `catch_unwind`
/// anywhere above them (`spawn_http_workers`), so the panic did not
/// fail the request - it killed the worker that took it, permanently.
/// One request cost a worker for the life of the process; eight left
/// the daemon listening and answering nothing. No log line says so and
/// nothing restarts a worker, so the symptom a user reports is "the web
/// UI stopped loading" some arbitrary time after a phone app sent one
/// pause-for.
///
/// Three routes reach it with a value the caller chooses, and all three
/// are exercised here because they arrive by different arithmetic:
///
/// - JSON-RPC `scheduleresume` takes a bare u64 of SECONDS off the wire
///   (LunaSea's pause-for dialog sends this after `pausedownload`), so
///   it reaches the add with no scaling at all.
/// - SAB `mode=pause&value=<minutes>` and `mode=config&name=set_pause`
///   both go through `timed_pause`, which multiplies by 60 - a second
///   overflow, one step earlier, and one that panics in a debug build
///   before the add is ever reached. Hence `saturating_mul` there.
///
/// `rate` is in for the same reason: same sweep, same shape (`kb * 1024`
/// on a u64 off the wire), same worker.
///
/// Ten of each, because eight is the whole pool - anything that kills a
/// worker per request is out of workers before the third route starts,
/// and the assertions below then fail on a dead socket rather than on a
/// wrong number. The closing checks are the two halves that matter: the
/// daemon still ANSWERS, and the pause it armed is a real one clamped to
/// a year rather than silently dropped.
#[tokio::test(flavor = "multi_thread")]
async fn an_absurd_pause_length_never_kills_an_http_worker() {
    let dir = std::env::temp_dir().join(format!("nzbfast-pauseclamp-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Nothing here downloads, so no mock NNTP server: the routes under
    // test are all pause bookkeeping. An empty server list is the
    // cheapest config the daemon will start on (see daemon_noservers).
    let cfg = dir.join("config.json");
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--port")
            .arg(port.to_string())
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    tokio::task::spawn_blocking(move || {
        // u64::MAX. As seconds it overflows the add; as minutes it
        // overflows the multiply first.
        const ABSURD: &str = "18446744073709551615";
        let rpc = |method: &str, params: &str| -> String {
            let body = format!("{{\"method\":\"{method}\",\"params\":{params},\"id\":8}}");
            http(
                port,
                "/jsonrpc",
                Some(("application/json", body.as_bytes())),
            )
        };

        for i in 0..10 {
            let r = rpc("scheduleresume", &format!("[{ABSURD}]"));
            assert!(
                r.contains("\"result\":true"),
                "scheduleresume #{i} did not answer: {r}"
            );
        }
        for i in 0..10 {
            let r = http(
                port,
                &format!("/api?mode=pause&value={ABSURD}&output=json"),
                None,
            );
            assert!(
                r.contains("\"status\":true"),
                "mode=pause #{i} did not answer: {r}"
            );
        }
        for i in 0..10 {
            let r = http(
                port,
                &format!("/api?mode=config&name=set_pause&value={ABSURD}&output=json"),
                None,
            );
            assert!(
                r.contains("\"status\":true"),
                "set_pause #{i} did not answer: {r}"
            );
        }
        for i in 0..10 {
            let r = rpc("rate", &format!("[{ABSURD}]"));
            assert!(
                r.contains("\"result\":true"),
                "rate #{i} did not answer: {r}"
            );
        }

        // The surface is whole: an ordinary read still works. This is
        // the assertion the unfixed daemon cannot reach - by here it has
        // lost every worker it had, so `http` exhausts its retries on a
        // socket that accepts and never answers.
        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q)
            .unwrap_or_else(|e| panic!("queue after 40 absurd pauses is not JSON: {e}: {q}"));

        // And the pause is real, and clamped rather than dropped: an
        // armed deadline a year out, not `null` and not a wrapped-round
        // instant in the past. `pause_int` is a STRING here (Dart's
        // tryParse takes one - see remote_compat.rs), and since 31 Aug
        // 2026 it is SAB's own `"minutes:seconds"` rather than bare
        // whole minutes - see `serve::sabcompat::units::pause_int`. The
        // MINUTES are what this test is about; the seconds field is
        // parsed only so that a regression to some third format fails
        // here rather than reading as a plausible number.
        assert_eq!(v["queue"]["paused"], serde_json::json!(true), "{q}");
        let raw = v["queue"]["pause_int"]
            .as_str()
            .unwrap_or_else(|| panic!("pause_int missing or not a string: {q}"));
        let (m, sec) = raw
            .split_once(':')
            .unwrap_or_else(|| panic!("pause_int is not minutes:seconds: {raw:?}: {q}"));
        assert_eq!(sec.len(), 2, "seconds are zero-padded to two: {raw:?}: {q}");
        sec.parse::<u64>()
            .unwrap_or_else(|e| panic!("pause_int seconds are not a number: {e}: {q}"));
        let mins: u64 = m
            .parse()
            .unwrap_or_else(|e| panic!("pause_int is not a number: {e}: {q}"));
        assert!(
            (ONE_YEAR_MINS - 2..=ONE_YEAR_MINS).contains(&mins),
            "a clamped pause should read about {ONE_YEAR_MINS} minutes, got {mins}: {q}"
        );

        // Not one-way: the clamped pause still lifts on a plain resume,
        // so a user who tripped this is not stuck for a year.
        let r = rpc("resumedownload", "[]");
        assert!(r.contains("\"result\":true"), "resume did not answer: {r}");
        let q = http(port, "/api?mode=queue&output=json", None);
        let v: serde_json::Value = serde_json::from_str(&q).unwrap();
        assert_eq!(v["queue"]["paused"], serde_json::json!(false), "{q}");
    })
    .await
    .unwrap();
}
