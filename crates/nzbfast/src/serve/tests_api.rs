//! serve tests: the API surface, the settings reflection guards, and
//! the process plumbing (run_capped_sieve, the body budget, redaction).//!
//! Split out of serve/mod.rs's inline `mod tests` by TODO 106 phase 4;
//! attached to serve as a sibling child module, so `super` still means
//! `serve` exactly as it did inline.

use super::*;
// Every test that reaches for these is `#[cfg(unix)]` - the process
// plumbing they cover is a unix path. Ungated, the import is dead on
// Windows and `-D warnings` turns that into a build error there.
#[cfg(unix)]
use script::{SCRIPT_ERR_TAIL, run_capped_sieve};

/// M5 (Codex sweep 5 Aug): a recategorize that physically moved the
/// payload and then could not write the queue file answered
/// `status:true` - and the restart restored the OLD record over the
/// emptied source, orphaning the bytes at the destination. The
/// caller must hear that the move happened but the record did not
/// stick, with both paths in hand.
#[cfg(unix)]
#[test]
fn a_recategorize_whose_record_cannot_persist_is_reported() {
    use crate::serve::job::{JobState, job_from_json};
    use crate::serve::testutil::test_daemon;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("nzbfast-recatsave-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let out = dir.join("out").join("Some.Job");
    std::fs::create_dir_all(&out).unwrap();
    std::fs::write(out.join("payload.bin"), b"bytes").unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_recat",
            "name": "Some.Job",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Completed",
            "category": "tv",
        }))
        .unwrap(),
    ));
    assert_eq!(job.lock_ok().state, JobState::Completed);
    d.history.lock_ok().push(job.clone());
    let spool = dir.join("spool");
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o555)).unwrap();
    let v = history_change_cat(&d, "SABnzbd_nzo_recat", "movies");
    std::fs::set_permissions(&spool, std::fs::Permissions::from_mode(0o755)).unwrap();

    // The move itself happened and the live record follows the bytes...
    let dest = dir.join("out").join("movies").join("Some.Job");
    assert!(
        dest.join("payload.bin").exists(),
        "the payload did not move: {v}"
    );
    assert_eq!(job.lock_ok().out_dir, dest);
    // ...but the response is a failure that names both paths.
    assert_eq!(v["status"], false, "{v}");
    let e = v["error"].as_str().unwrap_or_default();
    assert!(e.contains("could not be written"), "{v}");
    assert!(e.contains(&*out.to_string_lossy()), "{v}");
    assert!(e.contains(&*dest.to_string_lossy()), "{v}");
    let _ = std::fs::remove_dir_all(&dir);
}

/// A line is advertised in megaBITS everywhere on earth, so "900M"
/// in the Line speed box is what a person on a 900 Mbps connection
/// types - and reading it as 900 MB/s made their line eight times
/// bigger than it is, which is how a healthy 37 MB/s got scored as
/// "4% of your line".
#[test]
fn bit_units_are_bits_and_byte_units_are_bytes() {
    // 900 Mbps = 112.5 MB/s, however it is spelled.
    for s in [
        "900Mb", "900Mbit", "900Mbits", "900Mbps", "900mbps", "900 Mbps", "900Mb/s",
    ] {
        assert_eq!(parse_size(s), Some(112_500_000), "{s}");
    }
    assert_eq!(parse_size("1Gbps"), Some(125_000_000));
    // Explicit bytes stay bytes...
    assert_eq!(parse_size("900MB"), Some(900_000_000));
    assert_eq!(parse_size("112MB/s"), Some(112_000_000));
    // ...and so does a bare magnitude. 29 call sites read disk and
    // cache sizes through this; they are not secretly about bits.
    assert_eq!(parse_size("900M"), Some(900_000_000));
    assert_eq!(parse_size("1G"), Some(1_000_000_000));
    assert_eq!(parse_size("4096"), Some(4096));
}

/// Nothing that parsed before parses differently now. Every suffixed
/// form was REJECTED by this function, so the change can only turn a
/// refusal into a number - which is what made it safe to land
/// against a parser this widely used.
#[test]
fn the_old_accepted_forms_are_untouched() {
    assert_eq!(parse_size("0"), Some(0));
    assert_eq!(parse_size("10G"), Some(10_000_000_000));
    assert_eq!(parse_size("4M"), Some(4_000_000));
    assert_eq!(parse_size("  2K  "), Some(2_000));
    assert_eq!(parse_size("who knows"), None);
    assert_eq!(parse_size(""), None);
    assert_eq!(parse_size("-5M"), None);
}

/// SAB's `nzo_ids` selector: named ids bypass the start/limit
/// window entirely (Sonarr reconciles weeks-old downloads by id -
/// pagination hiding one reads as "deleted" and wedges it).
#[test]
fn nzo_ids_select_directly_and_skip_pagination() {
    let p = |kv: &[(&str, &str)]| -> std::collections::HashMap<String, String> {
        kv.iter()
            .map(|(k, v)| (k.to_string(), v.to_string()))
            .collect()
    };
    // Absent, empty, or all-blank lists mean "no selection".
    assert_eq!(nzo_ids_param(&p(&[])), None);
    assert_eq!(nzo_ids_param(&p(&[("nzo_ids", "")])), None);
    assert_eq!(nzo_ids_param(&p(&[("nzo_ids", " , ,")])), None);
    // A comma list parses with whitespace tolerated.
    let ids = nzo_ids_param(&p(&[(
        "nzo_ids",
        "SABnzbd_nzo_nzbfast1, SABnzbd_nzo_nzbfast7",
    )]))
    .expect("two ids");
    assert!(ids.contains("SABnzbd_nzo_nzbfast1"));
    assert!(ids.contains("SABnzbd_nzo_nzbfast7"));
    assert_eq!(ids.len(), 2);
    // The selection path must not paginate: the same params carry a
    // limit that would hide the row, and the history/queue builders
    // branch on `ids.is_some()` to skip `paginate`. Guard the
    // paginate half here: with limit=1 and start=1 the second slot
    // survives only via the ids branch.
    let slots = vec![json!({"nzo_id": "a"}), json!({"nzo_id": "b"})];
    let paged = paginate(
        slots,
        &p(&[("start", "0"), ("limit", "1"), ("nzo_ids", "b")]),
    );
    assert_eq!(paged.len(), 1, "paginate itself stays id-blind");
}

/// SAB accepts priorities as numbers or words; unknown words stay
/// None so the -100 "not given" sentinel logic is untouched.
#[test]
fn priority_tokens_parse_like_sab() {
    use super::sabcompat::parse_priority_token as t;
    assert_eq!(t("2"), Some(2));
    assert_eq!(t("-100"), Some(-100));
    assert_eq!(t("force"), Some(2));
    assert_eq!(t("Force"), Some(2));
    assert_eq!(t("HIGH"), Some(1));
    assert_eq!(t("normal"), Some(0));
    assert_eq!(t("low"), Some(-1));
    assert_eq!(t("paused"), Some(-2));
    assert_eq!(t("urgent"), None);
    assert_eq!(t(""), None);
}

/// Going offline pauses; coming back online must unpause ONLY the
/// pause that going offline created.
///
/// The case that matters is the third: an operator pauses by hand,
/// then goes offline to free the account, then comes back online.
/// Resuming their download for them is not what "online" was asked
/// to do, and it would start a transfer they deliberately stopped -
/// possibly a metered one.
#[test]
fn coming_online_does_not_resume_a_download_the_user_paused() {
    // Running -> offline: offline owns the pause, and gives it back.
    assert_eq!(offline_pause_transition(true, false, false), (true, true));
    assert_eq!(offline_pause_transition(false, true, true), (false, false));

    // Already paused by hand -> offline: the pause is not ours...
    assert_eq!(offline_pause_transition(true, true, false), (true, false));
    // ...so coming back online leaves it exactly as the user set it.
    assert_eq!(offline_pause_transition(false, true, false), (true, false));

    // Online while already running is a no-op on both flags.
    assert_eq!(
        offline_pause_transition(false, false, false),
        (false, false)
    );
}

/// The daemon's `fast_par` default and the CLI's (the nzbkit flag
/// initializer) must be the same value. Today that's by re-export;
/// if someone splits `FAST_PAR_DEFAULT` back into a local const,
/// this catches the two drifting apart.
#[test]
fn fast_par_default_matches_nzbkit() {
    assert_eq!(FAST_PAR_DEFAULT, nzbkit::par2repair::FAST_PAR_DEFAULT);
}

/// A post-script that prints without stopping must cost a bounded
/// amount of memory. The drain used to `read_to_string` into an
/// unbounded `String`, so the daemon grew until it died - and it did
/// so BEFORE the deadline could stop it, because the deadline only
/// ever checked the process, never the pipe.
#[cfg(unix)]
#[test]
fn a_script_that_never_stops_talking_is_bounded_and_still_killed() {
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c")
        .arg("while :; do printf 'noise noise noise\\n' >&2; done");
    let t0 = Instant::now();
    let (status, _, err) = run_capped_sieve(cmd, 1).unwrap();
    assert!(status.is_none(), "the deadline must have killed it");
    assert!(
        t0.elapsed() < std::time::Duration::from_secs(10),
        "returned late"
    );
    assert!(
        err.len() <= SCRIPT_ERR_TAIL + 64,
        "kept {} bytes of stderr; the ring is {SCRIPT_ERR_TAIL}",
        err.len()
    );
    assert!(err.contains("noise"), "the tail is what a log line quotes");
    assert!(err.contains("dropped"), "truncation has to be visible");
}

/// The in-flight body budget (28 Jul sweep: 8 workers x 256 MB could
/// OOM a clamped container): a second concurrent body must WAIT when
/// the pool is exhausted, the sole active reader must never be
/// refused (one huge NZB still uploads on a small box), and a
/// release must wake the waiter.
#[test]
fn body_budget_blocks_others_but_never_a_sole_reader() {
    let b = std::sync::Arc::new(BodyBudget::new(10));
    // Sole reader: exceeds the cap outright.
    let mut a = Hold::default();
    b.grow(&mut a, 8);
    b.grow(&mut a, 8);
    assert_eq!(a.bytes, 16, "the sole reader must always be admitted");
    // A second body must wait while the first holds the pool...
    let b2 = b.clone();
    let (tx, rx) = std::sync::mpsc::channel();
    let t = std::thread::spawn(move || {
        let mut h = Hold::default();
        b2.grow(&mut h, 4);
        tx.send(()).unwrap();
        b2.release(h);
    });
    assert!(
        rx.recv_timeout(std::time::Duration::from_millis(200))
            .is_err(),
        "a second reader was admitted past the cap"
    );
    // ...and proceed the moment the first releases.
    b.release(a);
    rx.recv_timeout(std::time::Duration::from_secs(5))
        .expect("the waiter never woke after the release");
    t.join().unwrap();
}

/// The deadlock the shape above hides: BOTH readers hold bytes. Each
/// is part of the total the other is queued behind and neither
/// releases until its read loop ends, so an unbounded wait parked the
/// pair forever - and every later body-reading request behind them,
/// which is all 8 HTTP workers. Reachable unauthenticated (bodies are
/// buffered before the auth decision) and by accident on a
/// memory-clamped box with two concurrent uploads.
#[test]
fn two_holders_that_exhaust_the_pool_both_finish() {
    let b = std::sync::Arc::new(BodyBudget::new(8));
    let (tx, rx) = std::sync::mpsc::channel();
    // Both must be HOLDING half before either asks for more -
    // otherwise one thread simply runs the whole sequence first and
    // the cycle never forms.
    let gate = std::sync::Arc::new(std::sync::Barrier::new(2));
    let hands: Vec<_> = (0..2)
        .map(|_| {
            let (b, tx, gate) = (b.clone(), tx.clone(), gate.clone());
            std::thread::spawn(move || {
                let mut h = Hold::default();
                // Each takes half the pool, then asks for more: the
                // point at which both are holders and neither can
                // proceed without the other releasing.
                b.grow(&mut h, 4);
                gate.wait();
                b.grow(&mut h, 4);
                tx.send(()).unwrap();
                b.release(h);
            })
        })
        .collect();
    for _ in 0..2 {
        rx.recv_timeout(BODY_BUDGET_WAIT * 3)
            .expect("a body-budget holder never woke: the pool deadlocked");
    }
    for h in hands {
        h.join().unwrap();
    }
}

/// The escape hatch that used to be here, run for a while. Codex
/// found this on the 31 Jul sweep and it was real: the timeout
/// release was granted to EVERY holder, every round, forever, so a
/// set of stalled uploads ratcheted the pool upward by one chunk each
/// per wait instead of being held near the cap. Against the old rule
/// this reached 117 with a cap of 16 - 7x - inside 600 ms, and in
/// production it walks at 8 MiB per 5 s back toward the
/// multi-gigabyte figure the budget exists to prevent, on the
/// add-only tier `addfile` accepts.
///
/// The bound that has to hold: at most ONE body over the cap, because
/// only the oldest holder is let past it. Every holder here asks for
/// far more than its share and none of them ever releases, which is
/// the slow-loris fleet; `EXTRA` stands in for the per-request `take`
/// cap that bounds the single over-runner in production.
#[test]
fn stalled_holders_cannot_ratchet_the_pool_upward() {
    // Eight, because eight is the HTTP worker count - the fleet size
    // that made the original finding a ~2 GiB one.
    const HOLDERS: u64 = 8;
    const SHARE: u64 = 4;
    const EXTRA: u64 = 16;
    let cap = HOLDERS * SHARE;
    let b = std::sync::Arc::new(BodyBudget::with_wait(
        cap,
        std::time::Duration::from_millis(5),
    ));
    let gate = std::sync::Arc::new(std::sync::Barrier::new(HOLDERS as usize));
    let peak = std::sync::Arc::new(AtomicU64::new(0));
    let hands: Vec<_> = (0..HOLDERS)
        .map(|_| {
            let (b, gate, peak) = (b.clone(), gate.clone(), peak.clone());
            std::thread::spawn(move || {
                let mut h = Hold::default();
                b.grow(&mut h, SHARE);
                // Everyone holds its share before anyone asks for
                // more, or one thread simply runs the whole sequence
                // alone as the sole reader.
                gate.wait();
                for _ in 0..EXTRA {
                    b.grow(&mut h, 1);
                    peak.fetch_max(b.cur.lock().unwrap().bytes, Ordering::Relaxed);
                }
                b.release(h);
            })
        })
        .collect();
    for h in hands {
        h.join().unwrap();
    }
    let peak = peak.load(Ordering::Relaxed);
    assert!(
        peak <= cap + EXTRA,
        "the pool peaked at {peak} against a cap of {cap}: more than one \
         body got past it, so stalled holders are ratcheting it upward"
    );
    assert_eq!(
        b.cur.lock().unwrap().bytes,
        0,
        "every hold must be released"
    );
}

/// The shape that leaked a blocking-pool worker per completed job: a
/// script that backgrounds something and exits happily. The
/// descendant inherits stdout/stderr, so the pipes stay open long
/// after the direct child is reaped - and the drain threads used to
/// be JOINED, which parked the caller for the descendant's lifetime
/// however short the configured deadline was.
///
/// Not joining them fixed the caller and left the cost: the thread
/// and the pipe's read end lived as long as the descendant did, once
/// per completed job, and `script_timeout_secs` never bounded it
/// because nothing had timed out. §144 item 4 puts the drains on a
/// stop flag instead, so this asserts all four halves - the caller
/// returns at once, the descendant is STILL RUNNING (killing what a
/// script deliberately backgrounded is the thing we chose not to do),
/// and both the thread count and the open-pipe count come back to
/// where they started over repeated runs.
///
/// The version of this test before §144 asserted only the first half
/// and left its own `sleep` running, which is what marked the binary
/// leaky under nextest.
#[cfg(unix)]
#[test]
fn a_backgrounded_descendant_stops_costing_us_a_thread_and_a_pipe() {
    use script::DRAIN_THREADS;

    /// Pipe FDs this process holds open. Counted by `fstat` over the
    /// descriptor space rather than by listing /dev/fd, so the count
    /// does not itself depend on a directory read that opens an FD -
    /// and so only PIPES are counted, which keeps the temp files and
    /// sockets of tests running alongside this one out of the number.
    fn open_pipes() -> usize {
        (0..1024)
            .filter(|&fd| {
                let mut st: libc::stat = unsafe { std::mem::zeroed() };
                let ok = unsafe { libc::fstat(fd, &mut st) } == 0;
                ok && st.st_mode & libc::S_IFMT == libc::S_IFIFO
            })
            .count()
    }

    fn alive(pid: i32) -> bool {
        unsafe { libc::kill(pid, 0) == 0 }
    }

    let dir = std::env::temp_dir().join(format!("nzbfast-drainleak-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    // A script that backgrounds a 60 s helper, records its pid so this
    // test can clean up after itself, and exits 0. The helper inherits
    // stdout and stderr, which is what holds the pipes open.
    let run = |n: usize| -> i32 {
        let pidfile = dir.join(format!("{n}.pid"));
        let mut cmd = std::process::Command::new("sh");
        cmd.arg("-c").arg(format!(
            "sleep 60 & echo $! > {}; exit 0",
            pidfile.display()
        ));
        let t0 = Instant::now();
        let (status, _, _) = run_capped_sieve(cmd, 5).unwrap();
        let took = t0.elapsed();
        assert!(
            status.is_some_and(|s| s.success()),
            "the script itself exited fine"
        );
        assert!(
            took < std::time::Duration::from_secs(5),
            "waited {took:?} on a descendant holding the pipe"
        );
        std::fs::read_to_string(&pidfile)
            .unwrap()
            .trim()
            .parse()
            .unwrap()
    };

    /// Poll until both counts are back at their baseline, or give up.
    /// A poll rather than one reading because the drains exit on their
    /// own clock, and because other tests in this binary open and close
    /// pipes of their own while this one runs.
    fn settle(threads: usize, pipes: usize) -> (usize, usize) {
        let end = Instant::now() + std::time::Duration::from_secs(10);
        loop {
            let (t, p) = (DRAIN_THREADS.load(Ordering::Relaxed), open_pipes());
            if (t <= threads && p <= pipes) || Instant::now() >= end {
                return (t, p);
            }
            std::thread::sleep(std::time::Duration::from_millis(50));
        }
    }

    // One warm run first, so the baseline is a steady state: the thread
    // that ran it has retired and `sh` has been paged in.
    let mut pids = vec![run(0)];
    settle(0, 0);
    let base_threads = DRAIN_THREADS.load(Ordering::Relaxed);
    let base_pipes = open_pipes();

    const RUNS: usize = 8;
    for n in 1..=RUNS {
        pids.push(run(n));
    }
    // Every descendant is still running: this fix does not kill what a
    // post-script deliberately left behind.
    for &pid in &pids {
        assert!(alive(pid), "descendant {pid} was killed on a clean exit");
    }

    let (threads, pipes) = settle(base_threads, base_pipes);
    assert!(
        threads <= base_threads,
        "{RUNS} finished scripts left {threads} drain threads alive \
         (baseline {base_threads}); their descendants outlive them, so \
         the drains have to let go rather than wait for EOF"
    );
    assert!(
        pipes <= base_pipes,
        "{RUNS} finished scripts left {pipes} pipe FDs open (baseline \
         {base_pipes}); each drain owns a read end and must drop it"
    );

    // Leave nothing behind - the whole point of the exercise.
    for pid in pids {
        unsafe { libc::kill(pid, libc::SIGKILL) };
    }
    let _ = std::fs::remove_dir_all(&dir);
}

/// Two workers registering different first-seen categories used to
/// race: each took a `cat_list()` snapshot after dropping the
/// category lock, and the later WRITE could carry the earlier
/// snapshot - so B's category was written and then overwritten away.
/// Live memory held both, so it only surfaced after a restart, with
/// an *arr suddenly failing its category test.
#[test]
fn registering_a_category_never_drops_one_already_on_disk() {
    // B landed {tv, movies} while A was still holding {tv, anime}.
    assert_eq!(
        merge_cat_list("tv, movies", "tv, anime"),
        "tv, movies, anime"
    );
    // Idempotent: re-registering something already recorded rewrites
    // the same list.
    assert_eq!(merge_cat_list("tv, movies", "tv, movies"), "tv, movies");
    // First category on a fresh install, and the empty-side cases.
    assert_eq!(merge_cat_list("", "tv"), "tv");
    assert_eq!(merge_cat_list("tv", ""), "tv");
    assert_eq!(merge_cat_list("", ""), "");
    // Whitespace and empty members in a hand-edited file.
    assert_eq!(
        merge_cat_list("tv ,, movies", " anime "),
        "tv, movies, anime"
    );
}

/// A scan pass owns a dedicated connection for minutes; the switch
/// and the wipe button are one click. The pass used to republish
/// unconditionally when it exited, so switching the indexer OFF
/// mid-scan got a live shared connection back, and wiping got the
/// database recreated seconds after the API reported it gone.
#[cfg(feature = "indexer")]
#[test]
fn a_scan_pass_may_only_publish_into_the_index_it_started_in() {
    // The ordinary case: same era, still on.
    assert!(may_publish_index(7, 7, true));
    // Switched off while the pass ran.
    assert!(!may_publish_index(8, 8, false));
    // Wiped while the pass ran - the era moved on, and a wipe that
    // gets its files recreated by an exiting scan was never a wipe.
    assert!(!may_publish_index(9, 8, true));
    // Both, which is what switching off actually looks like (the
    // close bumps the era too).
    assert!(!may_publish_index(9, 8, false));
}

/// The ordinary case still has to work: exit status and stderr are
/// what the caller logs.
#[cfg(unix)]
#[test]
fn a_failing_script_reports_its_status_and_stderr() {
    let mut cmd = std::process::Command::new("sh");
    cmd.arg("-c").arg("echo ignored; echo boom >&2; exit 3");
    let (status, _, err) = run_capped_sieve(cmd, 30).unwrap();
    assert_eq!(status.and_then(|s| s.code()), Some(3));
    assert_eq!(err.trim(), "boom");
}

/// An indexer transport error carries the URL it failed on, and that
/// URL carries the user's API key. It reached a rendered error row on
/// two surfaces before this scrubber existed.
#[test]
fn apikey_never_rides_an_error_string() {
    let msg = "https://idx.example/api?t=search&apikey=SECRET123&q=x: Dns Failed";
    let got = redact_apikey(msg);
    assert!(!got.contains("SECRET123"), "{got}");
    assert_eq!(
        got,
        "https://idx.example/api?t=search&apikey=***&q=x: Dns Failed"
    );
    // Key last in the query, so the value runs to the end of the URL
    // rather than to an '&'.
    let tail = redact_apikey("https://idx/api?t=caps&apikey=abc def");
    assert_eq!(tail, "https://idx/api?t=caps&apikey=*** def");
    // Two of them (a message that quotes the URL twice) and a string
    // with none at all.
    assert_eq!(
        redact_apikey("a apikey=1&b apikey=2&c"),
        "a apikey=***&b apikey=***&c"
    );
    assert_eq!(redact_apikey("plain error"), "plain error");
}

/// The third surface: text the INDEXER wrote. Newznab reports protocol
/// errors with HTTP 200, so an `<error description>` arrives after every
/// transport-level scrubber has already run, and it is echoed to Test
/// results, search notes, the wall and the logs. Indexers reflect the
/// request back, and not always spelling the key `apikey=` (14 Aug
/// sweep).
#[test]
fn an_indexer_written_error_never_carries_the_key() {
    use crate::newznab::NewznabError as E;
    let key = "SECRET123456";
    // The reflected-parameter shape, which redact_apikey alone covers.
    let got = scrub_indexer_body_error(E::Auth(100, format!("invalid apikey={key}")), key);
    let E::Auth(_, m) = &got else {
        panic!("{got:?}")
    };
    assert!(!m.contains(key), "{m}");
    // The BARE reflection: the key with no parameter name in front of
    // it, which is why the configured value itself has to be blanked.
    let got = scrub_indexer_body_error(E::Api(200, format!("no such user {key} here")), key);
    let E::Api(_, m) = &got else {
        panic!("{got:?}")
    };
    assert!(!m.contains(key), "{m}");
    assert_eq!(m, "no such user *** here");
    // Limit answers carry the same body and the same risk.
    let got = scrub_indexer_body_error(E::Limit(500, format!("quota for {key}")), key);
    let E::Limit(_, m) = &got else {
        panic!("{got:?}")
    };
    assert!(!m.contains(key), "{m}");
    // An ordinary message is untouched...
    let got = scrub_indexer_body_error(E::Api(0, "not a newznab API".into()), key);
    let E::Api(_, m) = &got else {
        panic!("{got:?}")
    };
    assert_eq!(m, "not a newznab API");
    // ...and a short or empty configured key never turns prose into
    // asterisks: blanking "abc" everywhere would redact real words.
    let got = scrub_indexer_body_error(E::Api(0, "abc is a code".into()), "abc");
    let E::Api(_, m) = &got else {
        panic!("{got:?}")
    };
    assert_eq!(m, "abc is a code");
    let got = scrub_indexer_body_error(E::Api(0, "plain trouble".into()), "");
    let E::Api(_, m) = &got else {
        panic!("{got:?}")
    };
    assert_eq!(m, "plain trouble");
}

/// The GRAB path needs more than [`redact_apikey`]. That scrubber
/// knows the credential is spelled `apikey=` because WE built the
/// search URL. An NZB enclosure link comes out of the indexer's own
/// XML and can spell it anything, so the whole URL past the host goes.
///
/// Regression for a real leak: `fetch_url` names the URL it failed
/// on, and both `indexer_grab` and the nzblnk ladder put that string
/// straight into a response the dashboard renders.
#[test]
fn a_grab_error_shows_the_host_and_nothing_else() {
    let got = redact_url_creds(
        "http://idx.example/getnzb/abc?r=SECRET123&i=42: 999 bytes is too large for an NZB",
    );
    assert!(!got.contains("SECRET123"), "{got}");
    // The `:` that separated the URL from the sentence goes with the
    // URL - it is attached to it, and telling sentence punctuation
    // apart from URL punctuation is a rabbit hole with a credential
    // at the bottom of it. Dropping is the safe direction, and the
    // message still reads.
    assert_eq!(
        got,
        "http://idx.example/... 999 bytes is too large for an NZB"
    );
    // Userinfo is a credential too.
    assert_eq!(
        redact_url_creds("https://user:pw@idx.example/x?k=1 failed"),
        "https://idx.example/... failed"
    );
    // A bare origin keeps its shape; two URLs in one sentence both go.
    assert_eq!(
        redact_url_creds("https://idx.example refused"),
        "https://idx.example refused"
    );
    assert_eq!(
        redact_url_creds("http://a/x?k=1 then https://b/y?k=2 done"),
        "http://a/... then https://b/... done"
    );
    assert_eq!(redact_url_creds("plain error"), "plain error");
    // https must not be matched as http:// + "s..." when both appear
    // and the https one comes first.
    assert_eq!(
        redact_url_creds("https://b/y?k=2 and http://a/x?k=1"),
        "https://b/... and http://a/..."
    );
}

/// §4 C2: the enricher's requests must REUSE a connection.
///
/// `ureq::get(...)` builds a throwaway agent per call, and in ureq
/// the agent is the connection pool, so every request reconnected
/// and re-did the TLS handshake. The enricher makes several requests
/// per title across thousands of titles, so this was a handshake per
/// lookup for nothing.
///
/// Counting ACCEPTED TCP connections is the direct evidence: three
/// requests to one host over a keep-alive server must open exactly
/// one. (Loopback is deliberately not in `is_forbidden_fetch_ip`,
/// which is what lets the guarded agent be tested at all.)
#[test]
fn the_shared_enrich_agent_reuses_one_connection() {
    use std::io::{BufRead, BufReader, Write};
    use std::sync::atomic::{AtomicUsize, Ordering};

    let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    let accepted = std::sync::Arc::new(AtomicUsize::new(0));
    let acc = accepted.clone();
    let done = std::sync::Arc::new(AtomicUsize::new(0));
    let d2 = done.clone();

    std::thread::spawn(move || {
        for stream in listener.incoming() {
            let Ok(mut stream) = stream else { break };
            acc.fetch_add(1, Ordering::SeqCst);
            let d = d2.clone();
            std::thread::spawn(move || {
                let peek = stream.try_clone().unwrap();
                let mut r = BufReader::new(peek);
                // Serve request after request on this ONE socket for
                // as long as the client keeps it open.
                loop {
                    let mut saw_request = false;
                    loop {
                        let mut line = String::new();
                        match r.read_line(&mut line) {
                            Ok(0) => return,
                            Ok(_) => {}
                            Err(_) => return,
                        }
                        if line.starts_with("GET ") {
                            saw_request = true;
                        }
                        if line == "\r\n" || line == "\n" {
                            break;
                        }
                    }
                    if !saw_request {
                        return;
                    }
                    let body = "ok";
                    let resp = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\
                         Connection: keep-alive\r\n\r\n{body}",
                        body.len()
                    );
                    if stream.write_all(resp.as_bytes()).is_err() {
                        return;
                    }
                    let _ = stream.flush();
                    d.fetch_add(1, Ordering::SeqCst);
                }
            });
        }
    });

    for i in 0..3 {
        // Fetched FRESH each time, exactly as every wall.rs call site
        // does (`shared_enrich_agent().get(...)`). Hoisting it into a
        // local would prove only that ureq pools within one agent -
        // true however this function is written - instead of that the
        // enricher's call sites share one.
        let resp = shared_enrich_agent()
            .get(&format!("http://127.0.0.1:{port}/x{i}"))
            .timeout(std::time::Duration::from_secs(5))
            .call()
            .unwrap_or_else(|e| panic!("request {i} failed: {e}"));
        // The body MUST be drained, or ureq cannot return the
        // connection to the pool and the next request opens a new one.
        let body = resp.into_string().unwrap();
        assert_eq!(body, "ok");
    }

    // Give the last handler a moment to finish writing.
    for _ in 0..50 {
        if done.load(Ordering::SeqCst) >= 3 {
            break;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    }
    assert_eq!(
        done.load(Ordering::SeqCst),
        3,
        "server should have served 3 requests"
    );
    assert_eq!(
        accepted.load(Ordering::SeqCst),
        1,
        "three requests opened {} connections - the agent is not pooling",
        accepted.load(Ordering::SeqCst)
    );
}

/// A crash between publish_over_previous's two renames used to leave
/// the superseded download under a pid-suffixed name that nothing in
/// the tree ever looked at again, with no canonical directory at all:
/// the job's history record pointed at a missing path, so the user's
/// previous download had vanished from everywhere the software looks.
#[test]
fn an_interrupted_replace_is_put_back_at_startup() {
    let root = std::env::temp_dir().join(format!(
        "nzbfast-replrec-{}-{}",
        std::process::id(),
        line!()
    ));
    let _ = std::fs::remove_dir_all(&root);
    let cat = root.join("tv");
    std::fs::create_dir_all(&cat).unwrap();

    // 1. The crash shape: aside exists, canonical is gone.
    let aside = cat.join(format!("Show.S01E01{REPLACED_SUFFIX}999"));
    std::fs::create_dir_all(&aside).unwrap();
    std::fs::write(aside.join("ep.mkv"), b"the user's episode").unwrap();

    // 2. Both present: ambiguous, must be left strictly alone.
    let keep_canon = cat.join("Other.S01E02");
    let keep_aside = cat.join(format!("Other.S01E02{REPLACED_SUFFIX}999"));
    std::fs::create_dir_all(&keep_canon).unwrap();
    std::fs::create_dir_all(&keep_aside).unwrap();
    std::fs::write(keep_canon.join("new.mkv"), b"new").unwrap();
    std::fs::write(keep_aside.join("old.mkv"), b"old").unwrap();

    // 3. An ordinary directory must not be touched.
    let normal = cat.join("Normal.S01E03");
    std::fs::create_dir_all(&normal).unwrap();

    // 4. Names that merely CONTAIN the suffix are the user's, not
    //    ours: an aside is always <name> + suffix + pid and nothing
    //    else, so a non-numeric tail, an empty tail and an empty stem
    //    are all somebody else's directory. Renaming one to its stem
    //    moves a folder of their media out from under them - and can
    //    collide with a real download of that name.
    let theirs: Vec<PathBuf> = vec![
        cat.join(format!("Movie{REPLACED_SUFFIX}Final")),
        cat.join(format!("Movie{REPLACED_SUFFIX}12ab")),
        cat.join(format!("Movie{REPLACED_SUFFIX}")),
        cat.join(format!("Movie{REPLACED_SUFFIX}999.part2")),
        cat.join(format!("{REPLACED_SUFFIX}999")), // no name in front of it
    ];
    for d in &theirs {
        std::fs::create_dir_all(d).unwrap();
        std::fs::write(d.join("theirs.mkv"), b"theirs").unwrap();
    }

    // 5. A canonical name that itself ends in a suffix-shaped string:
    //    the LAST occurrence is the parking one, so this must be put
    //    back under the whole leading name, not truncated at the
    //    first match.
    let nested = cat.join(format!("Odd{REPLACED_SUFFIX}1a{REPLACED_SUFFIX}777"));
    std::fs::create_dir_all(&nested).unwrap();
    std::fs::write(nested.join("odd.mkv"), b"odd").unwrap();

    recover_interrupted_publishes(&root);

    let restored = cat.join("Show.S01E01");
    assert!(
        restored.join("ep.mkv").exists(),
        "the only copy must be put back"
    );
    assert!(
        !aside.exists(),
        "the aside name should be gone once restored"
    );
    assert_eq!(
        std::fs::read(restored.join("ep.mkv")).unwrap(),
        b"the user's episode",
        "restored bytes must be the user's, untouched"
    );

    // Nothing deleted in the ambiguous case - guessing wrong there
    // would destroy a directory of somebody's media.
    assert!(keep_canon.join("new.mkv").exists(), "canonical left alone");
    assert!(keep_aside.join("old.mkv").exists(), "spare copy left alone");
    assert!(normal.exists(), "unrelated directories untouched");

    for d in &theirs {
        assert!(
            d.join("theirs.mkv").exists(),
            "{} is not one of our asides and must be left where it is",
            d.display()
        );
    }
    assert!(
        !cat.join("Movie").exists(),
        "a directory that merely contains the suffix was renamed over the user"
    );

    let nested_canon = cat.join(format!("Odd{REPLACED_SUFFIX}1a"));
    assert!(
        nested_canon.join("odd.mkv").exists(),
        "the aside must be split at the LAST suffix, not the first"
    );
    assert!(
        !cat.join("Odd").exists(),
        "split at the first suffix instead of the last"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// The MB in these APIs is 1048576 bytes, not 1000000. MEASURED on
/// the bench box against both reference clients: an NZB summing to
/// exactly 104857600 bytes reported as 100 by SABnzbd 5.0.4
/// (`mode=queue` -> "mb": "100.00") and by NZBGet (`listgroups` ->
/// FileSizeMB: 100 with FileSizeLo/Hi giving 104857600).
///
/// We divided by 1_000_000, so every size was 4.9% high - Sonarr
/// multiplies the field back by 1024*1024, which skewed both its
/// queue sizes and its free-space thresholds.
#[test]
fn api_megabytes_are_the_binary_ones_both_clients_use() {
    const PROBE: u64 = 104_857_600; // exactly 100 MiB, the NZB used
    assert_eq!(API_MB_U, 1_048_576);
    assert_eq!(API_MB, 1_048_576.0);
    assert_eq!(PROBE / API_MB_U, 100, "NZBGet reported 100 for these bytes");
    assert_eq!(
        format!("{:.2}", PROBE as f64 / API_MB),
        "100.00",
        "SAB reported \"100.00\" for these bytes"
    );

    // The NZBGet size triple has to agree with itself: Lo/Hi are the
    // exact bytes clients actually key on, and *SizeMB is derived.
    let m = size_fields("File", PROBE);
    let lo = m["FileSizeLo"].as_u64().unwrap();
    let hi = m["FileSizeHi"].as_u64().unwrap();
    assert_eq!(hi * (1 << 32) + lo, PROBE, "Lo/Hi must be the exact bytes");
    assert_eq!(m["FileSizeMB"].as_u64().unwrap(), 100);

    // And the old divisor must not creep back.
    assert_ne!(
        PROBE / 1_000_000,
        PROBE / API_MB_U,
        "104 vs 100 - the whole bug"
    );
}

/// Sonarr parses SAB's `timeleft` as a .NET TimeSpan, and the
/// `hh:mm:ss` form rejects hours above 23 - so an unbounded hours
/// field did not just misreport one job, it failed the whole
/// `mode=queue` payload and took every download's tracking with it.
/// Past a day the value has to carry a days component.
#[test]
fn sab_timeleft_never_emits_an_hours_field_dotnet_will_reject() {
    // Under a day: unchanged, bare hours.
    assert_eq!(sab_timeleft(0.0), "0:00:00");
    assert_eq!(sab_timeleft(59.4), "0:00:59");
    assert_eq!(sab_timeleft(3600.0), "1:00:00");
    assert_eq!(sab_timeleft(86_399.0), "23:59:59");

    // The regression: 500 GB on a 40 Mbit line. Was "27:46:12".
    assert_eq!(sab_timeleft(99_972.0), "1:03:46:12");

    // Exactly a day, and a long one.
    assert_eq!(sab_timeleft(86_400.0), "1:00:00:00");
    assert_eq!(sab_timeleft(1_000_000.0), "11:13:46:40");

    // Whatever we emit, the hours field is always parseable.
    for secs in [0.0, 1.0, 86_399.0, 86_400.0, 500_000.0, 9_999_999.0] {
        let out = sab_timeleft(secs);
        let hours: u64 = out.split(':').nth_back(2).unwrap().parse().unwrap();
        assert!(hours <= 23, "{out} has an hours field .NET will reject");
    }

    // Garbage in (a stalled or absurd rate) must not panic or emit
    // something unparseable.
    assert_eq!(sab_timeleft(f64::INFINITY), "0:00:00");
    assert_eq!(sab_timeleft(f64::NAN), "0:00:00");
    assert_eq!(sab_timeleft(-5.0), "0:00:00");
}
use serde_json::json;

/// The match arms of ONE dispatch function, read out of its own source.
///
/// There is no way to reflect over a `match`, and rewriting a hundred
/// hand-written validators into table rows would be a far bigger risk
/// than the drift it prevents - so the source IS the reflection. The
/// arms are string literals at a fixed indent inside one function, so
/// this is a two-line scan rather than a parser.
fn match_arms_of(src: &str, signature: &str) -> std::collections::BTreeSet<String> {
    // CR stripped because the splits below are byte-exact. A Windows
    // clone made before `.gitattributes` landed has this source in CRLF
    // (git's own core.autocrlf default), and `"\n}\n"` cannot match
    // "\r\n}\r\n" - so the guard failed with "no recognisable end"
    // rather than reporting drift, which is the one way a guard must
    // never fail. `.gitattributes` pins LF now; this keeps the scan
    // working in a checkout that predates it.
    let src = src.replace('\r', "");
    let body = src
        .split_once(signature)
        .unwrap_or_else(|| panic!("{signature} moved or was renamed"))
        .1
        .split_once("\n}\n")
        .unwrap_or_else(|| panic!("{signature} has no recognisable end"))
        .0;
    body.lines()
        .filter_map(|l| l.strip_prefix("        \""))
        .filter(|l| l.contains("=> {") || l.contains("=> (") || l.contains("=> set_"))
        .flat_map(|l| {
            // One arm can carry several names: `"a" | "b" => {`.
            l.split("=>")
                .next()
                .unwrap_or("")
                .split('|')
                .map(|n| n.trim().trim_matches('"').to_string())
                .filter(|n| !n.is_empty() && !n.contains(' '))
                .collect::<Vec<_>>()
        })
        .collect()
}

/// Every match arm in `apply_setting`, across BOTH halves of the table.
///
/// The dispatch outgrew the size gate's function ceiling and split at the
/// indexer block (TODO 106): names the first half does not know fall
/// through to `apply_setting_tail` in settings_apply.rs. Scanning only
/// settings.rs would silently see half the arms and report every name in
/// the other half as "declared but has no arm" - so both are scanned, and
/// the arm-count floor below is what catches it if a third half appears.
fn apply_setting_arms() -> std::collections::BTreeSet<String> {
    let mut arms = match_arms_of(
        include_str!("settings.rs"),
        "\npub(super) fn apply_setting(",
    );
    arms.extend(match_arms_of(
        include_str!("settings_apply.rs"),
        "\npub(super) fn apply_setting_tail(",
    ));
    arms
}

/// THE guard this whole table exists for.
///
/// Before it, the settings allowlist, the `apply_setting` match and
/// the `get_config` literal were three hand-maintained lists, and a
/// setting missing from one of them failed silently - no error, the
/// setting just did nothing. Now `get_config` and the log rules are
/// generated from the table, so only this last edge can drift: a new
/// `apply_setting` arm whose row nobody added (invisible in the UI
/// and unloggable), or a row whose arm nobody wrote (rejected at the
/// API with a "this is a bug" message).
#[test]
fn apply_arms_match_the_table() {
    let arms = apply_setting_arms();
    // The source scan cannot see cfg attributes, so in slim builds
    // subtract the indexer arms that are compiled out together with
    // their table rows.
    #[cfg(not(feature = "indexer"))]
    let arms: std::collections::BTreeSet<String> = {
        const INDEXER_ARMS: &[&str] = &[
            "index_db",
            "index_gates",
            "index_enabled",
            "spot_enabled",
            "index_interests",
            "index_evict_order",
            "index_evict_kinds",
            "predb_max_rows",
            "predb_seed_days",
        ];
        arms.into_iter()
            .filter(|a| !INDEXER_ARMS.contains(&a.as_str()))
            .collect()
    };
    assert!(
        arms.len() > 60,
        "the source scan found only {} arms - it has stopped matching \
         apply_setting's shape and is no longer guarding anything",
        arms.len()
    );
    let declared: std::collections::BTreeSet<String> = settings()
        .filter(|s| s.write == Write::Setting)
        .map(|s| s.name.to_string())
        .collect();
    let missing_row: Vec<_> = arms.difference(&declared).collect();
    assert!(
        missing_row.is_empty(),
        "apply_setting writes these, but they have no row in the settings \
         table - so get_config never shows them and the config log cannot \
         classify them: {missing_row:?}"
    );
    let missing_arm: Vec<_> = declared.difference(&arms).collect();
    assert!(
        missing_arm.is_empty(),
        "the settings table declares these as writable, but apply_setting \
         has no arm for them - setting one is rejected: {missing_arm:?}"
    );
}

/// The watcher deletes the user's .nzb once it has queued it, so
/// "looks complete" is the check standing between a half-copied file
/// and a release that is queued in fragments and then unrecoverable.
/// It must never say yes to a truncated file.
#[test]
fn a_truncated_nzb_never_looks_complete() {
    let whole = br#"<?xml version="1.0"?><nzb><file subject="x"></file></nzb>"#;
    assert!(nzb_looks_complete(whole));
    // Trailing whitespace is how most writers finish a file.
    assert!(nzb_looks_complete(b"<nzb></nzb>\n"));
    assert!(nzb_looks_complete(b"<nzb></nzb>\r\n  \t\n"));
    // Every prefix of a real nzb is what a copy in flight looks like,
    // and a half-written one still PARSES - which is the whole reason
    // this function exists rather than trusting the reader.
    for cut in 0..whole.len() {
        assert!(
            !nzb_looks_complete(&whole[..cut]),
            "a {cut}-byte prefix was accepted as a whole nzb"
        );
    }
    assert!(!nzb_looks_complete(b""));
    // The closing tag has to be at the END, not merely present.
    assert!(!nzb_looks_complete(b"<nzb></nzb><file>still writing"));
}

/// M7b.2 §5.7: the block-account flag survives a trip through the
/// server editor, and an OFF flag leaves no key behind.
///
/// The partial-object case is the one with teeth. `applyConns` - the
/// ladder's "Apply N to this server" button - posts only the fields it
/// knows about, and under an "absent means false" rule every per-server
/// boolean the user had set would be silently cleared by pressing it.
/// That is exactly how `pin_connections` behaved before this landed, so
/// it is asserted here alongside the new flag rather than trusted.
#[test]
fn per_server_booleans_survive_a_partial_save() {
    let stored = json!({
        "host": "news.example.com", "port": 563, "tls": true,
        "block_account": true, "pin_connections": true, "warm_pool": true,
    });
    // What applyConns sends: host, port, tls, connections, and nothing
    // about the checkboxes.
    let partial = json!({
        "host": "news.example.com", "port": 563, "tls": true, "connections": 12,
    });
    let out = normalized_server(Some(&stored), &partial).expect("host is set");
    assert_eq!(out["connections"], 12);
    for key in ["block_account", "pin_connections", "warm_pool"] {
        assert_eq!(
            out[key], true,
            "{key} was cleared by a save that never mentioned it"
        );
    }

    // The editor form always sends all three, so an explicit false is
    // still how a user turns one off - and it REMOVES the key rather
    // than writing false, because people read this file by hand.
    let cleared = json!({
        "host": "news.example.com", "port": 563, "tls": true,
        "block_account": false, "pin_connections": false, "warm_pool": false,
    });
    let out = normalized_server(Some(&stored), &cleared).expect("host is set");
    for key in ["block_account", "pin_connections", "warm_pool"] {
        assert!(out.get(key).is_none(), "{key}: off must write no key");
    }

    // And it is independent of the tier and of the block size: a
    // level-0 server with no block can still be billed per byte.
    let fresh = json!({
        "host": "news.example.com", "port": 563, "tls": true, "block_account": true,
    });
    let out = normalized_server(None, &fresh).expect("host is set");
    assert_eq!(out["block_account"], true);
    assert!(out.get("level").is_none());
    assert!(out.get("block_bytes").is_none());
    // Round-trips back through the config parser as the flag it was.
    let parsed: nzbkit::config::ServerConfig = serde_json::from_value(out).unwrap();
    assert!(parsed.block_account);
    assert_eq!(parsed.level, 0);
    assert!(!parsed.may_spend_on_measurement());
}

/// Sub-second resolution is load-bearing now that a pass can follow
/// another by 250 ms: at one-second granularity two samples that close
/// together are identical by construction, so "unchanged since I last
/// looked" would be true of a copy that is still running.
#[test]
fn watch_signature_has_sub_second_resolution() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sig-ms-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let f = dir.join("a.nzb");
    std::fs::write(&f, b"<nzb>").unwrap();
    let a = watch_sig(&f).unwrap();
    // A value in seconds would be ~1.7e9; in milliseconds ~1.7e12.
    assert!(a.0 > 1_000_000_000_000, "mtime {} is not milliseconds", a.0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Names are the persisted keys in settings.json. A duplicate row
/// would make `setting()` resolve to whichever came first, and two
/// rows exposing the same name would silently drop one value.
#[test]
fn setting_names_are_unique() {
    let mut seen = std::collections::BTreeSet::new();
    for s in settings() {
        assert!(seen.insert(s.name), "duplicate settings row: {}", s.name);
    }
}

/// Credentials must never reach the log, whatever else changes about
/// how the table is built.
#[test]
fn credentials_are_never_logged() {
    for name in ["apikey", "nzbkey", "omdb_key"] {
        assert_eq!(log_value(name, "hunter2"), "•••");
    }
    assert!(!log_value("notify_targets", r#"[{"kind":"plex","url":"tok"}]"#).contains("tok"));
    assert!(!log_value("feeds", r#"[{"url":"x?apikey=tok"}]"#).contains("tok"));
    assert!(
        !log_value(
            "indexers",
            r#"[{"name":"g","url":"https://x","apikey":"tok"}]"#
        )
        .contains("tok")
    );
    // A name with no row at all is shape-only, not verbatim.
    assert_eq!(
        log_value("brand_new_secret", "hunter2"),
        "(7 chars, not logged)"
    );
}

/// The tray cannot link against this binary, so it greps daemon.log
/// for KEYLESS_MARKER to tell "deliberately refused to start" from
/// "crashed" - and shows the user completely different advice for
/// each. If the two copies of the string ever drift, the tray
/// silently falls back to "stopped unexpectedly, try Restart", which
/// is the exact wrong answer: restarting fails identically forever.
/// Keep this in step with crates/nzbtray/src/main.rs.
#[test]
fn keyless_marker_matches_the_trays_copy() {
    const TRAY_COPY: &str = "nzbfast cannot start: API key file";
    assert_eq!(
        KEYLESS_MARKER, TRAY_COPY,
        "nzbtray greps for this exact string; update both or the tray \
         shows the wrong advice"
    );
    // And the message a user sees must actually begin with it, or the
    // tray's find() lands mid-sentence and prints a fragment.
    let msg = keyless_help(std::path::Path::new("C:\\x\\apikey"), "is empty");
    assert!(
        msg.starts_with(KEYLESS_MARKER),
        "message must lead with the marker: {msg}"
    );
    // The three remedies are the whole point of the rewrite.
    for needle in [
        "Sonarr",
        "DELETE the file",
        "NZBFAST_OPEN=1",
        "C:\\x\\apikey",
    ] {
        assert!(msg.contains(needle), "missing {needle} from:\n{msg}");
    }
}

#[cfg(feature = "indexer")]
#[test]
fn live_tip_policy_applies_custom_categories_to_gate_and_ingest() {
    let db = std::env::temp_dir().join(format!(
        "nzbfast-tip-custom-{}-{}.db",
        std::process::id(),
        epoch_secs()
    ));
    let _ = std::fs::remove_file(&db);
    let cats = vec![nzbkit::categories::CustomCategory {
        slug: "formula-1".into(),
        name: "Formula 1".into(),
        pattern: r"^formula\.?1\.".into(),
        not_match: String::new(),
        base: nzbkit::categories::BaseBehavior::Movie,
    }];
    let gates = crate::gates::Gates::from_json(r#"{"kinds":["formula-1"]}"#).unwrap();
    let mut ix = nzbkit::index::Index::open(&db).unwrap();
    install_live_ingest_policy(&mut ix, Some(gates), cats);
    let stem = "Formula1.2026.Round11.Hungary.Qualifying.F1TV.1080p";
    let entry = nzbkit::nntp::OverEntry {
        number: 1,
        subject: format!(r#""{stem}.mkv" yEnc (1/1)"#),
        from: "poster".into(),
        message_id: "<tip-custom@test>".into(),
        bytes: 1024,
        date: 1_700_000_000,
    };
    assert_eq!(
        ix.ingest("alt.binaries.formula1", &[entry], 1_700_000_001)
            .unwrap(),
        1
    );
    let q = nzbkit::index::BrowseQuery {
        kind: Some("formula-1".into()),
        limit: 10,
        ..Default::default()
    };
    let (rows, _) = ix.browse(&q).unwrap();
    assert_eq!(rows.len(), 1);
    assert_eq!(rows[0].kind, "formula-1");
    drop(ix);
    let _ = std::fs::remove_file(&db);
    let _ = std::fs::remove_file(db.with_extension("db-wal"));
    let _ = std::fs::remove_file(db.with_extension("db-shm"));
}

/// The 7 Aug incident's product half, pinned: with a global
/// move_completed set, a finished job whose directory sits OUTSIDE the
/// configured out-root (the live shape - the settings out-root named one
/// folder, the jobs landed in its parent) still gets its move ATTEMPTED,
/// and the outcome comes back as data rather than only a log line.
#[test]
fn relocate_attempts_the_move_for_an_out_of_root_job() {
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-reloc-attempt-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    *d.move_completed.write_ok() = Some(dir.join("nas"));
    // The job's folder is NOT under d.out_dir() - strip_prefix fails and
    // the category fallback (empty cat, the watch-folder default) must
    // still produce a destination rather than an early return.
    let job_dir = dir.join("elsewhere").join("Some.Release");
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), b"bytes").unwrap();

    let (moved, split, failed) = d.relocate_completed(&job_dir, "", None);
    assert_eq!(failed, None, "a movable job must not report a failure");
    assert_eq!(split, None);
    let dest = dir.join("nas").join("Some.Release");
    assert_eq!(moved.as_deref(), Some(dest.as_path()));
    assert!(
        dest.join("payload.bin").exists(),
        "the payload must actually move"
    );
    assert!(!job_dir.exists() || std::fs::read_dir(&job_dir).unwrap().next().is_none());
    let _ = std::fs::remove_dir_all(&dir);
}

/// A move that fails outright must say so IN THE RETURN, not only in a
/// log line - the log died once (7 Aug) and five finished jobs sat in
/// the download folder looking exactly like moved ones.
#[cfg(unix)]
#[test]
fn relocate_reports_a_nothing_moved_failure_as_data() {
    use crate::serve::testutil::test_daemon;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("nzbfast-reloc-fail-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    std::fs::create_dir_all(&nas).unwrap();
    *d.move_completed.write_ok() = Some(nas.clone());
    let job_dir = dir.join("elsewhere").join("Some.Release");
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), b"bytes").unwrap();
    // An unwritable destination root stands in for the live failure (a
    // network volume the OS denies).
    std::fs::set_permissions(&nas, std::fs::Permissions::from_mode(0o555)).unwrap();

    let (moved, split, failed) = d.relocate_completed(&job_dir, "", None);
    std::fs::set_permissions(&nas, std::fs::Permissions::from_mode(0o755)).unwrap();
    assert_eq!(moved, None);
    assert_eq!(split, None);
    let why = failed.expect("a nothing-moved failure must come back as data");
    assert!(
        why.contains(&*nas.join("Some.Release").to_string_lossy()),
        "the failure must name the destination: {why}"
    );
    assert!(
        job_dir.join("payload.bin").exists(),
        "nothing moved - the payload must be whole at the source"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// The move-retry ladder climbs and then stops. A destination volume
/// that was not mounted (8 Aug 2026) had one Completed job log the
/// identical EACCES every 20 minutes for 15 hours, because each failure
/// re-armed a FLAT cooldown with nothing counting the attempts.
#[test]
fn a_move_that_keeps_failing_backs_off_and_finally_gives_up() {
    use crate::serve::job::{MOVE_RETRY_GIVE_UP, MOVE_RETRY_MAX_SECS, move_retry_delay};

    const BASE: u64 = 1200; // the default 20 minutes
    // First retry waits the plain base, then it doubles.
    assert_eq!(move_retry_delay(BASE, 1), BASE);
    assert_eq!(move_retry_delay(BASE, 2), 2 * BASE);
    assert_eq!(move_retry_delay(BASE, 3), 4 * BASE);
    // ...to a ceiling, so a destination that is simply gone stops
    // filling the log rather than costing a probe every 20 minutes.
    assert_eq!(move_retry_delay(BASE, 30), MOVE_RETRY_MAX_SECS);
    // A base longer than the ceiling is the user's own choice and is
    // never shortened to it.
    let week = 7 * 24 * 3600;
    assert_eq!(move_retry_delay(week, 1), week);
    assert!(move_retry_delay(week, 9) >= week);
    // The shift cannot overflow however many attempts have failed.
    assert!(move_retry_delay(u64::MAX, u32::MAX) > 0);

    // And the ladder is finite: total time tried is about a day, not
    // forever.
    let total: u64 = (1..MOVE_RETRY_GIVE_UP)
        .map(|n| move_retry_delay(BASE, n))
        .sum();
    assert!(
        (12 * 3600..48 * 3600).contains(&total),
        "give-up should land inside a day or so, got {total}s"
    );
}

/// The counter drives arming: the daemon stops re-arming at the give-up
/// count and leaves the record amber for a human, and the drawer's own
/// button restarts the whole ladder.
#[tokio::test(flavor = "multi_thread")]
async fn the_move_ladder_stops_and_a_manual_retry_restarts_it() {
    use crate::serve::job::{JobState, MOVE_RETRY_GIVE_UP, job_from_json};
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-moveladder-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    d.auto_retry_secs.store(1200, Ordering::Relaxed);
    let mut j = job_from_json(&json!({
        "nzo_id": "SABnzbd_nzo_ladder",
        "name": "Some.Release",
        "nzb_path": dir.join("some.nzb").to_string_lossy(),
        "out_dir": dir.join("elsewhere").to_string_lossy(),
        "state": "Completed",
        "category": "",
        "move_failed": "/Volumes/TV/Downloaded/Some.Release: Permission denied (os error 13)",
    }))
    .unwrap();
    assert_eq!(j.state, JobState::Completed);

    // Every failure up to the give-up count arms a longer cooldown.
    let mut last = 0u64;
    for n in 1..MOVE_RETRY_GIVE_UP {
        d.settle_move_attempt(&mut j);
        assert_eq!(j.move_attempts, n);
        let at = j.auto_retry_at.expect("a retry is still owed");
        assert_eq!(j.auto_retry_why.as_deref(), Some("move"));
        // Non-decreasing, not strictly increasing: the ladder is capped
        // at MOVE_RETRY_MAX_SECS and the top rungs are deliberately the
        // same length.
        assert!(
            at >= last,
            "attempt {n} must not wait less than the one before"
        );
        last = at;
    }
    // The one that reaches the count arms nothing.
    d.settle_move_attempt(&mut j);
    assert_eq!(j.move_attempts, MOVE_RETRY_GIVE_UP);
    assert!(
        j.auto_retry_at.is_none(),
        "the ladder must end rather than retry an unreachable destination forever"
    );
    // ...but the payload is still reported, so the row stays amber and
    // the drawer keeps naming the destination and the error.
    assert!(!j.move_failed.is_empty());

    // A landed move clears the count and the stamp together.
    j.auto_retry_at = Some(1);
    j.auto_retry_why = Some("move".into());
    j.move_failed.clear();
    d.settle_move_attempt(&mut j);
    assert_eq!(j.move_attempts, 0);
    assert!(j.auto_retry_at.is_none());

    // The drawer button forgets the spent budget, so a job the daemon
    // had given up on becomes automatic again once the user has fixed
    // whatever was wrong.
    j.move_failed = "/Volumes/TV/Downloaded/Some.Release: Permission denied".into();
    j.move_attempts = MOVE_RETRY_GIVE_UP;
    let job = Arc::new(Mutex::new(j));
    d.history.lock_ok().push(job.clone());
    // No destination is configured on this daemon, so the redrive
    // itself is a no-op - the reset is what this asserts.
    d.retry_move_now("SABnzbd_nzo_ladder");
    assert_eq!(job.lock_ok().move_attempts, 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// The whole reported path, through the real mover: a `move_completed`
/// on a volume that is not mounted records a failure that SAYS it is
/// not mounted, and arms exactly one backed-off retry rather than the
/// flat forever-loop.
///
/// `/Volumes` is owned by root on every Mac, so a destination under an
/// absent volume is refused with EACCES by any user - which is what
/// makes this reproducible without a NAS and without privileges.
#[cfg(target_os = "macos")]
#[test]
fn a_move_to_an_unmounted_volume_explains_itself_and_arms_one_retry() {
    use crate::serve::job::{JobState, job_from_json};
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-unmounted-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    // Nothing has ever been mounted here, and nothing can create it.
    let absent = std::path::PathBuf::from(format!(
        "/Volumes/NzbfastNotMounted-{}/Downloaded",
        std::process::id()
    ));
    assert!(!absent.exists(), "the test needs a genuinely absent volume");
    *d.move_completed.write_ok() = Some(absent.clone());
    d.auto_retry_secs.store(1200, Ordering::Relaxed);

    let job_dir = d.out_dir().join("Some.Release");
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), b"bytes").unwrap();

    let (moved, split, failed) = d.relocate_completed(&job_dir, "", None);
    assert!(
        split.is_none(),
        "nothing can have moved to a missing volume"
    );
    // `None` is "the job's directory did not change" - the payload
    // stays exactly where it was, which is the whole point.
    assert!(moved.is_none(), "nothing moved, so nothing was re-pointed");
    let failed = failed.expect("an unreachable destination must be recorded");
    assert!(
        failed.contains("not mounted"),
        "the record has to explain the EACCES, got: {failed}"
    );
    assert!(
        job_dir.join("payload.bin").exists(),
        "the payload is untouched"
    );

    // ...and the ladder starts at its first rung, once.
    let mut j = job_from_json(&json!({
        "nzo_id": "SABnzbd_nzo_unmounted",
        "name": "Some.Release",
        "nzb_path": dir.join("some.nzb").to_string_lossy(),
        "out_dir": job_dir.to_string_lossy(),
        "state": "Completed",
        "category": "",
    }))
    .unwrap();
    assert_eq!(j.state, JobState::Completed);
    j.move_failed = failed;
    d.settle_move_attempt(&mut j);
    assert_eq!(j.move_attempts, 1);
    assert_eq!(j.auto_retry_why.as_deref(), Some("move"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// An absent mount answers EACCES, not ENOENT, because the component
/// that cannot be created lives inside root-owned `/Volumes` - so the
/// daemon has to say what the OS error will not.
#[cfg(target_os = "macos")]
#[test]
fn an_unmounted_destination_says_so_instead_of_permission_denied() {
    use std::path::Path;

    let hint = Daemon::unreachable_dest_hint(Path::new(
        "/Volumes/DefinitelyNotMounted/Downloaded/Some.Release",
    ))
    .expect("a missing volume is worth explaining");
    assert!(hint.contains("/Volumes/DefinitelyNotMounted"));
    assert!(hint.contains("not mounted"), "got {hint}");
    // A leaf that does not exist yet is the ORDINARY case - the mover
    // creates it - so it earns no hint.
    let tmp = std::env::temp_dir();
    assert!(Daemon::unreachable_dest_hint(&tmp.join("nzbfast-absent-leaf")).is_none());
    // A missing folder that is not a mount point is still named, just
    // without the volume guess.
    let deep = Daemon::unreachable_dest_hint(&tmp.join("nzbfast-absent/a/b/c"))
        .expect("a missing parent is worth naming");
    assert!(deep.contains("nzbfast-absent"));
    assert!(!deep.contains("not mounted"), "got {deep}");
}

/// redrive_move: the M32 cooldown's move half. A parked Completed job
/// with move_failed set gets its move re-attempted (files only), and a
/// success clears the amber and re-points the record.
#[tokio::test(flavor = "multi_thread")]
async fn redrive_move_retries_the_move_and_clears_the_marker() {
    use crate::serve::job::{JobState, job_from_json};
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-redrive-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    let job_dir = dir.join("elsewhere").join("Some.Release");
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), b"bytes").unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_redrive",
            "name": "Some.Release",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": job_dir.to_string_lossy(),
            "state": "Completed",
            "category": "",
            "move_failed": "/nas/Some.Release: Permission denied (os error 13)",
        }))
        .unwrap(),
    ));
    assert_eq!(job.lock_ok().state, JobState::Completed);
    d.history.lock_ok().push(job.clone());

    assert!(d.redrive_move("SABnzbd_nzo_redrive"));
    // The move runs on the blocking pool; wait for it to settle.
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(10);
    loop {
        {
            let g = job.lock_ok();
            if g.move_failed.is_empty() && g.out_dir != job_dir {
                break;
            }
        }
        assert!(
            std::time::Instant::now() < deadline,
            "redrive did not settle"
        );
        tokio::time::sleep(std::time::Duration::from_millis(20)).await;
    }
    let g = job.lock_ok();
    assert_eq!(g.out_dir, nas.join("Some.Release"));
    assert!(g.out_dir.join("payload.bin").exists());
    assert!(
        g.auto_retry_at.is_none(),
        "a landed move leaves no cooldown armed"
    );
    drop(g);
    // The fence is down again: a second call declines (nothing failed).
    assert!(!d.redrive_move("SABnzbd_nzo_redrive"));
    let _ = std::fs::remove_dir_all(&dir);
}

/// B (7 Aug): setting move_completed must prove the daemon can WRITE
/// there, with a real marker write - access(2) said yes while the OS
/// denied every actual write, so the bad setting was accepted and
/// failed 78 GB later, one finished job at a time.
#[cfg(unix)]
#[test]
fn setting_move_completed_probes_with_a_real_write() {
    use crate::serve::testutil::test_daemon;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("nzbfast-moveprobe-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    std::fs::create_dir_all(&nas).unwrap();
    std::fs::set_permissions(&nas, std::fs::Permissions::from_mode(0o555)).unwrap();
    let v = apply_setting(&d, "move_completed", &nas.to_string_lossy());
    std::fs::set_permissions(&nas, std::fs::Permissions::from_mode(0o755)).unwrap();
    let e = v.expect_err("an unwritable destination must be refused");
    assert!(e.contains("test write"), "{e}");
    assert!(
        d.move_completed.read_ok().is_none(),
        "the bad value must not stick"
    );
    // And the probe leaves no droppings on success.
    apply_setting(&d, "move_completed", &nas.to_string_lossy()).unwrap();
    assert_eq!(std::fs::read_dir(&nas).unwrap().count(), 0);
    let _ = std::fs::remove_dir_all(&dir);
}

/// C: one mover step. A parked Completed job with `move_pending` gets
/// its relocation attempted; success clears the marker and re-points
/// the record, and the fence never survives the step.
#[tokio::test(flavor = "multi_thread")]
async fn mover_process_moves_a_pending_job_and_clears_the_marker() {
    use crate::serve::job::{JobState, job_from_json};
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-moverstep-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    let job_dir = dir.join("out").join("Some.Release");
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), b"bytes").unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_moverstep",
            "name": "Some.Release",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": job_dir.to_string_lossy(),
            "state": "Completed",
            "category": "",
            "move_pending": true,
        }))
        .unwrap(),
    ));
    assert_eq!(job.lock_ok().state, JobState::Completed);
    d.history.lock_ok().push(job.clone());

    let requeue = tokio::task::spawn_blocking({
        let d = d.clone();
        let job = job.clone();
        move || d.mover_process(&job)
    })
    .await
    .unwrap();
    assert!(!requeue);
    let g = job.lock_ok();
    assert!(!g.move_pending, "a settled move leaves no pending marker");
    assert_eq!(g.move_failed, "");
    assert_eq!(g.out_dir, nas.join("Some.Release"));
    assert!(g.out_dir.join("payload.bin").exists());
    drop(g);
    assert!(
        !d.moving.lock_ok().contains("SABnzbd_nzo_moverstep"),
        "the fence must come down with the step"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// C: the mover step's record has to follow the bytes even when the
/// store refuses the line (Codex sweep 7, M5 follow-up).
///
/// `mover_process` is the sharpest of the callers that dropped
/// `history_upsert_if_present`'s answer: it publishes the payload's NEW
/// folder. A refused append left the store holding the old one, so the
/// next start replayed a row pointing at an emptied directory while the
/// files sat somewhere else - and every later delete, retry, play and
/// *arr import followed the row. The store here is 0444 with a writable
/// spool beside it, which is exactly the shape that made the failure
/// invisible: the append needs the FILE, the rewrite that stands in for
/// it needs only the DIRECTORY.
#[cfg(unix)]
#[tokio::test(flavor = "multi_thread")]
async fn a_move_survives_a_store_that_refuses_the_append() {
    use crate::serve::job::job_from_json;
    use crate::serve::testutil::test_daemon;
    use std::os::unix::fs::PermissionsExt;

    let dir = std::env::temp_dir().join(format!("nzbfast-moverstore-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let nas = dir.join("nas");
    *d.move_completed.write_ok() = Some(nas.clone());
    let job_dir = dir.join("out").join("Some.Release");
    std::fs::create_dir_all(&job_dir).unwrap();
    std::fs::write(job_dir.join("payload.bin"), b"bytes").unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_moverstore",
            "name": "Some.Release",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": job_dir.to_string_lossy(),
            "state": "Completed",
            "category": "",
            "move_pending": true,
        }))
        .unwrap(),
    ));
    d.history.lock_ok().push(job.clone());
    assert!(d.history_upsert(std::slice::from_ref(&job)));

    let store = d.history_store_path();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o444)).unwrap();
    let requeue = tokio::task::spawn_blocking({
        let d = d.clone();
        let job = job.clone();
        move || d.mover_process(&job)
    })
    .await
    .unwrap();
    std::fs::set_permissions(&store, std::fs::Permissions::from_mode(0o644)).unwrap();

    assert!(!requeue);
    assert_eq!(
        job.lock_ok().out_dir,
        nas.join("Some.Release"),
        "precondition: the move itself has to have landed"
    );
    let (rows, _) = d.history_replay();
    assert_eq!(
        rows.iter()
            .find(|j| j.nzo_id == "SABnzbd_nzo_moverstore")
            .map(|j| j.out_dir.clone()),
        Some(nas.join("Some.Release")),
        "the restart would send every later delete, retry and import to \
         the folder the payload has left"
    );
    let _ = std::fs::remove_dir_all(&dir);
}

/// C: the mover's byte budget - three modes, one setting.
#[test]
fn mover_budget_follows_the_mode() {
    use crate::serve::testutil::test_daemon;
    let dir = std::env::temp_dir().join(format!("nzbfast-pace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    // Default: yield. Idle queue = no cap; an active download carves
    // out the line minus the wire minus a 10% margin, floored.
    assert_eq!(d.mover_budget_bps(0), None, "idle queue must be uncapped");
    d.line_speed.store(100_000_000, Ordering::Relaxed);
    assert_eq!(d.mover_budget_bps(60_000_000), Some(30_000_000));
    assert_eq!(
        d.mover_budget_bps(95_000_000),
        Some(5_000_000),
        "the floor keeps a saturated line from starving the move to zero"
    );
    *d.move_pace.lock_ok() = "80".to_string();
    assert_eq!(d.mover_budget_bps(60_000_000), Some(80_000_000));
    *d.move_pace.lock_ok() = "full".to_string();
    assert_eq!(d.mover_budget_bps(60_000_000), None);
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 10 Aug L1: a custom key like `a&b` authenticated direct
/// calls but broke every URL the daemon generated with it, and `/watch`
/// silently dropped other punctuation. Creation refuses the charset,
/// and the generated-link boundaries encode whatever key they carry.
#[test]
fn custom_keys_are_charset_checked_and_links_encode_them() {
    use settings::key_charset_ok;
    assert!(key_charset_ok("abc123DEF-_"));
    assert!(key_charset_ok("")); // clearing stays allowed
    for bad in ["a&b", "a b", "a+b", "k%00", "k#f", "café", "a/b", "a?b"] {
        assert!(!key_charset_ok(bad), "must refuse {bad:?}");
    }
    // Boundary encoding: hex keys unchanged, punctuation percent-coded.
    assert_eq!(http::query_escape("0123abcdef"), "0123abcdef");
    assert_eq!(http::query_escape("a&b c+d"), "a%26b%20c%2Bd");
    assert_eq!(http::query_escape("k%00#"), "k%2500%23");
}

/// Codex sweep 10 Aug M14, half 1: the single-flight latch. Two tabs
/// (or a manual run beside the schedule) must not run the benchmark
/// workload concurrently; the second claim fails until the first
/// guard drops - and a panic mid-run still releases it.
#[test]
fn system_benchmarks_are_single_flight() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sysbench-single-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = crate::serve::testutil::test_daemon(&dir);
    let first = d.bench_begin().expect("idle latch must claim");
    assert!(d.bench_begin().is_none(), "second claim while running");
    drop(first);
    let again = d.bench_begin().expect("released latch must claim");
    drop(again);
    // Panic safety: a workload that dies must not wedge the latch.
    let d2 = d.clone();
    let _ = std::panic::catch_unwind(std::panic::AssertUnwindSafe(move || {
        let _running = d2.bench_begin().expect("claims before the panic");
        panic!("workload died");
    }));
    assert!(d.bench_begin().is_some(), "a panic must release the latch");
    let _ = std::fs::remove_dir_all(&dir);
}

/// Codex sweep 10 Aug M14, half 2: the history append is a
/// load-modify-write, and unlocked, two concurrent appends both read
/// the same file and one overwrote the other's row. Under the lock
/// every row survives.
#[test]
fn concurrent_bench_appends_lose_no_rows() {
    let dir = std::env::temp_dir().join(format!("nzbfast-sysbench-append-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = crate::serve::testutil::test_daemon(&dir);
    std::fs::create_dir_all(d.bench_history_path().parent().unwrap()).unwrap();
    let threads: Vec<_> = (0..8)
        .map(|t| {
            let d = d.clone();
            std::thread::spawn(move || {
                for i in 0..25 {
                    d.bench_append(json!({"ts": t * 1000 + i, "source": "test"}));
                }
            })
        })
        .collect();
    for t in threads {
        t.join().unwrap();
    }
    assert_eq!(d.bench_history().len(), 200, "every appended row survives");
    let _ = std::fs::remove_dir_all(&dir);
}

/// §96 (AltMount audit, item 2): a Completed history row whose output
/// folder the user has since deleted presents as Failed - the *arr's
/// import loop against a path that is not there ends in its
/// failed-download handling instead. The guard is the §154 half: the
/// flip fires only while the PARENT directory still exists, so an
/// unmounted NAS (parent gone too) keeps every row Completed and no
/// healthy release is mass-blocklisted. Render-time only - the store
/// keeps Completed throughout, so a restored folder restores the row.
#[test]
fn a_completed_row_with_a_deleted_folder_presents_failed_unless_the_volume_is_down() {
    use crate::serve::job::job_from_json;
    use crate::serve::testutil::test_daemon;
    let dir = std::env::temp_dir().join(format!("nzbfast-histgone-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let vol = dir.join("vol");
    let out = vol.join("Some.Job");
    std::fs::create_dir_all(&out).unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_histgone",
            "name": "Some.Job",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Completed",
            // Load-bearing: the flip is for jobs NOBODY imports. The
            // *arr-grabbed shape is the sibling test below.
            "origin": "dashboard",
        }))
        .unwrap(),
    ));
    d.history.lock_ok().push(job.clone());
    let facade_row = |d: &Daemon| {
        history_json(d, &std::collections::HashMap::new())["history"]["slots"][0].clone()
    };
    let summary_row = |d: &Daemon| {
        let q = HistQuery {
            failed_only: false,
            category: None,
            ids: None,
            search: None,
            bucket: None,
            start: 0,
            limit: 0,
        };
        history_page(d, &q, true).0[0].clone()
    };

    // Folder present: the row is what the store says.
    let r = facade_row(&d);
    assert_eq!(r["status"], "Completed", "{r}");
    assert_eq!(r["fail_message"], "", "{r}");

    // Folder deleted, volume present: Failed, with the remedy tokens the
    // drawer needs - `deleted`'s own hint (local's generic guidance
    // points at a folder that is gone) and a genuine retry.
    std::fs::remove_dir_all(&out).unwrap();
    let r = facade_row(&d);
    assert_eq!(r["status"], "Failed", "{r}");
    assert!(
        r["fail_message"]
            .as_str()
            .unwrap()
            .starts_with("the downloaded files are no longer on disk"),
        "{r}"
    );
    assert_eq!(r["fail_kind"], "local", "{r}");
    assert_eq!(r["fail_hint"], "deleted", "{r}");
    assert_eq!(r["fail_action"], "retry", "{r}");
    assert_eq!(r["retry"], true, "{r}");
    // The compact dashboard row flips with it - one record, one story.
    let s = summary_row(&d);
    assert_eq!(s["status"], "Failed", "{s}");
    assert_eq!(s["fail_action"], "retry", "{s}");

    // Mid-move the directory is legitimately absent: no flip.
    job.lock_ok().move_pending = true;
    let r = facade_row(&d);
    assert_eq!(r["status"], "Completed", "{r}");
    job.lock_ok().move_pending = false;

    // Volume down (the parent is gone too, the unmounted-NAS shape):
    // the guard stands down and the row stays Completed.
    std::fs::remove_dir_all(&vol).unwrap();
    let r = facade_row(&d);
    assert_eq!(r["status"], "Completed", "{r}");
    assert_eq!(r["fail_message"], "", "{r}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// ...and an *arr-grabbed job in that same shape stays Completed, because
/// for that job the shape IS success.
///
/// Sonarr/Radarr import the payload and then remove the leftover download
/// folder, leaving the completed-downloads root in place - the exact five
/// conditions `storage_deleted` tested for. So every imported row read
/// "Failed: the downloaded files are no longer on disk", which is both
/// false and, by the flip's own stated purpose, an instruction to the
/// *arr to grab another release. No filesystem evidence separates that
/// from a folder deleted before import, so the *arr owns the question.
/// Both origin spellings answer yes: the bare `arr` fallback and the
/// `arr:<client>` shape `api_origin` writes off the User-Agent.
#[test]
fn an_arr_grabbed_row_stays_completed_when_the_arr_cleaned_up_its_folder() {
    use crate::serve::job::job_from_json;
    use crate::serve::testutil::test_daemon;
    let dir = std::env::temp_dir().join(format!("nzbfast-histarr-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let vol = dir.join("complete");
    let out = vol.join("Some.Show.S01E01");
    std::fs::create_dir_all(&out).unwrap();
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_histarr",
            "name": "Some.Show.S01E01",
            "nzb_path": dir.join("some.nzb").to_string_lossy(),
            "out_dir": out.to_string_lossy(),
            "state": "Completed",
            "origin": "arr:sonarr",
        }))
        .unwrap(),
    ));
    d.history.lock_ok().push(job.clone());
    let facade_row = |d: &Daemon| {
        history_json(d, &std::collections::HashMap::new())["history"]["slots"][0].clone()
    };
    let summary_row = |d: &Daemon| {
        let q = HistQuery {
            failed_only: false,
            category: None,
            ids: None,
            search: None,
            bucket: None,
            start: 0,
            limit: 0,
        };
        history_page(d, &q, true).0[0].clone()
    };

    // The *arr has imported and cleaned up: folder gone, parent present.
    std::fs::remove_dir_all(&out).unwrap();
    for origin in ["arr:sonarr", "arr", "arr:nzb360"] {
        job.lock_ok().origin = origin.to_string();
        let r = facade_row(&d);
        assert_eq!(r["status"], "Completed", "{origin}: {r}");
        assert_eq!(r["fail_message"], "", "{origin}: {r}");
        assert_eq!(r["fail_kind"], "", "{origin}: {r}");
        assert_eq!(r["fail_hint"], "", "{origin}: {r}");
        // The compact dashboard row agrees - one record, one story.
        let s = summary_row(&d);
        assert_eq!(s["status"], "Completed", "{origin}: {s}");
        assert_eq!(s["fail_message"], "", "{origin}: {s}");
    }

    // ...and the row now AGREES with the history card's chips, which are
    // computed off `j.state` and so always counted this record as done.
    // The flip left the two telling different stories about one record:
    // a red Failed row sitting inside a "Completed" chip count.
    let counts = history_json(&d, &std::collections::HashMap::new())["history"]["counts"].clone();
    assert_eq!(counts["done"], 1, "{counts}");
    assert_eq!(counts["failed"], 0, "{counts}");
    assert_eq!(counts["clearable"], 1, "{counts}");

    // A near-miss origin is NOT an *arr - the prefix test is exact, so a
    // user category or a future origin word starting "arr" cannot mute
    // the flip by accident.
    job.lock_ok().origin = "arrival".into();
    let r = facade_row(&d);
    assert_eq!(r["status"], "Failed", "{r}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// U8: the compact history row draws the disk-space state for a `space`
/// failure without opening the drawer, so the summary shape must carry
/// the same verdict and space figure the full record does - and the
/// figure must be the RETRY's need (payload, doubled for an encrypted
/// set), not the set size, or the row lights Retry a payload too early.
#[test]
fn summary_row_carries_the_disk_full_verdict_and_space_figure() {
    use crate::serve::job::job_from_json;
    use crate::serve::testutil::test_daemon;
    let dir = std::env::temp_dir().join(format!("nzbfast-histspace-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    let job = Arc::new(Mutex::new(
        job_from_json(&json!({
            "nzo_id": "SABnzbd_nzo_histspace",
            "name": "Big.Set",
            "nzb_path": dir.join("big.nzb").to_string_lossy(),
            "out_dir": dir.join("Big.Set").to_string_lossy(),
            "state": "Failed",
            "fail_message": "could not write the download: disk full",
            "total_bytes": 5_000_000_000u64,
            "archive_shape": "rar encrypted",
        }))
        .unwrap(),
    ));
    d.history.lock_ok().push(job.clone());
    let summary_row = |d: &Daemon| {
        let q = HistQuery {
            failed_only: false,
            category: None,
            ids: None,
            search: None,
            bucket: None,
            start: 0,
            limit: 0,
        };
        history_page(d, &q, true).0[0].clone()
    };
    let s = summary_row(&d);
    assert_eq!(s["fail_action"], "space", "{s}");
    assert_eq!(s["disk_full"], true, "{s}");
    // Encrypted: payload twice over, exactly the full record's figure.
    assert_eq!(s["space_needed"], 10_000_000_000u64, "{s}");

    // A failure that was not the disk keeps the verdict false, so the
    // row cannot dress a transport error in the space copy.
    job.lock_ok().fail_message = "download failed on connection errors".into();
    let s = summary_row(&d);
    assert_eq!(s["disk_full"], false, "{s}");

    let _ = std::fs::remove_dir_all(&dir);
}

/// A delete issued while the runner is still bringing the pipeline up
/// must still stop it. `hub.abort` and `hub.queue_ctl` are published
/// partway INTO the fetch (get/vrig.rs `install_seek`), so a delete that
/// wins that race finds both slots empty - and a single shot at an empty
/// slot is a stop signal that never happened. Measured 16 Aug 2026: the
/// daemon logged "active download stopped by user" and then spun up its
/// connections and ran the whole doomed download anyway.
///
/// So the signal is re-fired until the pipeline is there to take it.
/// Standing in for the pipeline here: install the flag AFTER the call
/// returns, exactly as the real publish does, and require it to arrive.
#[test]
fn a_delete_that_beats_the_pipelines_publish_still_stops_it() {
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-delabort-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    // The runner has published the owner (reset_hub_for_job) but the
    // fetch has not reached install_seek: both handles are still empty.
    *d.active_stream.lock_ok() = Some("SABnzbd_nzo_gone".into());
    assert!(d.hub.abort.lock_ok().is_none());

    crate::serve::api::queue::stop_deleted_transfer(&d, vec!["SABnzbd_nzo_gone".into()]);

    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    *d.hub.abort.lock_ok() = Some(flag.clone());
    let t = std::time::Instant::now();
    while !flag.load(Ordering::Relaxed) && t.elapsed() < std::time::Duration::from_secs(5) {
        std::thread::sleep(std::time::Duration::from_millis(50));
    }
    assert!(
        flag.load(Ordering::Relaxed),
        "the stop signal was fired once into an empty slot and lost - a \
         deleted job's download runs its whole ladder after the row is gone"
    );
}

/// ...and never at anyone else. The re-fire waits for the hub to name
/// the DELETED job; while it names another, it must not fire. This is
/// the bug the owner test exists for - job N stays Downloading through
/// its whole disk tail while N+1 is on the wire holding these handles,
/// and deleting N once aborted N+1, a healthy unrelated download that
/// then failed permanently and fired its failure hooks.
#[test]
fn the_delete_stop_signal_is_never_aimed_at_another_job() {
    use crate::serve::testutil::test_daemon;

    let dir = std::env::temp_dir().join(format!("nzbfast-delabort2-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let d = test_daemon(&dir);
    *d.active_stream.lock_ok() = Some("SABnzbd_nzo_innocent".into());
    let flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    *d.hub.abort.lock_ok() = Some(flag.clone());

    crate::serve::api::queue::stop_deleted_transfer(&d, vec!["SABnzbd_nzo_gone".into()]);

    std::thread::sleep(std::time::Duration::from_millis(1500));
    assert!(
        !flag.load(Ordering::Relaxed),
        "a delete aimed its abort at the job that owns the wire, not at \
         the one it deleted"
    );
}
