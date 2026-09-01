//! TODO 312 item 2: the per-server CARRY probe, at the daemon door.
//!
//! A submodule of the daemon target rather than its own `tests/*.rs`,
//! for the reason every sibling here is one: a top-level file would
//! become a separate target and fall out of the standard daemon gate.
//!
//! # What this reaches, stated rather than left to be found
//!
//! `serve::probeids::real_ladder_ids` will not hand out a supply until
//! the install's own history holds at least `MIN_IDS` (1,000) articles
//! in the 300 KB - 1.2 MB band, STAT-verified on the target provider.
//! That is deliberate and it is the guard that stops this probe ever
//! reaching the wire on a population it cannot vouch for.
//!
//! For its first day that guard was also the reason the RUNGS were
//! reached by no test at all: a qualifying supply is ~300 MB of
//! payload, so every daemon test stopped at the no-supply refusal and
//! this note said the rungs were out of reach. They are not, and
//! `the_rungs_run_for_real_against_a_supply_a_real_download_built`
//! at the foot of this file is the other half of it - it builds the
//! 300 MB, so `carry_rung`, the between-rung article rotation, the
//! `CARRY_MAX_ARTICLES` byte cap and the two-rung scaling verdict all
//! run for real against a provider that really served them. Read that
//! test's own header for the cost, and for the one thing still NOT
//! covered here (the 60 s and 90 s timeouts).
//!
//! The DOOR tests are the rest of this file, and the four things about
//! it that would fail silently:
//!
//! * it ANSWERS against a host that accepts a connection and then never
//!   speaks, and the daemon is still serving afterwards;
//! * it RELEASES the shared ladder permit however it ends. A leaked
//!   permit is the quiet one: it takes the connection-ladder button
//!   down too, for the life of the process, and the only symptom is a
//!   button that says something else is already running when nothing
//!   is;
//! * it CHANGES NOTHING. The probe reports; the fleet arithmetic, the
//!   knee and the server's own connection count are untouched, which is
//!   TODO 312 item 2's whole constraint until the provenance work lands
//!   a representation for a measured carry;
//! * it REFUSES a row the user switched off, and the opt-in still gets
//!   past that refusal. Both halves matter and the second is the one
//!   that would rot silently: a refusal with no way through turns
//!   "should I turn this account back on?" into a question the product
//!   cannot answer. The refusal is reached BEFORE the shared permit is
//!   taken, which is what the permit assertion below is really pinning.
//!
//! The OTHER refusal - a download in flight - is not reachable from
//! here: raising `index_jobs_active` means running the runner, and a
//! qualifying supply for the probe cannot be built at test size (see
//! above). It is pinned by `serve::api::servers`'
//! `the_probe_refuses_a_running_download_and_a_switched_off_row`
//! instead, over the same predicate this door calls.

use super::*;

/// The carry probe answers, keeps nothing, and lets go of the permit.
///
/// The host is a real listener that accepts and then holds the socket
/// without ever writing a greeting - the shape that wedges a handler
/// which dials without a deadline, and the reason `m_server_test` and
/// `m_server_carry` are both written around a bounded `block_on`.
#[tokio::test(flavor = "multi_thread")]
async fn the_carry_probe_answers_a_silent_host_and_keeps_nothing() {
    let dir = std::env::temp_dir().join(format!("nzbfast-carry-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Accepts, then says nothing at all and holds the connection open.
    // `incoming()` is never dropped, so the sockets stay live for the
    // life of the test rather than being closed by a refusal.
    let sink = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    let held = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let held2 = held.clone();
    std::thread::spawn(move || {
        for s in sink.incoming().flatten() {
            held2.lock().unwrap().push(s);
        }
    });

    let cfg = dir.join("config.json");
    let cfg_json = format!(
        "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{sink_port},\
         \"tls\":false,\"connections\":8}}]}}"
    );
    std::fs::write(&cfg, &cfg_json).unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let cfg2 = cfg.clone();
    tokio::task::spawn_blocking(move || {
        // The whole server, the way the editor sends it - `server_test`
        // and `server_carry` both merge the form's current values over
        // the saved row, so a body carrying only an index is refused
        // before either of them dials anything.
        let body = format!(
            r#"{{"index":0,"server":{{"host":"127.0.0.1","port":{sink_port},"tls":false,"connections":8}}}}"#
        );
        let body = body.into_bytes();
        let probe = || {
            let t0 = std::time::Instant::now();
            let r = http(
                port,
                "/api?mode=server_carry&output=json",
                Some(("application/json", body.as_slice())),
            );
            (r, t0.elapsed())
        };

        let (r, took) = probe();
        // Bounded well inside the handler's own 60 s supply timeout and
        // 90 s measure timeout. The point is not the exact figure - it
        // is that a host which never answers cannot hold the door.
        assert!(
            took < std::time::Duration::from_secs(150),
            "the carry probe did not return against a silent host ({took:?})\n{r}"
        );
        // The outcome a fresh install reaches, pinned by name rather
        // than as "some json": this IS the supply guard refusing to
        // measure a population it cannot vouch for, and it is what
        // keeps the probe off the wire here. If it ever stops being
        // what this reaches, the module note above has gone stale and
        // the rungs are running in a test that never priced them.
        assert!(
            r.contains("\"no_real_articles\":true"),
            "the carry probe reached past its own supply guard\n{r}"
        );
        // ...and it named the host rather than failing anonymously.
        assert!(r.contains("127.0.0.1"), "the refusal names no server\n{r}");

        // The permit is shared with the connection ladder, so a leak
        // here disables THAT button too - with no symptom but a refusal
        // naming a run that is not happening. Both doors must still be
        // free.
        let (r2, _) = probe();
        assert!(
            !r2.contains("already running"),
            "the carry probe leaked the ladder permit - every later probe, \
             and the connection-ladder button, are locked out for the life \
             of the process\n{r2}"
        );
        let l = http(
            port,
            "/api?mode=connladder_live&output=json",
            None,
        );
        assert!(
            l.contains("\"running\":false"),
            "a probe that ended left the ladder reading as live\n{l}"
        );

        // ...and the daemon is still a daemon.
        let v = http(port, "/api?mode=version&output=json", None);
        assert!(
            v.contains("version"),
            "the daemon stopped serving after a carry probe\n{v}"
        );

        // REPORT ONLY. The probe must not have written a knee, a
        // connection count, or anything else back into the config -
        // `m_connladder`'s fixed-rung path holds itself to the same rule
        // and says why: a diagnostic that applies what it measured is a
        // diagnostic that caps real jobs off one short sample.
        assert_eq!(
            std::fs::read_to_string(&cfg2).unwrap(),
            cfg_json,
            "the carry probe wrote to the config - it must report and touch nothing"
        );
    })
    .await
    .unwrap();

    let _log = d.stop();
}

/// A switched-off server is refused, and the opt-in gets through.
///
/// The defect: the probe's permit excluded only another ladder or probe,
/// so this door would open a fresh pool of up to `CARRY_MAX_CONNS`
/// sockets against an account the config says to leave alone - the shape
/// a whole incident was spent on 23 Aug 2026 establishing the rule for,
/// when a machine was found holding live sockets to a provider marked
/// `"enabled": false` while another machine used that same shared
/// account.
///
/// Two things are asserted and the second is the load-bearing one. The
/// refusal names the row and carries `server_off` so the panel can offer
/// the opt-in rather than showing red text with no next step; and the
/// opt-in run gets PAST it, reaching the same supply guard the sibling
/// test above lands on. A refusal with no way through would be the same
/// defect one layer up.
#[tokio::test(flavor = "multi_thread")]
async fn a_switched_off_server_is_refused_and_the_opt_in_gets_through() {
    let dir = std::env::temp_dir().join(format!("nzbfast-carryoff-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);

    // Same silent listener as the sibling test: it is never reached on
    // either path here (the refusal answers first, and the opt-in run
    // stops at the supply guard, which counts spooled articles before it
    // dials anything), but a config naming a dead port would leave the
    // test asserting a refusal for the wrong reason if that ever changed.
    let sink = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let sink_port = sink.local_addr().unwrap().port();
    let held = std::sync::Arc::new(std::sync::Mutex::new(Vec::new()));
    let held2 = held.clone();
    std::thread::spawn(move || {
        for s in sink.incoming().flatten() {
            held2.lock().unwrap().push(s);
        }
    });

    let cfg = dir.join("config.json");
    // `enabled: false` on the only row. The engine keeps it configured
    // and testable and never puts it in a pool, which is exactly the
    // state the probe used to ignore.
    let cfg_json = format!(
        "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{sink_port},\
         \"tls\":false,\"connections\":8,\"enabled\":false}}]}}"
    );
    std::fs::write(&cfg, &cfg_json).unwrap();
    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"));
        c
    })
    .await;
    let port = d.port;

    let cfg2 = cfg.clone();
    tokio::task::spawn_blocking(move || {
        let post = |body: String| {
            let b = body.into_bytes();
            http(
                port,
                "/api?mode=server_carry&output=json",
                Some(("application/json", b.as_slice())),
            )
        };
        // The whole server, the way the editor sends it. Note the body
        // carries no `enabled`: `normalized_server` deliberately does
        // not merge that field, so what this door judges is the SAVED
        // state of the row and an unsaved tick cannot talk it into
        // dialling.
        let srv = format!(
            r#""server":{{"host":"127.0.0.1","port":{sink_port},"tls":false,"connections":8}}"#
        );

        let t0 = std::time::Instant::now();
        let r = post(format!("{{\"index\":0,{srv}}}"));
        let took = t0.elapsed();
        assert!(
            r.contains("\"server_off\":true"),
            "the carry probe dialled a server the user switched off\n{r}"
        );
        assert!(
            r.contains("127.0.0.1"),
            "the refusal names no server, so the page cannot offer the opt-in\n{r}"
        );
        // It refused before it went anywhere near the wire: the supply
        // guard, which is what an allowed run reaches, never ran.
        assert!(
            !r.contains("no_real_articles"),
            "the refusal came from the supply guard, so the probe had \
             already been let through the switch\n{r}"
        );
        assert!(
            took < std::time::Duration::from_secs(20),
            "a refusal that took {took:?} is not a refusal, it is a dial\n{r}"
        );

        // The permit is shared with the connection ladder, and a refusal
        // that took one would take THAT button down for the life of the
        // process with no symptom but a refusal naming a run that is not
        // happening. This is why both refusals stand before the permit.
        let l = http(port, "/api?mode=connladder_live&output=json", None);
        assert!(
            l.contains("\"running\":false"),
            "a refused probe left the ladder reading as live\n{l}"
        );

        // The opt-in: same row, same switch, and it gets through to the
        // supply guard - the outcome the sibling test pins for an
        // enabled row on a fresh install.
        let r2 = post(format!("{{\"index\":0,\"include_off\":true,{srv}}}"));
        assert!(
            !r2.contains("\"server_off\":true"),
            "the opt-in did not get past the switch, so \"is this account \
             worth turning back on?\" has no answer\n{r2}"
        );
        assert!(
            r2.contains("\"no_real_articles\":true"),
            "the opt-in run reached something other than the supply guard\n{r2}"
        );

        // ...and the daemon is still a daemon, and still has not been
        // written to. REPORT ONLY, refusal or not.
        let v = http(port, "/api?mode=version&output=json", None);
        assert!(
            v.contains("version"),
            "the daemon stopped serving after a refused carry probe\n{v}"
        );
        assert_eq!(
            std::fs::read_to_string(&cfg2).unwrap(),
            cfg_json,
            "the carry probe wrote to the config - it must report and touch nothing"
        );
    })
    .await
    .unwrap();

    let _log = d.stop();
}

/// What one tee'd connection may carry, and the reason the tee paces at
/// all.
///
/// Unpaced, a 256-article rung over loopback drains in ~180 ms, and
/// that is too fast for TWO separate reasons. The RATE is not the real
/// one: `timed_fetch_multi` measures first-completion to
/// last-completion only once at least 8 articles have landed AND the
/// span is a second or more, and falls back to the whole window with
/// the connect ramp inside it below that. And the FLEET never forms:
/// `PoolConfig::ramp_delay` is 150 ms and slot k sleeps `150 ms * k`
/// before it dials, so a rung gone in 180 ms is served by one or two
/// sockets no matter what it asked for - which makes `per_socket_bps`
/// a division by one, and no assertion over it can then be falsified.
///
/// A THIRD reason held until 28 Aug 2026 and is now gone, which is
/// worth knowing before anybody "simplifies" this constant away.
/// `granted` was read off the peak of a 100 ms sampler over the pool's
/// live socket gauge, so a rung finishing inside one tick reported 1 -
/// or 0 - whatever fleet it really held (TODO 312 item 3). The pacing
/// was what bought that sampler enough ticks to see a fleet at all. It
/// is now recorded exactly, at the moment each session is established,
/// so the pacing no longer serves `granted`; the two reasons above are
/// each sufficient on their own and neither has moved.
///
/// 12 MB/s a connection puts the 5-socket rung at ~1.3 s and the
/// 10-socket one at ~0.7 s of transfer: enough span for the estimator,
/// enough time for the small rung's ramp to finish with room over
/// (600 ms), and still 4x inside `CARRY_RUNG_SECS` (6 s) so a loaded
/// box cannot turn a drained rung into a timed-out one. Raising it back
/// towards loopback speed does not make this test faster in any way
/// that matters - it makes two of its assertions unfalsifiable.
const TEE_BPS: u64 = 12 << 20;

/// A line-sniffing TCP tee in front of a mock provider: the only way to
/// see WHICH articles a rung asked for.
///
/// Nothing the handler reports can answer that. The rungs are told to
/// skip past everything the previous one read
/// (`servers.rs`'s `ids.rotate_left(rot)`), and the whole point of that
/// line is that the second rung's articles are COLD - a provider, or
/// anything on the path, that served the second rung from the first
/// rung's cache would show carry HOLDING at the higher socket count on
/// a link where it does not. Delete the rotation and every field in the
/// answer still looks exactly right, which is why the ids have to be
/// counted from the wire.
///
/// Commands are ASCII lines and the client never sends anything else,
/// so the client-to-server leg is read a line at a time and forwarded
/// verbatim. The server-to-client leg is PACED at [`TEE_BPS`] a
/// connection, and that is not decoration either - see its own note.
/// Returns the port to point a client at, and the log of every article
/// id asked for, in arrival order across every connection of it.
fn id_tee(upstream: std::net::SocketAddr) -> (u16, std::sync::Arc<std::sync::Mutex<Vec<String>>>) {
    let l = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
    let port = l.local_addr().unwrap().port();
    let log: std::sync::Arc<std::sync::Mutex<Vec<String>>> = Default::default();
    let log2 = log.clone();
    std::thread::spawn(move || {
        for down in l.incoming().flatten() {
            let Ok(up) = std::net::TcpStream::connect(upstream) else {
                continue;
            };
            let (Ok(down_r), Ok(up_r)) = (down.try_clone(), up.try_clone()) else {
                continue;
            };
            let (mut down_w, mut up_w) = (down, up);
            std::thread::spawn(move || {
                use std::io::{Read, Write};
                let mut up_r = up_r;
                let mut buf = vec![0u8; 32 << 10];
                let (t0, mut sent) = (std::time::Instant::now(), 0u64);
                while let Ok(n) = up_r.read(&mut buf) {
                    if n == 0 || down_w.write_all(&buf[..n]).is_err() {
                        break;
                    }
                    sent += n as u64;
                    // Self-correcting against the total, not a sleep per
                    // chunk: a scheduler that overshoots one sleep does
                    // not compound into a rung that misses its window.
                    let want = std::time::Duration::from_nanos(sent * 1_000_000_000 / TEE_BPS);
                    if let Some(d) = want.checked_sub(t0.elapsed()) {
                        std::thread::sleep(d);
                    }
                }
                let _ = down_w.shutdown(std::net::Shutdown::Write);
            });
            let log = log2.clone();
            std::thread::spawn(move || {
                use std::io::{BufRead, Write};
                let mut r = std::io::BufReader::new(down_r);
                let mut line = Vec::new();
                loop {
                    line.clear();
                    match r.read_until(b'\n', &mut line) {
                        Ok(0) | Err(_) => break,
                        Ok(_) => {}
                    }
                    if let Ok(t) = std::str::from_utf8(&line) {
                        let t = t.trim();
                        for verb in ["BODY ", "ARTICLE "] {
                            if let Some(id) = t.strip_prefix(verb) {
                                log.lock().unwrap().push(id.trim().to_string());
                            }
                        }
                    }
                    if up_w.write_all(&line).is_err() {
                        break;
                    }
                }
                let _ = up_w.shutdown(std::net::Shutdown::Write);
            });
        }
    });
    (port, log)
}

/// TODO 312 item 6(b): the rungs themselves, end to end, against a
/// supply a REAL download built.
///
/// # Why this test is expensive, and why it cannot be cheaper
///
/// `real_ladder_ids` needs `MIN_IDS` (1,000) articles in the 300 KB -
/// 1.2 MB band out of the install's own spooled NZBs, so the fixture
/// floor is 1,000 x 300 KB and there is no way to be under it while the
/// fixture stays honest. Measured on the dev box 28 Aug 2026: 1,044
/// segments, 298 MB downloaded in ~1 s over loopback and written once
/// in place (there is no second copy - the peak is the 298 MB), and
/// the probe itself 0.46 s. That is a ~300x outlier in this suite's
/// fixture sizes and a rounding error in its wall clock.
///
/// **Do not "fix" that by shrinking the articles.** An NZB declaring
/// in-band sizes over a mock serving small bodies passes the band
/// filter and the STAT gate and downloads in a blink - and it silently
/// stops testing the ROTATION, which is derived from BYTES:
/// `read = r.bytes / MIN_PROBE_ARTICLE_BYTES` in `servers.rs`. At 8 KB
/// an article a 256-article rung scores a skip of 6, the second rung
/// re-reads 250 of the first rung's ids, and the assertion below passes
/// on a fixture that has quietly inverted the thing it is asserting.
///
/// # Why it lives in the daemon target
///
/// The placement question TODO 312's handoff asks to settle first. The
/// answer is: here, and it is already in the nightly heavy-suite family
/// by being here - the `daemon` target is build-gated behind
/// `heavy-tests` and its home is nightly.yml's `long-suites`, with its
/// own wedge check after it (CLAUDE.md invariant 4 and TODO 116b). An
/// eighth heavy `[[test]]` target would buy cost isolation and cost
/// four coordination surfaces that can drift apart - Cargo.toml,
/// nightly.yml, ci-private's `-E` list and CLAUDE.md's sweep prose -
/// plus a third copy of the daemon-spawning `http` helper this module
/// gets for free from its parent. This suite already spawns ~130 real
/// daemons; it can afford 298 MB of temp for the one test that reaches
/// the wire the probe was written for.
///
/// # The fixture
///
/// Two mock providers, because a ONE-server install gets only one rung:
/// its share IS the whole fleet, `carry_rungs_for` clamps both rungs to
/// the ceiling, and `carry_scaling` correctly answers `"unknown"` (that
/// is TODO 312's own item 1, a separate claim, and this test would go
/// quiet about the scaling verdict if it were written against one
/// server). `BenchSet`'s message-ids are derived from its parameters
/// alone, so ONE set served on two ports is one corpus on two
/// providers - which is what makes a two-server config testable against
/// a single 298 MB download.
///
/// A typed `line_cap_fleet` of 10 over 2 servers puts the share at 5
/// and the ceiling at 24, so the rungs are 5 and 10: a real doubling,
/// which is the comparison the panel exists to make.
///
/// # What is still NOT covered here
///
/// The 60 s supply timeout and the 90 s measure timeout. Both need a
/// provider that wedges MID-MEASUREMENT rather than one that is merely
/// silent - the door test above already bounds the silent case - and
/// the cost of reaching them from this door is the reason they are
/// left: the supply timeout only arms once `real_ladder_ids` is
/// STAT-verifying against a wedging host, which means building this
/// test's 298 MB fixture and then swapping the provider under it, and
/// the measure timeout wants 90 s of wall clock in a suite whose whole
/// carry family runs in 6 s. Neither would assert anything about the
/// carry arithmetic; both assert that a `tokio::time::timeout` the
/// module already wraps every rung in does what timeouts do. Priced and
/// declined 28 Aug 2026 - if that judgement is revisited, the shape to
/// build is a tee that forwards the greeting and then stops relaying,
/// so the session establishes and the BODY never lands.
///
/// `granted == 0` - the 481 case, an account already full from another
/// machine - USED to be listed here too. It is covered now, at the
/// level it belongs to rather than through 298 MB of fixture:
/// `nzbkit::sysbench::tests::granted_is_zero_when_the_provider_establishes_no_session`
/// drives a `cap_ghost_ms` mock that greets every dial with the
/// provider's own capacity refusal, and its sibling there pins the
/// whole-fleet case on a rung that drains at once. This test's own
/// `granted` assertions are the handler-level half of the same
/// contract.
#[tokio::test(flavor = "multi_thread")]
async fn the_rungs_run_for_real_against_a_supply_a_real_download_built() {
    let dir = std::env::temp_dir().join(format!("nzbfast-carryrung-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let watch = dir.join("watch");
    std::fs::create_dir_all(&watch).unwrap();

    // 4 files x 78 MB at a 300 KB article = 1,044 segments, every one
    // of them declared 309,644 bytes - inside `probeids`' 300 KB -
    // 1.2 MB band with no margin games. One set, two listeners.
    let set = std::sync::Arc::new(nzbkit::benchserve::BenchSet::new(4, 78_000_000, 300_000));
    let (mock_a, mock_b) = (free_port(), free_port());
    for p in [mock_a, mock_b] {
        let set = set.clone();
        tokio::spawn(async move {
            let _ = nzbkit::benchserve::serve(&format!("127.0.0.1:{p}"), set).await;
        });
    }
    // The tee goes in front of the server the probe measures (index 0)
    // and nothing else: the second provider is only there to make the
    // fleet share divisible.
    let (probe_port, wire) = id_tee(format!("127.0.0.1:{mock_a}").parse().unwrap());

    let cfg = dir.join("config.json");
    let cfg_json = format!(
        "{{\"servers\":[\
           {{\"host\":\"127.0.0.1\",\"port\":{probe_port},\"tls\":false,\"connections\":24}},\
           {{\"host\":\"localhost\",\"port\":{mock_b},\"tls\":false,\"connections\":24}}]}}"
    );
    std::fs::write(&cfg, &cfg_json).unwrap();
    // `line_speed` is what makes `anchor_bps`/`anchor_src` mean
    // something in the answer; `line_cap_fleet` is what fixes the two
    // rungs at 5 and 10 rather than leaving them to TODO 277's curve
    // over whatever the anchor happens to be.
    std::fs::write(
        dir.join("settings.json"),
        "{\"line_speed\": 1000000000, \"line_cap_fleet\": 10, \"index_enabled\": false}",
    )
    .unwrap();
    // TODO 312 item 6(e): the panel puts the carry this probe measures
    // beside the one a REAL download banked, so the reading has to
    // carry that second number out to the page. Seeded here rather than
    // left to the fixture's own download, and the reason is timing: the
    // banked value is written by a ONE-SECOND ticker
    // (`serve/linecarry.rs`'s `feed`, riding `linkpeak`'s loop) and this
    // fixture's supply job is ~1 s of loopback transfer on a quiet box,
    // so a run can legitimately finish having never been ticked. An
    // unseeded assertion would be green on a loaded box and red on an
    // idle one.
    //
    // DELIBERATELY BELOW `MIN_CARRY_BPS` (32,768). `observe` refuses
    // anything under that floor, so the daemon can never write this
    // value itself: seeing it come back out is proof the handler read
    // the banked slot rather than inventing a number. The download may
    // still overwrite it - that is the mechanism the field exists for -
    // and the assertion below admits exactly those two outcomes and no
    // third.
    std::fs::create_dir_all(dir.join(".spool")).unwrap();
    std::fs::write(
        dir.join(".spool").join("linecarry.json"),
        "{\"carry_bps\": 12345, \"checked\": 0}",
    )
    .unwrap();

    let d = serve(&dir, |port| {
        let mut c = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
        c.env("NZBFAST_OPEN", "1")
            .env("NZBFAST_NO_ENRICH", "1")
            .arg("--config")
            .arg(&cfg)
            .arg("serve")
            .arg("--port")
            .arg(port.to_string())
            .arg("--bind")
            .arg("127.0.0.1")
            .arg("--out")
            .arg(dir.join("complete"))
            .arg("--watch")
            .arg(&watch)
            // The suite's daemons run on a box with eight other
            // sessions building on it; a min-free hold here would
            // report as a probe that found no supply.
            .arg("--min-free")
            .arg("0")
            .arg("--connections")
            .arg("24");
        c
    })
    .await;
    let port = d.port;

    // The watch folder rather than a fourth hand-rolled multipart
    // addfile: the daemon picks the drop up on its own fs watch, and
    // this is a real add path.
    std::fs::write(watch.join("set.nzb"), set.nzb()).unwrap();

    tokio::task::spawn_blocking(move || {
        // ~1 s of transfer on a quiet box; the budget is for a loaded
        // one, and is well inside the profile's 600 s per-test ceiling.
        let t0 = std::time::Instant::now();
        let h = loop {
            let h = http(port, "/api?mode=history&output=json", None);
            if h.contains("\"status\":\"Completed\"") {
                break h;
            }
            assert!(
                t0.elapsed() < std::time::Duration::from_secs(300),
                "the 298 MB supply job never completed - the probe has \
                 nothing to measure with\n{h}"
            );
            std::thread::sleep(std::time::Duration::from_millis(250));
        };
        assert!(
            h.contains("bench-f0000.bin") || h.contains("set"),
            "the completed job is not the one this test posted\n{h}"
        );

        // Everything on the wire from here is the probe's, so the
        // download's own 1,044 ids are cut off rather than counted.
        let before = wire.lock().unwrap().len();

        let body = format!(
            "{{\"index\":0,\"server\":{{\"host\":\"127.0.0.1\",\"port\":{probe_port},\
              \"tls\":false,\"connections\":24}}}}"
        )
        .into_bytes();
        let r = http(
            port,
            "/api?mode=server_carry&output=json",
            Some(("application/json", body.as_slice())),
        );
        let v: serde_json::Value = serde_json::from_str(&r)
            .unwrap_or_else(|e| panic!("the carry probe did not answer json ({e})\n{r}"));

        // THE THING NO OTHER TEST REACHES. Every daemon test before
        // this one stopped at the supply guard; a run that still does
        // is a run that measured nothing, whatever else passes below.
        assert_eq!(
            v["status"], true,
            "the carry probe refused against a supply a real download built\n{r}"
        );
        assert!(
            v.get("no_real_articles").is_none(),
            "the supply guard refused 1,044 STAT-verified in-band articles\n{r}"
        );

        let rungs = v["rungs"].as_array().expect("rungs is not an array");
        // 5 and 10: `server_share(10, 2)` clamped into `2..=24`, then
        // doubled. Two rungs is what makes a scaling verdict possible
        // at all - see this test's header on the one-server case.
        assert_eq!(rungs.len(), 2, "the probe ran {} rung(s)\n{r}", rungs.len());
        assert_eq!(rungs[0]["connections"], 5, "{r}");
        assert_eq!(rungs[1]["connections"], 10, "{r}");

        for (i, rung) in rungs.iter().enumerate() {
            let bps = rung["bps"].as_u64().expect("bps");
            let bytes = rung["bytes"].as_u64().expect("bytes");
            let granted = rung["granted"].as_u64().expect("granted");
            let conns = rung["connections"].as_u64().expect("connections");
            assert!(bps > 0, "rung {i} measured no rate\n{r}");
            assert!(bytes > 0, "rung {i} moved no bytes\n{r}");
            // TIGHTENED from `granted >= 2` on 28 Aug 2026, with TODO
            // 312 item 3. Until then `timed_fetch_multi` read this off
            // the peak of a 100 ms sampler, so a rung finishing inside
            // one tick reported whatever that tick caught - 1, or 0 -
            // whatever fleet it really held, and the only thing this
            // test could assert was that the pacing had kept the
            // per-socket division below FALSIFIABLE (at `granted == 1`
            // it is `bps / 1` and no mutation of it can be caught). The
            // count is now recorded at the moment each session is
            // established, so it is exact and the real contract can be
            // asserted: the provider granted the fleet asked for.
            //
            // THE BAR IS THE PRODUCT'S OWN definition of "the fleet
            // formed" - `conntune::knee_of` and the dashboard's ceiling
            // note both read a socket or two short of the ask as
            // ordinary timing rather than a refusal - and here it is
            // load-bearing rather than borrowed slack.
            // `PoolConfig::ramp_delay` is 150 ms and slot k sleeps
            // `150 ms * k` before it dials, so a rung that drains before
            // its last slots have ramped in never holds the whole fleet
            // AT ONCE, correctly. Measured 28 Aug 2026: the 5-socket
            // rung reports 5 (ramped by 600 ms against a ~1.3 s run) and
            // the 10-socket rung reports 9 (slot 9 dials at 1.35 s, a
            // hair past the end). That is a true reading of what the
            // provider served, not an under-read - so a blanket
            // `== connections` here would be pinning the RAMP.
            assert!(
                granted + 2 >= conns,
                "rung {i} asked {conns} sockets and reports {granted} granted - \
                 shorter than the dial ramp explains, which is what \
                 `knee_of` reads as a provider refusal and caps the user to\n{r}"
            );
            assert_eq!(
                rung["per_socket_bps"].as_u64(),
                Some(bps / granted),
                "rung {i}: the reported per-socket carry is not the rate \
                 over the sockets it was granted\n{r}"
            );
            // The supply is 1,044 ids and each rung is capped at
            // `CARRY_MAX_ARTICLES`, so both drain what they were
            // ALLOWED rather than running out the 6 s window.
            assert_eq!(rung["drained"], true, "rung {i} did not drain\n{r}");
        }

        // The strongest claim this fixture supports, and the one the
        // sampler could not have passed at any tick rate: the SMALL
        // rung's fleet forms whole. Its five slots have all dialled by
        // 600 ms (`ramp_delay` 150 ms x slot) against a ~1.3 s paced
        // run, so there is better than a 2x margin - and the margin only
        // GROWS on a slower box, because the tee paces the transfer by
        // wall clock while anything that delays a dial also lengthens
        // the run. Spelled out here rather than folded into the loop
        // above, because the ten-socket rung has no such margin (see
        // there) and a generic `== connections` would assert the ramp.
        assert_eq!(
            rungs[0]["granted"].as_u64(),
            Some(5),
            "the 5-socket rung did not hold its whole fleet at once\n{r}"
        );

        // A verdict, not a shrug: two rungs with a per-socket number on
        // each is exactly the case `carry_scaling` exists for, and
        // `"unknown"` here would mean the second rung never produced
        // one.
        let scaling = v["scaling"].as_str().unwrap_or("");
        assert!(
            ["per_connection", "mixed", "line"].contains(&scaling),
            "two rungs produced no scaling verdict ({scaling:?})\n{r}"
        );
        assert!(v["carry_bps"].as_u64().unwrap_or(0) > 0, "{r}");
        // Read off the settings above, and reported so a reader can
        // judge the implied fleet at all.
        assert_eq!(v["anchor_bps"], 1_000_000_000u64, "{r}");
        assert_eq!(v["anchor_src"], "line", "{r}");
        assert_eq!(v["fleet_now"], 10, "{r}");
        assert_eq!(v["servers"], 2, "{r}");
        // THE IMPLIED FLEET IS UNCLAMPED, and that is the one number
        // in this panel a "tidy" would quietly cap. The paced tee puts
        // the carry at ~10 MB/s against a 1 GB/s anchor, so the line
        // wants ~100 sockets - twice `fleet_max`, and ten times the
        // fleet in force. Being shown the ceiling instead of the answer
        // is exactly what the panel exists to prevent (TODO 312 item 6,
        // and `linecap::fleet_implied_by_carry`'s own note).
        let implied = v["implied_fleet"].as_u64().expect("implied_fleet");
        let fleet_max = v["fleet_max"].as_u64().expect("fleet_max");
        assert!(
            implied > fleet_max,
            "the implied fleet ({implied}) did not stand above the ceiling \
             ({fleet_max}) on a link carrying ~10 MB/s a socket against a \
             1 GB/s anchor - it is being clamped, which answers a question \
             nobody asked\n{r}"
        );

        // TODO 312 item 6(e): the LIVE carry, beside the measured one.
        // Two readings of one quantity - `carry_bps` is this server
        // driven on purpose for a few seconds, `live_carry_bps` is what
        // a socket held during a real download - and without the second
        // on this response the panel cannot put them side by side at
        // all. It is the persisted form of whyslow's `fleet_carry_bps`
        // and is the only spelling of it that outlives the job, which
        // matters here because the probe REFUSES while a download runs:
        // the two numbers can never be live at the same moment.
        let live = v["live_carry_bps"]
            .as_u64()
            .unwrap_or_else(|| panic!("no live_carry_bps on the reading\n{r}"));
        assert!(
            live == 12_345 || live >= 32_768,
            "live_carry_bps came back {live}, which is neither the seed \
             this fixture wrote nor a reading the banking floor \
             (MIN_CARRY_BPS) could have produced - the handler is not \
             reading `d.line_carry`\n{r}"
        );

        // THE BYTE CAP AND THE ROTATION, off the wire.
        let asked: Vec<String> = wire.lock().unwrap()[before..].to_vec();
        let distinct: std::collections::HashSet<&String> = asked.iter().collect();
        // `CARRY_MAX_ARTICLES` is 256 and there are two rungs, so no
        // amount of link speed may put more than 512 articles on the
        // wire: this is the probe's cost control, and a diagnostic
        // button with a time bound alone spends a gigabyte and a half
        // on a fast line.
        assert!(
            (256..=512).contains(&asked.len()),
            "the two rungs asked for {} articles - the {} cap is not \
             holding (or the rungs never reached the wire)\n{r}",
            asked.len(),
            512
        );
        // ...and the second rung's were COLD. Without the rotation in
        // `servers.rs` the second rung re-reads the first rung's ids
        // from the head of the same list, so the count collapses to
        // ~half while every field in the answer above still looks
        // right - a warm re-read reports carry HOLDING on a link where
        // it does not.
        assert!(
            asked.len() - distinct.len() <= 16,
            "{} of the {} articles the two rungs asked for were repeats - \
             the between-rung rotation is not skipping past what the \
             first rung read\n{r}",
            asked.len() - distinct.len(),
            asked.len()
        );
    })
    .await
    .unwrap();

    // REPORT ONLY, on the path that actually measured something: the
    // door test above pins this against the refusal, which is the
    // cheaper half of the same rule.
    assert_eq!(
        std::fs::read_to_string(&cfg).unwrap(),
        cfg_json,
        "the carry probe wrote to the config - it must report and touch nothing"
    );
    let _log = d.stop();
}
