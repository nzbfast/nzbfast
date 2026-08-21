//! §129 3b: the client against TLS-layer faults, in process.
//!
//! Every fault shape the §111 campaign ever raced happens above the
//! transport, on plain TCP. These are the ones that live in the TLS
//! layer itself, where no rig had ever put the client: a handshake that
//! breaks two different ways, a mid-body cut with NO `close_notify`, a
//! corrupted record, and a kill followed by a failing reconnect.
//!
//! What each leg pins is the same three things: the error is CLASSIFIED
//! as a transport failure (the session ends as `peer` - not a protocol
//! desync, not a missing article, neither of which should feed the
//! give-up ladder), the run stays BOUNDED (no wedge), and the bytes that
//! come out are byte-exact against the corpus. The truncation leg is the
//! security-relevant one: a TLS stream that ends without `close_notify`
//! is indistinguishable from an attacker cutting the connection, and the
//! partial article behind it must never be accepted as complete.
//!
//! Intermittently red on `windows-unit` until 11 Aug 2026, and the
//! diagnosis is worth keeping because the symptom pointed the wrong way.
//! Two legs parked on a suspiciously round ~30 s and this one overran
//! `LEG_BUDGET` as a bare WEDGE, which reads like a retry ladder firing
//! only on Windows. It was not: 30 s is the flat `read_timeout` (see
//! `pool_cfg` - `adaptive_timeout` is off, so there is no pre-byte
//! ladder), every 30 s leg carried `stall >= 1` in its `ends` while the
//! sub-second ones carried `stall: 0`, and the stalled sessions were
//! ones with NO fault injected - their `peer` counts already matched the
//! faults the front had delivered. Nothing in the client's pacing can
//! even reach 30 s here: CONNECT_TIMEOUT is 20 s and the session-backoff
//! ladder tops out at 25.6 s off this `connect_backoff` before
//! MAX_SESSION_ATTEMPTS retires the worker.
//!
//! The cause was in the rig, in `mock_tls::pump`: `write_all` on a TLS
//! stream reports plaintext ACCEPTED, not delivered, so a would-block
//! socket write left the tail of an article queued inside rustls while
//! the front went back to waiting on the mock. The comment at that flush
//! carries the detail. A stalled session is now a named failure
//! (`check_peer_classified`) rather than 30 s of anonymous wall.
//!
//! One test in this binary on purpose, like `tests/tls.rs`: the trust
//! anchors are read from `NZBFAST_EXTRA_CA` exactly once per process,
//! when the first `ClientConfig` is built, so the process that sets it
//! cannot have another test racing that read. The four shapes run
//! sequentially inside it and every verdict is collected, so one broken
//! shape still reports the other three.

mod scratch;

use std::collections::HashMap;
use std::sync::Arc;
use std::time::{Duration, Instant};

use nzbkit::config::ServerConfig;
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::mock_tls::{HandshakeFault, TlsChaos, TlsFront};
use nzbkit::nntp::{Connection, NntpError};
use nzbkit::pool::{ArticleReq, FetchOutcome, LiveStats, PoolConfig, PoolStats, fetch_all_multi};
use tokio::sync::mpsc;

/// 12 x 64 KB: big enough that a per-connection byte budget cuts several
/// times mid-run, small enough that a wedge is obvious against the wall.
const ARTICLE: usize = 64 << 10;
const ARTICLES: usize = 12;
/// Every leg's no-wedge bound. Loopback, 768 KB, faults included: the
/// clean run is under a second, so this is two orders of magnitude of
/// rope and still catches a hang.
const LEG_BUDGET: Duration = Duration::from_secs(45);

// ---------------------------------------------------------------- certs

struct Certs {
    ca: std::path::PathBuf,
    /// Leaf for `localhost` + 127.0.0.1 - the name the legs dial.
    cert: std::path::PathBuf,
    key: std::path::PathBuf,
    /// Leaf for a name nothing dials, same CA: a certificate that
    /// verifies as a chain and still fails the name check.
    alt_cert: std::path::PathBuf,
    alt_key: std::path::PathBuf,
}

/// A CA plus two leaves signed by it. Not self-signed leaves: webpki
/// refuses a CA:TRUE certificate presented as an end entity
/// (`CaUsedAsEndEntity`), which has already cost this project a bench
/// rig once.
fn cert_chain(dir: &std::path::Path) -> Certs {
    let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
    ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
    ca_params
        .distinguished_name
        .push(rcgen::DnType::CommonName, "nzbkit tls chaos ca");
    let ca_key = rcgen::KeyPair::generate().expect("ca key");
    let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
    let issuer = rcgen::Issuer::new(ca_params, ca_key);

    let leaf = |names: Vec<String>, cn: &str, stem: &str| {
        let mut params = rcgen::CertificateParams::new(names).expect("leaf params");
        params
            .distinguished_name
            .push(rcgen::DnType::CommonName, cn);
        let key = rcgen::KeyPair::generate().expect("leaf key");
        let cert = params.signed_by(&key, &issuer).expect("leaf cert");
        let (cp, kp) = (
            dir.join(format!("{stem}.pem")),
            dir.join(format!("{stem}.key")),
        );
        std::fs::write(&cp, cert.pem()).expect("write cert");
        std::fs::write(&kp, key.serialize_pem()).expect("write key");
        (cp, kp)
    };

    let (cert, key) = leaf(
        vec!["localhost".into(), "127.0.0.1".into()],
        "localhost",
        "leaf",
    );
    let (alt_cert, alt_key) = leaf(vec!["wrong.invalid".into()], "wrong.invalid", "alt");
    let ca = dir.join("ca.pem");
    std::fs::write(&ca, ca_cert.pem()).expect("write ca");
    Certs {
        ca,
        cert,
        key,
        alt_cert,
        alt_key,
    }
}

// --------------------------------------------------------------- corpus

struct Corpus {
    articles: HashMap<String, Vec<u8>>,
    ids: Vec<String>,
    data: Vec<u8>,
}

fn corpus() -> Corpus {
    let data: Vec<u8> = (0..(ARTICLE * ARTICLES) as u64)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    let mut articles = HashMap::new();
    let segs = make_file_articles("tlschaos.bin", &data, ARTICLE, "tlsc", &mut articles);
    let ids = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
    Corpus {
        articles,
        ids,
        data,
    }
}

/// A plain mock holding the corpus, plus a TLS front in front of it.
/// `per_conn_bps` paces the MOCK (0 = as fast as loopback goes): a leg
/// whose healthy side finishes in 30 ms never gives the faulty side a
/// second dial, and then "bounded failover" is measuring nothing.
async fn rig(
    corpus: &Corpus,
    tls: Arc<rustls::ServerConfig>,
    chaos: TlsChaos,
    per_conn_bps: u64,
) -> (MockServer, TlsFront) {
    let mock = MockServer::start(
        corpus.articles.clone(),
        Chaos {
            throttle: Throttle {
                per_conn_bps,
                ..Default::default()
            },
            ..Default::default()
        },
    )
    .await;
    let front = TlsFront::start("127.0.0.1:0", mock.addr, tls, chaos)
        .await
        .expect("tls front");
    (mock, front)
}

fn pool_cfg(connections: usize) -> PoolConfig {
    PoolConfig {
        connections,
        window: 2,
        ramp_delay: Duration::ZERO,
        article_retries: 5,
        connect_backoff: Duration::from_millis(20),
        max_connect_attempts: 3,
        // The ladder is paced off `connect_backoff`; three bounces reach
        // the same "this server is dead" verdict as the shipped 75
        // without paying 75 real dials on a platform where a refused
        // connect is slow.
        cap_probe_bounces: 3,
        // DELIBERATELY `default()` rather than `PoolConfig::shipped()`:
        // the flat 30 s `read_timeout` is a thing under test here (the
        // header above spends a paragraph on it), and `shipped()` would
        // replace it with the adaptive two-phase budget. The other four
        // shipped knobs are speculation on top of a fleet that is one
        // faulty server, so they have nothing to add either.
        ..Default::default()
    }
}

struct Leg {
    elapsed: Duration,
    done: Vec<(Arc<str>, Vec<u8>)>,
    missing: Vec<Arc<str>>,
    failed: Vec<String>,
    stats: Vec<PoolStats>,
    /// The pool's own account of what went wrong, per host. A fault the
    /// client narrates as something else is a taxonomy bug, and this is
    /// where it shows.
    notes: Vec<String>,
}

/// One bounded fetch. A timeout is a WEDGE and reported as one - the
/// no-wedge half of the contract is this function, not a comment.
async fn run_leg(servers: Vec<(ServerConfig, PoolConfig)>, ids: &[String]) -> Result<Leg, String> {
    let live = LiveStats::for_servers(&servers);
    let servers: Vec<(ServerConfig, PoolConfig)> = servers
        .into_iter()
        .map(|(s, mut c)| {
            c.live = Some(live.clone());
            (s, c)
        })
        .collect();
    let reqs: Vec<ArticleReq> = ids.iter().cloned().map(ArticleReq::fresh).collect();
    let (tx, mut rx) = mpsc::channel(64);
    let t0 = Instant::now();
    let mut fetch = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });
    let collect = tokio::spawn(async move {
        let (mut done, mut missing, mut failed) = (Vec::new(), Vec::new(), Vec::new());
        while let Some(o) = rx.recv().await {
            match o {
                FetchOutcome::Done { id, raw } => done.push((id, raw)),
                FetchOutcome::Missing { id, .. } => missing.push(id),
                FetchOutcome::Failed { id, error } => failed.push(format!("{id}: {error}")),
            }
        }
        (done, missing, failed)
    });
    let say_notes = |live: &LiveStats| -> Vec<String> {
        live.recent_events(64)
            .into_iter()
            .map(|e| format!("{} {} {}", e.host, e.kind, e.detail))
            .collect()
    };
    let stats = match tokio::time::timeout(LEG_BUDGET, &mut fetch).await {
        // A wedge used to report the bound and NOTHING else, so a red CI
        // run left nobody anything to post-mortem - and the pool's own
        // event log is the discriminator. `stall` in a leg's `ends` is
        // one whole flat `read_timeout` (30 s, since `adaptive_timeout`
        // is off here): a session that went SILENT, not one the peer
        // closed. Two of those overrun this budget, which is what a
        // wedge here has actually been. Abort before returning too - a
        // detached pool would go on dialling through the next shape.
        Err(_) => {
            fetch.abort();
            return Err(format!(
                "WEDGE: no terminal state in {LEG_BUDGET:?}. The pool said:\n      {}",
                say_notes(&live).join("\n      ")
            ));
        }
        Ok(r) => r.map_err(|e| format!("fetch task died: {e}"))?,
    };
    let elapsed = t0.elapsed();
    let (done, missing, failed) = collect.await.map_err(|e| format!("collector died: {e}"))?;
    let notes = say_notes(&live);
    Ok(Leg {
        elapsed,
        done,
        missing,
        failed,
        stats,
        notes,
    })
}

/// Every article delivered exactly once, decoding to the corpus bytes it
/// claims to be. This is the "never marked verified" assertion in its
/// strongest form: a truncated or corrupted article that reached the
/// caller would either fail the yEnc gate or mismatch here.
fn check_output(leg: &Leg, corpus: &Corpus) -> Result<(), String> {
    if !leg.missing.is_empty() {
        return Err(format!(
            "{} article(s) reported MISSING - a transport fault must never \
             read as a missing post: {:?}",
            leg.missing.len(),
            leg.missing
        ));
    }
    if !leg.failed.is_empty() {
        return Err(format!(
            "{} article(s) FAILED: {:?}",
            leg.failed.len(),
            leg.failed
        ));
    }
    if leg.done.len() != corpus.ids.len() {
        return Err(format!(
            "{} of {} articles delivered",
            leg.done.len(),
            corpus.ids.len()
        ));
    }
    let mut seen = std::collections::HashSet::new();
    for (id, raw) in &leg.done {
        if !seen.insert(id.clone()) {
            return Err(format!("{id} delivered twice"));
        }
        let dec = nzbkit::yenc::decode(raw).map_err(|e| format!("{id}: yenc decode: {e}"))?;
        let off = dec.offset() as usize;
        let want = corpus.data.get(off..off + dec.data.len()).ok_or_else(|| {
            format!(
                "{id}: decoded range {off}..+{} is off the end",
                dec.data.len()
            )
        })?;
        if dec.data != want {
            return Err(format!("{id}: payload does not match the corpus"));
        }
    }
    Ok(())
}

/// One line of evidence per leg: what the front did to the connection
/// and what the pool made of it. A leg that passes for the wrong reason
/// (the fault never bit, the client never noticed) reads differently
/// here, and the rig log is where that gets caught.
fn say_leg(what: &str, leg: &Leg, engaged: &str) {
    println!(
        "  {what}: {engaged}, ends={:?}, reconnects={}, wall={:.1} s",
        leg.stats[0].ends,
        leg.stats[0].reconnects,
        leg.elapsed.as_secs_f64()
    );
}

/// Sessions must end as `peer` (an I/O-flavoured failure), never as
/// `protocol` - the taxonomy trap in the spec: a TLS fault lumped in
/// with a desync would feed the wrong ladder.
fn check_peer_classified(stats: &PoolStats, what: &str) -> Result<(), String> {
    if stats.ends.peer == 0 {
        return Err(format!(
            "{what}: no session ended as `peer` (ends={:?}) - the fault did not \
             engage, or it was classified as something else",
            stats.ends
        ));
    }
    if stats.ends.protocol > 0 {
        return Err(format!(
            "{what}: {} session(s) ended as `protocol` - a TLS transport fault \
             must not read as a protocol desync (ends={:?})",
            stats.ends.protocol, stats.ends
        ));
    }
    // `stall` is OUR deadline, not the peer's hangup: one whole flat
    // `read_timeout` (30 s - `adaptive_timeout` is off in `pool_cfg`)
    // spent on a session that simply went quiet. Every fault here is
    // meant to be seen at once, and these legs finish in tenths of a
    // second when they are, so a stall never means "the fault took a
    // while to land" - it means bytes were stranded upstream of the
    // client and nothing but the budget noticed. Pinning it here is
    // what turns that into a named failure instead of a leg that
    // silently eats 30 s and eventually overruns LEG_BUDGET as an
    // anonymous WEDGE, which is how it presented on windows-unit.
    if stats.ends.stall > 0 {
        return Err(format!(
            "{what}: {} session(s) ended as `stall` - a session went silent and \
             only the read_timeout ended it, so the fault was never delivered \
             (ends={:?})",
            stats.ends.stall, stats.ends
        ));
    }
    Ok(())
}

// ---------------------------------------------------------------- legs

/// The must-have: a TLS stream cut mid-body with no `close_notify`.
///
/// Two halves. First the direct one - a single connection, budget set
/// inside the first article, and `body()` MUST return an error: not
/// `Ok(None)` (that is "the server says 430"), not `Ok(Some(short))`.
/// Then the pool: every connection dies a few articles in, and the run
/// still has to finish with byte-exact output.
async fn truncate_shape(certs: &Certs, corpus: &Corpus) -> Result<Duration, String> {
    let tls = nzbkit::benchserve::tls_config(&certs.cert, &certs.key)
        .map_err(|e| format!("server tls config: {e}"))?;

    // Half one: the cut lands inside the first body.
    let (mock, front) = rig(
        corpus,
        tls.clone(),
        TlsChaos {
            truncate_after_bytes: 8 << 10,
            ..Default::default()
        },
        0,
    )
    .await;
    let sc = front.server_config("localhost", &mock);
    let mut conn = connect_retry(&sc).await?;
    match tokio::time::timeout(Duration::from_secs(20), conn.body(&corpus.ids[0])).await {
        Err(_) => return Err("BODY over a cut TLS stream hung".into()),
        Ok(Ok(Some(bytes))) => {
            return Err(format!(
                "BODY over a cut TLS stream returned {} bytes as a COMPLETE \
                 article - a truncated stream with no close_notify was \
                 accepted (article is {} bytes)",
                bytes.len(),
                corpus.articles[&corpus.ids[0]].len()
            ));
        }
        Ok(Ok(None)) => {
            return Err("BODY over a cut TLS stream read as a MISSING article".into());
        }
        Ok(Err(e)) => {
            // An I/O-flavoured error is what the pool counts as `peer`.
            // Printed because "which error" is the finding here: a
            // close_notify-less cut has to surface as a failed read, and
            // the exact wording is what the taxonomy is judged on.
            println!("  cut mid-body, client said: {e}");
            if !matches!(e, NntpError::Io(_) | NntpError::Closed | NntpError::Timeout) {
                return Err(format!("cut TLS stream classified as {e:?}, wanted I/O"));
            }
        }
    }
    drop((conn, front, mock));

    // Half two: recurrent cuts, whole corpus, byte-exact.
    let (mock, front) = rig(
        corpus,
        tls,
        TlsChaos {
            truncate_after_bytes: 192 << 10,
            ..Default::default()
        },
        0,
    )
    .await;
    let sc = front.server_config("localhost", &mock);
    let leg = run_leg(vec![(sc, pool_cfg(2))], &corpus.ids).await?;
    check_output(&leg, corpus)?;
    check_peer_classified(&leg.stats[0], "truncate")?;
    let cuts = front
        .counts
        .truncations
        .load(std::sync::atomic::Ordering::Relaxed);
    if cuts == 0 {
        return Err("no connection was actually cut - the profile did not engage".into());
    }
    say_leg("truncate", &leg, &format!("{cuts} cut(s), no close_notify"));
    Ok(leg.elapsed)
}

/// A bit flipped in the ciphertext after the handshake: the record's
/// AEAD tag fails at the client, which must drop the session and refetch
/// rather than hand the plaintext up.
async fn corrupt_record_shape(certs: &Certs, corpus: &Corpus) -> Result<Duration, String> {
    let tls = nzbkit::benchserve::tls_config(&certs.cert, &certs.key)
        .map_err(|e| format!("server tls config: {e}"))?;
    let (mock, front) = rig(
        corpus,
        tls,
        TlsChaos {
            corrupt_record_after_bytes: 160 << 10,
            ..Default::default()
        },
        0,
    )
    .await;
    let sc = front.server_config("localhost", &mock);
    let leg = run_leg(vec![(sc, pool_cfg(2))], &corpus.ids).await?;
    check_output(&leg, corpus)?;
    check_peer_classified(&leg.stats[0], "corrupt-record")?;
    let flips = front
        .counts
        .corruptions
        .load(std::sync::atomic::Ordering::Relaxed);
    if flips == 0 {
        return Err("no record was corrupted - the profile did not engage".into());
    }
    say_leg(
        "corrupt-record",
        &leg,
        &format!("{flips} flipped record(s)"),
    );
    Ok(leg.elapsed)
}

/// Both handshake variants, each with a clean twin carrying the job: the
/// faulty server must cost bounded time and no articles, and the client
/// must not report the corpus missing because one server cannot dial.
async fn handshake_shape(
    certs: &Certs,
    corpus: &Corpus,
    fault: HandshakeFault,
    what: &str,
) -> Result<Duration, String> {
    let tls = nzbkit::benchserve::tls_config(&certs.cert, &certs.key)
        .map_err(|e| format!("server tls config: {e}"))?;
    let (faulty_mock, faulty) = rig(
        corpus,
        tls.clone(),
        TlsChaos {
            handshake_fail: Some(fault),
            handshake_fail_count: u64::MAX,
            ..Default::default()
        },
        0,
    )
    .await;
    // ~400 KB/s per connection: the corpus takes about a second, which
    // is the window the faulty server's dial ladder runs in.
    let (twin_mock, twin) = rig(corpus, tls, TlsChaos::default(), 400_000).await;
    let servers = vec![
        (faulty.server_config("localhost", &faulty_mock), pool_cfg(2)),
        (twin.server_config("localhost", &twin_mock), pool_cfg(2)),
    ];
    let leg = run_leg(servers, &corpus.ids).await?;
    check_output(&leg, corpus)?;
    if leg.stats[0].bytes != 0 {
        return Err(format!(
            "{what}: the faulty server served {} bytes despite never completing \
             a handshake",
            leg.stats[0].bytes
        ));
    }
    if leg.stats[0].ever_connected {
        return Err(format!(
            "{what}: the faulty server reports a usable session - the fault did \
             not reach the client"
        ));
    }
    let faults = faulty
        .counts
        .handshake_faults
        .load(std::sync::atomic::Ordering::Relaxed);
    if faults == 0 {
        return Err(format!(
            "{what}: no handshake was broken - the profile did not engage"
        ));
    }
    // The dial cost of a server that can never hand over a session: the
    // give-up trap in the spec is a client that either grinds here or
    // writes the whole job off because one server cannot dial. The cap
    // is order-of-magnitude on purpose - the flap keepers spend ~36
    // dials, so anything under a hundred is politeness and anything
    // above it is a hot loop.
    let dials = faulty
        .counts
        .accepted
        .load(std::sync::atomic::Ordering::Relaxed);
    if dials > 100 {
        return Err(format!(
            "{what}: {dials} dials against a server that can never complete a \
             handshake, in a {:.1} s run - that is a hot loop",
            leg.elapsed.as_secs_f64()
        ));
    }
    println!("  {what}: {faults} broken handshake(s) over {dials} dial(s), pool said:");
    for n in leg.notes.iter().take(6) {
        println!("    {n}");
    }
    Ok(leg.elapsed)
}

/// Kill mid-body, then fail the reconnect's handshake once: dial-retry
/// and resume in one shape, which is where a client that treats a failed
/// dial as a dead server gives up on a server that is fine.
async fn resume_shape(certs: &Certs, corpus: &Corpus) -> Result<Duration, String> {
    let tls = nzbkit::benchserve::tls_config(&certs.cert, &certs.key)
        .map_err(|e| format!("server tls config: {e}"))?;
    let (mock, front) = rig(
        corpus,
        tls,
        TlsChaos {
            fault_during_resume: Some(192 << 10),
            ..Default::default()
        },
        0,
    )
    .await;
    let sc = front.server_config("localhost", &mock);
    let leg = run_leg(vec![(sc, pool_cfg(2))], &corpus.ids).await?;
    check_output(&leg, corpus)?;
    check_peer_classified(&leg.stats[0], "resume")?;
    let (cuts, faults) = (
        front
            .counts
            .truncations
            .load(std::sync::atomic::Ordering::Relaxed),
        front
            .counts
            .handshake_faults
            .load(std::sync::atomic::Ordering::Relaxed),
    );
    if cuts == 0 || faults == 0 {
        return Err(format!(
            "the shape did not engage: {cuts} cut(s), {faults} failed handshake(s)"
        ));
    }
    say_leg(
        "fault-during-resume",
        &leg,
        &format!("{cuts} cut(s) then {faults} failed reconnect handshake(s)"),
    );
    Ok(leg.elapsed)
}

/// The listener may not be up on the first tick; every other version of
/// this in the tree spins the same way.
async fn connect_retry(sc: &ServerConfig) -> Result<Connection, String> {
    let mut last = String::new();
    for _ in 0..50 {
        match Connection::connect(sc).await {
            Ok((c, _)) => return Ok(c),
            Err(e) => {
                last = e.to_string();
                tokio::time::sleep(Duration::from_millis(20)).await;
            }
        }
    }
    Err(format!("could not connect over TLS: {last}"))
}

// --------------------------------------------------------------- driver

#[test]
fn tls_fault_shapes() {
    let dir = std::env::temp_dir().join(format!("nzbkit-tlschaos-{}", std::process::id()));
    let _scratch = scratch::ScratchDir::attach(&dir);
    let certs = cert_chain(&dir);

    // SAFETY: this is the only test in this binary and nothing here has
    // built a `ClientConfig` yet - that is the one thing that reads this
    // variable, once, for the life of the process.
    unsafe { std::env::set_var("NZBFAST_EXTRA_CA", &certs.ca) };

    let rt = tokio::runtime::Builder::new_multi_thread()
        .enable_all()
        .build()
        .expect("runtime");
    let corpus = corpus();
    let alt = nzbkit::benchserve::tls_config(&certs.alt_cert, &certs.alt_key)
        .expect("alt server tls config");

    let results = rt.block_on(async {
        vec![
            (
                "truncate-no-close-notify",
                truncate_shape(&certs, &corpus).await,
            ),
            (
                "corrupt-record",
                corrupt_record_shape(&certs, &corpus).await,
            ),
            (
                "handshake-close",
                handshake_shape(&certs, &corpus, HandshakeFault::Close, "handshake-close").await,
            ),
            (
                "handshake-wrong-cert",
                handshake_shape(
                    &certs,
                    &corpus,
                    HandshakeFault::WrongCert(alt),
                    "handshake-wrong-cert",
                )
                .await,
            ),
            ("fault-during-resume", resume_shape(&certs, &corpus).await),
        ]
    });

    let mut failures = Vec::new();
    for (name, r) in results {
        match r {
            Ok(w) => println!("tls chaos {name}: OK in {:.1} s", w.as_secs_f64()),
            Err(e) => {
                println!("tls chaos {name}: FAIL - {e}");
                failures.push(format!("{name}: {e}"));
            }
        }
    }
    assert!(
        failures.is_empty(),
        "TLS fault shapes failed:\n  {}",
        failures.join("\n  ")
    );
}
