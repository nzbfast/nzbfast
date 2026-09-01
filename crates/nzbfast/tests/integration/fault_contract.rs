//! TODO 129 phase 3c: the fault CONTRACT, pinned as tests.
//!
//! The §111/§117 campaigns raced twenty-odd fault profiles against the
//! field and wrote the numbers down. Numbers in a document rot: what
//! keeps a fault shape honest over time is a contract that RUNS. This
//! suite is that contract, at in-process scale, over one profile per
//! fault family. The full matrix stays a bench-window activity
//! (the chaos matrix driver and its runbook, both in the private
//! bench tree).
//!
//! The five clauses, from the roadmap:
//!
//! 1. **No wedge** - the run reaches a TERMINAL state inside a
//!    profile-derived bound.
//! 2. **Bounded failover** - dials against the faulty server stay under
//!    a politeness cap (order of magnitude, never an exact count).
//! 3. **Correct provider accounting** - the per-server byte ledger the
//!    dashboard Providers card reads credits each server with what it
//!    actually served. The faulty server must never be credited with
//!    the clean twin's bytes.
//! 4. **Byte-valid resume** - SIGKILL inside a fault window, restart,
//!    output still hash-valid.
//! 5. **Resume without refetch** - the restart refetches only the gap.
//!
//! ## Where the profiles come from
//!
//! The fault shapes are NOT re-declared here. `src/chaos_serve.rs` is
//! compiled straight into this test via `#[path]` (the
//! watchlist_regressions.rs idiom - the source is not edited, only
//! included), so a leg here and a leg on the bench box run the same
//! `Chaos`. Two profile tables would drift the first time 3a/3b add a
//! shape to one of them.
//!
//! ## Where the bounds come from
//!
//! Wall bounds are the weakest kind of assertion and the easiest to
//! rot, so they are derived, written down, and never widened without a
//! diagnosis (memory nzbfast-daemon-test-flake). The recorded matrix
//! walls (the 5 Aug fault matrix: 300 MB / 408 articles / 8 conns x
//! 2 MB/s on an arm64 bench box) give the RATIO each fault costs over
//! clean: flap 42/22 = 1.9x, deadair 27/22 = 1.2x, brownout 26/22 =
//! 1.2x, corrupt (two-server) 18/22 = 0.8x. This suite's corpus is 1/50
//! of that, so those ratios shape the bounds while the measured walls
//! set their scale - see `BOUND_*` below for each number. The clause
//! these bounds exist to enforce is "not wedged", which is a difference
//! of minutes, not of percent: a 20% wall regression is the bench
//! matrix's job to catch, not this suite's.
//!
//! The other four clauses are ratio- and count-based, so they are
//! machine-independent and are the sharp end of this file.

// Held to `#[expect]` on 23 Aug 2026 and FULFILLED in every
// configuration measured - default, default + `heavy-tests`,
// `--no-default-features`, and `--target x86_64-pc-windows-gnu
// --features heavy-tests` - so it stays, as the falsifiable form. The
// sibling waiver in `watchlist_regressions.rs` was dead and is gone.
#![expect(dead_code)]

use crate::scratch;

use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::process::Command;
use std::sync::atomic::Ordering;
use std::time::{Duration, Instant};

use nzbkit::mock::{Chaos, MockServer, make_file_articles};

/// The profile table, compiled from its real source. `dead_code` is
/// allowed because this test uses `plan`/`PROFILES` and none of the
/// serving machinery around them.
use crate::chaos_serve;

// ---------------------------------------------------------------------------
// Corpus
// ---------------------------------------------------------------------------

/// Payload bytes per corpus file. Three of these is 6 MB - "tens of MB,
/// not 300" per the spec, and small enough that a leg is seconds even
/// on a cold CI runner.
const FILE_BYTES: usize = 2_000_000;
const FILES: usize = 3;
/// 48 KB articles -> 126 articles over the corpus. Enough for a fault
/// spread across the middle 30-90% of the queue (which is where
/// `spread_positions` puts them) to bite with healthy history behind
/// it, few enough that the whole leg fits in a couple of seconds.
const ARTICLE_BYTES: usize = 48_000;
/// Healthy per-connection ceiling handed to the profile table, bytes/s.
/// The matrix used 2 MB/s; this is the same number, so a profile whose
/// fault is expressed as a FRACTION of the healthy rate (flap's 0.4x,
/// slowconn's 1/40th) keeps its shape.
const PER_CONN_BPS: u64 = 2_000_000;
/// Connections per server for every leg.
const CONNS: u32 = 4;
/// Pipeline window per connection.
const WINDOW: u32 = 4;

/// Deterministic corpus bytes (chaos_serve's generator family, so a
/// corpus here and a corpus on the bench box have the same statistics).
fn corpus_data(len: usize, seed: u64) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            (i.wrapping_add(seed.wrapping_mul(0x9E37_79B9_7F4A_7C15))
                .wrapping_mul(2_654_435_761)
                >> 16) as u8
        })
        .collect()
}

/// One leg's corpus: the payloads (for the output hash gate), the
/// articles (for the mock), the NZB, and the article ids in NZB order
/// (which is what the profile table's fault placement walks).
struct Rig {
    dir: PathBuf,
    _scratch: scratch::ScratchDir,
    files: Vec<(String, Vec<u8>)>,
    articles: HashMap<String, Vec<u8>>,
    nzb_files: Vec<(String, Vec<(String, u64, u32)>)>,
    ids: Vec<String>,
}

impl Rig {
    fn new(tag: &str) -> Rig {
        let dir = std::env::temp_dir().join(format!("nzbfast-fc-{tag}-{}", std::process::id()));
        let guard = scratch::ScratchDir::attach(&dir);
        let mut articles = HashMap::new();
        let mut files = Vec::new();
        let mut nzb_files = Vec::new();
        for i in 0..FILES {
            let name = format!("fc-{:02}.bin", i + 1);
            let data = corpus_data(FILE_BYTES, 129 + i as u64);
            let segs = make_file_articles(
                &name,
                &data,
                ARTICLE_BYTES,
                &format!("fc{tag}s{i}"),
                &mut articles,
            );
            nzb_files.push((name.clone(), segs));
            files.push((name, data));
        }
        let ids = nzb_files
            .iter()
            .flat_map(|(_, segs)| segs.iter().map(|(id, _, _)| format!("<{id}>")))
            .collect();
        Rig {
            dir,
            _scratch: guard,
            files,
            articles,
            nzb_files,
            ids,
        }
    }

    fn write_nzb(&self) -> PathBuf {
        let mut xml = String::from(
            "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
             <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
        );
        for (name, segs) in &self.nzb_files {
            xml.push_str(&format!(
                "  <file poster=\"fc@test\" date=\"0\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n    \
                 <groups><group>mock.group</group></groups>\n    <segments>\n",
                segs.len()
            ));
            for (id, bytes, num) in segs {
                xml.push_str(&format!(
                    "      <segment bytes=\"{bytes}\" number=\"{num}\">{id}</segment>\n"
                ));
            }
            xml.push_str("    </segments>\n  </file>\n");
        }
        xml.push_str("</nzb>\n");
        let path = self.dir.join("test.nzb");
        std::fs::write(&path, xml).unwrap();
        path
    }

    /// Config in SERVER ORDER - the census prints one line per server in
    /// exactly this order, which is how a per-server assertion tells two
    /// mocks apart when both live on 127.0.0.1.
    fn write_config(&self, servers: &[&MockServer]) -> PathBuf {
        let ports: Vec<u16> = servers.iter().map(|s| s.addr.port()).collect();
        self.write_config_ports(&ports, false)
    }

    /// The same file by port, so a leg whose client-facing endpoint is
    /// NOT the mock (the §129 3b TLS legs dial the chaos TLS front, and
    /// the mock sits behind it on its own loopback port) can still write
    /// its config in server order.
    fn write_config_ports(&self, ports: &[u16], tls: bool) -> PathBuf {
        let entries: Vec<String> = ports
            .iter()
            .map(|p| format!("{{\"host\":\"127.0.0.1\",\"port\":{p},\"tls\":{tls}}}"))
            .collect();
        let path = self.dir.join("config.json");
        std::fs::write(&path, format!("{{\"servers\":[{}]}}", entries.join(","))).unwrap();
        path
    }

    /// A CA and a leaf for 127.0.0.1, PEM, in the leg's own directory.
    /// Returns (cert, key, ca-path) - the leaf is what the front serves
    /// and the CA is what the client is told to trust.
    ///
    /// Not one self-signed certificate: webpki refuses a CA:TRUE
    /// certificate presented as an end entity (`CaUsedAsEndEntity`),
    /// which has cost this project a bench rig once already. The SAN is
    /// the IP because that is what the config dials - verification is
    /// real here, not skipped.
    fn tls_pair(&self) -> (PathBuf, PathBuf, String) {
        let mut ca_params = rcgen::CertificateParams::new(Vec::new()).expect("ca params");
        ca_params.is_ca = rcgen::IsCa::Ca(rcgen::BasicConstraints::Unconstrained);
        ca_params
            .distinguished_name
            .push(rcgen::DnType::CommonName, "fault contract ca");
        let ca_key = rcgen::KeyPair::generate().expect("ca key");
        let ca_cert = ca_params.self_signed(&ca_key).expect("ca cert");
        let issuer = rcgen::Issuer::new(ca_params, ca_key);

        let mut leaf =
            rcgen::CertificateParams::new(vec!["127.0.0.1".to_string()]).expect("leaf params");
        leaf.distinguished_name
            .push(rcgen::DnType::CommonName, "127.0.0.1");
        let leaf_key = rcgen::KeyPair::generate().expect("leaf key");
        let leaf_cert = leaf.signed_by(&leaf_key, &issuer).expect("leaf cert");

        let (cert, key, ca) = (
            self.dir.join("leaf.pem"),
            self.dir.join("leaf.key"),
            self.dir.join("ca.pem"),
        );
        std::fs::write(&cert, leaf_cert.pem()).expect("write cert");
        std::fs::write(&key, leaf_key.serialize_pem()).expect("write key");
        std::fs::write(&ca, ca_cert.pem()).expect("write ca");
        (cert, key, ca.to_string_lossy().into_owned())
    }

    /// Total payload bytes the job must deliver.
    fn payload_bytes(&self) -> u64 {
        self.files.iter().map(|(_, d)| d.len() as u64).sum()
    }

    /// Clause 4's gate: every corpus file present, byte-for-byte. A size
    /// check is deliberately not enough - the corrupt and splitbrain
    /// families never change a length.
    fn assert_output_valid(&self, out: &Path) {
        for (name, data) in &self.files {
            let got = std::fs::read(out.join(name))
                .unwrap_or_else(|e| panic!("output {name} missing: {e}"));
            assert_eq!(
                got.len(),
                data.len(),
                "{name}: {} bytes on disk, {} expected",
                got.len(),
                data.len()
            );
            assert!(got == *data, "{name}: bytes differ from the source corpus");
        }
    }
}

// ---------------------------------------------------------------------------
// Running one leg
// ---------------------------------------------------------------------------

/// What the CLI's post-drain census said about one server. The census
/// prints `host` only, and both mocks live on 127.0.0.1, so servers are
/// identified by their ORDER in the config - see `Rig::write_config`.
#[derive(Debug, Clone, Copy)]
enum ServerCensus {
    /// `  <host>   12.3 MB · 4 conns, 0 reconnects`
    Connected {
        bytes: u64,
        conns: u64,
        reconnects: u64,
    },
    /// `  <host>   ⚠ no usable connection for the entire run`
    Dead,
}

impl ServerCensus {
    fn bytes(self) -> u64 {
        match self {
            ServerCensus::Connected { bytes, .. } => bytes,
            ServerCensus::Dead => 0,
        }
    }
}

/// Parse the per-server census block out of a `get` log, in config
/// order. Returns an empty vec if the run never reached the census,
/// which every caller treats as a failure rather than a pass - a
/// silently unparsed log must never read as a clean contract.
fn census(log: &str) -> Vec<ServerCensus> {
    let mut out = Vec::new();
    for line in log.lines() {
        let t = line.trim();
        if t.contains("no usable connection for the entire run") {
            out.push(ServerCensus::Dead);
            continue;
        }
        // "127.0.0.1     12.3 MB · 4 conns, 0 reconnects[ ...]"
        let Some((mb, rest)) = t.split_once(" MB · ") else {
            continue;
        };
        let Some(mb) = mb
            .split_whitespace()
            .last()
            .and_then(|v| v.parse::<f64>().ok())
        else {
            continue;
        };
        let Some((conns, rest)) = rest.split_once(" conns, ") else {
            continue;
        };
        let (Ok(conns), Some(reconnects)) = (
            conns.trim().parse::<u64>(),
            rest.split_whitespace().next().and_then(|v| v.parse().ok()),
        ) else {
            continue;
        };
        out.push(ServerCensus::Connected {
            // The census rounds to 0.1 MB; every assertion below carries
            // slack far wider than that.
            bytes: (mb * 1e6) as u64,
            conns,
            reconnects,
        });
    }
    out
}

/// One finished contract leg: the servers (still holding their counters)
/// and everything the run said.
struct Leg {
    profile: &'static str,
    faulty: MockServer,
    twin: Option<MockServer>,
    log: String,
    ok: bool,
    wall: Duration,
    census: Vec<ServerCensus>,
    out: PathBuf,
}

impl Leg {
    /// Servers in config order: faulty first, clean twin second.
    fn servers(&self) -> Vec<&MockServer> {
        let mut v = vec![&self.faulty];
        v.extend(self.twin.as_ref());
        v
    }

    /// Clause 1. `bound` is derived per profile; the message prints the
    /// measured wall so a tightening (or a diagnosis) has the number it
    /// needs without a re-run.
    fn assert_no_wedge(&self, bound: Duration) {
        assert!(
            self.ok,
            "{}: run did not reach a clean terminal state\n{}",
            self.profile, self.log
        );
        assert!(
            self.wall <= bound,
            "{}: {:.1}s wall exceeds the {:.0}s bound - diagnose before widening it\n{}",
            self.profile,
            self.wall.as_secs_f64(),
            bound.as_secs_f64(),
            self.log
        );
        eprintln!(
            "[contract] {}: wall {:.2}s (bound {:.0}s)",
            self.profile,
            self.wall.as_secs_f64(),
            bound.as_secs_f64()
        );
    }

    /// Clause 2. The reference is the flap keepers' politeness number -
    /// ~36 dials at the capped server on a 300 MB corpus, against
    /// NZBGet's 217 for the same shape. This corpus is 1/50 the size, so
    /// the assertion is order-of-magnitude: a client that PACES its
    /// redials lands in the tens, one that hammers lands in the
    /// hundreds-to-thousands, and only that difference is being pinned.
    fn assert_bounded_dials(&self, cap: u64) {
        let dials = self.faulty.accepted.load(Ordering::Relaxed);
        assert!(
            dials <= cap,
            "{}: {dials} dials at the faulty server exceeds the {cap} cap \
             (the flap reference is ~36 on a 50x larger corpus; hammering is \
             the failure this pins)\n{}",
            self.profile,
            self.log
        );
        eprintln!(
            "[contract] {}: {dials} dials at the faulty server",
            self.profile
        );
    }

    /// Clause 3. Two independent witnesses: the client's own per-server
    /// ledger (the census, which reads the same counter the dashboard
    /// Providers card does) and each mock's `bytes_out`.
    ///
    /// The sharp half is the upper bound: a server can never be credited
    /// with more than it put on the wire, so an attribution bug that
    /// bills the twin's bytes to the faulty server trips here at once.
    /// The lower bound is deliberately absent per-server - bytes written
    /// into a socket the client abandoned (a stalled or dropped session)
    /// are legitimately never credited - and is asserted on the TOTAL
    /// instead, so a ledger that simply loses bytes cannot pass either.
    fn assert_provider_accounting(&self, payload: u64) {
        let servers = self.servers();
        assert_eq!(
            self.census.len(),
            servers.len(),
            "{}: census names {} servers, config has {}\n{}",
            self.profile,
            self.census.len(),
            servers.len(),
            self.log
        );
        // 0.1 MB of census rounding, plus one article of slack for the
        // status lines and framing the client counts and the mock's
        // body-byte counter does not.
        let slack = 100_000 + ARTICLE_BYTES as u64;
        for (i, (c, srv)) in self.census.iter().zip(&servers).enumerate() {
            let wrote = srv.bytes_out.load(Ordering::Relaxed);
            let credited = c.bytes();
            assert!(
                credited <= wrote + slack,
                "{}: server {i} credited with {credited} bytes but only wrote {wrote} \
                 - the ledger is billing it for another server's work\n{}",
                self.profile,
                self.log
            );
        }
        let credited: u64 = self.census.iter().map(|c| c.bytes()).sum();
        assert!(
            credited >= payload,
            "{}: the whole per-server ledger totals {credited} bytes for a {payload}-byte \
             payload - bytes are going uncredited\n{}",
            self.profile,
            self.log
        );
        let per: Vec<String> = self
            .census
            .iter()
            .zip(&servers)
            .map(|(c, s)| {
                format!(
                    "{:.1}/{:.1} MB",
                    c.bytes() as f64 / 1e6,
                    s.bytes_out.load(Ordering::Relaxed) as f64 / 1e6
                )
            })
            .collect();
        eprintln!(
            "[contract] {}: credited/served per server = {}",
            self.profile,
            per.join(", ")
        );
    }

    /// Clause 5, in its steady-state form: a run that never crashed
    /// re-requests an article only when the fault forced it to.
    ///
    /// Counted FLEET-WIDE against the article count, not per server: a
    /// CRC steer asks the twin for a body the faulty server already
    /// served, and that is a refetch the job paid for even though
    /// neither server saw the same id twice. Per-server repeat counts
    /// score that as zero, which is the reading that would let an
    /// unbounded cross-server retry loop pass. `budget` is the
    /// profile's own designed refetch count plus in-flight slack.
    ///
    /// The 430 family is the one exception, and a leg added here for it
    /// must NOT use this function. An absent article is legitimately
    /// asked once per server - each server runs its own ladder to its
    /// own "no" - so a fleet-wide count reads every one of those as a
    /// refetch and indicts a client that did nothing wrong. Count that
    /// family per server (§129 3d's provider_demote_rig.rs does), and
    /// pick its budget with `Chaos::echo_missing_id` in hand: whether a
    /// provider echoes the message-id on its 430 decides whether the
    /// pool charges the article on arrival or requeues it uncharged for
    /// a soft_430 confirming repeat, which exactly DOUBLES dispatches
    /// for one identical fault (3d measured 400 against 1172). None of
    /// the profiles below serve a 430, so nothing here depends on it
    /// today.
    ///
    /// The rule both ways: per server for a fault each server answers
    /// independently, fleet-wide for anything that moves work ACROSS
    /// servers.
    fn assert_refetch_bounded(&self, articles: u64, budget: u64) {
        let requests: u64 = self
            .servers()
            .iter()
            .map(|s| s.body_log.lock().map(|l| l.len()).unwrap_or(0) as u64)
            .sum();
        let extra = requests.saturating_sub(articles);
        assert!(
            extra <= budget,
            "{}: {requests} article requests for {articles} articles - {extra} refetches \
             exceeds the {budget} the profile can justify\n{}\n{}",
            self.profile,
            self.servers()
                .iter()
                .enumerate()
                .map(|(i, s)| s.serve_count_line(&format!("server{i}")))
                .collect::<Vec<_>>()
                .join("\n"),
            self.log
        );
        eprintln!(
            "[contract] {}: {extra} refetches over {articles} articles (budget {budget})",
            self.profile
        );
    }
}

/// The two-server legs' one rig concession, and the same one
/// the chaos matrix driver makes (`is_twosrv && steer=...`).
///
/// CRC retry-elsewhere ships ON, but its gate is a same-level peer on a
/// DIFFERENT HOST: a genuine same-host sibling serves the same wrong
/// copy, so paying the forced per-article CRC there would buy nothing.
/// Every clean twin on this rig is a second listener on 127.0.0.1, so
/// the shipped gate reads "no elsewhere exists" and the steer stays off.
/// Without this the corrupt leg fails as a RIG artefact and reads as a
/// client regression - which is exactly what happened live on 6 Aug and
/// is why the matrix carries the same three lines.
fn twin_env(two_server: bool) -> Vec<(String, String)> {
    if two_server {
        vec![("NZBFAST_CRC_STEER".into(), "1".into())]
    } else {
        Vec::new()
    }
}

/// Build the mocks for `profile` from the shared profile table and run
/// one `nzbfast get` against them.
async fn run_leg(profile: &'static str, rig: &Rig, fault_count: Option<usize>) -> Leg {
    let plan = chaos_serve::plan(profile, &rig.ids, PER_CONN_BPS, 0, 129, fault_count)
        .unwrap_or_else(|e| panic!("profile {profile}: {e}"));
    eprintln!("[contract] {profile}: {}", plan.onset_note);
    let twin_articles = plan.twin.is_some().then(|| rig.articles.clone());
    let faulty = MockServer::start(rig.articles.clone(), plan.chaos).await;
    let twin = match plan.twin {
        Some(chaos) => Some(MockServer::start(twin_articles.unwrap_or_default(), chaos).await),
        None => None,
    };
    let mut servers: Vec<&MockServer> = vec![&faulty];
    servers.extend(twin.as_ref());
    let cfg = rig.write_config(&servers);
    let nzb = rig.write_nzb();
    let out = rig.dir.join(format!("out-{profile}"));
    let started = Instant::now();
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let env = twin_env(twin.is_some());
        tokio::task::spawn_blocking(move || get(&cfg, &nzb, &out, &env))
            .await
            .unwrap()
    };
    let wall = started.elapsed();
    Leg {
        profile,
        faulty,
        twin,
        census: census(&log),
        log,
        ok,
        wall,
        out,
    }
}

/// The §129 3b TLS legs: same shape as [`run_leg`], with the chaos TLS
/// front (`nzbkit::mock_tls`) in front of the mock and the client
/// dialling THAT. The mock keeps its own loopback port, so every
/// server-side counter the clauses read - serve counts, bytes_out,
/// accepted - still means what it means on a plain leg.
async fn run_leg_tls(profile: &'static str, rig: &Rig, fault_count: Option<usize>) -> Leg {
    let (cert, key, ca) = rig.tls_pair();
    let tls = nzbkit::benchserve::tls_config(&cert, &key).expect("rig server tls config");
    let plan = chaos_serve::plan_with_tls(
        profile,
        &rig.ids,
        PER_CONN_BPS,
        0,
        129,
        fault_count,
        chaos_serve::TlsPlanIn {
            article_size: ARTICLE_BYTES,
            articles_per_conn: fault_count.unwrap_or(chaos_serve::TLS_ARTICLES_PER_CONN),
            // The closed-handshake variant: a second certificate would
            // only change which error the client raises, and this suite
            // pins terminal states, not error strings.
            alt_cert: None,
        },
    )
    .unwrap_or_else(|e| panic!("profile {profile}: {e}"));
    eprintln!("[contract] {profile}: {}", plan.onset_note);
    assert!(
        plan.twin.is_none(),
        "{profile}: this helper only wires a single server's front"
    );
    let faulty = MockServer::start(rig.articles.clone(), plan.chaos).await;
    let front = nzbkit::mock_tls::TlsFront::start("127.0.0.1:0", faulty.addr, tls, plan.tls)
        .await
        .expect("tls front");
    let cfg = rig.write_config_ports(&[front.addr.port()], true);
    let nzb = rig.write_nzb();
    let out = rig.dir.join(format!("out-{profile}"));
    let started = Instant::now();
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        // The rig certificate is self-signed; this is how a client is
        // told to trust it (there is deliberately no skip-verification
        // switch). Per-child env, so nothing about this process changes.
        let env = vec![("NZBFAST_EXTRA_CA".to_string(), ca)];
        tokio::task::spawn_blocking(move || get(&cfg, &nzb, &out, &env))
            .await
            .unwrap()
    };
    let wall = started.elapsed();
    // The fault has to have engaged, or every clause below is measuring
    // a clean TLS run and would pass for the wrong reason.
    let c = &front.counts;
    eprintln!(
        "[contract] {profile}: tls dials={} handshakes={} broken={} cuts={} flips={}",
        c.accepted.load(Ordering::Relaxed),
        c.handshakes.load(Ordering::Relaxed),
        c.handshake_faults.load(Ordering::Relaxed),
        c.truncations.load(Ordering::Relaxed),
        c.corruptions.load(Ordering::Relaxed),
    );
    assert!(
        c.truncations.load(Ordering::Relaxed) > 0,
        "{profile}: no connection was cut - the TLS profile did not engage\n{log}"
    );
    Leg {
        profile,
        faulty,
        twin: None,
        census: census(&log),
        log,
        ok,
        wall,
        out,
    }
}

/// `nzbfast get` against the mocks, run to completion.
fn get(config: &Path, nzb: &Path, out: &Path, extra_env: &[(String, String)]) -> (String, bool) {
    let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
    // Keyless on purpose, the same deliberate opt-out the other CLI
    // suites take (see e2e.rs run_get_win), and no enrichment worker may
    // reach the real internet from a test (CLAUDE.md invariant 5).
    cmd.env("NZBFAST_OPEN", "1").env("NZBFAST_NO_ENRICH", "1");
    // The census lines this suite parses are INFO, and the child falls
    // back to ambient RUST_LOG when NZBFAST_LOG is unset - a parent
    // shell exporting RUST_LOG=warn silently emptied every census and
    // failed all eight contract tests with no product defect (Codex
    // sweep 24 Aug, F-22; third recurrence of the class, see
    // tests/daemon.rs). Pin INFO at the child.
    cmd.env("NZBFAST_LOG", "info").env_remove("RUST_LOG");
    for (k, v) in extra_env {
        cmd.env(k, v);
    }
    cmd.arg("--config")
        .arg(config)
        .arg("get")
        .arg(nzb)
        .arg("--out")
        .arg(out)
        .arg("--connections")
        .arg(CONNS.to_string())
        .arg("--window")
        .arg(WINDOW.to_string())
        .arg("--decoders")
        .arg("4");
    // Not `.output()`: cargo unlinks and re-links the uplifted
    // `target/debug/nzbfast` on every invocation, so a concurrent cargo
    // command makes this spawn answer NotFound for a binary that is
    // there before and after. See `harness::spawn_under_test`.
    let o = crate::harness::output_under_test(&mut cmd);
    (
        // stdout/stderr are separate pipes with no shared clock - label
        // the seam so a bare join can't be misread as one chronology.
        // Copy the comment along with the string.
        format!(
            "{}\n----- stderr (a SEPARATE stream: not in sequence with stdout above) -----\n{}",
            String::from_utf8_lossy(&o.stdout),
            String::from_utf8_lossy(&o.stderr)
        ),
        o.status.success(),
    )
}

// ---------------------------------------------------------------------------
// Bounds
//
// What a wall bound here is FOR: catching a wedge. The failure it exists
// to name is SABnzbd's brownout on the §111 matrix - four DNFs across two
// boxes, 450-900 s against a 26 s field - not a percentage. Percentages
// are the bench matrix's job, on a bench box, against a 300 MB corpus.
//
// So every bound is the measured wall on the dev box (debug build,
// M-series, 8 Aug 2026, printed by each leg as it runs) rounded up to a
// whole number of seconds at roughly an order of magnitude of headroom.
// A CI runner several times slower than the dev box still passes; a wedge
// is orders of magnitude the other way and cannot.
//
// Widening one of these is a code change that needs a diagnosis in its
// commit message. The flake this discipline exists for (memory
// nzbfast-daemon-test-flake) was a margin widened without one.
// ---------------------------------------------------------------------------

/// Clean: 6 MB over 4 connections capped at 2 MB/s each is under a
/// second of wire time; the rest is process start, NZB parse and the
/// settle pass. Measured 1.17s.
const BOUND_CLEAN: Duration = Duration::from_secs(20);
/// Flap: the matrix ratio is 1.9x clean, but at this scale the cost is
/// not the ratio - it is the per-dial session backoff while the faulty
/// server refuses, which is a fixed number of seconds however big the
/// corpus. Measured 1.10s; double the clean bound for the ratio.
const BOUND_FLAP: Duration = Duration::from_secs(40);
/// Dead air: matrix ratio 1.2x plus a fixed cost the ratio hides - each
/// stalled article burns one pre-byte budget (~4s at the adaptive floor)
/// and 4 stalls over 4 connections is a couple of budgets deep.
/// Measured 3.27s.
const BOUND_DEADAIR: Duration = Duration::from_secs(40);
/// Brownout: matrix ratio 1.2x; the faulty server goes mute after 40% of
/// the corpus and the twin carries the rest, so the cost is the fleet's
/// detour through the read bound - again a fixed number of seconds.
/// Measured 3.05s.
const BOUND_BROWNOUT: Duration = Duration::from_secs(40);
/// Corrupt: the matrix has this FASTER than clean (18s vs 22s) because
/// it is a two-server profile; CRC retry-elsewhere adds one refetch per
/// damaged article and no stall at all. Measured 0.79s.
const BOUND_CORRUPT: Duration = Duration::from_secs(20);
/// Crash-and-resume: two full runs plus the wait for the kill mark, on
/// a deliberately paced server (10 ms per body). Measured 2.88s.
const BOUND_CRASH: Duration = Duration::from_secs(60);
/// Shaped (M7b.2): the shaped server serves correctly at 1/10th
/// per-conn rate beside a full-speed twin, so the wire time is the
/// twin's plus whatever tail the shaped server's last pipelines hold -
/// sub-second each at this scale. Measured 2.61s; an order of
/// magnitude of headroom, same discipline as the rest.
const BOUND_SHAPED: Duration = Duration::from_secs(30);
/// TLS truncation (§129 3b): one server, every connection cut 8
/// articles in with no close_notify, so the cost is a redial - a real
/// handshake, not just a TCP connect - per cut, plus the in-flight
/// articles each cut requeues. 16 cuts over the corpus. Measured 3.33s;
/// the dead-air bound for the same reason (a fixed number of seconds,
/// not a ratio).
const BOUND_TLS_TRUNCATE: Duration = Duration::from_secs(40);

/// Politeness cap on dials at the faulty server, all profiles. The flap
/// reference is ~36 dials on a corpus 50x this one; NZBGet's hammering
/// on the same shape is 217. 150 sits between the two: a paced client
/// cannot reach it at this scale, a hammering one blows through it.
const DIAL_CAP: u64 = 150;

// ---------------------------------------------------------------------------
// The contract, one leg per fault family
// ---------------------------------------------------------------------------

/// Clean baseline. Every clause at its strictest: nothing is refetched,
/// every byte is credited to the one server that served it, and the
/// output is the corpus.
#[tokio::test(flavor = "multi_thread")]
async fn contract_clean() {
    let rig = Rig::new("clean");
    let articles = rig.ids.len() as u64;
    let leg = run_leg("clean", &rig, None).await;
    leg.assert_no_wedge(BOUND_CLEAN);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // Zero, not "a few": on a healthy single server every article is
    // fetched exactly once, and any drift from that is a real finding.
    leg.assert_refetch_bounded(articles, 0);
    rig.assert_output_valid(&leg.out);
}

/// Flap family (the eweka IP-cap shape): accept_cap=2 + drop_after=1 on
/// the faulty server, clean twin beside it. The clause that matters here
/// is accounting - a server that dies after one body per session must be
/// credited with one body per session, not with the twin's throughput.
#[tokio::test(flavor = "multi_thread")]
async fn contract_flap() {
    let rig = Rig::new("flap");
    let articles = rig.ids.len() as u64;
    let leg = run_leg("flap", &rig, None).await;
    leg.assert_no_wedge(BOUND_FLAP);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // Every session death drops whatever that session had in flight, so
    // the refetch budget is one window per dial the faulty server took.
    let dials = leg.faulty.accepted.load(Ordering::Relaxed);
    leg.assert_refetch_bounded(
        articles,
        dials * WINDOW as u64 + CONNS as u64 * WINDOW as u64,
    );
    rig.assert_output_valid(&leg.out);
    // The faulty server serves one body per accepted session and the
    // twin serves the rest: an accounting bug that reversed that would
    // still pass a total-bytes check, so pin the shape.
    let twin = leg.twin.as_ref().expect("flap is a two-server profile");
    assert!(
        leg.census[1].bytes() > leg.census[0].bytes(),
        "flap: the capped server was credited with {} bytes against the twin's {} \
         (mock says {} vs {})\n{}",
        leg.census[0].bytes(),
        leg.census[1].bytes(),
        leg.faulty.bytes_out.load(Ordering::Relaxed),
        twin.bytes_out.load(Ordering::Relaxed),
        leg.log
    );
}

/// Dead-air family: a spread of articles hang before the status line on
/// their FIRST request and answer the retry. The designed refetch count
/// is therefore exactly the fault count, which makes this the sharpest
/// steady-state test of clause 5.
#[tokio::test(flavor = "multi_thread")]
async fn contract_deadair() {
    let rig = Rig::new("deadair");
    // 4 of 126 articles = 3%, the same fraction the matrix raced
    // (12 of 408). The profile's own default is 12, which at this
    // corpus size would be 10% - a different shape, not a smaller one.
    let stalls = 4;
    let articles = rig.ids.len() as u64;
    let leg = run_leg("deadair", &rig, Some(stalls)).await;
    leg.assert_no_wedge(BOUND_DEADAIR);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // One retry per stalled article by design, plus the articles that
    // were in flight on the session the stall killed.
    leg.assert_refetch_bounded(articles, stalls as u64 + stalls as u64 * WINDOW as u64);
    rig.assert_output_valid(&leg.out);
}

/// Brownout: the faulty server goes mute mid-run and never returns, with
/// a clean twin beside it. This is the wedge shape - it took SABnzbd to
/// four DNFs across two boxes in the §111 matrix - so clause 1 is the
/// point, and clause 3 pins that the mute server keeps credit for
/// exactly the 40% it served before going dark.
#[tokio::test(flavor = "multi_thread")]
async fn contract_brownout() {
    let rig = Rig::new("brownout");
    let articles = rig.ids.len() as u64;
    let leg = run_leg("brownout", &rig, None).await;
    leg.assert_no_wedge(BOUND_BROWNOUT);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // Every article parked in a browned-out session is refetched from
    // the twin; the fleet can have at most CONNS x WINDOW parked, and
    // the client may spend a second detour before it stops asking.
    leg.assert_refetch_bounded(articles, 3 * CONNS as u64 * WINDOW as u64);
    rig.assert_output_valid(&leg.out);
    let served_faulty = leg.faulty.served.load(Ordering::Relaxed);
    assert!(
        served_faulty > 0,
        "brownout: the faulty server served nothing before going mute - the \
         profile did not engage, so nothing below was tested\n{}",
        leg.log
    );
}

/// Corrupt family: ~10% of the faulty server's articles serve flipped
/// bytes (yEnc CRC fails); the twin holds good copies. CRC
/// retry-elsewhere (§114, default-on with 2+ servers) has to turn that
/// into a byte-perfect finish, and the re-fetches it spends are the
/// refetch budget.
#[tokio::test(flavor = "multi_thread")]
async fn contract_corrupt() {
    let rig = Rig::new("corrupt");
    let damaged = rig.ids.len() / 10;
    let articles = rig.ids.len() as u64;
    let leg = run_leg("corrupt", &rig, Some(damaged)).await;
    leg.assert_no_wedge(BOUND_CORRUPT);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // One retry elsewhere per damaged article, plus in-flight slack.
    leg.assert_refetch_bounded(articles, 2 * damaged as u64 + CONNS as u64 * WINDOW as u64);
    // The whole point of the family: the output is the corpus, byte for
    // byte, and no size gate could tell.
    rig.assert_output_valid(&leg.out);
}

/// Shaped family (M7b.2, the Giganews account-shaping shape): the
/// shaped server serves CORRECT bytes at 1/10th of the healthy per-conn
/// rate, full-speed twin beside it. Nothing ever faults, so what this
/// leg pins is that a merely-slow provider costs no failover churn:
/// no dial storm (slow is not flapping), every byte credited to the
/// server that moved it, byte-perfect output - and a refetch budget
/// that caps what the racing machinery may spend against the shaped
/// server's stragglers. A dup storm against a slow-but-honest provider
/// is the regression this leg exists to catch (the tail-fanout
/// refetch dup-storm - 33-43 dups, 0 won - is the standing example of
/// a racing rule meeting a steer path badly).
#[tokio::test(flavor = "multi_thread")]
async fn contract_shaped() {
    let rig = Rig::new("shaped");
    let articles = rig.ids.len() as u64;
    let leg = run_leg("shaped", &rig, None).await;
    leg.assert_no_wedge(BOUND_SHAPED);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // No fault forces a single refetch; every extra request is racing
    // spend. The tail machinery may race what the shaped server's
    // pipelines hold at queue-dry - a fleet's worth of in-flight
    // articles - and not article-by-article all run long. Measured 9
    // on the dev box (the 3c round measured 6 tail refetches on CLEAN
    // at bench scale: tail dups are scale-luck, not damage).
    leg.assert_refetch_bounded(articles, 2 * CONNS as u64 * WINDOW as u64);
    rig.assert_output_valid(&leg.out);
    // The shaping must have engaged AND not have demoted the server:
    // a shaped provider is net-positive (§129 3d) and work-conserving
    // self-clocking should leave it carrying roughly its rate share
    // (~1/11th of the fleet). Zero bytes here means something decided
    // a slow server should not fetch - the demotion this design
    // explicitly does not build.
    let shaped_bytes = leg.census[0].bytes();
    assert!(
        shaped_bytes > 0,
        "shaped: the shaped server served nothing - a slow provider \
         was effectively demoted (3d closed this)\n{}",
        leg.log
    );
    let twin_bytes = leg.census[1].bytes();
    assert!(
        twin_bytes > shaped_bytes,
        "shaped: the full-speed twin ({twin_bytes} B) should out-serve the \
         shaped server ({shaped_bytes} B) under self-clocking\n{}",
        leg.log
    );
}

/// TLS family (§129 3b): the transport itself fails. Every connection
/// is cut a few articles in with NO close_notify - the truncation-attack
/// shape - and the client has to treat each cut as a transport failure,
/// requeue what was in flight, and finish byte-perfect from ONE server.
///
/// The family's own assertions (which error the client raises, that a
/// partial body is never accepted as complete) belong to and live in
/// `crates/nzbkit/tests/integration/tls_chaos.rs`; what this leg adds is the five
/// contract clauses over the whole daemon-scale path.
#[tokio::test(flavor = "multi_thread")]
async fn contract_tls_truncate() {
    let rig = Rig::new("tlstruncate");
    let articles = rig.ids.len() as u64;
    let leg = run_leg_tls("tlstruncate", &rig, None).await;
    leg.assert_no_wedge(BOUND_TLS_TRUNCATE);
    leg.assert_bounded_dials(DIAL_CAP);
    leg.assert_provider_accounting(rig.payload_bytes());
    // A cut requeues whatever that connection had in flight, so the
    // shape's own cost is one window per cut, and the cuts are the
    // corpus over the per-connection budget: 126/8 = 16 cuts (exactly
    // what the front reports), 16 x 4 = 64, plus a fleet's worth of
    // in-flight slack. Measured 49.
    let cuts = articles / chaos_serve::TLS_ARTICLES_PER_CONN as u64;
    leg.assert_refetch_bounded(articles, (cuts + CONNS as u64) * WINDOW as u64);
    // The point of the family: a stream that ended without close_notify
    // never contributed a byte to this file.
    rig.assert_output_valid(&leg.out);
}

// ---------------------------------------------------------------------------
// Clause 4 + 5: SIGKILL inside a fault window
// ---------------------------------------------------------------------------

/// Kill the client with SIGKILL while a fault is engaged, restart it,
/// and hold the resume to both halves of the contract: the final output
/// is byte-valid (clause 4) and the second run refetches only the gap
/// (clause 5), measured from the mock's own per-article serve counts.
///
/// The profile is `deadair` on a single server: its faults sit in the
/// middle 30-90% of the queue, which is exactly where a kill at ~40%
/// lands, and its designed refetch count is a known small number rather
/// than the open-ended churn a session-loss profile produces. The
/// documented §100 exceptions do not apply here - this is a plain
/// payload corpus, no crypto and no nested children, so the resume owes
/// us the gap and nothing more (memory nzbfast-held-article-journal).
#[tokio::test(flavor = "multi_thread")]
async fn contract_crash_in_fault_window() {
    let rig = Rig::new("crash");
    let stalls = 4;
    let plan = chaos_serve::plan("deadair", &rig.ids, PER_CONN_BPS, 0, 129, Some(stalls))
        .expect("deadair profile");
    // Pace the bodies so a kill at 40% is reachable: unthrottled, the
    // whole corpus can land before the poll loop ever sees the mark,
    // and a kill after completion resumes nothing (the same trap the
    // e2e resume test documents).
    let chaos = Chaos {
        delay_ms: 10,
        ..plan.chaos
    };
    let srv = MockServer::start(rig.articles.clone(), chaos).await;
    let cfg = rig.write_config(&[&srv]);
    let nzb = rig.write_nzb();
    let out = rig.dir.join("out-crash");
    let total = rig.ids.len() as u64;
    let started = Instant::now();

    // Run 1: SIGKILL once ~40% of the articles are served AND the
    // journal holds progress for run 2 to resume from.
    {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        let served = srv.served.clone();
        tokio::task::spawn_blocking(move || {
            let mut cmd = Command::new(env!("CARGO_BIN_EXE_nzbfast"));
            cmd.env("NZBFAST_OPEN", "1")
                .env("NZBFAST_NO_ENRICH", "1")
                // Same INFO pin as `get` above: this run's census is
                // parsed too, and ambient RUST_LOG=warn empties it.
                .env("NZBFAST_LOG", "info")
                .env_remove("RUST_LOG")
                .arg("--config")
                .arg(&cfg)
                .arg("get")
                .arg(&nzb)
                .arg("--out")
                .arg(&out)
                .arg("--connections")
                .arg(CONNS.to_string())
                .arg("--window")
                .arg(WINDOW.to_string());
            // Same uplift window as the `get` runner above.
            let mut child = crate::harness::spawn_under_test(&mut cmd);
            let deadline = Instant::now() + Duration::from_secs(30);
            let journal = out.join(".nzbfast.journal");
            while served.load(Ordering::Relaxed) < total * 2 / 5
                || !std::fs::read_to_string(&journal).is_ok_and(|s| s.lines().count() > 1)
            {
                if Instant::now() > deadline {
                    break;
                }
                std::thread::sleep(Duration::from_millis(5));
            }
            child.kill().unwrap(); // SIGKILL
            let _ = child.wait();
        })
        .await
        .unwrap();
    }
    let recorded_at_kill = nzbkit::journal::Journal::peek(&out)
        .map(|r| r.recorded_ids())
        .unwrap_or_default();
    let served_run1 = srv.served.load(Ordering::Relaxed);
    assert!(
        served_run1 >= total * 2 / 5,
        "run 1 made no progress ({served_run1}/{total}) - nothing below was tested"
    );
    // What run 1 asked for, so run 2's re-requests are attributable.
    let asked_run1 = srv.serve_counts();

    // Run 2: resume, complete, and stay honest about what it refetched.
    let (log, ok) = {
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        tokio::task::spawn_blocking(move || get(&cfg, &nzb, &out, &[]))
            .await
            .unwrap()
    };
    let wall = started.elapsed();
    assert!(ok, "resume run failed\n{log}");
    assert!(
        wall <= BOUND_CRASH,
        "crash+resume took {:.1}s against the {:.0}s bound - diagnose before \
         widening it\n{log}",
        wall.as_secs_f64(),
        BOUND_CRASH.as_secs_f64()
    );
    assert!(
        log.contains("[resume] ") && log.contains("already on disk"),
        "no resume banner:\n{log}"
    );

    // Clause 4: byte-valid output after a SIGKILL mid-fault.
    rig.assert_output_valid(&out);

    // Clause 5: the refetch is bounded by the gap. An article run 1
    // asked for and run 2 asks for again is only justified if it was in
    // flight at the kill (at most CONNS x WINDOW, plus channel slack) or
    // if the dead-air fault stalled its first request.
    let after = srv.serve_counts();
    let refetched: Vec<&String> = after
        .iter()
        .filter(|(id, n)| **n > asked_run1.get(*id).copied().unwrap_or(0))
        .filter(|(id, _)| asked_run1.contains_key(*id))
        .map(|(id, _)| id)
        .collect();
    // THE BUDGET IS MEASURED, NOT DERIVED, and that change is the whole
    // of this clause's history. It used to be `CONNS * WINDOW * 2 +
    // stalls` = 36, i.e. one in-flight window per connection twice over
    // plus the dead-air stalls - a WIRE quantity, describing how many
    // articles can be outstanding on the sockets. The quantity that
    // actually governs a refetch is DURABILITY: run 2 owes a refetch for
    // everything run 1 asked for and had not got into the journal, and
    // the distance between those two is set by the journal's flush
    // cadence against the decode lane, not by the pipelining window. On
    // a loaded box the network lane runs away from the write lane and
    // that distance grows without bound, while `CONNS * WINDOW` does not
    // move at all. Measured under 8x load on 30 Aug 2026 this test blew
    // the 36 with 54 refetched of 61 asked - and 54 is exactly 61 minus
    // the 7 the journal had recorded, which is the identity below rather
    // than an overrun.
    //
    // So the gap is READ at the kill, from the journal itself, through
    // the same parser the resume runs (`Journal::peek` - never a second
    // reader of the record grammar, which that function's own header
    // refuses). Measured six ways on 31 Aug 2026, idle and under 8x
    // load: `refetched` equalled `gap` EXACTLY every time (7/7, 6/6,
    // 9/9, 8/8, 9/9, 7/7), and the count of refetched articles that
    // were already recorded was ZERO every time.
    //
    // Note what leaves the formula with the derivation: `stalls`. A
    // stalled article's first request was asked and never served, so it
    // is already in the gap by construction - the old budget added it by
    // hand because it was modelling the gap instead of measuring it.
    //
    // DO NOT REPLACE THIS WITH A BIGGER CONSTANT. A constant cannot
    // track the flush cadence, and a constant large enough to survive a
    // loaded box is large enough to admit a resume that restarted from
    // scratch - which is the failure this clause exists to catch.
    let gap = asked_run1
        .keys()
        .filter(|id| !recorded_at_kill.contains(*id))
        .count();
    // A record is not a promise: `restore` re-reads the bytes and checks
    // them against the article's crc, so a record with no crc, or one
    // whose bytes the SIGKILL tore, is recorded here and refetches
    // anyway (see `ResumeState::recorded_ids`). That is what the slack
    // is for, and it is small on purpose - a resume that started over
    // refetches the whole recorded set, not four of it.
    let slack = CONNS as usize;
    let budget = gap + slack;
    assert!(
        refetched.len() <= budget,
        "resume refetched {} of the {} articles run 1 had already asked for \
         (budget {budget}: the {gap} the crash left un-journalled, plus {slack} \
         slack for records the kill may have torn; the journal held {} at the \
         kill)\n{}\n{log}",
        refetched.len(),
        asked_run1.len(),
        recorded_at_kill.len(),
        srv.serve_count_line("crash"),
    );
    // The sharper half, and the one that keeps the bound above from
    // going vacuous when the gap is wide: whatever run 1 DID get into
    // the journal, run 2 did not ask for again.
    let redone: Vec<&&String> = refetched
        .iter()
        .filter(|id| recorded_at_kill.contains(**id))
        .collect();
    assert!(
        redone.len() <= slack,
        "resume re-asked for {} articles run 1 had already journalled - a resume \
         owes the gap and nothing more, so this is work being redone, not \
         recovered: {redone:?}\n{log}",
        redone.len(),
    );
    eprintln!(
        "[contract] crash-in-window: {} refetched of {} asked in run 1 ({} journalled \
         at the kill, gap {gap}, budget {budget}), wall {:.2}s",
        refetched.len(),
        asked_run1.len(),
        recorded_at_kill.len(),
        wall.as_secs_f64()
    );
}

// ---------------------------------------------------------------------------
// Coverage gate: the contract must grow with the profile table
// ---------------------------------------------------------------------------

/// Profiles this suite knowingly does not run in-process, with the
/// reason. The full matrix races all of them on a bench box; this list
/// is what keeps "we run a subset" an explicit decision instead of an
/// accident.
const NOT_IN_PROCESS: &[(&str, &str)] = &[
    (
        "flap-dial",
        "same family as flap; the 250ms dial cost is a bench-box measurement",
    ),
    ("deadair-dial", "same family as deadair"),
    ("jitter-dial", "same family as jitter"),
    (
        "jitter",
        "a healthy link - the safety profile, priced by the matrix not pinned here",
    ),
    ("corruptstorm", "same family as corrupt"),
    (
        "desync",
        "same family as corrupt (wrong bytes attributed to the wrong slot)",
    ),
    ("splitbrain", "same family as corrupt"),
    ("truncate", "same family as corrupt"),
    (
        "slowconn",
        "a rate shape, not a terminal-state shape - matrix territory",
    ),
    ("slowstart", "a rate shape"),
    ("handover", "a rate shape"),
    (
        "bodyerror",
        "same family as brownout (a server that answers nothing usable)",
    ),
    ("authcap", "same family as brownout"),
    ("authbad", "same family as brownout"),
    ("capghost", "same family as flap (dial refusal)"),
    ("outage", "same family as flap"),
    (
        "cgnat",
        "same family as brownout (dead air, recovery by redial)",
    ),
    ("mutequit", "an exit-path check, not a contract clause"),
    ("mutegreeting", "same family as brownout"),
    (
        "deadpost",
        "terminal is a FAILURE by design; the contract's output gate cannot apply",
    ),
    (
        "gone",
        "needs par2 recovery volumes - the postproc lane suite owns that shape",
    ),
    (
        "freshmiss",
        "pinned in-process by §129 3d's own rig, nzbkit tests/provider_demote_rig.rs \
         (completion, bounded dispatches, per-server attribution) - a leg here would \
         re-run that at daemon cost and pin it LESS precisely: that rig reads the \
         pool's per-server tried/missing counters, where this suite sees only dials, \
         census bytes and request counts. The one clause it cannot make is byte-valid \
         output, and the 430 family needs no separate gate for it - a refused article \
         arrives from the twin down the identical decode/write path the two-server \
         corrupt and brownout legs already hash-gate",
    ),
    (
        "oldmiss",
        "the safety arm of the freshmiss pair, same rig - an identical 430 storm on an \
         old post, which must read as no fault at all",
    ),
    (
        "tlsfail",
        "same TLS family as tlstruncate, and a dial-cost shape: what it prices is how \
         many dials a server that can never hand over a session costs before the twin \
         carries the job, which is a bench-matrix measurement (pinned in-process by \
         nzbkit tests/tls_chaos.rs, both handshake variants)",
    ),
    (
        "tlscorrupt",
        "same TLS family as tlstruncate - a record that fails its AEAD tag ends the \
         session exactly as a cut does, and tls_chaos.rs pins the difference that \
         matters (the classified error) at nzbkit level",
    ),
    (
        "tlsresume",
        "same TLS family as tlstruncate, plus a failed reconnect handshake; the ordered \
         kill-then-fail-the-dial sequence is pinned by tls_chaos.rs",
    ),
];

/// The legs above, by profile name.
const IN_PROCESS: &[&str] = &[
    "clean",
    "flap",
    "deadair",
    "brownout",
    "corrupt",
    "shaped",
    "tlstruncate",
];

/// Every profile in the shared table is either pinned by a leg here or
/// listed with a reason. When 3a/3b land their profiles this test FAILS
/// until someone decides which of the two they are - which is what
/// "wire theirs in as they land" has to mean if it is to survive the
/// session that lands them.
///
/// The §129 3b TLS profiles (tlsfail / tlstruncate / tlscorrupt /
/// tlsresume) are the named case: the spec's acceptance for 3c includes
/// one TLS leg, and this gate is what stops that requirement being
/// quietly forgotten. It cannot be written as a leg before 3b exists -
/// the in-process TLS acceptor is 3b's deliverable - so it is written as
/// the failure that demands one.
#[test]
fn every_profile_is_pinned_or_excused() {
    let unclassified: Vec<&str> = chaos_serve::PROFILES
        .iter()
        .copied()
        .filter(|p| !IN_PROCESS.contains(p))
        .filter(|p| !NOT_IN_PROCESS.iter().any(|(name, _)| name == p))
        .collect();
    assert!(
        unclassified.is_empty(),
        "chaos-serve profiles with no place in the fault contract: {unclassified:?}.\n\
         Add a leg to tests/integration/fault_contract.rs (a TLS profile from §129 \
         3b needs one - see the acceptance criteria in \
         research/SPEC-2026-08-08-129-phase3.md), or add it to NOT_IN_PROCESS with \
         the reason it belongs to the bench matrix only."
    );
    // The excuse list may not outlive its profiles either: a stale entry
    // reads as coverage of something that no longer exists.
    let stale: Vec<&str> = NOT_IN_PROCESS
        .iter()
        .map(|(name, _)| *name)
        .filter(|name| !chaos_serve::PROFILES.contains(name))
        .collect();
    assert!(
        stale.is_empty(),
        "NOT_IN_PROCESS names profiles the table no longer has: {stale:?}"
    );
}
