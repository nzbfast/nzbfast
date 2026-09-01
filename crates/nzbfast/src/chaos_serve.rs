//! Standalone chaos NNTP server for the TODO 111 fault matrix: wraps
//! `nzbkit::mock` (the in-process chaos mock the payout rigs run
//! against) in a runnable server so EXTERNAL clients - nzbfast's own
//! CLI, NZBGet, SABnzbd, rustnzb, Weaver - can be raced against the
//! same fault shapes on loopback. Generates a deterministic corpus of
//! a few hundred MB, writes the matching .nzb, and serves it with a
//! fault profile chosen by flag. Two-server profiles (one faulty + one
//! clean twin, the shape the pool.rs payout rigs use) bind a second
//! port, so in-process numbers and standalone numbers stay comparable.
//!
//! Fault onset is logged with wall-clock timestamps, and a progress
//! line (bodies served / bytes moved per tick) is printed per server,
//! so recovery time (onset -> throughput restored) is measurable from
//! this log alone, whatever the client under test exposes.

use std::collections::{HashMap, HashSet};
use std::io::Write as _;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use std::sync::atomic::Ordering;

use anyhow::{Context, Result, anyhow, bail};
use nzbkit::mock::{Chaos, MockServer, Throttle, make_file_articles};
use nzbkit::mock_tls::{HandshakeFault, TlsChaos, TlsFront};

/// One corpus file's NZB ingredients.
struct CorpusFile {
    name: String,
    /// (message-id sans brackets, encoded size, part number)
    segs: Vec<(String, u64, u32)>,
}

/// The `chaos-serve` command line, beside the profile table it selects
/// from. Sizes arrive as strings ("300M") and are parsed in [`run`].
#[derive(clap::Args)]
pub struct Cli {
    /// One of chaos_serve::PROFILES: clean, flap, flap-dial, deadair,
    /// deadair-dial, brownout, jitter, jitter-dial, corrupt,
    /// corruptstorm, desync, splitbrain, slowconn, bodyerror, authcap,
    /// authbad, capghost, outage, cgnat, handover, slowstart, truncate,
    /// deadpost, gone, mutequit, mutegreeting, tlsfail, tlstruncate,
    /// tlscorrupt, tlsresume (the -dial variants add a 250 ms greeting
    /// delay per connection, so reconnect strategies pay their real
    /// dial cost on loopback; the tls* ones need --tls-cert/--tls-key).
    #[arg(long, default_value = "clean")]
    pub profile: String,
    #[arg(long, default_value = "127.0.0.1")]
    pub bind: String,
    /// Faulty (or single) server port.
    #[arg(long, default_value_t = 1190)]
    pub port: u16,
    /// Clean-twin port (flap/brownout/corrupt/corruptstorm/splitbrain/
    /// tlsfail profiles).
    #[arg(long, default_value_t = 1191)]
    pub port2: u16,
    /// Total corpus payload ("300M", "1G", …). Held in RAM.
    #[arg(long, default_value = "300M")]
    pub size: String,
    #[arg(long, default_value_t = 3)]
    pub files: u32,
    /// Article payload size; ~740K matches real posts.
    #[arg(long, default_value = "740K")]
    pub article_size: String,
    /// Where to write the matching NZB.
    #[arg(long, default_value = "chaos.nzb")]
    pub nzb: PathBuf,
    /// Shifts deterministic fault positions and corpus bytes; keep it
    /// fixed across clients so every client sees the same run.
    #[arg(long, default_value_t = 111)]
    pub seed: u64,
    /// Healthy per-connection cap ("2M" = 2 MB/s).
    #[arg(long, default_value = "2M")]
    pub per_conn: String,
    /// Whole-server line cap; 0 = per-connection cap only.
    #[arg(long, default_value = "0")]
    pub line: String,
    /// Create real PAR2 recovery volumes at this redundancy (%) with an
    /// external `par2` binary (PAR2_BIN to override) and serve them as
    /// part of the corpus.
    #[arg(long)]
    pub par2_redundancy: Option<u32>,
    /// Override the profile's faulted-article count (deadair/corrupt/
    /// splitbrain) or every-N (corruptstorm, desync).
    #[arg(long)]
    pub fault_count: Option<usize>,
    /// Override how long the faulty server sits on a "no such article"
    /// refusal, in ms. MEASURED per backbone, §146.3 item 4, 11 Aug:
    /// 79 / 454 / 871 / 1227 / 2239 ms. That is a 28x spread, so there
    /// is no single honest value and a fixture giving every mock
    /// backbone the same one models a fleet that does not exist - vary
    /// it per server. The cheapest backbone answers a 430 in one round
    /// trip (79 ms against a 77 ms DATE); the dearest charges 211x its
    /// own round trip, and pipelining recovers only 13-20% of that, so
    /// it is serial work at the server rather than client latency.
    /// A refusal ladder priced at wire speed reads exactly like a
    /// client that has already solved it - so a fixture racing give-up
    /// or fan-out policy against the ladder must set this.
    #[arg(long)]
    pub miss_delay_ms: Option<u64>,
    /// Refuse every connection past this many LIVE ones, on every
    /// server this instance serves, with `502 max connections reached:
    /// N` - an account sitting AT its provider's connection cap. It is
    /// a different fault from `authcap` (which refuses every AUTH, so
    /// the server is worth nothing) and from `capghost` (which refuses
    /// everything for a window and then clears): here the cap is real,
    /// permanent, and the grants already held keep working. That is the
    /// shape TODO 146 item 3 asks about - the tail give-up's demand rung
    /// borrows up to 8 connections per server while the main fleet idles
    /// at queue-dry, and the reasoning that shipped with it says the
    /// extra dials bounce off the capacity machinery and the rung
    /// degrades to the old 1-conn pace rather than failing. Set this to
    /// the main fleet's own per-server width and the borrow has nowhere
    /// to go.
    #[arg(long)]
    pub accept_cap: Option<u64>,
    /// Article-ize real files from disk into the corpus (repeatable).
    /// A playable video here turns the chaos rig into a playback
    /// end-to-end fixture; --files 0 serves only these.
    #[arg(long)]
    pub media: Vec<PathBuf>,
    /// Pack the whole corpus into a multi-volume RAR set of this
    /// volume size ("15M") with an external `rar` binary (RAR_BIN to
    /// override) and serve the VOLUMES instead of the loose files -
    /// the shape most real Usenet posts take, where a client sees only
    /// `name.partNN.rar` and the payload exists only after an unpack.
    /// Packing happens BEFORE --par2-redundancy, so the recovery
    /// volumes protect the RAR set rather than the payload, which is
    /// also what a real post does.
    #[arg(long)]
    pub rar_volume_size: Option<String>,
    /// Base name for that set (default: the --nzb file stem, which is
    /// what a real post uses - the release name names both).
    #[arg(long)]
    pub rar_name: Option<String>,
    /// PEM cert chain; with --tls-key, every server serves implicit TLS
    /// (the port-563 shape) through the chaos TLS front and the tls*
    /// fault profiles work. Mint a pair the way mockserve documents
    /// (CA:FALSE matters), and point the client at it with
    /// NZBFAST_EXTRA_CA=cert.pem.
    #[arg(long)]
    pub tls_cert: Option<PathBuf>,
    /// PEM private key matching --tls-cert.
    #[arg(long)]
    pub tls_key: Option<PathBuf>,
    /// A second PEM pair for a name clients do NOT dial. Only tlsfail
    /// reads it: with it, the handshake fails at the client's name
    /// check instead of being closed mid-flight.
    #[arg(long)]
    pub tls_alt_cert: Option<PathBuf>,
    /// PEM private key matching --tls-alt-cert.
    #[arg(long)]
    pub tls_alt_key: Option<PathBuf>,
}

/// The parsed run configuration: [`Cli`] with its sizes resolved.
pub struct Opts {
    profile: String,
    bind: String,
    port: u16,
    port2: u16,
    /// Total corpus payload bytes.
    size: u64,
    files: u32,
    article_size: usize,
    nzb: PathBuf,
    seed: u64,
    /// Per-connection cap on the healthy path, bytes/sec.
    per_conn_bps: u64,
    /// Whole-server line cap, bytes/sec (0 = per-connection only).
    line_bps: u64,
    par2_redundancy: Option<u32>,
    fault_count: Option<usize>,
    miss_delay_ms: Option<u64>,
    accept_cap: Option<u64>,
    media: Vec<PathBuf>,
    /// Volume size in bytes for the RAR set, if one is asked for.
    rar_volume_size: Option<u64>,
    rar_name: Option<String>,
    tls_cert: Option<PathBuf>,
    tls_key: Option<PathBuf>,
    tls_alt_cert: Option<PathBuf>,
    tls_alt_key: Option<PathBuf>,
}

impl Cli {
    /// Resolve the size strings into [`Opts`].
    ///
    /// `parse` is the crate's own size parser, passed in rather than
    /// called directly: this file is compiled straight into the
    /// integration test crate by `tests/integration/main.rs`'s
    /// `#[path]`, and that crate has no `crate::serve` to reach. Passing
    /// it keeps one parser in the tree and keeps the include compiling.
    pub fn opts(self, parse: impl Fn(&str) -> Option<u64>) -> Result<Opts> {
        let cli = self;
        let size = |v: &str, what: &str| parse(v).ok_or_else(|| anyhow!("bad {what} {v:?}"));
        Ok(Opts {
            size: size(&cli.size, "--size")?,
            article_size: size(&cli.article_size, "--article-size")? as usize,
            per_conn_bps: size(&cli.per_conn, "--per-conn")?,
            line_bps: size(&cli.line, "--line")?,
            profile: cli.profile,
            bind: cli.bind,
            port: cli.port,
            port2: cli.port2,
            files: cli.files,
            nzb: cli.nzb,
            seed: cli.seed,
            par2_redundancy: cli.par2_redundancy,
            fault_count: cli.fault_count,
            miss_delay_ms: cli.miss_delay_ms,
            accept_cap: cli.accept_cap,
            media: cli.media,
            rar_volume_size: match &cli.rar_volume_size {
                Some(v) => Some(size(v, "--rar-volume-size")?),
                None => None,
            },
            rar_name: cli.rar_name,
            tls_cert: cli.tls_cert,
            tls_key: cli.tls_key,
            tls_alt_cert: cli.tls_alt_cert,
            tls_alt_key: cli.tls_alt_key,
        })
    }
}

/// Default articles a connection serves before a TLS fault fires.
pub const TLS_ARTICLES_PER_CONN: usize = 8;

/// The TLS-shaped profiles: they need `--tls-cert`/`--tls-key` and are
/// refused without them, since serving them over plain TCP would look
/// like a clean run.
pub const TLS_PROFILES: &[&str] = &["tlsfail", "tlstruncate", "tlscorrupt", "tlsresume"];

/// What one profile does to each server. `label` feeds the log lines.
///
/// Public because the §129 3c fault-contract suite
/// (`crates/nzbfast/tests/integration/fault_contract.rs`) builds its
/// in-process legs from THIS table rather than a second copy of it. A
/// contract that drifts from the profiles the bench matrix races is
/// worth nothing, and two profile tables would drift the day 3a/3b add
/// a shape to one of them.
pub struct Plan {
    pub chaos: Chaos,
    /// TLS-layer faults for the faulty server, applied in the acceptor
    /// wrapper in front of it. Default = a plain TLS endpoint (and
    /// ignored entirely when the rig is not serving TLS). An in-process
    /// consumer wanting these has to put the front up itself - see
    /// `nzbkit::mock_tls::TlsFront`.
    pub tls: TlsChaos,
    /// Second server (clean twin) - None for single-server profiles.
    pub twin: Option<Chaos>,
    /// Human line printed at startup describing the fault and when it
    /// engages, so the run log is self-describing.
    pub onset_note: String,
    /// Body count at which a threshold fault engages (brownout); the
    /// monitor logs the exact onset timestamp when served crosses it.
    pub onset_after_bodies: Option<u64>,
}

pub const PROFILES: &[&str] = &[
    "clean",
    "flap",
    "flap-dial",
    "deadair",
    "deadair-dial",
    "brownout",
    "jitter",
    "jitter-dial",
    "corrupt",
    "corruptstorm",
    "desync",
    "splitbrain",
    "slowconn",
    "shaped",
    "bodyerror",
    "authcap",
    "authbad",
    "capghost",
    "outage",
    "cgnat",
    "handover",
    "slowstart",
    "truncate",
    "deadpost",
    "gone",
    "mutequit",
    "mutegreeting",
    "freshmiss",
    "oldmiss",
    "tlsfail",
    "tlstruncate",
    "tlscorrupt",
    "tlsresume",
];

/// The NZB `<file date>` a profile declares, in unix seconds. Age is not
/// decoration here: a 430 on an OLD post is propagation/retention and
/// carries no guilt, while a 430 on a post the NZB says is hours old is
/// a provider that did not take the feed (memory
/// nzbfast-retry-propagation-trap). `freshmiss` and `oldmiss` are the
/// same fault with the dates swapped, which is the whole point of the
/// pair - anything that reacts to one must sit still for the other.
fn post_date(profile: &str) -> u64 {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(FIXED_POST_DATE);
    match profile {
        // Two hours old: inside every provider's propagation window, so
        // "not here yet" is not an available excuse.
        "freshmiss" => now.saturating_sub(2 * 3600),
        _ => FIXED_POST_DATE,
    }
}

/// The corpus's historic post date (June 2025) - what every profile but
/// `freshmiss` declares, and what the matrix has always used.
const FIXED_POST_DATE: u64 = 1_750_000_000;

/// The `-dial` profile variants' per-connection greeting delay (TODO
/// 115): every fresh connection pays this before the server says 200,
/// approximating a real TCP+TLS+AUTH dial on loopback - so a strategy
/// that recovers by reconnecting pays its real-world cost on the rig
/// instead of redialing for free (NZBGet's flap "win" is 217 free
/// loopback dials; a provider would refuse that hammering).
const DIAL_COST_MS: u64 = 250;

/// Deterministic corpus bytes: same generator family as mockserv, mixed
/// with the seed so distinct seeds give distinct (but reproducible) data.
fn corpus_data(len: usize, seed: u64) -> Vec<u8> {
    (0..len as u64)
        .map(|i| {
            (i.wrapping_add(seed.wrapping_mul(0x9E3779B97F4A7C15))
                .wrapping_mul(2654435761)
                >> 16) as u8
        })
        .collect()
}

/// Evenly spread `count` positions across the middle of `n` articles
/// (30%..90% of the queue), so faults bite mid-run with healthy history
/// behind them - the placement the payout rigs use. Seed shifts phase.
fn spread_positions(n: usize, count: usize, seed: u64) -> Vec<usize> {
    if n == 0 || count == 0 {
        return Vec::new();
    }
    let lo = n * 3 / 10;
    let hi = n * 9 / 10;
    let span = (hi - lo).max(1);
    let count = count.min(span);
    let step = (span / count).max(1);
    let phase = (seed as usize) % step;
    (0..count)
        .map(|k| lo + (k * step + phase) % span)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

/// Evenly spread `count` positions across ALL `n` articles. Unlike
/// [`spread_positions`] (mid-queue only, for faults that must bite after
/// a healthy history) a propagation hole has no such shape: the articles
/// the provider never took are scattered through the whole post.
fn stride_positions(n: usize, count: usize, seed: u64) -> Vec<usize> {
    if n == 0 || count == 0 {
        return Vec::new();
    }
    let count = count.min(n);
    let phase = (seed as usize) % n;
    (0..count)
        .map(|k| (k * n / count + phase) % n)
        .collect::<HashSet<_>>()
        .into_iter()
        .collect()
}

fn ts() -> String {
    let now = std::time::SystemTime::now()
        .duration_since(std::time::UNIX_EPOCH)
        .unwrap_or_default();
    format!("{}.{:03}", now.as_secs(), now.subsec_millis())
}

fn say(msg: &str) {
    println!("CHAOS {} {msg}", ts());
    let _ = std::io::stdout().flush();
}

/// Write the multi-file NZB for the corpus, declaring `date` (unix
/// seconds) on every file - the only thing a client can know about a
/// post's age before it asks for a byte.
fn write_nzb(path: &Path, files: &[CorpusFile], date: u64) -> Result<()> {
    let mut nzb = String::from(
        "<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n\
         <nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for f in files {
        nzb.push_str(&format!(
            "<file poster=\"chaos@bench.local\" date=\"{date}\" \
             subject=\"&quot;{}&quot; yEnc (1/{})\">\n\
             <groups><group>alt.binaries.bench</group></groups>\n<segments>\n",
            f.name,
            f.segs.len()
        ));
        for (id, bytes, number) in &f.segs {
            nzb.push_str(&format!(
                "<segment bytes=\"{bytes}\" number=\"{number}\">{id}</segment>\n"
            ));
        }
        nzb.push_str("</segments>\n</file>\n");
    }
    nzb.push_str("</nzb>\n");
    std::fs::write(path, nzb).with_context(|| format!("write {}", path.display()))?;
    Ok(())
}

/// Run external `rar a -v<size>` over the corpus files and REPLACE them
/// with the resulting volumes, so a client sees only `name.partNN.rar`
/// and the payload exists only after an unpack.
///
/// Store (`-m0`) rather than compress, and that is the realistic
/// setting rather than the cheap one: a real media post packs an
/// already-compressed H.264 file, so a real packer stores it, and store
/// is the shape nzbfast's in-stream extraction is built around. A
/// compressed set is a different code path and is not what this fixture
/// claims to model.
///
/// `-ep` strips paths, so the archive members carry bare file names the
/// way a real post's do. Volume digit width is left to `rar`, which
/// pads to the set SIZE exactly as a real post does - measured, 3
/// volumes give `.part1.rar` and 11 give `.part01.rar`.
fn pack_rar(
    volume_size: u64,
    base: &str,
    payloads: Vec<(String, Vec<u8>, String)>,
    seed: u64,
) -> Result<Vec<(String, Vec<u8>, String)>> {
    let bin = std::env::var("RAR_BIN").unwrap_or_else(|_| "rar".into());
    let dir = std::env::temp_dir().join(format!("chaosserv-rar-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir)?;
    for (name, data, _) in &payloads {
        std::fs::write(dir.join(name), data)?;
    }
    let mut cmd = std::process::Command::new(&bin);
    cmd.current_dir(&dir)
        .arg("a")
        .arg("-m0")
        .arg("-ep")
        .arg("-idq")
        .arg(format!("-v{volume_size}b"))
        .arg(format!("{base}.rar"));
    for (name, _, _) in &payloads {
        cmd.arg(name);
    }
    let st = cmd
        .status()
        .with_context(|| format!("run {bin} a (set RAR_BIN to the binary)"))?;
    if !st.success() {
        bail!("{bin} a failed with {st}");
    }
    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "rar"))
        .collect();
    // Byte order is volume order here, and only because `rar` pads to
    // the set size: a mixed `part9`/`part10` set would sort wrong, and
    // `rar` never emits one. A set that packed to nothing is a silent
    // fixture failure - the corpus would simply be empty and the run
    // would look like a clean serve - so it is refused rather than
    // served.
    vols.sort();
    if vols.is_empty() {
        bail!("{bin} produced no .rar volumes in {}", dir.display());
    }
    let mut out = Vec::with_capacity(vols.len());
    for (i, vol) in vols.iter().enumerate() {
        let name = vol
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("non-utf8 rar volume name"))?
            .to_string();
        let data = std::fs::read(vol)?;
        out.push((name, data, format!("chr{seed}r{i}")));
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(out)
}

/// Run external `par2 create` over the corpus files and article-ize the
/// resulting volumes into the same corpus.
fn add_par2(
    redundancy: u32,
    payloads: &[(String, Vec<u8>, String)],
    article_size: usize,
    articles: &mut HashMap<String, Vec<u8>>,
    corpus: &mut Vec<CorpusFile>,
) -> Result<()> {
    let bin = std::env::var("PAR2_BIN").unwrap_or_else(|_| "par2".into());
    let dir = std::env::temp_dir().join(format!("nzbfast-chaosserv-par2-{}", std::process::id()));
    std::fs::create_dir_all(&dir)?;
    for (name, data, _) in payloads {
        std::fs::write(dir.join(name), data)?;
    }
    let mut cmd = std::process::Command::new(&bin);
    cmd.current_dir(&dir)
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg("-qq")
        .arg("chaos.par2");
    for (name, _, _) in payloads {
        cmd.arg(name);
    }
    let st = cmd
        .status()
        .with_context(|| format!("run {bin} create (set PAR2_BIN to the binary)"))?;
    if !st.success() {
        bail!("{bin} create failed with {st}");
    }
    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)?
        .filter_map(|e| e.ok())
        .map(|e| e.path())
        .filter(|p| p.extension().is_some_and(|x| x == "par2"))
        .collect();
    vols.sort();
    for (i, vol) in vols.iter().enumerate() {
        let name = vol
            .file_name()
            .and_then(|n| n.to_str())
            .ok_or_else(|| anyhow!("non-utf8 par2 name"))?
            .to_string();
        let data = std::fs::read(vol)?;
        let segs = make_file_articles(&name, &data, article_size, &format!("chp{i}"), articles);
        corpus.push(CorpusFile { name, segs });
    }
    let _ = std::fs::remove_dir_all(&dir);
    Ok(())
}

/// One PEM cert/key pair into a rustls server config, through the tree's
/// single loader (`benchserve::tls_config`, which also names the crypto
/// provider - a bare `builder()` panics at runtime here because both
/// aws-lc-rs and ring are linked in). Half a pair is a mistake, not a
/// default.
fn pem_pair(
    cert: &Option<PathBuf>,
    key: &Option<PathBuf>,
    what: &str,
) -> Result<Option<Arc<rustls::ServerConfig>>> {
    match (cert, key) {
        (Some(c), Some(k)) => Ok(Some(nzbkit::benchserve::tls_config(c, k)?)),
        (None, None) => Ok(None),
        _ => bail!("{what} must be given together"),
    }
}

/// The profile table. Shapes and ratios mirror the pool.rs payout rigs
/// (flap = payout_flap_breaker_collapses_ip_cap_churn, brownout =
/// payout_brownout_recovery_across_config_tiers, deadair =
/// payout_adaptive_timeout_cuts_dead_air_stalls, jitter =
/// safety_adaptive_timeout_kills_nothing_on_a_jittery_link, slowconn =
/// payout_slope_recycle_frees_a_degraded_session), scaled from the
/// rigs' tens-of-KB/s throttles to MB/s so a few-hundred-MB corpus
/// finishes in minutes.
///
/// `dead_code` because the binary itself always goes through
/// [`plan_with_tls`]; the consumer of this signature is the 3c contract
/// suite, which compiles this file into its own crate.
// Not #[expect]: the contract suite's compilation DOES reach it, so
// the expectation is unfulfilled there.
#[allow(dead_code)]
pub fn plan(
    profile: &str,
    all_ids: &[String],
    per_conn_bps: u64,
    line_bps: u64,
    seed: u64,
    fault_count: Option<usize>,
) -> Result<Plan> {
    plan_with_tls(
        profile,
        all_ids,
        per_conn_bps,
        line_bps,
        seed,
        fault_count,
        TlsPlanIn::default(),
    )
}

/// The inputs only the four TLS shapes read, kept off [`plan`] so the
/// signature the 3c contract suite calls stays as it landed. Byte
/// budgets scale with `article_size` because they have to: a budget
/// fixed in bytes either never fires on a small-article corpus or cuts
/// every article on a large one, and a fault profile that silently does
/// not engage reads exactly like a client that handled it.
pub struct TlsPlanIn {
    pub article_size: usize,
    /// Articles a connection serves before its fault fires; see
    /// [`tls_plan`] for why this is not one or two.
    pub articles_per_conn: usize,
    /// The mismatched chain that selects tlsfail's wrong-name variant;
    /// None closes the handshake mid-flight instead.
    pub alt_cert: Option<Arc<rustls::ServerConfig>>,
}

impl Default for TlsPlanIn {
    fn default() -> TlsPlanIn {
        // chaos-serve's own --article-size default, so a plain `plan`
        // caller racing a tls* profile still gets budgets that fire.
        TlsPlanIn {
            article_size: 740_000,
            articles_per_conn: TLS_ARTICLES_PER_CONN,
            alt_cert: None,
        }
    }
}

/// The account-shaping shape (M7b.2 steering/racing rig; memory
/// nzbfast-giganews-shaping): every connection on the shaped server
/// serves CORRECT bytes at 1/10th of the healthy per-conn rate, the
/// clean twin runs at full speed. Nothing ever faults - the whole cost
/// is per-article serve time, so what a client pays here is exactly its
/// pipeline-depth and racing policy (the measured live shape:
/// ~15 Mbps/conn shaped against ~165 clean, articles held ~430 ms
/// apiece, ~83 MB parked behind slow sessions at queue-dry on a
/// 26-conn fleet). Its own fn so `plan_with_tls` stays inside the
/// size gate's function ceiling.
fn shaped_plan(per_conn_bps: u64, line_bps: u64, base: Chaos, clean_twin: Chaos) -> Plan {
    let shaped_bps = (per_conn_bps / 10).max(10_000);
    Plan {
        chaos: Chaos {
            throttle: Throttle {
                per_conn_bps: shaped_bps,
                line_bps,
                ..Default::default()
            },
            ..base
        },
        tls: TlsChaos::default(),
        twin: Some(clean_twin),
        onset_note: format!(
            "shaped: every connection on the shaped server is capped to \
             {shaped_bps} B/s (1/10th of healthy), correct bytes, from t0; \
             clean twin on port2"
        ),
        onset_after_bodies: None,
    }
}

/// The steady-state fault shapes: a server that answers wrongly, refuses,
/// disappears, or goes quiet, plus the two that never answer at all.
///
/// `None` for a profile this arm does not know, so the caller still owns the
/// `unknown profile` message and its `PROFILES` list. Same shape as
/// `tls_plan`, `miss_plan` and `shaped_plan` beside it - the file already
/// splits its match this way. Split out of `plan_with_tls` (TODO 106), arms
/// verbatim.
fn steady_plan(
    profile: &str,
    base: Chaos,
    clean_twin: Chaos,
    all_ids: &[String],
    n: usize,
    seed: u64,
    fault_count: Option<usize>,
) -> Option<Plan> {
    Some(match profile {
        // Broken account / 502 storm: connect and AUTH succeed, every
        // BODY answers "502 byte limit exceeded", forever. The clean
        // twin carries the group; the race prices per-server circuit
        // breaking (a client without one grinds the broken account).
        "bodyerror" => Plan {
            chaos: Chaos {
                body_error: Some(u64::MAX),
                ..base
            },
            tls: TlsChaos::default(),
            twin: Some(clean_twin),
            onset_note: "bodyerror: every BODY on the faulty server answers 502 \
                         (AUTH fine), forever, structural from t0; clean twin on \
                         port2"
                .into(),
            onset_after_bodies: None,
        },
        // Capacity refusal vs bad credential: AUTH on the faulty
        // server always fails with the REAL capacity wording on reply
        // code 481 - the same code a wrong password uses. A client
        // that reads it as a bad credential disables the server; one
        // that reads it as capacity paces and retries. Either way the
        // clean twin carries the job; the spread is wall + dial count.
        "authcap" => Plan {
            chaos: Chaos {
                auth_rejected: true,
                auth_refusal_text: Some("481 max simultaneous IP addresses reached".into()),
                ..base
            },
            tls: TlsChaos::default(),
            twin: Some(clean_twin),
            onset_note: "authcap: every AUTH on the faulty server refused with \
                         '481 max simultaneous IP addresses reached', structural \
                         from t0; clean twin on port2"
                .into(),
            onset_after_bodies: None,
        },
        // authcap's contrast arm: the SAME 481 code with bad-credential
        // wording. A wording-aware client keeps pacing on authcap (the
        // capacity refusal clears when sessions close) but STOPS
        // dialing here (a wrong password never fixes itself); a client
        // that only reads the code shows identical dial counts on both.
        "authbad" => Plan {
            chaos: Chaos {
                auth_rejected: true,
                auth_refusal_text: Some("481 authentication failed".into()),
                ..base
            },
            tls: TlsChaos::default(),
            twin: Some(clean_twin),
            onset_note: "authbad: every AUTH on the faulty server refused with \
                         '481 authentication failed', structural from t0; clean \
                         twin on port2"
                .into(),
            onset_after_bodies: None,
        },
        // CGNAT eviction: every connection's NAT entry dies after 25
        // bodies - permanent dead air, no close, no RST. A reconnect
        // gets a fresh entry. Single server: the only recovery is
        // noticing the silence and redialing.
        // Issue #16's restart shape: the provider still counts a dead
        // process's sessions, so for the first 45 s EVERY dial bounces
        // off the capacity refusal - then the lease expires and the
        // account works normally. A resilient client keeps paced
        // redials alive through the window and eases back in; the
        // reported bug is stalling at 0 MB/s instead.
        "capghost" => Plan {
            chaos: Chaos {
                cap_ghost_ms: 45_000,
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "capghost: every dial refused with the 502 capacity \
                         text for the first 45000 ms (ghost sessions hold the \
                         cap), normal accepts after"
                .into(),
            onset_after_bodies: None,
        },
        // Hard outage: for the first 45 s every accepted connection is
        // closed with no greeting and no refusal text - the wifi-drop /
        // VPN-reconnect / router-reboot shape. Unlike capghost there is
        // nothing to classify: the dial simply fails. A resilient
        // client parks its fleet behind one paced prober and comes
        // back at full width when the window clears; the failure mode
        // is retiring every worker in ~15-30 s and failing the job.
        "outage" => Plan {
            chaos: Chaos {
                refuse_connect_ms: 45_000,
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "outage: every accepted connection closed with no \
                         greeting for the first 45000 ms (hard connect \
                         failure), normal accepts after"
                .into(),
            onset_after_bodies: None,
        },
        "cgnat" => Plan {
            chaos: Chaos {
                mute_after_bodies: 25,
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "cgnat: each connection goes permanently silent after 25 \
                         bodies (no close); a reconnect gets a fresh NAT entry"
                .into(),
            onset_after_bodies: None,
        },
        // Satellite handover: three staggered WANs, each frozen 4 s of
        // every 12 s cycle (connection conn_no % 3 belongs to a WAN).
        // Brief, recovering dead air - killing sessions here is
        // mostly wrong, waiting is mostly right.
        "handover" => Plan {
            chaos: Chaos {
                handover: Some((12_000, 4_000, 3)),
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "handover: 3 staggered WANs, each frozen 4000 ms per \
                         12000 ms cycle, structural from t0"
                .into(),
            onset_after_bodies: None,
        },
        // Slow-start trickle: every fresh connection crawls at 50 KB/s
        // for its first 3 s, then runs at the healthy rate. The shape
        // where a reconnect-happy strategy pays and a parked spare
        // rides the window out idle.
        "slowstart" => Plan {
            chaos: Chaos {
                slow_start: Some((3_000, 50_000)),
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "slowstart: every new connection paced at 50000 B/s for \
                         its first 3000 ms, healthy after"
                .into(),
            onset_after_bodies: None,
        },
        // Truncated bodies: a spread of articles are cut mid-payload
        // and the connection dropped, EVERY request (a damaged spool
        // entry). Clean twin holds good copies - partial-write and
        // requeue correctness, and whether the retry goes elsewhere.
        "truncate" => {
            let count = fault_count.unwrap_or(12);
            let truncate: HashSet<String> = spread_positions(n, count, seed)
                .into_iter()
                .map(|i| all_ids[i].clone())
                .collect();
            let note = format!(
                "truncate: {} articles cut mid-payload with the connection \
                 dropped, every request, structural from t0; clean twin on \
                 port2 holds good copies",
                truncate.len()
            );
            Plan {
                chaos: Chaos { truncate, ..base },
                tls: TlsChaos::default(),
                twin: Some(clean_twin),
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // §129 lane rig: a handful of PAYLOAD articles permanently 430,
        // single server, no twin - the damage shape that forces a PAR2
        // repair in the post-network tail (run with --par2-redundancy).
        // Faults are drawn from the first half of the corpus order so
        // the recovery volumes (appended last) are never the casualty.
        "gone" => {
            let count = fault_count.unwrap_or(4);
            let missing: HashSet<String> = spread_positions(n / 2, count, seed)
                .into_iter()
                .map(|i| all_ids[i].clone())
                .collect();
            let note = format!(
                "gone: {} payload articles answer 430 forever; with recovery \
                 volumes served, repair from parity is the only way home",
                missing.len()
            );
            Plan {
                chaos: Chaos { missing, ..base },
                tls: TlsChaos::default(),
                twin: None,
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // Wholly-dead post: EVERY article 430s, each refusal costing a
        // real round trip. Nobody can complete - the metric is wall to
        // TERMINAL (the gate reads DNF by design; a fast honest
        // failure beats a slow one).
        "deadpost" => Plan {
            chaos: Chaos {
                missing: all_ids.iter().cloned().collect(),
                missing_delay_ms: 70,
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "deadpost: every article answers 430 after a 70 ms round \
                         trip; completion is impossible - the wall to a TERMINAL \
                         failed state is the measurement"
                .into(),
            onset_after_bodies: None,
        },
        // Exit-path wedge check: a healthy server that never answers
        // QUIT (TCP ack, no goodbye). The job completes; the question
        // is whether the client's exit waits on the goodbye.
        "mutequit" => Plan {
            chaos: Chaos {
                mute_quit: true,
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "mutequit: healthy server that never answers QUIT; the \
                         measurement is whether completion pays an exit-path hang"
                .into(),
            onset_after_bodies: None,
        },
        // Connect-path wedge check: the faulty server accepts TCP but
        // never greets; the clean twin carries the job. Prices how
        // much a mute frontend costs a client that keeps a session
        // slot parked in connect().
        "mutegreeting" => Plan {
            chaos: Chaos {
                mute_greeting: true,
                ..base
            },
            tls: TlsChaos::default(),
            twin: Some(clean_twin),
            onset_note: "mutegreeting: faulty server accepts connections but \
                         never sends the greeting, structural from t0; clean \
                         twin on port2"
                .into(),
            onset_after_bodies: None,
        },
        _ => return None,
    })
}

/// [`plan`] with the TLS shapes' inputs supplied.
pub fn plan_with_tls(
    profile: &str,
    all_ids: &[String],
    per_conn_bps: u64,
    line_bps: u64,
    seed: u64,
    fault_count: Option<usize>,
    tls_in: TlsPlanIn,
) -> Result<Plan> {
    let healthy = Throttle {
        per_conn_bps,
        line_bps,
        ..Default::default()
    };
    let n = all_ids.len();
    let base = Chaos {
        throttle: healthy.clone(),
        ..Default::default()
    };
    // The clean twin: healthy throttle, no faults.
    let clean_twin = Chaos {
        throttle: healthy.clone(),
        ..Default::default()
    };
    Ok(match profile {
        "clean" => Plan {
            chaos: base,
            tls: TlsChaos::default(),
            twin: None,
            onset_note: "clean baseline - no fault".into(),
            onset_after_bodies: None,
        },
        // The eweka shape: 2 sessions win, the rest bounce off a 502
        // cap refusal, and each winner dies after one body at a crawl.
        // Rig ratio 60k:150k burned:steady = 0.4x healthy rate. The
        // -dial variant makes every (re)dial pay the 250 ms greeting,
        // so redial-heavy flap strategies price honestly on loopback.
        "flap" | "flap-dial" => {
            let dial = profile.ends_with("-dial");
            Plan {
                chaos: Chaos {
                    accept_cap: Some(2),
                    drop_after: 1,
                    greet_delay_ms: if dial { DIAL_COST_MS } else { 0 },
                    throttle: Throttle {
                        per_conn_bps: (per_conn_bps * 2) / 5,
                        line_bps,
                        ..Default::default()
                    },
                    ..Default::default()
                },
                tls: TlsChaos::default(),
                twin: Some(clean_twin),
                onset_note: format!(
                    "flap{}: accept_cap=2 + drop_after=1 on the faulty server, \
                     structural from t0; clean twin on port2{}",
                    if dial { "-dial" } else { "" },
                    if dial {
                        format!("; every new connection pays a {DIAL_COST_MS} ms greeting delay")
                    } else {
                        String::new()
                    }
                ),
                onset_after_bodies: None,
            }
        }
        "deadair" | "deadair-dial" => {
            let dial = profile.ends_with("-dial");
            let count = fault_count.unwrap_or(12);
            let stall_pre: HashSet<String> = spread_positions(n, count, seed)
                .into_iter()
                .map(|i| all_ids[i].clone())
                .collect();
            let note = format!(
                "deadair{}: {} articles hang before the status line on their \
                 first request (retries succeed); spread mid-queue{}",
                if dial { "-dial" } else { "" },
                stall_pre.len(),
                if dial {
                    format!("; every new connection pays a {DIAL_COST_MS} ms greeting delay")
                } else {
                    String::new()
                }
            );
            Plan {
                chaos: Chaos {
                    stall_pre,
                    greet_delay_ms: if dial { DIAL_COST_MS } else { 0 },
                    ..base
                },
                tls: TlsChaos::default(),
                twin: None,
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // Frontend goes mute after 40% of the corpus and never comes
        // back; the clean twin carries the group (rig shape).
        "brownout" => {
            let after = (n as u64 * 2) / 5;
            Plan {
                chaos: Chaos {
                    brownout_after: after,
                    ..base
                },
                tls: TlsChaos::default(),
                twin: Some(clean_twin),
                onset_note: format!(
                    "brownout: faulty server goes mute (dead air, no recovery) \
                     after {after} bodies; clean twin on port2"
                ),
                onset_after_bodies: Some(after),
            }
        }
        // Every 5th body 1.8 s late on a healthy link - the satellite
        // shape. The right client behaviour is to kill nothing.
        "jitter" | "jitter-dial" => {
            let dial = profile.ends_with("-dial");
            Plan {
                chaos: Chaos {
                    jitter: Some((5, 1_800)),
                    greet_delay_ms: if dial { DIAL_COST_MS } else { 0 },
                    ..base
                },
                tls: TlsChaos::default(),
                twin: None,
                onset_note: format!(
                    "jitter{}: every 5th body +1800 ms, structural from t0; \
                     a healthy link - killing sessions here is the failure{}",
                    if dial { "-dial" } else { "" },
                    if dial {
                        format!("; every new connection pays a {DIAL_COST_MS} ms greeting delay")
                    } else {
                        String::new()
                    }
                ),
                onset_after_bodies: None,
            }
        }
        // Bit-rot storm: a spread of articles serve wrong bytes (yEnc
        // CRC fails); a clean twin holds good copies, so re-fetching
        // elsewhere can save the job without repair.
        "corrupt" => {
            let count = fault_count.unwrap_or(n / 10);
            let corrupt: HashSet<String> = spread_positions(n, count, seed)
                .into_iter()
                .map(|i| all_ids[i].clone())
                .collect();
            let note = format!(
                "corrupt: {} articles serve flipped bytes (CRC fails) on the \
                 faulty server, structural from t0; clean twin on port2 holds \
                 good copies",
                corrupt.len()
            );
            Plan {
                chaos: Chaos { corrupt, ..base },
                tls: TlsChaos::default(),
                twin: Some(clean_twin),
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // Server-wide corrupt storm: a broken cache node. Every Nth
        // BODY the faulty server sends (arrival order, retries
        // included) has a flipped byte, so the damage cannot be pinned
        // to specific ids - a retry of the SAME article to the SAME
        // server may come back good or bad. Clean twin holds good
        // copies. Distinct from `corrupt` (fixed per-id set = a damaged
        // POST); this prices whether a retry policy converges under
        // damage it cannot attribute.
        "corruptstorm" => {
            let every = fault_count.map(|c| c as u64).unwrap_or(10).max(2);
            Plan {
                chaos: Chaos {
                    corrupt_every: every,
                    ..base
                },
                tls: TlsChaos::default(),
                twin: Some(clean_twin),
                onset_note: format!(
                    "corruptstorm: every {every}th body served by the faulty \
                     server has a flipped byte (CRC fails), retries included, \
                     structural from t0; clean twin on port2 holds good copies"
                ),
                onset_after_bodies: None,
            }
        }
        // Desync: every Nth BODY/ARTICLE response (server-wide arrival
        // order) is silently withheld while the request is consumed,
        // so every later response on that connection answers one
        // pipeline slot ahead of what positional attribution assumes.
        // A client that discards the echoed message-id files every
        // subsequent body on that connection under the wrong article
        // and "completes" corrupt; the echoed-id check must cut the
        // session and requeue instead. Single server: the recovery
        // must come from the same host.
        "desync" => {
            let every = fault_count.map(|c| c as u64).unwrap_or(60).max(2);
            Plan {
                chaos: Chaos {
                    skip_nth_response: every,
                    ..base
                },
                tls: TlsChaos::default(),
                twin: None,
                onset_note: format!(
                    "desync: every {every}th BODY/ARTICLE response silently \
                     withheld (request consumed, connection kept), structural \
                     from t0 - later responses on that connection shift one \
                     slot; only an echoed-id check can attribute them honestly"
                ),
                onset_after_bodies: None,
            }
        }
        // Split-brain: the faulty server's storage backend is
        // mismatched - a request for one id is answered with ANOTHER
        // article's fully valid bytes, in bidirectional pairs. The yEnc
        // CRC PASSES; only the article's declared identity (part
        // number) betrays it. The live "downloads complete but never
        // verify" class. Clean twin holds true copies. A size gate
        // cannot see this; the hash gate is mandatory.
        "splitbrain" => {
            let count = fault_count.unwrap_or(n / 10);
            let mut picks = spread_positions(n, count, seed);
            picks.sort_unstable();
            let mut swap = HashMap::new();
            for pair in picks.chunks(2) {
                if let [a, b] = pair {
                    swap.insert(all_ids[*a].clone(), all_ids[*b].clone());
                    swap.insert(all_ids[*b].clone(), all_ids[*a].clone());
                }
            }
            let note = format!(
                "splitbrain: {} articles served as {} swapped pairs (right id, \
                 wrong article's bytes, yEnc CRC passes) on the faulty server, \
                 structural from t0; clean twin on port2 holds true copies",
                swap.len(),
                swap.len() / 2
            );
            Plan {
                chaos: Chaos { swap, ..base },
                tls: TlsChaos::default(),
                twin: Some(clean_twin),
                onset_note: note,
                onset_after_bodies: None,
            }
        }
        // One degraded TCP session on an otherwise healthy server: the
        // 3rd accepted connection crawls at 1/40th of the healthy rate;
        // a reconnect gets a fresh, healthy session (rig shape).
        "slowconn" => Plan {
            chaos: Chaos {
                slow_conn: Some((3, (per_conn_bps / 40).max(10_000))),
                ..base
            },
            tls: TlsChaos::default(),
            twin: None,
            onset_note: format!(
                "slowconn: the 3rd accepted connection is capped to {} B/s; \
                 every other (re)connect is healthy",
                (per_conn_bps / 40).max(10_000)
            ),
            onset_after_bodies: None,
        },
        "shaped" => shaped_plan(per_conn_bps, line_bps, base, clean_twin),
        // §129 3b: the four TLS-layer shapes. The mock underneath is
        // HEALTHY in every one of them - the fault lives in the acceptor
        // in front of it, which is the whole point: these are failures
        // of the transport every real user is on, not of the NNTP
        // conversation, and no existing profile could express them.
        "tlsfail" | "tlstruncate" | "tlscorrupt" | "tlsresume" => {
            tls_plan(profile, base, clean_twin, tls_in)
        }
        "freshmiss" | "oldmiss" => miss_plan(profile, all_ids, base, clean_twin, seed, fault_count),
        other => match steady_plan(other, base, clean_twin, all_ids, n, seed, fault_count) {
            Some(p) => p,
            None => bail!("unknown profile {other:?}; one of {}", PROFILES.join("|")),
        },
    })
}

/// The TLS-shaped profiles. Byte budgets are per connection and scale
/// with the article size, so the cut always lands mid-body whatever the
/// corpus is built at.
fn tls_plan(profile: &str, base: Chaos, clean_twin: Chaos, tls_in: TlsPlanIn) -> Plan {
    // Articles a connection serves before the fault ends it. Eight, not
    // the two or three that first looked "severe": a cut requeues
    // whatever the pipeline had in flight, so cutting on the order of
    // the window turns EVERY article into a refetch and the run stops
    // measuring recovery and starts measuring the rig. Eight bites
    // several times per connection on any corpus a matrix leg uses and
    // still leaves refetch a bounded, meaningful number (§129 3c's
    // clause 5 is what caught this: 195 refetches for 126 articles).
    // --fault-count overrides it, as it does for the other profiles.
    let per_conn = tls_in.articles_per_conn.max(1) as u64;
    let art = tls_in.article_size.max(1) as u64 * per_conn;
    let alt_tls = tls_in.alt_cert;
    match profile {
        // Handshake failure with a clean twin carrying the job: what a
        // client pays for a provider whose TLS is broken but whose TCP
        // is fine. Both variants, picked by whether an alternate PEM
        // pair was given - a certificate that chains but does not match
        // the name is refused by the CLIENT's verifier, a closed
        // handshake is refused by the socket, and the two travel
        // different paths through the error taxonomy.
        "tlsfail" => {
            let wrong_cert = alt_tls.is_some();
            Plan {
                chaos: base,
                tls: TlsChaos {
                    handshake_fail: Some(match alt_tls {
                        Some(cfg) => HandshakeFault::WrongCert(cfg),
                        None => HandshakeFault::Close,
                    }),
                    handshake_fail_count: u64::MAX,
                    ..Default::default()
                },
                twin: Some(clean_twin),
                onset_note: format!(
                    "tlsfail: every handshake on the faulty server {}, structural \
                     from t0; clean twin on port2",
                    if wrong_cert {
                        "serves a certificate for the wrong name (--tls-alt-cert)"
                    } else {
                        "is closed mid-flight (pass --tls-alt-cert/--tls-alt-key \
                         for the wrong-certificate variant instead)"
                    }
                ),
                onset_after_bodies: None,
            }
        }
        // The truncation-attack shape: each connection is cut a few
        // articles in with NO close_notify, so the stream ends exactly
        // as an attacker cutting it would. Single server on purpose -
        // with a twin to fall back on, a client that accepted the
        // partial article would still produce a good file, and the
        // question here is whether it accepts one at all.
        "tlstruncate" => Plan {
            chaos: base,
            tls: TlsChaos {
                truncate_after_bytes: art,
                ..Default::default()
            },
            twin: None,
            onset_note: format!(
                "tlstruncate: every connection cut after {art} plaintext bytes \
                 ({per_conn} articles) with NO close_notify (truncation attack \
                 shape), structural from t0; partial articles must never be \
                 accepted as complete"
            ),
            onset_after_bodies: None,
        },
        // A bit flipped in the ciphertext after the handshake: the
        // record's AEAD tag fails and the session is unusable. A client
        // must classify it as a connection error and refetch, never
        // hand the plaintext up.
        "tlscorrupt" => Plan {
            chaos: base,
            tls: TlsChaos {
                corrupt_record_after_bytes: art,
                ..Default::default()
            },
            twin: None,
            onset_note: format!(
                "tlscorrupt: one bit flipped in the ciphertext after {art} bytes \
                 ({per_conn} articles) on every connection (record MAC fails), \
                 structural from t0"
            ),
            onset_after_bodies: None,
        },
        // Kill mid-body, then fail the reconnect's handshake once:
        // dial-retry and resume together, which is where a client that
        // reads a failed dial as a dead server abandons a server that
        // is fine two seconds later.
        _ => Plan {
            chaos: base,
            tls: TlsChaos {
                fault_during_resume: Some(art),
                ..Default::default()
            },
            twin: None,
            onset_note: format!(
                "tlsresume: every connection cut after {art} plaintext bytes \
                 ({per_conn} articles, no close_notify) and the NEXT dial's \
                 handshake fails once before the server serves normally again"
            ),
            onset_after_bodies: None,
        },
    }
}

/// §129 3d phase 1, the pair the item exists to tell apart. Both
/// serve the SAME fault - the faulty server answers 430 to 80% of
/// the post, spread over the whole corpus, while the clean twin
/// holds every article - and differ only in what the NZB says the
/// post's age is (see `post_date`).
///
/// freshmiss: the post is 2 hours old, so a provider missing four
/// articles in five did not take the feed. This is the shape a
/// per-job demotion would be FOR.
///
/// oldmiss: the same 430 ratio on a 400-day-old post, which is
/// ordinary retention/propagation loss and carries no guilt at
/// all. It is the safety arm: whatever reacts to freshmiss must
/// do nothing here, because "430 everywhere is NOT proof"
/// (memory nzbfast-retry-propagation-trap) is exactly how a
/// healthy provider gets wrongly demoted on old posts.
///
/// Refusals are answered at wire speed (no `missing_delay_ms`).
/// deadpost prices a SLOW refusal deliberately, but the mock
/// serializes that delay per connection, so borrowing it here
/// would turn the faulty server into a slow refuser and measure
/// that instead - two different faults. A real provider answers
/// a pipelined 430 from an index lookup at about the speed it
/// answers a header. What this profile prices is the cost of
/// ASKING a server that does not have the post: one wasted
/// dispatch per article, and the re-dispatch behind it.
fn miss_plan(
    profile: &str,
    all_ids: &[String],
    base: Chaos,
    clean_twin: Chaos,
    seed: u64,
    fault_count: Option<usize>,
) -> Plan {
    let n = all_ids.len();
    let count = fault_count.unwrap_or(n * 4 / 5);
    let missing: HashSet<String> = stride_positions(n, count, seed)
        .into_iter()
        .map(|i| all_ids[i].clone())
        .collect();
    let note = format!(
        "{profile}: {} of {n} articles answer 430 forever on the faulty \
         server, spread over the whole corpus; the clean twin on port2 \
         holds every one. The NZB declares this post {} - {}",
        missing.len(),
        if profile == "freshmiss" {
            "2 hours old"
        } else {
            "over a year old"
        },
        if profile == "freshmiss" {
            "a provider that did not take the feed"
        } else {
            "ordinary retention loss, no guilt (the safety arm)"
        }
    );
    Plan {
        chaos: Chaos { missing, ..base },
        tls: TlsChaos::default(),
        twin: Some(clean_twin),
        onset_note: note,
        onset_after_bodies: None,
    }
}

/// Resolves when the rig is asked to stop: SIGTERM (what the matrix
/// driver's `stop_chaos` sends) or Ctrl-C at a terminal. Used only to
/// get one last, exact serve-count dump into the log before exit.
async fn shutdown() {
    #[cfg(unix)]
    {
        use tokio::signal::unix::{SignalKind, signal};
        if let Ok(mut term) = signal(SignalKind::terminate()) {
            tokio::select! {
                _ = term.recv() => return,
                _ = tokio::signal::ctrl_c() => return,
            }
        }
    }
    let _ = tokio::signal::ctrl_c().await;
}

pub async fn run(opts: Opts) -> Result<()> {
    // ---- corpus ----
    let per_file = (opts.size / opts.files.max(1) as u64) as usize;
    let mut articles: HashMap<String, Vec<u8>> = HashMap::new();
    let mut corpus: Vec<CorpusFile> = Vec::new();
    // (name, bytes, message-id prefix). Article-izing is DEFERRED to
    // one loop below so --rar-volume-size can replace the whole set
    // first; the prefixes carried here are the ones the loose path
    // always used, so an unpacked run mints byte-identical ids.
    let mut payloads: Vec<(String, Vec<u8>, String)> = Vec::new();
    say(&format!(
        "generating corpus: {} files x {:.1} MB, {} B articles, seed {}",
        opts.files,
        per_file as f64 / 1e6,
        opts.article_size,
        opts.seed
    ));
    for i in 0..opts.files {
        let name = format!("chaos-{:02}.bin", i + 1);
        let data = corpus_data(per_file, opts.seed.wrapping_add(i as u64));
        payloads.push((name, data, format!("chs{}s{i}", opts.seed)));
    }
    for (i, path) in opts.media.iter().enumerate() {
        let name = path
            .file_name()
            .and_then(|n| n.to_str())
            .map(str::to_string)
            .ok_or_else(|| anyhow!("--media path has no file name: {}", path.display()))?;
        let data =
            std::fs::read(path).with_context(|| format!("read --media {}", path.display()))?;
        say(&format!(
            "media file: {} ({:.1} MB) joins the corpus",
            name,
            data.len() as f64 / 1e6
        ));
        payloads.push((name, data, format!("chm{}m{i}", opts.seed)));
    }
    // Pack BEFORE par2, so the recovery volumes protect the RAR set
    // rather than a payload no client ever sees on the wire - which is
    // the order a real post is built in.
    if let Some(vsz) = opts.rar_volume_size {
        let base = match &opts.rar_name {
            Some(n) => n.clone(),
            None => opts
                .nzb
                .file_stem()
                .and_then(|n| n.to_str())
                .unwrap_or("chaos")
                .to_string(),
        };
        let before = payloads.len();
        payloads = pack_rar(vsz, &base, payloads, opts.seed)?;
        say(&format!(
            "rar: packed {} file(s) into {} volume(s) of {:.1} MB as {}.partNN.rar \
             (store) - the client sees only the volumes",
            before,
            payloads.len(),
            vsz as f64 / 1e6,
            base
        ));
    }
    for (name, data, prefix) in &payloads {
        let segs = make_file_articles(name, data, opts.article_size, prefix, &mut articles);
        corpus.push(CorpusFile {
            name: name.clone(),
            segs,
        });
    }
    if let Some(r) = opts.par2_redundancy {
        say(&format!(
            "par2: creating recovery volumes at {r}% redundancy"
        ));
        add_par2(r, &payloads, opts.article_size, &mut articles, &mut corpus)?;
    }
    drop(payloads);
    // Fault selection walks the NZB's own article order.
    let all_ids: Vec<String> = corpus
        .iter()
        .flat_map(|f| f.segs.iter().map(|(id, _, _)| format!("<{id}>")))
        .collect();
    let date = post_date(&opts.profile);
    write_nzb(&opts.nzb, &corpus, date)?;
    say(&format!(
        "corpus: {} articles, {:.1} MB payload; nzb declares date={} \
         ({}); nzb at {}",
        all_ids.len(),
        opts.size as f64 / 1e6,
        date,
        if date == FIXED_POST_DATE {
            "historic post"
        } else {
            "recent post"
        },
        opts.nzb.display()
    ));

    // ---- servers ----
    let tls_cfg = pem_pair(&opts.tls_cert, &opts.tls_key, "--tls-cert/--tls-key")?;
    let alt_tls = pem_pair(
        &opts.tls_alt_cert,
        &opts.tls_alt_key,
        "--tls-alt-cert/--tls-alt-key",
    )?;
    if TLS_PROFILES.contains(&opts.profile.as_str()) && tls_cfg.is_none() {
        bail!(
            "profile {} is a TLS fault shape and needs --tls-cert/--tls-key; \
             serving it over plain TCP would read as a clean run",
            opts.profile
        );
    }
    let plan = plan_with_tls(
        &opts.profile,
        &all_ids,
        opts.per_conn_bps,
        opts.line_bps,
        opts.seed,
        opts.fault_count,
        TlsPlanIn {
            article_size: opts.article_size,
            articles_per_conn: opts.fault_count.unwrap_or(TLS_ARTICLES_PER_CONN),
            alt_cert: alt_tls,
        },
    )?;
    // --miss-delay-ms overrides AFTER the plan is drawn, so the flag
    // works uniformly across profiles without widening `plan`'s
    // signature (pinned by the 3c contract suite).
    let mut plan = plan;
    if let Some(ms) = opts.miss_delay_ms {
        plan.chaos.missing_delay_ms = ms;
        if let Some(t) = &mut plan.twin {
            t.missing_delay_ms = ms;
        }
    }
    // --accept-cap overrides the same way and for the same reason. It
    // reaches the TWIN too: the cap models an account, the twin is this
    // instance's second server, and a rig that capped only the faulty
    // one would leave the borrow somewhere to go and measure nothing.
    if let Some(cap) = opts.accept_cap {
        plan.chaos.accept_cap = Some(cap);
        if let Some(t) = &mut plan.twin {
            t.accept_cap = Some(cap);
        }
    }
    let twin_articles = plan.twin.is_some().then(|| articles.clone());
    // Under TLS the mocks move to their own loopback ports and the
    // fronts own the public ones; the plain path binds as it always did.
    let inner = |port: u16| match tls_cfg {
        Some(_) => "127.0.0.1:0".to_string(),
        None => format!("{}:{}", opts.bind, port),
    };
    let faulty = MockServer::start_bound(
        &inner(opts.port),
        articles,
        HashMap::new(),
        Vec::new(),
        plan.chaos,
    )
    .await;
    let faulty_front = match &tls_cfg {
        Some(cfg) => Some(
            TlsFront::start(
                &format!("{}:{}", opts.bind, opts.port),
                faulty.addr,
                cfg.clone(),
                plan.tls,
            )
            .await
            .with_context(|| format!("bind TLS front on port {}", opts.port))?,
        ),
        None => None,
    };
    say(&format!(
        "profile {} serving on {}:{} [{}{}]",
        opts.profile,
        opts.bind,
        opts.port,
        if plan.twin.is_some() {
            "faulty"
        } else {
            "single"
        },
        if tls_cfg.is_some() { ", TLS" } else { "" }
    ));
    let twin = match plan.twin {
        Some(chaos) => {
            let t = MockServer::start_bound(
                &inner(opts.port2),
                twin_articles.unwrap_or_default(),
                HashMap::new(),
                Vec::new(),
                chaos,
            )
            .await;
            say(&format!(
                "clean twin serving on {}:{} [clean]",
                opts.bind, opts.port2
            ));
            Some(t)
        }
        None => None,
    };
    // Held for the run: dropping a front stops its listener.
    let _twin_front = match (&tls_cfg, &twin) {
        (Some(cfg), Some(t)) => Some(
            TlsFront::start(
                &format!("{}:{}", opts.bind, opts.port2),
                t.addr,
                cfg.clone(),
                TlsChaos::default(),
            )
            .await
            .with_context(|| format!("bind TLS front on port {}", opts.port2))?,
        ),
        _ => None,
    };
    if tls_cfg.is_some() {
        say(
            "TLS on (implicit, the port-563 shape): point clients at it with \
             NZBFAST_EXTRA_CA=<cert.pem>, or with certificate verification off",
        );
    }
    say(&format!("ONSET-PLAN {}", plan.onset_note));

    // ---- monitor: onset + throughput timeline ----
    let mut onset_logged = plan.onset_after_bodies.is_none();
    let mut last = (0u64, 0u64, 0u64); // served faulty, served twin, accepted faulty
    // The FINAL serve-count dump rides on the shutdown signal. A
    // tick-granular last dump can be up to one tick stale, and the §129
    // 3c refetch clause is counted in single articles - so the numbers a
    // matrix leg reads have to be taken after the client is done, not
    // two seconds before it.
    // Under TLS the mock's `accepted` counts connections that got
    // THROUGH the handshake, so the front's own tally is the only place
    // a broken handshake is visible at all - and a TLS profile that
    // silently fails to engage reads exactly like a client that handled
    // it. Printed on every tick AND at shutdown, because a short leg
    // (tlsfail finishes in a second or two) never reaches a tick.
    let tls_tally = || {
        faulty_front.as_ref().map_or(String::new(), |f| {
            let c = &f.counts;
            format!(
                " · tls: dials={} handshakes={} broken={} cuts={} flips={}",
                c.accepted.load(Ordering::Relaxed),
                c.handshakes.load(Ordering::Relaxed),
                c.handshake_faults.load(Ordering::Relaxed),
                c.truncations.load(Ordering::Relaxed),
                c.corruptions.load(Ordering::Relaxed),
            )
        })
    };
    let mut done = Box::pin(shutdown());
    loop {
        tokio::select! {
            _ = tokio::time::sleep(std::time::Duration::from_secs(2)) => {}
            _ = &mut done => {
                say(&faulty.serve_count_line("faulty"));
                if let Some(t) = twin.as_ref() {
                    say(&t.serve_count_line("twin"));
                }
                let tls = tls_tally();
                if !tls.is_empty() {
                    say(&format!("FINAL{tls}"));
                }
                say("FINAL serve counts above; shutting down");
                return Ok(());
            }
        }
        let sf = faulty.served.load(Ordering::Relaxed);
        let af = faulty.accepted.load(Ordering::Relaxed);
        let st = twin
            .as_ref()
            .map_or(0, |t| t.served.load(Ordering::Relaxed));
        if !onset_logged
            && let Some(th) = plan.onset_after_bodies
            && sf >= th
        {
            say(&format!("ONSET fault engaged after {sf} bodies"));
            onset_logged = true;
        }
        if (sf, st, af) != (last.0, last.1, last.2) {
            let tls_note = tls_tally();
            say(&format!(
                "tick faulty: served={sf} (+{}) accepted={af} · twin: served={st} (+{}){tls_note}",
                sf - last.0,
                st - last.1
            ));
            // Serve counts, per tick, per server: the §129 3c refetch
            // clause read from the SERVER's side. In-process the
            // contract suite calls MockServer::refetched(); a bench-box
            // matrix leg drives an external client and has only this
            // log, so the same ledger has to reach it as a line. A
            // resumed job that refetches the whole corpus and one that
            // refetches only its in-flight gap look identical in the
            // served= counter above and differ only here.
            say(&faulty.serve_count_line("faulty"));
            if let Some(t) = twin.as_ref() {
                say(&t.serve_count_line("twin"));
            }
            last = (sf, st, af);
        }
    }
}

#[cfg(test)]
mod rar_fixture_tests {
    use super::*;

    /// `rar` is not on every box (no CI runner has one), so every test
    /// that packs opens with this - the same discipline
    /// `tools/par2-gate.py` enforces for the external `par2` binary.
    fn have_rar() -> bool {
        let bin = std::env::var("RAR_BIN").unwrap_or_else(|_| "rar".into());
        std::process::Command::new(&bin)
            .arg("-?")
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .is_ok()
    }

    /// The volumes REPLACE the payload rather than joining it.
    ///
    /// This is the property the whole fixture rests on and it fails
    /// silently if it is ever loosened: a `pack_rar` that APPENDED
    /// would post the payload AND the volumes, so a client would see a
    /// ready-made media file beside an archive of the same file, import
    /// the loose one, and certify an unpack that never happened. The
    /// run would look exactly like a pass. Measured against the same
    /// hazard one step on, `--par2-redundancy` runs over whatever this
    /// returns, so an appending version would also point the recovery
    /// set at bytes no real post carries.
    #[test]
    fn packing_replaces_the_payload_with_the_volumes() {
        if !have_rar() {
            eprintln!("skipping: no `rar` binary (set RAR_BIN)");
            return;
        }
        let payloads = vec![
            (
                "alpha.mp4".to_string(),
                vec![7u8; 900_000],
                "pfx-a".to_string(),
            ),
            (
                "beta.mp4".to_string(),
                vec![9u8; 900_000],
                "pfx-b".to_string(),
            ),
        ];
        let out = pack_rar(400_000, "Some.Release-CERT", payloads, 4242).unwrap();

        assert!(
            out.len() >= 2,
            "a volume size well under the payload must split: {:?}",
            out.iter().map(|(n, _, _)| n).collect::<Vec<_>>()
        );
        for (name, data, _) in &out {
            assert!(name.ends_with(".rar"), "not a volume: {name}");
            assert!(
                name.starts_with("Some.Release-CERT."),
                "wrong set name: {name}"
            );
            assert!(!data.is_empty(), "empty volume: {name}");
        }
        // The load-bearing half: neither loose payload survives into the
        // corpus. Named individually so a failure says which leaked.
        for leaked in ["alpha.mp4", "beta.mp4"] {
            assert!(
                !out.iter().any(|(n, _, _)| n == leaked),
                "{leaked} reached the corpus beside the volumes - a client \
                 would import it without ever unpacking: {:?}",
                out.iter().map(|(n, _, _)| n).collect::<Vec<_>>()
            );
        }
        // Every volume needs its own message-id prefix, or two volumes
        // mint the same article ids and the second is served as the
        // first - a corrupt set that reads as a clean one.
        let mut prefixes: Vec<&str> = out.iter().map(|(_, _, p)| p.as_str()).collect();
        prefixes.sort_unstable();
        let before = prefixes.len();
        prefixes.dedup();
        assert_eq!(
            before,
            prefixes.len(),
            "duplicate message-id prefixes: {prefixes:?}"
        );
    }
}
