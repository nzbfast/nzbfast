// `job_json` is one `json!` literal per persisted Job field, and the
// macro expands one recursion level per key - so the default limit of
// 128 is a cap on how many facts a job record may carry, which is not a
// design constraint anybody chose. Raised once here rather than
// splitting the literal at every field that happens to cross the line.
#![recursion_limit = "256"]

use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::Instant;
use tracing::info;

// mimalloc on macOS + Linux: faster under the pipeline's alloc/free churn
// on constrained-CPU Linux boxes (ARM NAS, Celeron, Pi), and on macOS it
// lets the post-job idle trim (serve.rs) hand freed memory back to the OS.
// Windows keeps the system allocator. See the note in Cargo.toml.
#[cfg(any(target_os = "macos", target_os = "linux"))]
#[global_allocator]
static GLOBAL_ALLOC: mimalloc::MiMalloc = mimalloc::MiMalloc;

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

mod chaos_serve;
mod conntune;
mod diag;
mod eatvol;
#[cfg(feature = "indexer")]
mod gates;
mod get;
#[cfg(feature = "indexer")]
mod groups;
#[cfg(feature = "indexer")]
mod groupstats;
mod health;
mod identify;
mod identity;
mod import_sab;
mod interests;
mod lanegate;
// TODO 151 (issue #36): external list sources for the watchlist.
mod listsrc;
mod logging;
mod nettools;
mod newznab;
mod notify;
#[cfg(feature = "indexer")]
mod oracle_backtest;
mod persist;
// TODO 151 (issue #36): the first list source's own wire formats.
mod plex;
mod post_cmd;
mod rarfix;
mod ratelimit;
mod repair;
mod rss;
#[cfg(feature = "indexer")]
mod scan;
mod serve;
mod setup;
mod sfx;
mod smart;
mod splitjoin;
mod srrdb;
mod tools;
mod unpack;
#[cfg(feature = "indexer")]
mod wall;
// Slim builds compile out wall.rs; wall_slim.rs keeps the
// `crate::wall::` paths the core filing/rename code uses alive. Shared
// with lib.rs (the embedded/FFI crate root) via `#[path]`.
#[cfg(not(feature = "indexer"))]
#[path = "wall_slim.rs"]
mod wall;
mod watchlist;
mod xrel;
use sfx::*;
use unpack::*;
mod check;
use check::*;
use get::*;
mod streamhub;
use diag::*;
use nettools::*;
use nzbkit::config::{Config, ServerConfig};
use nzbkit::nntp::Connection;
use nzbkit::nzb::{FileKind, Nzb};
// Re-exported, not merely imported: this is what lets the rest of the crate
// say `use crate::MutexExt;` for `lock_ok()` rather than naming nzbkit.
pub use nzbkit::sync::{MutexExt, RwLockExt};
use rarfix::*;
use repair::*;
#[cfg(feature = "indexer")]
use scan::*;
use splitjoin::*;
use streamhub::*;

#[derive(Parser)]
#[command(name = "nzbfast", version, about = "Speed-focused NZB downloader")]
struct Cli {
    /// Path to config with server credentials.
    ///
    /// Falls back to $NZBFAST_CONFIG before the cwd-relative default, so
    /// every subcommand lands on the same file the daemon is serving from.
    /// The container sets that variable (ENV NZBFAST_CONFIG=/config/config.json)
    /// and its entrypoint already honoured it, but the CLI did not: a
    /// `docker exec … import-sab` wrote /config/config.local.json - a real
    /// file, which `probe` then read back happily - while the daemon kept
    /// serving from /config/config.json and showed no servers at all.
    #[arg(
        long,
        env = "NZBFAST_CONFIG",
        default_value = "config.local.json",
        global = true
    )]
    config: PathBuf,

    /// Memory budget for the pipeline's cache tiers (e.g. 512M, 2G).
    /// Default: a quarter of physical RAM, clamped to 256M..16G; in a
    /// container, additionally capped at half the cgroup memory limit
    /// (see MemBudget::auto). Beyond the budget the engine degrades to
    /// disk (materialized volumes, settle read-back) instead of
    /// swapping the machine.
    #[arg(long, global = true)]
    mem_limit: Option<String>,

    #[command(subcommand)]
    command: Command,
}

#[derive(Subcommand)]
enum Command {
    /// Parse an NZB and print its contents + minimality accounting.
    Inspect { nzb: PathBuf },
    /// Read a video file's own facts and work out which film it is, the
    /// way post-download synthesised naming does - without renaming it.
    ///
    /// Prints the container facts, the catalogue shortlist, and whether
    /// the acceptance gate would have accepted a name. Films only.
    Identify {
        /// The video file to read. Local bytes only; nothing is fetched
        /// from a news server.
        file: PathBuf,
        /// Year the release was posted, which bounds the film's release
        /// year from above. Defaults to this year.
        #[arg(long)]
        year: Option<u32>,
    },
    /// Connection + TLS + AUTHINFO smoke test; reports RTT and capabilities.
    Probe,
    /// Throughput A/B: pipelined vs serial article fetching.
    Bench {
        /// Group to draw benchmark articles from.
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Articles per mode.
        #[arg(long, default_value_t = 100)]
        articles: usize,
        /// Concurrent connections per mode.
        #[arg(long, default_value_t = 5)]
        connections: usize,
        /// Pipelined commands in flight per connection.
        #[arg(long, default_value_t = 3)]
        window: usize,
        /// Run both modes at the same time (paired test - cancels drift in
        /// provider/link conditions; use when total bandwidth isn't the cap).
        #[arg(long)]
        simultaneous: bool,
        /// Fixed-duration mode: fetch continuously for this many seconds and
        /// count bytes (immune to cold-article stragglers). 0 = fetch-all.
        #[arg(long, default_value_t = 0)]
        duration: u64,
    },
    /// Fetch + decode articles through the managed pool (Phase 2b shakeout).
    Fetch {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        #[arg(long, default_value_t = 200)]
        articles: usize,
        #[arg(long, default_value_t = 6)]
        connections: usize,
        #[arg(long, default_value_t = 3)]
        window: usize,
    },
    /// Bandwidth soak: ALL configured servers pull from one shared queue.
    /// Proves aggregate throughput beyond any single provider's cap.
    Soak {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Total articles to pull (≈ 0.75 MB each).
        #[arg(long, default_value_t = 4000)]
        articles: usize,
        /// Connections PER SERVER.
        #[arg(long, default_value_t = 8)]
        connections: usize,
        #[arg(long, default_value_t = 4)]
        window: usize,
        /// Parallel yEnc decode workers.
        #[arg(long, default_value_t = 4)]
        decoders: usize,
        /// Independent tokio runtimes (each with its own I/O driver).
        #[arg(long, default_value_t = 3)]
        shards: usize,
        /// Socket receive buffer per connection, in MB (0 = kernel default).
        #[arg(long, default_value_t = 4)]
        rcvbuf_mb: u32,
    },
    /// Download an NZB end to end: pool → decode → write at final offsets.
    Get {
        nzb: PathBuf,
        /// Output directory.
        #[arg(long, default_value = "downloads")]
        out: PathBuf,
        /// Connections per server.
        #[arg(long, default_value_t = 8)]
        connections: usize,
        #[arg(long, default_value_t = 4)]
        window: usize,
        #[arg(long, default_value_t = 4)]
        decoders: usize,
        /// PAR2 verify mode. "lean" is the slow-CPU boost: like fast,
        /// but also skips per-article yEnc CRCs once PAR2 covers a
        /// file - corruption detection rests on the PAR2 block CRC32
        /// alone in-stream (one CRC32 layer instead of two; ~7% more
        /// single-core throughput). End-of-job verification and repair
        /// are unchanged, and PAR2-less files keep article CRCs.
        /// "fast" claims in-stream blocks by CRC32 only
        /// (each article's yEnc CRC already passed; 2.9× on CPU-bound
        /// boxes), "full" also MD5s every block. Settle read-back always
        /// hashes in full.
        #[arg(long, default_value = "fast")]
        verify: String,
        /// Sampled STAT sweep first; abort without downloading if the post
        /// can't possibly complete (missing > recovery everywhere).
        #[arg(long)]
        preflight: bool,
        /// Disable store-mode direct extraction (write RAR volumes to disk
        /// instead of extracting them in-stream).
        #[arg(long)]
        no_extract: bool,
        /// Do not download sample/proof clips at all. A sample-named file
        /// large enough to plausibly be the feature is still fetched, and
        /// a job whose only video is sample-named is fetched whole.
        #[arg(long)]
        skip_samples: bool,
        /// Archive password for encrypted RAR sets. Usually unnecessary:
        /// a `<meta type="password">` in the NZB or a `{{password}}`
        /// suffix in the NZB filename is picked up automatically.
        #[arg(long)]
        password: Option<String>,
    },
    /// Pre-flight availability check: pipelined STAT sweep across all
    /// servers; verdict COMPLETE / REPAIRABLE / IMPOSSIBLE without
    /// downloading a byte of payload.
    Check {
        nzb: PathBuf,
        /// Percentage of each file's segments to sample (100 = every one).
        #[arg(long, default_value_t = 100)]
        sample: u8,
        /// STAT connections per server.
        #[arg(long, default_value_t = 4)]
        connections: usize,
        /// Pipelined STATs in flight per connection.
        #[arg(long, default_value_t = 50)]
        window: usize,
        /// Answer only the daemon's question - "must this job be
        /// abandoned?" - and take its shortcuts to get there: stop
        /// asking other servers about an article once one has it, and
        /// stop the sweep outright once the deficit outweighs the
        /// recovery budget. When volume names leave that budget
        /// unsizable it buys the block size first - one article - so
        /// there is a budget to stop against at all. Much faster and
        /// much less to report: the per-server availability lines are a
        /// claim about each server individually, which a sweep that
        /// skips questions cannot make.
        #[arg(long)]
        fast: bool,
    },
    /// Verify files in a directory against the PAR2 set found there.
    Verify { dir: PathBuf },
    /// Process an already-assembled directory offline: PAR2-repair from
    /// on-disk recovery (no network), then extract the RAR archives. The
    /// same repair+extract pipeline the daemon runs after a download,
    /// pointed at local files - the robustness-harness hook.
    Extract {
        /// Directory of assembled archive volumes (+ optional .par2 set).
        dir: PathBuf,
        /// Password for encrypted archives.
        #[arg(long)]
        password: Option<String>,
    },
    /// Per-stage CPU benchmark: where compute goes at line rate, and the
    /// machine's compute ceiling vs its network and disk.
    BenchCpu {
        /// MB of synthetic payload per stage.
        #[arg(long, default_value_t = 512)]
        mb: usize,
    },
    /// Full system benchmark: network + compute + disk → expected max
    /// download speed, the bottleneck, and a server-diversity report.
    Sysbench {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
    },
    /// Loopback ceiling bench server: a local NNTP server fast enough
    /// that the CLIENT is the bottleneck. Serves a synthetic release of
    /// any size from ~1 MB of RAM and writes the matching .nzb - point
    /// ANY newsreader client (nzbfast, NZBGet, SABnzbd, …) at it to
    /// measure that client's pipeline ceiling with no provider limits.
    Mockserve {
        #[arg(long, default_value_t = 1190)]
        port: u16,
        /// Bind address; 0.0.0.0 serves LAN clients too.
        #[arg(long, default_value = "127.0.0.1")]
        bind: String,
        /// Files in the synthetic release.
        #[arg(long, default_value_t = 16)]
        files: u32,
        /// Size of each file ("2G", "512M", …).
        #[arg(long, default_value = "2G")]
        file_size: String,
        /// Article payload size ("750K"…); ~740K matches real posts.
        #[arg(long, default_value = "740K")]
        article_size: String,
        /// Where to write the matching NZB.
        #[arg(long, default_value = "bench-loopback.nzb")]
        nzb: PathBuf,
        /// Serve a matching PAR2 index too (verify-only: no recovery
        /// slices). Gives the client real live-verify MD5/CRC load -
        /// required for any constrained-CPU bench to be representative.
        #[arg(long)]
        par2: bool,
        /// PEM cert chain; with --tls-key, serves implicit TLS (port-563
        /// shape) instead of plain TCP. Every provider is TLS, so the
        /// plain leg alone measures a path no real user is on. Make a
        /// pair with (basicConstraints=CA:FALSE matters - rustls refuses
        /// a CA certificate used as the server cert, CaUsedAsEndEntity):
        ///   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem \
        ///     -out cert.pem -days 30 -subj /CN=localhost \
        ///     -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
        ///     -addext basicConstraints=critical,CA:FALSE
        /// then point the client at it with NZBFAST_EXTRA_CA=cert.pem.
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// PEM private key matching --tls-cert.
        #[arg(long)]
        tls_key: Option<PathBuf>,
    },
    /// Chaos NNTP server (TODO 111 fault matrix): serves a generated
    /// corpus through the in-process chaos mock with a fault profile
    /// chosen by flag, so ANY client can be raced against the same
    /// fault shapes the payout rigs price. Writes the matching .nzb;
    /// two-server profiles bind a clean twin on --port2.
    // The flags live in chaos_serve.rs, beside the profile table they
    // select: a fault shape and the switch that turns it on drift apart
    // when they sit in different files. A plain comment, not a doc one:
    // clap prints doc comments as help text.
    #[command(hide = true)]
    ChaosServe(chaos_serve::Cli),
    /// Score the M29 availability oracle against reality: sample
    /// indexed releases per (family, age bucket) cell, STAT them on
    /// every configured server, and print what the ledger predicted
    /// beside what the network answered.
    ///
    /// The oracle's routing skip acts on counted ARTICLES, and articles
    /// of one posting are not independent samples - one doomed release
    /// can pin a whole cell red. This is how that is caught: it reports
    /// precision, recall and the false-skip rate (the share of skipped
    /// provider attempts that would have served the release).
    ///
    /// The index is opened read-only and nothing is written back, so it
    /// is safe against a live daemon's database. No change to
    /// MIN_SAMPLES, GREEN_LOW or RED_HIGH ships without a run of this.
    #[cfg(feature = "indexer")]
    OracleBacktest {
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
        /// Releases sampled per (family, age bucket) cell.
        #[arg(long, default_value_t = 12)]
        releases: usize,
        /// Message-ids STATted per release, spread evenly across its
        /// files (head-only sampling misses tail takedowns).
        #[arg(long, default_value_t = 3)]
        msgids: usize,
        /// Only score this group family (repeatable; default = the
        /// families the ledger has evidence in).
        #[arg(long = "family")]
        families: Vec<String>,
        /// Only score this age bucket 0-6 (repeatable).
        #[arg(long = "bucket")]
        buckets: Vec<u8>,
        /// Cells to score, most ledger evidence first.
        #[arg(long, default_value_t = 6)]
        cells: usize,
        /// Seed for the release sample. The same seed replays the same
        /// draw order, but the age window it draws from moves with the
        /// clock, so a run tomorrow scores different releases.
        #[arg(long, default_value_t = 1)]
        seed: u64,
        /// A release counts as carried by a backbone when at least this
        /// fraction of its probed articles answered 223.
        #[arg(long, default_value_t = 0.5)]
        truth: f64,
        /// Seconds spent drawing one cell's sample out of the index
        /// before settling for a short one. A family with nothing
        /// indexed in the bucket's age window costs a full window scan
        /// per attempt, so the draw is bounded by the clock.
        #[arg(long, default_value_t = 15)]
        sample_secs: u64,
        #[arg(long)]
        json: bool,
    },
    /// Scan group headers into the local release index (M12).
    #[cfg(feature = "indexer")]
    Index {
        #[arg(long, default_value = "alt.binaries.teevee")]
        group: String,
        /// Articles to scan backwards from the newest (first run) -
        /// later runs resume from the stored high-water mark.
        #[arg(long, default_value_t = 500_000)]
        backfill: u64,
        /// Only index posts newer than this ("90d"/"26w"/"6m"/"2y";
        /// bare number = days; empty/0 = off). On a first scan this
        /// overrides --backfill: the group's article range is bisected
        /// by Date to find the cutoff, so old headers are never fetched.
        #[arg(long, default_value = "")]
        max_age: String,
        /// Ingest gates JSON - kinds/year/resolution/language/title/size
        /// filters applied before anything is stored (see gates.rs).
        #[arg(long)]
        gates: Option<PathBuf>,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Search the local release index.
    #[cfg(feature = "indexer")]
    Search {
        query: String,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
        /// Write the NZB of the first hit to this path.
        #[arg(long)]
        nzb: Option<PathBuf>,
    },
    /// Seed the local pre database from api.predb.net, so the
    /// correlation legs have announcements from before the live feed
    /// was switched on. Same walk, pacing and refusals as the
    /// dashboard's button; no daemon needed.
    #[cfg(feature = "indexer")]
    PredbSeed {
        /// How far back to reach, in days.
        #[arg(long, default_value_t = 180)]
        days: u32,
        /// Rows the pre table may hold (the importer stops short of it
        /// rather than importing rows a prune would eat).
        #[arg(long, default_value_t = 250_000)]
        max_rows: u64,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Scan a Spotnet group's spot headers (From-record parse + RSA verify)
    /// into the local index (M14j). Header-only pass - no article bodies.
    #[cfg(feature = "indexer")]
    Spots {
        #[arg(long, default_value = "free.pt")]
        group: String,
        /// Articles to scan backwards from the newest (first run) -
        /// later runs resume from the stored high-water mark.
        #[arg(long, default_value_t = 100_000)]
        backfill: u64,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Search locally indexed spots by title.
    #[cfg(feature = "indexer")]
    SpotSearch {
        query: String,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// What this index was asked for and could not answer (TODO 131
    /// D3). Read it to decide what the scanner should deepen or
    /// backfill next; nothing acts on it by itself.
    #[cfg(feature = "indexer")]
    SearchMisses {
        /// Rolling window in days.
        #[arg(long, default_value_t = 30)]
        days: i64,
        /// How few results still counts as a miss (0 = only the true
        /// zeroes).
        #[arg(long, default_value_t = 0)]
        thin: u32,
        /// Only one surface: wall (the dashboard and the wall's search
        /// box) or newznab (Sonarr/Radarr and friends).
        #[arg(long)]
        surface: Option<String>,
        #[arg(long, default_value_t = 50)]
        limit: u32,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Posted-NZB ingestion rung: fetch the one-file `*.nzb` posts the
    /// index already holds (uploaders drop the .nzb beside the
    /// content), parse each, and join its payload message-ids against
    /// the index. An imported name is only reported against a row when
    /// MULTIPLE message-ids agree - identity by message-id only, never
    /// time/size. Report-only until the identity claims layer lands.
    #[cfg(feature = "indexer")]
    NzbImport {
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
        /// Stop after this many objects (0 = walk them all).
        #[arg(long, default_value_t = 0)]
        limit: usize,
        /// Resume cursor: only rows whose arrival ordinal
        /// (`releases.arrival_seq`) is above this are considered.
        #[arg(long, default_value_t = 0)]
        after: i64,
        /// Write the full per-object JSON report here.
        #[arg(long)]
        report: Option<PathBuf>,
        /// Write quorum joins as proven-name claims (provenance
        /// nzb-import) through the identity claims layer. Default off:
        /// measure first.
        #[arg(long)]
        apply: bool,
    },
    /// Fetch one spot's NZB payload (X-XML headers → alt.binaries.ftd
    /// segments → inflate) and write the NZB file.
    #[cfg(feature = "indexer")]
    SpotGet {
        /// Spot message-id (angle brackets optional).
        msgid: String,
        #[arg(long, default_value = "out.nzb")]
        nzb: PathBuf,
        #[arg(long, default_value = "index.db")]
        db: PathBuf,
    },
    /// Interactive setup: add/manage usenet servers, no file editing.
    /// Returns success to proceed; exits non-zero if you choose to quit.
    Setup,
    /// Stream an NZB immediately: enqueue it on the running daemon at
    /// Force priority and hand the OS default player the .m3u - watch
    /// while it downloads (M11).
    Stream {
        /// Path to a .nzb file, or an http(s) URL to one.
        nzb: String,
        /// Daemon to submit to.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        #[arg(long, default_value_t = 6789)]
        port: u16,
        /// API key (or NZB key), if the daemon requires one.
        #[arg(long)]
        apikey: Option<String>,
        /// Print the URLs only; don't launch the player.
        #[arg(long)]
        no_open: bool,
    },
    /// Run the download daemon: queue manager + watch folder + SABnzbd-
    /// compatible API (Sonarr/Radarr-ready).
    Serve {
        /// Listening port. 0 asks the OS for a free one, which a
        /// launcher that starts the daemon itself should prefer: the
        /// chosen port is reported in the readiness banner and in
        /// runtime.json beside the settings file.
        #[arg(long, default_value_t = 6789)]
        port: u16,
        /// Listen address. The default serves every interface, which is
        /// what a NAS/headless box with Sonarr or a phone remote on
        /// another host needs; use 127.0.0.1 to keep it to this machine.
        #[arg(long, default_value = "0.0.0.0")]
        bind: String,
        /// PEM certificate chain; with --tls-key the dashboard and API
        /// are served over HTTPS instead of plain HTTP (one listener,
        /// one scheme). A reverse proxy or Tailscale stays a fine
        /// alternative - see the manual's "expose it safely" section.
        /// Self-signed test pair (basicConstraints=CA:FALSE matters -
        /// strict clients refuse a CA certificate as a server cert):
        ///   openssl req -x509 -newkey rsa:2048 -nodes -keyout key.pem \
        ///     -out cert.pem -days 365 -subj /CN=localhost \
        ///     -addext subjectAltName=DNS:localhost,IP:127.0.0.1 \
        ///     -addext basicConstraints=critical,CA:FALSE
        #[arg(long)]
        tls_cert: Option<PathBuf>,
        /// PEM private key matching --tls-cert.
        #[arg(long)]
        tls_key: Option<PathBuf>,
        /// Open the web dashboard in the default browser once the server
        /// is listening (the double-click launchers use this).
        #[arg(long)]
        open: bool,
        /// Require this API key on every request.
        #[arg(long)]
        apikey: Option<String>,
        /// Secondary add-only key (SABnzbd "NZB key"): may addfile/addurl
        /// but not read the queue or change settings.
        #[arg(long)]
        nzbkey: Option<String>,
        /// Completed downloads root (per-category subdirs).
        #[arg(long, default_value = "downloads")]
        out: PathBuf,
        /// Poll this folder for new .nzb files.
        #[arg(long)]
        watch: Option<PathBuf>,
        /// Post-processing script, run after every job with SABnzbd's
        /// positional args + SAB_* env vars (script ecosystem compatible).
        #[arg(long)]
        script: Option<PathBuf>,
        /// Pause new jobs when free space drops below this (e.g. 10G).
        #[arg(long)]
        min_free: Option<String>,
        /// Download quota per period, e.g. 100G (Force jobs bypass).
        #[arg(long)]
        quota: Option<String>,
        /// Quota period: d = daily, w = weekly (Monday), m = monthly
        /// (local-calendar boundaries).
        #[arg(long, default_value = "d")]
        quota_period: char,
        /// RSS feeds config (JSON list of {url, interval_secs, category,
        /// rules}) - items passing the rules are auto-downloaded.
        #[arg(long)]
        feeds: Option<PathBuf>,
        /// Connections per server (each server still capped by its own
        /// configured count and by any measured auto-tune knee). 100 is
        /// the allowance most providers sell; asking for the full
        /// allowance and letting the tuner trim beats a low default
        /// that quietly caps every fast server.
        #[arg(long, default_value_t = 100)]
        connections: usize,
        #[arg(long, default_value_t = 4)]
        window: usize,
        #[arg(long, default_value_t = 6)]
        decoders: usize,
        /// Initial download speed cap, e.g. "4M" or "500K" (bytes/sec;
        /// bare numbers accepted). 0 = unlimited. Adjustable live via
        /// mode=config&name=speedlimit.
        #[arg(long)]
        speedlimit: Option<String>,
        /// Time-of-week scheduler: JSON file of {days, time, action,
        /// value} entries, evaluated once per minute in LOCAL time.
        #[arg(long)]
        schedule: Option<PathBuf>,
        /// Auto-adjust the speed cap to yield to other household traffic
        /// (RTT-governed, LEDBAT-style). Toggleable live via
        /// mode=config&name=auto_speed.
        #[arg(long)]
        auto_speed: bool,
        /// Categories whose jobs become metadata-only library entries
        /// (M14i): availability-checked, .strm written, downloaded on
        /// first playback of /stream/<nzo_id>.
        #[arg(long, value_delimiter = ',')]
        library_cats: Vec<String>,
        /// Re-verify parked library entries this often (seconds).
        #[arg(long, default_value_t = 21600)]
        library_recheck_secs: u64,
        /// Index database (newznab facade + dashboard browse).
        #[cfg(feature = "indexer")]
        #[arg(long, default_value = "index.db")]
        index_db: PathBuf,
        /// Groups to OVER-scan continuously (comma-separated); the
        /// newznab endpoint serves whatever lands in the index.
        #[cfg(feature = "indexer")]
        #[arg(long, value_delimiter = ',')]
        index_groups: Vec<String>,
        /// Seconds between incremental index scans.
        #[cfg(feature = "indexer")]
        #[arg(long, default_value_t = 900)]
        index_interval: u64,
        /// Articles to backfill on a group's first scan.
        #[cfg(feature = "indexer")]
        #[arg(long, default_value_t = 20000)]
        index_backfill: u64,
        /// Only index posts newer than this ("90d"/"6m"/"2y"; bare
        /// number = days; empty/0 = off). Overrides --index-backfill on
        /// a group's first scan via a Date bisection.
        #[cfg(feature = "indexer")]
        #[arg(long, default_value = "")]
        index_max_age: String,
        /// Ingest gates JSON for the index scanner (see gates.rs).
        #[cfg(feature = "indexer")]
        #[arg(long)]
        index_gates: Option<PathBuf>,
    },
    /// Import servers from a SABnzbd installation's sabnzbd.ini.
    ImportSab {
        /// Path to sabnzbd.ini. Omit to search the standard SABnzbd
        /// install locations, the nzbfast config directory, and the
        /// current directory (issue #15: in Docker, copy the file into
        /// /config and plain `import-sab` finds it).
        ini: Option<PathBuf>,
        /// Where to write our config (default: the global --config path).
        #[arg(long)]
        out: Option<PathBuf>,
        /// Overwrite an existing config file.
        #[arg(long)]
        force: bool,
    },
    /// Upload files as yEnc posts to a test group and emit the matching
    /// NZB (ops tool; runbook: bench/nested-corpus/POSTING.md). Requires
    /// an explicit --post-server - posting never picks a server for you.
    Post {
        /// Files and/or directories (walked recursively) to post.
        paths: Vec<PathBuf>,
        /// The ONE configured server to post through (host, or host:port).
        /// Mandatory: there is no default.
        #[arg(long)]
        post_server: String,
        /// Where to write the NZB describing the post.
        #[arg(long, default_value = "posted.nzb")]
        nzb: PathBuf,
        /// Newsgroup to post into.
        #[arg(long, default_value = "alt.binaries.test")]
        group: String,
        /// From header value.
        #[arg(long, default_value = "corpus@nzbfast.com")]
        from: String,
        /// Message-ID domain (right-hand side of generated ids).
        #[arg(long, default_value = "corpus.nzbfast.com")]
        msgid_domain: String,
        /// Decoded payload bytes per article ("700K", "512K", …).
        #[arg(long, default_value = "700K")]
        article_size: String,
        /// Optional set title: subjects become
        /// `title [i/n] - "file" yEnc (p/t)`.
        #[arg(long)]
        title: Option<String>,
        /// Concurrent posting connections.
        #[arg(long, default_value_t = 4)]
        connections: usize,
        /// After posting, download the set back from the same server and
        /// hash it against the sources.
        #[arg(long)]
        verify: bool,
    },
    /// Build an NZB of one COMPLETE release (data + par2 main + volumes,
    /// one poster, shared filename stem) found via OVER - the full-pipeline
    /// test fixture generator.
    #[cfg(feature = "indexer")]
    MakeReleaseNzb {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Minimum total release size.
        #[arg(long, default_value_t = 1.0)]
        min_gb: f64,
        /// Maximum total release size.
        #[arg(long, default_value_t = 15.0)]
        max_gb: f64,
        #[arg(long, default_value = "release.nzb")]
        out: PathBuf,
    },
    /// Build a real test NZB from complete multipart posts found via OVER.
    #[cfg(feature = "indexer")]
    MakeTestNzb {
        #[arg(long, default_value = "alt.binaries.boneless")]
        group: String,
        /// Number of complete files to include.
        #[arg(long, default_value_t = 3)]
        files: usize,
        /// Skip files larger than this.
        #[arg(long, default_value_t = 300)]
        max_file_mb: u64,
        #[arg(long, default_value = "test.nzb")]
        out: PathBuf,
    },
}

/// Every subcommand runs on a thread we size ourselves, never on the
/// process's own main thread.
///
/// `#[tokio::main]` is `block_on` on the calling thread, so the whole async
/// body's state machine lives on that thread's stack - and Windows reserves
/// 1 MB for the main thread, against 8 MB on Linux and macOS. A debug build
/// of `serve` overflowed it and the process died before it bound its port,
/// with no panic message beyond "thread 'main' has overflowed its stack" and
/// no backtrace, because a Windows stack overflow aborts without unwinding.
/// That took the ENTIRE daemon e2e suite - 39 integration tests, the only
/// coverage of the queue, the SAB/NZBGet facades, streaming and
/// post-processing - with it on Windows, and it also meant no Windows
/// contributor could run the daemon they had just built. It was invisible
/// because `cargo test` stops at the first failing target, so the suite
/// never got as far as `tests/daemon.rs` (see pr-check.yml's
/// `--no-fail-fast`).
///
/// 16 MB, and the same on every platform so the stack a release build gets
/// is the stack the tests proved. It costs no memory: a thread stack is
/// reserved address space, committed by the page as it is touched.
fn main() -> Result<()> {
    // A panic in a detached worker (wall enricher, IMDb refresher, an
    // HTTP worker) kills only that thread: the daemon keeps serving with
    // the subsystem silently dark. Log every panic with its thread name
    // and location through the normal output (logtee captures it when
    // the daemon is logging to a file), then run the default hook so
    // backtraces and exit behaviour are unchanged.
    let default_hook = std::panic::take_hook();
    std::panic::set_hook(Box::new(move |info| {
        let thread = std::thread::current();
        let loc = info
            .location()
            .map(|l| format!("{}:{}", l.file(), l.line()))
            .unwrap_or_else(|| "unknown".into());
        // NOT a tracing event, on purpose. This hook is installed before
        // the subscriber exists and still has to work after it is gone -
        // a panic during wind-down, or one in a thread that outlives the
        // subscriber, would otherwise print nothing at all. The one place
        // in the daemon where a raw write to stderr is the safer call.
        eprintln!(
            "[panic] thread '{}' at {loc}",
            thread.name().unwrap_or("unnamed")
        );
        default_hook(info);
    }));
    std::thread::Builder::new()
        .name("nzbfast-main".into())
        .stack_size(16 * 1024 * 1024)
        .spawn(run)
        .expect("spawn the main thread")
        .join()
        // Re-raise rather than repackage: this keeps a panic's own message,
        // location and exit status exactly as it would have been had the
        // body run on the main thread.
        .unwrap_or_else(|panic| std::panic::resume_unwind(panic))
}

/// The mockserve throughput line, every 10 s while it serves.
///
/// Out of line only because `run()` is at the §106 function ceiling and
/// this is the one piece of that arm that stands alone. Silent while
/// nothing is being served: a bench log that prints zeros every ten
/// seconds buries the run it is measuring.
fn spawn_benchserve_stats(set: std::sync::Arc<nzbkit::benchserve::BenchSet>) {
    tokio::spawn(async move {
        let (mut last_b, mut last_n) = (0u64, 0u64);
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(10)).await;
            let b = set.bytes.load(std::sync::atomic::Ordering::Relaxed);
            let n = set.served.load(std::sync::atomic::Ordering::Relaxed);
            if b != last_b {
                info!(
                    target: "benchserve",
                    "{:>7.2} Gbps wire · {} articles ({} total)",
                    (b - last_b) as f64 * 8.0 / 10.0 / 1e9,
                    n - last_n,
                    n
                );
            }
            (last_b, last_n) = (b, n);
        }
    });
}

#[tokio::main]
async fn run() -> Result<()> {
    let cli = Cli::parse();
    // Before anything that can log. The daemon's log is read out of a
    // screenshot hours later and needs stamps; a foreground command's
    // output is read as it scrolls past and does not (see logging.rs).
    logging::init(match cli.command {
        Command::Serve { .. } => logging::Style::Daemon,
        _ => logging::Style::Cli,
    });
    nzbkit::disk::raise_fd_limit();
    // Windows 11 parks sustained background CPU work on E-cores a few
    // seconds in (EcoQoS) - a daemon downloading or repairing IS
    // background work, and the measured cliff is 8x (see
    // mem::opt_out_of_power_throttling).
    nzbkit::mem::opt_out_of_power_throttling();
    let budget = match &cli.mem_limit {
        Some(v) => nzbkit::mem::MemBudget::with_total(
            serve::parse_size(v)
                .ok_or_else(|| anyhow::anyhow!("--mem-limit: can't parse size {v:?}"))?,
        ),
        None => nzbkit::mem::MemBudget::auto(),
    };
    // The repair paths run several layers below any command's call site and
    // need the same budget everything else honours.
    nzbkit::mem::set_process_budget(budget);
    match cli.command {
        Command::Inspect { nzb } => inspect(&nzb),
        Command::Identify { file, year } => identify_cmd(&cli.config, &file, year),
        Command::Probe => probe(&cli.config).await,
        Command::Stream {
            nzb,
            host,
            port,
            apikey,
            no_open,
        } => stream_cmd(&nzb, &host, port, apikey.as_deref(), no_open),
        Command::Bench {
            group,
            articles,
            connections,
            window,
            simultaneous,
            duration,
        } => {
            bench(
                &cli.config,
                &group,
                articles,
                connections,
                window,
                simultaneous,
                duration,
            )
            .await
        }
        Command::Fetch {
            group,
            articles,
            connections,
            window,
        } => fetch(&cli.config, &group, articles, connections, window).await,
        Command::Soak {
            group,
            articles,
            connections,
            window,
            decoders,
            shards,
            rcvbuf_mb,
        } => {
            soak(
                &cli.config,
                &group,
                articles,
                connections,
                window,
                decoders,
                shards,
                rcvbuf_mb,
            )
            .await
        }
        Command::Get {
            nzb,
            out,
            connections,
            window,
            decoders,
            verify,
            preflight,
            no_extract,
            skip_samples,
            password,
        } => {
            let (fast_verify, verify_lean) = match verify.as_str() {
                "fast" => (true, false),
                "full" => (false, false),
                // Lean: for slow CPUs. Skips the per-article yEnc CRC
                // once PAR2 covers a file - in-stream corruption is then
                // caught by the PAR2 block CRC32 alone (one CRC32 layer
                // instead of two). End-of-job verification and repair
                // are unchanged; PAR2-less downloads keep article CRCs.
                "lean" => (true, true),
                other => anyhow::bail!("--verify must be fast, full, or lean, not {other:?}"),
            };
            // M32 perf: CLI downloads have no /stream readers, so
            // dropping settled page cache is safe and saves real CPU on
            // small-RAM Linux boxes (see disk.rs maybe_drop_cache).
            #[cfg(target_os = "linux")]
            nzbkit::disk::set_drop_cache_default(true);
            if preflight {
                let verdict = check(&cli.config, &nzb, 10, 4, 50, true).await?;
                if let Verdict::Impossible {
                    est_missing,
                    recovery,
                    measured,
                    ..
                } = verdict
                {
                    anyhow::bail!(
                        "aborting: pre-flight says this post cannot complete - {}",
                        crate::check::impossible_reason(est_missing, recovery, &measured)
                    );
                }
            }
            get_with_progress(
                &cli.config,
                &nzb,
                &out,
                connections,
                window,
                decoders,
                fast_verify,
                verify_lean,
                no_extract,
                // No CLI setting for this; matching the daemon default
                // keeps one behaviour across both front ends, and it
                // only ever fires on a repair that verified.
                true,
                skip_samples,
                password,
                // No CLI consent prompt: `unpack_eat_volumes=low_disk`
                // asks per job through the dashboard drawer, and there is
                // nowhere here to ask. `always` needs no consent and
                // still applies to an offline `get`.
                false,
                None,
                None,
                "",
                None,
                budget,
            )
            .await
        }
        Command::ImportSab { ini, out, force } => {
            let ini = match ini {
                Some(p) => p,
                None => {
                    // Search near the config we would write to (Docker:
                    // /config), the cwd, then the OS install locations.
                    let out_path = out.as_deref().unwrap_or(&cli.config);
                    let mut near: Vec<&std::path::Path> = out_path.parent().into_iter().collect();
                    near.push(std::path::Path::new("."));
                    match nzbkit::config::sabnzbd_ini_path(&near) {
                        Some(p) => {
                            info!(target: "import", "using {}", p.display());
                            p
                        }
                        None => anyhow::bail!(
                            "no sabnzbd.ini found - looked in {}, the current \
                             directory, and the standard SABnzbd locations; \
                             pass the path: nzbfast import-sab <path/to/sabnzbd.ini>",
                            out_path
                                .parent()
                                .filter(|p| !p.as_os_str().is_empty())
                                .unwrap_or(std::path::Path::new("."))
                                .display()
                        ),
                    }
                }
            };
            import_sab::import(&ini, out.as_deref().unwrap_or(&cli.config), force)
        }
        Command::BenchCpu { mb } => {
            bench_cpu(mb);
            Ok(())
        }
        Command::Sysbench { group } => sysbench_cmd(&cli.config, &group).await,
        Command::Mockserve {
            port,
            bind,
            files,
            file_size,
            article_size,
            nzb,
            par2,
            tls_cert,
            tls_key,
        } => {
            let fsize = serve::parse_size(&file_size)
                .ok_or_else(|| anyhow::anyhow!("bad --file-size {file_size:?}"))?;
            let asize = serve::parse_size(&article_size)
                .ok_or_else(|| anyhow::anyhow!("bad --article-size {article_size:?}"))?
                as usize;
            if par2 {
                info!(target: "benchserve", "hashing the synthetic set for the PAR2 index …");
            }
            let set = std::sync::Arc::new(nzbkit::benchserve::BenchSet::with_par2(
                files, fsize, asize, par2,
            ));
            std::fs::write(&nzb, set.nzb())?;
            info!(
                target: "benchserve",
                "set: {} files × {:.2} GB = {:.2} GB{} · nzb: {}",
                files,
                fsize as f64 / 1e9,
                set.total_bytes() as f64 / 1e9,
                if par2 { " + par2 index" } else { "" },
                nzb.display()
            );
            let tls = match (&tls_cert, &tls_key) {
                (Some(c), Some(k)) => Some(nzbkit::benchserve::tls_config(c, k)?),
                (None, None) => None,
                _ => anyhow::bail!("--tls-cert and --tls-key must be given together"),
            };
            info!(
                target: "benchserve",
                "point any client at host {bind} port {port}, TLS {}, no auth\n\
                 [benchserve]   nzbfast: {{\"servers\":[{{\"host\":\"localhost\",\"port\":{port},\"tls\":{},\"connections\":16}}]}}\n\
                 [benchserve]   stats print every 10 s; Ctrl-C to stop",
                if tls.is_some() { "ON" } else { "OFF" },
                tls.is_some()
            );
            if tls.is_some() {
                info!(
                    target: "benchserve",
                    "  self-signed: run the client with NZBFAST_EXTRA_CA=<cert.pem>"
                );
            }
            spawn_benchserve_stats(set.clone());
            nzbkit::benchserve::serve_with(&format!("{bind}:{port}"), set, tls).await?;
            Ok(())
        }
        Command::ChaosServe(cli) => chaos_serve::run(cli.opts(serve::parse_size)?).await,
        #[cfg(feature = "indexer")]
        Command::Index {
            group,
            backfill,
            max_age,
            gates,
            db,
        } => {
            let age = parse_age(&max_age)?;
            let gates = gates.as_deref().map(gates::Gates::load).transpose()?;
            index_scan(&cli.config, &group, backfill, age, gates.as_ref(), &db).await
        }
        Command::Post {
            paths,
            post_server,
            nzb,
            group,
            from,
            msgid_domain,
            article_size,
            title,
            connections,
            verify,
        } => {
            let asize = serve::parse_size(&article_size)
                .ok_or_else(|| anyhow::anyhow!("bad --article-size {article_size:?}"))?
                as usize;
            post_cmd::run(
                &cli.config,
                post_cmd::PostArgs {
                    paths,
                    post_server,
                    nzb,
                    group,
                    from,
                    msgid_domain,
                    article_size: asize,
                    title,
                    connections,
                    verify,
                },
            )
            .await
        }
        #[cfg(feature = "indexer")]
        Command::PredbSeed { days, max_rows, db } => {
            // Blocking (paced HTTP, one request every 2 s) and there is
            // nothing else to do meanwhile, so it runs on a worker
            // rather than stalling the runtime.
            let msg = tokio::task::spawn_blocking(move || {
                serve::predb_seed::run_cli(&db, days.clamp(1, 366), max_rows)
            })
            .await?
            .map_err(|e| anyhow::anyhow!("{e}"))?;
            println!("{msg}");
            Ok(())
        }
        #[cfg(feature = "indexer")]
        Command::OracleBacktest {
            db,
            releases,
            msgids,
            families,
            buckets,
            cells,
            seed,
            truth,
            sample_secs,
            json,
        } => {
            oracle_backtest::run(
                &cli.config,
                oracle_backtest::Opts {
                    db,
                    releases,
                    msgids,
                    families,
                    buckets,
                    cells,
                    seed,
                    truth,
                    sample_secs,
                    json,
                },
            )
            .await
        }
        #[cfg(feature = "indexer")]
        Command::Search { query, db, nzb } => search_index(&query, &db, nzb.as_deref()),
        #[cfg(feature = "indexer")]
        Command::Spots {
            group,
            backfill,
            db,
        } => spots_scan(&cli.config, &group, backfill, &db).await,
        #[cfg(feature = "indexer")]
        Command::SpotSearch { query, db } => spot_search(&query, &db),
        #[cfg(feature = "indexer")]
        Command::SearchMisses {
            days,
            thin,
            surface,
            limit,
            db,
        } => search_misses(&db, days, thin, surface.as_deref(), limit),
        #[cfg(feature = "indexer")]
        Command::SpotGet { msgid, nzb, db } => spot_get(&cli.config, &msgid, &nzb, &db).await,
        #[cfg(feature = "indexer")]
        Command::NzbImport {
            db,
            limit,
            after,
            report,
            apply,
        } => nzb_import(&cli.config, &db, limit, after, report.as_deref(), apply).await,
        Command::Setup => {
            if setup::run(&cli.config)? {
                Ok(())
            } else {
                std::process::exit(3); // user chose Quit - launcher won't serve
            }
        }
        Command::Serve {
            port,
            bind,
            tls_cert,
            tls_key,
            open,
            apikey,
            nzbkey,
            out,
            watch,
            script,
            min_free,
            quota,
            quota_period,
            feeds,
            connections,
            window,
            decoders,
            speedlimit,
            schedule,
            auto_speed,
            library_cats,
            library_recheck_secs,
            #[cfg(feature = "indexer")]
            index_db,
            #[cfg(feature = "indexer")]
            index_groups,
            #[cfg(feature = "indexer")]
            index_interval,
            #[cfg(feature = "indexer")]
            index_backfill,
            #[cfg(feature = "indexer")]
            index_max_age,
            #[cfg(feature = "indexer")]
            index_gates,
        } => {
            let size = |name: &str, v: Option<String>| -> Result<Option<u64>> {
                v.map(|s| {
                    serve::parse_size(&s)
                        .ok_or_else(|| anyhow::anyhow!("--{name}: can't parse size {s:?}"))
                })
                .transpose()
            };
            let opts = serve::ServeOpts {
                // Off unless the dashboard turns it on; settings.json
                // overrides this on load.
                group_desc_isc: false,
                port,
                bind,
                tls_cert,
                tls_key,
                open,
                apikey,
                nzbkey,
                out_root: out,
                watch,
                script,
                connections,
                window,
                decoders,
                fast_verify: true,
                verify_lean: false,
                min_free: size("min-free", min_free)?,
                // Settings-only (#20): there is no CLI flag, so the
                // launch value is always "off" and apply_saved_settings
                // is what turns it on.
                out_umask: None,
                auto_retry_mins: 20,
                preflight: false,
                quota: size("quota", quota)?,
                quota_period,
                feeds,
                speedlimit,
                schedule,
                auto_speed,
                library_cats,
                library_recheck_secs,
                mem_budget: budget,
                #[cfg(feature = "indexer")]
                index_db,
                #[cfg(feature = "indexer")]
                index_groups,
                #[cfg(feature = "indexer")]
                index_interval_secs: index_interval,
                #[cfg(feature = "indexer")]
                index_backfill,
                #[cfg(feature = "indexer")]
                index_max_age_secs: parse_age(&index_max_age)?,
                #[cfg(feature = "indexer")]
                index_gates: index_gates.as_deref().map(gates::Gates::load).transpose()?,
            };
            serve::serve(cli.config.clone(), opts).await
        }
        Command::Check {
            nzb,
            sample,
            connections,
            window,
            fast,
        } => run_check(&cli.config, &nzb, sample, connections, window, fast).await,
        Command::Verify { dir } => {
            verify_dir(&dir)?;
            Ok(())
        }
        Command::Extract { dir, password } => {
            if extract_local(&dir, password.as_deref())? {
                Ok(())
            } else {
                std::process::exit(1);
            }
        }
        #[cfg(feature = "indexer")]
        Command::MakeReleaseNzb {
            group,
            min_gb,
            max_gb,
            out,
        } => make_release_nzb(&cli.config, &group, min_gb, max_gb, &out).await,
        #[cfg(feature = "indexer")]
        Command::MakeTestNzb {
            group,
            files,
            max_file_mb,
            out,
        } => make_test_nzb(&cli.config, &group, files, max_file_mb, &out).await,
    }
}
