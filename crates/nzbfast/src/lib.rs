//! The crate root. This package has ONE module tree and it lives here:
//! `main.rs` is a shim that sets the allocator and calls
//! [`cli_main`], and every module below is declared once, in this file.
//!
//! It was two roots until the crate-split step 4.5 (2 Sep 2026). `lib.rs`
//! was `#![cfg(feature = "ffi")]` - an embedded-hosting root for the iOS
//! staticlib (see `crates/nzbfast-ffi`) that re-declared the same module
//! tree and compiled to EMPTY in every ordinary build - while `main.rs`
//! carried the real tree. Two things made that arrangement worth ending:
//! the lib target a `tests/` binary links was empty, so `nzbfast::serve`
//! did not resolve from one and serve's 48k lines of test code had
//! nowhere to move to (`research/SERVE-TEST-FOLD-2026-09-02.md`), and a
//! `--workspace` build compiled the whole tree a SECOND time under `ffi`
//! for ~1,776 duplicate tests.
//!
//! The unification costs neither. The tree compiles ONCE, as the lib;
//! the bin unit is this file's `cli_main` behind a shim and is empty of
//! everything else, so `--all-targets` builds the same two real units it
//! did before (the lib and the lib's own `cfg(test)` build) rather than
//! the bin and the bin's. `ffi` survives as a feature but no longer
//! gates the root: it turns on the three `embedded_*` entry points at
//! the foot of this file and nothing else.
//!
//! `#![expect(dead_code)]` / `#![expect(unused_imports)]` are GONE with
//! the old root. They were sound for a root with no CLI - everything
//! only a subcommand arm calls was dead there by construction - and are
//! exactly wrong for a root that has one: this file's tree is the whole
//! product, so both lints have something real to say about it again.
//
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

use anyhow::{Context, Result};
use clap::{Parser, Subcommand};

// Archive name and magic grammar - pure path predicates every layer
// asks, hoisted out of `unpack` / `rarfix` by the crate-split prep.
mod chaos_serve;
// Free-space measurement, hoisted out of serve/ by TODO 276 item 3 so
// eatvol, get, lanegate and rarfix can ask it without depending on the
// daemon.
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::gates;
// The failure-message classifier, hoisted out of serve/ by TODO 276
// item 3 so `diag` (and everything under it) stops depending on the
// daemon. Pure `&str` in, small value out.
// GATED since the `tasks` layer left for `nzbfast-tasks` (lane 3): the
// bin's own test modules are the only readers left, and a `use` can be
// unused where a `mod` never could.
pub(crate) use nzbfast_core::identify;
#[cfg(any(feature = "indexer", test))]
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_core::identity;
pub(crate) use nzbfast_core::import_sab;
// The download pipeline, cut out as `nzbfast-engine` by crate-split
// step 4 and re-imported under its old name, so every `crate::get::`
// path and the `use get::*;` glob below are unchanged. The comment
// that used to stand above `mod get;` described `fileslot`, which went
// to nzbfast-core at step 2 and carries that note at its own
// declaration.
pub(crate) use nzbfast_engine::get;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::groupstats;
// TODO 151 (issue #36): external list sources for the watchlist.
// Which interface carries our traffic and how fast it is. Hoisted out of
// serve/ by TODO 276 item 3 so the CLI sysbench can ask without the daemon.
pub(crate) use nzbfast_core::locallink;
pub(crate) use nzbfast_core::logging;
pub(crate) use nzbfast_core::manifest;
mod nettools;
// Outbound HTTP for third-party URLs - the SSRF guard, the shared agents
// and URL credential redaction. Hoisted out of serve/ by TODO 276 item 3.
pub(crate) use nzbfast_core::netfetch;
// TODO 297 (issue #57): the nzbindex.com JSON API, a second search
// source dispatched to from indexers.rs on `newznab::SourceKind`.
pub(crate) use nzbfast_core::notify;
// Named by `serve/daemon_api_tests.rs` alone since lane 3 moved the api
// layer out - a `use` can be unused where a `mod` never could.
#[cfg(all(test, feature = "indexer"))]
pub(crate) use nzbfast_meta::newznab;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::oracle_backtest;
// The bounded PAR2 packet-byte scan of a directory, hoisted out of
// `unpack` by the crate-split prep so the junk sweep can ask it.
// The child half of the leaked-daemon fix: a daemon spawned by a test
// binary exits when that binary dies, including when it dies by SIGKILL
// and no destructor anywhere runs.
mod parentwatch;
pub(crate) use nzbfast_core::persist;
// TODO 151 (issue #36): the first list source's own wire formats.
mod post_cmd;
// Where the operator's passwords file lives - a process-wide setting
// the extraction ladder reads without a `Daemon` handle.
// GATED since the crate-split step 4 cut, for the reason the
// `ratelimit` line below states at length: `get` was this crate's
// unconditional consumer and it left for nzbfast-engine, so the only
// one left is `tasks/indexer/probe7z.rs`'s 7z part split. A
// `mod` could never be unused; a `use` can be.
// GATED where the other core re-imports are not, and the difference is
// what a `use` can say that a `mod` cannot: every consumer of it in
// THIS crate is an indexer one (wall, api/wall), so a slim build
// binds a name nothing reads and `unused_imports` says so - where the
// `mod ratelimit;` this replaced could never be unused. The module
// itself is unconditional in nzbfast-core, because `srrdb` and `xrel`
// pace through it in every build.
// The rename-race harness. `#[cfg(test)]` while it lived here, and its
// pins are spread across `serve`'s tests AND `smart`'s - which are two
// crates since the step 3 cut, so it moved down to the lower of the two
// behind `nzbfast-unpack`'s `test-support` feature. Re-imported here
// under its old name, so every `crate::renameclaim::` path is unchanged.
// Release-name grammar - the password convention and the dedupe
// reduction, hoisted out of `smart` by the crate-split prep.
// TODO 314 stage 1: the ONE spawn wrapper every child that runs code
// we did not write goes through - unrar, par2 and the user's scripts.
// In nzbfast-core because it is a leaf: it depends on nothing of ours
// and three layers above it call it.
pub(crate) use nzbfast_core::sandbox;
#[cfg(feature = "indexer")]
pub(crate) use nzbfast_meta::scan;
// GATED where the other unpack re-imports are not, and the difference
// is what a `use` can say that a `mod` never could: `get` left for
// nzbfast-engine at the crate-split step 4 cut and it was the only
// production consumer here, so what is left naming this is `serve`'s
// own tests. A production build would bind a name nothing reads and
// `unused_imports` is `-D warnings` in this workspace.
pub mod serve;
// Which configured server a lane should talk to. Hoisted out of
// `nettools` into nzbfast-core by the crate-split step 3 cut, because
// `scan` (nzbfast-meta) calls all three selectors - see that module's
// note. Globbed below so the bin's ~10 bare call sites are unchanged.
pub(crate) use nzbfast_core::servers;
pub(crate) use nzbfast_core::setup;
// Human size/rate strings ("900Mb" -> bytes). Hoisted out of serve/ by
// TODO 276 item 3 - gates, rss and smart all parse them.
#[cfg(test)]
mod testscratch;
pub(crate) use nzbfast_core::tools;
// Spending a password on a locked archive, hoisted out of `smart` by
// the crate-split prep - it drives the extractor, not the filing code.
pub(crate) use nzbfast_unpack::unpack;
// The wall/wall_slim swap is a cfg INSIDE nzbfast-meta since the
// crate-split step 3 cut, so this is one unconditional name rather than
// the `#[path]` pair both roots used to spell out.
mod yencvec_cmd;
use check::*;
use get::*;
pub(crate) use nzbfast_unpack::check;
use unpack::*;
// The three largest subcommand arms of `run`, hoisted out verbatim
// when that function reached the size gate's 500-line ceiling.
mod run_cmds;
// Same lane-3 gating as `failkind` above: `incomplete_reason`,
// `LossCauses` and `with_build` are named by `tests_grabs.rs` and by
// nothing in this crate's production code any more.
use nettools::*;
pub(crate) use nzbfast_core::streamhub;
use nzbkit::config::{Config, ServerConfig};
use nzbkit::nntp::Connection;
use nzbkit::nzb::{FileKind, Nzb};
use run_cmds::*;
use servers::*;
// `lock_ok()` and friends now live in `tools`, the lowest layer, so no
// module has to reach the crate ROOT for them - see the note there.
// Imported (not re-exported) because this root's own code calls them.
use crate::tools::MutexExt;
#[cfg(feature = "indexer")]
use scan::*;
use streamhub::*;

/// `--config` takes a PATH, and a value opening with `{` is inline JSON.
///
/// Nothing downstream can recover from that mistake usefully. The
/// filename does not exist, so `Config::load` falls back to whatever
/// SABnzbd install the host has (deliberately - see `load_no_fallback`
/// in `crates/nzbkit-base/src/config.rs` for why that fallback is
/// unconditional), and the run then dials a provider the operator never
/// named and fails against it minutes later looking like a network
/// fault. That is how it was found, on a TODO 215 loopback rig on
/// 22 Aug 2026, five legs in. No real deployment has a config file whose
/// name begins with a brace, so refusing it here costs nothing and turns
/// a silent substitution into a clap error before any socket is opened.
///
/// Applies to `NZBFAST_CONFIG` too, which is the same mistake by
/// another route.
fn config_path(raw: &str) -> Result<PathBuf, String> {
    if raw.trim_start().starts_with('{') {
        return Err(
            "takes a path to a config file, not inline JSON. Write the JSON to a file \
             and pass that path (or run `nzbfast setup` to create one)."
                .to_string(),
        );
    }
    Ok(PathBuf::from(raw))
}

#[derive(Parser)]
#[command(name = "nzbfast", version, about = "Speed-focused NZB downloader")]
struct Cli {
    /// Path to config with server credentials (a path, not inline JSON).
    ///
    /// If the file does not exist, a SABnzbd install's server list is
    /// used instead when one can be found - on the machine, or beside
    /// this path - and a warning says which file it came from. That
    /// holds whether or not you passed this flag yourself.
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
        value_parser = config_path,
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
    Probe {
        /// Also report per-server POSTING capability without posting:
        /// greeting code, CAPABILITIES advertisement, and a POST
        /// command aborted before any article data moves (a 340 answer
        /// followed by a connection drop posts nothing).
        #[arg(long)]
        post_check: bool,
    },
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
    /// Verify files in a directory against the PAR2 set found there, or
    /// against the settle manifest when the PAR2 files are gone.
    ///
    /// Exit 0 when the files check out, 1 when verification finds damage.
    /// A directory with nothing to check - no PAR2 set and no manifest,
    /// or a PAR2 set too large for the scan cap - also exits 0, and says
    /// so on stderr: that is "not checked", not "clean".
    Verify {
        dir: PathBuf,
        /// Prove each file from the PAR2 set's per-block checksums alone
        /// and skip the whole-file digest: much faster on fast storage,
        /// and it calls a malformed set clean where par2cmdline calls it
        /// damaged. Off by default. See the manual before turning it on.
        #[arg(long)]
        fast: bool,
    },
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
        /// The oldest announcement to keep, in days. A limit rather
        /// than a target: the walk reads only the two newest pages of
        /// each section (predb.net asks people not to build their own
        /// database from the API), so it usually stops well short of
        /// this.
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
        /// Daemon to submit to: a host name (plain HTTP, on --port), or
        /// a full base URL. A daemon started with --tls-cert/--tls-key
        /// serves one listener and one scheme, so it is reachable only
        /// as `--host https://nas.local`. Self-signed pair: point this
        /// client at it with NZBFAST_EXTRA_CA=<cert.pem>.
        #[arg(long, default_value = "127.0.0.1")]
        host: String,
        /// Daemon port. A port inside a --host URL wins over this.
        #[arg(long, default_value_t = 6789)]
        port: u16,
        /// API key (or NZB key), if the daemon requires one. Sent as an
        /// X-Api-Key header, never in the request target.
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
        #[arg(long, default_value = "corpus@nzbfast.invalid")]
        from: String,
        /// Message-ID domain (right-hand side of generated ids).
        #[arg(long, default_value = "nzbfast.invalid")]
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
        /// Corpus mode: admit 0-byte files (each posts as one empty yEnc
        /// article). Off by default - an empty file in an ordinary post
        /// is nearly always a staging mistake.
        #[arg(long)]
        allow_empty: bool,
        /// No-RAR mode: post bare files under a random subject and a
        /// random yEnc `name=`, so a scraper that never saw the NZB
        /// cannot tie an article to a release. The real names ride in
        /// the NZB, and in the PAR2 FileDesc packets when --par2 is on.
        /// This breaks header LINKAGE and hides no bytes: yEnc is +42,
        /// so the payload is as readable as it ever was.
        #[arg(long)]
        obfuscate: bool,
        /// With --obfuscate, leave the yEnc `name=` empty instead of
        /// repeating the subject's random token.
        #[arg(long)]
        obfuscate_empty_name: bool,
        /// Build and post a PAR2 set beside the payload, carrying the
        /// real names and directory tree in its FileDesc packets. The
        /// value is a percentage of the input slice count; 0 is a
        /// verify-only set with no recovery slices. Native - no
        /// external par2 binary, so a 0-byte member is described
        /// rather than skipped.
        #[arg(long, value_name = "PERCENT")]
        par2: Option<u32>,
        /// PAR2 slice size ("512K", "700K", …); default is derived from
        /// the payload size. Must be a multiple of 4.
        #[arg(long)]
        par2_block_size: Option<String>,
        /// Base name of the emitted .par2 files. Default: a random
        /// token under --obfuscate, the NZB's own stem otherwise.
        #[arg(long)]
        par2_base: Option<String>,
    },
    /// Write a deterministic yEnc-encryption test corpus (Tensai75
    /// draft, body + control-lines + combined): wire-exact articles,
    /// NZBs with the draft's required subjects and password meta, and
    /// the full derivation-chain vectors. No network anywhere.
    YencVectors {
        /// Directory to create the corpus in.
        #[arg(long)]
        out: PathBuf,
        /// Session password embedded in the NZBs' meta tags.
        #[arg(long, default_value = "test123")]
        password: String,
        /// Decoded payload bytes per article.
        #[arg(long, default_value_t = 6000)]
        article_size: usize,
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
        /// Keep descending past a release with no rar members, instead
        /// of returning the newest qualifying one. A bare payload plus
        /// a par2 ladder puts no extractor in the job's path.
        #[arg(long)]
        require_rar: bool,
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

/// The CLI, called by `main.rs`'s shim. Every subcommand runs on a
/// thread we size ourselves, never on the process's own main thread.
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
pub fn cli_main() -> Result<()> {
    // FIRST, ahead of even the parent watch below: this process may not
    // be nzbfast at all. TODO 314 stage 1's Windows half confines a
    // subprocess by re-invoking THIS executable as a job-object helper,
    // and a helper must not arm a watch, install a hook or start a
    // thread - it creates a job, runs one child and exits with that
    // child's code. Returns immediately for every ordinary launch;
    // never returns for a helper one. See `crate::sandbox`.
    crate::sandbox::confine_main_if_asked();
    // BEFORE ANYTHING ELSE, and before any subcommand can start a
    // listener: if a test binary launched us, stop being a process the
    // moment that binary is gone. Seventy daemons survived a killed
    // `cargo nextest` run for three days on the dev Mac because nothing
    // here did this - see `parentwatch`, which carries the census and
    // why the harness side cannot cover it. Inert in production, which
    // never sets the variable.
    parentwatch::arm();
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
/// Out of line only because `run()` was at 487 of the §106 500-line
/// function ceiling on 15 Aug 2026, and this is the one piece of that
/// arm that stands alone. Silent while
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
        // `from_user_limit` and not `with_total`: this is a figure a
        // PERSON typed, and the clamp used to be silent - `--mem-limit`
        // parses decimal, so 8M/32M/64M are all one budget. See
        // `MemBudget::from_user_limit`.
        Some(v) => nzbkit::mem::MemBudget::from_user_limit(
            serve::parse_size(v)
                .ok_or_else(|| anyhow::anyhow!("--mem-limit: can't parse size {v:?}"))?,
            "--mem-limit",
        ),
        None => nzbkit::mem::MemBudget::auto(),
    };
    // The repair paths run several layers below any command's call site and
    // need the same budget everything else honours.
    nzbkit::mem::set_process_budget(budget);
    match cli.command {
        Command::Inspect { nzb } => inspect(&nzb),
        Command::Identify { file, year } => identify_cmd(&cli.config, &file, year),
        Command::Probe { post_check } => probe(&cli.config, post_check).await,
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
        cmd @ Command::Get { .. } => get_cmd(cmd, &cli.config, budget).await,
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
        cmd @ Command::Mockserve { .. } => mockserve_cmd(cmd).await,
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
            allow_empty,
            obfuscate,
            obfuscate_empty_name,
            par2,
            par2_block_size,
            par2_base,
        } => {
            let asize = serve::parse_size(&article_size)
                .ok_or_else(|| anyhow::anyhow!("bad --article-size {article_size:?}"))?
                as usize;
            let par2_block_size = par2_block_size
                .as_deref()
                .map(|v| {
                    serve::parse_size(v)
                        .ok_or_else(|| anyhow::anyhow!("bad --par2-block-size {v:?}"))
                })
                .transpose()?;
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
                    allow_empty,
                    obfuscate,
                    obfuscate_empty_name,
                    par2,
                    par2_block_size,
                    par2_base,
                },
            )
            .await
        }
        Command::YencVectors {
            out,
            password,
            article_size,
        } => yencvec_cmd::run(yencvec_cmd::VecArgs {
            out,
            password,
            article_size,
        }),
        #[cfg(feature = "indexer")]
        Command::PredbSeed { days, max_rows, db } => {
            // Blocking (paced HTTP, one request every PACE_MS) and
            // there is nothing else to do meanwhile, so it runs on a
            // worker rather than stalling the runtime.
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
        cmd @ Command::Serve { .. } => serve_cmd(cmd, cli.config.clone(), budget).await,
        Command::Check {
            nzb,
            sample,
            connections,
            window,
            fast,
        } => run_check(&cli.config, &nzb, sample, connections, window, fast).await,
        Command::Verify { dir, fast } => {
            // The ONE value, set before anything reads it. An explicit
            // flag wins; without it `NZBFAST_VERIFY_IFSC_ONLY` still
            // answers, so the environment stays the lowest rung of the
            // precedence rather than being shadowed by a `false` here.
            if fast {
                nzbkit::par2::set_fast_check(true);
            }
            // PAR2 stays the first choice - it can REPAIR, the manifest
            // can only judge. The manifest arm exists for the day the
            // cleanup default has already deleted the .par2 files,
            // which is exactly when a user reaches for verify.
            //
            // THE TWO ARMS AGREE ON EXIT CODE since 2 Sep 2026, when the
            // compatibility call on TODO 310 was taken. Damage found by
            // either arm exits 1; both exit 0 when the files check out.
            // The PAR2 arm used to exit 0 on damage because `verify_dir`
            // returned one bool for two different answers - `false` was
            // both "damaged" and "there was nothing to verify" - so the
            // caller could not act on it and discarded it. `DirVerify`
            // splits that return.
            //
            // NOTHING TO VERIFY EXITS 0, and says so on stderr. It is the
            // same shape the manifest arm has always had for an absent
            // manifest: no manifest and no PAR2 is not a conviction, and
            // a script that treats "I could not check" as "damaged" would
            // fail every directory whose .par2 files the cleanup default
            // already removed. Scripts that need the distinction read the
            // stderr line, which names the directory. Documented in
            // `nzbfast verify --help` and in docs/MANUAL.html.
            if !dir_has_par2(&dir).unwrap_or(false) && dir.join(manifest::MANIFEST_NAME).is_file() {
                if !manifest::verify_cli(&dir)? {
                    // §310 stage 2. The manifest records, per entry, the
                    // post that proved it, so a running daemon can
                    // re-fetch exactly the damaged files and adopt every
                    // intact byte off the disk (§293). Verify SAYS so
                    // and does not do it: its stated job is to answer a
                    // question, and a command that answers one by
                    // starting a download cannot be run safely in a
                    // script or on a metered line.
                    tracing::warn!(
                        target: "par2",
                        "this folder records which post each damaged file came from, \
                         so a running nzbfast can re-download just the damaged parts: \
                         mode=heal_offer on {} reports what it would do, mode=heal_start \
                         does it",
                        dir.display()
                    );
                    std::process::exit(1);
                }
            } else {
                match verify_dir(&dir)? {
                    unpack::DirVerify::Clean => {}
                    unpack::DirVerify::Damaged => std::process::exit(1),
                    unpack::DirVerify::NothingToVerify => {
                        // warn! so it lands on stderr (see logging::init):
                        // a report redirected to a file keeps its
                        // complaints visible on the terminal.
                        tracing::warn!(
                            target: "par2",
                            "nothing to verify in {} - exit 0 means \"not checked\", not \"clean\"",
                            dir.display()
                        );
                    }
                }
            }
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
            require_rar,
            out,
        } => make_release_nzb(&cli.config, &group, min_gb, max_gb, require_rar, &out).await,
        #[cfg(feature = "indexer")]
        Command::MakeTestNzb {
            group,
            files,
            max_file_mb,
            out,
        } => make_test_nzb(&cli.config, &group, files, max_file_mb, &out).await,
    }
}

// ---------------------------------------------------------------------
// Embedded (in-process) hosting: the iOS staticlib is the customer, via
// `crates/nzbfast-ffi`. Behind `ffi` because a desktop build has no use
// for it - the feature no longer gates this whole root, only these
// three entry points.
// ---------------------------------------------------------------------

/// The [`serve::ServeOpts`] an embedded host runs with: the CLI's
/// defaults, a loopback bind (the host process owns the only client),
/// everything else settings-driven - `apply_saved_settings` overlays
/// settings.json exactly as it does for the daemon.
///
/// `mem_limit` is the host's answer in BYTES, or `None` for
/// [`nzbkit::mem::MemBudget::auto`] - a quarter of physical RAM, which
/// is a DESKTOP figure and the one default in this function that a
/// phone must not take. `MemBudget::auto` reads the machine's RAM, and
/// on a 12 GB phone that is a 3 GB budget for a process the platform is
/// willing to kill for being large; `MemBudget::with_total` clamps
/// whatever arrives to the engine's own 64 MB floor, so a host that
/// passes something silly gets a small engine rather than a broken one.
/// See `nzbfast_start`'s `mem_limit_bytes` for why this is a parameter
/// and not an environment variable, and TODO 281 IO2 for the
/// measurement the iOS figure comes from.
///
/// A saved `mem_limit` in settings.json still overrides it: `serve`
/// runs `apply_saved_settings` before it publishes the process budget,
/// so this is the platform's DEFAULT and an explicit user setting wins,
/// which is the same precedence `--mem-limit` has on a desktop.
#[cfg(feature = "ffi")]
pub fn embedded_serve_opts(
    port: u16,
    apikey: Option<String>,
    out_root: PathBuf,
    mem_limit: Option<u64>,
) -> serve::ServeOpts {
    serve::ServeOpts {
        port,
        bind: "127.0.0.1".into(),
        // Loopback-only host process: TLS is settings-driven if ever
        // wanted here, same as everything else below.
        tls_cert: None,
        tls_key: None,
        open: false,
        apikey,
        nzbkey: None,
        out_root,
        watch: None,
        script: None,
        connections: 8,
        window: 4,
        decoders: 6,
        fast_verify: true,
        verify_lean: false,
        library_cats: Vec::new(),
        library_recheck_secs: 21600,
        min_free: None,
        out_umask: None,
        auto_retry_mins: 20,
        preflight: false,
        quota: None,
        quota_period: 'd',
        feeds: None,
        speedlimit: None,
        schedule: None,
        auto_speed: false,
        mem_budget: embedded_budget(mem_limit),
        group_desc_isc: false,
        #[cfg(feature = "indexer")]
        index_db: PathBuf::from("index.db"),
        #[cfg(feature = "indexer")]
        index_groups: Vec::new(),
        #[cfg(feature = "indexer")]
        index_interval_secs: 900,
        #[cfg(feature = "indexer")]
        index_backfill: 20000,
        #[cfg(feature = "indexer")]
        index_max_age_secs: 0,
        #[cfg(feature = "indexer")]
        index_gates: None,
    }
}

/// The budget an embedded host gets, in one place because TWO callers
/// need the identical answer: [`embedded_init`] publishes the process
/// budget before the engine thread exists, and [`embedded_serve_opts`]
/// puts it in the opts `serve` republishes from. Written twice, a host
/// that passed a phone-sized limit would still spend the window between
/// those two calls advertising a desktop one.
#[cfg(feature = "ffi")]
fn embedded_budget(mem_limit: Option<u64>) -> nzbkit::mem::MemBudget {
    match mem_limit {
        // Clamps to MemBudget::MIN and fits the address space, so a
        // host that asks for 1 byte gets the 64 MB floor rather than an
        // engine whose every tier rounds to nothing - and SAYS so, which
        // it did not until 31 Aug 2026. An embedded host is the one
        // caller that cannot see a `--mem-limit` it never typed, so a
        // phone-sized figure silently becoming the floor is a budget
        // nobody could have checked.
        Some(bytes) => nzbkit::mem::MemBudget::from_user_limit(bytes, "the host's memory limit"),
        None => nzbkit::mem::MemBudget::auto(),
    }
}

/// Process-wide one-time setup the CLI's `run()` does before serving,
/// minus the pieces that make no sense in a host app (power-throttling
/// opt-out is Windows-only and harmless; the allocator stays the
/// system's - mimalloc is cfg'd to macOS + Linux).
///
/// `mem_limit` is the same argument [`embedded_serve_opts`] takes and
/// must be the SAME VALUE: this is the budget in force from here until
/// `serve` republishes its own, and the repair and extract paths read
/// the process budget rather than the opts.
#[cfg(feature = "ffi")]
pub fn embedded_init(mem_limit: Option<u64>) {
    logging::init(logging::Style::Daemon);
    nzbkit::disk::raise_fd_limit();
    nzbkit::mem::opt_out_of_power_throttling();
    nzbkit::mem::set_process_budget(embedded_budget(mem_limit));
}

#[cfg(test)]
mod config_arg_tests {
    use super::config_path;
    use clap::Parser as _;

    /// The mistake this exists for: `--config '{"servers":[...]}'` is a
    /// filename that cannot exist, and without this it was answered by
    /// the host's SABnzbd server list rather than by an error.
    #[test]
    fn inline_json_is_refused_and_real_paths_are_not() {
        for json in [
            r#"{"servers":[{"host":"127.0.0.1","port":8129,"tls":false}]}"#,
            "  {}",
        ] {
            let err = config_path(json).expect_err("inline JSON must not parse as a path");
            assert!(err.contains("not inline JSON"), "unhelpful message: {err}");
        }
        // Ordinary paths, including ones with a brace somewhere that is
        // not the first character, are untouched.
        for ok in [
            "config.local.json",
            "/config/config.json",
            "C:\\ProgramData\\nzbfast\\config.json",
            "~/.config/nzbfast/{staging}.json",
        ] {
            assert_eq!(config_path(ok).unwrap(), std::path::PathBuf::from(ok));
        }
    }

    /// End to end through clap, so the wiring is pinned too: the parser
    /// is only useful if the attribute actually references it.
    #[test]
    fn clap_rejects_inline_json_before_any_subcommand_runs() {
        // `.err()` rather than `expect_err`, which would want `Cli:
        // Debug` - and `Cli` holds an `--apikey`, so it deliberately
        // has no Debug to print it with.
        let e = super::Cli::try_parse_from(["nzbfast", "--config", r#"{"servers":[]}"#, "probe"])
            .err()
            .expect("clap must refuse it");
        assert!(
            e.to_string().contains("not inline JSON"),
            "clap surfaced the wrong error: {e}"
        );
    }
}
