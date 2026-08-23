//! Local configuration (`config.local.json`, gitignored - holds credentials).

use std::path::Path;
use tracing::warn;

use serde::{Deserialize, Serialize};

#[derive(Debug, thiserror::Error)]
pub enum ConfigError {
    #[error("reading config: {0}")]
    Io(#[from] std::io::Error),
    #[error("parsing config: {0}")]
    Json(#[from] serde_json::Error),
    #[error("parsing sabnzbd.ini: {0}")]
    Ini(String),
    #[error("config has no servers")]
    NoServers,
    #[error(
        "config has {0} servers; the maximum is {max}. Routing state (which \
         servers have 430'd an article, which are live, retention windows) is \
         a bitmask with one bit per server, so servers past the {max}th have \
         no bit of their own and would be treated as already-tried",
        max = crate::pool::MAX_SERVERS
    )]
    TooManyServers(usize),
}

#[derive(Debug, Clone, Deserialize)]
pub struct Config {
    pub servers: Vec<ServerConfig>,
    /// M13: TMDB API key for poster-wall metadata/artwork. Absent =
    /// wall runs text-only. (TMDB_API_KEY env var also works.)
    #[serde(default)]
    pub tmdb_key: Option<String>,
}

#[derive(Debug, Clone, Deserialize, Serialize)]
pub struct ServerConfig {
    pub host: String,
    #[serde(default = "default_port")]
    pub port: u16,
    #[serde(default = "default_true")]
    pub tls: bool,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub username: Option<String>,
    /// Stored obfuscated (`obf1:…`), read as either that or cleartext. See
    /// [`obfuscate`] - it is obfuscation, not encryption.
    #[serde(
        default,
        skip_serializing_if = "Option::is_none",
        deserialize_with = "de_secret",
        serialize_with = "ser_secret"
    )]
    pub password: Option<String>,
    /// Provider's allowed concurrent connections (we typically use far fewer).
    #[serde(default = "default_connections")]
    pub connections: u32,
    /// Use exactly `connections` on this server: the auto-tuner may keep
    /// measuring it, but its knee is never applied here.
    ///
    /// The tuner is a measurement, and a measurement can be wrong in a
    /// way its own guards do not catch - a tester whose downloads got
    /// faster all the way to 36 sockets was handed 6, and the only
    /// escape was the GLOBAL auto-tune switch, which also gives up
    /// tuning on the providers it was getting right. This is the
    /// per-server lock: whatever the ladder decides, this number wins.
    ///
    /// Deliberately not a "disable tuning here" flag. The probe still
    /// runs and still reports, because a user who pins a number is
    /// exactly the user who wants to see what the ladder thinks of it -
    /// they simply are not going to be overruled by it.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub pin_connections: bool,
    /// Socket receive buffer in bytes (best-effort; kernel may clamp).
    /// Leave unset: kernels autotune per-connection windows (Linux to
    /// ~6 MB via tcp_rmem, macOS to 4 MB via autorcvbufmax), and bench
    /// probes show real usenet paths cap per-connection rate far below
    /// where those ceilings bind (~40 Mbps/conn transatlantic vs the
    /// ~420 Mbps a 4 MB window sustains at 77 ms). On Linux an explicit
    /// value is usually a DOWNGRADE: setting SO_RCVBUF disables
    /// autotuning and is clamped to net.core.rmem_max (~208 KB stock),
    /// shrinking the window ~30x. Only set this on a host whose
    /// rmem_max has been raised to match.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub rcvbuf: Option<u32>,
    /// M14e tier (NZBGet "Level"): 0 = primary; a level-N server only
    /// fetches articles every live lower-level server has already missed.
    /// Fill-server economics - pay-per-GB blocks never see bytes the
    /// flatrate primaries can serve.
    #[serde(default)]
    pub level: u32,
    /// Servers sharing a group name are mirrors of one backbone: a 430
    /// from one marks the article tried on all of them.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub group: Option<String>,
    /// Provider retention in days; articles older than this are never
    /// requested from this server (routed to deeper servers instead).
    /// 0 = unlimited.
    #[serde(default)]
    pub retention_days: u32,
    /// Block account: total prepaid bytes. The daemon tracks lifetime
    /// usage per host and stops using the server once the block is
    /// spent. None/0 = unlimited (flatrate).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub block_bytes: Option<u64>,
    /// Every byte from this server costs money: spend none deliberately.
    ///
    /// A flagged server serves the user's actual download exactly as
    /// before - what it never gets is the traffic nzbfast sends for its
    /// own benefit: connection-ladder probes, the system benchmark's
    /// provider leg, index header pulls, and (owned by the M7b.2 racing
    /// work) speculative duplicate fetches.
    ///
    /// DECOUPLED from `level` and from `block_bytes`, which is the whole
    /// point of having it. Until now per-byte economics were INFERRED
    /// from the topology - `level > 0` for racing, `block_bytes.is_some()`
    /// for the prober - and both inferences are wrong in both
    /// directions. A metered account can sit at level 0 (it is the only
    /// provider the user has), and a flatrate account can sit at level 2
    /// (it is a second unlimited backbone kept for completion). Guessing
    /// costs real money in one direction and free speed in the other, so
    /// the user gets to say it outright.
    ///
    /// Default OFF, and deliberately not auto-set from any signal: the
    /// server editor SUGGESTS it at level > 0 (the strongest hint a
    /// server is a fill account) and leaves the decision alone.
    ///
    /// Not a spending cap - that is `block_bytes`, and the two compose:
    /// the cap says when to stop, this says never to spend on our own
    /// curiosity in the first place.
    #[serde(default, skip_serializing_if = "std::ops::Not::not")]
    pub block_account: bool,
    /// M32: bind outgoing connections for this server to
    /// a specific local IP - multi-homed boxes and VPN split-tunnel
    /// setups. The address family also picks the target family (a v4
    /// bind connects to the server's v4 address).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub bind_ip: Option<String>,
    /// M32 (nzbdav#315): SOCKS5 proxy for this server's NNTP traffic -
    /// "host:port" or "user:pass@host:port". The server hostname is
    /// resolved BY the proxy (no local DNS leak).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub socks5: Option<String>,
    /// Soft on/off switch: a disabled server stays configured (and
    /// testable) but never joins a download pool.
    #[serde(default = "default_true")]
    pub enabled: bool,
    /// Park this server's drained connections between jobs (§36).
    ///
    /// OFF by default and settled PER SERVER, because the decision is a
    /// property of the link, not of the installation. Measured: on a
    /// controlled 50 ms path pooling is worth -19.5% of job time, but on
    /// a real Starlink link 60 paired reps could not separate it from
    /// nothing (-0.1%, CI -6.2% to +5.9%) - the link's own jitter is far
    /// larger than the 1-2 s the pool saves, so the saving is real and
    /// simply gets buried. We cannot know a user's link, so we do not
    /// guess:  measures THIS server and recommends.
    #[serde(default)]
    pub warm_pool: bool,
    /// Seconds this server's connections may stay open with nothing
    /// downloading, before the daemon hangs them up so the account is
    /// usable from the operator's other machines.
    ///
    /// `None` = derive from the provider ([`caps_source_ips`]);
    /// `Some(0)` = hold them open indefinitely, which is right when this
    /// install is the account's only consumer (a NAS, a seedbox).
    ///
    /// PER SERVER, and for a stronger reason than `warm_pool` above: a
    /// server is an ACCOUNT, and each provider counts its own limit
    /// against its own account. Two servers share nothing. Letting a
    /// strict provider's cap shorten a lax one's timeout would throw
    /// away warm connections on a link that never had a problem, and
    /// letting a lax one lengthen a strict one's would leave the lockout
    /// in place - so there is no correct single answer for a mixed
    /// config, only a per-account one.
    ///
    /// Independent of `warm_pool`: the background samplers (the M29
    /// availability oracle and the tip watcher) hold one session per
    /// server whether or not the pool is on, so this has to bind for a
    /// server that never opted into pooling at all.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_release_secs: Option<u64>,
    /// Connections to this server kept open through that release, so the
    /// next download still starts warm. `None` = derive.
    ///
    /// Counted in CONNECTIONS, because connections are what the pool
    /// controls. On a provider that limits ADDRESSES the useful
    /// distinction is only none-or-some: this host is one address
    /// whether it holds one connection or sixty, so any non-zero value
    /// occupies exactly one of that account's address slots. Which is
    /// why the derived default for those providers is zero - see
    /// [`ServerConfig::idle_release_policy`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub idle_keep: Option<u32>,
    /// How many distinct source ADDRESSES this account may use at once,
    /// as stated by the provider. `None` = not known.
    ///
    /// A different quantity from `connections`, and the two are easy to
    /// confuse because providers print them side by side: `connections`
    /// is how many sockets one machine may open, this is how many
    /// PLACES may use the account at all. UsenetExpress allows 2,
    /// Giganews and Newshosting 1, and plenty of providers set no limit.
    ///
    /// It exists because the hostname heuristic in [`caps_source_ips`]
    /// can only recognise providers we happen to have heard of, and gets
    /// resellers wrong in both directions. A number the user read off
    /// their provider's control panel beats any guess we can make, so
    /// when it is set it decides the idle-release default outright.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_source_ips: Option<u32>,
}

/// Does this host belong to a provider that caps concurrent distinct
/// SOURCE IPS per account, rather than (or as well as) connections?
///
/// The distinction changes what an idle held connection costs. Against a
/// connection cap, one parked session is one slot out of an allowance of
/// twenty or a hundred. Against an IP cap - UsenetExpress allows 2
/// concurrent source IPs, Giganews and Newshosting 1 - a single held
/// session consumes a whole slot for the HOST, so an idle home daemon
/// locks a laptop, a seedbox or a bench machine out of the account
/// entirely, and trimming a fleet of 64 down to 1 frees exactly nothing.
///
/// A HINT, not a fact table, and deliberately used only to pick a
/// DEFAULT that the operator can override:
///
/// - It under-detects. Resellers front the same backbones under their
///   own hostnames, and a provider can change its policy without
///   changing its hostname. Matching by substring cannot see either.
/// - It never over-restricts anything that matters: a false positive
///   costs a shorter idle timeout and a floor of zero, which is a small
///   re-warm, not a broken download.
///
/// The setting is the real control; this only decides where it starts.
pub fn caps_source_ips(host: &str) -> bool {
    let h = host.to_ascii_lowercase();
    // Tweaknews earned its place the hard way: on a multi-WAN link it
    // refuses with "502 Authentication Failed", the same code as a bad
    // password, so it read as a broken credential for hours before the
    // pattern was recognised (31 Jul - the operator had already turned
    // Giganews off for the same behaviour).
    ["usenetexpress", "giganews", "newshosting", "tweaknews"]
        .iter()
        .any(|p| h.contains(p))
}

/// How long connections to ONE server may sit idle, and how many of
/// them survive the release. `None` = never release.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct ReleasePolicy {
    pub after: Option<std::time::Duration>,
    pub keep: usize,
}

/// Shortest idle-release timeout that is worth honouring.
///
/// One keepalive interval, which is also the pool's own release
/// granularity - below this the setting cannot be obeyed by the pool
/// anyway, and the samplers WOULD obey it, reconnecting every tick.
pub const MIN_IDLE_RELEASE_SECS: u64 = 60;

/// Below this many allowed source addresses, one held by an idle
/// install is a problem rather than a rounding error.
///
/// At 1 it is total: nothing else can touch the account. At 2 - the
/// common paid-add-on shape - a home daemon plus a laptop already fills
/// it, and any third place is locked out. At 3 there is one spare, which
/// a phone or a second client takes. Past that, one address out of
/// several is a slice of a generous allowance and the ordinary default
/// applies.
///
/// A judgement, not a measurement, and only ever the source of a
/// DEFAULT: both idle-release settings override it per server.
const TIGHT_SOURCE_IPS: u32 = 3;

impl ServerConfig {
    /// May nzbfast spend this server's bytes on its OWN curiosity -
    /// connection-ladder probes, the system benchmark's provider leg,
    /// index header pulls - as opposed to the download the user asked
    /// for?
    ///
    /// Two ways to answer no, and both are honoured: the explicit
    /// [`ServerConfig::block_account`] flag, and the older inference
    /// from a configured prepaid block, which stays because plenty of
    /// installs predate the flag and their owners should not have to
    /// re-declare something they already said.
    ///
    /// One predicate rather than one per caller, because the callers
    /// have to AGREE. `update_tune_hint` decides the line-speed verdict
    /// is complete once every measurable server carries a probe result:
    /// if its idea of "measurable" is wider than the prober's, one
    /// unprobed server suppresses the verdict for the whole install,
    /// permanently and with nothing in the log saying why. That bug has
    /// been shipped once already (against block accounts); sharing the
    /// predicate is what stops it happening again.
    ///
    /// `block_bytes: Some(0)` reads as flatrate here, matching the pool,
    /// the job planner and the settings UI, all of which treat 0 as "no
    /// block configured".
    pub fn may_spend_on_measurement(&self) -> bool {
        !self.block_account && !self.block_bytes.is_some_and(|b| b > 0)
    }

    /// Does this server's account limit distinct source addresses
    /// tightly enough that an idle install holding one is a lockout?
    ///
    /// The operator's own number wins when they have supplied it - they
    /// read it off the provider's control panel, we are pattern-matching
    /// a hostname. `0` is treated as "no limit" rather than "no
    /// addresses", since that is what a provider printing 0 means.
    pub fn source_ips_are_tight(&self) -> bool {
        match self.max_source_ips {
            Some(0) | None => caps_source_ips(&self.host),
            Some(n) => n <= TIGHT_SOURCE_IPS,
        }
    }

    /// This server's effective idle-release policy: the configured
    /// values, or a default derived from the provider.
    ///
    /// The two resolve independently, so lengthening the timeout does
    /// not silently re-raise a floor the provider's address limit made
    /// pointless.
    pub fn idle_release_policy(&self) -> ReleasePolicy {
        let capped = self.source_ips_are_tight();
        ReleasePolicy {
            after: match self.idle_release_secs {
                // Sooner for an address-capped provider, because the
                // cost of holding is different in kind: not a slice of a
                // generous connection allowance but one of one or two
                // address slots for the whole account, so the operator's
                // other machines are locked out rather than slowed.
                None => Some(match capped {
                    true => crate::warmpool::CAPPED_IDLE_RELEASE,
                    false => crate::warmpool::DEFAULT_IDLE_RELEASE,
                }),
                Some(0) => None,
                // Floored, and floored HERE rather than at the settings
                // handler, because the value arrives by three routes -
                // the dashboard, the API, a hand-edited config.local.json
                // - and only this one is common to all of them. An
                // earlier cut clamped in the API handler; moving the
                // setting per-server left the clamp behind and a
                // one-second timeout became reachable.
                //
                // A short timeout is not merely useless, it is harmful.
                // The pool exists because a cold fleet costs 4.5-14.3x
                // on job start, and the background samplers consult this
                // same value every tick - the tip watcher's is 20 s - so
                // a timeout below the tick turns "hold nothing while
                // idle" into "reconnect on every pass", against
                // providers that punish connect bursts 3-4x.
                Some(n) => Some(std::time::Duration::from_secs(n.max(MIN_IDLE_RELEASE_SECS))),
            },
            keep: match self.idle_keep {
                // Floor of ZERO against an address cap: this host is one
                // address whether it holds one connection or sixty, so a
                // floor of one would free nothing and the operator's
                // other machines would stay locked out. Elsewhere keep
                // one warm - the next job starts on a live session while
                // the rest of the fleet's slots go back to the account.
                None => usize::from(!capped),
                // Capped at what the pool will ever park per server. A
                // floor ABOVE that is silently "never release", which is
                // not what someone typing a big number is asking for -
                // they want lots kept warm, and the honest answer is
                // "all of them", not "the setting did nothing".
                Some(n) => (n as usize).min(crate::warmpool::MAX_PER_SERVER),
            },
        }
    }
}

fn default_port() -> u16 {
    563
}
fn default_true() -> bool {
    true
}
pub fn default_connections() -> u32 {
    // The allowance most providers sell. Jobs use min(global setting,
    // this cap, measured knee), so a big default costs nothing on a
    // provider that grants less - the grant probe and knee trim it -
    // while a small one quietly starves every fast server (10 Aug: a
    // 100-conn xsnews account held to 32 read as "slow provider").
    100
}

/// Password OBFUSCATION - deliberately not encryption.
///
/// What this is for: a config file holds provider passwords, and those files
/// end up in screenshots, in forum posts, in bug reports, and on screens other
/// people can see. Storing them as plain readable text makes every one of
/// those an instant disclosure. Obfuscation removes the *casual* leak.
///
/// What this is NOT: protection from anyone who has the file. The key is
/// below, in public source, and the decoder ships in the binary. Anybody who
/// can read the config can recover the password in seconds. Never describe
/// this as encryption anywhere in the UI, the docs or a release note - a user
/// who believes their config is encrypted will attach it to a public issue.
/// The file is still written 0600 and still has to be kept private.
///
/// Neither NZBGet nor SABnzbd obfuscates (both store `password = <cleartext>`),
/// so this is a small improvement on the field norm rather than catching up.
///
/// Format: `obf1:<hex>`. Reading accepts BOTH forms - a cleartext password
/// keeps working, so hand-edited configs and SABnzbd/NZBGet imports are never
/// broken by this. Writing always obfuscates.
const OBF_PREFIX: &str = "obf1:";
const OBF_KEY: &[u8] = b"nzbfast-config-obfuscation-not-encryption";

fn obf_xor(bytes: &[u8]) -> Vec<u8> {
    // Mix the index in as well as the key, so a repeated character does not
    // produce a repeated output byte and the result carries no visible
    // pattern for something like "aaaaaa".
    bytes
        .iter()
        .enumerate()
        .map(|(i, b)| b ^ OBF_KEY[i % OBF_KEY.len()] ^ (i as u8))
        .collect()
}

/// Obfuscate a secret for writing to disk. Empty stays empty (an empty
/// password is a meaningful "no password", not a secret worth hiding).
///
/// Idempotent on an already-encoded value, so a caller that may be
/// holding either form is safe. That guess is what [`obfuscate_input`]
/// exists to avoid: use this only for a value that may ALREADY be stored
/// in our format.
pub fn obfuscate(secret: &str) -> String {
    if secret.starts_with(OBF_PREFIX) {
        return secret.to_string();
    }
    obfuscate_input(secret)
}

/// Obfuscate a secret that is RAW USER INPUT - a typed password, a value
/// out of an imported config - and so is never already encoded.
///
/// The distinction matters because the prefix is a guess and a password
/// is free to start with it: `obf1:0000` is a legal provider password,
/// and [`obfuscate`] wrote it to disk verbatim, after which
/// `deobfuscate` decoded the "hex" and handed the connect path four
/// different bytes. AUTHINFO PASS then failed forever, with the config
/// looking correct (Codex sweep 12 Aug F16). Encoding unconditionally
/// round-trips it: the stored form is `obf1:<hex of the whole literal>`,
/// which `deobfuscate` reverses exactly.
pub fn obfuscate_input(secret: &str) -> String {
    if secret.is_empty() {
        return secret.to_string();
    }
    let mut out = String::with_capacity(OBF_PREFIX.len() + secret.len() * 2);
    out.push_str(OBF_PREFIX);
    for b in obf_xor(secret.as_bytes()) {
        out.push_str(&format!("{b:02x}"));
    }
    out
}

/// Reverse `obfuscate`. Anything that is not in our format is returned
/// unchanged - that is what keeps cleartext configs working.
pub fn deobfuscate(stored: &str) -> String {
    let Some(hex) = stored.strip_prefix(OBF_PREFIX) else {
        return stored.to_string();
    };
    if hex.len() % 2 != 0 {
        return stored.to_string();
    }
    let mut raw = Vec::with_capacity(hex.len() / 2);
    for pair in hex.as_bytes().chunks(2) {
        let Ok(s) = std::str::from_utf8(pair) else {
            return stored.to_string();
        };
        let Ok(b) = u8::from_str_radix(s, 16) else {
            return stored.to_string();
        };
        raw.push(b);
    }
    // A password is UTF-8; if it does not decode, the value was not ours
    // after all and the caller is better served by the original string.
    String::from_utf8(obf_xor(&raw)).unwrap_or_else(|_| stored.to_string())
}

/// serde hook: de-obfuscate on the way in, so the rest of the program only
/// ever sees the real password and no call site has to remember.
fn de_secret<'de, D>(d: D) -> Result<Option<String>, D::Error>
where
    D: serde::Deserializer<'de>,
{
    Ok(Option::<String>::deserialize(d)?.map(|s| deobfuscate(&s)))
}

/// serde hook: obfuscate on the way out, for any writer that serializes a
/// `ServerConfig` rather than building JSON by hand.
fn ser_secret<S>(v: &Option<String>, s: S) -> Result<S::Ok, S::Error>
where
    S: serde::Serializer,
{
    match v {
        Some(p) => s.serialize_some(&obfuscate(p)),
        None => s.serialize_none(),
    }
}

impl Config {
    /// Load servers from `path`. A `.ini` extension means SABnzbd's
    /// `sabnzbd.ini` format; anything else is our JSON. If `path` doesn't
    /// exist, fall back to a SABnzbd install's ini in its standard
    /// per-platform location - a machine already running SAB needs no
    /// configuration at all. That fallback is unconditional, including
    /// when the operator named `path` themselves; the reasoning, and the
    /// policy that was weighed against it, is beside `load_no_fallback`.
    pub fn load(path: &Path) -> Result<Config, ConfigError> {
        // Search next to the missing config too: in Docker that is
        // /config, the one place a user can put the file. Lazily, inside
        // the closure: this runs at the download runner's tick rate, and
        // the healthy path must not stat a directory it will never read.
        Self::load_or_sab(path, || {
            let near: Vec<&Path> = path.parent().into_iter().collect();
            sabnzbd_ini_path(&near)
        })
    }

    /// [`load`](Self::load) with the SABnzbd search injected, so both
    /// halves of the fallback are testable on a machine that HAS a
    /// SABnzbd install - which every bench box here does. Same seam, and
    /// the same reason, as `storage_override` in `crates/nzbkit/src/disk.rs`:
    /// tests share one process, so pointing `$HOME` at an empty
    /// directory would race every other test that reads it.
    fn load_or_sab(
        path: &Path,
        find_sab: impl FnOnce() -> Option<std::path::PathBuf>,
    ) -> Result<Config, ConfigError> {
        match std::fs::read(path) {
            Ok(b) => Self::parse(&b, is_ini(path)),
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                let Some(sab) = find_sab() else {
                    return Err(e.into());
                };
                let parsed = Self::parse(&std::fs::read(&sab)?, true);
                // WARN, not INFO, and after the parse rather than before
                // it. INFO goes to stdout (the writer split in
                // `crates/nzbfast/src/logging.rs` gives stderr WARN and
                // above), so under a download's own output this line
                // scrolled past unread: on 22 Aug 2026 five benchmark
                // legs ran against a provider nobody had configured
                // before anyone noticed, and the run's visible failure
                // was "no usable connection to <that provider>", which
                // reads as a network fault. Naming the hosts is what
                // connects the two, and it is why the parse comes first.
                //
                // The failed parse is announced too, not swallowed as an
                // error path that speaks for itself: `NoServers` from a
                // SAB ini with nothing enabled is reported by callers as
                // "config has no servers", which points at a file the
                // operator never wrote and may not know was read.
                //
                // Once per process: the daemon re-loads this config
                // several times a second.
                static NOTICE: std::sync::Once = std::sync::Once::new();
                NOTICE.call_once(|| match &parsed {
                    Ok(cfg) => {
                        let hosts: Vec<&str> =
                            cfg.servers.iter().map(|s| s.host.as_str()).collect();
                        warn!(
                            target: "config",
                            "{} not found - using SABnzbd's server list from {} instead: {}",
                            path.display(),
                            sab.display(),
                            hosts.join(", ")
                        );
                    }
                    Err(e) => warn!(
                        target: "config",
                        "{} not found - fell back to SABnzbd's {}, which gives no usable \
                         server list either: {}",
                        path.display(),
                        sab.display(),
                        e
                    ),
                });
                parsed
            }
            Err(e) => Err(e.into()),
        }
    }

    /// The file the operator pointed us at, and nothing else: no search
    /// for a SABnzbd install, so a missing or unreadable `path` comes
    /// back as the `Io` error it is rather than as some other
    /// application's server list.
    ///
    /// TODO §156 item 7: the runner's no-servers guard reads through
    /// this, because `load`'s fallback makes the two conditions that
    /// guard exists to tell apart indistinguishable. A typo'd `--config`
    /// on a box with SABnzbd installed and a genuinely empty server list
    /// both arrive as `NoServers`, so the guard would hold the queue
    /// saying "no server is configured" about a config nobody could
    /// read, which is the one case its own doc comment promises to stand
    /// down for. It also keeps that guard off an unrelated application's
    /// file, which `load` would otherwise re-read and re-parse at the
    /// runner's tick rate forever.
    ///
    /// The trade, deliberately: on a machine that runs SABnzbd and has
    /// no nzbfast config at all, a SAB ini with no enabled server no
    /// longer raises the hold (the download reports "config has no
    /// servers" as it did before §154). Every other SAB-fallback shape
    /// is untouched - `load` still resolves the servers the download
    /// actually dials.
    ///
    /// ## Why `load` falls back even when `--config` was explicit
    ///
    /// Asked and answered 22 Aug 2026, after a loopback rig was handed
    /// `--config '{"servers":[...]}'` - inline JSON, so a filename that
    /// does not exist - and quietly downloaded through the host's
    /// SABnzbd server list for five benchmark legs. The obvious policy
    /// is "fall back when we were guessing, fail when you told us":
    /// clap knows whether an argument came from the command line, the
    /// environment or its default, so a typo'd path could come back as
    /// the `Io` error it is while a container's absent
    /// `/config/config.json` still found the SAB ini beside it.
    ///
    /// It was rejected, and not on complexity grounds - it does not
    /// work. EVERY packaged deployment passes `--config` on the command
    /// line: `packaging/docker-entrypoint.sh` builds `serve --config
    /// "$CONFIG"`, and so do the systemd unit, the launchd plist, the
    /// FreeBSD rc.d script, the Synology and QNAP wrappers, the flatpak
    /// launcher, the Homebrew service, both desktop start scripts and
    /// both Android engine services. Under that policy the fallback
    /// would fire only for a developer running bare `nzbfast` in a cwd,
    /// and would be dead in the container it was written for (issue #15,
    /// fa70cc23, whose message names "the daemon's missing-config
    /// fallback" as one of the three things it was fixing). The
    /// argument's SOURCE does not separate a first-run container from a
    /// typo; it separates packaged installs from unpackaged ones, which
    /// is not the question anyone is asking. Do not re-derive this.
    ///
    /// What changed instead is what the fallback SAYS. The notice in
    /// `load_or_sab` was one INFO line, and INFO goes to stdout, so a
    /// download's own output buried it; it is now a WARN on stderr that
    /// names the hosts it adopted, which is the link between "some other
    /// application's config" and the "no usable connection to <host>"
    /// the run dies of minutes later. The one shape now refused outright
    /// is inline JSON in `--config`, caught at parse time by
    /// `config_path` in `crates/nzbfast/src/main.rs` - it is never a
    /// filename anyone meant, so there is no behaviour to preserve.
    pub fn load_no_fallback(path: &Path) -> Result<Config, ConfigError> {
        Self::parse(&std::fs::read(path)?, is_ini(path))
    }

    /// The half both loaders share, once the bytes are in hand.
    fn parse(bytes: &[u8], ini: bool) -> Result<Config, ConfigError> {
        let cfg = if ini {
            let text = String::from_utf8_lossy(bytes);
            Config {
                servers: parse_sabnzbd_ini(&text)?,
                tmdb_key: None,
            }
        } else {
            serde_json::from_slice(bytes)?
        };
        if cfg.servers.is_empty() {
            return Err(ConfigError::NoServers);
        }
        // Refuse rather than silently alias: past this count the routing
        // bitmasks cannot tell two servers apart, and the failure mode is a
        // provider that never gets asked for articles it holds.
        if cfg.servers.len() > crate::pool::MAX_SERVERS {
            return Err(ConfigError::TooManyServers(cfg.servers.len()));
        }
        Ok(cfg)
    }
}

/// A `.ini` extension means SABnzbd's format; anything else is our JSON.
fn is_ini(p: &Path) -> bool {
    p.extension().is_some_and(|e| e.eq_ignore_ascii_case("ini"))
}

/// Standard sabnzbd.ini locations, most likely first. `extra_dirs` are
/// searched ahead of the OS install locations: callers pass the nzbfast
/// config dir, which is where a Docker user's copied sabnzbd.ini lands -
/// the OS locations all live under $HOME and never exist in a container
/// (issue #15).
pub fn sabnzbd_ini_path(extra_dirs: &[&Path]) -> Option<std::path::PathBuf> {
    let mut candidates: Vec<std::path::PathBuf> =
        extra_dirs.iter().map(|d| d.join("sabnzbd.ini")).collect();
    #[cfg(windows)]
    {
        for var in ["LOCALAPPDATA", "APPDATA"] {
            if let Ok(base) = std::env::var(var) {
                candidates.push(
                    std::path::Path::new(&base)
                        .join("sabnzbd")
                        .join("sabnzbd.ini"),
                );
            }
        }
    }
    #[cfg(not(windows))]
    if let Ok(home) = std::env::var("HOME") {
        let home = std::path::Path::new(&home);
        #[cfg(target_os = "macos")]
        candidates.push(home.join("Library/Application Support/SABnzbd/sabnzbd.ini"));
        candidates.push(home.join(".sabnzbd/sabnzbd.ini"));
    }
    candidates.into_iter().find(|p| p.is_file())
}

/// Parse the `[servers]` section of a SABnzbd configobj ini. Field
/// mapping: ssl→tls, priority→level, retention→retention_days; servers
/// with `enable = 0` are skipped. Everything else SAB stores per server
/// (timeouts, ciphers, notes…) has no nzbfast equivalent and is ignored.
pub fn parse_sabnzbd_ini(text: &str) -> Result<Vec<ServerConfig>, ConfigError> {
    use std::collections::HashMap;

    fn flush(cur: &mut Option<HashMap<String, String>>, out: &mut Vec<ServerConfig>) {
        let Some(map) = cur.take() else { return };
        let get = |k: &str| map.get(k).map(|s| s.as_str()).unwrap_or("");
        let host = get("host");
        if host.is_empty() || get("enable") == "0" {
            return;
        }
        let tls = get("ssl") != "0"; // SAB default is TLS on
        let opt = |v: &str| (!v.is_empty()).then(|| v.to_string());
        out.push(ServerConfig {
            host: host.to_string(),
            port: get("port").parse().unwrap_or(if tls { 563 } else { 119 }),
            tls,
            username: opt(get("username")),
            password: opt(get("password")),
            connections: get("connections")
                .parse()
                .unwrap_or_else(|_| default_connections()),
            pin_connections: false,
            rcvbuf: None,
            level: get("priority").parse().unwrap_or(0),
            group: None,
            retention_days: get("retention").parse().unwrap_or(0),
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        });
    }

    let mut servers = Vec::new();
    let mut in_servers = false;
    let mut cur: Option<HashMap<String, String>> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            flush(&mut cur, &mut servers);
            if in_servers {
                if inner.trim().is_empty() {
                    return Err(ConfigError::Ini("empty server section name".into()));
                }
                cur = Some(HashMap::new());
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            flush(&mut cur, &mut servers);
            in_servers = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .eq_ignore_ascii_case("servers");
            continue;
        }
        if let (Some(map), Some((k, v))) = (cur.as_mut(), line.split_once('=')) {
            let v = v.trim();
            let v = v
                .strip_prefix('"')
                .and_then(|s| s.strip_suffix('"'))
                .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
                .unwrap_or(v);
            map.insert(k.trim().to_ascii_lowercase(), v.to_string());
        }
    }
    flush(&mut cur, &mut servers);
    Ok(servers)
}

/// Parse an NZBGet `nzbget.conf` (flat `ServerN.Key=Value` lines).
/// Mapping: Encryption→tls, Level→level, numeric mirror-group id→group
/// "gN", Retention→retention_days; `Active=no` servers are skipped.
pub fn parse_nzbget_conf(text: &str) -> Vec<ServerConfig> {
    use std::collections::{BTreeMap, HashMap};
    let mut by_idx: BTreeMap<u32, HashMap<String, String>> = BTreeMap::new();
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let Some(rest) = k.trim().strip_prefix("Server") else {
            continue;
        };
        let Some((idx, field)) = rest.split_once('.') else {
            continue;
        };
        let Ok(idx) = idx.parse::<u32>() else {
            continue;
        };
        by_idx
            .entry(idx)
            .or_default()
            .insert(field.trim().to_ascii_lowercase(), v.trim().to_string());
    }
    let mut out = Vec::new();
    for m in by_idx.values() {
        let get = |k: &str| m.get(k).map(|s| s.as_str()).unwrap_or("");
        let host = get("host");
        if host.is_empty() || get("active").eq_ignore_ascii_case("no") {
            continue;
        }
        let tls = get("encryption").eq_ignore_ascii_case("yes");
        let opt = |v: &str| (!v.is_empty()).then(|| v.to_string());
        let grp: u32 = get("group").parse().unwrap_or(0);
        out.push(ServerConfig {
            host: host.to_string(),
            port: get("port").parse().unwrap_or(if tls { 563 } else { 119 }),
            tls,
            username: opt(get("username")),
            password: opt(get("password")),
            connections: get("connections")
                .parse()
                .unwrap_or_else(|_| default_connections()),
            pin_connections: false,
            rcvbuf: None,
            level: get("level").parse().unwrap_or(0),
            group: (grp > 0).then(|| format!("g{grp}")),
            retention_days: get("retention").parse().unwrap_or(0),
            block_bytes: None,
            block_account: false,
            bind_ip: None,
            socks5: None,
            enabled: true,
            warm_pool: false,
            idle_release_secs: None,
            idle_keep: None,
            max_source_ips: None,
        });
    }
    out
}

#[cfg(test)]
mod warm_pool_default_tests {
    use super::*;

    /// §36: pooling is OFF unless the server asks for it, and the
    /// absence of the key means off. A config written before this
    /// existed must not silently start pooling on upgrade.
    #[test]
    fn connection_pooling_is_off_unless_a_server_opts_in() {
        let s: ServerConfig = serde_json::from_str(r#"{"host":"news.example.com"}"#).unwrap();
        assert!(
            !s.warm_pool,
            "a server that never heard of the setting pools nothing"
        );

        let on: ServerConfig = serde_json::from_str(r#"{"host":"h","warm_pool":true}"#).unwrap();
        assert!(on.warm_pool);

        // And it is per SERVER: one opting in says nothing about another.
        let cfg: Config =
            serde_json::from_str(r#"{"servers":[{"host":"a","warm_pool":true},{"host":"b"}]}"#)
                .unwrap();
        assert!(cfg.servers[0].warm_pool);
        assert!(
            !cfg.servers[1].warm_pool,
            "pooling must not leak between servers"
        );
    }

    fn srv(json: &str) -> ServerConfig {
        serde_json::from_str(json).unwrap()
    }

    /// M7b.2 §5.7: the block-account flag round-trips, defaults to OFF,
    /// and writes nothing when it is off.
    ///
    /// The serialize half matters as much as the parse half: the daemon
    /// re-writes config.local.json whenever the editor saves a server,
    /// and people hand-edit that file. A `"block_account": false` line
    /// appearing under every server they never touched is noise that
    /// reads like a setting they chose.
    #[test]
    fn the_block_account_flag_defaults_off_and_round_trips() {
        let off = srv(r#"{"host":"news.example.com"}"#);
        assert!(
            !off.block_account,
            "a config written before the flag existed declares nothing"
        );
        assert!(
            !serde_json::to_string(&off)
                .unwrap()
                .contains("block_account"),
            "an off flag writes no key"
        );

        let on = srv(r#"{"host":"h","block_account":true}"#);
        assert!(on.block_account);
        assert!(
            serde_json::to_string(&on)
                .unwrap()
                .contains(r#""block_account":true"#)
        );

        // Per SERVER, like every other account property.
        let cfg: Config =
            serde_json::from_str(r#"{"servers":[{"host":"a","block_account":true},{"host":"b"}]}"#)
                .unwrap();
        assert!(cfg.servers[0].block_account);
        assert!(
            !cfg.servers[1].block_account,
            "the flag must not leak between servers"
        );
    }

    /// The flag is INDEPENDENT of the level and of the block size: that
    /// independence is the whole reason it exists.
    ///
    /// Before it, per-byte economics were inferred from the topology,
    /// and the inference is wrong in both directions - a metered account
    /// can be someone's only provider (level 0), and an unlimited one
    /// can sit at level 2 as a completion backbone. Each of these four
    /// combinations is a real configuration.
    #[test]
    fn measurement_spending_reads_the_flag_not_the_topology() {
        // Flatrate primary: measure freely.
        assert!(srv(r#"{"host":"a"}"#).may_spend_on_measurement());
        // Flatrate server parked at a fill level: still free to measure.
        assert!(srv(r#"{"host":"a","level":2}"#).may_spend_on_measurement());
        // Metered, and the user's ONLY provider. The topology says
        // primary; the bill says otherwise, and the bill wins.
        assert!(!srv(r#"{"host":"a","block_account":true}"#).may_spend_on_measurement());
        // The older inference still holds for configs that predate the
        // flag: a prepaid block is metered whether or not it says so.
        assert!(
            !srv(r#"{"host":"a","block_bytes":5000000000}"#).may_spend_on_measurement(),
            "a configured block is metered even without the flag"
        );
        // Zero reads as "no block configured" - the same reading the
        // pool, the job planner and the settings UI take.
        assert!(srv(r#"{"host":"a","block_bytes":0}"#).may_spend_on_measurement());
    }

    /// The operator's own number beats our hostname guess, in BOTH
    /// directions.
    ///
    /// The heuristic can only recognise providers we have heard of, and
    /// resellers front the same backbones under their own names - so it
    /// under-detects a strict provider and can over-detect a lax one
    /// that merely shares a word with a strict one. A figure read off
    /// the provider's control panel has neither problem, which is the
    /// whole reason the field exists.
    #[test]
    fn a_stated_address_limit_overrides_the_hostname_guess() {
        // Unknown host, but the user says two addresses: tight.
        let s = srv(r#"{"host":"news.some-reseller.example","max_source_ips":2}"#);
        assert!(s.source_ips_are_tight());
        assert_eq!(s.idle_release_policy().keep, 0);

        // A host the heuristic flags, but the user's plan is generous.
        let s = srv(r#"{"host":"news.newshosting.com","max_source_ips":20}"#);
        assert!(
            !s.source_ips_are_tight(),
            "a stated limit must beat the guess"
        );
        assert_eq!(s.idle_release_policy().keep, 1);

        // 0 is how a provider prints "no limit", not "no addresses".
        let s = srv(r#"{"host":"news.example.com","max_source_ips":0}"#);
        assert!(!s.source_ips_are_tight());

        // Nothing stated: fall back to the hostname hint.
        assert!(srv(r#"{"host":"news.usenetexpress.com"}"#).source_ips_are_tight());
        assert!(!srv(r#"{"host":"news.example.com"}"#).source_ips_are_tight());
    }

    /// The policy is PER SERVER, and that is the point: a server is an
    /// account, and each provider counts its own limit against its own
    /// account. Two servers share nothing.
    ///
    /// The mixed config is the case that makes it matter - a flatrate
    /// primary that does not care, plus a block account allowing two
    /// addresses. A single process-wide policy would either drag the
    /// primary down to the block account's short timeout and zero floor,
    /// throwing away warm connections on a link that never had a
    /// problem, or leave the block account's lockout in place.
    #[test]
    fn one_strict_provider_does_not_drag_down_a_lax_one() {
        let cfg: Config = serde_json::from_str(
            r#"{"servers":[{"host":"news.example.com"},
                           {"host":"news.usenetexpress.com"}]}"#,
        )
        .unwrap();
        let lax = cfg.servers[0].idle_release_policy();
        let strict = cfg.servers[1].idle_release_policy();

        assert_eq!(lax.after, Some(crate::warmpool::DEFAULT_IDLE_RELEASE));
        assert_eq!(lax.keep, 1, "the lax provider keeps a warm connection");
        assert_eq!(strict.after, Some(crate::warmpool::CAPPED_IDLE_RELEASE));
        assert_eq!(
            strict.keep, 0,
            "a floor of one frees nothing against an address cap"
        );
    }

    /// Explicit settings win, and resolve INDEPENDENTLY: lengthening the
    /// timeout must not silently re-raise a floor the address limit made
    /// pointless. `0` seconds is the off switch (a NAS or seedbox that
    /// is the account's only consumer), which is a different answer from
    /// "not set".
    #[test]
    fn explicit_settings_win_and_do_not_drag_each_other() {
        let s = srv(r#"{"host":"news.usenetexpress.com","idle_release_secs":900}"#);
        let p = s.idle_release_policy();
        assert_eq!(p.after, Some(std::time::Duration::from_secs(900)));
        assert_eq!(
            p.keep, 0,
            "the derived floor still reflects the address limit"
        );

        let s = srv(r#"{"host":"news.example.com","idle_release_secs":0}"#);
        assert_eq!(s.idle_release_policy().after, None, "0 = hold them open");

        let s = srv(r#"{"host":"news.usenetexpress.com","idle_keep":2}"#);
        let p = s.idle_release_policy();
        assert_eq!(
            p.keep, 2,
            "an explicit floor is honoured even where it frees nothing"
        );
        assert_eq!(p.after, Some(crate::warmpool::CAPPED_IDLE_RELEASE));

        // Absent from the JSON entirely = derive. A config written
        // before any of this existed must not read as "hold forever".
        let s = srv(r#"{"host":"news.example.com"}"#);
        assert_eq!(s.idle_release_secs, None);
        assert!(
            s.idle_release_policy().after.is_some(),
            "unset must not mean never"
        );
    }

    /// A too-short timeout is not merely useless, it is harmful, and it
    /// must be impossible to set by ANY route.
    ///
    /// The clamp used to live in the settings handler. Moving the
    /// setting per-server left it behind, and one second became
    /// reachable from the dashboard and from a hand-edited config - at
    /// which point the tip watcher (20 s tick) and the availability
    /// oracle, which consult this same value every pass, would hang up
    /// and reconnect on every tick, against providers that punish
    /// connect bursts 3-4x. So it is enforced at the single point every
    /// route resolves through.
    #[test]
    fn a_pathologically_short_timeout_is_floored_whatever_route_it_came_by() {
        for secs in [1, 5, 59] {
            let s = srv(&format!(r#"{{"host":"h","idle_release_secs":{secs}}}"#));
            assert_eq!(
                s.idle_release_policy().after,
                Some(std::time::Duration::from_secs(MIN_IDLE_RELEASE_SECS)),
                "{secs}s must be floored: below one tick the samplers would \
                 reconnect every pass"
            );
        }
        // At and above the floor, the operator's number is honoured.
        let s = srv(r#"{"host":"h","idle_release_secs":300}"#);
        assert_eq!(
            s.idle_release_policy().after,
            Some(std::time::Duration::from_secs(300))
        );
        // Zero keeps its own meaning - it is the off switch, not a
        // timeout to be floored up to 60.
        let s = srv(r#"{"host":"h","idle_release_secs":0}"#);
        assert_eq!(
            s.idle_release_policy().after,
            None,
            "0 must stay 'never release'"
        );
    }

    /// A floor above what the pool will ever park is silently "never
    /// release". Someone typing a big number wants everything kept warm,
    /// and that is what they get - not a setting that quietly does
    /// nothing.
    #[test]
    fn a_keep_floor_above_the_pool_cap_is_clamped_not_ignored() {
        let s = srv(r#"{"host":"h","idle_keep":100000}"#);
        assert_eq!(
            s.idle_release_policy().keep,
            crate::warmpool::MAX_PER_SERVER
        );
        let s = srv(r#"{"host":"h","idle_keep":2}"#);
        assert_eq!(s.idle_release_policy().keep, 2);
    }

    /// The timeout has to be picked against the re-warm cost - a cold
    /// fleet is 4.5-14.3x on job start - so neither default may drift
    /// down into the seconds where releasing costs more than it frees.
    #[test]
    fn neither_default_releases_fast_enough_to_defeat_the_pool() {
        for d in [
            crate::warmpool::DEFAULT_IDLE_RELEASE,
            crate::warmpool::CAPPED_IDLE_RELEASE,
        ] {
            assert!(
                d >= std::time::Duration::from_secs(60),
                "{d:?} is short enough that a queue draining back to back would \
                 pay the cold-start cost repeatedly, which is the pool's whole \
                 reason to exist"
            );
            assert!(
                d <= crate::warmpool::DEFAULT_MAX_IDLE,
                "{d:?} is past max_idle, so the release would never be the thing \
                 that frees the account and the setting would be inert"
            );
        }
    }
}

#[cfg(test)]
mod tests {
    #[test]
    fn nzbget_conf_parses_servers_levels_groups() {
        let conf = "\n# comment\nMainDir=/data\nServer1.Active=yes\nServer1.Host=news.prim.com\nServer1.Port=563\nServer1.Username=u1\nServer1.Password=p1\nServer1.Encryption=yes\nServer1.Connections=30\nServer1.Level=0\nServer1.Group=1\nServer2.Active=yes\nServer2.Host=fill.block.com\nServer2.Encryption=no\nServer2.Level=1\nServer2.Retention=4000\nServer3.Active=no\nServer3.Host=off.example.com\n";
        let s = parse_nzbget_conf(conf);
        assert_eq!(s.len(), 2);
        assert_eq!(s[0].host, "news.prim.com");
        assert!(s[0].tls);
        assert_eq!(s[0].connections, 30);
        assert_eq!(s[0].group.as_deref(), Some("g1"));
        assert_eq!(s[1].host, "fill.block.com");
        assert!(!s[1].tls);
        assert_eq!(s[1].port, 119);
        assert_eq!(s[1].level, 1);
        assert_eq!(s[1].retention_days, 4000);
    }

    use super::*;

    const SAB_INI: &str = r#"
__version__ = 19
[misc]
queue_complete = ""
[servers]
[[main]]
name = news.frugal.com
displayname = Frugal
host = news.frugal.com
port = 563
username = "user@example.com"
password = 's3cr,et"x'
connections = 30
ssl = 1
priority = 0
retention = 0
enable = 1
[[block]]
host = fill.block.co
port = 119
ssl = 0
username = blk
password = pw
connections = 8
priority = 1
retention = 1200
enable = 1
[[old]]
host = dead.example.com
enable = 0
[misc2]
x = y
"#;

    #[test]
    fn sab_ini_maps_fields() {
        let s = parse_sabnzbd_ini(SAB_INI).unwrap();
        assert_eq!(s.len(), 2); // disabled server skipped
        assert_eq!(s[0].host, "news.frugal.com");
        assert_eq!(s[0].port, 563);
        assert!(s[0].tls);
        assert_eq!(s[0].username.as_deref(), Some("user@example.com"));
        assert_eq!(s[0].password.as_deref(), Some("s3cr,et\"x"));
        assert_eq!(s[0].connections, 30);
        assert_eq!(s[0].level, 0);
        assert_eq!(s[1].host, "fill.block.co");
        assert_eq!(s[1].port, 119);
        assert!(!s[1].tls);
        assert_eq!(s[1].level, 1);
        assert_eq!(s[1].retention_days, 1200);
    }

    #[test]
    fn sab_ini_defaults_port_from_ssl() {
        let s =
            parse_sabnzbd_ini("[servers]\n[[a]]\nhost = h1\n[[b]]\nhost = h2\nssl = 0\n").unwrap();
        assert_eq!((s[0].port, s[0].tls), (563, true));
        assert_eq!((s[1].port, s[1].tls), (119, false));
    }

    #[test]
    fn ini_extension_routes_to_sab_parser() {
        let dir = std::env::temp_dir().join("nzbfast-cfg-test");
        std::fs::create_dir_all(&dir).unwrap();
        let p = dir.join("sabnzbd.ini");
        std::fs::write(&p, SAB_INI).unwrap();
        let cfg = Config::load(&p).unwrap();
        assert_eq!(cfg.servers.len(), 2);
    }

    /// Issue #15: a sabnzbd.ini copied next to the config file (Docker's
    /// /config) must be found by discovery and by Config::load's
    /// missing-config fallback - the OS install locations never exist in
    /// a container.
    #[test]
    fn sab_ini_next_to_config_is_discovered() {
        let dir = std::env::temp_dir().join("nzbfast-cfg-test-near");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sabnzbd.ini"), SAB_INI).unwrap();
        let found = sabnzbd_ini_path(&[dir.as_path()]).expect("extra dir searched");
        assert_eq!(found, dir.join("sabnzbd.ini"));
        let cfg = Config::load(&dir.join("config.local.json")).unwrap();
        assert_eq!(cfg.servers.len(), 2);
    }

    /// TODO §156 item 7: the strict loader reads the file it was given
    /// and nothing else. The runner's no-servers guard needs "this
    /// config could not be read" to stay distinguishable from "this
    /// config lists no server", and the fallback above erases that
    /// difference: a typo'd path on a SAB box comes back as SAB's list,
    /// or as `NoServers` when SAB has none enabled, which is the guard's
    /// own hold condition. It also kept the guard re-parsing another
    /// application's file twice a second.
    ///
    /// Same fixture as the test above, so the fallback it pins and the
    /// refusal pinned here are the same situation read two ways.
    #[test]
    fn load_no_fallback_does_not_search_for_sabnzbd_ini() {
        let dir = std::env::temp_dir().join("nzbfast-cfg-test-strict");
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sabnzbd.ini"), SAB_INI).unwrap();
        let missing = dir.join("config.local.json");
        // The fallback is intact for everyone else...
        assert_eq!(Config::load(&missing).unwrap().servers.len(), 2);
        // ...and invisible here: a missing file is a missing file.
        let err = Config::load_no_fallback(&missing).expect_err("must not fall back");
        assert!(
            matches!(&err, ConfigError::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
            "a missing config must stay an Io error, got {err:?}"
        );
        // And the file it WAS given still parses by extension.
        assert_eq!(
            Config::load_no_fallback(&dir.join("sabnzbd.ini"))
                .unwrap()
                .servers
                .len(),
            2
        );
    }

    /// The three shapes the 22 Aug 2026 fallback decision turns on, in
    /// the order the argument runs. The policy settled on is that
    /// `load` cannot see the difference between the first two and must
    /// not try (the reasoning is beside `load_no_fallback`), so what is
    /// pinned here is that an EXPLICIT path and a DEFAULTED one behave
    /// identically, and that the fallback is skipped - not merely
    /// unlucky - when there is no SABnzbd install to find.
    ///
    /// `load_or_sab` rather than `load` because the third case cannot
    /// be written against the real search: these bench boxes all have
    /// SABnzbd installed (we benchmark against it), so `sabnzbd_ini_path`
    /// finds `$HOME/.sabnzbd/sabnzbd.ini` and a "nothing to find" test
    /// would pass on CI and silently not run here.
    #[test]
    fn missing_config_falls_back_the_same_way_however_the_path_was_chosen() {
        let dir = std::env::temp_dir().join("nzbfast-cfg-test-fallback-policy");
        // From scratch: the last case below writes a real config at one
        // of the paths the first case needs to be MISSING, and temp_dir
        // survives the test binary, so a second run inherited it and
        // failed on the first assertion.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        std::fs::write(dir.join("sabnzbd.ini"), SAB_INI).unwrap();
        let sab = dir.join("sabnzbd.ini");
        let find = || Some(sab.clone());

        // 1. Explicit and missing: the operator named this path, and it
        //    still resolves to SAB's servers. This is the case that cost
        //    five benchmark legs, and it is deliberate - every packaged
        //    install (Docker's entrypoint included) passes --config, so
        //    refusing here would kill the fallback where it is needed.
        let explicit = dir.join("typo.local.json");
        let cfg = Config::load_or_sab(&explicit, find).expect("explicit-and-missing falls back");
        assert_eq!(cfg.servers.len(), 2);

        // 2. Defaulted and missing, SABnzbd present: issue #15's Docker
        //    shape. Indistinguishable from case 1 by construction - same
        //    call, same result - which IS the finding.
        let defaulted = dir.join("config.local.json");
        let cfg = Config::load_or_sab(&defaulted, find).expect("default-and-missing falls back");
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[0].host, "news.frugal.com");

        // 3. Defaulted and missing with nothing to find: the search
        //    coming back empty must surface the original NotFound, not
        //    some later error from a file it went looking for.
        let err = Config::load_or_sab(&defaulted, || None).expect_err("nothing to fall back to");
        assert!(
            matches!(&err, ConfigError::Io(e) if e.kind() == std::io::ErrorKind::NotFound),
            "with no SABnzbd install the missing config must stay an Io error, got {err:?}"
        );

        // A SAB ini that gives nothing usable still reports the SAB
        // error, not a silent one: `NoServers` here is about a file the
        // operator never wrote, and the warning is what says so.
        let empty = dir.join("empty.ini");
        std::fs::write(&empty, "[servers]\n").unwrap();
        let err = Config::load_or_sab(&defaulted, || Some(empty.clone()))
            .expect_err("an ini with no servers is not a config");
        assert!(matches!(err, ConfigError::NoServers), "got {err:?}");

        // And a config that IS there is never overridden by an ini
        // sitting next to it, whatever the search would have returned.
        std::fs::write(&explicit, br#"{"servers":[{"host":"mine","port":119}]}"#).unwrap();
        let cfg = Config::load_or_sab(&explicit, find).expect("present config wins");
        assert_eq!(cfg.servers.len(), 1);
        assert_eq!(cfg.servers[0].host, "mine");
    }
}

#[cfg(test)]
mod obf_tests {
    use super::*;

    #[test]
    fn roundtrips_including_punctuation_and_unicode() {
        // Provider passwords routinely carry '!' and other punctuation, which
        // is exactly the class of character rot13 would have left readable.
        // Every fixture here is synthetic on purpose: test data must never be
        // a credential anyone actually uses.
        for pw in [
            "Tr0ub4dor&3!",
            "correcthorse",
            "a",
            "p@ss w/ spaces & £unicode✓",
        ] {
            let o = obfuscate(pw);
            assert!(o.starts_with(OBF_PREFIX), "{o}");
            assert!(
                !o.contains(pw),
                "obfuscated form still contains the secret: {o}"
            );
            assert_eq!(deobfuscate(&o), pw);
        }
    }

    #[test]
    fn repeated_characters_leave_no_visible_pattern() {
        // Keyed XOR alone would emit the same byte for every 'a'; the index is
        // mixed in so it does not.
        let o = obfuscate("aaaaaaaa");
        let hex = o.strip_prefix(OBF_PREFIX).unwrap();
        let bytes: Vec<&str> = hex
            .as_bytes()
            .chunks(2)
            .map(|c| std::str::from_utf8(c).unwrap())
            .collect();
        assert!(bytes.iter().collect::<std::collections::HashSet<_>>().len() > 1);
    }

    #[test]
    fn cleartext_still_loads() {
        // Hand-edited configs and SAB/NZBGet imports must keep working.
        assert_eq!(deobfuscate("correcthorse"), "correcthorse");
        assert_eq!(deobfuscate(""), "");
    }

    #[test]
    fn empty_and_already_obfuscated_are_left_alone() {
        assert_eq!(obfuscate(""), "");
        let once = obfuscate("secret");
        assert_eq!(
            obfuscate(&once),
            once,
            "must not double-obfuscate on re-save"
        );
        assert_eq!(deobfuscate(&once), "secret");
    }

    /// A provider password is free to start with our own prefix.
    /// `obfuscate` guesses from that prefix that the value is already
    /// encoded and stores it verbatim; `deobfuscate` then decodes the
    /// "hex" and hands the connect path different bytes, so AUTHINFO PASS
    /// fails forever against a config that looks right. The raw-input
    /// encoder makes no such guess (Codex sweep 12 Aug F16).
    #[test]
    fn a_literal_obf_prefixed_password_round_trips() {
        for pw in [
            "obf1:0000",     // valid even-length hex - the ambiguous one
            "obf1:abcdef01", // ditto, longer
            "obf1:zz",       // invalid hex
            "obf1:abc",      // odd length
            "obf1:",         // prefix alone
            "obf1",          // near miss
        ] {
            let stored = obfuscate_input(pw);
            assert_eq!(deobfuscate(&stored), pw, "round trip failed for {pw:?}");
            assert!(
                !stored[OBF_PREFIX.len()..].contains("obf1"),
                "the literal survived into the stored form: {stored}"
            );
        }
        // Empty is still "no password", not a secret worth hiding.
        assert_eq!(obfuscate_input(""), "");
        // And the idempotent wrapper is still idempotent, which is what
        // the settings re-save paths rely on.
        let once = obfuscate_input("secret");
        assert_eq!(obfuscate(&once), once);
        assert_eq!(deobfuscate(&once), "secret");
    }

    #[test]
    fn malformed_obf_values_degrade_to_the_original() {
        // Non-hex, and odd-length hex: not ours, hand it back untouched rather
        // than inventing a password.
        for bad in ["obf1:zz", "obf1:abc"] {
            assert_eq!(deobfuscate(bad), bad);
        }
        // An empty payload is not malformed - it means an empty password.
        // Returning the literal "obf1:" here would make us try to authenticate
        // with that string.
        assert_eq!(deobfuscate("obf1:"), "");
    }

    #[test]
    fn config_json_roundtrips_through_serde() {
        let json = r#"{"servers":[{"host":"h","username":"u","password":"Tr0ub4dor&3!"}]}"#;
        let c: Config = serde_json::from_str(json).unwrap();
        assert_eq!(c.servers[0].password.as_deref(), Some("Tr0ub4dor&3!"));
        // Serializing must write the obfuscated form, not the secret.
        let out = serde_json::to_string(&c.servers[0]).unwrap();
        assert!(
            !out.contains("Tr0ub4dor"),
            "cleartext leaked on write: {out}"
        );
        assert!(out.contains("obf1:"), "{out}");
        let back: ServerConfig = serde_json::from_str(&out).unwrap();
        assert_eq!(back.password.as_deref(), Some("Tr0ub4dor&3!"));
    }
}

/// One SABnzbd category, reduced to the two fields that have a home in
/// nzbfast: its name, and where finished downloads in it should land.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SabCategory {
    /// The category name, already reduced to a single path component -
    /// nzbfast's `enqueue` and `refile_out_dir` both sanitize it into
    /// one, so `movies/anime` would become the literal folder
    /// `movies_anime` rather than a nested path. The nesting, when there
    /// is any, lives in `dir` instead.
    pub name: String,
    /// Absolute destination for this category, or `None` when SAB's
    /// layout already matches what nzbfast does by default and an
    /// override would change nothing.
    pub dir: Option<String>,
}

/// What [`parse_sabnzbd_categories`] found, and what it could not carry.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub struct SabCategories {
    pub cats: Vec<SabCategory>,
    /// Human-readable notes about fields that were present in the file
    /// and deliberately not imported. Surfaced to the user rather than
    /// dropped silently: an import that looks complete when it is not is
    /// worse than one that says what it left behind.
    pub dropped: Vec<String>,
}

/// Parse the `[categories]` section of a SABnzbd configobj ini.
///
/// Only `name` and `dir` come over. A SAB category has six fields and
/// four of them have nowhere to go: `pp`, `script` and `priority` are
/// per-category in SAB and global here, `order` is real precedence in SAB
/// (`get_ordered_categories` sorts by it) while `Daemon::cats` is a
/// `BTreeSet` rendered alphabetically, and `newzbin` matches the
/// INDEXER-supplied category or newsgroup name rather than the release
/// name - which nzbfast deliberately declines to route on. Every one of
/// those is reported in `dropped` instead of being ignored.
///
/// The directory rules mirror SAB's own `get_complete_directory`:
///
/// - a `dir` ending in `*` means "no per-job subdirectory". nzbfast
///   always joins a job folder, so the star is stripped and the
///   behaviour is reported as not carried over. It cannot simply be left
///   on: `sanitize_filename` does not map `*`, so on Linux it would
///   become a real folder with a star in its name.
/// - an EMPTY `dir` falls back to the `[[*]]` category's `dir`, not to
///   `complete_dir`, so `[[*]]` has to be read even though it is not
///   itself an importable category.
/// - a relative `dir` is resolved against `[misc] complete_dir`; an
///   absolute one is left alone and a leading `~/` is expanded. nzbfast's
///   `move_completed_cats` REFUSES a relative path, so resolving here is
///   required rather than merely tidy.
/// - a `dir` that is just the category's own name needs no entry at all:
///   nzbfast already files a category into its own subfolder, so an
///   override would say what the default already says.
pub fn parse_sabnzbd_categories(text: &str) -> SabCategories {
    use std::collections::HashMap;

    let mut complete_dir = String::new();
    // Insertion-ordered so the emitted list follows the file rather than
    // a hash seed; `order` itself cannot be honoured (see `dropped`).
    let mut order: Vec<String> = Vec::new();
    let mut cats: HashMap<String, HashMap<String, String>> = HashMap::new();

    let mut section = String::new();
    let mut sub: Option<String> = None;
    for raw in text.lines() {
        let line = raw.trim();
        if line.is_empty() || line.starts_with('#') || line.starts_with(';') {
            continue;
        }
        if let Some(inner) = line.strip_prefix("[[").and_then(|s| s.strip_suffix("]]")) {
            let name = inner.trim().to_string();
            if section.eq_ignore_ascii_case("categories") && !name.is_empty() {
                if !cats.contains_key(&name) {
                    order.push(name.clone());
                }
                cats.entry(name.clone()).or_default();
                sub = Some(name);
            } else {
                sub = None;
            }
            continue;
        }
        if line.starts_with('[') && line.ends_with(']') {
            section = line
                .trim_matches(|c| c == '[' || c == ']')
                .trim()
                .to_string();
            sub = None;
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let k = k.trim().to_ascii_lowercase();
        let v = v.trim();
        let v = v
            .strip_prefix('"')
            .and_then(|s| s.strip_suffix('"'))
            .or_else(|| v.strip_prefix('\'').and_then(|s| s.strip_suffix('\'')))
            .unwrap_or(v)
            .trim();
        if section.eq_ignore_ascii_case("misc") && k == "complete_dir" {
            complete_dir = v.to_string();
        }
        if let Some(name) = sub.as_ref()
            && let Some(map) = cats.get_mut(name)
        {
            map.insert(k, v.to_string());
        }
    }

    // `[[*]]` is SAB's default category: it supplies the fallback `dir`
    // for every other one, and is not itself importable.
    let star_dir = cats
        .get("*")
        .and_then(|m| m.get("dir"))
        .map(String::as_str)
        .unwrap_or("")
        .to_string();

    // Expand the base BEFORE it resolves anyone else: SAB accepts
    // `complete_dir=~/Downloads/complete`, and joining a relative
    // category dir onto the verbatim value produced `~/…/movies`,
    // which the absolute-path check below then rejected - dropping a
    // perfectly valid destination (Codex sweep 5 Aug L2).
    let complete_dir = resolve_sab_dir(&complete_dir, "");

    let mut out = SabCategories::default();
    let mut saw_star_flag = false;
    let saw = |set: &mut Vec<String>, note: &str| {
        if !set.iter().any(|s| s == note) {
            set.push(note.to_string());
        }
    };

    for name in &order {
        if name == "*" {
            continue;
        }
        let map = &cats[name];
        for (key, note) in [
            ("order", "the order categories are tried in"),
            ("newzbin", "the indexer-category match terms"),
            ("pp", "the per-category post-processing level"),
            ("script", "the per-category post-processing script"),
            ("priority", "the per-category priority"),
        ] {
            if map.get(key).is_some_and(|v| !v.is_empty()) {
                saw(&mut out.dropped, note);
            }
        }

        // SAB lets the display name differ from the section name; the
        // section name is what `cat_convert` matches on, so it wins when
        // `name` is absent.
        let display = map.get("name").filter(|s| !s.is_empty()).unwrap_or(name);
        let cat = crate::disk::sanitize_filename(display);
        if cat.is_empty() {
            continue;
        }

        let raw_dir = map.get("dir").map(String::as_str).unwrap_or("");
        let raw_dir = if raw_dir.is_empty() {
            star_dir.as_str()
        } else {
            raw_dir
        };
        let (raw_dir, starred) = match raw_dir.strip_suffix('*') {
            Some(stripped) => (stripped.trim_end_matches('/'), true),
            None => (raw_dir, false),
        };
        if starred {
            saw_star_flag = true;
        }

        let dir = if raw_dir.is_empty() || raw_dir == cat {
            // Nothing to override: with no dir at all, or with a dir that
            // is exactly the category's own folder, nzbfast's default
            // filing already puts it in the same place.
            None
        } else {
            Some(resolve_sab_dir(raw_dir, &complete_dir))
        };
        out.cats.push(SabCategory { name: cat, dir });
    }

    if saw_star_flag {
        saw(
            &mut out.dropped,
            "\"no job folder\" (a dir ending in *) - nzbfast always makes one",
        );
    }
    // Any category whose destination could not be made absolute is not
    // importable as an override, because `move_completed_cats` refuses a
    // relative path.
    let unresolved = out
        .cats
        .iter()
        .filter(|c| c.dir.as_deref().is_some_and(|d| !is_absolute_path(d)))
        .count();
    if unresolved > 0 {
        saw(
            &mut out.dropped,
            "folders for some categories, because sabnzbd.ini has no [misc] complete_dir \
             to resolve them against",
        );
        out.cats.iter_mut().for_each(|c| match c.dir.as_deref() {
            Some(d) if !is_absolute_path(d) => c.dir = None,
            _ => {}
        });
    }
    out
}

/// The user's home directory. `HOME` is not set on Windows - `USERPROFILE`
/// is - and a sabnzbd.ini carrying `~/...` is an ordinary thing to import
/// there, so reading only `HOME` left the tilde unexpanded and the caller
/// then joined it onto `complete_dir` to make a path with a literal `~`
/// segment in the middle. Same fallback order the daemon's own path
/// helper uses.
fn home_dir() -> Option<String> {
    ["HOME", "USERPROFILE"]
        .iter()
        .find_map(|k| std::env::var(k).ok().filter(|v| !v.is_empty()))
}

/// SAB's `real_path`: absolute stays, `~` expands, anything else is
/// relative to `complete_dir`. All three home spellings a sabnzbd.ini
/// carries in the wild - `~/x`, `~\x` (Windows-authored), and a bare
/// `~` - expand; leaving one unexpanded lands category downloads in a
/// directory literally named `~` under complete_dir.
fn resolve_sab_dir(dir: &str, complete_dir: &str) -> String {
    if is_absolute_path(dir) {
        return dir.to_string();
    }
    if let Some(rest) = dir
        .strip_prefix("~/")
        .or_else(|| dir.strip_prefix("~\\"))
        .or_else(|| (dir == "~").then_some(""))
        && let Some(home) = home_dir()
    {
        let home = home.trim_end_matches(['/', '\\']);
        if rest.is_empty() {
            return home.to_string();
        }
        return format!("{home}/{rest}");
    }
    if complete_dir.is_empty() {
        return dir.to_string();
    }
    format!("{}/{dir}", complete_dir.trim_end_matches('/'))
}

/// Absolute on either platform, because a sabnzbd.ini written on Windows
/// is a perfectly ordinary thing to import on Linux and vice versa.
fn is_absolute_path(p: &str) -> bool {
    p.starts_with('/')
        || p.starts_with('\\')
        || (p.len() > 2
            && p.as_bytes()[1] == b':'
            && (p.as_bytes()[2] == b'\\' || p.as_bytes()[2] == b'/'))
}

#[cfg(test)]
mod sab_category_tests {
    use super::*;

    const INI: &str = r#"
[misc]
complete_dir = /data/usenet/complete
[categories]
[[*]]
name = *
dir = ""
[[movies_anime]]
name = movies_anime
order = 0
dir = movies/movies_anime
newzbin = *anime*
[[books]]
name = books
dir = books
[[flat]]
name = flat
dir = oneshot/*
[[absolute]]
name = absolute
dir = /mnt/nas/Absolute
[[bare]]
name = bare
[servers]
[[news.example.com]]
host = news.example.com
"#;

    fn cats(text: &str) -> SabCategories {
        parse_sabnzbd_categories(text)
    }

    /// Pitfall 6: `[[*]]` supplies fallbacks, it is not a category.
    #[test]
    fn the_star_category_is_not_imported() {
        assert!(!cats(INI).cats.iter().any(|c| c.name == "*"));
    }

    /// Pitfall 1: a relative dir resolves against `[misc] complete_dir`,
    /// an absolute one is left alone. This is not cosmetic - since #20,
    /// `move_completed_cats` REFUSES a relative path outright.
    #[test]
    fn a_relative_dir_resolves_against_complete_dir_and_an_absolute_one_does_not() {
        let c = cats(INI);
        let by = |n: &str| c.cats.iter().find(|c| c.name == n).unwrap().dir.clone();
        assert_eq!(
            by("movies_anime"),
            Some("/data/usenet/complete/movies/movies_anime".into())
        );
        assert_eq!(by("absolute"), Some("/mnt/nas/Absolute".into()));
    }

    /// Pitfall 4: a dir equal to the category's own name is already what
    /// nzbfast does, so it must NOT bloat the override setting.
    #[test]
    fn a_dir_that_is_just_the_category_name_needs_no_override() {
        let c = cats(INI);
        let books = c.cats.iter().find(|c| c.name == "books").unwrap();
        assert_eq!(
            books.dir, None,
            "an override was emitted that changes nothing"
        );
        // ...and so does a category with no dir at all, which falls back
        // to `[[*]]`'s empty dir rather than to complete_dir.
        let bare = c.cats.iter().find(|c| c.name == "bare").unwrap();
        assert_eq!(bare.dir, None);
    }

    /// Pitfall 2: a trailing `*` is a "no job folder" FLAG, not a path.
    /// It must be stripped (sanitize_filename does not map `*`, so it
    /// would otherwise become a real folder with a star in its name) and
    /// the behaviour must be reported as not carried over.
    #[test]
    fn a_starred_dir_is_stripped_and_the_lost_behaviour_is_reported() {
        let c = cats(INI);
        let flat = c.cats.iter().find(|c| c.name == "flat").unwrap();
        assert_eq!(flat.dir, Some("/data/usenet/complete/oneshot".into()));
        assert!(
            c.dropped.iter().any(|d| d.contains("no job folder")),
            "the star's meaning was dropped silently: {:?}",
            c.dropped
        );
    }

    /// Pitfall 5: the category is one path component. A nested dir can
    /// only live in the override, never in the name.
    #[test]
    fn a_category_name_is_always_a_single_component() {
        let c = cats("[categories]\n[[x]]\nname = movies/anime\ndir = /a/b\n");
        assert_eq!(c.cats[0].name, "movies_anime");
        assert_eq!(c.cats[0].dir, Some("/a/b".into()));
    }

    /// Pitfall 7 and the scope note: everything with nowhere to go is
    /// NAMED, so an import cannot look complete when it is not.
    #[test]
    fn every_unimportable_field_is_reported() {
        let c = cats(INI);
        let joined = c.dropped.join(" | ");
        for want in ["order", "indexer-category", "no job folder"] {
            assert!(joined.contains(want), "{want:?} not reported in {joined:?}");
        }
        let c2 = cats("[categories]\n[[a]]\ndir = /x\npp = 3\nscript = go.sh\npriority = -1\n");
        let j2 = c2.dropped.join(" | ");
        for want in [
            "post-processing level",
            "post-processing script",
            "priority",
        ] {
            assert!(
                want.is_empty() || j2.contains(want),
                "{want:?} not in {j2:?}"
            );
        }
    }

    /// With no `complete_dir` there is nothing to resolve a relative dir
    /// against. Dropping the override is the honest answer - emitting a
    /// relative one would be rejected by the settings arm anyway.
    #[test]
    fn a_relative_dir_with_no_complete_dir_is_dropped_and_said_so() {
        let c = cats("[categories]\n[[tv]]\nname = tv\ndir = shows/tv\n");
        assert_eq!(c.cats[0].dir, None);
        assert!(
            c.dropped.iter().any(|d| d.contains("complete_dir")),
            "{:?}",
            c.dropped
        );
    }

    /// A tilde `complete_dir` is a base SAB accepts, so a relative
    /// category dir must land under `$HOME/...` - joining the verbatim
    /// `~/...` produced a path the absolute check rejected, and a
    /// valid destination was dropped with a misleading "no
    /// complete_dir" note (Codex sweep 5 Aug L2).
    #[test]
    fn a_tilde_complete_dir_still_resolves_relative_category_dirs() {
        // HOME on unix, USERPROFILE on Windows - resolved the same way
        // the product does, so this asserts the shipped behaviour on
        // both platforms instead of panicking on one of them.
        let home = super::home_dir().expect("test needs HOME or USERPROFILE");
        let c = cats(
            "[misc]\ncomplete_dir = ~/Downloads/complete\n\
             [categories]\n[[movies]]\nname = movies\ndir = films\n",
        );
        assert_eq!(
            c.cats[0].dir,
            Some(format!(
                "{}/Downloads/complete/films",
                home.trim_end_matches('/')
            )),
            "dropped: {:?}",
            c.dropped
        );
        assert!(
            !c.dropped.iter().any(|d| d.contains("complete_dir")),
            "a resolvable base was reported unresolvable: {:?}",
            c.dropped
        );
    }

    /// Codex sweep 7 Aug (the 3df076bf residual): the OTHER two home
    /// spellings a sabnzbd.ini carries - `~\...` from a Windows-authored
    /// config and a bare `~` - must expand too, or category downloads
    /// land in a directory literally named `~` under complete_dir.
    #[test]
    fn windows_tilde_and_bare_tilde_dirs_expand() {
        let home = super::home_dir().expect("test needs HOME or USERPROFILE");
        let home = home.trim_end_matches(['/', '\\']);
        assert_eq!(
            super::resolve_sab_dir("~\\Downloads", "/c"),
            format!("{home}/Downloads")
        );
        assert_eq!(super::resolve_sab_dir("~", "/c"), home);
        // The plain spelling keeps working, and a name merely STARTING
        // with a tilde is a real directory name, not a home reference.
        assert_eq!(super::resolve_sab_dir("~/dl", "/c"), format!("{home}/dl"));
        assert_eq!(super::resolve_sab_dir("~backup", "/c"), "/c/~backup");
    }

    /// The parser must not wander into `[servers]` or back out of it.
    #[test]
    fn only_the_categories_section_is_read() {
        let c = cats(INI);
        assert!(!c.cats.iter().any(|c| c.name.contains("news")));
        assert_eq!(c.cats.len(), 5, "{:?}", c.cats);
    }
}
