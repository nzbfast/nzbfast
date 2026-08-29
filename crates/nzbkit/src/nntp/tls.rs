//! The TLS layer of the NNTP client: which cipher suite and which trust
//! anchors this process offers, the shared `ClientConfig` cache behind
//! both, the handshake ladder that turns a connected socket into a
//! [`Wire`], and the Linux kernel offload underneath it.
//!
//! It is one subject in the sense that matters here: every item below
//! exists to answer "what does a TLS session for this download look
//! like", and none of them is reachable from the NNTP protocol code -
//! `Connection` calls exactly three of them ([`tls_full_host`],
//! [`mark_tls_full_host`], [`tls_handshake`]) and nothing else.
//!
//! The socket UNDER rustls - the ciphertext read buffer and the
//! userspace rung that builds the stream - stays in `nntp/tlswire.rs`;
//! this module configures what rides on it.

use std::sync::Arc;

use crate::config::AddressFamily;
use crate::sync::MutexExt;
use tracing::{info, warn};

use super::tlswire::userspace_tls;
use super::{CONNECT_TIMEOUT, NntpError, Wire, direct_connect_opts};

/// Whether this CPU has hardware AES (AES-NI / ARMv8 crypto extensions).
/// Boxes without it - Raspberry Pi 4-class ARM, old x86 - do AES-GCM in
/// software at a fraction of ChaCha20-Poly1305's speed, and TLS covers
/// every downloaded byte.
fn aes_accelerated() -> bool {
    #[cfg(target_arch = "x86_64")]
    {
        std::arch::is_x86_feature_detected!("aes")
    }
    #[cfg(target_arch = "aarch64")]
    {
        std::arch::is_aarch64_feature_detected!("aes")
    }
    #[cfg(not(any(target_arch = "x86_64", target_arch = "aarch64")))]
    {
        false
    }
}

/// Whether a suite is ChaCha20-Poly1305 (any TLS version).
fn is_chacha(s: &rustls::SupportedCipherSuite) -> bool {
    matches!(
        s.suite(),
        rustls::CipherSuite::TLS13_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256
    )
}

/// Whether a suite is AES-**128**-GCM (any TLS version).
fn is_aes128(s: &rustls::SupportedCipherSuite) -> bool {
    matches!(
        s.suite(),
        rustls::CipherSuite::TLS13_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256
            | rustls::CipherSuite::TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256
    )
}

/// The aws-lc-rs provider, tuned for bulk transfer.
///
/// TLS covers every downloaded byte, so the AEAD runs over the whole
/// download and its cost per byte is a throughput term on any CPU
/// without headroom. Measured on Apple silicon at 16 KB records:
/// AES-128-GCM 9.70 GB/s, AES-256-GCM 8.25, ChaCha20-Poly1305 2.12.
///
/// `pin_fast_suite` offers exactly ONE suite: the fastest this CPU can
/// run (AES-128-GCM with hardware AES, ChaCha20 without - on a
/// Raspberry Pi 4-class core, software AES-GCM is the slow one and the
/// ranking inverts).
///
/// It has to be exactly one, and that is the whole subtlety. Under TLS
/// 1.3 the SERVER chooses, walking its own preference list for the
/// first suite the client offered; OpenSSL's default order is
/// AES-256 → ChaCha20 → AES-128. So a client that merely REORDERS its
/// list changes nothing, and a client that drops only AES-256 gets
/// handed ChaCha20 - measured on 4 of our 6 providers, a ~4x per-byte
/// REGRESSION over the AES-256 it was trying to improve on. Offering a
/// single suite is the only way to actually choose.
///
/// A server that cannot do our one suite fails the handshake, and
/// `connect_unbounded` retries once with the full list, remembering the
/// host (see [`tls_full_host`]). 128-bit AES is not a meaningful
/// security downgrade for bulk transfer.
fn tls_provider(aes_accelerated: bool, pin_fast_suite: bool) -> rustls::crypto::CryptoProvider {
    let mut provider = rustls::crypto::aws_lc_rs::default_provider();
    if pin_fast_suite {
        if aes_accelerated {
            provider.cipher_suites.retain(is_aes128);
        } else {
            provider.cipher_suites.retain(is_chacha);
        }
    } else if !aes_accelerated {
        // Full-list fallback on a soft-AES CPU: ChaCha first is the best
        // we can do, though a server-preference server will ignore it.
        provider.cipher_suites.sort_by_key(|s| !is_chacha(s));
    }
    provider
}

/// Hosts whose handshake failed on the AES-128-only offer (see
/// [`tls_provider`]). Small and append-only: one entry per genuinely
/// odd provider, for the life of the process.
fn tls_full_hosts() -> &'static std::sync::Mutex<std::collections::HashSet<String>> {
    static S: std::sync::OnceLock<std::sync::Mutex<std::collections::HashSet<String>>> =
        std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

pub(super) fn tls_full_host(host: &str) -> bool {
    // NZBFAST_TLS_AES256=1 forces the old full-list behaviour everywhere:
    // the escape hatch if a provider we never tested behaves oddly.
    if std::env::var_os("NZBFAST_TLS_AES256").is_some() {
        return true;
    }
    tls_full_hosts().lock_ok().contains(host)
}

pub(super) fn mark_tls_full_host(host: &str) {
    tls_full_hosts().lock_ok().insert(host.to_string());
}

/// The PEM file the extra trust anchors are read from, or `None`:
/// [`set_extra_ca`] first, then `NZBFAST_EXTRA_CA`. Both name a PATH -
/// neither turns verification off, and no third spelling does either.
fn extra_ca_path() -> Option<std::path::PathBuf> {
    if let Some(p) = extra_ca_override().lock_ok().clone() {
        return Some(p);
    }
    std::env::var_os("NZBFAST_EXTRA_CA").map(std::path::PathBuf::from)
}

fn extra_ca_override() -> &'static std::sync::Mutex<Option<std::path::PathBuf>> {
    static S: std::sync::OnceLock<std::sync::Mutex<Option<std::path::PathBuf>>> =
        std::sync::OnceLock::new();
    S.get_or_init(Default::default)
}

/// Point the extra trust anchors at `path`, or clear them with `None`,
/// without writing the environment.
///
/// Same anchors and the same opt-in-by-explicit-path rule as
/// `NZBFAST_EXTRA_CA`, which this overrides while it is set. It exists
/// because `std::env::set_var` is sound only where nothing else reads
/// the environment, which `crates/nzbkit/tests/integration/` - one
/// binary of twenty-odd modules on parallel threads, all reading
/// `NZBFAST_*` - is not. Changing the anchors after a connection has
/// been made takes effect: [`tls_client_config`] keys its cache on this
/// path.
pub fn set_extra_ca(path: Option<std::path::PathBuf>) {
    *extra_ca_override().lock_ok() = path;
}

/// The trust anchors: webpki's built-in roots plus anything in the PEM
/// file at `extra_ca`. Built once per distinct `extra_ca`.
fn tls_roots(extra_ca: Option<&std::path::Path>) -> rustls::RootCertStore {
    let mut roots = rustls::RootCertStore::empty();
    roots.extend(webpki_roots::TLS_SERVER_ROOTS.iter().cloned());
    // Extra trust anchors from a PEM file, ADDED to the webpki set,
    // never replacing it. Two real uses: a self-hosted or corporate-
    // MITM'd provider whose CA isn't public, and the TLS bench leg
    // (mockserve's self-signed cert). Opt-in by explicit path - this is
    // deliberately not a "skip verification" switch, which is the thing
    // that quietly ships and then never gets turned back off.
    let Some(p) = extra_ca else {
        return roots;
    };
    use rustls::pki_types::pem::PemObject;
    match rustls::pki_types::CertificateDer::pem_file_iter(p) {
        Err(e) => warn!(target: "tls", "NZBFAST_EXTRA_CA {p:?}: {e}"),
        Ok(it) => {
            let mut added = 0usize;
            for c in it {
                match c
                    .map_err(|e| e.to_string())
                    .and_then(|c| roots.add(c).map_err(|e| e.to_string()))
                {
                    Ok(()) => added += 1,
                    Err(e) => warn!(target: "tls", "NZBFAST_EXTRA_CA {p:?}: {e}"),
                }
            }
            info!(target: "tls", "NZBFAST_EXTRA_CA {p:?}: {added} extra trust anchor(s)");
        }
    }
    roots
}

/// True when this process has asked for kernel TLS. Constant `false`
/// unless the `ktls` feature is built in on Linux, and it is read
/// before the first `ClientConfig` is built so the answer cannot
/// change underneath a cached config.
fn ktls_wanted() -> bool {
    #[cfg(all(feature = "ktls", target_os = "linux"))]
    {
        super::ktls::wanted()
    }
    #[cfg(not(all(feature = "ktls", target_os = "linux")))]
    {
        false
    }
}

/// One shared ClientConfig per (suite policy, trust anchors), for the
/// life of the process: rustls keeps its session ticket cache inside the
/// config, so sharing it enables TLS session RESUMPTION on reconnects
/// (abbreviated handshake - one less round-trip and no fresh key
/// exchange per connection). Two suite policies, because the AES-128
/// offer needs a full-list fallback for any server that cannot do it.
///
/// KEYED BY THE EXTRA-CA PATH, and that half is not an optimisation.
/// This was two `OnceLock`s, so the FIRST caller to want a config
/// latched the trust anchors for the whole process and every later one
/// silently got them - a `tls_roots()` read that could never happen
/// again, however the path changed underneath it. Production never
/// notices, since it sets the path once before anything connects, which
/// is exactly why nothing reported it: it surfaces only where two things
/// in one process legitimately need different anchors, and there the
/// second one simply cannot connect. A process pointed at N distinct CA
/// paths holds up to 2N configs; production's N is 1.
pub(super) fn tls_client_config(pin_fast_suite: bool) -> Arc<rustls::ClientConfig> {
    type Key = (bool, Option<std::path::PathBuf>);
    static CACHE: std::sync::OnceLock<
        std::sync::Mutex<std::collections::HashMap<Key, Arc<rustls::ClientConfig>>>,
    > = std::sync::OnceLock::new();
    let build = |pin_fast_suite: bool, extra_ca: Option<&std::path::Path>| {
        // Name the crypto provider explicitly. The dependency tree links
        // BOTH aws-lc-rs and ring (a transitive dep pulled ring in), so
        // rustls can no longer auto-select a process default - plain
        // `builder()` panics at runtime. Pin aws-lc-rs so the choice is
        // unambiguous regardless of what else links a provider.
        let mut cfg = rustls::ClientConfig::builder_with_provider(Arc::new(tls_provider(
            aes_accelerated(),
            pin_fast_suite,
        )))
        .with_safe_default_protocol_versions()
        .expect("aws-lc-rs supports safe default protocol versions")
        .with_root_certificates(tls_roots(extra_ca))
        .with_no_client_auth();
        // Kernel TLS needs the negotiated traffic secrets after the
        // handshake, and rustls will only part with them when it was
        // told so before the handshake. Left off otherwise: the secrets
        // are in the process either way, but there is no reason to make
        // them extractable when nothing extracts them.
        cfg.enable_secret_extraction = ktls_wanted();
        Arc::new(cfg)
    };
    let key: Key = (pin_fast_suite, extra_ca_path());
    // Built under the lock, so two connects racing the same key build
    // one config rather than two - which is the whole point of sharing
    // it, since a second config would start with an empty ticket cache.
    let mut cache = CACHE.get_or_init(Default::default).lock_ok();
    if let Some(cfg) = cache.get(&key) {
        return cfg.clone();
    }
    let cfg = build(pin_fast_suite, key.1.as_deref());
    cache.insert(key, cfg.clone());
    cfg
}

/// The shared TLS client configuration, for the engine's non-NNTP TLS
/// links (today: the pre feed's IRC connection). Full suite list, not
/// the AES-128 pin - that pin is a per-byte throughput optimisation for
/// the download path and means nothing on a link carrying a line of
/// text a minute. Sharing the config also shares the trust anchors, so
/// `NZBFAST_EXTRA_CA` applies here too.
pub fn shared_tls_client_config() -> Arc<rustls::ClientConfig> {
    tls_client_config(false)
}

/// One rung of the handshake ladder. `Ok(None)` means "the kernel
/// refused kTLS, the socket is spent, dial again" - it cannot happen
/// when kTLS is not compiled in.
#[cfg(all(feature = "ktls", target_os = "linux"))]
pub(super) async fn tls_handshake(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Option<Wire>> {
    if super::ktls::active() {
        return super::ktls::connect(name, tcp, pin_fast_suite).await;
    }
    userspace_tls(name, tcp, pin_fast_suite).await.map(Some)
}

#[cfg(not(all(feature = "ktls", target_os = "linux")))]
pub(super) async fn tls_handshake(
    name: rustls::pki_types::ServerName<'static>,
    tcp: tokio::net::TcpStream,
    pin_fast_suite: bool,
) -> std::io::Result<Option<Wire>> {
    userspace_tls(name, tcp, pin_fast_suite).await.map(Some)
}

/// Diagnostic: handshake with `host:port` exactly as a download
/// connection would, and report `(protocol, cipher suite)`. Answers the
/// only question that matters when tuning the AEAD cost - what the
/// server actually PICKED, which under TLS 1.3 is its choice from our
/// offer, not ours (see [`tls_provider`]). No NNTP traffic, no
/// credentials sent.
pub async fn probe_tls(host: &str, port: u16) -> Result<(String, String), NntpError> {
    // Bounded like every production connect: a single-candidate dial gets
    // no per-candidate slice and the TLS peer may simply never answer, so
    // an unbounded probe parked its caller for as long as the OS let the
    // SYN wait.
    let dial = direct_connect_opts(host, port, None, None, AddressFamily::default());
    let tcp = tokio::time::timeout(CONNECT_TIMEOUT, dial)
        .await
        .map_err(|_| NntpError::Timeout)??;
    tcp.set_nodelay(true)?;
    let name = rustls::pki_types::ServerName::try_from(host.to_string())
        .map_err(|_| NntpError::TlsName)?;
    let connector = tokio_rustls::TlsConnector::from(tls_client_config(!tls_full_host(host)));
    let stream = tokio::time::timeout(CONNECT_TIMEOUT, connector.connect(name, tcp))
        .await
        .map_err(|_| NntpError::Timeout)??;
    let (_, conn) = stream.get_ref();
    let proto = conn
        .protocol_version()
        .map_or_else(|| "?".to_string(), |v| format!("{v:?}"));
    let suite = conn
        .negotiated_cipher_suite()
        .map_or_else(|| "?".to_string(), |s| format!("{:?}", s.suite()));
    Ok((proto, suite))
}

#[cfg(test)]
mod tls_provider_tests {
    use super::tls_provider;
    use std::sync::Arc;

    fn is_chacha(s: &rustls::SupportedCipherSuite) -> bool {
        format!("{:?}", s.suite()).contains("CHACHA20")
    }

    fn is_aes128(s: &rustls::SupportedCipherSuite) -> bool {
        format!("{:?}", s.suite()).contains("AES_128")
    }

    /// The pinned offer must contain EXACTLY ONE algorithm, because a
    /// TLS 1.3 server picks from its own preference order: an offer with
    /// two entries is the server's choice, not ours. This is the
    /// regression guard for the measured trap - dropping only AES-256
    /// left {AES-128, ChaCha} and 4 of 6 providers answered ChaCha,
    /// which is ~4x slower per byte than the AES-256 it replaced.
    #[test]
    fn pinned_offer_is_a_single_algorithm() {
        let aes = tls_provider(true, true);
        assert!(!aes.cipher_suites.is_empty());
        assert!(
            aes.cipher_suites.iter().all(is_aes128),
            "hardware-AES CPUs must offer AES-128 and nothing else: {:?}",
            aes.cipher_suites
        );

        let soft = tls_provider(false, true);
        assert!(!soft.cipher_suites.is_empty());
        assert!(
            soft.cipher_suites.iter().all(is_chacha),
            "soft-AES CPUs must offer ChaCha20 and nothing else: {:?}",
            soft.cipher_suites
        );
    }

    #[test]
    fn unaccelerated_cpu_gets_chacha_first_in_the_fallback() {
        let p = tls_provider(false, false);
        assert!(is_chacha(&p.cipher_suites[0]), "{:?}", p.cipher_suites);
        // Stable partition: every ChaCha suite precedes every AES suite,
        // and the AES suites keep aws-lc-rs's own relative order.
        let first_aes = p.cipher_suites.iter().position(|s| !is_chacha(s)).unwrap();
        assert!(p.cipher_suites[first_aes..].iter().all(|s| !is_chacha(s)));
        let default = rustls::crypto::aws_lc_rs::default_provider();
        let aes_order: Vec<_> = p.cipher_suites[first_aes..]
            .iter()
            .map(|s| s.suite())
            .collect();
        let default_aes: Vec<_> = default
            .cipher_suites
            .iter()
            .filter(|s| !is_chacha(s))
            .map(|s| s.suite())
            .collect();
        assert_eq!(aes_order, default_aes);
    }

    /// The policy has to reach the handshake. `tls_provider` decides
    /// what to offer, but what a connection actually offers is whatever
    /// `tls_client_config` built - and the two only stay in step while
    /// nothing else in this file constructs a `ClientConfig` of its
    /// own. Verified live on x86_64 (2 Aug): a connection to the bench
    /// server negotiates TLSv1_3 / TLS13_AES_128_GCM_SHA256, which is
    /// the single suite this pin offers.
    #[test]
    fn the_shared_config_carries_the_pinned_offer() {
        let cfg = super::tls_client_config(true);
        let got: Vec<_> = cfg
            .crypto_provider()
            .cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect();
        let want: Vec<_> = tls_provider(super::aes_accelerated(), true)
            .cipher_suites
            .iter()
            .map(|s| s.suite())
            .collect();
        assert_eq!(got, want, "the built config must offer the pinned suite");
        // Extractable traffic secrets are for kTLS and nothing else, so
        // a process that did not ask for kTLS must not have them.
        assert_eq!(cfg.enable_secret_extraction, super::ktls_wanted());
    }

    /// The cached config must follow the trust anchors, not latch them.
    ///
    /// Sharing one config per suite policy is what gets session
    /// resumption, so the SAME anchors must still hand back the SAME
    /// `Arc`: equality would pass on an implementation that rebuilt a
    /// config every call and quietly lost the ticket cache, hence
    /// `Arc::ptr_eq`. Two DIFFERENT anchors must hand back two configs;
    /// before the key carried the path, the second caller got the first
    /// one's roots and could not connect.
    ///
    /// The paths deliberately do not exist: `tls_roots` warns and
    /// returns the plain webpki set for an unreadable file, so every
    /// config here is equivalent to the default one and cannot affect a
    /// neighbour in the same process. Cleared again at the end for the
    /// same reason.
    #[test]
    fn the_config_cache_follows_the_trust_anchors() {
        let dir = std::env::temp_dir();
        let a = dir.join("nzbkit-no-such-ca-a.pem");
        let b = dir.join("nzbkit-no-such-ca-b.pem");

        super::set_extra_ca(Some(a.clone()));
        let first = super::tls_client_config(true);
        let again = super::tls_client_config(true);
        assert!(
            Arc::ptr_eq(&first, &again),
            "the same anchors must share one config, ticket cache included"
        );

        super::set_extra_ca(Some(b));
        let other = super::tls_client_config(true);
        assert!(
            !Arc::ptr_eq(&first, &other),
            "different anchors must not be served the first caller's config"
        );

        super::set_extra_ca(Some(a));
        let back = super::tls_client_config(true);
        super::set_extra_ca(None);
        assert!(Arc::ptr_eq(&first, &back), "the first config must survive");
    }

    /// The fallback path must stay a superset - it is what rescues a
    /// server that cannot do the pinned suite.
    #[test]
    fn accelerated_cpu_fallback_keeps_default_order() {
        let p = tls_provider(true, false);
        let default = rustls::crypto::aws_lc_rs::default_provider();
        let got: Vec<_> = p.cipher_suites.iter().map(|s| s.suite()).collect();
        let want: Vec<_> = default.cipher_suites.iter().map(|s| s.suite()).collect();
        assert_eq!(got, want);
    }
}
