//! System benchmark (design: M15): measure the three download bottlenecks
//! - network, compute, disk - and report the fastest download speed the
//! machine could sustain, plus which stage limits it and what to change.
//!
//! Also: per-server benchmarks and an infrastructure-overlap detector.
//! Two Usenet servers on the SAME backbone share takedowns and missing
//! articles, so they add capacity but NOT recovery diversity. We STAT a
//! shared article sample on every server and cluster servers whose
//! missing-article vectors agree - telling the user which providers are
//! redundant and which genuinely widen coverage.

use std::sync::Arc;

/// Whether this CPU has hardware AES, which decides which AEAD the TLS
/// connection pins (see `nntp::tls_provider`). Duplicated as a `pub`
/// here so the CPU bench can measure the suite the download path will
/// actually negotiate rather than a guess.
pub fn hw_aes() -> bool {
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

/// Name of the AEAD a TLS connection will use on this CPU.
pub fn tls_aead_name() -> &'static str {
    if hw_aes() {
        "tls aead AES-128-GCM"
    } else {
        "tls aead ChaCha20"
    }
}

/// Run the negotiated TLS AEAD over `p` in 16 KB TLS records, using
/// rustls' own provider (aws-lc-rs) so the number matches the download
/// path. Every downloaded byte is decrypted, so this belongs in the
/// per-byte budget alongside md5 and yEnc decode - and on a weak core it
/// is a large share of it.
///
/// Seals rather than opens: `open_in_place` consumes its ciphertext, so
/// a throughput loop would have to re-seal anyway, and for GCM and
/// ChaCha20-Poly1305 the two directions are the same work.
pub fn tls_aead_seal(p: &[u8]) {
    use aws_lc_rs::aead::{Aad, LessSafeKey, Nonce, UnboundKey};
    let alg = if hw_aes() {
        &aws_lc_rs::aead::AES_128_GCM
    } else {
        &aws_lc_rs::aead::CHACHA20_POLY1305
    };
    let key = LessSafeKey::new(UnboundKey::new(alg, &[0x5au8; 32][..alg.key_len()]).unwrap());
    const REC: usize = 16 * 1024;
    let mut buf = Vec::with_capacity(REC + 32);
    for c in p.chunks(REC) {
        buf.clear();
        buf.extend_from_slice(c);
        key.seal_in_place_append_tag(
            Nonce::assume_unique_for_key([0u8; 12]),
            Aad::empty(),
            &mut buf,
        )
        .expect("seal");
        std::hint::black_box(&buf);
    }
}
/// Run AES-256-CBC decryption over `p.len()` bytes through the same
/// `rarcrypt` decryptor the encrypted-RAR path uses, so the number
/// reflects whichever AES backend this BUILD selected. That is the
/// point: RustCrypto's `cpufeatures` cannot detect AES at runtime on
/// every OS (ARM64 Windows in particular), so targets it is blind to
/// need `-C target-feature=+aes` in `.cargo/config.toml` or this runs
/// fixsliced soft AES - ~230 MB/s against ~13 GB/s hardware, measured
/// on M-series. `rarcrypt` is crate-private by design; this is the one
/// public window onto it, like `tls_aead_seal` above.
pub fn rar_aes_decrypt(p: &[u8]) {
    use crate::rarcrypt::{AesKey, cbc_decrypt};
    let key = AesKey::Aes256([7u8; 32]);
    let mut buf = vec![0u8; (4 << 20).min(p.len().max(16) & !15)];
    let iters = p.len() / buf.len();
    for _ in 0..iters.max(1) {
        cbc_decrypt(&key, &[3u8; 16], &mut buf);
        std::hint::black_box(&buf);
    }
}

use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

use md5::{Digest, Md5};

use crate::config::ServerConfig;
use crate::nntp::Connection;
use tracing::info;

/// OVER returns message-ids already angle-bracketed; NZB segments do not.
/// Normalize to exactly one bracket pair for STAT/BODY.
pub fn bracket_id(id: &str) -> String {
    let t = id.trim().trim_start_matches('<').trim_end_matches('>');
    format!("<{t}>")
}

/// Per-id presence on ONE server: pipelined STATs over a single
/// connection, ~50 bytes per id, so a few hundred ids cost well under a
/// second. This is the gate that makes a real-article ladder supply
/// safe: retention differs per provider, and an article a fast primary
/// holds may not exist on a low-retention fill - laddering 430s
/// measures nothing (see conntune::MIN_LADDER_GBPS).
///
/// Output is in input order. Errors out rather than guessing when the
/// connection dies mid-sweep - a partial verdict on a broken session is
/// not a sample.
pub async fn stat_presence(
    server: &ServerConfig,
    ids: &[String],
) -> Result<Vec<bool>, Box<dyn std::error::Error + Send + Sync>> {
    let (mut conn, _) = Connection::connect(server).await?;
    let mut out = Vec::with_capacity(ids.len());
    let window = 32usize;
    let mut sent = 0usize;
    while out.len() < ids.len() {
        while sent < ids.len() && sent - out.len() < window {
            conn.send_stat(&ids[sent]).await?;
            sent += 1;
        }
        conn.flush().await?;
        // `read_stat_checked`, never `read_stat`: replies are attributed
        // POSITIONALLY here - the next one belongs to `ids[out.len()]` -
        // so a leg that lost one reply upstream would file every later
        // reply against the id behind it and the whole presence vector
        // would shift. An id mismatch errors out, which is what this
        // function already does for a session that dies mid-sweep: a
        // partial verdict on a desynced session is not a sample. A
        // server that echoes no id at all still passes.
        let expected = ids[out.len()].as_str();
        let have = tokio::time::timeout(
            Duration::from_secs(20),
            conn.read_stat_checked(Some(expected)),
        )
        .await
        .map_err(|_| Box::<dyn std::error::Error + Send + Sync>::from("STAT timed out"))??;
        out.push(have);
    }
    conn.quit().await;
    Ok(out)
}

/// GB/s of a compute stage, single-core and all-core.
#[derive(Clone, Copy, serde::Serialize)]
pub struct StageRate {
    pub(crate) one_core: f64,
    pub all_core: f64,
}

#[derive(Clone, serde::Serialize)]
pub struct ComputeReport {
    pub cores: usize,
    pub decode_simd: StageRate,
    pub(crate) crc32: StageRate,
    pub(crate) md5: StageRate,
    /// The binding stage of the pipeline (decode once + verify once).
    pub verify: StageRate,
    /// All-core Gbps with full MD5+CRC32 verify - the compute ceiling
    /// when `fast_verify` is off.
    pub ceiling_gbps: f64,
    /// All-core Gbps with CRC32-only verify - the compute ceiling when
    /// `fast_verify` is on, which has been the shipped default since
    /// 21 Jul 2026 (TODO §10). Same measurement as `crc32.all_core`,
    /// exposed as a ceiling so a caller outside this crate need not
    /// reach `crc32` (`pub(crate)`) to see what fast verify buys.
    pub fast_ceiling_gbps: f64,
}

/// Run the per-stage compute benchmark. `mb` = payload per stage.
pub fn compute(mb: usize) -> ComputeReport {
    // cpu-workers-gate: this benchmark measures the MACHINE's compute
    // ceiling, so it has to use the machine's cores. Running it against a
    // launcher's worker cap would report the cap back as the box's speed.
    let cores = std::thread::available_parallelism().map_or(8, |n| n.get());
    let bytes = mb * 1024 * 1024;
    let payload: Vec<u8> = (0..bytes)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 11) as u8))
        .collect();
    let part = &payload[..(700 * 1024).min(payload.len())];
    let article = crate::yenc::encode("b.bin", part.len() as u64, Some((1, 2)), 1, part);

    let run = |f: &(dyn Fn(&[u8]) + Sync)| -> StageRate {
        let t0 = Instant::now();
        f(&payload);
        let one = bytes as f64 / t0.elapsed().as_secs_f64() / 1e9;
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..cores {
                s.spawn(|| f(&payload));
            }
        });
        let all = (bytes * cores) as f64 / t0.elapsed().as_secs_f64() / 1e9;
        StageRate {
            one_core: one,
            all_core: all,
        }
    };

    let art = article.clone();
    let decode_simd = run(&move |p: &[u8]| {
        for _ in 0..(p.len() / (700 * 1024)).max(1) {
            std::hint::black_box(crate::yenc_simd::decode(&art).ok());
        }
    });
    let crc32 = run(&|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            std::hint::black_box(crc32fast::hash(c));
        }
    });
    let md5 = run(&|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box(d);
        }
    });
    let verify = run(&|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box((d, crc32fast::hash(c)));
        }
    });

    ComputeReport {
        cores,
        decode_simd,
        crc32,
        md5,
        verify,
        ceiling_gbps: verify.all_core * 8.0,
        fast_ceiling_gbps: crc32.all_core * 8.0,
    }
}

/// Sequential write throughput of `dir`'s filesystem, GB/s. Writes+fsyncs
/// `mb` of data to a temp file, then removes it.
pub fn disk_write(dir: &std::path::Path, mb: usize) -> std::io::Result<f64> {
    use std::io::Write;
    let path = dir.join(format!(".nzbfast-diskbench-{}", std::process::id()));
    let block = vec![0xA5u8; 8 << 20];
    let t0 = Instant::now();
    {
        let mut f = std::fs::File::create(&path)?;
        let mut written = 0usize;
        while written < mb << 20 {
            f.write_all(&block)?;
            written += block.len();
        }
        f.sync_all()?;
    }
    let secs = t0.elapsed().as_secs_f64();
    let _ = std::fs::remove_file(&path);
    Ok((mb << 20) as f64 / secs / 1e9)
}

/// Live download-rate probe: fetch `articles` real bodies from one server
/// over `connections` pipelined connections for up to `secs`, return Gbps.
/// Uses the pool so it reflects our actual fetch path.
/// Discover up to `want` fetch-worthy article ids (300 KB–1.2 MB) from
/// the newest headers of `group`. Kept cheap: a few OVER chunks, never a
/// deep scan - a probe must start in seconds even on a slow link.
pub async fn discover_ids(
    server: &ServerConfig,
    group: &str,
    want: usize,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    let (mut conn, _) = Connection::connect(server).await?;
    let g = conn.group(group).await?;
    let mut ids = Vec::new();
    let mut high = g.high;
    let mut chunks = 0;
    // Small wants stay cheap (6 chunks); the multi-gig probes ask for
    // thousands of ids and may scan deeper - the loop still exits the
    // moment `want` is reached, so dense groups pay almost nothing extra.
    let max_chunks = (want / 600).clamp(6, 20);
    while ids.len() < want && high > g.low && chunks < max_chunks {
        let from = high.saturating_sub(4_000).max(g.low);
        for e in conn.over(from, high).await? {
            if (300_000..=1_200_000).contains(&e.bytes) && !e.message_id.is_empty() {
                ids.push(bracket_id(&e.message_id));
            }
        }
        chunks += 1;
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    conn.quit().await;
    if ids.is_empty() {
        return Err(format!("no suitably-sized articles found in {group}").into());
    }
    Ok(ids)
}

/// Fetch `ids` from one server with `connections` sockets for `secs`,
/// returning the achieved rate in Gbps.
/// Returns (Gbps over the window, total raw bytes actually transferred -
/// callers bill the latter to the data-usage ledger).
pub async fn timed_fetch(
    server: &ServerConfig,
    ids: Vec<String>,
    connections: usize,
    secs: u64,
) -> (f64, u64) {
    use crate::pool::PoolConfig;
    let cfg = PoolConfig {
        connections,
        window: 4,
        ..PoolConfig::default()
    };
    let (gbps, per, _, _) =
        timed_fetch_multi(vec![(server.clone(), cfg)], ids, usize::MAX, secs).await;
    (gbps, per.first().copied().unwrap_or(0))
}

/// Timed fetch across a whole SERVER SET sharing one work queue - the
/// pool-aggregate measurement ("do my providers together saturate the
/// line?"). Returns (aggregate Gbps, per-server raw bytes, per-server
/// GRANTED sockets - the most sessions that server served us at once
/// during the run, exact rather than sampled - supply-exhausted flag),
/// all vecs in input order.
///
/// With a big-enough sample (≥8 completions over ≥1 s) the rate is
/// measured first-completion to last-completion - steady state, the
/// connect/TLS/slow-start ramp excluded - so ladder rungs with more
/// sockets aren't penalized by their own bigger ramp. Small samples
/// fall back to the whole-window figure below.
///
/// The rate is bytes over the time the transfer ACTUALLY took, not the
/// nominal window: a fast line drains a fixed id supply in a fraction of
/// the window, and dividing by the full window capped the measured rate
/// at supply/window (East Coast bench box, 5 Gbps: "0.24 Gbps - network is your
/// limit" on a path that does 3+ Gbps in real downloads). When the
/// exhausted flag is true the rate is real but slightly LOW - the
/// connect/TLS ramp is inside the measured span - so callers wanting
/// precision should hand in a supply sized to outlast the window.
pub async fn timed_fetch_multi(
    mut servers: Vec<(ServerConfig, crate::pool::PoolConfig)>,
    mut ids: Vec<String>,
    max_ids: usize,
    secs: u64,
) -> (f64, Vec<u64>, Vec<usize>, bool) {
    use crate::pool::{FetchOutcome, LiveStats, QueueControl, fetch_all_multi_ctl};
    // Live gauges so the caller can see how many sockets the provider
    // actually accepted (asked ≠ granted near account limits).
    let live = LiveStats::for_servers(&servers);
    for (_, cfg) in servers.iter_mut() {
        cfg.live = Some(live.clone());
    }
    let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchOutcome>(256);
    let bytes = Arc::new(AtomicU64::new(0));
    let bytes2 = bytes.clone();
    let t0 = Instant::now();
    let deadline = t0 + Duration::from_secs(secs);
    // Nanos-since-t0 of the last in-window completion: the denominator
    // when the queue runs dry early (excludes the QUIT/teardown tail).
    let last_done_ns = Arc::new(AtomicU64::new(0));
    let last_done_ns2 = last_done_ns.clone();
    // First in-window completion (time, bytes) and completion count:
    // with enough completions the rate is measured first-article to
    // last-article, excluding the connect/TLS/slow-start ramp. The ramp
    // grows with the socket count, so measuring over the whole window
    // systematically penalized the HIGHER rungs of a connection ladder -
    // exactly the comparison the tuner makes - worst on high-RTT paths
    // where extra connections matter most.
    let first_done_ns = Arc::new(AtomicU64::new(u64::MAX));
    let first_bytes = Arc::new(AtomicU64::new(0));
    let done_count = Arc::new(AtomicU64::new(0));
    let (first_done_ns2, first_bytes2, done_count2) = (
        first_done_ns.clone(),
        first_bytes.clone(),
        done_count.clone(),
    );
    let consumer = tokio::spawn(async move {
        while let Some(o) = rx.recv().await {
            if let FetchOutcome::Done { raw, .. } = o {
                let now = Instant::now();
                if now < deadline {
                    bytes2.fetch_add(raw.len() as u64, Ordering::Relaxed);
                    let ns = (now - t0).as_nanos() as u64;
                    last_done_ns2.store(ns, Ordering::Relaxed);
                    done_count2.fetch_add(1, Ordering::Relaxed);
                    if first_done_ns2
                        .compare_exchange(u64::MAX, ns, Ordering::Relaxed, Ordering::Relaxed)
                        .is_ok()
                    {
                        first_bytes2.store(raw.len() as u64, Ordering::Relaxed);
                    }
                }
            }
        }
    });
    // Cap the id list so fetch_all returns near the window.
    ids.truncate(max_ids.max(64));
    let n_servers = servers.len();
    let reqs: Vec<crate::pool::ArticleReq> = ids
        .into_iter()
        .map(crate::pool::ArticleReq::fresh)
        .collect();
    // Stop via QueueControl at the deadline: aborting the outer future
    // instead LEAKED the spawned workers, which kept downloading and
    // strangled every later ladder step's measurement.
    let ctl = Arc::new(QueueControl::default());
    let ctl2 = ctl.clone();
    let mut handle =
        tokio::spawn(async move { fetch_all_multi_ctl(&servers, reqs, tx, Some(&ctl2)).await });
    // The deadline path below stops the pool politely. NOTHING stopped it
    // when this whole future was DROPPED instead - and both ladder
    // callers wrap the ladder in a timeout, so a slow provider that
    // outruns it detaches the spawned task and leaves its workers pulling
    // articles against the user's real downloads, billed to their
    // account, for as long as the queue lasts. The wider that timeout
    // gets - it is 240 s now, with a reopen probe and a best-of-three
    // run-off inside it - the more there is to leak.
    //
    // `ctl.abort()` ONLY - deliberately no `handle.abort()` beside it,
    // and the reason is the opposite of the obvious one.
    //
    // It is not that aborting the task would strand its workers (an
    // earlier version of this comment said so and was wrong). The
    // workers are owned by `fetch_all_multi_ctl`'s own
    // `Vec<JoinHandle>`, which `join_fleet` consumes - and dropping a
    // JoinHandle DETACHES rather than kills, so they survive the abort
    // either way and still see `aborted` and still close their sockets.
    //
    // The cost is `join_fleet` itself. It is the only thing that ever
    // reclaims a worker parked on a wedged connection: it waits for
    // `finished`, sleeps EXIT_GRACE, and then abandons the stragglers
    // with a "worker still parked" warning. `ctl.abort()` sends
    // `finished`, so that reaper is armed and counting the moment this
    // guard fires. Aborting the task would drop the reaper's future and
    // leave a genuinely wedged worker running for good - reintroducing
    // the exact leak this guard exists to close, wearing a tidier fix.
    // (Mechanism established by the Codex sweep session, 4 Aug.)
    //
    // It needs no disarming. Once the run has finished the pool's last
    // strong Arc is gone, the handle's Weak no longer upgrades, and
    // abort() is a no-op that returns false.
    struct AbortOnDrop(Arc<QueueControl>);
    impl Drop for AbortOnDrop {
        fn drop(&mut self) {
            self.0.abort();
        }
    }
    // Deliberately NOT `impl Drop for QueueControl`: the streaming layer
    // holds one of these on purpose past the end of its run (see the type
    // docs), and aborting there would kill live playback.
    let _abort_on_cancel = AbortOnDrop(ctl.clone());
    // Wait for the window - or for the queue to drain first, which stops
    // the clock at the real end of the transfer.
    let mut early = None;
    tokio::select! {
        _ = tokio::time::sleep(Duration::from_secs(secs)) => {}
        r = &mut handle => { early = Some(r.unwrap_or_default()); }
    }
    let exhausted = early.is_some();
    // Granted = the PEAK sockets held at once during the run, on both
    // paths (asked ≠ granted near account limits).
    //
    // It used to be the instantaneous count at the measure point when
    // the supply had not drained, and that is a single sample of a
    // quantity the tuner now makes a decision on: the knee is clamped to
    // it. A provider shedding a few sockets in the last second of the
    // window reads "granted 5 of 16 asked" and caps every job at 5 for a
    // week - and nothing re-checks it, because the contested re-measure
    // keys off RATES. "The provider let us hold 16 at once" is a fact
    // about the account either way; a socket count that fell at the
    // deadline is not evidence it was never granted.
    //
    // The peak is read off the pool's own `connected_peak`, recorded at
    // the moment each session is established, and NOT off a sampler
    // here. This function ran a 100 ms sampler over `connected` until
    // 28 Aug 2026 (TODO 312 item 3), and a sampler can only ever see a
    // fleet that outlives a tick: a carry rung asking 13 sockets and
    // draining in ~0.45 s reported 3; the daemon carry probe's rungs of
    // 5 and 10 both reported 1 against an unpaced loopback provider; and
    // `granted_sees_the_whole_fleet_on_a_rung_that_drains_at_once` below
    // measures a fleet of six reported as ZERO, the whole transfer
    // having fitted inside the sampler's first tick. Its own comment
    // already said the quantity wanted was "the provider let us hold N
    // at once" - a high-water mark, which the increment site can state
    // exactly and for free.
    //
    // Do NOT "fix" a future under-read by ticking the sampler faster:
    // that spends CPU on every ladder rung to approximate a number the
    // pool already knows exactly. And do not redefine `granted` as
    // "distinct sockets that COMPLETED an article" - that is a different
    // quantity (USEFUL sockets, not granted ones) and it under-reads for
    // the same reason, harder to see: on a fast-draining rung most of
    // the fleet legitimately connects and is handed no work because the
    // queue is already empty. `conntune::knee_of` reads this field to
    // decide the provider is REFUSING sockets and caps the user's
    // connection count to it; a socket the provider accepted and we then
    // had nothing to send down is not a refusal.
    let granted: Vec<usize> = live
        .servers
        .iter()
        .map(|s| s.connected_peak.load(Ordering::Acquire))
        .collect();
    let stats = match early {
        Some(s) => s,
        None => {
            let _ = tokio::task::spawn_blocking(move || ctl.abort()).await;
            tokio::time::timeout(Duration::from_secs(10), handle)
                .await
                .ok()
                .and_then(|r| r.ok())
                .unwrap_or_default()
        }
    };
    let _ = consumer.await;
    let total = bytes.load(Ordering::Relaxed);
    let first_ns = first_done_ns.load(Ordering::Relaxed);
    let last_ns = last_done_ns.load(Ordering::Relaxed);
    let n_done = done_count.load(Ordering::Relaxed);
    let span = last_ns.saturating_sub(first_ns.min(last_ns)) as f64 / 1e9;
    // Steady-state rate (first completion → last completion, first
    // article's bytes excluded to match the span) whenever the sample is
    // big enough to be meaningful; otherwise fall back to the whole
    // window (ramp included, as before).
    let gbps = if first_ns != u64::MAX && n_done >= 8 && span >= 1.0 {
        total.saturating_sub(first_bytes.load(Ordering::Relaxed)) as f64 * 8.0 / 1e9 / span
    } else {
        let secs_f = if exhausted {
            (last_ns as f64 / 1e9).max(0.1)
        } else {
            (secs as f64).max(0.1)
        };
        total as f64 * 8.0 / 1e9 / secs_f
    };
    let per: Vec<u64> = if stats.len() == n_servers {
        stats.iter().map(|s| s.bytes).collect()
    } else {
        vec![0; n_servers]
    };
    (gbps, per, granted, exhausted)
}

/// Returns (Gbps, raw bytes transferred) - bill the bytes.
pub async fn network_probe(
    server: &ServerConfig,
    group: &str,
    connections: usize,
    secs: u64,
) -> Result<(f64, u64), Box<dyn std::error::Error + Send + Sync>> {
    // Enough ids to keep a ~6 Gbps line busy for the whole window
    // (~600 KB low-end article estimate). Sparse groups return fewer;
    // the early-drain timing in timed_fetch_multi keeps that honest.
    let want = (connections * 60).max(secs as usize * 1250);
    let ids = discover_ids(server, group, want).await?;
    Ok(timed_fetch(server, ids, connections, secs).await)
}

/// Aggregate probe over a whole server set: every server pulls from one
/// shared queue at its clamped connection count, which is what a real
/// download does when it saturates all providers at once. One server's
/// figure reads far below what several accounts deliver together
/// (issue #12, round 2: five providers, 160+ connections, and a probe
/// that could only ever show the first one).
///
/// Levels are flattened to 0 for the probe: the pool holds a fill
/// server back until the primaries 430, which is correct for downloads
/// and wrong for a capacity measurement - a backup that never gets
/// asked measures as zero.
///
/// Returns (aggregate Gbps, per-server raw bytes in input order - bill
/// each to its own host).
pub async fn network_probe_multi(
    servers: &[ServerConfig],
    group: &str,
    secs: u64,
) -> Result<(f64, Vec<u64>), Box<dyn std::error::Error + Send + Sync>> {
    use crate::pool::PoolConfig;
    // Per-server clamp as before; a total cap keeps a many-account
    // fleet's probe from becoming a real download - scale everyone
    // down proportionally, never to zero.
    let conns: Vec<usize> = servers
        .iter()
        .map(|s| (s.connections as usize).clamp(1, 100))
        .collect();
    let total: usize = conns.iter().sum();
    let scale = if total > 200 {
        200.0 / total as f64
    } else {
        1.0
    };
    let conns: Vec<usize> = conns
        .iter()
        .map(|&c| ((c as f64 * scale) as usize).max(1))
        .collect();
    let total: usize = conns.iter().sum();
    // Discover from the first server that answers - message-IDs are
    // universal, but the first configured server may be the dead one.
    let want = (total * 60).max(secs as usize * 1250);
    let mut ids = Vec::new();
    let mut last_err: Option<Box<dyn std::error::Error + Send + Sync>> = None;
    for s in servers {
        match discover_ids(s, group, want).await {
            Ok(v) => {
                ids = v;
                break;
            }
            Err(e) => last_err = Some(e),
        }
    }
    if ids.is_empty() {
        return Err(last_err.unwrap_or_else(|| "no servers to probe".into()));
    }
    let set: Vec<(ServerConfig, PoolConfig)> = servers
        .iter()
        .zip(&conns)
        .map(|(s, &c)| {
            let mut s = s.clone();
            s.level = 0;
            (
                s,
                PoolConfig {
                    connections: c,
                    window: 4,
                    ..PoolConfig::default()
                },
            )
        })
        .collect();
    let (gbps, per, _granted, _exhausted) = timed_fetch_multi(set, ids, usize::MAX, secs).await;
    Ok((gbps, per))
}

/// One step of a connection ladder: sockets asked for, sockets the
/// provider actually granted (still connected at the measure point), and
/// the achieved rate.
#[derive(Clone, serde::Serialize)]
pub struct LadderStep {
    pub connections: usize,
    pub granted: usize,
    pub gbps: f64,
    /// Raw bytes this step transferred (for the data-usage ledger).
    pub bytes: u64,
    /// The step drained its whole article supply before the window
    /// closed. The rate is still measured over the actual transfer time
    /// (so it's real), but reads slightly low - the connect ramp is
    /// inside the span.
    pub saturated: bool,
}

/// How much a doubling has to gain for the climb to continue.
///
/// Small on purpose. This is the threshold that decides how much speed
/// the tuner is willing to leave on the table without even looking, and
/// the answer the product wants is "almost none" - the sockets are free
/// to the user and the seconds are not. The cost of a low bar is a
/// longer ladder (a few more 5 s rungs), which is paid once per provider
/// per week by a background probe on an idle link.
const CLIMB_GAIN: f64 = 1.03;

/// How close to the best rung a rung has to be to earn a run-off place.
const RUNOFF_BAND: f64 = 0.90;

/// Most rungs that get the longer second look.
const RUNOFF_MAX: usize = 3;

/// Extra races each run-off candidate gets, on top of its ladder rung.
///
/// Two, so every candidate ends up a best-of-THREE. This is the number
/// that decides whether the selection bar can mean anything: a
/// best-of-two still carries most of the ~6% spread that repeated
/// samples of an identical rung show, and a 5% rule read off two such
/// estimates is a coin toss wearing a decimal point. More samples of a
/// subtractively-noisy quantity move every estimate closer to the true
/// capacity, so the GAPS between candidates shrink toward the real ones.
///
/// The cost is the honest part: up to RUNOFF_MAX x this many extra
/// windows at double length, so a ladder that reaches the run-off with
/// three candidates spends about a minute more. It buys the difference
/// between a recommendation that wanders between probes and one that
/// does not, on a measurement made once per provider per week - and a
/// user who does not want to wait has the per-server pin.
const RUNOFF_ROUNDS: usize = 2;

/// Has a doubling stopped paying?
///
/// Pulled out of the climb as a plain function on purpose. The end-to-end
/// harness measures real throughput against a mock paced on real
/// `Instant`s, so it is load-sensitive and flakes on a busy machine -
/// which makes it a poor place to prove a THRESHOLD. The rule itself has
/// no I/O in it and can be pinned exactly; the harness is then only
/// asked whether the whole thing hangs together.
///
/// `starved` means the step ran out of articles before its window
/// closed: the rate is ramp-biased low and must not be read as "the
/// doubling stopped paying".
fn climb_stalled(prev_gbps: f64, cur_gbps: f64, starved: bool) -> bool {
    !starved && cur_gbps <= prev_gbps * CLIMB_GAIN
}

/// Is a finished climb too far below the account's allowance to be taken
/// on trust? See the reopen block for why the answer is usually yes.
///
/// Note the argument: this asks about the top rung the climb REACHED,
/// not about where the knee landed. A ladder that climbed to 16 of 20
/// has not stopped short, whatever its knee says. Reading this predicate
/// off a failure's shape instead of its signature is how a correct
/// mechanism got raised as a release blocker.
///
/// Not part of the real API: public only so `tests/conn_tuner.rs` can
/// gate an assertion on this exact rule rather than restate it, and an
/// integration test is a separate crate so `pub(crate)` will not reach
/// it. A restated copy meant changing the predicate here would leave the
/// test asserting the old band - a silent version of the very defect it
/// was written to fix. Call it, do not copy it.
///
/// `#[doc(hidden)]` because `sysbench` IS published (lib.rs names it in
/// the crate docs) and TODO §84 puts nzbkit on crates.io: a bare `pub`
/// would make a tuning heuristic a semver commitment, which is the exact
/// freedom this was opened up to preserve.
#[doc(hidden)]
pub fn worth_reopening(top_rung: usize, ceiling: usize) -> bool {
    ceiling > 2 && top_rung.saturating_mul(2) < ceiling
}

/// Did the ceiling probe beat the ladder's peak by enough to say the
/// climb ended on noise rather than on a real limit?
fn reopen_won(high_gbps: f64, peak_gbps: f64) -> bool {
    high_gbps > peak_gbps * CLIMB_GAIN
}

/// Articles a ladder step needs to outlast its window, sized from the
/// fastest rate seen so far (×2.5: a doubling step may better-than-
/// double). A fixed connections×40 supply drains in a fraction of the
/// window on a multi-gig line, capping every step at supply/window and
/// reading as a flat ladder (East Coast bench box: identical per-conn
/// rates at 2 and 4).
fn ladder_supply_for(peak_gbps: f64, conns: usize, secs_per_step: u64) -> usize {
    let by_rate =
        (peak_gbps.max(0.05) * 2.5 * secs_per_step as f64 * 1e9 / 8.0 / 600_000.0) as usize;
    (conns * 40).max(by_rate).max(64)
}

/// Re-measure specific rungs of a finished ladder, once each, back to
/// back.
///
/// A jagged ladder is one whose rungs contradict each other, and the
/// cure is a second sample of the rungs that disagree - not another full
/// climb, which would re-measure six rungs to settle two. The caller
/// averages these into the originals (`conntune::merge_samples`) and
/// re-reads the knee.
///
/// `peak_gbps` is the finished ladder's peak: the article supply has to
/// be sized for the rate these rungs are ALREADY known to reach, or a
/// re-measure starves where the climb did not and reads low, which on
/// this path would manufacture the very dip it was sent to check.
///
/// `ids` is the caller's article supply - REAL-CONTENT articles the
/// target provider is known to hold (design doc 12.1). The synthetic
/// probe group undermeasured a provider 17x, so this function no longer
/// discovers its own.
pub async fn remeasure(
    server: &ServerConfig,
    mut ids: Vec<String>,
    rungs: &[usize],
    peak_gbps: f64,
    secs_per_step: u64,
) -> Result<Vec<LadderStep>, Box<dyn std::error::Error + Send + Sync>> {
    use crate::pool::PoolConfig;
    if ids.is_empty() {
        return Err("no articles to measure with".into());
    }
    let mut out: Vec<LadderStep> = Vec::new();
    for &c in rungs {
        let c = c.clamp(1, 150);
        let want = ladder_supply_for(peak_gbps, c, secs_per_step);
        let per_step = want.min(ids.len());
        let slice: Vec<String> = ids[..per_step].to_vec();
        // Fresh articles per step, so provider-side caching cannot
        // flatter the re-measure the way it would a repeat read.
        let rot = per_step.min(ids.len().saturating_sub(1));
        ids.rotate_left(rot);
        let cfg = PoolConfig {
            connections: c,
            window: 4,
            ..PoolConfig::default()
        };
        let (gbps, per, granted, saturated) =
            timed_fetch_multi(vec![(server.clone(), cfg)], slice, per_step, secs_per_step).await;
        out.push(LadderStep {
            connections: c,
            granted: granted.first().copied().unwrap_or(0),
            gbps,
            bytes: per.first().copied().unwrap_or(0),
            saturated,
        });
    }
    Ok(out)
}

/// M18: per-server connection tuning - ADAPTIVE: keep doubling the
/// socket count (2, 4, 8, … up to `max_conns`) while the previous step
/// still gained ≥12%, so the knee is found wherever it is - including
/// ABOVE the configured account limit (over-asking is harmless: the
/// provider refuses the extras, workers bow out, and `granted` exposes
/// the real ceiling). Distinct article slices per step so provider-side
/// caching can't flatter the later steps.
///
/// `ceiling` is what a job would really be allowed to open on this server
/// (the account limit, already reconciled with the global setting) - NOT
/// the probe cap, which is deliberately higher so the knee can be found
/// above a conservative config value. 0 disables the reopen check.
///
/// `on_progress(phase, conns, steps_so_far)` is called as the ladder
/// works, so a caller can show it happening - and RETURNS false to stop
/// it. The caller owns that decision because the caller owns the reason
/// (a user pressing Cancel, a shutdown); the prober only has to honour
/// it, which it does between rungs. Not mid-rung: a rung is 5-10 s and
/// half of one is a worse number than none, so a cancelled ladder hands
/// back the whole rungs it completed and nothing else. A full run is now minutes
/// long - the climb, a re-race, the bisect, a ceiling check and a
/// best-of-three run-off - and a user watching a spinner for four
/// minutes has no way to tell a working probe from a hung one, nor any
/// sight of the reasoning behind the number it eventually prints. Phases
/// are TOKENS, not sentences: the translation belongs to whoever is
/// displaying them.
///
/// `ids` is the caller's article supply. It must be REAL-CONTENT
/// articles the target provider is known to hold (STAT-checked - see
/// design doc 12.1): the synthetic probe group undermeasured a provider
/// 17x because per-group backends differ, and a supply of missing
/// articles ladders 430s and measures nothing. The rotation below still
/// hands every rung a distinct slice, which is what excludes
/// provider-side caching from the comparison.
pub async fn conn_ladder(
    server: &ServerConfig,
    mut ids: Vec<String>,
    max_conns: usize,
    ceiling: usize,
    secs_per_step: u64,
    mut on_progress: impl FnMut(&str, usize, &[LadderStep]) -> bool,
) -> Result<Vec<LadderStep>, Box<dyn std::error::Error + Send + Sync>> {
    use crate::pool::PoolConfig;
    if ids.is_empty() {
        return Err("no articles to measure with".into());
    }
    let mut out: Vec<LadderStep> = Vec::new();
    let mut c = 2usize;
    let mut stopped_flat = false;
    let supply_for = |peak_gbps: f64, conns: usize| -> usize {
        ladder_supply_for(peak_gbps, conns, secs_per_step)
    };
    loop {
        let c_now = c.min(max_conns.max(2));
        // Checkpoint: a cancel between rungs stops here with whole
        // rungs only.
        if !on_progress("climb", c_now, &out) {
            return Ok(out);
        }
        let peak = out.iter().map(|s| s.gbps).fold(0.0, f64::max);
        let want = supply_for(peak, c_now);
        let per_step = want.min(ids.len());
        let slice: Vec<String> = ids[..per_step].to_vec();
        // Rotate so the next step reads different articles.
        let rot = per_step.min(ids.len().saturating_sub(1));
        ids.rotate_left(rot);
        let cfg = PoolConfig {
            connections: c_now,
            window: 4,
            ..PoolConfig::default()
        };
        let (gbps, per, granted, saturated) =
            timed_fetch_multi(vec![(server.clone(), cfg)], slice, per_step, secs_per_step).await;
        out.push(LadderStep {
            connections: c_now,
            granted: granted.first().copied().unwrap_or(0),
            gbps,
            bytes: per.first().copied().unwrap_or(0),
            saturated,
        });
        // The group didn't yield the supply this step wanted AND the step
        // drained it early: the rate is ramp-biased low, so don't let it
        // masquerade as "the doubling stopped paying".
        let last_starved = saturated && per_step < want;
        if c_now >= max_conns {
            break;
        }
        let n = out.len();
        // Stop once a doubling stopped paying (we've tested one step past
        // the knee), or the provider granted well under what we asked.
        //
        // Keep climbing while a doubling still pays at all - the bar is
        // CLIMB_GAIN, not the 12% it used to be. 12% meant every real
        // gain between 3% and 12% was thrown away and the ladder stopped
        // there, which is not a rounding error on a download: a tester
        // whose 4->8 step gained 8% was stopped at 8 and tuned to 6,
        // while his own timings kept improving out to 36 connections
        // (4 Aug). If the product will not give away 5% at the top, it
        // cannot give away 11% in the middle either.
        //
        // The flat verdict is CONFIRMED before it sticks: one 5 s sample
        // saying "8 conns barely beat 4" can be a transient (evening
        // congestion, a background transfer, macOS timer coalescing on
        // an idle daemon), and a false flat here bisects to a knee that
        // silently caps the user's connections at half their line for a
        // week. Re-race the same step once and keep the better reading;
        // only a dip that reproduces ends the ladder. Field case: a
        // gigabit fibre user tuned to 6 connections and downloaded at
        // half the speed of a 16-connection client.
        if n >= 2 && climb_stalled(out[n - 2].gbps, out[n - 1].gbps, last_starved) {
            if !on_progress("recheck", c_now, &out) {
                return Ok(out);
            }
            let want = supply_for(out.iter().map(|s| s.gbps).fold(0.0, f64::max), c_now);
            let per_step = want.min(ids.len());
            let slice: Vec<String> = ids[..per_step].to_vec();
            let rot = per_step.min(ids.len().saturating_sub(1));
            ids.rotate_left(rot);
            let cfg = PoolConfig {
                connections: c_now,
                window: 4,
                ..PoolConfig::default()
            };
            let (gbps, per, granted, saturated) =
                timed_fetch_multi(vec![(server.clone(), cfg)], slice, per_step, secs_per_step)
                    .await;
            let redo_starved = saturated && per_step < want;
            {
                // The redo's bytes are billed whichever sample wins -
                // both transfers happened.
                let s = &mut out[n - 1];
                s.bytes += per.first().copied().unwrap_or(0);
                if gbps > s.gbps {
                    s.gbps = gbps;
                    s.granted = granted.first().copied().unwrap_or(s.granted);
                    s.saturated = saturated;
                }
            }
            if climb_stalled(out[n - 2].gbps, out[n - 1].gbps, redo_starved) {
                stopped_flat = true;
                break;
            }
            // The dip did not reproduce: the doubling paid after all -
            // keep climbing.
        }
        if out[n - 1].granted + 2 < c_now {
            break;
        }
        c = c_now * 2;
    }
    // Binary refinement: a doubling bracket overshoots the knee by up to
    // 2× (flat at 16 says the knee is anywhere in 8..16). Bisect between
    // the last gaining step and the flat one - up to two 5 s probes -
    // so the recommendation lands near the true knee.
    if stopped_flat && out.len() >= 2 {
        let peak = out.iter().map(|s| s.gbps).fold(0.0, f64::max);
        let (mut lo, mut hi) = (
            out[out.len() - 2].connections,
            out[out.len() - 1].connections,
        );
        for _ in 0..2 {
            if hi.saturating_sub(lo) <= (lo / 4).max(2) {
                break;
            }
            let mid = (lo + hi) / 2;
            if !on_progress("refine", mid, &out) {
                out.sort_by_key(|s| s.connections);
                return Ok(out);
            }
            let per_step = supply_for(peak, mid).min(ids.len());
            let slice: Vec<String> = ids[..per_step].to_vec();
            let rot = per_step.min(ids.len().saturating_sub(1));
            ids.rotate_left(rot);
            let cfg = PoolConfig {
                connections: mid,
                window: 4,
                ..PoolConfig::default()
            };
            let (gbps, per, granted, saturated) =
                timed_fetch_multi(vec![(server.clone(), cfg)], slice, per_step, secs_per_step)
                    .await;
            out.push(LadderStep {
                connections: mid,
                granted: granted.first().copied().unwrap_or(0),
                gbps,
                bytes: per.first().copied().unwrap_or(0),
                saturated,
            });
            if gbps >= peak * 0.9 {
                hi = mid;
            } else {
                lo = mid;
            }
        }
        out.sort_by_key(|s| s.connections);
    }
    // The climb stops on a rung that FAILED to gain, and a rung fails to
    // gain for two very different reasons: the provider really has
    // stopped giving, or that one 5 s sample was interfered with. Every
    // mechanism that mis-measures a rung here reads it LOW - competing
    // traffic, loss, a throttled burst - so the stop condition sits
    // exactly where the noise does its damage, and the error always runs
    // in the slow direction.
    //
    // Which is survivable when the answer lands near the account's
    // ceiling anyway, and not survivable when it lands nowhere near it:
    // a 4-of-50 knee is an enormous claim to make from two 5 s samples,
    // and a tester whose real downloads got faster all the way to 36
    // sockets was handed 6 (4 Aug). So when the climb stops far below
    // what the account allows, ask the ceiling directly before believing
    // it. One probe, and only on ladders that stopped implausibly low.
    if stopped_flat {
        let top = out.iter().map(|s| s.connections).max().unwrap_or(0);
        let peak = out.iter().map(|s| s.gbps).fold(0.0, f64::max);
        // Half the allowance untested is enough to want the check: one
        // probe to confirm beats assuming, and the case this exists for
        // (a climb stopped at 8 on an account allowing 50) is only the
        // extreme end of it.
        if worth_reopening(top, ceiling) {
            let probe = |c: usize, ids: &mut Vec<String>| {
                let per_step = supply_for(peak, c).min(ids.len());
                let slice: Vec<String> = ids[..per_step].to_vec();
                let rot = per_step.min(ids.len().saturating_sub(1));
                ids.rotate_left(rot);
                let cfg = PoolConfig {
                    connections: c,
                    window: 4,
                    ..PoolConfig::default()
                };
                async move {
                    let (gbps, per, granted, saturated) = timed_fetch_multi(
                        vec![(server.clone(), cfg)],
                        slice,
                        per_step,
                        secs_per_step,
                    )
                    .await;
                    LadderStep {
                        connections: c,
                        granted: granted.first().copied().unwrap_or(0),
                        gbps,
                        bytes: per.first().copied().unwrap_or(0),
                        saturated,
                    }
                }
            };
            if !on_progress("ceiling", ceiling, &out) {
                out.sort_by_key(|s| s.connections);
                return Ok(out);
            }
            let high = probe(ceiling, &mut ids).await;
            let won = reopen_won(high.gbps, peak);
            out.push(high);
            let _ = on_progress("ceiling", ceiling, &out);
            // It won, so the climb ended on noise rather than on a
            // ceiling - and the knee is now somewhere in a bracket
            // nothing has measured. Bisect it like the doubling's own
            // overshoot, so the answer is not simply "use all of them".
            if won {
                let (mut lo, mut hi) = (top, ceiling);
                for _ in 0..2 {
                    if hi.saturating_sub(lo) <= (lo / 4).max(2) {
                        break;
                    }
                    let mid = (lo + hi) / 2;
                    let step = probe(mid, &mut ids).await;
                    let gained =
                        step.gbps >= peak.max(out.last().map(|s| s.gbps).unwrap_or(0.0)) * 0.9;
                    out.push(step);
                    if gained {
                        hi = mid;
                    } else {
                        lo = mid;
                    }
                }
            }
            out.sort_by_key(|s| s.connections);
        }
    }
    // Run-off. Whoever wins the ladder wins it on ONE 5 s sample, and the
    // sample-to-sample spread on a domestic line is far wider than the
    // 2% the selection rule now cares about - so without this, tightening
    // that rule would only have bought a more confident way of picking
    // the luckiest reading. Everything within RUNOFF_BAND of the best
    // gets a second look at double the window, and the better of a rung's
    // two readings stands (noise here is subtractive: contention, loss
    // and a drained supply all read LOW, and nothing reads high).
    //
    // Capped at RUNOFF_MAX rungs, so the cost is bounded at a few tens of
    // seconds on a probe that runs once per provider per week.
    let peak = out.iter().map(|s| s.gbps).fold(0.0, f64::max);
    if peak > 0.0 && out.len() > 1 {
        let mut cands: Vec<usize> = out
            .iter()
            .filter(|s| s.gbps >= peak * RUNOFF_BAND)
            .map(|s| s.connections)
            .collect();
        // Highest rungs first when there are more than we will pay for:
        // the top of the curve is where the decision actually is.
        cands.sort_unstable_by(|a, b| b.cmp(a));
        cands.truncate(RUNOFF_MAX);
        if cands.len() > 1 {
            // Each candidate is re-raced RUNOFF_ROUNDS times, not once.
            // One extra sample per rung narrows nothing: it still leaves
            // every candidate represented by a single best-of-two, and
            // two best-of-twos of the SAME rate still disagree by about
            // the spread that made the ladder unreliable in the first
            // place. Alternating the rungs round by round rather than
            // finishing one before starting the next also means a slow
            // patch part-way through the run-off lands on all of them
            // instead of ruining whichever candidate owned that minute.
            for round in 0..RUNOFF_ROUNDS {
                for &c in &cands {
                    if !on_progress(if round == 0 { "runoff" } else { "runoff2" }, c, &out) {
                        return Ok(out);
                    }
                    let want = ladder_supply_for(peak, c, secs_per_step * 2).min(ids.len());
                    let slice: Vec<String> = ids[..want].to_vec();
                    let rot = want.min(ids.len().saturating_sub(1));
                    ids.rotate_left(rot);
                    let cfg = PoolConfig {
                        connections: c,
                        window: 4,
                        ..PoolConfig::default()
                    };
                    let (gbps, per, granted, saturated) = timed_fetch_multi(
                        vec![(server.clone(), cfg)],
                        slice,
                        want,
                        secs_per_step * 2,
                    )
                    .await;
                    if let Some(s) = out.iter_mut().find(|s| s.connections == c) {
                        // Bytes SUM (both transfers happened and the ledger is
                        // owed them); the rate is the better reading.
                        s.bytes = s.bytes.saturating_add(per.first().copied().unwrap_or(0));
                        s.granted = s.granted.max(granted.first().copied().unwrap_or(0));
                        if gbps.is_finite() && gbps > s.gbps {
                            s.gbps = gbps;
                            s.saturated = saturated;
                        }
                    }
                }
            }
        }
    }
    Ok(out)
}

/// The whole-system verdict.
#[derive(serde::Serialize)]
pub struct SystemReport {
    pub network_gbps: f64,
    /// The compute ceiling under the ACTIVE verify mode - this is what
    /// bounds `expected_gbps` and draws the compute bar. Equals
    /// `compute_fast_gbps` when fast verify is on (the shipped
    /// default) and `compute_full_gbps` when it is off.
    pub compute_gbps: f64,
    /// All-core ceiling with full MD5+CRC32 verify (fast verify off).
    pub compute_full_gbps: f64,
    /// All-core ceiling with CRC32-only verify (fast verify on). The
    /// pair exists so a reader can see what fast verify actually buys
    /// on their box, whichever mode is active (TODO §10).
    pub compute_fast_gbps: f64,
    pub disk_gbps: f64,
    pub bottleneck: String,
    /// Expected sustained download speed = min of the three.
    pub expected_gbps: f64,
    pub advice: String,
    /// What the network figure was actually measured over: the provider
    /// it pulled from and how many connections it opened. Without these
    /// the row reads as a line-speed test and gets compared against one
    /// (issue #12) - it is neither. Empty/0 when the caller does not
    /// know, so the UI simply omits the qualifier.
    #[serde(skip_serializing_if = "String::is_empty")]
    pub network_host: String,
    #[serde(skip_serializing_if = "is_zero")]
    pub network_conns: usize,
    /// TODO 210 item (b): the machine's own network link, named when it
    /// is what the network figure ran into. The row is a download over
    /// N connections and cannot say WHICH network is short, so on a
    /// Wi-Fi machine at its access point's ceiling the advice below
    /// ("more connections or another provider may raise it") sends the
    /// reader somewhere that cannot help. Empty unless the caller holds
    /// a link observation AND the measurement reached its ceiling -
    /// filled in by the daemon, which is the side that probes the link
    /// (`measured_note` in `crates/nzbfast/src/serve/locallink.rs`).
    #[serde(skip_serializing_if = "String::is_empty")]
    pub network_link: String,
}

fn is_zero(n: &usize) -> bool {
    *n == 0
}

/// `fast_verify` is the mode a real download would actually run under -
/// pass the daemon's live `fast_verify` setting (or the shipped default,
/// `true`, when there is no daemon to ask). It decides which of
/// `compute.ceiling_gbps` / `compute.fast_ceiling_gbps` is the real
/// compute ceiling; both are reported on `SystemReport` regardless, so
/// the caller can show what the OTHER mode would buy.
pub fn verdict(
    network_gbps: f64,
    compute: &ComputeReport,
    disk_gbps: f64,
    fast_verify: bool,
) -> SystemReport {
    let n = network_gbps;
    let c = if fast_verify {
        compute.fast_ceiling_gbps
    } else {
        compute.ceiling_gbps
    };
    let d = disk_gbps * 8.0;
    let expected = n.min(c).min(d);
    let (bottleneck, advice) = if expected == n {
        (
            "network",
            // Name NO hardware here. "Move to a faster link (2.5/10 GbE)"
            // shipped until 20 Aug 2026 and it is bad advice twice over: on
            // many streets that service cannot be bought at any price, and
            // where it can it is a real expense to raise a number that is not
            // broken. Saying a faster connection is the ceiling is true and
            // worth saying; naming the product is what makes it useless.
            // Do not reintroduce a speed, a standard, or a price - and do not
            // add "if you can afford it" either, which only makes the same
            // suggestion sound worse.
            //
            // The order is load-bearing. This row is a real Usenet download
            // over N connections, not a line-speed test, so a low figure has
            // two causes and the reader cannot tell them apart from the bar:
            // the line, or too few connections to fill it. Connections and
            // providers come first because they are free and because trying
            // them is what DISTINGUISHES the two cases. Only once they fail
            // to move it has the line been shown to be the ceiling.
            "The network is your limit. More connections or another provider \
             may raise it. If they do not, this is what your connection \
             delivers, and only a faster one will beat it. Compute and disk \
             have headroom."
                .to_string(),
        )
    } else if expected == c {
        (
            "compute",
            // Rare - only on very fast links, which is why the advice
            // spells out where the setting lives rather than assuming
            // the reader has seen it. `fast_verify` has shipped, DEFAULT
            // ON, since 21 Jul 2026 (TODO §10) - so the common case on
            // this branch is ALREADY running the fast ceiling, and the
            // old text ("a CRC32-only fast-verify mode would raise it")
            // described a feature the reader already had turned on.
            if fast_verify {
                format!(
                    "CPU verification is your limit ({:.0} Gbps), even with fast \
                     verify (CRC32-only block checks) already on - full MD5 \
                     verify would be {:.0} Gbps. Rare - only on very fast links. \
                     Only a faster CPU raises it further.",
                    c, compute.ceiling_gbps
                )
            } else if compute.fast_ceiling_gbps > compute.ceiling_gbps {
                format!(
                    "CPU verification is your limit ({:.0} Gbps). Rare - only \
                     on very fast links. Turn on \"Checking while downloading: \
                     fast\" in Settings to raise it to {:.0} Gbps, or use a \
                     faster CPU.",
                    c, compute.fast_ceiling_gbps
                )
            } else {
                // THAT ORDERING IS A PROPERTY OF THE KERNELS AND NOT OF THE
                // BOX - the full-verify stage hashes each chunk with MD5 and
                // then CRC32s the same chunk, so it does strictly more work
                // than the CRC32-only stage - but the two ceilings reaching
                // here are LIVE MEASUREMENTS, and a measurement can come out
                // the other way on a loaded machine. Measured on the dev Mac
                // on 27 Aug 2026 under artificial load: the full-verify stage
                // timed FASTER than MD5 alone in two runs of three, which is
                // structurally impossible, so the estimator demonstrably
                // inverts its own orderings when the box is busy. Recommending
                // a setting on the strength of such a reading would advertise
                // fast verify as a speed-up that slows the box down, which is
                // the one thing this pair of ceilings must never say. So the
                // RECOMMENDATION is withheld and the reading is reported as
                // what it is. The `fast_verify` arm above needs no such guard:
                // it quotes both measured figures and recommends nothing.
                //
                // This is the guard that `sysbench::tests` used to carry as a
                // live assertion on `compute(16)`, where it was really
                // asserting the test runner was fast; it reddened CI on
                // 27 Aug 2026 (run 33035356437). It belongs here, on the
                // stated numbers a user's own inverted measurement would
                // reach, and it is tested on a fixture in
                // `compute_advice_matches_the_fast_verify_state`.
                format!(
                    "CPU verification is your limit ({:.0} Gbps). Rare - only \
                     on very fast links. This run did not measure fast verify \
                     (CRC32-only block checks) as any quicker here ({:.0} \
                     Gbps), so only a faster CPU raises it.",
                    c, compute.fast_ceiling_gbps
                )
            },
        )
    } else {
        (
            "disk",
            format!(
                "Disk write is your limit ({:.1} GB/s). Use an NVMe/SSD \
                 target, or a faster volume; network and CPU have headroom.",
                disk_gbps
            ),
        )
    };
    SystemReport {
        network_gbps: n,
        compute_gbps: c,
        compute_full_gbps: compute.ceiling_gbps,
        compute_fast_gbps: compute.fast_ceiling_gbps,
        disk_gbps: d,
        bottleneck: bottleneck.to_string(),
        expected_gbps: expected,
        advice,
        // Filled in by the caller, which is the one that knows what it
        // pointed the probe at - and, for the link, what carries it.
        network_host: String::new(),
        network_conns: 0,
        network_link: String::new(),
    }
}

// ---------------------------------------------------------------------------
// Server diversity / overlap detector
// ---------------------------------------------------------------------------

/// Per-server result of the overlap sweep.
#[derive(Clone, serde::Serialize)]
pub struct ServerProbe {
    pub host: String,
    pub(crate) connect_ok: bool,
    pub rtt_ms: f64,
    /// Fraction of the shared sample this server HAD (0..1).
    pub availability: f64,
    /// Solo download rate, Gbps (short probe).
    pub speed_gbps: f64,
    /// Raw bytes the speed probe transferred (for the usage ledger).
    pub bytes: u64,
}

/// One pair's infra-overlap score.
#[derive(Clone, serde::Serialize)]
pub struct OverlapPair {
    pub a: String,
    pub b: String,
    /// Jaccard similarity of the two servers' MISSING-article sets over
    /// the shared sample (1.0 = identical gaps = same backbone).
    pub missing_jaccard: f64,
    /// Correlation verdict for the UI.
    pub verdict: String,
}

#[derive(serde::Serialize)]
pub struct DiversityReport {
    pub servers: Vec<ServerProbe>,
    pub pairs: Vec<OverlapPair>,
    pub recommendation: String,
}

/// Jaccard similarity of two servers' MISSING sets, over the first
/// `common` positions only. `None` when there is nothing both answered.
///
/// `common` is the crux. A sweep that resets, times out or fails to flush
/// leaves the rest of its vector `false`, and `false` there means UNKNOWN,
/// not missing. Comparing the whole sample let two unrelated providers
/// that each answered five of 100 requests and then reset look like they
/// shared the same 95 gaps - a near-1.0 overlap, a "SAME infra" verdict
/// and a "keep only one, add another backbone" recommendation drawn from
/// nothing at all (Codex sweep 12 Aug F15).
fn missing_jaccard(a: &[bool], b: &[bool], common: usize) -> Option<f64> {
    let common = common.min(a.len()).min(b.len());
    if common == 0 {
        return None;
    }
    let (mut inter, mut union) = (0usize, 0usize);
    for k in 0..common {
        let (mi, mj) = (!a[k], !b[k]);
        if mi || mj {
            union += 1;
        }
        if mi && mj {
            inter += 1;
        }
    }
    Some(if union == 0 {
        0.0
    } else {
        inter as f64 / union as f64
    })
}

/// STAT a shared article sample on every server; per-server availability
/// vectors reveal which providers share infrastructure (identical gaps).
///
/// `sample_ids` should span a range of ages (recent + old) so takedowns
/// and retention differences actually show up. Returns a per-server
/// present/absent bit vector alongside the probes.
pub async fn diversity(
    servers: &[ServerConfig],
    sample_ids: &[String],
    group: &str,
) -> DiversityReport {
    let _ = group; // speed probes reuse the shared sample now
    // Phase 1: STAT sweeps run CONCURRENTLY - they're latency-bound and
    // independent, so wall time is the slowest server, not the sum (the
    // sequential version blew the API's 60 s cap on slow links).
    let t_sweeps = Instant::now();
    // collect() eagerly: a lazy map would spawn each sweep only when the
    // join loop reaches it - sequential again.
    let sweeps: Vec<_> = servers
        .iter()
        .map(|s| {
            let s = s.clone();
            let ids: Vec<String> = sample_ids.to_vec();
            tokio::spawn(async move {
                let n = ids.len();
                // Whole-sweep hard cap: send/flush have no per-op timeouts, so
                // one black-holed connection would otherwise hang its task (and
                // the whole report) forever.
                let swept = tokio::time::timeout(Duration::from_secs(45), async move {
                    let t0 = Instant::now();
                    let mut vec = vec![false; ids.len()];
                    let mut connect_ok = false;
                    let mut rtt = 0.0;
                    let mut had = 0usize;
                    // How many of the sample the server ANSWERED. A sweep
                    // that resets, times out or fails to flush leaves the
                    // rest of `vec` false, and false has to mean "unknown"
                    // there rather than "missing" (Codex sweep 12 Aug F15).
                    let mut answered = 0usize;
                    if let Ok(Ok((mut conn, _))) =
                        tokio::time::timeout(Duration::from_secs(12), Connection::connect(&s)).await
                    {
                        connect_ok = true;
                        rtt = t0.elapsed().as_secs_f64() * 1000.0;
                        // Pipelined STAT sweep.
                        let window = 40usize;
                        let mut sent = 0;
                        let mut recv = 0;
                        'sweep: while recv < ids.len() {
                            while sent < ids.len() && sent - recv < window {
                                if conn.send_stat(&ids[sent]).await.is_err() {
                                    break 'sweep;
                                }
                                sent += 1;
                            }
                            if conn.flush().await.is_err() {
                                break;
                            }
                            // `read_stat_checked`, never `read_stat`:
                            // `vec[recv]` files this reply POSITIONALLY,
                            // so one lost reply upstream would shift
                            // every later verdict by one slot. A
                            // mismatch breaks the sweep, which leaves
                            // `answered` short - and everything past it
                            // reads as unknown rather than as missing
                            // (Codex sweep 12 Aug F15). A server that
                            // echoes no id at all still passes.
                            let expected = ids[recv].as_str();
                            match tokio::time::timeout(
                                Duration::from_secs(20),
                                conn.read_stat_checked(Some(expected)),
                            )
                            .await
                            {
                                Ok(Ok(has)) => {
                                    vec[recv] = has;
                                    if has {
                                        had += 1;
                                    }
                                    recv += 1;
                                }
                                _ => break,
                            }
                        }
                        conn.quit().await;
                        answered = recv;
                    }
                    (connect_ok, rtt, had, vec, answered)
                })
                .await;
                swept.unwrap_or((false, 0.0, 0, vec![false; n], 0))
            })
        })
        .collect();
    let mut sweep_results = Vec::new();
    for h in sweeps {
        sweep_results.push(
            h.await
                .unwrap_or((false, 0.0, 0, vec![false; sample_ids.len()], 0)),
        );
    }
    info!(
        target: "diversity",
        "STAT sweeps done in {:.1}s ({} servers × {} ids)",
        t_sweeps.elapsed().as_secs_f64(),
        servers.len(),
        sample_ids.len()
    );

    // Phase 2: short solo speed probes, SEQUENTIAL so they don't contend
    // for the line, fetching from the shared sample this server was just
    // seen to HAVE (no per-server OVER discovery - that alone used to
    // cost more than the probe).
    let t_probes = Instant::now();
    let mut probes = Vec::new();
    let mut present: Vec<Vec<bool>> = Vec::new(); // [server][article] = had it
    // How far into `present[i]` that server's answers actually reach.
    let mut answered: Vec<usize> = Vec::new();
    for (s, (connect_ok, rtt, had, vec, got)) in servers.iter().zip(sweep_results) {
        let (speed, probe_bytes) = if connect_ok {
            let have: Vec<String> = sample_ids
                .iter()
                .zip(&vec)
                .filter(|&(_, &h)| h)
                .map(|(id, _)| id.clone())
                .collect();
            if have.is_empty() {
                (0.0, 0)
            } else {
                timed_fetch(s, have, 8, 4).await
            }
        } else {
            (0.0, 0)
        };
        probes.push(ServerProbe {
            host: s.host.clone(),
            connect_ok,
            rtt_ms: rtt,
            // Over what was ANSWERED, not over the sample. Dividing by the
            // full sample turned an interrupted sweep into a low
            // availability figure for a provider that had everything it was
            // asked about.
            availability: had as f64 / got.max(1) as f64,
            speed_gbps: speed,
            bytes: probe_bytes,
        });
        present.push(vec);
        answered.push(got);
    }
    info!(
        target: "diversity",
        "speed probes done in {:.1}s",
        t_probes.elapsed().as_secs_f64()
    );

    // Pairwise MISSING-set Jaccard: over the shared sample, articles this
    // server lacked. High overlap of gaps ⇒ same infra.
    let mut pairs = Vec::new();
    for i in 0..servers.len() {
        for j in (i + 1)..servers.len() {
            if !probes[i].connect_ok || !probes[j].connect_ok {
                continue;
            }
            let Some(jac) = missing_jaccard(&present[i], &present[j], answered[i].min(answered[j]))
            else {
                continue;
            };
            let verdict = if jac >= 0.8 {
                "SAME infra - redundant for recovery (share takedowns/gaps)"
            } else if jac >= 0.4 {
                "partial overlap - some shared backbone"
            } else {
                "diverse - independent gaps, good recovery pairing"
            };
            pairs.push(OverlapPair {
                a: servers[i].host.clone(),
                b: servers[j].host.clone(),
                missing_jaccard: jac,
                verdict: verdict.to_string(),
            });
        }
    }

    // Recommendation: flag redundant clusters, praise diversity.
    let redundant: Vec<String> = pairs
        .iter()
        .filter(|p| p.missing_jaccard >= 0.8)
        .map(|p| format!("{} ≈ {}", p.a, p.b))
        .collect();
    let recommendation = if redundant.is_empty() {
        "Your providers have diverse infrastructure - good article recovery \
         coverage. Keep them all."
            .to_string()
    } else {
        format!(
            "Redundant (same backbone, won't help recover each other's \
             missing articles): {}. For maximum recovery, keep one of each \
             cluster and add a provider on a different backbone.",
            redundant.join(", ")
        )
    };

    DiversityReport {
        servers: probes,
        pairs,
        recommendation,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// MB/s -> Gbps, so these read like the dashboard.
    fn r(mbps: f64) -> f64 {
        mbps * 8.0 / 1000.0
    }

    /// The reported field case, at the exact step that decided it: 4
    /// connections read 25 MB/s and 8 read 27. Under the old 12% rule
    /// that 8% gain was "the doubling stopped paying", the climb ended
    /// at 8, and the bisect answered 6 - on an account allowing 50,
    /// while the user's own timings kept improving out to 36 sockets.
    #[test]
    fn an_eight_percent_gain_is_a_gain() {
        assert!(
            !climb_stalled(r(25.0), r(27.0), false),
            "8% is real speed and the climb must continue for it"
        );
        for (prev, cur) in [(25.0, 26.0), (25.0, 28.0), (100.0, 104.0)] {
            assert!(
                !climb_stalled(r(prev), r(cur), false),
                "{prev} -> {cur} MB/s is a real gain"
            );
        }
    }

    /// It still has to STOP, or every ladder runs to the ceiling and
    /// costs a fortune to learn nothing.
    #[test]
    fn a_flat_rung_still_stops_the_climb() {
        assert!(climb_stalled(r(30.0), r(30.5), false), "under 3% is flat");
        assert!(climb_stalled(r(30.0), r(20.0), false), "a drop is flat");
        assert!(climb_stalled(r(30.0), r(30.0), false), "no change is flat");
    }

    /// A step that ran out of articles reads low for a reason that has
    /// nothing to do with sockets, and must never end the climb.
    #[test]
    fn a_starved_step_never_ends_the_climb() {
        assert!(
            !climb_stalled(r(30.0), r(2.0), true),
            "a drained supply is not a knee"
        );
    }

    /// Over half the allowance untested is worth one confirming probe -
    /// exactly the shape the field case had (stopped at 8, allowed 50).
    #[test]
    fn a_climb_that_stopped_low_gets_checked_against_the_ceiling() {
        assert!(worth_reopening(8, 50), "8 of 50 must be checked");
        assert!(worth_reopening(4, 20));
        assert!(!worth_reopening(16, 20), "close to the ceiling: trust it");
        assert!(!worth_reopening(30, 50));
        assert!(!worth_reopening(8, 0), "no ceiling, nothing to check");
    }

    /// The ceiling probe reopens the climb only when it wins by the same
    /// margin the climb itself needs - otherwise a tie at the top turns
    /// every ladder into a march to the ceiling.
    #[test]
    fn the_ceiling_only_wins_by_a_real_margin() {
        assert!(reopen_won(r(50.0), r(37.0)), "50 vs 37 is a real win");
        assert!(!reopen_won(r(37.5), r(37.0)), "a tie is not a win");
        assert!(!reopen_won(r(20.0), r(37.0)), "slower is not a win");
    }

    /// `compute()` BENCHMARKS THE MACHINE IT RUNS ON, so a test over its
    /// output may assert only what a noisy box cannot break: the shape of the
    /// report, and the arithmetic that derives the two ceilings from the
    /// stage rates. It may not assert a performance ORDERING.
    ///
    /// It used to assert two of them - `decode_simd > md5`, and, through the
    /// ceilings, `crc32 > verify`. The second inverted on a loaded CI runner
    /// on 27 Aug 2026 (run 33035356437, main `7212ad8c9`) and failed
    /// `unit-one-process`, which is one of only two places in this system
    /// that can see the process-global-state class. Five later pushes then
    /// carried a failed run, because the job that reports main red is itself
    /// a job that can go red. Nobody fixed anything; it cleared on its own.
    /// That is the mistake `verdict_picks_min` below was converted away from,
    /// one test along, for the same reason in the same file: it was asserting
    /// the host was fast, not that the code was right.
    ///
    /// NO TOLERANCE RESCUES A LIVE ORDERING HERE, which is why one is not
    /// offered. A preempted thread loses an unbounded amount of wall time, so
    /// a measured rate has no lower bound to write a margin against - and the
    /// nominal margin is not the protection it looks like. Measured on the dev
    /// Mac under artificial load on 27 Aug 2026, `verify` timed FASTER than
    /// `md5` alone in two runs of three, an ordering that is structurally
    /// impossible: `verify` hashes each chunk with MD5 and then CRC32s the
    /// same chunk, so it always does strictly more work. An estimator that
    /// inverts a relationship it cannot possibly have is not one to assert
    /// orderings from.
    ///
    /// What that ordering was FOR - that fast verify is a speed-up rather
    /// than a slow-down - now lives where it can be tested exactly and where
    /// an inverted measurement would actually reach a user: `verdict` refuses
    /// to recommend the setting when the pair of ceilings does not support
    /// it, asserted on stated numbers in
    /// `compute_advice_matches_the_fast_verify_state`.
    #[test]
    fn compute_report_is_sane() {
        let r = compute(16);
        assert!(r.cores >= 1);
        for (name, s) in [
            ("decode_simd", r.decode_simd),
            ("crc32", r.crc32),
            ("md5", r.md5),
            ("verify", r.verify),
        ] {
            assert!(
                s.one_core.is_finite() && s.one_core > 0.0,
                "{name} one_core is {}",
                s.one_core
            );
            assert!(
                s.all_core.is_finite() && s.all_core > 0.0,
                "{name} all_core is {}",
                s.all_core
            );
        }
        assert!(r.ceiling_gbps.is_finite() && r.ceiling_gbps > 0.0);
        assert!(r.fast_ceiling_gbps.is_finite() && r.fast_ceiling_gbps > 0.0);
        // The derivation, which is the part with no timing in it: the full
        // ceiling is the MD5+CRC32 `verify` stage and the fast one is the
        // CRC32-only stage, each converted GB/s to Gbps. Holding the report
        // against its OWN stage rates rather than against a threshold is what
        // makes this noise-proof - both sides move together however slow the
        // box is - and `* 8.0` is exact in binary floating point, so equality
        // is the right test here rather than an epsilon.
        //
        // This is what catches the mistake that matters: the two stages wired
        // to the wrong ceilings. It catches it whenever the two measurements
        // differ, which two timings of different work always do. Note the
        // polarity - bit-equal stage rates would let a swap through, and can
        // never produce a FAILURE - so this assertion has no flake in it.
        assert_eq!(r.ceiling_gbps, r.verify.all_core * 8.0);
        assert_eq!(r.fast_ceiling_gbps, r.crc32.all_core * 8.0);
    }

    #[test]
    fn disk_write_measures() {
        let d = std::env::temp_dir();
        let gbps = disk_write(&d, 64).unwrap();
        assert!(gbps > 0.0 && gbps < 1000.0);
    }

    /// `verdict` is arithmetic - it picks the min of three numbers - so the
    /// compute figure is STATED here, not measured.
    ///
    /// It used to call `compute(16)`, which benchmarks this machine for real,
    /// and the test then assumed the answer would land above the 1.0 Gbps
    /// network figure it was comparing against. On a debug build that is not
    /// a safe assumption: the compute kernels are unoptimized, and on Windows
    /// x64 the measured ceiling came in UNDER 1.0, so `verdict` correctly
    /// answered "compute" and the test called it a failure. It was asserting
    /// the host was fast, not that the min-picking works. A stated ceiling
    /// tests the logic on every machine and takes ~16 MB of benchmarking per
    /// run out of the suite.
    #[test]
    fn verdict_picks_min() {
        let flat = StageRate {
            one_core: 1.0,
            all_core: 8.0,
        };
        // Two distinct ceilings, exactly as the real `compute()` reports:
        // full MD5+CRC verify is the SLOWER one, CRC32-only fast verify
        // the faster one - `fast_ceiling_gbps` keeps the value the
        // pre-existing assertions below already expected (40.0), so the
        // fixture change is additive rather than a silent re-derivation.
        let c = ComputeReport {
            cores: 8,
            decode_simd: flat,
            crc32: flat,
            md5: flat,
            verify: flat,
            ceiling_gbps: 20.0,
            fast_ceiling_gbps: 40.0,
        };
        // Network tiny → network is the bottleneck.
        let v = verdict(1.0, &c, 5.0, true);
        assert_eq!(v.bottleneck, "network");
        assert!((v.expected_gbps - 1.0).abs() < 1e-9);
        // Disk tiny (0.05 GB/s = 0.4 Gbps) → disk bottleneck.
        let v = verdict(50.0, &c, 0.05, true);
        assert_eq!(v.bottleneck, "disk");
        // ...and compute when it is genuinely the floor, which the measured
        // version could never pin because it did not know its own value.
        // fast_verify=true picks fast_ceiling_gbps (40.0), not ceiling_gbps.
        let v = verdict(50.0, &c, 100.0, true);
        assert_eq!(v.bottleneck, "compute");
        assert!((v.expected_gbps - 40.0).abs() < 1e-9);
        assert!((v.compute_gbps - 40.0).abs() < 1e-9);
        assert!((v.compute_fast_gbps - 40.0).abs() < 1e-9);
        assert!((v.compute_full_gbps - 20.0).abs() < 1e-9);
        // fast_verify=false picks ceiling_gbps (20.0) instead.
        let v = verdict(50.0, &c, 100.0, false);
        assert_eq!(v.bottleneck, "compute");
        assert!((v.expected_gbps - 20.0).abs() < 1e-9);
        assert!((v.compute_gbps - 20.0).abs() < 1e-9);
    }

    /// The compute advice names the real setting and its actual state,
    /// instead of describing fast verify as hypothetical - TODO §10's
    /// last unticked box. Both directions: on (the shipped default),
    /// the advice must say so and must NOT claim a faster mode is
    /// available to turn on; off, it must name where to turn it on.
    #[test]
    fn compute_advice_matches_the_fast_verify_state() {
        let flat = StageRate {
            one_core: 1.0,
            all_core: 8.0,
        };
        let c = ComputeReport {
            cores: 8,
            decode_simd: flat,
            crc32: flat,
            md5: flat,
            verify: flat,
            ceiling_gbps: 20.0,
            fast_ceiling_gbps: 40.0,
        };
        let on = verdict(50.0, &c, 100.0, true);
        assert_eq!(on.bottleneck, "compute");
        assert!(
            on.advice.contains("already on"),
            "advice must say fast verify is already on: {}",
            on.advice
        );
        assert!(
            !on.advice.contains("would raise it"),
            "the on-state advice must not offer fast verify as an unactivated fix: {}",
            on.advice
        );

        let off = verdict(50.0, &c, 100.0, false);
        assert_eq!(off.bottleneck, "compute");
        assert!(
            off.advice.contains("Checking while downloading"),
            "advice must name the setting by its dashboard label: {}",
            off.advice
        );
        assert!(
            off.advice.contains(&format!("{:.0}", c.fast_ceiling_gbps)),
            "off-state advice must quote the fast-verify ceiling it promises: {}",
            off.advice
        );

        // AND THE INVERTED PAIR, which is this test's half of the guard
        // `compute_report_is_sane` used to carry as a live assertion on a real
        // benchmark. The two ceilings are measured, so on a loaded box the
        // CRC32-only figure can come out at or below the MD5+CRC32 one even
        // though the kernel does strictly less work - the same estimator was
        // measured inverting a structurally impossible ordering on the dev Mac
        // on 27 Aug 2026, and inverting THIS one on a CI runner the same day.
        // When it does, the off-state advice must not tell the reader to turn
        // a setting on to reach a number below the one they already have.
        // Stated numbers, so this bites on every machine and every build
        // profile, which is exactly what the live version could not do.
        for (full, fast) in [(40.0, 20.0), (40.0, 40.0)] {
            let inverted = ComputeReport {
                cores: 8,
                decode_simd: flat,
                crc32: flat,
                md5: flat,
                verify: flat,
                ceiling_gbps: full,
                fast_ceiling_gbps: fast,
            };
            let off = verdict(50.0, &inverted, 100.0, false);
            assert_eq!(off.bottleneck, "compute");
            assert!(
                !off.advice.contains("Turn on"),
                "must not recommend fast verify when it did not measure faster \
                 (full {full}, fast {fast}): {}",
                off.advice
            );
            assert!(
                !off.advice.contains("raise it to"),
                "must not promise a raise it cannot deliver (full {full}, fast \
                 {fast}): {}",
                off.advice
            );
            assert!(
                off.advice.contains("faster CPU"),
                "the remaining advice is still owed to the reader (full {full}, \
                 fast {fast}): {}",
                off.advice
            );
        }
    }

    /// Regression (East Coast bench box, 5 Gbps): a fixed article supply drained in
    /// well under the timing window and the rate was still divided by the
    /// FULL window - sysbench reported "0.24 Gbps, network is your limit"
    /// on a path that does 3+ Gbps, and every connladder step read the
    /// same per-conn rate. When the queue runs dry early, the clock must
    /// stop at the last completion and the step must be flagged.
    #[tokio::test(flavor = "multi_thread")]
    async fn exhausted_supply_measures_actual_transfer_time() {
        let mut articles = std::collections::HashMap::new();
        let data: Vec<u8> = (0..400_000u32).map(|i| i as u8).collect();
        let segs = crate::mock::make_file_articles("t.bin", &data, 20_000, "sb", &mut articles);
        let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let cfg = crate::pool::PoolConfig {
            connections: 2,
            window: 4,
            ramp_delay: Duration::from_millis(0),
            ..Default::default()
        };
        const WINDOW: u64 = 30; // loopback drains the supply in ms
        let t0 = Instant::now();
        let (gbps, per, _granted, exhausted) =
            timed_fetch_multi(vec![(srv.server_config(), cfg)], ids, usize::MAX, WINDOW).await;
        let took = t0.elapsed();
        assert!(exhausted, "tiny supply must be flagged exhausted");
        assert!(
            took < Duration::from_secs(WINDOW / 2),
            "must return when the queue drains, not sleep out the window (took {took:?})"
        );
        // The old bug: bytes / full-window. The fix must beat that cap by
        // a wide margin because the drain took milliseconds, not 30 s.
        let capped = per[0] as f64 * 8.0 / 1e9 / WINDOW as f64;
        assert!(
            gbps > capped * 10.0,
            "rate must reflect actual drain time, not the window ({gbps} vs capped {capped})"
        );
    }

    /// TODO 312 item 3: the granted count must survive a rung that
    /// drains before a sampler could tick.
    ///
    /// This is the SAME loopback fixture as
    /// `exhausted_supply_measures_actual_transfer_time` above - a
    /// handful of small articles served unpaced, gone in milliseconds -
    /// and it is the cheapest deterministic reproduction of the defect
    /// there is. Under the old 100 ms sampler this reported `granted: 1`
    /// for a fleet of six, because the whole transfer fitted inside the
    /// sampler's first tick; the daemon carry probe had to PACE its mock
    /// at 12 MB/s a connection just to keep two of its assertions
    /// falsifiable (see `TEE_BPS` in `daemon_carry`).
    ///
    /// Asserting MORE THAN ONE, and the reason it is not the whole fleet
    /// is written out at the assertion itself: the fleet size a ramp
    /// reaches inside a drain this fast is a property of the box, not of
    /// the product, and asserting it made this test fail on Windows with
    /// two different numbers. Anything above 1 is what the sampler could
    /// not support at any tick rate, and that is the point of moving the
    /// recording to the increment site.
    #[tokio::test(flavor = "multi_thread")]
    async fn granted_sees_the_whole_fleet_on_a_rung_that_drains_at_once() {
        const CONNS: usize = 6;
        let mut articles = std::collections::HashMap::new();
        let data: Vec<u8> = (0..400_000u32).map(|i| i as u8).collect();
        let segs = crate::mock::make_file_articles("g.bin", &data, 20_000, "gr", &mut articles);
        let srv = crate::mock::MockServer::start(articles, crate::mock::Chaos::default()).await;
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let cfg = crate::pool::PoolConfig {
            connections: CONNS,
            window: 4,
            ramp_delay: Duration::from_millis(0),
            ..Default::default()
        };
        let t0 = Instant::now();
        let (_gbps, _per, granted, exhausted) =
            timed_fetch_multi(vec![(srv.server_config(), cfg)], ids, usize::MAX, 30).await;
        let took = t0.elapsed();
        assert!(exhausted, "the supply must drain inside the window");
        // The condition that makes this test about the defect at all. If
        // a future box is slow enough that the run outlives a 100 ms
        // sampler tick, the assertion below would pass under the old
        // code too and would be pinning nothing.
        assert!(
            took < Duration::from_millis(400),
            "this fixture must drain faster than the sampler this replaced              could ever have seen a fleet through (took {took:?})"
        );
        // WHY THIS IS `>= 2` AND NOT `== CONNS`, since the block above
        // argues at length for the whole fleet and that argument is half
        // right. It is right about the MECHANISM: recording at the
        // increment site is what makes any number above 1 reachable, and
        // a sampler cannot report one at any tick rate on a fixture that
        // drains this fast. It is wrong about the FIXTURE, because "every
        // one of these workers dials before it looks for work" is a race
        // and not a guarantee - the supply is 20 small articles and the
        // first workers to connect can drain it before the last ones
        // finish dialling. So a fleet of six is what we ASK for, never
        // what a box must grant inside the drain.
        //
        // Measured, not reasoned: windows-unit shard 2 of run
        // 33221261870 failed BOTH attempts of this test, reporting 5 on
        // one and 3 on the other. Two different numbers is the signature
        // of a race, and neither is a defect - `granted` was correctly
        // reporting a peak that really was 5, then really was 3. The
        // sibling test added hours later,
        // `a_fleet_cannot_be_bigger_than_its_ramp_had_time_to_dial`,
        // states the same property from the other side.
        //
        // What survives is the assertion that actually falsifies the
        // defect. The old sampler reported `granted: 1` for a fleet of
        // six because the whole transfer fitted inside its first tick, so
        // anything above 1 kills it, on every box, deterministically. Do
        // NOT restore `== CONNS` to make it feel stronger: an assertion
        // that fails on a slow-dial box is not stronger, it is flaky, and
        // a flaky test in a shard that retries is how a real wedge gets
        // reported as green.
        let peak = granted.first().copied().unwrap_or(0);
        assert!(
            peak >= 2,
            "the probe must see the concurrency the fleet actually reached;              a sampler reported 1 here and this reported {granted:?}"
        );
        assert!(
            peak <= CONNS,
            "the probe may never report more sessions than were asked for              ({CONNS} asked, {granted:?} reported)"
        );
    }

    /// The other half of the same contract: a provider that grants
    /// NOTHING must read 0, not "however many the gauge happened to
    /// see". `granted == 0` is what the carry panel turns into "this
    /// server accepted no connections at all" - the 481 / account
    /// already-in-use case - so a peak that could drift up from a failed
    /// dial would replace a true diagnosis with a wrong rate.
    ///
    /// `cap_ghost_ms` is the shape that reaches it: every accept is
    /// greeted with the provider's own capacity refusal and closed, so
    /// sessions are attempted and none is ever established.
    #[tokio::test(flavor = "multi_thread")]
    async fn granted_is_zero_when_the_provider_establishes_no_session() {
        let mut articles = std::collections::HashMap::new();
        let data: Vec<u8> = (0..200_000u32).map(|i| i as u8).collect();
        let segs = crate::mock::make_file_articles("z.bin", &data, 20_000, "gz", &mut articles);
        let chaos = crate::mock::Chaos {
            // Longer than the window below, so the refusal holds for the
            // whole run rather than clearing under it.
            cap_ghost_ms: 60_000,
            ..Default::default()
        };
        let srv = crate::mock::MockServer::start(articles, chaos).await;
        let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
        let cfg = crate::pool::PoolConfig {
            connections: 4,
            window: 4,
            ramp_delay: Duration::from_millis(0),
            ..Default::default()
        };
        let (_gbps, per, granted, _exhausted) =
            timed_fetch_multi(vec![(srv.server_config(), cfg)], ids, usize::MAX, 3).await;
        assert_eq!(
            granted,
            vec![0],
            "a provider refusing every dial granted nothing, got {granted:?}"
        );
        assert_eq!(per, vec![0], "a refused provider moved no bytes");
    }

    /// The other half of what `granted` means, and the one nothing
    /// pinned: a fleet cannot be larger than its own RAMP had time to
    /// dial. Worker slot k sleeps `ramp_delay * k` before it connects
    /// (`pool.rs`'s `let ramp = cfg.ramp_delay * slot`), so a rung whose
    /// window is W can never hold more than `floor(W / ramp_delay) + 1`
    /// sockets at once - whatever the provider allows, and with nothing
    /// anywhere saying so.
    ///
    /// That arithmetic is why this test exists rather than being a note.
    /// Both real ladder callers pass a 5 s step against the shipped
    /// 150 ms ramp, so their ceiling is 34, and measured against a mock
    /// capping NOTHING a rung asking 48 and a rung asking 64 both read
    /// 34 granted. `conn_ladder` then reads the shortfall as the
    /// provider refusing sockets and `conntune::knee_of` clamps the
    /// user's connection count to it. Worse, and not visible in
    /// `granted` at all, the RATE of such a rung is the rate of the
    /// partial fleet that did dial: on this same mock, 32 sockets and 64
    /// sockets read 0.0330 and 0.0331 Gbps - a false flat inside
    /// `CLIMB_GAIN`, on a provider that would have given nearly four
    /// times as much. TODO 312 item 6(c) carries the full measurement
    /// and the option pricing; two of the four options it opened with
    /// are eliminated there, by measurement rather than by argument.
    ///
    /// What is pinned here is the POOL's contract - the ceiling exists
    /// and is the ramp's arithmetic - NOT the ladder's use of it, which
    /// is the defect. So this stays true and stays meaningful under
    /// every option still open there: shorten the probe ramp and the ceiling
    /// rises with it, lengthen the window and it rises too, and the
    /// control leg below is what keeps the assertion falsifiable either
    /// way. Do NOT relax it to "granted is near the ask" once the ladder
    /// is fixed - the ask is exactly the thing it must not assume.
    ///
    /// The band is loose ON PURPOSE, in the one direction that can
    /// wobble. A loaded box makes the ramp sleeps land LATE, which only
    /// ever lowers `granted`; the window's own `sleep` landing late is
    /// what could raise it, so the upper bound is twice the arithmetic
    /// rather than the arithmetic itself. Nothing in between is
    /// interesting - the failure this pins is the whole fleet appearing
    /// when the ramp says it cannot.
    #[tokio::test(flavor = "multi_thread")]
    async fn a_fleet_cannot_be_bigger_than_its_ramp_had_time_to_dial() {
        const CONNS: usize = 32;
        const WINDOW: u64 = 1;
        const RAMP_MS: u64 = 100;
        // Paced so the supply CANNOT drain inside the window - a rung
        // that ends early ends its own ramp with it, which would make
        // this test measure the drain instead of the ramp.
        //
        // Returns the fleet AND the window that actually elapsed, which
        // is what keeps the arithmetic below honest on a loaded runner.
        // The two error directions are not symmetric: a slow box makes
        // the ramp sleeps land LATE, which only ever lowers `granted`,
        // while the window's own `sleep` landing late RAISES it - so the
        // ceiling is computed against the measured window rather than
        // the nominal one, and a runner that overruns cannot turn this
        // into a red that says nothing about the pool.
        let fleet = |ramp_ms: u64| async move {
            let mut articles = std::collections::HashMap::new();
            let data: Vec<u8> = (0..6_000_000u32).map(|i| i as u8).collect();
            let segs =
                crate::mock::make_file_articles("ramp.bin", &data, 20_000, "rp", &mut articles);
            let chaos = crate::mock::Chaos {
                throttle: crate::mock::Throttle {
                    per_conn_bps: 40_000,
                    ..Default::default()
                },
                ..Default::default()
            };
            let srv = crate::mock::MockServer::start(articles, chaos).await;
            let ids: Vec<String> = segs.iter().map(|(id, _, _)| format!("<{id}>")).collect();
            let cfg = crate::pool::PoolConfig {
                connections: CONNS,
                window: 4,
                ramp_delay: Duration::from_millis(ramp_ms),
                ..Default::default()
            };
            let t0 = Instant::now();
            let (_gbps, _per, granted, exhausted) =
                timed_fetch_multi(vec![(srv.server_config(), cfg)], ids, usize::MAX, WINDOW).await;
            assert!(
                !exhausted,
                "the supply must outlast the window or this measures the drain, not the ramp"
            );
            (granted[0], t0.elapsed())
        };

        // The control, and the half that keeps the assertion below
        // honest: the SAME fleet, the same window and the same provider,
        // with the ramp taken out. Everything the provider was ever
        // going to grant is granted.
        //
        // Two short of the ask rather than exact, and the tolerance is
        // borrowed rather than invented: `granted + 2 < asked` is the
        // rule `conn_ladder` and `conntune::knee_of` BOTH use to decide
        // a provider is refusing sockets, precisely because a socket or
        // two short is ordinary timing. A straggler on a loaded runner
        // must not read as a cap here either.
        let (unramped, _) = fleet(0).await;
        assert!(
            unramped + 2 >= CONNS,
            "this provider caps nothing, so an unramped fleet of {CONNS} must \
             essentially all connect, and only {unramped} did"
        );

        let (ramped, window) = fleet(RAMP_MS).await;
        assert!(
            ramped < unramped,
            "a {RAMP_MS} ms ramp cannot dial as many sockets as no ramp at all, \
             yet granted read {ramped} against the unramped {unramped} - the \
             ceiling this pins has moved"
        );
        // The ceiling itself, against the window that really elapsed:
        // slot k dials at `ramp_ms * k`, so at most `floor(W / r) + 1`
        // can be up. Rounded up by one for the boundary slot, whose
        // sleep lands within a scheduler tick of the deadline and may
        // fall either side of it.
        let formable = (window.as_millis() as u64 / RAMP_MS) as usize + 2;
        assert!(
            ramped <= formable,
            "granted {ramped} is above the {formable} a {RAMP_MS} ms ramp had \
             time to dial in the {window:?} this rung actually ran"
        );
    }

    #[test]
    fn diversity_math_on_synthetic_vectors() {
        // Not a network test - the real Jaccard function, directly.
        // 3 "servers": A,B identical gaps; C independent. All answered
        // the whole sample.
        let present = [
            vec![true, false, true, false, true, false], // A: missing idx 1,3,5
            vec![true, false, true, false, true, false], // B: same
            vec![false, true, true, true, false, true],  // C: missing 0,4
        ];
        let n = present[0].len();
        let jac = |x: &[bool], y: &[bool]| missing_jaccard(x, y, n).unwrap();
        assert!((jac(&present[0], &present[1]) - 1.0).abs() < 1e-9); // identical
        assert!(jac(&present[0], &present[2]) < 0.4); // diverse
    }

    /// An interrupted sweep must not fabricate shared gaps. Two unrelated
    /// providers each answer the first two of six requests - HAVING both -
    /// and then reset. Over what they actually answered there is no gap to
    /// share; counting the four unanswered entries as confirmed-missing
    /// made them look perfectly correlated, which is what produces a
    /// "SAME infra - keep only one" recommendation out of nothing (Codex
    /// sweep 12 Aug F15).
    #[test]
    fn an_interrupted_sweep_does_not_invent_shared_gaps() {
        // Both answered positions 0-1 (present), then the sweep died and
        // the rest of the vector is still its `false` default.
        let a = vec![true, true, false, false, false, false];
        let b = vec![true, true, false, false, false, false];

        // Over the WHOLE sample, the old maths: four identical "gaps".
        let whole = missing_jaccard(&a, &b, 6).unwrap();
        assert!(
            whole >= 0.8,
            "this fixture must reproduce the pre-fix SAME-infra reading, got {whole}"
        );

        // Over what both answered, the truth: no gap on either side.
        let common = missing_jaccard(&a, &b, 2).unwrap();
        assert!(
            common < 0.4,
            "two positions, both present on both servers: {common}"
        );

        // A sweep that answered nothing is not comparable at all, rather
        // than perfectly correlated with every other failure.
        assert_eq!(missing_jaccard(&a, &b, 0), None);
        // And a `common` past either vector cannot index out of bounds.
        assert!(missing_jaccard(&a, &b, 999).is_some());
    }
}
