//! Raw NNTP tooling commands: soak, fetch, probe, bench, sysbench, discover, plus the stream/identify/inspect front-ends and the shared server-config loaders.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;

// ---------------------------------------------------------------------------
// bench-cpu - per-stage compute ceilings (network/compute/disk balance)
// ---------------------------------------------------------------------------

pub(crate) fn bench_cpu(mb: usize) {
    let cores = std::thread::available_parallelism().map_or(8, |n| n.get());
    let bytes = mb * 1024 * 1024;
    let payload: Vec<u8> = (0..bytes)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add((i >> 11) as u8))
        .collect();
    // One realistic article for decode benches: 700 KB part.
    let part = &payload[..700 * 1024];
    let article = nzbkit::yenc::encode("bench.bin", part.len() as u64, Some((1, 2)), 1, part);
    println!("bench-cpu: {mb} MB per stage, {cores} cores\n");
    println!(
        "{:<26} {:>10} {:>10} {:>8}",
        "stage", "1-core", "all-core", "scale"
    );

    let stage = |name: &str, f: &(dyn Fn(&[u8]) + Sync)| {
        // Single core.
        let t0 = Instant::now();
        f(&payload);
        let one = bytes as f64 / t0.elapsed().as_secs_f64() / 1e9;
        // All cores: each thread runs the same volume (measures aggregate).
        let t0 = Instant::now();
        std::thread::scope(|s| {
            for _ in 0..cores {
                s.spawn(|| f(&payload));
            }
        });
        let all = (bytes * cores) as f64 / t0.elapsed().as_secs_f64() / 1e9;
        println!(
            "{:<26} {:>7.2} GB/s {:>7.2} GB/s {:>7.1}x",
            name,
            one,
            all,
            all / one
        );
        (one, all)
    };

    let (one_memcpy, _) = stage("memcpy (baseline)", &|p: &[u8]| {
        let mut dst = vec![0u8; 4 << 20];
        for c in p.chunks(4 << 20) {
            dst[..c.len()].copy_from_slice(c);
            std::hint::black_box(&dst);
        }
    });
    let art = article.clone();
    stage("yEnc decode (scalar)", &move |p: &[u8]| {
        let iters = p.len() / (700 * 1024);
        for _ in 0..iters.max(1) {
            std::hint::black_box(nzbkit::yenc::decode(&art).unwrap());
        }
    });
    let art2 = article.clone();
    stage("yEnc decode (SIMD)", &move |p: &[u8]| {
        let iters = p.len() / (700 * 1024);
        for _ in 0..iters.max(1) {
            std::hint::black_box(nzbkit::yenc_simd::decode(&art2).unwrap());
        }
    });
    stage("crc32 (1 MB blocks)", &|p: &[u8]| {
        for c in p.chunks(1 << 20) {
            std::hint::black_box(crc32fast::hash(c));
        }
    });
    let (_, md5_all) = stage("md5 (1 MB blocks)", &|p: &[u8]| {
        use md5::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box(d);
        }
    });
    let (_, verify_all) = stage("par2 verify (md5+crc32)", &|p: &[u8]| {
        use md5::{Digest, Md5};
        for c in p.chunks(1 << 20) {
            let d: [u8; 16] = Md5::digest(c).into();
            std::hint::black_box((d, crc32fast::hash(c)));
        }
    });
    // Every provider is TLS, so the AEAD runs over every downloaded
    // byte - it belongs in this budget as much as md5 does. Same
    // implementation the download path uses (aws-lc-rs, rustls'
    // provider) and the same suite the connection would pin, at the
    // 16 KB TLS record size. Seal rather than open because open
    // consumes its ciphertext; for GCM and ChaCha the two directions
    // are the same work.
    let (_, aead_all) = stage(nzbkit::sysbench::tls_aead_name(), &|p: &[u8]| {
        nzbkit::sysbench::tls_aead_seal(p)
    });

    println!(
        "\npipeline compute ceiling ≈ min stage all-core = {:.2} GB/s ({:.1} Gbps)",
        verify_all.min(aead_all),
        verify_all.min(aead_all) * 8.0
    );
    println!(
        "(md5 alone: {:.2} GB/s all-core; every downloaded byte is decrypted once, decoded once, verified once)",
        md5_all
    );
    // The memory-traffic view. On a fast desktop memcpy is ~40 GB/s and
    // copies vanish into the noise; on a single-channel N100 or an A53
    // NAS it is ~10x slower and the SAME copies become the budget. This
    // prints the wire-path traffic in units of the machine's own memcpy
    // so the two regimes are directly comparable.
    let recv_passes = 2.0; // rustls plaintext to_vec, then append to the body buffer
    println!(
        "\nreceive-path memory traffic: {recv_passes:.0} userspace copies per wire byte \
         (rustls plaintext chunk, then the article buffer)"
    );
    println!(
        "  at this box's memcpy ({:.1} GB/s 1-core) that is {:.3} cpu-s/GB of pure copying",
        one_memcpy,
        recv_passes / one_memcpy
    );
    println!("compare: the network ceiling (soak) and disk ceiling (dd bs=16m)");
}

pub(crate) async fn sysbench_cmd(config: &Path, group: &str) -> Result<()> {
    let cfg = Config::load(config)?;
    println!("== system benchmark ==");
    let compute = nzbkit::sysbench::compute(128);
    println!(
        "compute: verify ceiling {:.1} Gbps ({} cores, SIMD decode {:.0} GB/s all-core)",
        compute.ceiling_gbps, compute.cores, compute.decode_simd.all_core
    );
    let out = std::env::temp_dir();
    let disk = nzbkit::sysbench::disk_write(&out, 512).unwrap_or(0.0);
    println!(
        "disk:    {:.2} GB/s sequential write ({:.1} Gbps)",
        disk,
        disk * 8.0
    );
    let srv = &cfg.servers[0];
    // The probe group is the --group argument, never `ServerConfig.group`:
    // that field is a MIRROR LABEL (servers sharing it are backbone twins,
    // and the pool dedups 430s by it), freeform text from the dashboard and
    // not a newsgroup at all. Sending it as a GROUP argument answered 411 -
    // which network_probe folded into a "0.00 Gbps" verdict, and which made
    // the diversity phase below hard-error - while also overriding the group
    // the user explicitly asked for.
    let grp = group.to_string();
    // Every enabled server at its configured connection count, not a
    // fixed 8 on the first server - see measure_system in serve/mod.rs
    // (issue #12, both rounds: eight connections cannot show more than a
    // few hundred Mbps, and one provider cannot show what five deliver
    // together).
    //
    // Metered servers sit it out, same rule as the daemon's own system
    // benchmark (M7b.2 §5.7): this leg pulls real article bodies for
    // 8 s across the whole fleet. Named on the way past, because a
    // figure quietly covering fewer servers than the operator has
    // configured is a figure they will misread.
    let skipped: Vec<&str> = cfg
        .servers
        .iter()
        .filter(|s| s.enabled && !s.may_spend_on_measurement())
        .map(|s| s.host.as_str())
        .collect();
    if !skipped.is_empty() {
        println!(
            "network: skipping {} (billed per byte; this probe downloads real articles)",
            skipped.join(", ")
        );
    }
    let probe_servers: Vec<_> = cfg
        .servers
        .iter()
        .filter(|s| s.enabled && s.may_spend_on_measurement())
        .cloned()
        .collect();
    if probe_servers.is_empty() {
        anyhow::bail!(
            "every enabled server is billed per byte, so there is nothing to measure the \
             network with. Clear `block_account` on a server to include it."
        );
    }
    let conns = probe_servers
        .iter()
        .map(|s| (s.connections as usize).clamp(1, 100))
        .sum::<usize>()
        .min(200);
    print!(
        "network: probing {} server(s) for 8s on {conns} connections… ",
        probe_servers.len()
    );
    use std::io::Write as _;
    std::io::stdout().flush().ok();
    let (net, _per_server) = nzbkit::sysbench::network_probe_multi(&probe_servers, &grp, 8)
        .await
        .unwrap_or((0.0, Vec::new()));
    println!("{:.2} Gbps", net);
    let mut v = nzbkit::sysbench::verdict(net, &compute, disk);
    v.network_host = probe_servers
        .iter()
        .map(|s| s.host.as_str())
        .take(3)
        .collect::<Vec<_>>()
        .join(", ");
    if probe_servers.len() > 3 {
        v.network_host.push_str(", …");
    }
    v.network_conns = conns;
    // The verdict leads: the sustainable speed, then a bar per subsystem -
    // the shortest bar is the limit; the others show their headroom.
    println!(
        "\n>>> expected max download: {:.2} Gbps (≈ {:.0} MB/s) - limited by {} <<<",
        v.expected_gbps,
        v.expected_gbps * 125.0,
        v.bottleneck
    );
    let rows = [
        ("network", "Network         ", v.network_gbps),
        ("compute", "Compute (verify)", v.compute_gbps),
        ("disk", "Disk write      ", v.disk_gbps),
    ];
    let mx = rows.iter().map(|r| r.2).fold(0.01f64, f64::max);
    for (key, label, val) in rows {
        let w = ((val / mx * 30.0).round() as usize).max(1);
        let tail = if key == v.bottleneck {
            " ⟵ your limit".to_string()
        } else {
            format!("  ×{:.1} headroom", val / v.expected_gbps.max(0.01))
        };
        println!("  {label} {:<30} {val:7.2} Gbps{tail}", "█".repeat(w));
    }
    println!("{}", v.advice);

    if cfg.servers.len() >= 2 {
        println!("\n== server diversity ==");
        // Age-spanning sample from server 0.
        use nzbkit::nntp::Connection;
        let (mut conn, _) = Connection::connect(srv).await?;
        let g = conn.group(&grp).await?;
        let span = g.high.saturating_sub(g.low).max(1);
        let mut ids = Vec::new();
        for band in 0..5u64 {
            let center = g.high.saturating_sub(span * band / 5);
            let from = center.saturating_sub(2_000).max(g.low);
            if let Ok(es) = conn.over(from, center).await {
                for e in es.into_iter().filter(|e| !e.message_id.is_empty()).take(20) {
                    ids.push(nzbkit::sysbench::bracket_id(&e.message_id));
                }
            }
        }
        conn.quit().await;
        let rep = nzbkit::sysbench::diversity(&cfg.servers, &ids, &grp).await;
        for s in &rep.servers {
            println!(
                "  {:<28} {:>5.0}% avail · {:>5.2} Gbps · {:.0} ms",
                s.host,
                s.availability * 100.0,
                s.speed_gbps,
                s.rtt_ms
            );
        }
        for p in &rep.pairs {
            println!(
                "  {:<20} ↔ {:<20} {:>4.0}% shared gaps - {}",
                p.a,
                p.b,
                p.missing_jaccard * 100.0,
                p.verdict
            );
        }
        println!("\n{}", rep.recommendation);
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// soak - multi-provider aggregate throughput
// ---------------------------------------------------------------------------

pub(crate) async fn soak(
    config: &Path,
    group: &str,
    articles: usize,
    connections: usize,
    window: usize,
    decoders: usize,
    shards: usize,
    rcvbuf_mb: u32,
) -> Result<()> {
    use nzbkit::pool::{ArticleReq, BufPool, FetchOutcome, PoolConfig, fetch_all_sharded};

    let mut cfg_all = Config::load(config)?;
    for s in &mut cfg_all.servers {
        if rcvbuf_mb > 0 {
            s.rcvbuf = Some(rcvbuf_mb * 1024 * 1024);
        }
    }
    println!(
        "{} server(s), {} shard(s), rcvbuf {}MB:",
        cfg_all.servers.len(),
        shards,
        rcvbuf_mb
    );
    for s in &cfg_all.servers {
        println!("  {}:{} ({} conns)", s.host, s.port, connections);
    }

    // Discover once via the first server - message-IDs are universal.
    let (mut conn, _) = Connection::connect(&cfg_all.servers[0]).await?;
    let g = conn.group(group).await?;
    let ids = discover(&mut conn, &g, articles).await?;
    conn.quit().await;
    let est: u64 = ids.iter().map(|c| c.1).sum();
    println!(
        "{} articles (~{:.1} GB) on one shared queue\n",
        ids.len(),
        est as f64 / 1e9
    );

    let buf_pool = BufPool::new(nzbkit::mem::MemBudget::auto().bufpool_bufs());
    let pool_cfg = PoolConfig {
        connections,
        window,
        buf_pool: Some(buf_pool.clone()),
        ..PoolConfig::default()
    };
    let servers: Vec<_> = cfg_all
        .servers
        .iter()
        .map(|s| (s.clone(), pool_cfg.clone()))
        .collect();

    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(256);
    let rx = Arc::new(tokio::sync::Mutex::new(rx));

    // Shared consumer-side counters (also feed the live ticker).
    let raw_bytes = Arc::new(AtomicU64::new(0));
    let ok = Arc::new(AtomicU64::new(0));
    let bad = Arc::new(AtomicU64::new(0));
    let gone = Arc::new(AtomicU64::new(0));

    let mut decode_tasks = Vec::new();
    for _ in 0..decoders.max(1) {
        let rx = rx.clone();
        let pool = buf_pool.clone();
        let (raw_bytes, ok, bad, gone) = (raw_bytes.clone(), ok.clone(), bad.clone(), gone.clone());
        decode_tasks.push(tokio::spawn(async move {
            loop {
                let outcome = { rx.lock().await.recv().await };
                match outcome {
                    Some(FetchOutcome::Done { raw, .. }) => {
                        raw_bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
                        match nzbkit::yenc_simd::decode(&raw) {
                            Ok(_) => ok.fetch_add(1, Ordering::Relaxed),
                            Err(_) => bad.fetch_add(1, Ordering::Relaxed),
                        };
                        pool.give(raw);
                    }
                    Some(_) => {
                        gone.fetch_add(1, Ordering::Relaxed);
                    }
                    None => break,
                }
            }
        }));
    }

    // Live rate ticker.
    let ticker_bytes = raw_bytes.clone();
    let ticker = tokio::spawn(async move {
        let mut last = 0u64;
        let mut tick = tokio::time::interval(std::time::Duration::from_secs(2));
        tick.tick().await;
        loop {
            tick.tick().await;
            let now = ticker_bytes.load(Ordering::Relaxed);
            println!(
                "  … {:>7.1} MB/s ({:.2} Gbps)  total {:.2} GB",
                (now - last) as f64 / 2e6,
                (now - last) as f64 * 8.0 / 2e9,
                now as f64 / 1e9
            );
            last = now;
        }
    });

    let t0 = Instant::now();
    // Discovered live off the spool - fresh by definition.
    let id_list: Vec<ArticleReq> = ids
        .into_iter()
        .map(|(id, _)| ArticleReq::fresh(id))
        .collect();
    let servers_moved = servers.clone();
    let stats = tokio::task::spawn_blocking(move || {
        fetch_all_sharded(servers_moved, id_list, tx, shards, None)
    })
    .await?;
    let elapsed = t0.elapsed();
    for t in decode_tasks {
        let _ = t.await;
    }
    ticker.abort();

    let total = raw_bytes.load(Ordering::Relaxed);
    println!(
        "\n== aggregate: {:.2} GB in {:.2?} → {:.1} MB/s ({:.2} Gbps) ==",
        total as f64 / 1e9,
        elapsed,
        total as f64 / 1e6 / elapsed.as_secs_f64(),
        total as f64 * 8.0 / 1e9 / elapsed.as_secs_f64(),
    );
    for ((s, _), st) in servers.iter().zip(&stats) {
        println!(
            "  {:<28} {:>8.1} MB ({:>4.0} Mbps avg) · {} conns, {} reconnects",
            s.host,
            st.bytes as f64 / 1e6,
            st.bytes as f64 * 8.0 / 1e6 / elapsed.as_secs_f64(),
            st.connects,
            st.reconnects
        );
    }
    println!(
        "decoded OK {} · errors {} · missing/failed {}",
        ok.load(Ordering::Relaxed),
        bad.load(Ordering::Relaxed),
        gone.load(Ordering::Relaxed)
    );
    Ok(())
}

// ---------------------------------------------------------------------------
// fetch - pool + decoder shakeout under real conditions
// ---------------------------------------------------------------------------

pub(crate) async fn fetch(
    config: &Path,
    group: &str,
    articles: usize,
    connections: usize,
    window: usize,
) -> Result<()> {
    use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all};

    let server = load_server(config)?;
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;
    let ids = discover(&mut conn, &g, articles).await?;
    conn.quit().await;
    println!(
        "{} articles from {group}; pool: {connections} conns, window {window}",
        ids.len()
    );

    let cfg = PoolConfig {
        connections,
        window,
        ..PoolConfig::default()
    };
    let (tx, mut rx) = tokio::sync::mpsc::channel(64);

    // Consumer decodes concurrently with the pool's fetching - the overlap
    // the real pipeline relies on.
    let consumer = tokio::spawn(async move {
        let (mut ok, mut decoded_bytes, mut crc_bad, mut missing, mut failed) =
            (0u64, 0u64, 0u64, 0u64, 0u64);
        while let Some(outcome) = rx.recv().await {
            match outcome {
                FetchOutcome::Done { raw, .. } => match nzbkit::yenc_simd::decode(&raw) {
                    Ok(dec) => {
                        ok += 1;
                        decoded_bytes += dec.data.len() as u64;
                    }
                    Err(_) => crc_bad += 1,
                },
                FetchOutcome::Missing { .. } => missing += 1,
                FetchOutcome::Failed { .. } => failed += 1,
            }
        }
        (ok, decoded_bytes, crc_bad, missing, failed)
    });

    let t0 = Instant::now();
    let stats = fetch_all(
        &server,
        &cfg,
        ids.iter()
            .map(|(id, _)| ArticleReq::fresh(id.clone()))
            .collect(),
        tx,
    )
    .await;
    let elapsed = t0.elapsed();
    let (ok, decoded_bytes, crc_bad, missing, failed) = consumer.await?;

    println!(
        "{:.1} MB raw in {:.2?} → {:.1} MB/s ({:.0} Mbps)",
        stats.bytes as f64 / 1e6,
        elapsed,
        stats.bytes as f64 / 1e6 / elapsed.as_secs_f64(),
        stats.bytes as f64 * 8.0 / 1e6 / elapsed.as_secs_f64(),
    );
    println!(
        "decoded OK {ok} ({:.1} MB) · decode/crc errors {crc_bad} · missing {missing} · failed {failed}",
        decoded_bytes as f64 / 1e6
    );
    println!(
        "connections: {} opened, {} reconnects",
        stats.connects, stats.reconnects
    );
    Ok(())
}

pub(crate) fn load_server(config: &Path) -> Result<ServerConfig> {
    let cfg = Config::load(config).with_context(|| {
        format!(
            "loading {} (copy config.local.json.example?)",
            config.display()
        )
    })?;
    Ok(cfg.servers[0].clone())
}

/// A8 multi-server indexing: the servers worth scanning HEADERS from.
///
/// - enabled only;
/// - never a metered account ([`ServerConfig::may_spend_on_measurement`]:
///   the explicit block-account flag, or a configured prepaid block):
///   OVER traffic is bytes the user's download never asked for, and on a
///   block it burns the credit that exists to rescue missing bodies;
/// - one per backbone: mirrors share a spool, so a second reseller of
///   the same backbone contributes no headers the first didn't. Mirrors
///   are detected by the explicit `group` field first, else by
///   [`nzbkit::oracle::backbone_of`];
/// - ranked level-then-config-order, which is the tiebreak order the
///   per-group primary choice uses.
///
/// An all-metered (but enabled) config falls back to the enabled list
/// unfiltered - a user who configured indexing gets an index; the
/// caller logs that headers are spending billed bytes. Indexing is
/// opt-in and asks before it starts, so someone who turned it on with
/// nothing but metered servers has already chosen to spend on it; the
/// flag reorders who scans, and only silences it where there is a
/// free alternative.
/// Resolve a marks server key (see [`nzbkit::index::Index::server_key`])
/// back to its config entry - the scan loop persists only the key.
/// None = the config no longer carries that server.
#[cfg(feature = "indexer")]
pub(crate) fn find_scan_server(config: &Path, key: &str) -> Option<ServerConfig> {
    let cfg = Config::load(config).ok()?;
    cfg.servers
        .iter()
        .find(|s| nzbkit::index::Index::server_key(&s.host) == key)
        .cloned()
}

#[cfg(feature = "indexer")]
pub(crate) fn scan_servers(cfg: &Config) -> Vec<ServerConfig> {
    let eligible: Vec<&ServerConfig> = {
        let flat: Vec<&ServerConfig> = cfg
            .servers
            .iter()
            .filter(|s| s.enabled && s.may_spend_on_measurement())
            .collect();
        if flat.is_empty() {
            cfg.servers.iter().filter(|s| s.enabled).collect()
        } else {
            flat
        }
    };
    let mut ranked = eligible;
    // Stable: config order survives within a level.
    ranked.sort_by_key(|s| s.level);
    let mut seen = std::collections::HashSet::new();
    ranked
        .into_iter()
        .filter(|s| {
            let backbone = s
                .group
                .clone()
                .unwrap_or_else(|| nzbkit::oracle::backbone_of(&s.host));
            seen.insert(backbone)
        })
        .cloned()
        .collect()
}

// ---------------------------------------------------------------------------
// probe
// ---------------------------------------------------------------------------

pub(crate) async fn probe(config: &Path) -> Result<()> {
    let cfg = Config::load(config)?;
    for server in &cfg.servers {
        print!("{:<28}", server.host);
        let t0 = Instant::now();
        match Connection::connect(server).await {
            Ok((mut conn, _)) => {
                let connected = t0.elapsed();
                let mut rtts = Vec::new();
                for _ in 0..3 {
                    let t = Instant::now();
                    conn.exec("DATE").await?;
                    rtts.push(t.elapsed());
                }
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let pipelining = conn
                    .capabilities()
                    .await
                    .map(|caps| caps.iter().any(|c| c.contains("PIPELINING")))
                    .unwrap_or(false);
                let g = conn.group("alt.binaries.boneless").await;
                conn.quit().await;
                println!(
                    " ok: auth {:>4}ms · RTT {:>5.1}ms · PIPELINING {} · boneless {}",
                    connected.as_millis(),
                    avg.as_secs_f64() * 1000.0,
                    if pipelining { "yes" } else { "n/a" },
                    if g.is_ok() { "ok" } else { "MISSING" },
                );
            }
            Err(e) => println!(" FAILED: {e}"),
        }
    }
    Ok(())
}

// ---------------------------------------------------------------------------
// bench - the thesis test (design: Phase 2c)
// ---------------------------------------------------------------------------

pub(crate) struct FetchStats {
    pub(crate) bytes: u64,
    pub(crate) missing: u64,
    pub(crate) errors: u64,
    pub(crate) error_samples: Vec<String>,
    pub(crate) elapsed: std::time::Duration,
}

pub(crate) async fn bench(
    config: &Path,
    group: &str,
    articles: usize,
    connections: usize,
    window: usize,
    simultaneous: bool,
    duration: u64,
) -> Result<()> {
    let server = load_server(config)?;

    // Discovery: pull OVER data until we have 2×articles usable candidates.
    println!("discovering articles in {group} …");
    let (mut conn, _) = Connection::connect(&server).await?;
    let g = conn.group(group).await?;
    anyhow::ensure!(g.count > 0, "group {group} is empty on this server");

    // In duration mode, size the pool so no fleet runs dry: assume up to
    // ~30 MB/s/conn on fibre → ~45 articles/s/conn.
    let want = if duration > 0 {
        (connections * duration as usize * 45 * 2).max(articles * 2)
    } else {
        articles * 2
    };
    let candidates = discover(&mut conn, &g, want).await?;
    anyhow::ensure!(
        candidates.len() >= (articles * 2).min(want),
        "only {} usable articles found in {group}; try another group",
        candidates.len()
    );
    conn.quit().await; // free the discovery session before the fetch fleets
    let est: u64 = candidates.iter().map(|c| c.1).sum();
    println!(
        "{} candidates, ~{:.0} MB total; {} conns, window {}",
        candidates.len(),
        est as f64 / 1e6,
        connections,
        window
    );

    // Alternate assignment so both modes see the same size distribution and
    // neither benefits from provider-side caching of the other's set.
    let mut serial_set = Vec::new();
    let mut pipe_set = Vec::new();
    for (i, c) in candidates.into_iter().enumerate() {
        if i % 2 == 0 {
            serial_set.push(c.0);
        } else {
            pipe_set.push(c.0);
        }
    }

    let dur = (duration > 0).then(|| std::time::Duration::from_secs(duration));
    let (s, p) = if simultaneous {
        println!("\nrunning both modes simultaneously (paired) …");
        let (s, p) = tokio::join!(
            run_fetch(&server, serial_set, connections, 1, dur),
            run_fetch(&server, pipe_set, connections, window, dur),
        );
        (s?, p?)
    } else {
        println!("\n- serial (window 1) -");
        let s = run_fetch(&server, serial_set, connections, 1, dur).await?;
        println!("\n- pipelined (window {window}) -");
        let p = run_fetch(&server, pipe_set, connections, window, dur).await?;
        (s, p)
    };
    println!("\n- serial (window 1) -");
    report(&s);
    println!("- pipelined (window {window}) -");
    report(&p);

    let s_rate = s.bytes as f64 / s.elapsed.as_secs_f64();
    let p_rate = p.bytes as f64 / p.elapsed.as_secs_f64();
    println!(
        "\npipelining speedup at {connections} connections: {:+.1}%",
        (p_rate / s_rate - 1.0) * 100.0
    );
    Ok(())
}

pub(crate) fn report(s: &FetchStats) {
    println!(
        "  {:.1} MB in {:.2?}  →  {:.1} MB/s ({:.0} Mbps){}{}",
        s.bytes as f64 / 1e6,
        s.elapsed,
        s.bytes as f64 / 1e6 / s.elapsed.as_secs_f64(),
        s.bytes as f64 * 8.0 / 1e6 / s.elapsed.as_secs_f64(),
        if s.missing > 0 {
            format!("  [{} missing]", s.missing)
        } else {
            String::new()
        },
        if s.errors > 0 {
            format!("  [{} errors]", s.errors)
        } else {
            String::new()
        },
    );
    for e in &s.error_samples {
        println!("    error: {e}");
    }
}

/// Scan a group backwards collecting mid-size binary articles (comparable
/// units of work) until `want` candidates are found.
pub(crate) async fn discover(
    conn: &mut Connection,
    g: &nzbkit::nntp::GroupInfo,
    want: usize,
) -> Result<Vec<(String, u64)>> {
    let mut candidates: Vec<(String, u64)> = Vec::new();
    let mut high = g.high;
    let mut scanned = 0u64;
    while candidates.len() < want && high > g.low && scanned < 400_000 {
        let from = high.saturating_sub(4_000).max(g.low);
        for e in conn.over(from, high).await? {
            if (300_000..=1_200_000).contains(&e.bytes) && !e.message_id.is_empty() {
                candidates.push((e.message_id, e.bytes));
            }
        }
        scanned += high - from;
        if from == g.low {
            break;
        }
        high = from - 1;
    }
    candidates.truncate(want);
    Ok(candidates)
}

/// Pull the next message-id, or None when the queue is dry / deadline passed.
pub(crate) async fn pop_id(
    queue: &tokio::sync::Mutex<std::collections::VecDeque<String>>,
    deadline: Option<Instant>,
) -> Option<String> {
    if let Some(d) = deadline
        && Instant::now() >= d
    {
        return None;
    }
    queue.lock().await.pop_front()
}

/// Fetch from a shared work queue across `connections` connections with
/// `window` commands in flight per connection. Connection setup happens
/// before the clock starts.
///
/// With `duration` set, workers stop pulling new work at the deadline and
/// only bytes received before it are counted - cold-article stragglers
/// can't skew the rate.
pub(crate) async fn run_fetch(
    server: &ServerConfig,
    ids: Vec<String>,
    connections: usize,
    window: usize,
    duration: Option<std::time::Duration>,
) -> Result<FetchStats> {
    let queue = Arc::new(tokio::sync::Mutex::new(
        ids.into_iter()
            .collect::<std::collections::VecDeque<String>>(),
    ));

    let mut conns = Vec::new();
    for _ in 0..connections {
        let (c, _) = Connection::connect(server).await?;
        conns.push(c);
    }

    let bytes = Arc::new(AtomicU64::new(0));
    let missing = Arc::new(AtomicU64::new(0));
    let errors = Arc::new(AtomicU64::new(0));
    let error_log = Arc::new(tokio::sync::Mutex::new(Vec::<String>::new()));

    let t0 = Instant::now();
    let deadline = duration.map(|d| t0 + d);
    let mut tasks = Vec::new();
    for mut conn in conns {
        let queue = queue.clone();
        let bytes = bytes.clone();
        let missing = missing.clone();
        let errors = errors.clone();
        let error_log = error_log.clone();
        tasks.push(tokio::spawn(async move {
            let fail = |msg: String| async move {
                errors.fetch_add(1, Ordering::Relaxed);
                let mut log = error_log.lock().await;
                if log.len() < 3 {
                    log.push(msg);
                }
            };

            let mut inflight = 0usize;
            // Prime the window.
            for _ in 0..window {
                if let Some(id) = pop_id(&queue, deadline).await {
                    if let Err(e) = conn.send_body(&id).await {
                        fail(format!("send: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    inflight += 1;
                }
            }
            if let Err(e) = conn.flush().await {
                fail(format!("flush: {e}")).await;
                conn.quit().await;
                return;
            }

            while inflight > 0 {
                match tokio::time::timeout(std::time::Duration::from_secs(60), conn.read_body())
                    .await
                {
                    Ok(Ok(Some(raw))) => {
                        if deadline.is_none_or(|d| Instant::now() < d) {
                            bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
                        }
                    }
                    Ok(Ok(None)) => {
                        missing.fetch_add(1, Ordering::Relaxed);
                    }
                    Ok(Err(e)) => {
                        fail(format!("read: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    Err(_) => {
                        // Timed out mid-response - connection state is
                        // unusable; drop without QUIT.
                        fail("read: 60s timeout".into()).await;
                        return;
                    }
                }
                inflight -= 1;
                if let Some(id) = pop_id(&queue, deadline).await {
                    if let Err(e) = conn.send_body(&id).await {
                        fail(format!("send: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    if let Err(e) = conn.flush().await {
                        fail(format!("flush: {e}")).await;
                        conn.quit().await;
                        return;
                    }
                    inflight += 1;
                }
            }
            conn.quit().await;
        }));
    }
    for t in tasks {
        let _ = t.await;
    }
    // In duration mode the rate denominator is the fixed window, not the
    // (slightly longer) drain time.
    let elapsed = duration.unwrap_or_else(|| t0.elapsed());

    Ok(FetchStats {
        bytes: bytes.load(Ordering::Relaxed),
        missing: missing.load(Ordering::Relaxed),
        errors: errors.load(Ordering::Relaxed),
        error_samples: std::mem::take(&mut *error_log.lock().await),
        elapsed,
    })
}

// ---------------------------------------------------------------------------
// inspect (Phase 1a)
// ---------------------------------------------------------------------------

/// `nzbfast stream`: submit an NZB (file or URL) to the running daemon
/// with stream=1 - Force priority + player-handoff links - then hand the
/// .m3u to the OS default player. The download side is the daemon's; this
/// is just the one-command front door for "watch it now".
pub(crate) fn stream_cmd(
    nzb: &str,
    host: &str,
    port: u16,
    apikey: Option<&str>,
    no_open: bool,
) -> Result<()> {
    use std::io::{Read as _, Write as _};
    fn urlenc(s: &str) -> String {
        s.bytes()
            .map(|b| match b {
                b'A'..=b'Z' | b'a'..=b'z' | b'0'..=b'9' | b'-' | b'_' | b'.' | b'~' => {
                    (b as char).to_string()
                }
                _ => format!("%{b:02X}"),
            })
            .collect()
    }
    let key_q = apikey.map(|k| format!("&apikey={k}")).unwrap_or_default();
    const BOUNDARY: &str = "----nzbfaststream";
    let (path, body): (String, Vec<u8>) = if nzb.starts_with("http://")
        || nzb.starts_with("https://")
    {
        (
            format!(
                "/api?mode=addurl&output=json&stream=1{key_q}&name={}",
                urlenc(nzb)
            ),
            Vec::new(),
        )
    } else {
        let bytes = std::fs::read(nzb).with_context(|| format!("reading {nzb}"))?;
        let fname = std::path::Path::new(nzb)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_string();
        let mut b = Vec::new();
        b.extend_from_slice(
                format!(
                    "--{BOUNDARY}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n"
                )
                .as_bytes(),
            );
        b.extend_from_slice(&bytes);
        b.extend_from_slice(format!("\r\n--{BOUNDARY}--\r\n").as_bytes());
        (format!("/api?mode=addfile&output=json&stream=1{key_q}"), b)
    };
    let mut s = std::net::TcpStream::connect((host, port))
        .with_context(|| format!("no daemon at {host}:{port} - start one with `nzbfast serve`"))?;
    if body.is_empty() {
        write!(
            s,
            "GET {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\n\r\n"
        )?;
    } else {
        write!(
            s,
            "POST {path} HTTP/1.1\r\nHost: {host}:{port}\r\nConnection: close\r\nContent-Type: multipart/form-data; boundary={BOUNDARY}\r\nContent-Length: {}\r\n\r\n",
            body.len()
        )?;
        s.write_all(&body)?;
    }
    let mut raw = String::new();
    s.read_to_string(&mut raw)?;
    let json_body = raw.split("\r\n\r\n").nth(1).unwrap_or("").trim();
    let v: serde_json::Value = serde_json::from_str(json_body)
        .with_context(|| format!("bad daemon response: {json_body}"))?;
    if v["status"].as_bool() != Some(true) {
        anyhow::bail!(
            "daemon refused: {}",
            v["error"].as_str().unwrap_or(json_body)
        );
    }
    println!(
        "queued {} at Force priority",
        v["nzo_ids"][0].as_str().unwrap_or("?")
    );
    let m3u = v["m3u"].as_str().unwrap_or_default().to_string();
    println!("  player link: {m3u}");
    println!("  raw stream:  {}", v["stream"].as_str().unwrap_or(""));
    if !no_open && !m3u.is_empty() {
        #[cfg(target_os = "macos")]
        let opened = std::process::Command::new("open").arg(&m3u).status();
        // Windows: explorer, NOT `cmd /C start` - cmd re-parses its command
        // line, so metacharacters (&, ^, %) in the string would execute. This
        // string is the daemon's `m3u` field, read over plaintext HTTP from a
        // possibly-remote `--host`, so an on-path attacker answering
        // {"m3u":"http://h/x&calc.exe"} got arbitrary execution. Same rule the
        // daemon's own os_open already follows for exactly this reason.
        #[cfg(target_os = "windows")]
        let opened = std::process::Command::new("explorer").arg(&m3u).status();
        #[cfg(not(any(target_os = "macos", target_os = "windows")))]
        let opened = std::process::Command::new("xdg-open").arg(&m3u).status();
        match opened {
            Ok(st) if st.success() => println!("  handed to the default player"),
            _ => println!("  (couldn't launch a player - open the link above manually)"),
        }
    }
    Ok(())
}

/// `nzbfast identify <file>`: the synthesised-naming ladder, end to end,
/// with the verdict printed instead of applied. The same fact
/// extraction, the same catalogue queries and the same acceptance gate
/// the renamer runs after a completed job.
pub(crate) fn identify_cmd(
    config: &std::path::Path,
    file: &std::path::Path,
    year: Option<u32>,
) -> Result<()> {
    let facts = nzbkit::media::probe(file).ok_or_else(|| {
        anyhow::anyhow!(
            "{}: no container facts (not a Matroska or MP4 head we could read)",
            file.display()
        )
    })?;
    let show = |v: &[String]| {
        if v.is_empty() {
            "-".to_string()
        } else {
            v.join(", ")
        }
    };
    println!("container      {}", facts.container);
    println!(
        "runtime        {}",
        match (facts.duration_secs, facts.runtime_minutes()) {
            (Some(s), Some(m)) => format!("{s:.1}s ({m} min)"),
            (Some(s), None) => format!("{s:.1}s (not a feature runtime)"),
            _ => "-".into(),
        }
    );
    println!(
        "dimensions     {}",
        match (facts.width, facts.height) {
            (Some(w), Some(h)) => format!("{w}x{h} ({})", nzbkit::mkv::res_bucket(w, h)),
            _ => "-".into(),
        }
    );
    println!(
        "video codec    {}",
        facts.video_codec.as_deref().unwrap_or("-")
    );
    println!("audio codecs   {}", show(&facts.audio_codecs));
    println!("audio langs    {}", show(&facts.audio_langs));
    println!("subtitle langs {}", show(&facts.sub_langs));
    println!(
        "original lang  {}",
        facts
            .original_language()
            .unwrap_or("(not asserted: no language filter)")
    );

    let post_year = year.unwrap_or_else(identify::current_year);
    let tmdb_key = Config::load(config)
        .ok()
        .and_then(|c| c.tmdb_key)
        .filter(|k| !k.is_empty());
    println!("\npost year      {post_year}");
    println!(
        "sources        wikidata{}",
        if tmdb_key.is_some() {
            " + tmdb"
        } else {
            " (no tmdb_key configured)"
        }
    );

    let outcome = identify::identify(&facts, post_year, tmdb_key.as_deref());
    println!("\nverdict        {}", outcome.log_line());
    if !outcome.shortlist.is_empty() {
        println!("\nshortlist ({} shown):", outcome.shortlist.len());
        for c in &outcome.shortlist {
            println!("  {c}");
        }
    }
    match outcome.accepted_name() {
        Some(name) => println!("\nWOULD RENAME TO: {name}"),
        None => println!("\nWOULD NOT RENAME - the filename is left exactly as posted"),
    }
    Ok(())
}

pub(crate) fn inspect(path: &Path) -> Result<()> {
    let xml = std::fs::read(path).with_context(|| format!("reading {}", path.display()))?;
    let nzb = Nzb::parse(&xml).context("parsing NZB")?;

    println!("{:<7} {:>10} {:>5}  file", "kind", "bytes", "segs");
    for f in &nzb.files {
        let kind = match f.kind() {
            FileKind::Data => "data",
            FileKind::Par2Main => "par2",
            FileKind::Par2Volume => "par2vol",
        };
        println!(
            "{:<7} {:>10} {:>5}  {}",
            kind,
            f.bytes(),
            f.segments.len(),
            f.filename_hint().unwrap_or(&f.subject),
        );
    }

    let total = nzb.total_bytes();
    let eager = nzb.eager_bytes();
    println!(
        "\n{} files, {:.1} MB total; eager set {:.1} MB ({:.1}% saved by deferring PAR2 volumes)",
        nzb.files.len(),
        total as f64 / 1e6,
        eager as f64 / 1e6,
        (total - eager) as f64 * 100.0 / total.max(1) as f64,
    );
    Ok(())
}

#[cfg(all(test, feature = "indexer"))]
mod multi_server_selection {
    use super::*;

    fn cfg(servers: serde_json::Value) -> Config {
        serde_json::from_value(serde_json::json!({ "servers": servers })).unwrap()
    }

    /// A8: header scanning never spends block credit, never reads the
    /// same backbone twice (mirrors share a spool), and ranks
    /// level-then-config-order.
    #[test]
    fn scan_servers_skip_blocks_and_dedupe_backbones() {
        let c = cfg(serde_json::json!([
            { "host": "news.newshosting.com" },
            // Same SPOOL (another Highwinds reseller): contributes
            // nothing. Eweka would NOT qualify - same owner, own spool.
            { "host": "news.usenetserver.com" },
            // Prepaid block: OVER would burn rescue credit.
            { "host": "news.blocknews.net", "block_bytes": 5_000_000_000u64 },
            // Fill server, flatrate, own backbone: eligible, ranked after
            // the level-0 entries.
            { "host": "news.xsnews.nl", "level": 1 },
            { "host": "news.usenetexpress.com", "enabled": false },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.newshosting.com", "news.xsnews.nl"]);
    }

    /// M7b.2 §5.7: the block-account flag keeps headers off a metered
    /// server just as a configured block size does, and it works on a
    /// level-0 host - which the block-size inference alone would have
    /// happily scanned.
    #[test]
    fn scan_servers_skip_servers_flagged_as_billed_per_byte() {
        let c = cfg(serde_json::json!([
            // Metered by declaration, not by topology: level 0, no block
            // size, and still not somewhere to spend header traffic.
            { "host": "news.eweka.nl", "block_account": true },
            { "host": "news.xsnews.nl" },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.xsnews.nl"]);
    }

    /// The explicit mirror `group` field outranks hostname clustering:
    /// two hosts the alias map would call separate backbones are one
    /// spool when the user says so.
    #[test]
    fn scan_servers_honour_the_mirror_group_field() {
        let c = cfg(serde_json::json!([
            { "host": "news.eweka.nl", "group": "main" },
            { "host": "news.xsnews.nl", "group": "main" },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.eweka.nl"]);
    }

    /// An all-block config still gets an index: the user configured
    /// indexing, and "no index at all" is worse than spending credit.
    #[test]
    fn scan_servers_fall_back_to_blocks_when_nothing_else_exists() {
        let c = cfg(serde_json::json!([
            { "host": "news.blocknews.net", "block_bytes": 5_000_000_000u64 },
            { "host": "news.abavia.com", "enabled": false },
        ]));
        let picked: Vec<String> = scan_servers(&c).into_iter().map(|s| s.host).collect();
        assert_eq!(picked, ["news.blocknews.net"]);
    }
}
