//! Raw NNTP tooling commands: soak, fetch, probe, bench, sysbench, discover, plus the stream/identify/inspect front-ends and the shared server-config loaders.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use std::path::Path;

// ---------------------------------------------------------------------------
// bench-cpu - per-stage compute ceilings (network/compute/disk balance)
// ---------------------------------------------------------------------------

pub(crate) fn bench_cpu(mb: usize) {
    // cpu-workers-gate: bench-cpu measures this box's per-stage compute
    // ceiling, the same reason sysbench asks directly.
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
    // The encrypted-RAR path: AES-256-CBC through nzbkit's own
    // decryptor, so this reads whichever AES backend the build actually
    // selected. That is the point of the stage - on aarch64 the hardware
    // backend needs `-C target-feature=+aes` on targets cpufeatures is
    // blind to (ARM64 Windows), and soft vs hardware here is ~230 MB/s
    // vs ~13 GB/s. Not folded into the pipeline ceiling below because it
    // only runs over encrypted posts.
    stage("aes-256-cbc decrypt (rar)", &|p: &[u8]| {
        nzbkit::sysbench::rar_aes_decrypt(p)
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
        "compute: full-verify ceiling {:.1} Gbps, fast-verify (CRC32-only) ceiling \
         {:.1} Gbps ({} cores, SIMD decode {:.0} GB/s all-core)",
        compute.ceiling_gbps,
        compute.fast_ceiling_gbps,
        compute.cores,
        compute.decode_simd.all_core
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
    // §210 item (b) on the CLI side: the same link reading the daemon's
    // System benchmark card carries. Probed here rather than read off a
    // daemon because this command has none behind it.
    //
    // Started before the network leg and collected after it, for two
    // reasons. `system_profiler SPAirPortDataType` takes ~10 s on a
    // macOS Wi-Fi machine and 8 s of that hides behind the probe below.
    // And the Wi-Fi figure it reads is whatever the radio last sent a
    // frame at - so sampling it while the line is running flat out is
    // the one moment a single sample describes the association rather
    // than one idle exchange (the daemon does not need that: it takes
    // the median of three probes instead, which a one-shot cannot).
    //
    // It overlaps the NETWORK leg and not the compute or disk legs on
    // purpose: a subprocess competing with the all-core verify bench
    // would depress a figure this command reports, where 8 s of
    // network-bound transfer does not notice it.
    //
    // The route is taken to the first server actually probed - the one
    // these bytes come from. The daemon's loop uses the first ENABLED
    // server, which differs only when that server is billed per byte
    // and sits this out; either way both take the default route to the
    // same link on any normal machine.
    let (link_host, link_port) = (probe_servers[0].host.clone(), probe_servers[0].port);
    let mut link_probe = tokio::task::spawn_blocking(move || {
        crate::locallink::probe_local_link(&link_host, link_port)
    });
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
    // Usually already done. When it is not, say so rather than sitting
    // silent on a finished-looking benchmark.
    let link =
        match tokio::time::timeout(std::time::Duration::from_millis(300), &mut link_probe).await {
            Ok(r) => r.ok().flatten(),
            Err(_) => {
                print!("network: reading this machine's own network link… ");
                std::io::stdout().flush().ok();
                let r = link_probe.await.ok().flatten();
                println!("done");
                r
            }
        };
    // This standalone probe has no daemon settings to read, so it
    // reports against the shipped default (`fast_verify` on since 21
    // Jul 2026, TODO §10) - what an out-of-the-box download actually
    // does. Both ceilings are still on the report either way.
    let mut v = nzbkit::sysbench::verdict(net, &compute, disk, true);
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
    // Gated exactly as the daemon path is (`measure_system` in
    // serve/groupscan.rs): only when the network row IS the limit,
    // because that is when the advice below tells the reader to add
    // connections or another provider - and that is the reading this
    // corrects on a machine sitting at its own link's ceiling.
    // `measured_note` decides the rest and is empty unless the figure
    // actually reached that ceiling, so this never puts a second
    // opinion beside a healthy row.
    if v.bottleneck == "network"
        && let Some(l) = &link
    {
        v.network_link = l.measured_note((net * 1e9 / 8.0) as u64);
    }
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
    // Above the advice, as on the dashboard card: it is the qualifier
    // that tells the reader whether the advice can help them at all.
    if !v.network_link.is_empty() {
        println!("\n{}", v.network_link);
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
                        let raw = pool.adopt(raw);
                        raw_bytes.fetch_add(raw.len() as u64, Ordering::Relaxed);
                        match nzbkit::yenc_simd::decode(&raw) {
                            Ok(_) => ok.fetch_add(1, Ordering::Relaxed),
                            Err(_) => bad.fetch_add(1, Ordering::Relaxed),
                        };
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

/// The single server a one-connection lane should talk to: the first
/// ENABLED entry, in config order.
///
/// The `enabled` filter is the whole point of this function and is not a
/// refinement. Until 23 Aug 2026 this was `cfg.servers[0].clone()`, which
/// consulted the flag nowhere - so on any install whose FIRST configured
/// server is the switched-off one, every caller here dialled the one
/// account the user had taken out of service. That is not theoretical: it
/// was found in the field holding seven established sockets to a disabled
/// provider, opened by the hourly group-profile sampler
/// (`serve::groupscan::sample_one_group`), while a benchmark round on
/// another machine was using that same shared account. Nothing in the log named the
/// host, because only the download planner prints "<host> disabled - not
/// in the pool" and no download had run - so the switch looked like it was
/// holding for four days while it was not.
///
/// Deliberately an ERROR rather than a fallback to `servers[0]` when
/// everything is off. "The user disabled every server" and "the user has
/// no servers" are the same instruction, and the §154 queue hold already
/// treats them alike; quietly dialling a disabled account to avoid an
/// error message is exactly the behaviour this function is being fixed for.
pub(crate) fn load_server(config: &Path) -> Result<ServerConfig> {
    let cfg = Config::load(config).with_context(|| {
        format!(
            "loading {} (copy config.local.json.example?)",
            config.display()
        )
    })?;
    cfg.servers
        .iter()
        .find(|s| s.enabled)
        .cloned()
        .with_context(|| {
            format!(
                "no enabled server in {} ({} configured, all switched off)",
                config.display(),
                cfg.servers.len()
            )
        })
}

/// Resolve a marks server key (see [`nzbkit::index::Index::server_key`])
/// back to its config entry - the scan loop persists only the key.
/// None = the config no longer carries that server, or no longer carries
/// it ENABLED.
///
/// `enabled` is part of "carries". The key is written by the full pass out
/// of [`scan_servers`], which is already enabled-only, but it OUTLIVES the
/// config: a server switched off after the pass that chose it leaves its
/// key in the index until the next full pass re-chooses, and resolving
/// that key unfiltered handed the tip watcher a disabled account to hold a
/// session on. `None` is the right answer and the caller already handles
/// it - it skips the group until the next pass, exactly as it does for a
/// key naming a server that was deleted outright.
#[cfg(feature = "indexer")]
pub(crate) fn find_scan_server(config: &Path, key: &str) -> Option<ServerConfig> {
    let cfg = Config::load(config).ok()?;
    cfg.servers
        .iter()
        .find(|s| s.enabled && nzbkit::index::Index::server_key(&s.host) == key)
        .cloned()
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

pub(crate) async fn probe(config: &Path, post_check: bool) -> Result<()> {
    let cfg = Config::load(config)?;
    for server in &cfg.servers {
        print!("{:<28}", server.host);
        let t0 = Instant::now();
        match Connection::connect(server).await {
            Ok((mut conn, greeting)) => {
                let connected = t0.elapsed();
                let mut rtts = Vec::new();
                for _ in 0..3 {
                    let t = Instant::now();
                    conn.exec("DATE").await?;
                    rtts.push(t.elapsed());
                }
                let avg = rtts.iter().sum::<std::time::Duration>() / rtts.len() as u32;
                let caps = conn.capabilities().await.unwrap_or_default();
                let pipelining = caps.iter().any(|c| c.contains("PIPELINING"));
                let g = conn.group("alt.binaries.boneless").await;
                print!(
                    " ok: auth {:>4}ms · RTT {:>5.1}ms · PIPELINING {} · boneless {}",
                    connected.as_millis(),
                    avg.as_secs_f64() * 1000.0,
                    if pipelining { "yes" } else { "n/a" },
                    if g.is_ok() { "ok" } else { "MISSING" },
                );
                if !post_check {
                    println!();
                    conn.quit().await;
                    continue;
                }
                // Posting capability WITHOUT posting anything. Three
                // tiers of evidence, weakest first: the greeting code
                // (RFC 3977: 200 = posting allowed, 201 = reading
                // only), the CAPABILITIES advertisement, and the
                // definitive one - issue POST and read the answer,
                // which arrives BEFORE any article data (340 = go
                // ahead, 440 = posting not permitted). On a 340 the
                // connection is dropped without sending a byte; a
                // close before the terminating dot discards the
                // article, so nothing ever reaches the group. QUIT
                // must NOT be sent after a 340 - the server would
                // read it as article content.
                let advertised = caps.iter().any(|c| c.trim() == "POST");
                print!(
                    " · greeting {} · caps POST {}",
                    greeting.code(),
                    if advertised { "yes" } else { "no" },
                );
                match conn.exec("POST").await {
                    Ok(st) if st.code() == 340 => {
                        println!(" · POST → 340: CAN POST (aborted, nothing sent)");
                        drop(conn);
                    }
                    Ok(st) if st.code() == 440 => {
                        println!(" · POST → 440: posting not permitted");
                        conn.quit().await;
                    }
                    Ok(st) => {
                        println!(" · POST → {} {}", st.code(), st.line());
                        conn.quit().await;
                    }
                    Err(e) => {
                        println!(" · POST probe failed: {e}");
                    }
                }
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
/// The multipart boundary the `addfile` submit uses. Named once: the
/// body builder and the `Content-Type` header have to agree, and they
/// are no longer in the same function.
const STREAM_BOUNDARY: &str = "----nzbfaststream";

/// Percent-encode everything that is not an unreserved character.
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

/// A v6 literal carrying an INTERFACE SCOPE, in any spelling this
/// command can be handed one: `fe80::1%en0`, the RFC 6874
/// `fe80::1%25en0`, bracketed or bare, with or without a `:port`.
///
/// It exists because A URL AUTHORITY CANNOT CARRY ONE, and that is a
/// property of the WHATWG URL standard rather than of `ureq` or of this
/// code: `url` 2.5.8's IPv6 parser has no `%` branch at all, so it
/// refuses `%en0`, the percent-encoded `%25en0` and even a numeric
/// `%26` alike. Every browser address bar refuses them for the same
/// reason, which is why the dashboard could never take the spelling
/// either. Measured in two independent implementations of that standard
/// on 27 Aug 2026 (`research/STREAM-FE80-SCOPE-ID-2026-08-27.md`).
///
/// So a scoped literal is REFUSED HERE, at the spelling, rather than
/// built into a base that dies later at URL parse - which is what it did
/// until 27 Aug 2026, under the headline "no daemon at ... start one
/// with `nzbfast serve`", sending the user to look for a daemon that was
/// running fine. The bare spelling reached the OTHER arm below and was
/// told to bracket itself, which produces exactly that base: advice that
/// dead-ends.
///
/// WHAT IS LOST IS SMALLER THAN IT LOOKS, and the refusal names the
/// replacement, because one that does not is just a later dead end. A
/// NAME carries the scope by itself: getaddrinfo fills in
/// `sin6_scope_id` and returns one answer per (address, interface) pair,
/// so `--host nas.local` reaches a daemon listening on nothing but a
/// scoped link-local address - measured end to end the same day, against
/// a listener bound to no other address. Reaching a scoped literal
/// additionally needs a daemon started off its default `--bind 0.0.0.0`,
/// which is IPv4-only. The pre-URL submit (`d55d0c879^`) did reach the
/// BARE spelling, through `TcpStream::connect((host, port))`; the
/// BRACKETED one has never worked in any release, because std does not
/// strip brackets before handing the host to getaddrinfo.
fn has_v6_scope_id(h: &str) -> bool {
    // Bracketed or not: the zone sits INSIDE the brackets, so the
    // address is whatever precedes the literal's first '%'.
    let inner = match h.strip_prefix('[') {
        Some(r) => r.split(']').next().unwrap_or(r),
        None => h,
    };
    // Only a real v6 literal. A '%' anywhere else - a percent-encoded
    // byte in a host name, say - is somebody else's mistake and earns
    // somebody else's message.
    inner
        .split_once('%')
        .is_some_and(|(addr, _)| addr.parse::<std::net::Ipv6Addr>().is_ok())
}

/// The refusal [`has_v6_scope_id`] earns: the cause, and the spellings
/// that do work. Written once because both arms of [`daemon_base`] reach
/// it, and a message that drifts between them is one nobody can grep
/// for.
///
/// The example zone is FIXED rather than echoed back from what the user
/// typed. Echoing it re-derives the percent-encoded form by prepending
/// `25`, which is right for `%en0` and gibberish for somebody who has
/// already tried `%25en0`: they were told not to type `%2525en0`. What
/// they typed is quoted at the head of the message anyway, so nothing is
/// lost by naming the RULE instead of their own string.
fn scoped_v6_refusal(host: &str) -> anyhow::Error {
    anyhow::anyhow!(
        "--host {host:?}: a URL cannot carry an interface scope, so an IPv6 address with a \
         `%<interface>` suffix has no spelling this client can use - neither the bare `%en0` \
         form nor the percent-encoded `%25en0` one. Name the daemon instead \
         (--host nas.local): a name carries the scope for you. Or give it an address that \
         needs none - a ULA or global IPv6 address, or its IPv4 address."
    )
}

/// The daemon base URL that `--host` and `--port` name, with no trailing
/// slash.
///
/// `--host` takes either shape. A BARE host is what this command has
/// always taken and keeps its meaning exactly - plaintext, on `--port`.
/// A full `http(s)://` base is the new one, and it is the only way to
/// reach a daemon started with `--tls-cert`/`--tls-key`: that serves ONE
/// listener and ONE scheme, so a plaintext-only client cannot address it
/// by any spelling of a host name.
///
/// A port INSIDE the URL wins over `--port`. A URL that names none takes
/// `--port`, and deliberately not the scheme default: nzbfast's daemon
/// answers on 6789 whichever scheme it serves, so 443 would be the wrong
/// guess for every real install.
///
/// BRACKETS FIRST for IPv6, the rule `notify::smtp::send_email` and
/// `Daemon::predb_irc_config` already write down: a literal v6 address is
/// full of colons, so `rsplit_once(':')` reads the last one as the port
/// separator. A bare `--host ::1` is bracketed on the way in, because the
/// old code handed it to `TcpStream::connect` as a tuple and a URL cannot
/// take it unbracketed.
///
/// A PATH is refused rather than ignored. Nothing here serves the API
/// under a prefix, and silently dropping one would send the request
/// somewhere the user did not name.
fn daemon_base(host: &str, port: u16) -> Result<String> {
    let h = host.trim();
    if h.is_empty() {
        anyhow::bail!("--host is empty");
    }
    // The SCHEME is split off before any trailing slash is trimmed.
    // Trimming first turns a bare `https://` into `https:`, which then
    // parses as a HOST called `https:` and dials `http://https::6789` -
    // silently, and at a plaintext port.
    let Some((scheme, rest)) = h.split_once("://") else {
        // Bare host: unchanged behaviour, plus the bracketing a URL needs.
        let h = h.trim_end_matches('/');
        if h.is_empty() || h.contains(['/', '?', '#']) {
            anyhow::bail!("--host {host:?}: give a host name, or a full http(s):// base");
        }
        // A scope id has no URL spelling at all, so it is refused at the
        // spelling rather than built into a base that dies at URL parse
        // under a headline blaming the daemon.
        if has_v6_scope_id(h) {
            return Err(scoped_v6_refusal(host));
        }
        // A bracketed literal may carry its own port, which wins over
        // `--port` the same way a port inside a full base does; one
        // without a port takes `--port`. Appending `:6789` after
        // `[::1]:8080` would be the quiet reinterpretation this
        // function's contract refuses.
        if let Some(inner) = h.strip_prefix('[') {
            let Some(end) = inner.find(']') else {
                anyhow::bail!("--host {host:?}: unclosed '[' in an IPv6 literal");
            };
            let after = &inner[end + 1..];
            if after.is_empty() {
                return Ok(format!("http://{h}:{port}"));
            }
            if after
                .strip_prefix(':')
                .is_some_and(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
            {
                return Ok(format!("http://{h}"));
            }
            anyhow::bail!("--host {host:?}: what follows the ']' is not a :port");
        }
        // An unbracketed v6 literal is bracketed on the way in - the old
        // code handed it to TcpStream::connect as a tuple, and a URL
        // cannot take it unbracketed.
        if h.parse::<std::net::Ipv6Addr>().is_ok() {
            return Ok(format!("http://[{h}]:{port}"));
        }
        // The universal `host:port` spelling: its port wins over
        // `--port`. Not a v6 literal (checked above), so a second colon
        // means neither shape and is REFUSED rather than bracketed as
        // if it were one - the mangled URL would send the user chasing
        // a daemon that is running fine.
        return Ok(match h.rsplit_once(':') {
            Some((hh, p))
                if !hh.is_empty()
                    && !hh.contains(':')
                    && !p.is_empty()
                    && p.bytes().all(|b| b.is_ascii_digit()) =>
            {
                format!("http://{hh}:{p}")
            }
            Some(_) => anyhow::bail!(
                "--host {host:?}: not an IPv6 literal and not host:port - bracket a v6 \
                 address ([{h}]), or name the port with --port"
            ),
            None => format!("http://{h}:{port}"),
        });
    };
    let scheme = scheme.to_ascii_lowercase();
    if scheme != "http" && scheme != "https" {
        anyhow::bail!("--host {h}: only http:// and https:// bases are understood");
    }
    let rest = rest.trim_end_matches('/');
    if rest.is_empty() {
        anyhow::bail!("--host {h}: no host after the scheme");
    }
    if rest.contains(['/', '?', '#']) {
        anyhow::bail!(
            "--host {h}: give the daemon's base only (scheme, host and port) - \
             the API is served at the root, so a path here would not be used"
        );
    }
    // Same refusal in the scheme arm: `http://[fe80::1%en0]:6789` is the
    // spelling the bare arm's old advice produced, and it is the one the
    // URL parser refuses.
    if has_v6_scope_id(rest) {
        return Err(scoped_v6_refusal(host));
    }
    // An unbracketed v6 literal in a full base: bracket it the way the
    // bare-host path does, rather than reading its last group as a
    // port (or appending one), both of which yield a URL nothing can
    // parse.
    if rest.parse::<std::net::Ipv6Addr>().is_ok() {
        return Ok(format!("{scheme}://[{rest}]:{port}"));
    }
    let has_port = if let Some(inner) = rest.strip_prefix('[') {
        inner.split_once("]:").is_some()
    } else {
        rest.rsplit_once(':')
            .is_some_and(|(_, p)| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
    };
    Ok(if has_port {
        format!("{scheme}://{rest}")
    } else {
        format!("{scheme}://{rest}:{port}")
    })
}

/// A file name that can sit inside a quoted MIME header value without
/// closing it or starting a header line of its own. A name is chosen by
/// whoever wrote the file, which is not always whoever runs this.
///
/// Separate from [`stream_request`] so it can be tested on names that
/// CANNOT EXIST ON DISK. The first version of this test built its
/// hostile name by creating a real file, which is fine on macOS and
/// Linux and is refused outright by Windows - `"`, `\` and control
/// characters are all illegal in a Win32 path - so it passed every
/// local gate on this fleet and took `windows-unit` red on main. The
/// rule is the CLAUDE.md SIXTEENTH gate's: a test fixture that only
/// some platforms can build is a test only some platforms run.
fn mime_filename(name: &str) -> String {
    name.chars()
        .filter(|c| *c != '"' && *c != '\\' && !c.is_control())
        .collect()
}

/// The request `nzbfast stream` submits: the full URL, and the body
/// (empty for the GET shape).
///
/// **NO CREDENTIAL IS IN EITHER.** This used to splice `&apikey=<key>`
/// into the request target, which puts the key in every access log,
/// every proxy log and - via `--host`, which is any machine - on the
/// wire to a remote box. The key rides `X-Api-Key` now, the header the
/// daemon has merged into its param map since v1.0.14 and the one TODO
/// 61d moved the dashboard's own navigations onto. TODO 290 F-20.
///
/// Split out from the send - the shape [`player_argv`] already uses for
/// the player spawn - so a test can read the exact target and assert the
/// thing that is invisible at the call site.
fn stream_request(base: &str, nzb: &str) -> Result<(String, Vec<u8>)> {
    let lower = nzb.to_ascii_lowercase();
    if lower.starts_with("http://") || lower.starts_with("https://") {
        return Ok((
            format!(
                "{base}/api?mode=addurl&output=json&stream=1&name={}",
                urlenc(nzb)
            ),
            Vec::new(),
        ));
    }
    let bytes = std::fs::read(nzb).with_context(|| format!("reading {nzb}"))?;
    let fname = mime_filename(
        &std::path::Path::new(nzb)
            .file_name()
            .unwrap_or_default()
            .to_string_lossy(),
    );
    let mut b = Vec::new();
    b.extend_from_slice(
        format!(
            "--{STREAM_BOUNDARY}\r\nContent-Disposition: form-data; name=\"name\"; filename=\"{fname}\"\r\n\r\n"
        )
        .as_bytes(),
    );
    b.extend_from_slice(&bytes);
    b.extend_from_slice(format!("\r\n--{STREAM_BOUNDARY}--\r\n").as_bytes());
    Ok((format!("{base}/api?mode=addfile&output=json&stream=1"), b))
}

/// The warning a plaintext submit to a NON-loopback daemon earns, if it
/// earns one.
///
/// It is a warning and NOT a refusal, and that is a decision rather than
/// an omission. `nzbfast serve` binds `0.0.0.0` and speaks plain HTTP by
/// DEFAULT - a NAS reached from a laptop is the topology the product
/// documents - so a client that refused what the server's own default
/// serves would be this one subcommand disagreeing with `serve`. What is
/// worth saying is what the user cannot see: the key and the NZB cross
/// the network readable, and there is now a spelling that fixes it.
fn plaintext_remote_warning(base: &str) -> Option<String> {
    let rest = base.strip_prefix("http://")?;
    let hostname = match rest.strip_prefix('[') {
        Some(inner) => inner.split(']').next().unwrap_or("").to_string(),
        None => rest.rsplit_once(':').map_or(rest, |(h, _)| h).to_string(),
    };
    let local = hostname.eq_ignore_ascii_case("localhost")
        || hostname.eq_ignore_ascii_case("localhost.localdomain")
        || hostname
            .parse::<std::net::IpAddr>()
            .is_ok_and(|ip| ip.is_loopback());
    (!local).then(|| {
        // A v6 literal is printed BRACKETED, or the remedy dead-ends:
        // `daemon_base` reads an unbracketed literal's last group as a
        // port, and only the bracketed spelling parses.
        let spelling = if hostname.contains(':') {
            format!("[{hostname}]")
        } else {
            hostname.clone()
        };
        format!(
            "warning: {hostname} is not this machine and the request is plain HTTP, so the API \
             key and the NZB cross the network readable. Serve the daemon with --tls-cert/--tls-key \
             and pass --host https://{spelling} to encrypt it."
        )
    })
}

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
    let base = daemon_base(host, port)?;
    let (url, body) = stream_request(&base, nzb)?;
    if let Some(w) = plaintext_remote_warning(&base) {
        eprintln!("{w}");
    }
    // The crate's shared client, not a hand-rolled socket: that is what
    // makes an `https://` base reachable at all, and what puts this on
    // the same trust anchors (`NZBFAST_EXTRA_CA`) as every other TLS
    // path here. Generous timeout - an `addurl` submit waits for the
    // daemon to fetch the NZB from wherever it lives.
    let agent = crate::netfetch::daemon_api_agent(120);
    let mut req = agent.request(if body.is_empty() { "GET" } else { "POST" }, &url);
    if let Some(k) = apikey {
        req = req.set("X-Api-Key", k);
    }
    let sent = if body.is_empty() {
        req.call()
    } else {
        req.set(
            "Content-Type",
            &format!("multipart/form-data; boundary={STREAM_BOUNDARY}"),
        )
        .send_bytes(&body)
    };
    let (code, text) = match sent {
        Ok(r) => (r.status(), r.into_string().unwrap_or_default()),
        Err(ureq::Error::Status(c, r)) => (c, r.into_string().unwrap_or_default()),
        Err(ureq::Error::Transport(t)) => {
            let brief = crate::notify::transport_brief(&t);
            // Our OWN guard refusing the address is not "nothing is
            // listening", and telling that user to start a daemon sends
            // them to look in the wrong place.
            if brief.contains("refusing to fetch an internal address") {
                anyhow::bail!("--host {base}: {brief}");
            }
            anyhow::bail!(
                "no daemon at {base} - start one with `nzbfast serve` ({brief}){}",
                if base.starts_with("https://") {
                    "\n  self-signed certificate? point this client at it with \
                     NZBFAST_EXTRA_CA=<cert.pem>"
                } else {
                    ""
                }
            );
        }
    };
    if (300..400).contains(&code) {
        anyhow::bail!(
            "{base} answered {code} (a redirect). This client does not follow one, because the \
             API key rides a header and a redirect would carry it to whatever host answered. \
             Point --host at the daemon itself."
        );
    }
    let snippet: String = text.trim().chars().take(200).collect();
    let v: serde_json::Value = serde_json::from_str(text.trim())
        .with_context(|| format!("bad daemon response ({code}): {snippet}"))?;
    if v["status"].as_bool() != Some(true) {
        anyhow::bail!(
            "daemon refused: {}",
            v["error"].as_str().unwrap_or(&snippet)
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
        match player_argv(&m3u) {
            Ok((prog, args)) => match std::process::Command::new(prog).args(args).status() {
                Ok(st) if st.success() => println!("  handed to the default player"),
                _ => println!("  (couldn't launch a player - open the link above manually)"),
            },
            Err(param) => println!(
                "  (not launching a player: that daemon's player link carries `{param}=`, and a \
                 child process's command line is readable by every other account on this \
                 machine. Open the link above yourself, or update the daemon.)"
            ),
        }
    }
    Ok(())
}

/// A query parameter that is a CREDENTIAL, if this URL carries one.
///
/// Only the query is judged, and only a parameter NAME: `apikey` in a
/// path segment or a hostname is not a key, and refusing on it would
/// cost a launch for nothing. Case-insensitive because the API accepts
/// the parameter either way, and all three spellings the daemon's own
/// auth reads are listed - a link is refused on what it could be
/// carrying, not on what this version happens to build.
///
/// A FRAGMENT counts. A `#` tail never reaches the server, so it is not
/// a credential in transit - but this function is about what lands in
/// ARGV, and `#apikey=` is as readable there as `?apikey=` is.
fn credential_param(url: &str) -> Option<&'static str> {
    let q = url.find(['?', '#']).map(|i| &url[i + 1..])?;
    q.split(['&', ';', '#']).find_map(|p| {
        let name = p
            .split('=')
            .next()
            .unwrap_or("")
            .trim()
            .to_ascii_lowercase();
        match name.as_str() {
            "apikey" => Some("apikey"),
            "api_key" => Some("api_key"),
            "nzbkey" => Some("nzbkey"),
            _ => None,
        }
    })
}

/// The exact command line [`stream_cmd`] hands the player, and the one
/// rule about it: no credential is in it.
///
/// Split out from the spawn - the shape `serve::bootstrap::dashboard_argv_in`
/// uses for the browser launch - so a test can read what the child would
/// be given and assert the thing that is invisible at the call site. A
/// spawned process's command line is readable by every other account on
/// the box (Linux `/proc/<pid>/cmdline` is world-readable, macOS `ps`
/// shows other users' arguments, the Windows line comes out of WMI), and
/// with the API key comes `mode=server_secret`, the Usenet password in
/// cleartext. That is TODO 23 low1, which closed the browser launch and
/// deliberately left this one; the daemon now builds its `m3u` link with
/// the JOB's own `?t=` capability token, so the ordinary answer carries
/// nothing worth reading off a `ps`.
///
/// A link that still names a key came from a daemon older than that
/// change - `--host` is any machine - and is REFUSED rather than
/// spawned. The point of the fix is that the credential does not travel
/// as an argument, and the caller prints the link so the user can open
/// it themselves. Refusing is also what keeps the fix honest as the flag
/// grows: `--apikey` has no env or config fallback today, so the key is
/// already on the user's own command line before any child exists, and
/// the day somebody adds one this path must not quietly become the leak
/// that was just closed.
fn player_argv(m3u: &str) -> std::result::Result<(&'static str, Vec<String>), &'static str> {
    if let Some(p) = credential_param(m3u) {
        return Err(p);
    }
    #[cfg(target_os = "macos")]
    let argv = ("open", vec![m3u.to_string()]);
    // Windows: explorer, NOT `cmd /C start` - cmd re-parses its command
    // line, so metacharacters (&, ^, %) in the string would execute. This
    // string is the daemon's `m3u` field, read over plaintext HTTP from a
    // possibly-remote `--host`, so an on-path attacker answering
    // {"m3u":"http://h/x&calc.exe"} got arbitrary execution. Same rule the
    // daemon's own os_open already follows for exactly this reason.
    #[cfg(target_os = "windows")]
    let argv = ("explorer", vec![m3u.to_string()]);
    #[cfg(not(any(target_os = "macos", target_os = "windows")))]
    let argv = ("xdg-open", vec![m3u.to_string()]);
    Ok(argv)
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

/// TODO 23 low1, CLI half: what `nzbfast stream` hands the player.
#[cfg(test)]
mod player_handoff {
    use super::*;

    /// The API key must never reach the player child's argv - the same
    /// rule `the_browser_argv_never_carries_the_api_key` pins on the
    /// dashboard launch, and the same reason: a child's command line is
    /// readable by every other local account, and with the key comes
    /// `mode=server_secret` (the Usenet password in cleartext).
    ///
    /// Asserted against the argv the spawn really uses, including the
    /// program name, because the leak was one `format!` away from looking
    /// correct.
    #[test]
    fn the_player_argv_never_carries_a_credential() {
        const KEY: &str = "1f8b0e5c2d4a6b8c0e1f2a3b4c5d6e7f8a9b0c1d2e3f4a5b";
        // What a current daemon answers with: the job's own capability
        // token, which /m3u accepts and which starts that job and nothing
        // else. Fine to spawn.
        const OK: &str = "http://nas.local:6789/m3u/SABnzbd_nzo_nzbfast1?t=0123456789abcdef";
        let (prog, args) = player_argv(OK).expect("a tokened link is spawnable");
        assert_ne!(
            prog, "cmd",
            "cmd re-parses its command line, so `&calc.exe` in a remote daemon's answer runs"
        );
        assert_eq!(args.iter().filter(|a| a.contains(KEY)).count(), 0);
        assert_eq!(args.last().map(String::as_str), Some(OK));
        // A daemon older than the fix still answers with the key in the
        // link. Refused, naming the parameter - never spawned.
        for (url, want) in [
            (format!("http://h:6789/m3u/nzo_1?apikey={KEY}"), "apikey"),
            (
                format!("http://h:6789/m3u/nzo_1?t=abc&apikey={KEY}"),
                "apikey",
            ),
            (format!("http://h:6789/m3u/nzo_1?API_KEY={KEY}"), "api_key"),
            (format!("http://h:6789/m3u/nzo_1?nzbkey={KEY}"), "nzbkey"),
        ] {
            assert_eq!(player_argv(&url), Err(want), "spawned a keyed link: {url}");
        }
    }

    /// Only a parameter NAME counts. A path or host that merely spells
    /// the word is not a credential, and refusing on it would cost a
    /// launch for nothing; a keyless daemon's link has no query at all.
    #[test]
    fn a_credential_is_a_query_parameter_and_not_a_substring() {
        assert_eq!(credential_param("http://h:6789/m3u/nzo_1"), None);
        assert_eq!(credential_param("http://h:6789/m3u/nzo_1?t=abcd"), None);
        assert_eq!(
            credential_param("http://apikey.example/m3u/nzo_1?t=a"),
            None
        );
        assert_eq!(credential_param("http://h/m3u/apikey=1?t=a"), None);
        // Value-side mentions are not names either.
        assert_eq!(credential_param("http://h/m3u/n?t=apikey%3Dx"), None);
        assert_eq!(credential_param("http://h/m3u/n?t=a#frag"), None);
        // …but the real thing is caught wherever it sits in the query.
        assert_eq!(credential_param("http://h/m3u/n?apikey=k"), Some("apikey"));
        assert_eq!(
            credential_param("http://h/m3u/n?t=a&ApiKey=k"),
            Some("apikey")
        );
        // A fragment never reaches the server, but it is still argv.
        assert_eq!(
            credential_param("http://h/m3u/n?t=a#apikey=k"),
            Some("apikey")
        );
        assert_eq!(credential_param("http://h/m3u/n#apikey=k"), Some("apikey"));
    }
}

#[cfg(test)]
mod stream_submit {
    use super::*;

    /// TODO 290 F-20, the half that leaked. The key used to be spliced
    /// into the request target as `&apikey=<key>`, which puts it in the
    /// daemon's access log, in any reverse proxy in front of it, and -
    /// because `--host` is any machine - on the wire to a remote box.
    /// It rides `X-Api-Key` now, and NO target this command builds may
    /// name a credential in any spelling, in either submit shape.
    ///
    /// Asserted against the real target rather than against the absence
    /// of a `format!` argument: the leak was one interpolation away from
    /// looking correct, which is why `credential_param` exists at all.
    #[test]
    fn no_submit_target_ever_carries_a_credential() {
        let base = "http://nas.local:6789";
        let (url, body) = stream_request(base, "https://idx.example/get/abc.nzb").unwrap();
        assert!(body.is_empty(), "an http(s) nzb is the GET shape");
        assert_eq!(credential_param(&url), None, "{url}");
        let (_scratch, f) = tmp_nzb("nocred", b"<nzb/>");
        let (url, body) = stream_request(base, f.to_str().unwrap()).unwrap();
        assert!(!body.is_empty(), "a file nzb is the POST shape");
        assert_eq!(credential_param(&url), None, "{url}");
        // …and not merely absent from the query: nothing that looks like
        // a key is anywhere in either target.
        for u in [
            stream_request(base, "https://idx.example/x.nzb").unwrap().0,
            stream_request(base, f.to_str().unwrap()).unwrap().0,
        ] {
            let low = u.to_ascii_lowercase();
            for name in ["apikey", "api_key", "nzbkey"] {
                assert!(!low.contains(name), "{u} names {name}");
            }
        }
    }

    /// The submit targets themselves, so a reshuffle of the query has to
    /// be deliberate. `mode`, `output` and `stream=1` are what the daemon
    /// dispatches on; the URL shape percent-encodes the whole link, so an
    /// `&` inside it cannot start a parameter of our own.
    #[test]
    fn the_submit_targets_are_the_two_api_shapes() {
        let (url, _) = stream_request(
            "https://nas.local:6789",
            "https://idx.example/g?id=1&apikey=SEKRIT",
        )
        .unwrap();
        assert_eq!(
            url,
            "https://nas.local:6789/api?mode=addurl&output=json&stream=1\
             &name=https%3A%2F%2Fidx.example%2Fg%3Fid%3D1%26apikey%3DSEKRIT"
        );
        // The indexer's own key is inside the encoded NAME, which is a
        // value and not a parameter of ours - the daemon needs the link
        // whole to fetch it.
        assert_eq!(credential_param(&url), None);
        let (_scratch, f) = tmp_nzb("shape", b"<nzb/>");
        let (url, _) = stream_request("http://127.0.0.1:6789", f.to_str().unwrap()).unwrap();
        assert_eq!(
            url,
            "http://127.0.0.1:6789/api?mode=addfile&output=json&stream=1"
        );
    }

    /// A filename reaches a MIME header, so it must not be able to close
    /// the quoted string or open a second header line. Whoever wrote the
    /// file is not always whoever runs this.
    ///
    /// Driven through `mime_filename` on a name that CANNOT EXIST ON
    /// DISK, rather than by creating a file called it. The first version
    /// of this test did create one, which macOS and Linux allow and
    /// Windows refuses outright - `"`, `\` and control characters are
    /// illegal in a Win32 path - so it passed every gate on this fleet
    /// and took `windows-unit` red on main. A fixture only some
    /// platforms can build is a test only some platforms run.
    #[test]
    fn a_hostile_filename_cannot_forge_a_multipart_header() {
        let clean = mime_filename("evil\"\r\nX-Injected: 1\\x");
        // The injected text survives as inert characters - what must not
        // survive is its ability to end the quoted value or to start a
        // line.
        assert!(!clean.contains('"'), "{clean:?}");
        assert!(!clean.contains('\\'), "{clean:?}");
        assert!(!clean.chars().any(char::is_control), "{clean:?}");
        assert_eq!(clean, "evilX-Injected: 1x");
        // A name that needs no cleaning is passed through untouched.
        assert_eq!(
            mime_filename("Some.Show.S01E01.nzb"),
            "Some.Show.S01E01.nzb"
        );
        // And the header the real body builds from such a name is one
        // line carrying exactly its two quoted values.
        let (_scratch, f) = tmp_nzb("shape-guard.nzb", b"PAYLOAD");
        let (_, body) = stream_request("http://h:6789", f.to_str().unwrap()).unwrap();
        let whole = String::from_utf8_lossy(&body).to_string();
        let head = whole.split("\r\n\r\n").next().unwrap().to_string();
        assert_eq!(head.lines().count(), 2, "one header line only: {head:?}");
        assert_eq!(
            head.matches('"').count(),
            4,
            "two quoted values only: {head}"
        );
        assert!(head.starts_with(&format!("--{STREAM_BOUNDARY}\r\nContent-Disposition:")));
        assert!(
            body.ends_with(format!("\r\n--{STREAM_BOUNDARY}--\r\n").as_bytes()),
            "the body must still close the multipart"
        );
    }

    /// TODO 290 F-20, the half that made a TLS daemon unreachable. A
    /// bare `--host` keeps its old plaintext meaning exactly; a full
    /// base is the new spelling, and it is the only way to address a
    /// `--tls-cert` daemon, which serves one listener and one scheme.
    #[test]
    fn a_host_is_either_a_bare_name_or_a_full_base() {
        // Unchanged: the shape every existing caller passes.
        assert_eq!(
            daemon_base("127.0.0.1", 6789).unwrap(),
            "http://127.0.0.1:6789"
        );
        assert_eq!(
            daemon_base("nas.local", 8080).unwrap(),
            "http://nas.local:8080"
        );
        // New: a scheme is honoured, and https is what a --tls-cert
        // daemon answers.
        assert_eq!(
            daemon_base("https://nas.local", 6789).unwrap(),
            "https://nas.local:6789"
        );
        // A port INSIDE the URL wins over --port…
        assert_eq!(
            daemon_base("https://nas.local:443", 6789).unwrap(),
            "https://nas.local:443"
        );
        // …and a URL without one takes --port, NOT the scheme default:
        // the daemon answers on 6789 whichever scheme it serves.
        assert_eq!(
            daemon_base("https://nas.local", 9999).unwrap(),
            "https://nas.local:9999"
        );
        // Scheme case is not the user's problem, and a trailing slash is
        // what a copied browser address bar hands you.
        assert_eq!(
            daemon_base("HTTPS://nas.local:6789/", 1).unwrap(),
            "https://nas.local:6789"
        );
    }

    /// Brackets first, the rule `notify::smtp::send_email` already
    /// writes down: a literal v6 address is full of colons, so the last
    /// one is not a port separator. The bare form has to be bracketed on
    /// the way in too - the old code handed it to `TcpStream::connect`
    /// as a tuple, and a URL cannot take it unbracketed.
    #[test]
    fn an_ipv6_literal_is_bracketed_and_its_colons_are_not_a_port() {
        assert_eq!(daemon_base("::1", 6789).unwrap(), "http://[::1]:6789");
        assert_eq!(
            daemon_base("http://[2001:db8::1]", 6789).unwrap(),
            "http://[2001:db8::1]:6789"
        );
        assert_eq!(
            daemon_base("http://[2001:db8::1]:8080", 6789).unwrap(),
            "http://[2001:db8::1]:8080"
        );
        assert_eq!(daemon_base("[::1]", 6789).unwrap(), "http://[::1]:6789");
        // A bracketed literal's own port wins over --port; :6789 must
        // NOT be appended after it.
        assert_eq!(
            daemon_base("[::1]:8080", 6789).unwrap(),
            "http://[::1]:8080"
        );
        // A full base carrying an unbracketed v6 literal is bracketed,
        // not read as host "2001" port "db8::5" - this is the spelling
        // plaintext_remote_warning used to print.
        assert_eq!(
            daemon_base("https://2001:db8::5", 6789).unwrap(),
            "https://[2001:db8::5]:6789"
        );
    }

    /// The universal `host:port` spelling parses as host plus port
    /// rather than being bracketed as if it were a v6 literal - the
    /// mangled `http://[nas.local:8080]:6789` diagnosed a healthy
    /// daemon as absent.
    #[test]
    fn a_bare_host_port_is_a_host_and_a_port() {
        assert_eq!(
            daemon_base("nas.local:8080", 6789).unwrap(),
            "http://nas.local:8080"
        );
        assert_eq!(
            daemon_base("192.168.1.9:8080", 6789).unwrap(),
            "http://192.168.1.9:8080"
        );
        // Neither a v6 literal nor host:port is refused, never guessed.
        for bad in ["nas.local:http", "a:b:c", "[::1", "[::1]x"] {
            assert!(daemon_base(bad, 6789).is_err(), "{bad:?} must be refused");
        }
    }

    /// An IPv6 SCOPE ID is refused at the spelling, in every spelling,
    /// and the refusal names what to type instead.
    ///
    /// A URL authority cannot carry one: `url` 2.5.8's IPv6 parser has no
    /// `%` branch at all, so the bare form, the RFC 6874 percent-encoded
    /// form and a numeric zone are refused alike, and every browser's
    /// address bar refuses them for the same reason (both measured
    /// 27 Aug 2026). Until then `daemon_base` BUILT a base out of the
    /// bracketed spelling and let it die at URL parse, which `stream_cmd`
    /// then reported as "no daemon at ... start one with `nzbfast serve`"
    /// - a person sent to look for a daemon that was running fine.
    ///
    /// The last assertion is the one with the history behind it. The bare
    /// spelling used to be told to BRACKET itself, and bracketing is what
    /// produces the base that cannot parse, so the old advice was a loop.
    /// A refusal that does not name the working spelling only moves the
    /// dead end, so the message is pinned on naming one.
    #[test]
    fn an_ipv6_scope_id_is_refused_with_the_spelling_that_works() {
        for bad in [
            "fe80::1%en0",   // the bare form the pre-URL submit reached
            "[fe80::1%en0]", // what the old advice told you to type
            "[fe80::1%en0]:8080",
            "fe80::1%en0:8080",
            "fe80::1%25en0", // RFC 6874, refused by the URL parser too
            "[fe80::1%25en0]",
            "[fe80::1%1]",               // a NUMERIC zone is no better
            "http://[fe80::1%en0]:6789", // and the same in a full base
            "https://[fe80::1%en0]",
            "http://fe80::1%en0",
        ] {
            let e = daemon_base(bad, 6789)
                .expect_err(&format!("{bad:?} must be refused, never built into a base"))
                .to_string();
            assert!(
                e.contains("interface scope"),
                "{bad:?} must be refused for the RIGHT reason: {e}"
            );
            // The replacement, or the refusal is just a later dead end.
            assert!(
                e.contains("nas.local"),
                "{bad:?} must name a spelling that works: {e}"
            );
            // And never the advice that produced the unparseable base.
            assert!(
                !e.contains("bracket a v6"),
                "{bad:?} must not be told to bracket itself: {e}"
            );
        }
        // The scope id is the whole of what is refused: the same
        // addresses without one keep working, in both arms.
        assert_eq!(
            daemon_base("fe80::1", 6789).unwrap(),
            "http://[fe80::1]:6789"
        );
        assert_eq!(
            daemon_base("[fe80::1]:8080", 6789).unwrap(),
            "http://[fe80::1]:8080"
        );
        assert_eq!(
            daemon_base("http://[fe80::1]:6789", 1).unwrap(),
            "http://[fe80::1]:6789"
        );
        // And a '%' that is not a v6 zone earns somebody else's message,
        // not this one.
        for other in ["nas%20local", "nas.local"] {
            let msg = daemon_base(other, 6789).unwrap_or_else(|e| e.to_string());
            assert!(!msg.contains("interface scope"), "{other:?}: {msg}");
        }
    }

    /// A base this command cannot honour is REFUSED, never quietly
    /// reinterpreted: a dropped path would send the submit somewhere the
    /// user did not name, and a foreign scheme is a typo worth reading.
    #[test]
    fn an_unusable_base_is_refused_rather_than_reinterpreted() {
        for bad in [
            "https://nas.local/nzbfast",
            "https://nas.local:6789/api",
            "https://nas.local:6789?x=1",
            "ftp://nas.local",
            "unix://var/run/x",
            "https://",
            "",
            "   ",
        ] {
            assert!(daemon_base(bad, 6789).is_err(), "{bad:?} must be refused");
        }
    }

    /// Plain HTTP to a machine that is not this one earns a WARNING and
    /// not a refusal - `nzbfast serve` binds 0.0.0.0 and speaks plain
    /// HTTP by default, so refusing what the server's own default serves
    /// would break every working LAN install. Loopback is silent, and so
    /// is TLS anywhere.
    #[test]
    fn a_plaintext_submit_off_this_machine_warns_and_is_not_refused() {
        for quiet in [
            "http://127.0.0.1:6789",
            "http://localhost:6789",
            "http://[::1]:6789",
            "https://nas.local:6789",
            "https://203.0.113.7:6789",
        ] {
            assert_eq!(plaintext_remote_warning(quiet), None, "{quiet}");
        }
        for loud in ["http://nas.local:6789", "http://192.168.1.9:6789"] {
            let w = plaintext_remote_warning(loud).expect(loud);
            // The message must name the fix, or it is only an alarm.
            assert!(w.contains("--tls-cert"), "{w}");
            assert!(w.contains("--host https://"), "{w}");
        }
        // A v6 remedy has to be the spelling daemon_base can parse: the
        // BRACKETED literal, not the bare one whose last group reads as
        // a port.
        let w = plaintext_remote_warning("http://[2001:db8::5]:6789").expect("v6 remote warns");
        assert!(w.contains("--host https://[2001:db8::5]"), "{w}");
        assert!(
            daemon_base("https://[2001:db8::5]", 6789).is_ok(),
            "and that spelling round-trips through daemon_base"
        );
    }

    /// The guard comes back with the path because the file lives inside
    /// it: this used to `create_dir_all` and hand back a bare path with
    /// nothing removing it, one `$TMPDIR` entry per name per run
    /// forever. See `crates/nzbfast/tests/scratch/mod.rs`.
    fn tmp_nzb(name: &str, bytes: &[u8]) -> (crate::testscratch::ScratchDir, std::path::PathBuf) {
        let d = crate::testscratch::ScratchDir::attach(&std::env::temp_dir().join(format!(
            "nzbfast-stream-{}-{}",
            std::process::id(),
            name.bytes().map(|b| format!("{b:02x}")).collect::<String>()
        )));
        let p = d.join(name);
        std::fs::write(&p, bytes).unwrap();
        (d, p)
    }
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

    /// Write a config to disk - `load_server` and `find_scan_server` both
    /// take a path, because both are called from lanes that re-read the
    /// file rather than hold a parsed copy.
    /// The guard comes back with the path for the reason `tmp_nzb` above
    /// gives.
    fn cfg_file(
        name: &str,
        servers: serde_json::Value,
    ) -> (crate::testscratch::ScratchDir, std::path::PathBuf) {
        let d = crate::testscratch::ScratchDir::attach(
            &std::env::temp_dir().join(format!("nzbfast-nettools-{name}-{}", std::process::id())),
        );
        let p = d.join("config.local.json");
        std::fs::write(&p, serde_json::json!({ "servers": servers }).to_string()).unwrap();
        (d, p)
    }

    /// The 23 Aug 2026 defect, at the helper every one-connection
    /// lane goes through: with the DISABLED account sorted first, this
    /// used to hand it straight back.
    #[test]
    fn load_server_skips_a_switched_off_server_however_early_it_sorts() {
        let (_scratch, p) = cfg_file(
            "off-first",
            serde_json::json!([
                { "host": "news.newshosting.com", "enabled": false },
                { "host": "news.giganews.com" },
            ]),
        );
        assert_eq!(load_server(&p).unwrap().host, "news.giganews.com");
    }

    /// All off is an instruction, not a config error to route around. A
    /// fallback to `servers[0]` here would reintroduce the whole defect
    /// for the single-server install that switched its one server off.
    #[test]
    fn load_server_refuses_when_every_server_is_switched_off() {
        let (_scratch, p) = cfg_file(
            "all-off",
            serde_json::json!([
                { "host": "news.newshosting.com", "enabled": false },
                { "host": "news.eweka.nl", "enabled": false },
            ]),
        );
        let e = load_server(&p).unwrap_err().to_string();
        assert!(
            e.contains("no enabled server"),
            "the error must say WHICH rule stopped it, got: {e}"
        );
    }

    /// A `scan_primary:<group>` key outlives the config that produced it,
    /// so resolving one has to re-check `enabled` - otherwise the tip
    /// watcher holds a session on an account switched off after the pass
    /// that chose it.
    #[test]
    fn find_scan_server_does_not_resurrect_a_disabled_primary() {
        let (_scratch, p) = cfg_file(
            "stale-primary",
            serde_json::json!([
                { "host": "news.newshosting.com", "enabled": false },
                { "host": "news.giganews.com" },
            ]),
        );
        let stale = nzbkit::index::Index::server_key("news.newshosting.com");
        assert!(
            find_scan_server(&p, &stale).is_none(),
            "a primary key naming a disabled server must resolve to None"
        );
        let live = nzbkit::index::Index::server_key("news.giganews.com");
        assert_eq!(
            find_scan_server(&p, &live).map(|s| s.host),
            Some("news.giganews.com".to_string()),
            "an enabled primary must still resolve"
        );
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
