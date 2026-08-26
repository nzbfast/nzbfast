//! The three largest subcommand arms of `fn run`: `get`, `mockserve`
//! and `serve`. Hoisted out of `main.rs` verbatim on 22 Aug 2026 because
//! `fn run` sat seven lines under the size gate's 500-line function
//! ceiling, so the next subcommand anyone added would have reddened main
//! (TODO 106 pattern, as `check_sweep.rs`, `fleet_knobs.rs` and
//! `extract/names.rs`). A function ceiling, so splitting `main.rs` could
//! not have helped.
//!
//! Behaviour unchanged: this is the bin root's own child module,
//! glob-imported back, and each function holds one arm's pattern and
//! body exactly as they stood - the destructure is the same pattern the
//! `match` matched on, so the `let ... else` can never take its else
//! branch. What `run` keeps is the dispatch line.

use super::*;
use std::path::Path;

/// `nzbfast get`: the offline one-shot download. Hoisted out of [`run`]
/// verbatim on 22 Aug 2026; behaviour unchanged, and every comment block
/// inside is the one that sat over the same line in the match arm.
///
/// `config` is the `--config` path `run` used to reach for as
/// `cli.config`, and `budget` the process memory budget it resolved
/// before the match.
pub(crate) async fn get_cmd(
    cmd: Command,
    config: &Path,
    budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    let Command::Get {
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
    } = cmd
    else {
        unreachable!("get_cmd is only reached from the `Command::Get` arm of `run`")
    };
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
    // M32/C1 perf: CLI downloads have no /stream readers, so
    // dropping settled page cache is SAFE here - but only a WIN
    // on small-memory boxes, so the default is memory-aware
    // rather than the old flat `true` (threshold rationale and
    // the measured crossover: `drop_cache_auto` in nzbkit's
    // disk.rs).
    // NZBFAST_DROP_CACHE=1/0 force-overrides either way.
    #[cfg(target_os = "linux")]
    nzbkit::disk::set_drop_cache_default(nzbkit::disk::drop_cache_auto());
    if preflight {
        let verdict = check(config, &nzb, 10, 4, 50, true).await?;
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
        config,
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
        // §293: donor directories are a daemon switch-job concern; a
        // CLI get has no predecessor to donate from.
        Vec::new(),
        None,
        None,
        "",
        None,
        budget,
    )
    .await
}

/// `nzbfast mockserve`: the synthetic NNTP server the bench rigs point a
/// client at. Hoisted out of [`run`] verbatim on 22 Aug 2026; behaviour
/// unchanged. Reads nothing off the `Cli` but its own flags, so it takes
/// no config path.
pub(crate) async fn mockserve_cmd(cmd: Command) -> Result<()> {
    let Command::Mockserve {
        port,
        bind,
        files,
        file_size,
        article_size,
        nzb,
        par2,
        tls_cert,
        tls_key,
    } = cmd
    else {
        unreachable!("mockserve_cmd is only reached from the `Command::Mockserve` arm of `run`")
    };
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

/// `nzbfast serve`: the daemon. Hoisted out of [`run`] verbatim on
/// 22 Aug 2026; behaviour unchanged - `ServeOpts` is built field for
/// field as it was, and the settings-only comments moved with their
/// fields.
///
/// Takes the config path by value because [`serve::serve`] does; the
/// clone stays at the call site in `run`, where it always was.
pub(crate) async fn serve_cmd(
    cmd: Command,
    config: PathBuf,
    budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    let Command::Serve {
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
    } = cmd
    else {
        unreachable!("serve_cmd is only reached from the `Command::Serve` arm of `run`")
    };
    let size = |name: &str, v: Option<String>| -> Result<Option<u64>> {
        v.map(|s| {
            serve::parse_size(&s).ok_or_else(|| anyhow::anyhow!("--{name}: can't parse size {s:?}"))
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
    serve::serve(config, opts).await
}
