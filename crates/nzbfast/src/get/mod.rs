//! The download pipeline: get_with_progress, the whole one-pass fetch/decode/verify/extract drive shared by the get command and the daemon.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use nzbkit::pool::fetch_all_multi_ctl;
use std::path::Path;

mod vrig;
use vrig::{Rig, build_rig, install_seek};
mod fleet;
use fleet::{Fleet, build_fleet};
mod plan;
use plan::{FetchPlan, Intake, build_fetch_plan, build_intake, clamp_concurrency};
mod census;
mod tail;
use tail::finish_run;
mod settle;
use settle::fetch_matched_deferred;
mod rig;
mod workers;
use workers::{
    Counters, TailWatchers, build_counters, drain_network, spawn_deadlock_watchdog,
    spawn_decode_consumers, spawn_rate_ticker, spawn_tail_watchers,
};

/// Queue-row activity token, advanced at section transitions only
/// (never per article): the daemon's queue payload reads it to say
/// what the pipeline is doing right now. No hub (CLI) means no one
/// is listening; a sidecar's hub is never read by the queue payload.
/// Lifted out of `get_with_progress` (with `announce_plan` below) for
/// the size gate.
fn note_activity_impl(hub: &Option<Arc<StreamHub>>, stream_owner: &str, tok: &'static str) {
    if let Some(h) = hub {
        h.activity.lock_ok().insert(stream_owner.to_string(), tok);
    }
}

/// §129: this run's cancel handle for the post-network tail's
/// recovery-volume side-fetches, published on the hub under the owning
/// nzo_id so a delete can find it.
///
/// Deliberately NOT `queue_ctl`. That one is the MAIN pool's, the
/// daemon publishes it in a single hub slot, and that slot belongs to
/// whatever is downloading NOW - so by the time this run's repair is
/// pulling parity, the next job owns it, and a cancel aimed there would
/// kill a healthy unrelated download while this one fetched on. Keyed
/// by owner instead, and released at `Daemon::park` beside the activity
/// token. No hub (a CLI run) means nobody can ask for a cancel; the
/// handle still exists so the driver's contract is the same everywhere.
/// Lifted out of `get_with_progress` for the size gate.
fn install_tail_cancel(
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
) -> Arc<crate::repair::SideCancel> {
    let c = Arc::new(crate::repair::SideCancel::new());
    if let Some(h) = hub {
        h.tail_cancel
            .lock_ok()
            .insert(stream_owner.to_string(), c.clone());
    }
    c
}

/// D1 (big-link): how many independent I/O runtimes to shard the fleet
/// across. The single-runtime path tops out at ~4.1 Gbps per process -
/// one I/O driver thread saturates while the NIC still has headroom -
/// so big machines with enough connections spread it over the
/// soak-proven `fetch_all_sharded`. Small boxes stay single-runtime:
/// extra runtimes are pure overhead below the ceiling. NZBFAST_SHARDS=n
/// forces either way (1 = force single-runtime), clamped because each
/// shard spins its own 2-thread runtime and an absurd value
/// (NZBFAST_SHARDS=100000) would panic on thread exhaustion and take the
/// download down with it; 16 covers any real fleet. Lifted out of
/// `get_with_progress` for the size gate.
fn shard_count(total_conns: usize) -> usize {
    std::env::var("NZBFAST_SHARDS")
        .ok()
        .and_then(|v| v.parse::<usize>().ok())
        .map(|n| n.clamp(1, 16))
        .unwrap_or_else(|| {
            let cores = std::thread::available_parallelism().map_or(1, |n| n.get());
            if cores >= 12 && total_conns >= 24 {
                (total_conns / 16).clamp(2, 4)
            } else {
                1
            }
        })
}

/// The one-line launch banner: file count, eager/total megabytes, and
/// where the output lands. Lifted out of `get_with_progress` for the
/// size gate (the §91 rule: the gate forces fixes into helpers).
fn announce_plan(nzb_path: &Path, files: usize, eager: u64, total: u64, out_dir: &Path) {
    println!(
        "{}: {} files ({:.1} MB eager of {:.1} MB total) → {}",
        nzb_path.display(),
        files,
        eager as f64 / 1e6,
        total as f64 / 1e6,
        out_dir.display()
    );
}

/// The network fetch itself: D1 (big-link) shards the fleet across
/// independent I/O runtimes when `shard_count` says it is worth it,
/// small fleets stay on the single-runtime path. Lifted out of
/// `get_with_progress` for the size gate.
async fn run_fetch(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    ids: Vec<nzbkit::pool::ArticleReq>,
    tx: tokio::sync::mpsc::Sender<nzbkit::pool::FetchOutcome>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
) -> Vec<nzbkit::pool::PoolStats> {
    let total_conns: usize = servers.iter().map(|(_, c)| c.connections).sum();
    let shards = shard_count(total_conns);
    if shards > 1 {
        println!("  sharding {total_conns} connections across {shards} I/O runtimes");
        let servers_owned = servers.to_vec();
        let qc = queue_ctl.clone();
        tokio::task::spawn_blocking(move || {
            nzbkit::pool::fetch_all_sharded(servers_owned, ids, tx, shards, Some(&qc))
        })
        .await
        .expect("sharded fetch panicked")
    } else {
        fetch_all_multi_ctl(servers, ids, tx, Some(queue_ctl.as_ref())).await
    }
}

#[allow(clippy::too_many_arguments)]
/// Test-only (`NZBFAST_TEST_STALL_TAIL_MS`): hold the post-network tail
/// open so the §129 lane suite can observe the Finishing state
/// deterministically. Unset (the only production state) is a no-op.
async fn test_stall_tail() {
    if let Some(ms) = std::env::var("NZBFAST_TEST_STALL_TAIL_MS")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
    {
        tokio::time::sleep(std::time::Duration::from_millis(ms)).await;
    }
}

pub(crate) async fn get_with_progress(
    config: &Path,
    nzb_path: &Path,
    out_dir: &Path,
    connections: usize,
    window: usize,
    decoders: usize,
    // PAR2 fast verify (TODO §10): CRC32-only in-stream block claims.
    // NZBFAST_FAST_VERIFY=0/1 overrides for bench A/Bs.
    fast_verify: bool,
    // M32 "lean" verify (slow-CPU boost): with fast verify on, also skip
    // the per-article yEnc CRC once PAR2 covers a file - in-stream
    // integrity rests on the PAR2 block CRC32 alone (one CRC32 layer
    // instead of two). Settle read-back + repair authority unchanged;
    // PAR2-less downloads keep full article CRCs automatically.
    verify_lean: bool,
    no_extract: bool,
    // Delete the spent recovery set once a repair has VERIFIED: the
    // daemon's `par_cleanup`, threaded in because the only place that
    // reads it today (the job tail's extension sweep) cannot see the
    // files this one deletes. Bears solely on the obfuscated disk-side
    // arm below, which removes magic-sniffed volumes no extension rule
    // can ever match; named `*.par2` stays the job tail's business.
    par_cleanup: bool,
    // PLAN M32 leftover (sabnzbd#3475): leave a job's sample/proof
    // clips unfetched instead of downloading them and deleting them
    // afterwards. Off by default - see the setting's own note for why
    // ours differs from SABnzbd's.
    skip_samples: bool,
    // Explicit archive password (CLI/API). NZB `<meta type="password">`
    // and the `Name{{password}}.nzb` filename convention are picked up
    // automatically; this overrides both.
    password: Option<String>,
    // TODO 101: this job's own yes to the volume-eating unpack, given in
    // the disk-full drawer. Consulted only in `low_disk` mode - `always`
    // is itself the consent and `off` cannot be talked into it - and
    // never enough on its own: the set must still have verified.
    eat_consent: bool,
    progress: Option<Arc<AtomicU64>>,
    hub: Option<Arc<StreamHub>>,
    // The nzo_id that owns this run's hub extractor (daemon jobs); empty for
    // CLI downloads. Tags the installed extractor so /stream ownership is
    // checked atomically with the clone (finding 11).
    stream_owner: &str,
    // net_done fires when the network phase is done (all articles
    // terminal, consumers drained) - the daemon starts the next job's
    // download then, while this job's tail (settle/repair/extract) runs.
    net_done: Option<tokio::sync::oneshot::Sender<()>>,
    budget: nzbkit::mem::MemBudget,
) -> Result<()> {
    // B4 small-RAM clamp + rotational decoder pick: see clamp_concurrency.
    let (connections, window, decoders) = clamp_concurrency(connections, window, decoders, out_dir);

    // Queue-row activity token, advanced at section transitions only
    // (never per article): see `note_activity_impl`.
    let note_activity = |tok: &'static str| note_activity_impl(&hub, stream_owner, tok);
    // Job intake - config, NZB parse, oracle routing, the archive
    // password, the crash-resume journal: see build_intake in
    // get/plan.rs. The destructure keeps downstream reads on the
    // inline names.
    let Intake {
        cfg_all,
        nzb,
        job_family,
        job_posted,
        password,
        journal,
        restored,
        completed,
        resuming,
        has_main,
        bootstrap_vol,
        resume_vols,
    } = build_intake(config, nzb_path, out_dir, password, &hub)?;
    // The slot + article fetch plan: see build_fetch_plan. The
    // destructure keeps every downstream read on the inline names.
    let FetchPlan {
        resume_sniffed_slots,
        resume_deferred_arts,
        resume_deferred_bytes,
        resume_have_bytes,
        slots,
        id_to_slot,
        slot_file,
        mut slot_arts,
        ids,
        fetch_done,
    } = build_fetch_plan(
        &nzb,
        &hub,
        &completed,
        resuming,
        bootstrap_vol,
        &resume_vols,
        skip_samples,
    );

    // The verification rig - verifier, sniff control, the configured
    // extractor: see build_rig. The destructure keeps every downstream
    // read on the inline names.
    let Rig {
        verifier,
        fast_verify,
        par2_outstanding,
        sniff,
        shape_said,
        resume_map,
        extractor,
    } = build_rig(
        &nzb,
        &slots,
        &slot_file,
        &hub,
        stream_owner,
        out_dir,
        &journal,
        &restored,
        &resume_sniffed_slots,
        resume_deferred_arts,
        resume_deferred_bytes,
        &fetch_done,
        &password,
        fast_verify,
        verify_lean,
        no_extract,
        resuming,
        &budget,
    );
    // M11: seek re-prioritization handle. QueueControl attaches to the
    // pool's pending queue when the fetch starts; SeekCtl turns player
    // read positions into promotions through it.
    let queue_ctl = Arc::new(nzbkit::pool::QueueControl::default());
    let abort_flag = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // §129: this run's recovery-fetch cancel handle - see
    // `install_tail_cancel`.
    let side_cancel = install_tail_cancel(&hub, stream_owner);
    let cancel = Some(side_cancel.as_ref());
    // The seek/promote ladder and the hub publish: see install_seek in
    // get/vrig.rs. slot_arts is taken - the SeekCtl owns it from here.
    let seek_names = install_seek(
        &slots,
        &mut slot_arts,
        &queue_ctl,
        &abort_flag,
        &extractor,
        &verifier,
        &hub,
        stream_owner,
    );
    announce_plan(
        nzb_path,
        slots.len(),
        nzb.eager_bytes(),
        nzb.total_bytes(),
        out_dir,
    );

    // The buffer pools and the per-server fleet (race knobs, conntune
    // caps, warm-pool reconcile, live gauges, oracle sink): see
    // build_fleet. The destructure keeps downstream reads on the
    // inline names.
    let Fleet {
        buf_pool,
        out_pool,
        servers,
    } = build_fleet(
        &cfg_all,
        config,
        connections,
        window,
        &hub,
        job_posted,
        &job_family,
        &budget,
    )
    .await;

    // The outcome channel, the shared counters and samples, the
    // consumer throttle, the backfill cell: see build_counters in
    // get/workers.rs.
    let Counters {
        tx,
        rx,
        decoded_bytes,
        decode_errors,
        retention_excluded,
        missing_430,
        transport_failed,
        transport_sample,
        decode_error_sample,
        disk_full_sample,
        throttle_mbps,
        throttle_t0,
        backfill,
        rt,
    } = build_counters(&budget, progress, &hub, resume_have_bytes);
    // The decode-consumer fleet: see spawn_decode_consumers.
    let (consumers, pending_d, pending_r) = spawn_decode_consumers(
        decoders,
        &rx,
        &buf_pool,
        &out_pool,
        &slots,
        &id_to_slot,
        &seek_names,
        &decoded_bytes,
        &fetch_done,
        &decode_errors,
        &retention_excluded,
        &missing_430,
        &transport_failed,
        &transport_sample,
        &decode_error_sample,
        &disk_full_sample,
        &verifier,
        &extractor,
        &shape_said,
        &par2_outstanding,
        &journal,
        &backfill,
        &sniff,
        &queue_ctl,
        &rt,
        throttle_mbps,
        throttle_t0,
        servers.first().is_some_and(|(_, c)| c.crc_steer),
    );

    // Live rate ticker: see spawn_rate_ticker.
    let ticker = spawn_rate_ticker(decoded_bytes.clone(), slots.clone());

    // Deadlock watchdog: see spawn_deadlock_watchdog.
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = spawn_deadlock_watchdog(
        decoded_bytes.clone(),
        slots.clone(),
        queue_ctl.clone(),
        abort_flag.clone(),
        stalled.clone(),
    );

    let t0 = Instant::now();
    // The recovery-side watchers - spec prefetch (M2c.5), the dark PAR2
    // race, the §146 tail give-up - and the scratch state they share:
    // see spawn_tail_watchers in get/workers.rs. The destructure keeps
    // downstream reads on the inline names.
    let TailWatchers {
        prefetched,
        prefetch_stop,
        spec_prefetch_task,
        par_race_task,
        tail_giveup_task,
    } = spawn_tail_watchers(
        &hub,
        has_main,
        &nzb,
        &servers,
        &slots,
        out_dir,
        &buf_pool,
        &verifier,
        &queue_ctl,
        &fetch_done,
        &decoded_bytes,
        &slot_file,
    );
    // The network fetch itself - sharded across I/O runtimes when the
    // fleet is big enough (D1), single-runtime otherwise: see run_fetch.
    let stats = run_fetch(&servers, ids, tx, &queue_ctl).await;
    // Network phase over: stop the side tasks, join the decode
    // consumers, flush the last D records, honor abort/pause, signal
    // net_done and re-read the late password: see drain_network in
    // get/workers.rs. Bailing inside drops net_done, which the daemon
    // reads as network-drained - same as the inline code did.
    let (elapsed, password) = drain_network(
        &prefetch_stop,
        spec_prefetch_task,
        par_race_task,
        tail_giveup_task,
        consumers,
        &pending_d,
        &pending_r,
        &extractor,
        &journal,
        t0,
        ticker,
        watchdog,
        &stalled,
        &abort_flag,
        &disk_full_sample,
        &queue_ctl,
        &note_activity,
        net_done,
        &hub,
        stream_owner,
        password,
        &backfill,
    )
    .await?;

    test_stall_tail().await;

    // Issue #14 drain fallback - deferred slots the active set covers
    // fetch on the side machinery: see fetch_matched_deferred in
    // get/settle.rs.
    fetch_matched_deferred(
        &verifier, &sniff, &slots, &slot_file, &servers, &nzb, out_dir, &buf_pool, &extractor,
        cancel,
    )
    .await;

    // Everything after the network drain - accounting, settle/repair,
    // extraction, the unpack tail and the journal's retirement: see
    // finish_run in get/tail.rs.
    finish_run(
        &servers,
        &stats,
        &nzb,
        &slots,
        &slot_file,
        &sniff,
        &verifier,
        &extractor,
        journal,
        out_dir,
        &buf_pool,
        &decode_errors,
        &retention_excluded,
        &decoded_bytes,
        &missing_430,
        &transport_failed,
        &transport_sample,
        &decode_error_sample,
        &stalled,
        &pending_r,
        elapsed,
        bootstrap_vol,
        &resume_vols,
        &prefetched,
        &restored,
        fast_verify,
        par_cleanup,
        password,
        resuming,
        no_extract,
        resume_map,
        eat_consent,
        &note_activity,
        cancel,
        &hub,
        stream_owner,
        &budget,
    )
    .await
}
