//! The download pipeline: get_with_progress, the whole one-pass fetch/decode/verify/extract drive shared by the get command and the daemon.
//!
//! Split out of main.rs verbatim; behaviour unchanged.

use crate::*;
use nzbkit::pool::fetch_all_multi_ctl;
use std::path::Path;
use tracing::info;

mod vrig;
use vrig::{Rig, build_rig, install_seek};
mod fleet;
use fleet::{Fleet, build_fleet};
mod jobspec;
pub use jobspec::{JobSpec, JournalOwner};
mod plan;
use plan::{FetchPlan, Intake, build_fetch_plan, build_intake, clamp_concurrency};
// The demotion watchdog (`tasks/stall.rs`) predicts this gate's
// answer before it causes a requeue, and a prediction made with a COPY
// of the rule is one that drifts the day the rule moves - which is
// exactly what happened when TODO 309(a) widened the gate and the
// watchdog kept warning about a disk route the rerun no longer takes.
// One function, two readers.
pub use plan::resume_map_admits;
mod census;
mod donor;
mod dropped;
// PLAN M31 stage 1: borrow a bad block's bytes from a duplicate
// posting's live articles, before repair spends a recovery block on it.
mod dupefill;
mod emptydesc;
mod latesets;
mod publishplan;
// X5-24: which loss a leftover recovery set stands for, when the post
// admits exactly one answer (30 Aug 2026 ruling).
mod residual;
// M4-07: a sidecar entry declaring the CRC32 of the empty input names a
// zero-byte placeholder nothing was posted for (30 Aug 2026 ruling).
mod sfvempty;
mod sfvname;
mod tail;
/// M4-70: which ARTICLE's yEnc name a file is published under. The
/// weakest naming tier, last, over the files still sitting under a name
/// only a yEnc header ever gave them.
mod yencname;
use tail::finish_run;
mod rig;
mod settle;
mod workers;
use workers::{
    TailWatchers, build_counters, drain_network, spawn_deadlock_watchdog, spawn_decode_consumers,
    spawn_rate_ticker, spawn_tail_watchers,
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
            // cpu-workers-gate: I/O runtime shards, not a CPU pool, and
            // NZBFAST_SHARDS above is this site's own override.
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
    info!(
        target: "get",
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
    // Two different numbers for two different jobs, and TODO 277 is
    // what parted them. `spawned` is how many worker slots exist, which
    // is what the shard layout has to cover: it is decided once here
    // and cannot follow the in-run fleet governor, so it is sized for
    // the fleet that MAY come up rather than the one dialling now.
    // `dialled` is how many connections this run is actually asking the
    // providers for - the parked surplus holds nothing - and that is
    // the number to report. The bench rigs read it positionally out of
    // the head of this line (`rig_conn_scan`'s `sharding [0-9]+
    // connections`) as the denominator of `conns_held=`, and a
    // denominator that counted parked slots would read every ordinary
    // leg as a fleet that came up short.
    let spawned: usize = servers.iter().map(|(_, c)| c.connections).sum();
    let dialled: usize = servers.iter().map(|(_, c)| c.dialled()).sum();
    let shards = shard_count(spawned);
    if shards > 1 {
        let parked = match spawned.saturating_sub(dialled) {
            0 => String::new(),
            n => format!(" ({n} more spawned and parked, headroom for the line-rate governor)"),
        };
        info!(target: "get", "sharding {dialled} connections across {shards} I/O runtimes{parked}");
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

/// Sweep F1 (27 Aug 2026): a §293 donation lands AFTER the restore
/// already ran in the map shape - which wrote NO volume bytes, every
/// restored span still sitting in the previous run's output files,
/// named by `seeds.sources` - and the donation then flips the run onto
/// the adopt shape, whose path hands each restored seed to the
/// extractor via `seed_slot`/`seed_pre_spans`. Those calls assert the
/// spans are in the volume files themselves, so without this re-run the
/// verifier trusts bytes that were never written.
///
/// Re-running the restore MATERIALISING is idempotent over the
/// map-shape pass: phase A re-encrypts the same bytes to the same
/// offsets and phase B is a plain copy into the volume file (pinned by
/// `a_no_materialise_restore_writes_no_volume_and_names_the_real_source`).
/// The admission answer can only shrink if a source file vanished in
/// the milliseconds between the two calls - the same exposure the map
/// replay itself carries, per `restore_for`'s own doc - so `completed`
/// is extended, not rebuilt. Paid only by a resumed switch that
/// actually donated, which has just skipped a download.
fn rematerialize_for_donation(
    out_dir: &Path,
    resume_state: &nzbkit::journal::ResumeState,
    password: Option<&str>,
    mut completed: std::collections::HashSet<String>,
    resume_route: Option<crate::streamhub::ResumeRoute>,
) -> (
    nzbkit::journal::Restored,
    std::collections::HashSet<String>,
    Option<crate::streamhub::ResumeRoute>,
) {
    info!(
        target: "resume",
        "donation forces the adopt shape - re-running the restore to materialise volumes"
    );
    let mut redone = crate::persist::blocking_db(|| {
        nzbkit::journal::restore_for(out_dir, resume_state, password, true)
    });
    completed.extend(std::mem::take(&mut redone.ids));
    // The report must say which way the run actually went: the gate
    // admitted the map, the donation overrode it.
    let route = resume_route.map(|mut r| {
        r.mapped = false;
        r
    });
    (redone, completed, route)
}

/// TODO 309: publish which route the resume took, tagged with the job
/// that owns it, for the tail to latch onto the record and the download
/// report to print. Called from `get_with_progress` rather than inside
/// `build_intake` because that is where `stream_owner` is - and the tag
/// is not optional: the lane reads this cell after the next job may
/// already have claimed the hub (`detach_job_tail`), which is the
/// handover `extractor_for` exists for. Called after the donation block,
/// so a donation-overridden route is published as the adopt shape it
/// became rather than the map the gate admitted.
///
/// Left alone when there is no route, rather than stored as `None`. The
/// runner clears the cell at every job start, so the only thing a store
/// of `None` could overwrite is a verdict this same run already
/// published, and there is exactly one gate call per run. Lifted out of
/// `get_with_progress` for the size gate.
fn publish_resume_route(
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
    resume_route: Option<crate::streamhub::ResumeRoute>,
) {
    if let (Some(h), Some(r)) = (hub, resume_route) {
        *h.resume_route.lock_ok() = Some((stream_owner.to_string(), r));
    }
}

/// A donation forces the run off the mapped shape (the flip in
/// `build_fetch_plan`, sweep F1): re-materialize the resume state when
/// one landed, and hand the three values back untouched when none did.
///
/// Lifted out of `get_with_progress` for the size gate, body verbatim;
/// the caller destructures the triple straight back onto the inline
/// names. The condition is a parameter rather than re-derived here so
/// the two facts it is made of - `resume_map` and whether the adoption
/// pass placed anything - stay where they are computed.
fn donation_reshape(
    donated: bool,
    out_dir: &Path,
    resume_state: &nzbkit::journal::ResumeState,
    password: Option<&str>,
    restored: nzbkit::journal::Restored,
    completed: std::collections::HashSet<String>,
    resume_route: Option<crate::streamhub::ResumeRoute>,
) -> (
    nzbkit::journal::Restored,
    std::collections::HashSet<String>,
    Option<crate::streamhub::ResumeRoute>,
) {
    if donated {
        rematerialize_for_donation(out_dir, resume_state, password, completed, resume_route)
    } else {
        (restored, completed, resume_route)
    }
}

/// Register each donated file as a restored SLOT SEED.
///
/// A donated file is bytes on disk this run will not fetch, which is the
/// crash-resume ADOPT shape exactly - so it takes that path, seeds and
/// all. `SlotSeed` is the same record `journal::restore` builds, and
/// `replay_or_adopt_restored` (inside `build_rig`) does the three things
/// it exists to do: adopt the file as the slot's plain writer, register
/// its bytes as pre-activation spans so the M15b backfill re-reads and
/// HASHES them against the PAR2 block map, and let the real on-disk name
/// beat the subject hint for PAR2 matching. The donation's own
/// whole-file MD5 is therefore not the only thing standing behind these
/// bytes: the backfill checks every block of them, and the settle
/// read-back backs that up.
///
/// A free function rather than the inline loop it was until 28 Aug 2026,
/// and the reason is worth stating so nobody folds it back: its caller
/// sat at EXACTLY the 500-line function ceiling (`tools/size-gate.py`),
/// so an ordinary lane threading one more counter through had nowhere
/// to put it. The 31 Aug 2026 split bought that caller 120 lines of
/// margin, which is room to fold this back and no reason to - and a
/// new OPTION now has [`JobSpec`] to live in, which costs the caller
/// nothing at all. Behaviour is unchanged - the same loop over the
/// same three inputs, hoisted whole.
fn seed_donated_slots(
    donated: &donor::Donated,
    slot_file: &[usize],
    restored: &mut nzbkit::journal::Restored,
) {
    for (fi, name, size) in &donated.placed {
        let Some(slot) = slot_file.iter().position(|&f| f == *fi) else {
            continue;
        };
        restored.seeds.push(nzbkit::journal::SlotSeed {
            slot,
            name: name.clone(),
            size: *size,
            spans: vec![(0, *size)],
            sources: Vec::new(),
            article_ids: Vec::new(),
        });
    }
}

/// The one-pass download drive: fetch, decode, verify, repair and
/// extract one NZB. Its inputs are [`JobSpec`] - see that module for
/// why they are a struct and what belongs in it - destructured here
/// onto the same names the inline parameters used.
pub async fn get_with_progress(job: JobSpec<'_>) -> Result<()> {
    let JobSpec {
        config,
        nzb_path,
        out_dir,
        connections,
        window,
        decoders,
        fast_verify,
        verify_lean,
        no_extract,
        journal_owner,
        par_cleanup,
        skip_samples,
        password,
        eat_consent,
        donor_dirs,
        donor_nzbs,
        progress,
        hub,
        stream_owner,
        net_done,
        budget,
    } = job;
    // THE OUTPUT ROOT, RESOLVED ONCE - every line below carries the
    // resolved path. `nzbkit::disk::open_out_leaf` refuses a payload
    // whose immediate parent is a symlink, and for a flat name that
    // parent is this directory, so a job pointed at a symlinked (or, on
    // Windows, junctioned) downloads folder errored on its first write
    // where it used to succeed. The fix belongs HERE and not at the
    // write: following a symlink there is the hole X5-08 was. What it
    // deliberately leaves alone - a link ABOVE the root, and an ordinary
    // directory, which comes back byte-identical - is at
    // `resolve_out_root`.
    //
    // FIRST: `clamp_concurrency` below probes this directory's storage
    // and `build_intake` opens the journal in it, and a probe of a link
    // and a probe of its target can disagree.
    let resolved_out = nzbkit::disk::resolve_out_root(out_dir);
    let out_dir: &Path = &resolved_out;
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
        resume_map,
        resume_route,
        mut resume_state,
    } = build_intake(config, nzb_path, out_dir, password, no_extract, &hub)?;
    // §293 plan-side adoption (TODO 305 item 2): before the plan
    // finalizes, take whole member files off a failed predecessor's disk
    // so their articles are never queued. Costs one small PAR2-index
    // fetch and touches nothing at all when `donor_dirs` is empty, which
    // is the CLI, the sidecar and every job that is not a switch. See
    // get/donor.rs for why it needs the successor's own set to be safe.
    let donated =
        donor::adopt_from_donors(&cfg_all.servers, &nzb, out_dir, &donor_dirs, &completed).await;
    let (mut restored, completed, resume_route) = donation_reshape(
        resume_map && donated.any(),
        out_dir,
        &resume_state,
        password.as_deref(),
        restored,
        completed,
        resume_route,
    );
    // M4-70 across a crash: run 1's per-slot name tally, taken before the
    // state is freed. `build_fetch_plan` seeds it into the slots it
    // builds, because a resumed slot with an EMPTY tally reads as "every
    // article agreed" and the settle-time re-decision never runs.
    let resume_votes = std::mem::take(&mut resume_state.name_votes);
    drop(resume_state);
    publish_resume_route(&hub, stream_owner, resume_route);
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
        &donated.by_file,
        &resume_votes,
    );
    // The resume id set is read exactly once - by the plan walk above -
    // and nothing downstream asks about it again (`resuming` already
    // carries the only bit anyone needs). Free it here rather than let a
    // 128k-article set sit resident through the whole fetch and tail.
    drop(completed);

    // Donated files join the run on the crash-resume ADOPT path: see
    // `seed_donated_slots`.
    seed_donated_slots(&donated, &slot_file, &mut restored);
    // ...and the two flags that path answers to. `resume_map` is forced
    // OFF rather than left: mapping means replaying journal placements
    // through the one-pass extractor, and a donated file has no
    // placements to replay - what it has is a finished file on disk,
    // which is precisely what the adopt path is for. Together these put
    // the run on the resumed shape end to end: in-stream extraction off,
    // the volumes on disk re-extracted at the tail. Paid only by a job
    // that actually donated - which has just skipped a download.
    let resuming = resuming || donated.any();
    let resume_map = resume_map && !donated.any();

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
        replay,
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
        resume_map,
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
        &nzb,
        &slots,
        &slot_file,
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
        mut servers,
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
    // Where a pool reports that it is HOLDING an article's terminal
    // verdict back. Wired here rather than inside `build_fleet` because
    // the flag belongs to the JOB's extractor, not to a server's
    // configuration - and the extractor exists by now, `build_rig`
    // having run above. The tail watchers' recovery side-fetch inherits
    // it with the rest of the fleet, deliberately: a recovery block that
    // will not arrive is the same doubt about the same set repairing
    // from what is still in RAM. See `nzbkit::extract::LossDoubt`.
    for (_, c) in &mut servers {
        c.loss_doubt = Some(extractor.loss_doubt());
    }
    let servers = servers;

    // The outcome channel, the shared counters and samples, the
    // consumer throttle, the backfill cell: see build_counters in
    // get/workers.rs. NOT destructured onto inline names the way the
    // other phase bundles are - it is handed WHOLE to the decode fleet
    // below and, as `counters.loss`, to the tail, which is what stops
    // two of its five identically-typed `Arc<CauseSplit>` ledgers being
    // swapped in a long positional call. See `spawn_decode_consumers`
    // and `workers::LossLedgers` for the whole reasoning.
    let counters = build_counters(&budget, progress, &hub, resume_have_bytes);
    // Body-encryption spike (Tensai75 draft, `NZBFAST_YENC_CRYPT=1`):
    // the job's decryption context, None whenever the spike is off, the
    // job has no password, or the NZB cannot carry the draft's
    // continuous segmentIndex - see `nzbkit::yencrypt::JobCrypt`.
    let yencrypt = nzbkit::yencrypt::JobCrypt::for_job(&nzb.files, &slot_file, password.as_deref());
    // The decode-consumer fleet: see spawn_decode_consumers.
    let (consumers, pending_d, pending_r) = spawn_decode_consumers(
        decoders,
        &counters,
        &buf_pool,
        &out_pool,
        &slots,
        &id_to_slot,
        &seek_names,
        &fetch_done,
        &verifier,
        &extractor,
        &shape_said,
        &par2_outstanding,
        &journal,
        &sniff,
        &replay,
        &queue_ctl,
        servers.first().is_some_and(|(_, c)| c.crc_steer),
        &yencrypt,
    );
    // The consumers hold the only other references to the id manifest,
    // and nothing downstream of the spawn reads it. Dropping the
    // orchestrator's `Arc` here lets the map die when the decode fleet
    // joins rather than staying resident through the repair tail, where
    // PAR2 wants every byte of RAM it can get (§A1).
    drop(id_to_slot);

    // Live rate ticker: see spawn_rate_ticker. It also carries §282
    // item 3's running damage projection - see `DamageWatch`.
    let ticker = spawn_rate_ticker(
        counters.decoded_bytes.clone(),
        slots.clone(),
        workers::DamageWatch {
            nzb: nzb.clone(),
            slot_file: slot_file.clone(),
            verifier: verifier.clone(),
            volumes: workers::declared_volumes(&nzb),
        },
    );

    // Memory-floor attribution sampler; owns this job's peak record and
    // is retired BY TOKEN in print_mem_summary (tail.rs) after the
    // summary reads that record.
    let mem_sampler = workers::spawn_mem_sampler(stream_owner, nzb_path);

    // Deadlock watchdog: see spawn_deadlock_watchdog.
    let stalled = Arc::new(std::sync::atomic::AtomicBool::new(false));
    let watchdog = spawn_deadlock_watchdog(
        counters.decoded_bytes.clone(),
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
        &counters.decoded_bytes,
        &slot_file,
    );
    // The network fetch itself - sharded across I/O runtimes when the
    // fleet is big enough (D1), single-runtime otherwise: see run_fetch.
    let stats = run_fetch(&servers, ids, counters.tx, &queue_ctl).await;
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
        &counters.disk_full_sample,
        &queue_ctl,
        &note_activity,
        net_done,
        &hub,
        stream_owner,
        password,
        &counters.backfill,
    )
    .await?;

    // Everything after the network drain - the §94 A replay backstop,
    // post-drain accounting, settle/repair, extraction, the unpack tail
    // and the journal's retirement: see finish_run in get/tail.rs.
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
        &counters.decode_errors,
        &counters.decoded_bytes,
        &counters.loss,
        &stalled,
        &pending_r,
        elapsed,
        bootstrap_vol,
        &resume_vols,
        &prefetched,
        &restored,
        &replay,
        fast_verify,
        par_cleanup,
        password,
        resuming,
        no_extract,
        journal_owner,
        resume_map,
        eat_consent,
        &note_activity,
        cancel,
        &donor_dirs,
        &donor_nzbs,
        &hub,
        stream_owner,
        &budget,
        &mem_sampler,
    )
    .await
}
