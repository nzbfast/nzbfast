//! The verification rig (TODO 106 phase 2.1, cut 8): the live verifier,
//! the in-stream PAR2 sniff control, and the extractor with its whole
//! configuration ladder (verify gate, holds caps, zip-split declaration,
//! prealloc ceiling, extract budget, password + probe, decrypt barrier,
//! crash-resume replay/adopt, name hints). Body is a verbatim move from
//! the orchestrator.

use super::rig::{install_password_probe, replay_or_adopt_restored};
use crate::*;
use std::collections::HashMap;
use std::path::Path;
use std::sync::atomic::AtomicUsize;
use tracing::info;

/// The wired-up verification and extraction machinery. Field names match
/// the local bindings the inline code used.
pub(super) struct Rig {
    pub(super) verifier: Arc<nzbkit::live::LiveVerifier>,
    pub(super) fast_verify: bool,
    pub(super) par2_outstanding: Arc<AtomicUsize>,
    pub(super) sniff: Arc<SniffCtl>,
    pub(super) shape_said: Arc<std::sync::atomic::AtomicBool>,
    pub(super) resume_map: bool,
    pub(super) extractor: Arc<nzbkit::extract::Extractor>,
    /// §94 A: restored files the replay still owes the extractor,
    /// fed back per slot as each one's offset-0 article lands. See
    /// `ReplayPending` for why this is not done up front.
    pub(super) replay: Arc<super::rig::ReplayPending>,
}

#[expect(clippy::too_many_arguments)]
pub(super) fn build_rig(
    nzb: &Arc<Nzb>,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
    out_dir: &Path,
    journal: &Arc<nzbkit::journal::Journal>,
    restored: &nzbkit::journal::Restored,
    resume_sniffed_slots: &[usize],
    resume_deferred_arts: usize,
    resume_deferred_bytes: u64,
    fetch_done: &Arc<AtomicU64>,
    password: &Option<String>,
    fast_verify: bool,
    verify_lean: bool,
    no_extract: bool,
    resuming: bool,
    resume_map: bool,
    budget: &nzbkit::mem::MemBudget,
) -> Rig {
    let verifier_seed_slots: Vec<usize> = slots
        .iter()
        .enumerate()
        .filter(|(_, s)| {
            // remaining == 0 alone is not "complete": a slot whose
            // segments were parser-dropped (or claimed by another file)
            // never had anything to fetch and is missing, not done.
            !s.is_par2_main
                && s.remaining.load(Ordering::Relaxed) == 0
                && s.missing.load(Ordering::Relaxed) == 0
        })
        .map(|(i, _)| i)
        .collect();

    let verifier = Arc::new(nzbkit::live::LiveVerifier::with_partials_cap(
        slots.len(),
        budget.partials_cap(),
    ));
    // Fast verify (TODO §10): default ON - bench-validated 2.9× on
    // CPU-bound boxes (Europe bench box E-core round, 21 Jul), nzbget parity.
    // The env var overrides flag/config either way (bench A/Bs).
    let fast_verify = match std::env::var("NZBFAST_FAST_VERIFY") {
        Ok(v) => v != "0",
        Err(_) => fast_verify,
    };
    verifier.set_fast_verify(fast_verify);
    verifier.set_lean(fast_verify && verify_lean);
    // Measurement arm for the verified-CRC reuse (RAR audit round 30).
    // Default on; `NZBFAST_NO_CRC_REUSE=1` re-hashes every needed piece
    // from the bytes, which is the pre-2 Sep behaviour and the only way
    // to price the reuse on one binary. Trust is unchanged either way.
    if std::env::var("NZBFAST_NO_CRC_REUSE").is_ok_and(|v| v != "0") {
        verifier.set_crc_reuse(false);
    }
    if !fast_verify {
        info!(target: "verify", "full (per-block MD5+CRC32)");
    } else if verify_lean {
        info!(
            target: "verify",
            "lean - article CRCs skipped once PAR2 covers a file (single-CRC32 in-stream; end-of-job verification unchanged)"
        );
    }
    let n_par2_slots = slots.iter().filter(|s| s.is_par2_main).count();
    let par2_outstanding = Arc::new(AtomicUsize::new(n_par2_slots));
    // NOTE: no `verifier.set_off()` when n_par2_slots == 0 any more. A
    // fully obfuscated post (issue #14) names no par2 anywhere, yet its
    // recovery volumes identify themselves by packet magic in the first
    // round-trips - the verifier stays in Waiting so that sniff can still
    // activate the set mid-download. For a post with genuinely no par2
    // the Waiting cost is a few bytes of pre-span bookkeeping per article
    // and a 16 KiB head capture per file, and settle behaves as before.
    //
    // Issue #14 runtime state: slots reclassified as recovery data by the
    // offset-0 `PAR2\0PKT` sniff. A dynamic bootstrap is only electable
    // when the NZB gave us no par2 slot at all - otherwise the activation
    // counter belongs to the static slots and sniffed volumes just defer.
    let sniff = Arc::new(SniffCtl {
        nzb: nzb.clone(),
        slot_file: slot_file.to_vec(),
        allow_bootstrap: n_par2_slots == 0,
        state: Default::default(),
        deferred_articles: AtomicUsize::new(resume_deferred_arts),
        deferred_bytes: AtomicU64::new(resume_deferred_bytes),
        // The same counter the resume seeding above already credited
        // its deferred bytes into - a live deferral has to reach it too
        // (Codex sweep 2, 3 Aug ML2).
        fetch_done: fetch_done.clone(),
    });
    if !resume_sniffed_slots.is_empty() {
        info!(
            target: "resume",
            "{} restored file(s) are recovery volumes by content - deferring {resume_deferred_arts} unfetched article(s)",
            resume_sniffed_slots.len()
        );
        // Registered as sniffed-but-never-bootstrap: the repair planner
        // sees them (deferred_files) while the election stays open for
        // volumes whose heads still fetch and decode this run.
        sniff
            .state
            .lock_ok()
            .sniffed
            .extend(resume_sniffed_slots.iter().copied());
    }
    // All file writing goes through the extractor: plain files write
    // through; store-mode RAR volumes extract in-stream (M3). Resumed
    // runs under NZBFAST_NO_RESUME_MAP disable in-stream mapping
    // (restored spans then never flow through `write`, so headers would
    // be incomplete) - volumes materialize and extraction happens from
    // disk after verification instead. With it, the replay feeds the
    // restored spans through `write` as the run opens, and mapping
    // proceeds as on a fresh run.
    // The archive shape prints ONCE, folded into the first volume line
    // that lands after the mappers have worked it out - several decode
    // consumers race for that line, so the flag is shared.
    let shape_said = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // §94 A: resumed jobs map in-stream. Restored spans REPLAY through
    // the normal write path - per slot, as soon as that slot can place
    // them (see `ReplayPending`) - so the mappers re-derive their state
    // from the same code a fresh run uses and the run continues
    // one-pass; only the still-missing fraction transits the wire, and
    // only the resumed fraction is read back off disk. Without it a
    // resumed run materializes volumes and extracts from disk, as
    // before. `resume` stays true either way - writers must adopt
    // restored files without truncating them.
    //
    // DEFAULT ON since 21 Aug 2026, with `NZBFAST_NO_RESUME_MAP=1` as
    // the kill switch, per the plan's sequencing (build dark, soak,
    // then flip in its own commit).
    //
    // Measured on a 4 GiB store set killed at half and resumed, over a
    // loopback post, out-dir on a dedicated disk image
    // (research/MEASURED-94A-resume-map-2026-08-21.md). Device I/O as a
    // multiple of payload: a clean run 1.01x, the resumed run 2.53x
    // without this and 1.51x with it - and a PEAK footprint of 0.95x
    // rather than 1.9x, because no volume file is written at all. The
    // last 0.5x is the replay writing bytes the output already holds;
    // recognising those ranges as already-correct instead of feeding
    // them is the next step, and is not taken yet.
    //
    // The first cut of the replay was WORSE than not mapping at all
    // (4.4x at a 2 GB budget, 13.6x at 512 MB) because it fed every
    // restored span before the pool opened and held all of them. Three
    // things fixed that and all three are load-bearing: `replay_order`
    // sorts the seeds, `ReplayPending` waits for each slot to be able
    // to PLACE what it is given, and the admission gate below declines
    // to map at all when the restored bytes cannot fit. With them the
    // mapped path is never worse than the ordinary one at any budget -
    // 1.51x where it fits, and exactly the 2.53x adopt path where it
    // does not.
    //
    // The decision itself is `plan.rs resume_map_admitted`, made before
    // the restore because the restore's own behaviour depends on it -
    // a run that will replay must not have its placements copied into
    // volume files first. `resuming` still gates it here: a fresh run
    // maps because it is fresh, not because of §94 A.
    let resume_map = resuming && resume_map;
    let extractor = Arc::new(nzbkit::extract::Extractor::with_resume(
        out_dir,
        slots.len(),
        !no_extract && (!resuming || resume_map),
        resuming,
    ));
    // The root has to know its own Arc before any span arrives, or a
    // top-level chase (a posted .7z) has nothing for its worker to reach
    // the extractor through and quietly declines. Unconditional: the
    // promote hook below anchors too, but it only exists on the daemon
    // path, and `nzbfast get` chases the same archives.
    extractor.anchor();
    // §94 B, DEFAULT ON since 23 Aug 2026 (`NZBFAST_CHASE_VERIFY_GATE=0`
    // is the escape hatch): the chase decode gates on the PAR2
    // verified-block watermark, so a repair can never rewrite consumed
    // bytes and the "repair rewrote chased bytes" demote becomes
    // unreachable for gated sets. The frontier's conflict tripwire
    // stays armed underneath either way. Flipped on the three
    // preconditions §94 B set: the damaged-corpus leg (row 27, 2.55x ->
    // 1.01x nested), the gated e2e damage matrix (22 Aug), and the
    // costB2 leg with the gate and row 26's in-place repair both on
    // (23 Aug: 2.02x, zero forfeits, inert on missing-article damage,
    // and 2.05x -> 1.01x on the silent-corruption twin at the root).
    //
    // The HANDLE is attached unconditionally (22 Aug 2026): the dropping
    // trim reads its watermark to drop only bytes the verifier has
    // vouched for, spilling the rest, so a drop can never leave the
    // settle read-back a range nothing can serve. Only the decode's
    // WAIT on it answers to the env variable.
    let gate = nzbkit::live::VerifyGate::new(slots.len());
    verifier.set_gate(gate.clone());
    // The byte source the self-prove prefix hasher reads through - the
    // SAME reader settle read-back uses, so what it hashes is what the
    // repair rereads. Wired unconditionally and inert until damage arms
    // a slot: no thread, no read, no hash on a clean job
    // (`nzbkit::live::prefix`).
    {
        let ex = extractor.clone();
        verifier.set_prefix_reader(std::sync::Arc::new(
            move |slot: usize, off: u64, buf: &mut [u8]| ex.read_at(slot, off, buf),
        ));
    }
    extractor.set_verify_gate(gate);
    // ... and the other half of the same question (3 Sep 2026). The
    // handle above is attached unconditionally, so a job whose post
    // carries NO parity has a gate no slot ever engages: `vouched` in
    // `rar_trim_volume` is false for the life of the run and every byte
    // the drop-behind decides to release is SPILLED into the volume
    // files instead. Measured on a 1.87 GB `-m3` set: 48,149 of 48,151
    // passes decided DROP and 0 dropped, costing 1.6-1.8 GB of extra
    // device writes and up to 1.36 GB of extra peak footprint against
    // the identical set with a 10% PAR2 set beside it.
    //
    // The extractor asks this only once EVERY slot's offset-0 span has
    // reached it (`Extractor::parity_ruled_out`), which is what turns
    // "nothing is recovery data yet" into "nothing ever will be": a
    // par2 volume is identified from its offset-0 bytes and nowhere
    // else, and `reclassify_sniffed_par2` sets the slot's flag BEFORE
    // the same span is handed to `write_verified`.
    //
    // THREE CONJUNCTS, and each closes a different way parity can still
    // arrive:
    //
    // - `n_par2_slots == 0`: the NZB named no par2 main and elected no
    //   bootstrap volume. A captured constant.
    // - no set has EVER activated. This is the MONOTONIC anchor - once a
    //   set is live it stays live, a second one merges - and it is why
    //   the sniff flags below can be trusted although they are not
    //   monotonic themselves: `mark_reconciled` clears a slot's flag
    //   when the activated set proves the "volume" was really
    //   set-covered payload, and that can only happen with a set already
    //   live, which this conjunct has already refused.
    // - and nothing is currently believed to be recovery data.
    //
    // Everything fails safe. A slot whose head never arrives - a
    // missing article, a sample-skipped file, a donated one - keeps
    // `heads_left` above zero and the vouch stands for the whole run.
    // And a CRC-failed article never reaches `write_verified` at all in
    // this regime (the integrity delegation that skips the article CRC
    // needs a live set, which the second conjunct has refused), so a
    // head is only ever counted from bytes whose classification is
    // final.
    //
    // AND IT TAKES NO LOCK, which is a requirement and not a nicety:
    // the extractor asks it from under its ROUTING lock, and the settle
    // read-back runs the other way round - `LiveVerifier::finish_slot_from`
    // holds the verifier's `plan` for read and then reads bytes through
    // `Extractor::read_at`, which takes that routing lock. Both orders at
    // once is AB/BA as soon as an `activate` is waiting for the write
    // lock, since a pending writer parks new readers. So this reads
    // `ever_activated` (an atomic) rather than `sets()`, and the
    // per-slot `par2_sniffed` flags rather than `SniffCtl::any_sniffed`
    // (a mutex) - the flags carry the same population, resume-restored
    // volumes included, because `plan.rs` seeds them from
    // `resume_sniffed` exactly as vrig seeds the sniff ledger.
    {
        // WEAK on purpose, and it has to stay weak. The extractor owns
        // this closure; the verifier's prefix table owns a reader that
        // holds `Arc<Extractor>` (set_prefix_reader, just above). A
        // strong handle here closes the ring
        //
        //   LiveVerifier -> PrefixTable -> reader -> Extractor
        //                -> no_parity_hook -> LiveVerifier
        //
        // so NEITHER end ever drops, `Drop for LiveVerifier` never runs,
        // and `PrefixTable::shutdown` - the only thing that stops the
        // `par2-prefix` worker - is never called. That leaks the thread
        // and its 1 MiB hash buffer for the life of the process, once
        // per job that arms a slot. It is what took the soak red on
        // d7d89a88: +63 threads and +381.6 MiB over 2h21m, on flat
        // slopes, with every other thread class measured flat.
        let v = std::sync::Arc::downgrade(&verifier);
        let sl = slots.to_vec();
        extractor.set_no_parity_hook(std::sync::Arc::new(move || {
            // Gone means the run that owned it is over, and "parity is
            // ruled out" is the answer that lets the drop-behind DROP.
            // Answer the conservative half instead - the pre-660abf2ae
            // behaviour - rather than deciding anything on a dead run.
            let Some(v) = v.upgrade() else { return false };
            n_par2_slots == 0
                && !v.ever_activated()
                && !sl.iter().any(|s| s.par2_sniffed.load(Ordering::Relaxed))
        }));
    }
    extractor.set_verify_gate_waits(verify_gate_waits_value(
        std::env::var("NZBFAST_CHASE_VERIFY_GATE").ok().as_deref(),
    ));
    extractor.set_holds_cap(budget.holds_cap());
    // TODO 219 follow-up: under the daemon two pipelines are alive
    // during a hand-over, and each would otherwise claim the full 45%
    // slice. The process ledger makes the pair share one cap - the job
    // on the lane keeps the whole slice, the successor sees what is
    // left. Only the daemon installs a ledger; `get` is unchanged.
    if let Some(ledger) = nzbkit::extract::process_ledger() {
        extractor.join_holds_ledger(&ledger);
    }
    // One-pass zip, split sets: a byte-split zip cannot be sized from
    // its own bytes (no part carries a container-sizing header, unlike
    // 7z), so the NZB's file list - which we have and the extractor
    // does not - declares each set's part count. Declared only when the
    // indices run exactly 1..=n: a set the NZB itself has a hole in can
    // never stream, and not declaring it keeps every part on the
    // phase-1 disk path.
    {
        let mut sets: HashMap<String, Vec<u32>> = HashMap::new();
        for s in slots.iter().filter(|s| !s.is_par2_main) {
            // Bare-numeric sets (`movie.001`, no `.zip.` infix) declare
            // too - the declaration is speculative (RAR numeric volumes
            // share the grammar), and that is fine: RAR and 7z magic
            // classify before the zip split arm is consulted, and a
            // declared set whose part 1 does not sniff `PK\x03\x04`
            // forfeits to the disk path exactly as an undeclared one
            // would have landed there.
            if let Some((base, idx)) = nzbkit::zip::split_part_name(&s.hint)
                .or_else(|| nzbkit::zip::numeric_split_part_name(&s.hint))
            {
                sets.entry(base).or_default().push(idx);
            }
        }
        for (base, mut idxs) in sets {
            idxs.sort_unstable();
            let n = idxs.len() as u32;
            if idxs.first() == Some(&1)
                && idxs.last() == Some(&n)
                && idxs.windows(2).all(|w| w[0] < w[1])
            {
                extractor.declare_zip_split(&base, n);
            }
        }
    }
    // TODO 211 (b): the same declaration for a `.rar.NNN` byte split of
    // a single `.rar`, for the same reason - no RAR header sizes the
    // container, so the NZB's part count is what lets the head's mapper
    // close once every part's exact size is in. Same gapless rule: a
    // set the NZB has a hole in never maps, and undeclared parts take
    // the disk path plus the (a) rescue exactly as before.
    {
        let mut sets: HashMap<String, Vec<u32>> = HashMap::new();
        for s in slots.iter().filter(|s| !s.is_par2_main) {
            if let Some((base, idx)) = nzbkit::extract::rar_split_part_name(&s.hint) {
                sets.entry(base).or_default().push(idx);
            }
        }
        for (base, mut idxs) in sets {
            idxs.sort_unstable();
            let n = idxs.len() as u32;
            if idxs.first() == Some(&1)
                && idxs.last() == Some(&n)
                && idxs.windows(2).all(|w| w[0] < w[1])
            {
                extractor.declare_rar_split(&base, n);
            }
        }
    }
    // An inner file's declared `unpacked_size` is an attacker-controlled
    // RAR header vint, and on Linux preallocation is a real fallocate - so
    // a few-hundred-KB post declaring 8 TB used to genuinely reserve the
    // volume's free space until the finish-time gates demoted it. The
    // NZB's own posted byte count is the defensible bound: nothing posted
    // here can legitimately unpack to more than what was posted (compressed
    // inner files can, but preallocation is an optimisation - writes past
    // the reservation extend the file exactly as they do on macOS, where
    // nothing is reserved at all). Deliberately a RESERVATION ceiling and
    // not a clamp on the declared size, which resume truncation and the
    // reported extracted size both depend on.
    // The posted count is itself an untrusted attribute an attacker can
    // inflate alongside the yEnc `size=`, and an NZB with NO byte
    // attributes used to get no ceiling at all - so the post's article
    // geometry (articles x a generous per-article max) bounds it both
    // ways. Same bound as the recovery-volume side-fetch.
    extractor.set_prealloc_ceiling(crate::repair::volume_prealloc_cap(nzb));
    // Decompression-bomb budget for the IN-STREAM extractor - the same
    // guard `write_archives_to`/`extract_one_sevenz` put on the disk and
    // post-pass sinks, which until now covered only the fallback and not
    // the default path. Shared across every inner file and every nesting
    // level, so a bomb split over many outputs gets one allowance.
    //
    // FLOORED at the post's own byte bound, and that floor is what makes
    // free space a legitimate ceiling here at all. On the DISK path the
    // volumes are already on disk when extraction starts, so free space
    // is genuinely the room the output has left to grow into. On the
    // in-stream path they never land: the extracted file IS the job's
    // whole footprint, and free-space-minus-reserve therefore demands
    // payload + 256 MB free to write payload bytes. A RAR5 STORED set -
    // no expansion whatever, the extracted size equals the packed size -
    // then trips a "decompression bomb" purely for being on a tight
    // disk. Measured 22 Aug 2026 on the TODO 206 class E floor: a
    // 6.48 GB set on 1.02x free failed all three reps at the last
    // ~134 MB, the exact size of the reserve overhang; 1.05x passed.
    //
    // Nothing posted can legitimately unpack to LESS than what was
    // posted, so a budget below that bound is not a bomb test - it is a
    // disk-space test wearing a bomb's error message, and disk space is
    // ENOSPC's job (which halts with the right verdict and keeps the
    // journal). The same bound the preallocation ceiling above uses, for
    // the same reason and with the same untrusted-attribute guard.
    if let Some(free) = crate::diskfree::free_bytes(out_dir) {
        extractor.set_extract_budget(instream_extract_budget(
            free,
            crate::repair::volume_prealloc_cap(nzb),
        ));
        // Holds-paging scratch ceiling: transient relief for the RAM
        // holds cap, not a second copy of the download - 4x the RAM cap,
        // and never more than a quarter of post-reserve free space (the
        // payload itself still has to fit). Exceeding it demotes with
        // the same "held-bytes cap" reasons as a RAM breach.
        extractor.set_holds_scratch_cap(
            (4 * budget.holds_cap() as u64).min(free.saturating_sub(EXTRACT_RESERVE) / 4),
        );
    }
    // With a password, RAR5 encrypted STORE sets stay on the in-stream
    // path: ciphertext assembles at plain store offsets and one AES pass
    // at finish decrypts it - no materialized volumes, no unrar.
    if let Some(pw) = &password {
        extractor.set_password(pw);
    }
    // One-pass encrypted plan, increment A: see install_password_probe.
    // The dominant poster is the §99 try-order key the probe can read
    // off the NZB itself; the source-site key rides the hub.
    install_password_probe(
        &extractor,
        hub,
        out_dir,
        stream_owner,
        &crate::smart::dominant_poster(nzb),
    );
    // Materialized-volume demote (advG follow-up, 13 Aug 2026): when a
    // slot falls back to volumes-on-disk, its reconstruction puts every
    // journaled byte at final offsets in the volume file - and then
    // deletes the inner files the R records name as copy sources, so
    // without this line a retry over intact, complete volumes refetched
    // the ENTIRE post. The M record lets parse rewrite those placements
    // to identity form.
    //
    // Weak, like the promote hook: the extractor outlives this scope, and
    // a strong clone parked in it would defeat the `Arc::try_unwrap` that
    // retires the whole journal after a verified finish. A journal that is
    // already gone records nothing, which is the right answer once the
    // job is done.
    {
        let j = Arc::downgrade(journal);
        extractor.set_materialized_hook(Arc::new(move |slot: usize, name: &str, size: u64| {
            if let Some(j) = j.upgrade() {
                j.record_materialized(slot, name, size);
            }
        }));
    }
    // Crash resume (placement journal): see replay_or_adopt_restored.
    let replay = Arc::new(replay_or_adopt_restored(
        restored, slots, resume_map, &extractor, &verifier, out_dir, journal,
    ));
    // Seeds that carry their own offset 0 need no fresh article to
    // trigger them (see `ReplayPending::try_drain`), and a run whose
    // every head is restored may never write an offset 0 at all.
    if !replay.is_empty() {
        replay.try_drain(&extractor, &verifier);
    }
    // Fully-resumed slots see no articles - seed their names so PAR2
    // matching and read-back verification still reach them.
    for &si in &verifier_seed_slots {
        verifier.set_name_hint(si, &slots[si].hint);
    }
    Rig {
        verifier,
        fast_verify,
        par2_outstanding,
        sniff,
        shape_said,
        resume_map,
        extractor,
        replay,
    }
}

/// Build the M11 seek-promotion ladder, wire the extractor's promote
/// hook through a weak ref, and publish the run's control surfaces
/// (extractor, verifier, seek, abort, queue ctl, per-file table) on the
/// hub. Returns the SeekCtl clone the decode consumers register observed
/// names on.
#[expect(clippy::too_many_arguments)]
pub(super) fn install_seek(
    nzb: &nzbkit::nzb::Nzb,
    slots: &[Arc<FileSlot>],
    slot_file: &[usize],
    slot_arts: &mut Vec<(Vec<(u64, std::sync::Arc<str>)>, u64)>,
    queue_ctl: &Arc<nzbkit::pool::QueueControl>,
    abort_flag: &Arc<std::sync::atomic::AtomicBool>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    hub: &Option<Arc<StreamHub>>,
    stream_owner: &str,
) -> Arc<SeekCtl> {
    // The promote ladder is built for EVERY run, not just the daemon's.
    // A player seek needs the hub; the 7z tail prefetch does not - it is
    // the extractor asking for the articles carrying an archive's end
    // header, and without it the chase cannot read the archive map until
    // the tail arrives on its own, which in a sequential download is
    // last. That turns one-pass into a decode burst at the end, and it
    // denies drop-behind trimming the read watermark it needs, so a `get`
    // of a large .7z demoted where the daemon streamed it.
    let seek = {
        let mut vol_slots: Vec<usize> = slots
            .iter()
            .enumerate()
            .filter(|(_, s)| !s.is_par2_main)
            .map(|(i, _)| i)
            .collect();
        vol_slots.sort_by_key(|&i| nzbkit::extract::vol_sort_key(&slots[i].hint));
        // First insertion wins on a duplicate hint - same article ladder
        // either way for the split-volume sets where hints repeat.
        let mut slot_by_name = std::collections::HashMap::new();
        for &i in &vol_slots {
            slot_by_name
                .entry(nzbkit::disk::sanitize_out_name(&slots[i].hint))
                .or_insert(i);
        }
        let slot_articles = std::mem::take(slot_arts);
        let observed = slot_articles
            .iter()
            .map(|_| std::sync::atomic::AtomicBool::new(false))
            .collect();
        Arc::new(SeekCtl {
            slot_articles,
            ctl: queue_ctl.clone(),
            extractor: extractor.clone(),
            vol_slots,
            slot_by_name,
            observed_by_name: std::sync::RwLock::new(std::collections::HashMap::new()),
            observed,
        })
    };
    // The decode consumers register observed yEnc names (obfuscated
    // sets) - cloned HERE because `seek` itself moves into the hub.
    let seek_names = seek.clone();
    // Weak - the hook must not pin the SeekCtl/Extractor pair into a
    // reference cycle.
    let weak_seek = Arc::downgrade(&seek);
    extractor.set_promote_hook(Arc::new(
        move |name: &str, size: u64, spans: &[(u64, u64)], urgent: bool| {
            if let Some(s) = weak_seek.upgrade() {
                s.promote_output_spans(name, size, spans, urgent);
            }
        },
    ));
    // Held-bytes backpressure (TODO 94 item E): the root extractor
    // parks a chased group's slots at the pool near its holds cap and
    // releases them as the engine catches up. Slots ARE the pool's file
    // ordinals (`ArticleReq::file`). A Weak, like the promote hook: the
    // queue control outlives the run only through the hub.
    let weak_ctl = Arc::downgrade(queue_ctl);
    let weak_gauge = Arc::downgrade(queue_ctl);
    extractor.set_park_hook(
        Arc::new(move |slots: &[usize], allow: Option<u64>| {
            if let Some(ctl) = weak_ctl.upgrade() {
                let files: Vec<u32> = slots.iter().map(|&s| s as u32).collect();
                ctl.park_files(&files, allow);
                tracing::trace!(
                    target: "extract",
                    "holds backpressure: {} slot(s) at the pool, allowance {:?}",
                    files.len(),
                    allow
                );
            }
        }),
        Some(Arc::new(move || {
            let wire = weak_gauge
                .upgrade()
                .and_then(|c| c.wire_inflight_bytes())
                .unwrap_or(0);
            // Between the wire and the holds: raw bodies off the socket
            // (channel and decoder hands) and decoded payloads not yet
            // routed. Process-wide gauges, which is conservative under
            // a hand-over and exact otherwise.
            use nzbkit::memgauge::{Sub, cur};
            (wire, cur(Sub::RawOut) + cur(Sub::OutOut))
        })),
    );
    // TODO 274: the per-file table the API reports and promotes
    // through. Built HERE because this is the one place that holds the
    // NZB, the slots and the article ladder at once, and built ONCE
    // because a listing poll must not re-parse anything. The rows cover
    // every NZB file in NZB order; `slot_file` runs the other way (slot
    // -> file), so it is inverted onto the rows rather than kept.
    let job_files = {
        let mut rows: Vec<crate::streamhub::JobFileRow> = nzb
            .files
            .iter()
            .enumerate()
            .map(|(i, f)| crate::streamhub::job_file_row(i, f))
            .collect();
        for (si, &fi) in slot_file.iter().enumerate() {
            if let Some(r) = rows.get_mut(fi) {
                r.slot = Some(si);
            }
        }
        Arc::new(crate::streamhub::JobFiles {
            rows,
            slots: slots.to_vec(),
            seek: seek.clone(),
        })
    };
    if let Some(h) = &hub {
        *h.extractor.lock_ok() = Some((stream_owner.to_string(), extractor.clone()));
        *h.verifier.lock_ok() = Some(verifier.clone());
        *h.seek.lock_ok() = Some(seek);
        *h.abort.lock_ok() = Some(abort_flag.clone());
        *h.queue_ctl.lock_ok() = Some(queue_ctl.clone());
        *h.job_files.lock_ok() = Some((stream_owner.to_string(), job_files));
    }
    seek_names
}

/// The in-stream extractor's decompression-bomb allowance: free space
/// less the reserve, but never below what the post itself declares.
///
/// See the call site for why the floor is load-bearing on this path and
/// not on the disk one. `posted` is `volume_prealloc_cap` - the posted
/// byte count bounded by the post's article geometry, so an inflated
/// attribute cannot buy an attacker allowance it did not also declare
/// articles for.
pub(super) fn instream_extract_budget(free: u64, posted: u64) -> u64 {
    free.saturating_sub(EXTRACT_RESERVE).max(posted)
}

/// Pure parse of `NZBFAST_CHASE_VERIFY_GATE` (unit-testable without
/// touching the process environment under the parallel test runner, the
/// `chase_repair_on_value` pattern in `repair.rs`). Only the exact `0`
/// disables the decode's wait on the verified-block watermark: `1` was
/// the soak-era opt-in and still means on, and a near-miss like `false`
/// must not silently hand a set back to the materialize route.
pub(crate) fn verify_gate_waits_value(v: Option<&str>) -> bool {
    v != Some("0")
}

#[cfg(test)]
mod tests {
    use super::*;

    // §94 B went default-ON on 23 Aug 2026; the switch that matters is
    // the one that turns it OFF, and only the exact `0` is that switch.
    #[test]
    fn only_an_exact_zero_disables_the_verify_gate_wait() {
        assert!(
            verify_gate_waits_value(None),
            "unset must be ON after the flip"
        );
        assert!(
            !verify_gate_waits_value(Some("0")),
            "the escape hatch must bite"
        );
        assert!(
            verify_gate_waits_value(Some("1")),
            "the soak-era opt-in still means on"
        );
        assert!(verify_gate_waits_value(Some("")), "empty is not the hatch");
        assert!(
            verify_gate_waits_value(Some("false")),
            "only `0` is the hatch"
        );
    }

    /// BUG (HIGH): the in-stream bomb budget was free-space-minus-reserve
    /// flat, which on the one-pass path (volumes never land, so the
    /// extracted file is the job's whole footprint) demands
    /// payload + 256 MB free to write payload bytes. A RAR5 STORED set
    /// expands by nothing at all and still tripped "possible
    /// decompression bomb" for being on a tight disk - TODO 206 class E,
    /// 22 Aug 2026: 6,483,486,514 bytes onto 6,612,279,296 free failed
    /// all three reps at the last ~134 MB, the size of the reserve
    /// overhang. Whether the payload physically FITS is ENOSPC's
    /// question, and ENOSPC answers it with the right verdict.
    #[test]
    fn a_stored_set_is_never_a_bomb_on_a_tight_disk() {
        const RESERVE: u64 = EXTRACT_RESERVE;
        let payload = 6_483_486_514u64;
        let free = 6_457_304u64 * 1024; // 1.02x the payload, the failing leg

        assert!(
            free.saturating_sub(RESERVE) < payload,
            "the leg's arithmetic must still be the tight one"
        );
        assert!(
            instream_extract_budget(free, payload) >= payload,
            "a stored set writing exactly what was posted must not trip"
        );

        // A genuine bomb is unaffected: a small post on a big disk still
        // gets the free-space ceiling, because the floor is below it.
        let tiny_post = 4u64 << 20;
        let big_disk = 900u64 << 30;
        assert_eq!(
            instream_extract_budget(big_disk, tiny_post),
            big_disk - RESERVE,
            "the floor must never RAISE a bomb's allowance"
        );

        // And an NZB with no byte attributes at all (posted == 0, the
        // "unknown" case volume_prealloc_cap folds into geometry) keeps
        // exactly today's behaviour.
        assert_eq!(
            instream_extract_budget(big_disk, 0),
            big_disk - RESERVE,
            "an unknown post size must not change the ceiling"
        );
    }
}
