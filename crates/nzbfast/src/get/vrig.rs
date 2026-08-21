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
}

#[allow(clippy::too_many_arguments)]
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
    if !fast_verify {
        println!("verify: full (per-block MD5+CRC32)");
    } else if verify_lean {
        println!(
            "verify: lean - article CRCs skipped once PAR2 covers a file \
             (single-CRC32 in-stream; end-of-job verification unchanged)"
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
        println!(
            "resume: {} restored file(s) are recovery volumes by content - \
             deferring {resume_deferred_arts} unfetched article(s)",
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
    // runs without NZBFAST_RESUME_MAP disable in-stream mapping
    // (restored spans then never flow through `write`, so headers would
    // be incomplete) - volumes materialize and extraction happens from
    // disk after verification instead. With it, the replay below feeds
    // the restored spans through `write` first, and mapping proceeds as
    // on a fresh run.
    // The archive shape prints ONCE, folded into the first volume line
    // that lands after the mappers have worked it out - several decode
    // consumers race for that line, so the flag is shared.
    let shape_said = Arc::new(std::sync::atomic::AtomicBool::new(false));
    // §94 A: resumed jobs map in-stream. Restored spans REPLAY through
    // the normal write path before the network opens, so the mappers
    // re-derive their state from replayed headers and the run continues
    // one-pass; only the still-missing fraction transits the wire, and
    // only the resumed fraction is read back off disk. Opt-in while it
    // soaks (NZBFAST_RESUME_MAP=1); without it a resumed run
    // materializes volumes and extracts from disk, as before. `resume`
    // stays true either way - writers must adopt restored files without
    // truncating them.
    let resume_map =
        resuming && !no_extract && std::env::var("NZBFAST_RESUME_MAP").is_ok_and(|v| v == "1");
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
    // §94 B, opt-in while it soaks (NZBFAST_CHASE_VERIFY_GATE=1): the
    // chase decode gates on the PAR2 verified-block watermark, so a
    // repair can never rewrite consumed bytes and the "repair rewrote
    // chased bytes" demote becomes unreachable for gated sets. The
    // frontier's conflict tripwire stays armed underneath either way.
    if std::env::var("NZBFAST_CHASE_VERIFY_GATE").is_ok_and(|v| v == "1") {
        let gate = nzbkit::live::VerifyGate::new(slots.len());
        verifier.set_gate(gate.clone());
        extractor.set_verify_gate(gate);
    }
    extractor.set_holds_cap(budget.holds_cap());
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
    if let Some(free) = crate::serve::free_bytes(out_dir) {
        extractor.set_extract_budget(free.saturating_sub(EXTRACT_RESERVE));
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
    // That AES pass replaces the ciphertext this journal's placement
    // records point INTO. Once a file holds plaintext it is no longer the
    // bytes the journal describes, so a resume that still trusted it would
    // copy translated fragments out of it into the volume files and mark
    // those articles restored - skipping the refetch, and without PAR2
    // looping forever on poisoned local bytes while the provider still has
    // every original article. Gate the publish on retiring the claim
    // first: the extractor hands over the output names and moves no byte
    // until this returns Ok, and `invalidate` is durable before it does.
    //
    // Weak, like the promote hook: the extractor outlives this scope, and
    // a strong clone parked in it would defeat the `Arc::try_unwrap` that
    // retires the whole journal after a verified finish. A journal that is
    // already gone claims nothing, so publishing is free.
    {
        let j = Arc::downgrade(journal);
        extractor.set_decrypt_barrier(Arc::new(move |names: &[String]| match j.upgrade() {
            // retire_for_decrypt = invalidate + parking the dropped
            // placements, so the publish hook below can republish them.
            Some(j) => j.retire_for_decrypt(names),
            None => Ok(()),
        }));
    }
    // Materialized-volume demote (advG follow-up, 13 Aug 2026): when a
    // slot falls back to volumes-on-disk, its reconstruction puts every
    // journaled byte at final offsets in the volume file - and then
    // deletes the inner files the R records name as copy sources, so
    // without this line a retry over intact, complete volumes refetched
    // the ENTIRE post. The M record lets parse rewrite those placements
    // to identity form. Weak for the same try_unwrap reason as above.
    {
        let j = Arc::downgrade(journal);
        extractor.set_materialized_hook(Arc::new(move |slot: usize, name: &str, size: u64| {
            if let Some(j) = j.upgrade() {
                j.record_materialized(slot, name, size);
            }
        }));
    }
    // TODO 100: the publish half of the handshake. Once a file's verified
    // plaintext is RENAMED into place, its crypt facts land as E/K/T
    // records and the retired placements republish as D records - the
    // plaintext-once grammar, which a resume run restores by re-encrypting
    // the local plaintext. Without this, a later failure in the same job
    // (another file's ENOSPC, the nested pass) left a journal that could
    // vouch for nothing of a file that was already done, and the retry
    // refetched essentially the whole set.
    {
        let j = Arc::downgrade(journal);
        extractor.set_decrypt_publish(Arc::new(
            move |name: &str, evs: &[nzbkit::extract::CryptoJournalEvent]| {
                if let Some(j) = j.upgrade() {
                    j.record_decrypted(name, evs);
                }
            },
        ));
    }
    // Crash resume (placement journal): see replay_or_adopt_restored.
    replay_or_adopt_restored(restored, slots, resume_map, &extractor, &verifier, out_dir);
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
    }
}

/// Build the M11 seek-promotion ladder, wire the extractor's promote
/// hook through a weak ref, and publish the run's control surfaces
/// (extractor, verifier, seek, abort, queue ctl) on the hub. Returns
/// the SeekCtl clone the decode consumers register observed names on.
#[allow(clippy::too_many_arguments)]
pub(super) fn install_seek(
    slots: &[Arc<FileSlot>],
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
                .entry(nzbkit::disk::sanitize_filename(&slots[i].hint))
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
    if let Some(h) = &hub {
        *h.extractor.lock_ok() = Some((stream_owner.to_string(), extractor.clone()));
        *h.verifier.lock_ok() = Some(verifier.clone());
        *h.seek.lock_ok() = Some(seek);
        *h.abort.lock_ok() = Some(abort_flag.clone());
        *h.queue_ctl.lock_ok() = Some(queue_ctl.clone());
    }
    seek_names
}
