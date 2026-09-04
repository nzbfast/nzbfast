//! Rig-phase helpers for get_with_progress (TODO 106 phase 2.1, cut 3):
//! the in-stream password probe hook and the crash-resume replay/adopt
//! pass. Bodies are verbatim moves from the orchestrator.

use crate::*;
use std::collections::HashMap;
use std::path::Path;
use tracing::{info, warn};

// Increment A (one-pass encrypted plan, 2026-07-31): candidate probe
// over the job's OWN files. Password sidecars ride the same NZB and
// land within the head round (M3 scheduling fetches every file's
// first segment up front, and a password note is one segment), so
// when an encrypted set blocks, the extractor parks it and asks this
// hook instead of demoting. Candidates are the 2nd-pass harvest
// (small .txt/.nfo/.diz lines, "password:" tails, file stems) plus
// the job directory's name - the release stem an obfuscated post
// carries nowhere else - plus, on daemon runs, a password the user
// typed mid-download (mode=set_password → the hub's owner-tagged
// cell; C2 step 1). Only a check-VERIFIED candidate is returned;
// the tried-set is keyed by (salt, value) so a value that failed one
// set's check is still tested against a second set's - which is also
// what lets a corrected password typed after a wrong one get its
// turn. Check-less sets never park (try_pw_await gates on a
// well-formed check), so an unverifiable typed password can never
// key a mapper here - those sets take the finish-adjudication route.
pub(super) fn install_password_probe(
    extractor: &Arc<nzbkit::extract::Extractor>,
    hub: &Option<Arc<StreamHub>>,
    out_dir: &Path,
    stream_owner: &str,
    poster: &str,
) {
    let dir = out_dir.to_path_buf();
    let poster = poster.to_string();
    let tried: std::sync::Mutex<std::collections::HashSet<([u8; 16], String)>> = Default::default();
    let hub_pw = hub.clone();
    let owner = stream_owner.to_string();
    extractor.set_password_probe(std::sync::Arc::new(move |probe| {
        let t0 = std::time::Instant::now();
        let mut cands = harvest_password_candidates(&dir, None);
        if let Some(n) = dir.file_name().map(|n| n.to_string_lossy().to_string()) {
            let stem = nzbkit::extract::release_stem(&n);
            if stem != n {
                cands.push(PwCandidate {
                    value: stem,
                    source: "job name stem".into(),
                    structured: false,
                });
            }
            cands.push(PwCandidate {
                value: n,
                source: "job name".into(),
                structured: false,
            });
        }
        // The operator's passwords file outranks the harvested
        // guesses (curated beats scraped), re-read per invocation -
        // the operator may add the password WHILE the download
        // runs, and this probe is exactly the moment it pays off:
        // the set re-keys in place and streams one-pass instead of
        // parking for a post-completion unlock. Structured, like
        // the typed password, so the KDF-depth gate never blocks
        // an operator-supplied value.
        if let Some(path) = hub_pw
            .as_ref()
            .and_then(|h| h.unpack_password_file.lock_ok().clone())
        {
            // §99 try-order: the password last known to unlock this
            // NZB's source site first, then this poster's, then the
            // file top to bottom - so the wall-clock budget below is
            // spent on the likeliest lines first.
            let site = hub_pw
                .as_ref()
                .and_then(|h| h.pw_assoc_site_for(&owner))
                .unwrap_or_default();
            for (i, pw) in crate::smart::order_passwords(
                crate::smart::read_password_file(&path),
                &path,
                &site,
                &poster,
            )
            .into_iter()
            .enumerate()
            {
                cands.insert(
                    i,
                    PwCandidate {
                        value: pw,
                        source: "passwords file".into(),
                        structured: true,
                    },
                );
            }
        }
        // The late-typed password outranks every harvested guess:
        // first in line, and structured (operator-supplied) so the
        // KDF-depth gate never blocks it. Re-read per invocation -
        // the cell can change between probes. CLI runs have no hub.
        if let Some(pw) = hub_pw.as_ref().and_then(|h| h.late_password_for(&owner)) {
            cands.insert(
                0,
                PwCandidate {
                    value: pw,
                    source: "set_password (typed mid-download)".into(),
                    structured: true,
                },
            );
        }
        let mut tried = tried.lock_ok();
        for c in cands {
            if !tried.insert((probe.salt, c.value.clone())) {
                continue;
            }
            // Same KDF-depth gate as the 2nd-pass harvest: only the
            // operator's own password may pay for a hostile-depth
            // KDF, and no candidate sweep may exceed the wall-clock
            // budget - a crafted post can stuff sidecars with
            // thousands of lines.
            if !kdf_candidate_allowed(probe.lg2_count, c.structured) {
                continue;
            }
            if t0.elapsed() > PW_PROBE_BUDGET {
                break;
            }
            if probe.verify(&c.value) == nzbkit::rar::PwVerdict::Verified {
                info!(
                    target: "password",
                    "🔑 archive password found in {} (in-stream probe)",
                    c.source
                );
                // A verified key means nobody needs to be asked -
                // and the winner is parked for finalize to record
                // onto the Job (the volumes decrypt one-pass, so
                // the completion path never meets them).
                if let Some(h) = hub_pw.as_ref() {
                    *h.password_wanted.lock_ok() = None;
                    *h.password_found.lock_ok() = Some((owner.clone(), c.value.clone()));
                }
                return Some(c.value);
            }
        }
        // The probe only fires when an encrypted set is BLOCKED on a
        // password, so a fruitless sweep IS the live "this download
        // wants a password" moment. Owner-tagged; the dashboard's
        // "ask at once" mode prompts off the queue slot this raises.
        if let Some(h) = hub_pw.as_ref() {
            *h.password_wanted.lock_ok() = Some(owner.clone());
        }
        None
    }));
}

// Crash resume (placement journal). Two modes:
//
// Replay (§94 A, the default since 21 Aug 2026; kill switch
// NZBFAST_NO_RESUME_MAP=1): restored spans flow through
// `Extractor::write` in offset order BEFORE the network opens,
// exactly as if the articles had just arrived - the offset-0 sniff
// fires, the mappers walk replayed headers, and the run continues
// one-pass. Deliberately NOT re-journaled: the spans are already
// durable, and the old records keep describing where the bytes are
// if this run is killed too (restored source files are only removed
// after a fully-good finish, below). The verifier sees each span as
// an unverified arrival - full MD5 under delegation - because no
// decoder vouched for these bytes THIS run.
//
// Adopt (default): restored files become plain slot writers and
// their spans are registered as pre-spans - the M15b backfill hashes
// every restored byte against the PAR2 block map once the set
// activates, so nothing is trusted unverified.
/// The order the restored seeds are fed back in - **volume order**, and
/// it is load-bearing rather than cosmetic.
///
/// `journal::restore` collects its seeds by walking a `HashMap`, so it
/// returns them in a different arbitrary order every process run. Feed a
/// store set's volumes back in that order and a volume whose
/// predecessors have not been seen yet has no resolved base offset, so
/// every byte of it parks in `holds` until `reresolve` catches up and
/// drains it. The held-bytes cap is judged against the PEAK, so an
/// out-of-order replay pages to scratch (or demotes the group) on sets
/// an ordered replay places without holding a byte.
///
/// Measured both ways by nzbkit's
/// `a_replayed_store_set_places_only_in_volume_order_and_only_with_its_head`,
/// which puts an 8-volume set at under
/// 64 KB held in order and over half the set held in reverse, and the
/// F4 disk round (research/MEASURED-94A-resume-map-2026-08-21.md) saw
/// the unsorted driver hold 100% of the replayed bytes - which is also
/// why two runs of the same leg differed by 2.6x, since each process
/// drew a different order.
///
/// `vol_sort_key` is the same ordering the seek ladder uses. Plain
/// (non-volume) names sort last as one block and are order-independent
/// anyway; the slot index breaks ties so the result is total and
/// deterministic.
fn replay_order(restored: &nzbkit::journal::Restored) -> Vec<&nzbkit::journal::SlotSeed> {
    let mut seeds: Vec<&nzbkit::journal::SlotSeed> = restored.seeds.iter().collect();
    seeds.sort_by(|a, b| {
        nzbkit::extract::vol_sort_key(&a.name)
            .cmp(&nzbkit::extract::vol_sort_key(&b.name))
            .then(a.slot.cmp(&b.slot))
    });
    seeds
}

/// One restored file the replay still owes the extractor, parked until
/// its slot's offset-0 article lands.
pub(super) struct ReplaySeed {
    slot: usize,
    name: String,
    size: u64,
    /// Sorted by `vol_off`. The source is where the bytes physically
    /// ARE: with volume materialisation off (what a mapped resume asks
    /// for) that is the output file run 1 wrote them to, so nothing was
    /// ever copied into a volume file for the replay to read back.
    spans: Vec<ReplaySpan>,
}

/// One restored span the replay feeds back, with the article it came
/// from. Articles are disjoint in volume address space and every span
/// of one article tiles its range, so once `spans` is sorted by `off`
/// an article's spans are contiguous: `feed_spans` folds them into one
/// journal record per article.
struct ReplaySpan {
    off: u64,
    len: u64,
    file: std::sync::Arc<str>,
    file_off: u64,
    /// Message-id of the article these bytes were journaled under.
    id: std::sync::Arc<str>,
}

/// What the extractor did with every span of one replayed article,
/// folded across chunks: the article-level view `ReplayPending::record`
/// journals. Mirrors the `Persist` arms the decode consumer handles -
/// the replay is the same write path fed from disk instead of the wire.
enum Fed {
    /// Every byte placed as plain bytes - journals as an `R` record.
    Placed(Vec<nzbkit::extract::Frag>),
    /// At least one plaintext-once placement - parks as a pending `D`.
    Crypto(Vec<nzbkit::extract::Frag>),
    /// Some bytes were held for a later re-feed; carries the plain
    /// placements already on disk. Parks like `Persist::Held` does.
    Held(Vec<nzbkit::extract::Frag>),
    /// Not on disk as one coherent placement: the record run 1 wrote
    /// stands (last R/D per id wins at the next parse).
    No,
}

impl Fed {
    fn fold(self, p: nzbkit::extract::Persist) -> Fed {
        use nzbkit::extract::Persist;
        let join = |mut a: Vec<nzbkit::extract::Frag>, b: Vec<nzbkit::extract::Frag>| {
            a.extend(b);
            a
        };
        match (self, p) {
            (Fed::No, _) | (_, Persist::No) => Fed::No,
            // A held article completes into a plain `R` through
            // `flush_pending_r`, and an `R` must never describe
            // plaintext-once bytes - same rule as the extractor's own
            // partial view: such an article simply never re-records.
            (Fed::Held(_), Persist::PlacedCrypto(_)) | (Fed::Crypto(_), Persist::Held(_)) => {
                Fed::No
            }
            (Fed::Held(a), Persist::Held(b) | Persist::Placed(b))
            | (Fed::Placed(a), Persist::Held(b)) => Fed::Held(join(a, b)),
            (Fed::Crypto(a), Persist::Placed(b) | Persist::PlacedCrypto(b))
            | (Fed::Placed(a), Persist::PlacedCrypto(b)) => Fed::Crypto(join(a, b)),
            (Fed::Placed(a), Persist::Placed(b)) => Fed::Placed(join(a, b)),
        }
    }
}

/// The restored files §94 A's replay has yet to feed back, keyed by
/// slot. Empty (and every method a no-op) on the adopt path.
///
/// **Why this is deferred rather than done up front.** The obvious
/// driver replays every restored span before the pool opens. It reads
/// correctly and it holds the whole set in RAM, because the one article
/// a store volume needs FIRST is the one article a resume never has.
/// The offset-0 article carries the RAR headers, and those bytes land
/// nowhere on disk - the mapper consumes them - so the article never
/// completes into an `R` record (`Persist::Held` parks it and
/// `flush_pending_r` only journals a span its placements cover). Every
/// restored volume therefore starts at the SECOND article, with a hole
/// exactly where the header is: measured on an 8-volume fixture, every
/// seed's first span began at offset 25000 and the mapper could not
/// parse one of them, so 100% of the replayed bytes sat in `holds`
/// until the heads refetched live and `reresolve` drained them. That
/// peak is what the held-bytes cap is judged against, which is why the
/// F4 disk round measured the replay costing MORE than the ordinary
/// resume on any budget below the set size.
///
/// The head refetches within the first round trips either way (M3 puts
/// every file's first segment at the front of the queue), so waiting
/// for it costs nothing and buys the mapper the header it needs. Each
/// slot's bytes are then fed the moment its own offset-0 write returns,
/// place straight into the output, and hold nothing.
#[derive(Default)]
pub(super) struct ReplayPending {
    seeds: std::sync::Mutex<Vec<ReplaySeed>>,
    out_dir: std::path::PathBuf,
    files: AtomicU64,
    bytes: AtomicU64,
    /// Of `bytes`, how many the extractor left IN PLACE - routed and
    /// mapped, then found to land at the very (file, offset) they were
    /// read from, so the pwrite was skipped and the range marked
    /// covered instead (§94 A residual, 22 Aug 2026). Never counts a
    /// byte under `NZBFAST_NO_RESUME_INPLACE=1`.
    in_place: AtomicU64,
    /// Restored files whose replay failed (open, read, or extractor
    /// write). Their article ids were moved to `completed` by the plan,
    /// so the pool never refetches them: a failure here is a permanent
    /// hole the run must NOT finish over (Codex F-04, 22 Aug 2026).
    failed: std::sync::Mutex<Vec<String>>,
    /// TODO 158 item 2, belt-and-braces half: every replayed article is
    /// RE-JOURNALED under the route this run actually took, exactly as
    /// the decode consumer journals a fresh article. The route seed
    /// (`Extractor::seed_resumed_routes`) is still the safety property;
    /// this makes the records describe what is on disk even if it were
    /// not. Weak for the same `Arc::try_unwrap` reason as the other
    /// journal hooks in `vrig.rs`; a dropped journal records nothing.
    journal: std::sync::Weak<nzbkit::journal::Journal>,
    /// The decode consumers' own parked-`D` and held-article lists
    /// (see `workers::PendingD`, `workers::PendingR`): owned here so a
    /// replay fed before the consumers exist (`vrig.rs`, the
    /// self-sniff seeds) parks into the same lists they flush.
    pub(super) pending_d: Arc<std::sync::Mutex<Vec<super::workers::PendingD>>>,
    pub(super) pending_r: Arc<std::sync::Mutex<super::workers::PendingR>>,
}

/// The marker [`test_park_in_replay`] prints before it parks. Named
/// once so the product and the probe that waits for it cannot drift
/// apart in the way two hand-typed string literals do.
const PARK_IN_REPLAY_MARK: &str = "resume replay fed its first chunk - parked for the delete probe";

/// Has [`test_park_in_replay`] already parked in this process? The
/// barrier is for ONE window and a replay feeds many chunks across many
/// seeds, so without this it would park on every one of them and the
/// probe would be measuring a sleep loop rather than a window.
static REPLAY_PARKED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);

/// Test-only (`NZBFAST_TEST_PARK_IN_REPLAY_MS`): announce that the
/// resume replay has fed its FIRST chunk back through the extractor and
/// then hold this thread for up to that many milliseconds. Unset - the
/// only production state - is a no-op and reads no clock.
///
/// This is a BARRIER, not a delay, and the difference is the whole
/// point - `get::tail::test_park_after_engine_finish` carries the
/// argument at length and this is its sibling. X5-12 asks what a DELETE
/// does to a run that is halfway through replaying restored bytes back
/// through the extractor, and that window closes in milliseconds on a
/// small fixture: a test that sleeps into it is guessing, and a guess on
/// a box running nine lanes' cargo builds is a flake in both directions.
/// So the product says WHERE it is and holds; the probe waits for the
/// LINE - a state - and deletes. The `ms` is only a wedge bound, never
/// the thing being waited for.
///
/// AFTER THE FIRST CHUNK AND NOT BEFORE THE SEED, because the row is
/// about a delete landing ACROSS a replay rather than before one. Parked
/// at the top of `feed_spans` the extractor has taken nothing, the
/// output holds no replayed byte, and the question collapses into the
/// ordinary "delete a queued job" that `daemon_delete` already asks.
fn test_park_in_replay() {
    use std::sync::atomic::Ordering::Relaxed;
    // Already spent, which after the one park is every call for the
    // rest of the process. First because it is the cheapest question -
    // see the latch below for why the env read is not asked here.
    if REPLAY_PARKED.load(Relaxed) {
        return;
    }
    // READ ONCE, and that is not tidiness: this sits inside the replay's
    // per-CHUNK loop, so an env read here is one per 4 MiB replayed - on
    // a large resume, thousands of them, each taking the process-wide
    // environment lock that every other thread's reads and any
    // `set_var` share. `test_park_after_engine_finish` can afford the
    // straightforward spelling because it is called once per JOB. A
    // `OnceLock` is the right shape rather than a second `AtomicBool`
    // because the answer is a VALUE, and it is deliberately not a
    // mutation as far as `tools/test-global-gate.py` is concerned:
    // `get_or_init` is idempotent and no test moves it.
    static MS: std::sync::OnceLock<Option<u64>> = std::sync::OnceLock::new();
    let Some(ms) = *MS.get_or_init(|| {
        std::env::var("NZBFAST_TEST_PARK_IN_REPLAY_MS")
            .ok()
            .and_then(|v| v.parse::<u64>().ok())
    }) else {
        return;
    };
    if REPLAY_PARKED.swap(true, Relaxed) {
        return;
    }
    info!(target: "resume", "{PARK_IN_REPLAY_MARK}");
    std::thread::sleep(std::time::Duration::from_millis(ms));
}

impl ReplayPending {
    /// Journal one replayed article under the route the extractor just
    /// took for it, mirroring the consumer's handling of `Persist`:
    /// `R` now for a plain placement, a parked `D` for a plaintext-once
    /// span (its seam bytes may still be RAM-held), a `ParkedR` for a
    /// held span so `flush_pending_r` completes it when the hold
    /// drains. Never a par2-main bare record: par2 slots are not
    /// replayed at all. The in-place case needs nothing special - a
    /// pwrite the extractor skipped because the bytes were already at
    /// their derived destination still returns its fragment, so the
    /// record says the bytes are there, which they are.
    #[expect(clippy::too_many_arguments)]
    fn record(
        &self,
        seed: &ReplaySeed,
        id: &std::sync::Arc<str>,
        off: u64,
        len: u64,
        fed: Fed,
        extractor: &nzbkit::extract::Extractor,
        crc: Option<u32>,
    ) {
        let Some(journal) = self.journal.upgrade() else {
            return;
        };
        if id.is_empty() {
            return; // a seed built without article ids: nothing to name
        }
        match fed {
            Fed::Placed(mut frags) => {
                frags.sort_by_key(|f| f.vol_off);
                journal.record_placed(
                    seed.slot,
                    id,
                    extractor.slot_file_info(seed.slot),
                    &seed.name,
                    seed.size,
                    &frags,
                    crc,
                );
            }
            Fed::Crypto(mut frags) => {
                frags.sort_by_key(|f| f.vol_off);
                self.pending_d.lock_ok().push((
                    seed.slot,
                    id.clone(),
                    seed.name.clone(),
                    seed.size,
                    frags,
                    crc,
                ));
            }
            Fed::Held(frags) => {
                self.pending_r
                    .lock_ok()
                    .parked
                    .push(super::workers::ParkedR {
                        sidx: seed.slot,
                        id: id.clone(),
                        name: seed.name.clone(),
                        size: seed.size,
                        off,
                        len,
                        frags,
                        par2_main: false,
                        crc,
                    });
            }
            Fed::No => {}
        }
    }

    /// True when nothing is owed - the adopt path, and every fresh run.
    pub(super) fn is_empty(&self) -> bool {
        self.seeds.lock_ok().is_empty()
    }

    /// Feed back every restored file whose slot can now PLACE what it
    /// is given, in volume order. Called from the decode consumer after
    /// each offset-0 write, because that is what moves the condition:
    /// a volume classifies on its own head article, and a split
    /// member's base resolves once the volumes ahead of it have parsed
    /// theirs.
    ///
    /// Waiting on `slot_can_place` rather than on the slot's own head
    /// is the difference between placing and holding. Feeding volume 5
    /// the instant its own header parses still holds all of it if
    /// volumes 1-4 have not been seen, and on the F4 fixture that was
    /// worth 31% of the replayed bytes still held; the same run waits
    /// here and holds none of it.
    pub(super) fn try_drain(
        &self,
        extractor: &nzbkit::extract::Extractor,
        verifier: &nzbkit::live::LiveVerifier,
    ) {
        loop {
            let seed = {
                let mut g = self.seeds.lock_ok();
                let placeable = g.iter().position(|s| extractor.slot_can_place(s.slot));
                // A seed whose OWN offset-0 span was journaled (a slot
                // that classified non-RAR in the earlier run: the
                // RAR head journals as Held, never as a placement) is
                // the only sniff its slot will ever get - that article
                // is complete, so the pool never refetches it. Left
                // waiting on `slot_can_place` it waited for the network
                // drain, while every fresh article of the slot was held
                // in RAM or scratch up to the unclassified spill (bug
                // sweep 22 Aug 2026). Its first write classifies the
                // slot, so it is fed as soon as it is the head of the
                // volume order - the volumes ahead of it go first.
                let self_sniff = g
                    .first()
                    .is_some_and(|s| s.carries_offset0() && extractor.slot_unclassified(s.slot));
                match placeable.or(if self_sniff { Some(0) } else { None }) {
                    Some(i) => g.remove(i),
                    None => return,
                }
            };
            self.feed(&seed, extractor, verifier);
        }
    }

    /// Feed back everything still owed, in volume order. The backstop
    /// for slots whose offset-0 article never arrived (a 430, a
    /// take-down): their bytes must still reach the extractor, and they
    /// hold exactly as the up-front driver used to. Called once the
    /// decode consumers have joined and before anything settles, so no
    /// restored span is ever silently dropped.
    pub(super) fn drain_rest(
        &self,
        extractor: &nzbkit::extract::Extractor,
        verifier: &nzbkit::live::LiveVerifier,
    ) {
        let rest = std::mem::take(&mut *self.seeds.lock_ok());
        for seed in &rest {
            self.feed(seed, extractor, verifier);
        }
    }

    /// The restored files whose replay failed, by name - see `failed`.
    pub(super) fn failures(&self) -> Vec<String> {
        self.failed.lock_ok().clone()
    }

    /// What the replay managed to feed back, for the banner.
    pub(super) fn replayed(&self) -> (u64, u64) {
        (
            self.files.load(Ordering::Relaxed),
            self.bytes.load(Ordering::Relaxed),
        )
    }

    /// Of the replayed bytes, how many were marked covered in place
    /// rather than written back - see `in_place`.
    pub(super) fn left_in_place(&self) -> u64 {
        self.in_place.load(Ordering::Relaxed)
    }

    fn feed(
        &self,
        seed: &ReplaySeed,
        extractor: &nzbkit::extract::Extractor,
        verifier: &nzbkit::live::LiveVerifier,
    ) {
        if let Err(e) = self.feed_spans(seed, extractor, verifier) {
            warn!(target: "resume", "replaying {}: {e}", seed.name);
            self.failed.lock_ok().push(seed.name.clone());
        }
    }

    fn feed_spans(
        &self,
        seed: &ReplaySeed,
        extractor: &nzbkit::extract::Extractor,
        verifier: &nzbkit::live::LiveVerifier,
    ) -> std::io::Result<()> {
        // Sources are opened once each and kept for the whole seed: a
        // mapped set's spans nearly all come from the same output file,
        // and reopening it per span is thousands of opens on a big
        // resume. Read positionally, so nothing depends on a cursor the
        // decode threads could be sharing.
        let mut srcs: HashMap<std::sync::Arc<str>, std::fs::File> = HashMap::new();
        let mut buf = vec![0u8; 4 << 20];
        // The write half of the replay is the last 0.5x: with volume
        // materialisation off the source IS the output file, so the
        // ordinary `write` reads a range and writes it back onto
        // itself. `write_in_place` hands the extractor the source
        // coordinates and it skips exactly the pwrites whose DERIVED
        // destination is that same (file, offset) - every other
        // placement writes as before. The read stays: the mapper
        // needs the header bytes inside the span, and the verifier
        // hashes what it is given.
        let in_place = !std::env::var("NZBFAST_NO_RESUME_INPLACE").is_ok_and(|v| v == "1");
        let mut left = 0u64;
        // The article being folded: its id, where its range starts and
        // ends in volume space, and what the extractor did with it so
        // far. `spans` is sorted, so an article's spans are contiguous
        // and a change of id closes the previous article's record.
        // X5-02: the replay re-records every article it feeds back, so
        // it owes the same content commitment the download path records.
        // It has no pcrc32 to copy - the bytes come off DISK, not off
        // the wire - so it takes the crc over the very bytes it feeds,
        // which is the same question asked one hop later. Free: the
        // bytes are already in `buf` and already being read.
        //
        // Correct by the same argument the restore side hashes on. An
        // article's spans are contiguous in VOLUME space and `spans` is
        // sorted, so reading them in order reconstructs the payload the
        // original pcrc32 was taken over - the loop below is already
        // relying on exactly that to know when an article ends.
        let mut cur: Option<(std::sync::Arc<str>, u64, u64, Fed, crc32fast::Hasher)> = None;
        for ReplaySpan {
            off,
            len,
            file,
            file_off,
            id,
        } in &seed.spans
        {
            if cur
                .as_ref()
                .is_some_and(|c| !std::sync::Arc::ptr_eq(&c.0, id) && *c.0 != **id)
            {
                let (pid, poff, pend, fed, h) = cur.take().expect("checked above");
                self.record(
                    seed,
                    &pid,
                    poff,
                    pend - poff,
                    fed,
                    extractor,
                    Some(h.finalize()),
                );
            }
            let cur = cur.get_or_insert_with(|| {
                (
                    id.clone(),
                    *off,
                    *off,
                    Fed::Placed(Vec::new()),
                    crc32fast::Hasher::new(),
                )
            });
            if !srcs.contains_key(file) {
                let f = std::fs::File::open(self.out_dir.join(&**file)).map_err(|e| {
                    std::io::Error::new(e.kind(), format!("{file} failed to open: {e}"))
                })?;
                srcs.insert(file.clone(), f);
            }
            let src = &srcs[file];
            let mut done = 0u64;
            while done < *len {
                let chunk = ((*len - done).min(4 << 20)) as usize;
                nzbkit::disk::read_exact_at(src, &mut buf[..chunk], file_off + done).map_err(
                    |e| std::io::Error::new(e.kind(), format!("{file} failed mid-span: {e}")),
                )?;
                let persist = if in_place {
                    let (p, covered) = extractor
                        .write_in_place(
                            seed.slot,
                            &seed.name,
                            seed.size,
                            off + done,
                            &buf[..chunk],
                            file,
                            file_off + done,
                        )
                        .map_err(|e| std::io::Error::other(format!("replay write: {e}")))?;
                    left += covered;
                    p
                } else {
                    extractor
                        .write(seed.slot, &seed.name, seed.size, off + done, &buf[..chunk])
                        .map_err(|e| std::io::Error::other(format!("replay write: {e}")))?
                };
                let fed = std::mem::replace(&mut cur.3, Fed::No);
                cur.3 = fed.fold(persist);
                cur.4.update(&buf[..chunk]);
                verifier.on_data_unverified(
                    seed.slot,
                    &seed.name,
                    seed.size,
                    off + done,
                    &buf[..chunk],
                );
                done += chunk as u64;
                // The X5-12 window, held open on demand. Unset in
                // production, which is every run but a probe's.
                test_park_in_replay();
            }
            cur.2 = cur.2.max(off + len);
        }
        if let Some((pid, poff, pend, fed, h)) = cur.take() {
            self.record(
                seed,
                &pid,
                poff,
                pend - poff,
                fed,
                extractor,
                Some(h.finalize()),
            );
        }
        self.files.fetch_add(1, Ordering::Relaxed);
        self.in_place.fetch_add(left, Ordering::Relaxed);
        self.bytes.fetch_add(
            seed.spans.iter().map(|s| s.len).sum::<u64>(),
            Ordering::Relaxed,
        );
        Ok(())
    }
}

impl ReplaySeed {
    /// Does the restored file's first span start at its own offset 0?
    /// `spans` is sorted, so the head span answers.
    fn carries_offset0(&self) -> bool {
        self.spans.first().is_some_and(|s| s.off == 0)
    }
}

pub(super) fn replay_or_adopt_restored(
    restored: &nzbkit::journal::Restored,
    slots: &[Arc<FileSlot>],
    resume_map: bool,
    extractor: &Arc<nzbkit::extract::Extractor>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    out_dir: &Path,
    journal: &Arc<nzbkit::journal::Journal>,
) -> ReplayPending {
    let pending = ReplayPending {
        out_dir: out_dir.to_path_buf(),
        journal: Arc::downgrade(journal),
        ..Default::default()
    };
    // TODO 158 item 2: the crypto route each output was committed to
    // by the run that wrote it, before a single span is fed - the
    // replay below and the refetch behind it both route through the
    // gate this seeds. On the adopt path the extractor is disabled and
    // never routes; seeding it is harmless.
    extractor.seed_resumed_routes(&restored.wire_outputs, &restored.plaintext_outputs);
    for seed in replay_order(restored) {
        // is_par2(): a resume-recognised recovery volume is not adopted as
        // a payload writer and its bytes stay out of the verifier - like a
        // par2-main slot, its file simply waits on disk for a repair.
        if seed.slot >= slots.len() || slots[seed.slot].is_par2() {
            continue;
        }
        if resume_map {
            // The restored file is a live SOURCE for this whole run, so
            // this half stays UP FRONT even though the bytes do not:
            // claim its name before the pool opens, or an inner member
            // with the same sanitized name opens the very inode the
            // replay will read (Codex sweep 3 Aug H3) - a fresh
            // extractor starts with an empty name set, and `hash.bin`
            // containing a member named `hash.bin` is exactly the shape
            // the disk extractor stages into an isolated directory to
            // avoid. Slot-owned, so the slot's own writer may adopt it.
            extractor.preclaim_name(seed.slot, &seed.name);
            // ...and the files the replay actually READS. In map mode
            // the sources are the earlier run's extracted outputs, and
            // a different archive's member sanitizing to the same name
            // would otherwise claim that inode and write into it before
            // the delayed replay got to read it (Codex F-03, 22 Aug
            // 2026). Claimed under this slot; `claim_name` lets any slot
            // of the same archive group adopt it, which is the owning
            // archive re-creating its own inner writer.
            for (file, _) in &seed.sources {
                if **file != *seed.name {
                    extractor.preclaim_name(seed.slot, file);
                }
            }
            // The journal name (the real on-disk name) beats the subject
            // hint for PAR2 file matching, same as the adopt path.
            verifier.set_name_hint(seed.slot, &seed.name);
            // `sources` is parallel to `spans` when the restore was
            // told not to materialise volumes, and empty when it was -
            // in which case every span is at `vol_off` in the volume
            // file itself. Zipped before the sort, so a span never
            // loses track of where its bytes are.
            let self_name: std::sync::Arc<str> = std::sync::Arc::from(seed.name.as_str());
            // `article_ids` is parallel too; a seed built without them
            // (an older caller, a test) folds every span under one
            // anonymous article that is simply never re-recorded.
            let mut spans: Vec<ReplaySpan> = seed
                .spans
                .iter()
                .enumerate()
                .map(|(i, &(off, len))| {
                    let (file, file_off) = match seed.sources.get(i) {
                        Some((file, file_off)) => (file.clone(), *file_off),
                        None => (self_name.clone(), off),
                    };
                    let id = seed
                        .article_ids
                        .get(i)
                        .cloned()
                        .unwrap_or_else(|| std::sync::Arc::from(""));
                    ReplaySpan {
                        off,
                        len,
                        file,
                        file_off,
                        id,
                    }
                })
                .collect();
            spans.sort_by_key(|s| s.off);
            pending.seeds.lock_ok().push(ReplaySeed {
                slot: seed.slot,
                name: seed.name.clone(),
                size: seed.size,
                spans,
            });
        } else {
            if let Err(e) = extractor.seed_slot(seed.slot, &seed.name, seed.size, &seed.spans) {
                warn!(target: "resume", "adopting {} failed: {e}", seed.name);
                continue;
            }
            verifier.seed_pre_spans(seed.slot, &seed.spans);
            // The journal name (the real on-disk name) beats the subject hint
            // for PAR2 file matching.
            verifier.set_name_hint(seed.slot, &seed.name);
        }
    }
    pending
}

#[cfg(test)]
mod replay_order_tests {
    use super::replay_order;
    use nzbkit::journal::{Restored, SlotSeed};

    fn seed(slot: usize, name: &str) -> SlotSeed {
        SlotSeed {
            slot,
            name: name.to_string(),
            size: 0,
            spans: Vec::new(),
            sources: Vec::new(),
            article_ids: Vec::new(),
        }
    }

    /// The replay must feed volumes back in volume order whatever order
    /// `journal::restore` handed them over in - it walks a HashMap, so
    /// that order is arbitrary and differs every process run. See
    /// `replay_order` for what an out-of-order replay costs.
    #[test]
    fn replay_visits_restored_volumes_in_volume_order() {
        // Deliberately scrambled. A real post uses ONE naming scheme,
        // so the two families are checked separately - `vol_sort_key`
        // interleaves them on purpose (`x.rar` is volume 1 of the
        // old-style scheme and `x.r00` its volume 2), which is right for
        // sorting one set and meaningless across two.
        let order = |names: &[(usize, &str)]| {
            let mut restored = Restored::default();
            for &(slot, name) in names {
                restored.seeds.push(seed(slot, name));
            }
            replay_order(&restored)
                .iter()
                .map(|s| s.name.clone())
                .collect::<Vec<String>>()
        };
        assert_eq!(
            order(&[
                (3, "r.part04.rar"),
                (0, "r.part01.rar"),
                (2, "r.part03.rar"),
                (1, "r.part02.rar"),
            ]),
            [
                "r.part01.rar",
                "r.part02.rar",
                "r.part03.rar",
                "r.part04.rar"
            ]
        );
        assert_eq!(
            order(&[(9, "r.r02"), (6, "r.rar"), (7, "r.r00"), (8, "r.r01")]),
            ["r.rar", "r.r00", "r.r01", "r.r02"]
        );
    }

    /// Plain payload files carry no volume ordering at all, so they sort
    /// as one block after the volumes. Order among them does not matter
    /// (each is its own slot's whole output), but it must be TOTAL and
    /// deterministic, so the slot index breaks the tie - otherwise the
    /// replay is still a coin flip for a post of plain files.
    #[test]
    fn plain_files_sort_last_and_deterministically() {
        let mut restored = Restored::default();
        for (slot, name) in [(5, "b.bin"), (4, "a.bin"), (1, "r.part02.rar")] {
            restored.seeds.push(seed(slot, name));
        }
        let got: Vec<(usize, &str)> = replay_order(&restored)
            .iter()
            .map(|s| (s.slot, s.name.as_str()))
            .collect();
        assert_eq!(got, [(1, "r.part02.rar"), (4, "a.bin"), (5, "b.bin")]);
    }
}

#[cfg(test)]
mod replay_failure_tests {
    use super::{ReplayPending, ReplaySeed};

    /// §94 A map mode: the plan moves a restored file's article ids into
    /// `completed` before the replay runs, so nothing downstream can
    /// tell the extractor never received those bytes. A replay that
    /// could not read its source therefore has to be RECORDED - the run
    /// fails naming the file rather than settling over a permanent hole
    /// (Codex F-04, 22 Aug 2026). Before the fix the open error printed
    /// and returned `()`, and `failures` stayed empty.
    #[test]
    fn a_replay_whose_source_cannot_be_read_is_recorded_as_a_failure() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-replay-fail-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();

        let pending = ReplayPending {
            out_dir: dir.clone(),
            ..Default::default()
        };
        // The source the earlier run's outputs were supposed to hold.
        // It is not there: clobbered, truncated away, or never written.
        let seed = ReplaySeed {
            slot: 0,
            name: "r.part01.rar".to_string(),
            size: 4_096,
            spans: vec![super::ReplaySpan {
                off: 0,
                len: 4_096,
                file: std::sync::Arc::from("gone.mkv"),
                file_off: 0,
                id: std::sync::Arc::from("<a@x>"),
            }],
        };
        let extractor = nzbkit::extract::Extractor::new(&dir, 1, true);
        let verifier = nzbkit::live::LiveVerifier::new(1);

        pending.feed(&seed, &extractor, &verifier);

        assert_eq!(
            pending.failures(),
            vec!["r.part01.rar".to_string()],
            "an unreadable replay source was swallowed"
        );
        assert_eq!(
            pending.replayed(),
            (0, 0),
            "a failed replay must not count as replayed bytes"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }
}

#[cfg(test)]
mod fed_fold_tests {
    use super::Fed;
    use nzbkit::extract::Persist;

    /// The article-level fold over a replayed article's chunk results
    /// mirrors the consumer's `Persist` arms: all-plain is an `R`, any
    /// plaintext-once part makes it a `D`, a hold parks it, and a hold
    /// mixed with a crypto part - an `R` can never describe
    /// plaintext-once bytes - drops the re-record altogether. `No` is
    /// absorbing in both directions. (`Frag` has no public constructor;
    /// the join is a plain `extend`, so the variants are what is pinned.)
    #[test]
    fn fold_mirrors_the_consumer_arms() {
        let p = || Persist::Placed(Vec::new());
        let c = || Persist::PlacedCrypto(Vec::new());
        let h = || Persist::Held(Vec::new());
        assert!(matches!(Fed::Placed(Vec::new()).fold(p()), Fed::Placed(_)));
        assert!(matches!(Fed::Placed(Vec::new()).fold(c()), Fed::Crypto(_)));
        assert!(matches!(Fed::Crypto(Vec::new()).fold(p()), Fed::Crypto(_)));
        assert!(matches!(Fed::Crypto(Vec::new()).fold(c()), Fed::Crypto(_)));
        assert!(matches!(Fed::Placed(Vec::new()).fold(h()), Fed::Held(_)));
        assert!(matches!(Fed::Held(Vec::new()).fold(p()), Fed::Held(_)));
        assert!(matches!(Fed::Held(Vec::new()).fold(h()), Fed::Held(_)));
        assert!(matches!(Fed::Held(Vec::new()).fold(c()), Fed::No));
        assert!(matches!(Fed::Crypto(Vec::new()).fold(h()), Fed::No));
        assert!(matches!(Fed::Placed(Vec::new()).fold(Persist::No), Fed::No));
        assert!(matches!(Fed::No.fold(p()), Fed::No));
    }
}
