//! Recovery-volume side-fetches: the small, budget-exempt pool a repair
//! uses to pull par2 volumes down after the main run has drained.
//!
//! Split out of `repair.rs` whole (§129 residue 2) so the cancel wire
//! below has a home and its parent file drops back under the size gate.
//! Everything here is re-exported from `crate::repair`, so callers and
//! `super::*` importers are unchanged.

use super::*;
use std::sync::atomic::{AtomicBool, Ordering};

/// A sticky cancel handle for one owner's recovery-volume side-fetches.
///
/// Two halves, because neither alone is a cancel wire:
///
/// - `QueueControl::abort` only reaches the pool the handle is attached
///   to RIGHT NOW. A cancel arriving between two volumes, or in the
///   window before `fetch_all_multi_ctl` attaches, is a silent no-op and
///   the fetch runs to completion - which is the bug this exists to
///   close, just narrower. So the latch is the durable half: once set it
///   refuses every later side-fetch outright and keeps re-aborting the
///   one in flight (see [`SideCancel::guard`]).
/// - The latch alone cannot drop an in-flight read. A blackholed
///   provider's retry ladder is minutes long; only the pool abort ends
///   it promptly.
///
/// The speculative prefetch (get/workers.rs) shares its own `stop` flag
/// through [`SideCancel::over`] rather than carrying a second mechanism.
pub(crate) struct SideCancel {
    flag: Arc<AtomicBool>,
    ctl: Arc<nzbkit::pool::QueueControl>,
}

impl SideCancel {
    /// A handle with its own latch - what the daemon registers per job.
    pub(crate) fn new() -> Self {
        SideCancel::over(Arc::new(AtomicBool::new(false)))
    }

    /// A handle over a latch the caller already owns and reads itself.
    pub(crate) fn over(flag: Arc<AtomicBool>) -> Self {
        SideCancel {
            flag,
            ctl: Arc::new(nzbkit::pool::QueueControl::default()),
        }
    }

    /// Stop this owner's side-fetches: refuse the ones not yet started,
    /// drop the reads of the one in flight. Idempotent.
    pub(crate) fn cancel(&self) {
        self.flag.store(true, Ordering::Release);
        self.ctl.abort();
    }

    pub(crate) fn is_cancelled(&self) -> bool {
        self.flag.load(Ordering::Acquire)
    }

    /// Run one side-fetch under this handle, keeping the pool abort
    /// live for its whole duration.
    ///
    /// The ticker is not laziness about a wake-up primitive: the pool a
    /// `cancel()` needs to abort may not be attached yet when the call
    /// arrives, so the abort has to be re-tried until the fetch returns.
    /// Same shape, same reason as the prefetch watcher this replaces
    /// (Codex 5 Aug M3) - 250 ms is well inside a user's patience and
    /// costs one timer per volume.
    async fn guard<T>(&self, fut: impl std::future::Future<Output = T>) -> T {
        let flag = self.flag.clone();
        let ctl = self.ctl.clone();
        let watcher = tokio::spawn(async move {
            loop {
                if flag.load(Ordering::Acquire) {
                    ctl.abort();
                }
                tokio::time::sleep(std::time::Duration::from_millis(250)).await;
            }
        });
        let out = fut.await;
        watcher.abort();
        out
    }
}

/// `.volNNN+MM.par2` / `.volNNN-MMM.par2` → declared recovery-slice count.
pub(crate) fn vol_count_from_name(name: &str) -> Option<usize> {
    nzbkit::nzb::par2_vol_count(name)
}

/// Download the chosen recovery volumes to `out_dir` (same decode→pwrite
/// path as the main run). Shared by the disk repair path and the mapped
/// (into-the-output) path.
///
/// Returns the article-failure count. `Ok(0)` is the only value that
/// means every chosen volume landed whole; any nonzero count means at
/// least one of them is PARTIAL, and only a complete volume may ever
/// enter a whole-file exclusion list (the escalation fetch strips
/// excluded files, so excluding a partial one makes its missing slices
/// unreachable for the rest of the job).
pub(crate) async fn fetch_volumes(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    nzb: &Nzb,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    file_indexes: &[usize],
    cancel: Option<&SideCancel>,
) -> Result<usize> {
    let mut ids: Vec<nzbkit::pool::ArticleReq> = Vec::new();
    let mut id_to_file: std::collections::HashMap<Arc<str>, usize> =
        std::collections::HashMap::new();
    for &fi in file_indexes {
        volume_reqs(nzb, fi, &mut ids, &mut id_to_file);
    }
    fetch_volume_articles(
        servers,
        ids,
        id_to_file,
        out_dir,
        buf_pool,
        volume_prealloc_cap(nzb),
        cancel,
    )
    .await
    .map(|(failures, _paths)| failures)
}

/// One volume's `ArticleReq`s and id → file-index entries, appended to
/// the caller's holders. R9: one interned handle per id, shared with
/// the ArticleReq (and so with the Work, the in-flight entry and the
/// outcome). Every caller is a side pool of its own - the disk/mapped
/// repair fetch after the main run's plan is gone, and the speculative
/// prefetch, which builds a rung's requests only AT RUNG SELECTION
/// (C5) - so it interns at its own birth site rather than borrowing
/// the plan's.
pub(crate) fn volume_reqs(
    nzb: &Nzb,
    fi: usize,
    ids: &mut Vec<nzbkit::pool::ArticleReq>,
    id_to_file: &mut std::collections::HashMap<Arc<str>, usize>,
) {
    let age_days = nzb_age_days(nzb.files[fi].date);
    for seg in &nzb.files[fi].segments {
        let b: Arc<str> = format!("<{}>", seg.message_id).into();
        id_to_file.insert(b.clone(), fi);
        ids.push(nzbkit::pool::ArticleReq {
            id: b,
            age_days,
            part: seg.number,
        });
    }
}

/// Reservation ceiling for a recovery-volume side-fetch, the same bound
/// `main` hands the extractor: a recovery volume cannot legitimately
/// exceed the whole post, and the yEnc `size=` it declares is a poster-
/// controlled number that on Linux turns into a real `fallocate`. The
/// posted byte count is itself an untrusted attribute (and 0 means the
/// NZB carried no byte attributes at all - unknown, not zero), so the
/// post's article GEOMETRY bounds it either way: reserving more space
/// requires declaring more articles, which the download is then held
/// accountable for. See [`Nzb::geometry_bytes`].
pub(crate) fn volume_prealloc_cap(nzb: &Nzb) -> u64 {
    let geometry = nzb.geometry_bytes();
    match nzb.total_bytes() {
        0 => geometry,
        posted => posted.min(geometry),
    }
}

/// Shrink the download fleet to the one-connection-per-server side pool the
/// M2c.5 speculative prefetch runs on. The main pool already holds this
/// account's grants, so the prefetch may add exactly one connection per
/// server or the provider starts refusing them.
pub(crate) fn side_pool_servers(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
) -> Vec<(ServerConfig, nzbkit::pool::PoolConfig)> {
    servers
        .iter()
        .map(|(sc, pc)| {
            let mut sc = sc.clone();
            sc.connections = 1;
            let mut pc = pc.clone();
            // The POOL config is what spawns workers (pool::fetch_all_multi);
            // ServerConfig.connections was consumed when this config was
            // built, far above. Setting only that one leaves the "tiny side
            // pool" a full second fleet, opened mid-download.
            pc.connections = 1;
            // Same reason it must stay small: side-pool workers are not part
            // of the download, so they must not move the dashboard's
            // per-server gauges either.
            pc.live = None;
            // TODO 114: the steer seam defers each Done's completion
            // until the consumer's note_decoded verdict - and the
            // side-fetch consumer (consume_volume_articles) never
            // gives one (it has no QueueControl at all), so a cloned
            // crc_steer would park every delivery forever and hang
            // the volume fetch. fetch_volume_articles now strips the
            // ack seams itself (the 7 Aug 2026 wedge came in through
            // a caller that bypassed this helper); cleared here too
            // so the side pool's config states its own contract.
            // Damaged side-fetched volumes already have their own
            // answer: incomplete volumes stay fetchable and repair
            // proves the bytes.
            pc.crc_steer = false;
            (sc, pc)
        })
        .collect()
}

/// Inner driver for recovery-volume side-fetches: downloads the given
/// article set on its own small pool and assembles the volume file(s)
/// in `out_dir`. Returns (article failures, paths written) - the
/// failure count is how a caller tells a COMPLETE volume from a
/// partial one, and only a complete volume may ever enter a whole-file
/// exclusion list (a partial one must stay fetchable for its missing
/// articles).
#[allow(clippy::too_many_arguments)]
pub(crate) async fn fetch_volume_articles(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    ids: Vec<nzbkit::pool::ArticleReq>,
    id_to_file: std::collections::HashMap<Arc<str>, usize>,
    out_dir: &Path,
    buf_pool: &Arc<nzbkit::pool::BufPool>,
    // Ceiling on what one volume writer may RESERVE - see
    // [`volume_prealloc_cap`]. u64::MAX = no ceiling.
    prealloc_cap: u64,
    // Cancellation handle for callers that must be able to stop a
    // side-fetch mid-volume: the speculative prefetch (Codex 5 Aug M3 -
    // it could hold Cancel/Pause through a blackholed provider's whole
    // retry ladder) and, since §129, the postproc lane's tail, whose
    // repair fetches used to outlive the job the user deleted. See
    // [`SideCancel`]. None = uncancellable, which is only the CLI.
    cancel: Option<&SideCancel>,
) -> Result<(usize, Vec<PathBuf>)> {
    use nzbkit::pool::{FetchOutcome, fetch_all_multi_ctl};
    // Refuse outright rather than fetch and discard: a cancelled owner
    // may still have a ladder of volumes queued behind this one, and
    // every rung of it is now bytes nobody will read.
    if cancel.is_some_and(SideCancel::is_cancelled) {
        anyhow::bail!("recovery fetch cancelled");
    }
    // This driver's consumer never gives the pool a verdict:
    // consume_volume_articles has no QueueControl, so it calls neither
    // note_decoded (the crc_steer seam) nor note_settled (arrival_ack).
    // A caller that hands in the MAIN fleet's configs - crc_steer is ON
    // by default on a multi-server setup - parks every delivered body's
    // completion behind an ack that can never come: the volume lands
    // fully on disk while the pool never drains, and the job hangs in
    // "Repairing" with the whole finalize chain wedged behind it (the
    // 7 Aug 2026 daemon wedge). side_pool_servers already strips these
    // for the speculative prefetch, but the strip belongs HERE, at the
    // single driver every side-fetch goes through, so no caller can
    // reintroduce the hang.
    let servers: Vec<(ServerConfig, nzbkit::pool::PoolConfig)> = servers
        .iter()
        .map(|(sc, pc)| {
            let mut pc = pc.clone();
            pc.crc_steer = false;
            pc.arrival_ack = false;
            (sc.clone(), pc)
        })
        .collect();
    let servers = servers.as_slice();
    // Side-fetch: small volume sets, fast disk-writer consumer - a
    // modest fixed depth (≈25 MB) instead of the old 256 (~200 MB of
    // budget-exempt bytes on a box that may only have 256 MB total).
    let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(32);
    let out_dir2 = out_dir.to_path_buf();
    let pool2 = buf_pool.clone();
    let consumer = tokio::spawn(async move {
        consume_volume_articles(rx, id_to_file, out_dir2, pool2, prealloc_cap).await
    });
    let t0 = Instant::now();
    let stats = match cancel {
        Some(c) => {
            c.guard(fetch_all_multi_ctl(servers, ids, tx, Some(&c.ctl)))
                .await
        }
        None => fetch_all_multi_ctl(servers, ids, tx, None).await,
    };
    let (failures, paths) = consumer.await?;
    // An aborted run's unresolved articles emit NO outcome, so `failures`
    // can read 0 over a volume that is actually short - the H2
    // false-shortfall shape. Never hand that back as a clean result: a
    // caller allowed to believe it would strike the whole volume off its
    // fetch list. The written paths are abandoned on disk exactly as an
    // interrupted download's partials are, and the sweep owns them.
    if cancel.is_some_and(SideCancel::is_cancelled) {
        anyhow::bail!("recovery fetch cancelled after {:.2?}", t0.elapsed());
    }
    let raw: u64 = stats.iter().map(|s| s.bytes).sum();
    println!(
        "  fetched {:.1} MB of recovery data in {:.2?}{}",
        raw as f64 / 1e6,
        t0.elapsed(),
        if failures > 0 {
            format!(" ({failures} article failures)")
        } else {
            String::new()
        }
    );
    Ok((failures as usize, paths))
}

/// Decode side-fetched articles onto their volume files. Returns
/// (article failures, paths actually written) - split out of
/// [`fetch_volume_articles`] so the writer-failure path is reachable from
/// a test without a server.
///
/// A volume whose writer cannot be created is DROPPED, not fatal: the
/// declared name is attacker-influenced (it may sanitise to something
/// unopenable) and the disk may be full or read-only. Panicking here took
/// the consumer task down and, with it, every other volume in the same
/// side-fetch. Absent from the returned paths means "we did not get that
/// volume", which every caller already handles - the slices are counted
/// from the files that actually landed, so nothing is over-credited.
pub(crate) async fn consume_volume_articles(
    mut rx: tokio::sync::mpsc::Receiver<nzbkit::pool::FetchOutcome>,
    id_to_file: std::collections::HashMap<Arc<str>, usize>,
    out_dir: PathBuf,
    buf_pool: Arc<nzbkit::pool::BufPool>,
    prealloc_cap: u64,
) -> (u32, Vec<PathBuf>) {
    use nzbkit::disk::{FileWriter, sanitize_filename};
    use nzbkit::pool::FetchOutcome;
    use std::collections::hash_map::Entry;
    use std::collections::{HashMap, HashSet};

    let mut writers: HashMap<usize, (PathBuf, Arc<FileWriter>)> = HashMap::new();
    // Volumes whose writer could not be opened. Remembered so the create
    // is attempted ONCE per volume rather than once per article - on a
    // full disk that would be thousands of failing opens - and so the
    // failure is reported once.
    let mut unwritable: HashSet<usize> = HashSet::new();
    let mut failures = 0u32;
    while let Some(outcome) = rx.recv().await {
        match outcome {
            FetchOutcome::Done { id, raw } => {
                let Some(&fi) = id_to_file.get(&*id) else {
                    buf_pool.give(raw);
                    continue;
                };
                match nzbkit::yenc_simd::decode(&raw) {
                    Ok(dec) if !unwritable.contains(&fi) => {
                        let w = match writers.entry(fi) {
                            Entry::Occupied(e) => Some(&e.into_mut().1),
                            Entry::Vacant(slot) => {
                                let path = out_dir.join(sanitize_filename(&dec.name));
                                // The declared `size=` is the poster's
                                // number and on Linux preallocation is a
                                // real fallocate, so it reserves only up
                                // to the ceiling. `size` itself stays
                                // unclamped (the writer reports it).
                                match FileWriter::create_capped(&path, dec.file_size, prealloc_cap)
                                {
                                    Ok(f) => Some(&slot.insert((path, Arc::new(f))).1),
                                    Err(e) => {
                                        println!(
                                            "  ⚠ cannot write recovery volume {} ({e}) - skipping it",
                                            path.display()
                                        );
                                        unwritable.insert(fi);
                                        None
                                    }
                                }
                            }
                        };
                        match w {
                            Some(w) if w.write_at(dec.offset(), &dec.data).is_ok() => {}
                            _ => failures += 1,
                        }
                    }
                    _ => failures += 1,
                }
                buf_pool.give(raw);
            }
            _ => failures += 1,
        }
    }
    (failures, writers.into_values().map(|(p, _)| p).collect())
}

#[cfg(test)]
mod recovery_volume_tests {
    use super::*;
    use nzbkit::pool::{BufPool, FetchOutcome};
    use std::collections::HashMap;

    fn temp_dir(tag: &str) -> PathBuf {
        let dir = std::env::temp_dir().join(format!("nzbfast-vol-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// One complete single-part yEnc article body, exactly as the fetch
    /// pool hands it to the consumer. `declared` is the `size=` field -
    /// the number the POSTER controls, which is the whole point here.
    fn article(name: &str, declared: u64, data: &[u8]) -> Vec<u8> {
        nzbkit::yenc::encode(name, declared, Some((1, 1)), 1, data)
    }

    /// Drive the real consumer over `arts` = (file index, article body).
    async fn consume(dir: &Path, arts: Vec<(usize, Vec<u8>)>, cap: u64) -> (u32, Vec<PathBuf>) {
        let (tx, rx) = tokio::sync::mpsc::channel::<FetchOutcome>(16);
        let mut id_to_file = HashMap::new();
        for (n, (fi, body)) in arts.into_iter().enumerate() {
            let id: Arc<str> = format!("<a{n}@test>").into();
            id_to_file.insert(id.clone(), fi);
            tx.send(FetchOutcome::Done { id, raw: body }).await.unwrap();
        }
        drop(tx);
        // Spawned, so a panic in the consumer surfaces as a JoinError
        // instead of unwinding the test itself - that is the assertion
        // for the panic regression below.
        tokio::spawn(consume_volume_articles(
            rx,
            id_to_file,
            dir.to_path_buf(),
            BufPool::new(4),
            cap,
        ))
        .await
        .expect("the recovery-volume consumer task must not panic")
    }

    /// BUG (HIGH): the PAR2 recovery-volume side-fetch preallocated the
    /// attacker-declared yEnc `size=` with NO ceiling - `FileWriter::create`
    /// -> `create_capped(.., u64::MAX)` -> `set_len` plus a real Linux
    /// `fallocate`. It bypassed the ceiling the extractor already had, so a
    /// small post could reserve the victim's free space on ext4/XFS.
    #[tokio::test]
    async fn a_recovery_volume_cannot_reserve_past_the_posted_ceiling() {
        let dir = temp_dir("cap");
        const HUGE: u64 = 8 << 40; // 8 TiB "declared"
        const POSTED: u64 = 1 << 20; // what the NZB actually posted
        let payload = vec![0x5Au8; 4096];

        let (failures, paths) = consume(
            &dir,
            vec![(0, article("set.vol000+01.par2", HUGE, &payload))],
            POSTED,
        )
        .await;

        assert_eq!(failures, 0);
        assert_eq!(paths.len(), 1);
        let len = std::fs::metadata(&paths[0]).unwrap().len();
        assert_eq!(
            len, POSTED,
            "a poster-declared volume size must not reserve past the posted ceiling"
        );
        // The cap bounds the RESERVATION only - the article's bytes still
        // land at their offset, byte for byte.
        assert_eq!(
            &std::fs::read(&paths[0]).unwrap()[..payload.len()],
            &payload[..]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// THE test that matters: a wrong fix here silently de-optimises every
    /// real download. A genuine recovery volume, whose declared size fits
    /// under the posted ceiling, must still be reserved IN FULL from the
    /// first article - not clamped to the bytes that have arrived.
    #[tokio::test]
    async fn a_legitimate_recovery_volume_still_preallocates_in_full() {
        let dir = temp_dir("cap-ok");
        const SIZE: u64 = 4_000_000; // the volume's real size
        const POSTED: u64 = 64_000_000; // the NZB's posted bytes
        let first_part = vec![0x11u8; 8192];

        let (failures, paths) = consume(
            &dir,
            vec![(0, article("set.vol000+02.par2", SIZE, &first_part))],
            POSTED,
        )
        .await;
        assert_eq!(failures, 0);
        assert_eq!(
            std::fs::metadata(&paths[0]).unwrap().len(),
            SIZE,
            "a legitimate volume under the ceiling must be preallocated in full, \
             not clamped to the bytes received so far"
        );
        std::fs::remove_dir_all(&dir).unwrap();

        // And with no ceiling at all: byte-for-byte the old behaviour.
        let dir = temp_dir("cap-none");
        let (_, paths) = consume(
            &dir,
            vec![(0, article("set.vol000+02.par2", SIZE, &first_part))],
            u64::MAX,
        )
        .await;
        assert_eq!(std::fs::metadata(&paths[0]).unwrap().len(), SIZE);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The ceiling for an NZB without byte attributes (0 posted bytes
    /// means "unknown", not zero) used to be NO ceiling at all - which
    /// let a poster omit `bytes=` and reserve the declared yEnc `size=`
    /// unbounded. The post's article geometry bounds it instead: one
    /// declared article justifies one article's worth of reservation,
    /// never a 0 ceiling (which would reserve nothing for every volume
    /// of such a post).
    #[test]
    fn an_nzb_without_byte_attributes_is_bounded_by_its_geometry() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment number="1">a@test</segment></segments>
 </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        assert_eq!(nzb.total_bytes(), 0);
        assert_eq!(volume_prealloc_cap(&nzb), 16 << 20);
    }

    /// Codex H3: the posted `bytes=` total is as poster-controlled as
    /// the yEnc `size=`, so "min(size, posted)" was the attacker picking
    /// both sides - one tiny article declaring two 100 GB numbers became
    /// a real fallocate. The article geometry caps it: a single-segment
    /// post can never justify more than one article's worth.
    #[test]
    fn an_inflated_posted_byte_count_is_bounded_by_its_geometry() {
        let xml = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/1)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="109951162777600" number="1">a@test</segment></segments>
 </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        assert_eq!(volume_prealloc_cap(&nzb), 16 << 20);
        // And a genuine posted count under the geometry passes through.
        let xml2 = br#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject="set.vol000+01.par2 yEnc (1/2)" date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments>
   <segment bytes="750000" number="1">a@test</segment>
   <segment bytes="750000" number="2">b@test</segment>
  </segments>
 </file>
</nzb>"#;
        let nzb2 = nzbkit::nzb::Nzb::parse(xml2).unwrap();
        assert_eq!(volume_prealloc_cap(&nzb2), 1_500_000);
    }

    /// BUG (LOW): the writer was created with `.expect("create recovery
    /// volume")` inside the consumer task, so a volume that could not be
    /// opened - a name that sanitises to something unopenable, a full or
    /// read-only disk - panicked the task and took every OTHER volume in
    /// the same side-fetch with it. An unwritable volume is a volume we
    /// did not get, nothing more.
    #[tokio::test]
    async fn an_unwritable_recovery_volume_does_not_panic_the_consumer() {
        let dir = temp_dir("unwritable");
        // A directory sitting exactly where the volume file must go: the
        // create fails, deterministically, on every platform.
        std::fs::create_dir_all(dir.join("set.vol000+01.par2")).unwrap();
        let good = vec![0x22u8; 2048];

        let (failures, paths) = consume(
            &dir,
            vec![
                (0, article("set.vol000+01.par2", 1 << 20, &[1u8; 512])),
                // A second article for the SAME dead volume: the create
                // must not be retried per article, and it must still not
                // panic.
                (0, article("set.vol000+01.par2", 1 << 20, &[2u8; 512])),
                (1, article("set.vol001+02.par2", 2048, &good)),
            ],
            1 << 30,
        )
        .await;

        assert_eq!(
            failures, 2,
            "both articles of the dead volume count as failures"
        );
        assert_eq!(
            paths.len(),
            1,
            "the healthy volume of the same fetch still lands"
        );
        assert!(paths[0].ends_with("set.vol001+02.par2"));
        assert_eq!(std::fs::read(&paths[0]).unwrap(), good);
        std::fs::remove_dir_all(&dir).unwrap();
    }
}
