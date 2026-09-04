//! TODO 131 B3: the byte-probe naming lane.
//!
//! Fetch a handful of articles off a dark post, read the archive headers
//! and name it from what is inside. Moved out of indexer.rs whole (TODO
//! 106) - it was 582 lines of one subject and the file had crossed the
//! 3,000-line size-gate ceiling.
//!
//! A child of `indexer`, so `use super::*` reaches the lane's private
//! neighbours unchanged. `spawn_probe7z` keeps `pub(crate)`,
//! which is absolute, and indexer.rs re-exports it so
//! `tasks::spawn_probe7z` still resolves through tasks.rs's glob.
//!
//! The RAR half - the bounded article fetch, the volume picker, the
//! header read and its `RarNameRun` verdict - is
//! `crate::rarprobe` since 2 Sep 2026, because `api::index::pull`
//! runs it ON DEMAND for a row a human is looking at, and an API handler
//! must not reach into a background lane. Nothing about it belongs to
//! this lane: it takes an open `Connection` and a byte budget and
//! touches no `Daemon`.

use super::*;
// The RAR half now lives one layer down; the single-7z recipe and the
// lane still call into it.
use crate::rarprobe::{probe_fetch, rar_probe_volumes, run_rar_probe};

/// Ceiling of articles one probe may spend (head + the two extra head
/// tries for the ~1/29 scrambled case + a bounded trailing fetch). The
/// token bucket refuses to start a release it cannot finish.
#[cfg(feature = "indexer")]
const PROBE7Z_ARTICLES_MAX: u64 = 8;

/// Trailing segments fetched at most while hunting the end header (the
/// confirmation run found it inside the last two for every readable
/// target; two more are slack for packed headers, not a search).
#[cfg(feature = "indexer")]
const PROBE7Z_TAIL_MAX: usize = 4;

/// What one probed release produced. `articles`/`bytes` are the wire
/// spend the tallies track against the budget.
#[cfg(feature = "indexer")]
struct ProbeRun {
    outcome: &'static str,
    /// A structural verdict: retrying cannot change the bytes, so the
    /// row leaves the lane for good (the post-grab path still gets its
    /// chance if the release is ever downloaded).
    give_up: bool,
    /// The recovered inner filename, on "named" only.
    name: Option<String>,
    articles: u64,
    bytes: u64,
}

#[cfg(feature = "indexer")]
impl ProbeRun {
    fn new(outcome: &'static str, give_up: bool, articles: u64, bytes: u64) -> Self {
        Self {
            outcome,
            give_up,
            name: None,
            articles,
            bytes,
        }
    }
}

/// The uploader-recipe registry: which bounded byte-peek names this
/// release's shape. One entry today; Pesto's tiny-PAR2 grammar and any
/// future RAR continuation recipe slot in as further variants, each
/// with its own matcher, so the lane is a registry of poster-tool
/// shapes rather than a hardcoded special case.
#[cfg(feature = "indexer")]
pub(super) enum ProbeRecipe {
    /// A single logical 7z (one `.7z`, or an ordered `.7z.NNN` split
    /// set): real name in the end header, reachable from the offset-0
    /// article plus a bounded trailing fetch.
    SevenzTail(Vec<nzbkit::index::ProbeFile>),
    /// A RAR volume set (`.rar`, `.partNN.rar`, `.rNN`): the inner
    /// media name sits in volume 1's file header, one offset-0 article
    /// away - the read the on-demand click path has done since
    /// `run_rar_probe` landed, now driven from the background pick.
    RarHead,
}

/// Match a candidate's file rows against the registry. None = no
/// recipe fits (the pick's SQL shape-gate and this can disagree when a
/// release mixes shapes; those rows are marked off, not chased).
#[cfg(feature = "indexer")]
pub(super) fn probe_recipe(files: &[nzbkit::index::ProbeFile]) -> Option<ProbeRecipe> {
    let data: Vec<&nzbkit::index::ProbeFile> = files
        .iter()
        .filter(|f| !f.segments.is_empty() && !f.filename.to_lowercase().ends_with(".par2"))
        .collect();
    // Ordered split set: every data file a `.7z.NNN` part of one base,
    // numbered contiguously from 001.
    let mut parts: Vec<(u32, &nzbkit::index::ProbeFile)> = Vec::new();
    let mut bases: std::collections::BTreeSet<String> = Default::default();
    for f in &data {
        if let Some((base, idx)) = crate::rarfix::split_7z_part(&f.filename) {
            bases.insert(base);
            parts.push((idx, f));
        }
    }
    if !parts.is_empty() && parts.len() == data.len() && bases.len() == 1 {
        parts.sort_by_key(|(idx, _)| *idx);
        if parts
            .iter()
            .enumerate()
            .all(|(i, (idx, _))| *idx == i as u32 + 1)
        {
            return Some(ProbeRecipe::SevenzTail(
                parts.into_iter().map(|(_, f)| f.clone()).collect(),
            ));
        }
        return None;
    }
    // Single container: exactly one `.7z` among the data files.
    let singles: Vec<&&nzbkit::index::ProbeFile> = data
        .iter()
        .filter(|f| f.filename.to_lowercase().ends_with(".7z"))
        .collect();
    if singles.len() == 1 {
        return Some(ProbeRecipe::SevenzTail(vec![(*singles[0]).clone()]));
    }
    // RAR after 7z, never instead of it: a release carrying both is a
    // 7z shape with a stray volume, and the 7z read is the cheaper
    // certain one.
    if !rar_probe_volumes(files).is_empty() {
        return Some(ProbeRecipe::RarHead);
    }
    None
}

/// Run the single-7z recipe against one release: find the offset-0
/// article (segments[0] almost always; two more tries cover the
/// pilot's ~1/29 scrambled case), read the start header, fetch the
/// LAST volume's trailing segments until the end header - and, when it
/// is a packed header, its pack stream - fit inside, then parse and
/// name. Every article is budgeted; nothing here retries beyond the
/// caps, because the alternative is the known fetch livelock.
#[cfg(feature = "indexer")]
async fn run_sevenz_probe(
    conn: &mut nzbkit::nntp::Connection,
    vols: &[nzbkit::index::ProbeFile],
    spent: &mut (u64, u64),
) -> Result<ProbeRun, nzbkit::nntp::NntpError> {
    // `spent` is an out-param so a mid-run connection error does not drop
    // the wire spend already paid: the caller's Err arm used to log
    // fetchfail as 0/0 and skip the token debit, under-counting the lane
    // (14 Aug sweep).
    use nzbkit::nameprobe;
    // Head: the archive's first bytes, wherever the poster put them.
    let first = &vols[0];
    let mut head: Option<Vec<u8>> = None;
    for (_, msgid, _) in first.segments.iter().take(3) {
        if let Some(dec) = probe_fetch(conn, msgid, spent).await?
            && dec.offset() == 0
            && dec.data.len() >= 32
        {
            head = Some(dec.data);
            break;
        }
    }
    let Some(head) = head else {
        return Ok(ProbeRun::new("nohead", false, spent.0, spent.1));
    };
    let Some(start) = nameprobe::sevenz_start(&head) else {
        return Ok(ProbeRun::new("parsefail", true, spent.0, spent.1));
    };
    if start.header_size == 0 || start.header_size > nameprobe::SEVENZ_END_MAX {
        return Ok(ProbeRun::new("parsefail", true, spent.0, spent.1));
    }
    // Tail of the LAST volume, walked backwards. Chunks must chain
    // contiguously up to the file's end; a break in the chain is the
    // scrambled-offsets shape the pilot proved unprobeable.
    let last = vols.last().expect("recipe never matches empty");
    let mut chunks: Vec<nzbkit::yenc::Decoded> = Vec::new();
    let mut have: u64 = 0;
    let mut verdict: Option<Result<Vec<nzbkit::nameprobe::SevenzEntryInfo>, ()>> = None;
    for (_, msgid, _) in last.segments.iter().rev().take(PROBE7Z_TAIL_MAX) {
        let Some(dec) = probe_fetch(conn, msgid, spent).await? else {
            return Ok(ProbeRun::new("fetchfail", false, spent.0, spent.1));
        };
        have += dec.data.len() as u64;
        chunks.push(dec);
        // The chain grows tail-first; verify contiguity before parsing.
        // checked_add: `end` comes off the wire (a =ybegin size with no
        // =ypart passes through ungeometry-checked), and u64::MAX + 1
        // must read as "not contiguous", not panic a debug daemon's
        // probe task.
        chunks.sort_by_key(|c| c.begin);
        let contiguous = chunks
            .windows(2)
            .all(|w| w[0].end.checked_add(1) == Some(w[1].begin));
        if !contiguous {
            return Ok(ProbeRun::new("tailmiss", true, spent.0, spent.1));
        }
        if have < start.header_size {
            continue;
        }
        let tail: Vec<u8> = chunks.iter().flat_map(|c| c.data.iter().copied()).collect();
        match nameprobe::sevenz_tail_names(&head, &tail) {
            Ok(entries) => {
                verdict = Some(Ok(entries));
                break;
            }
            // A packed header wanting bytes just before our chunks:
            // extend the chain if the cap allows, otherwise report it.
            Err(nameprobe::ProbeError::HeaderUnreachable) => {
                verdict = Some(Err(()));
                continue;
            }
            Err(nameprobe::ProbeError::EncryptedHeader) => {
                return Ok(ProbeRun::new("encrypted", true, spent.0, spent.1));
            }
            Err(nameprobe::ProbeError::TailCrcMismatch) => {
                return Ok(ProbeRun::new("tailmiss", true, spent.0, spent.1));
            }
            Err(_) => {
                return Ok(ProbeRun::new("parsefail", true, spent.0, spent.1));
            }
        }
    }
    match verdict {
        Some(Ok(entries)) => match nzbkit::nameprobe::pick_media_name(&entries) {
            Some(name) => Ok(ProbeRun {
                outcome: "named",
                give_up: true,
                name: Some(name),
                articles: spent.0,
                bytes: spent.1,
            }),
            None => Ok(ProbeRun::new("junkname", true, spent.0, spent.1)),
        },
        Some(Err(())) => Ok(ProbeRun::new("unreachable", true, spent.0, spent.1)),
        None => Ok(ProbeRun::new("tailmiss", true, spent.0, spent.1)),
    }
}

// ---- TODO 131 rung 5: the ON-DEMAND RAR namer ------------------------

/// Volumes a RAR probe would look at, in the order the pilot proved
/// pays: MIDDLE first, then the physical first, then the last.
///
/// The middle-first order is the pilot's actual finding, not a style
/// choice. A multi-volume RAR's CONTINUATION volumes repeat the inner
/// file header, and the earlier bundle's "779-fetch dead end" measured
/// the wrong search: it looked for physical volume 1 by FILENAME, which
/// in this band is not where the archive starts (`part01.rar` carrying
/// payload at offset ~288 MB, global segment 1 decoding to `part44`).
/// Selecting by the stored part-1 TUPLE of any file row lands on that
/// row's own leading bytes instead - 44 of 44 sampled targets decoded
/// at yEnc `begin=1`, and a header parsed in a mean of 1.1 articles.
///
/// Capped at three because that is the measured ceiling: only 4 of 40
/// targets needed a second look and none needed a fourth. Chasing
/// further is the fetch livelock every lane here is built to avoid.
/// The byte-probe naming worker (TODO 131 B3): a 60 s loop that spends
/// a small article budget reading real names out of obfuscated
/// single-7z posts. Modelled on the oracle sampler: stamp-first
/// rotation, one held connection, cooldowns, and a hard stand-down
/// while anything downloads.
///
/// Honest scope, so nobody reads more into this lane than the
/// measurements support: the shape it names is ~29% of currently-dark
/// bytes on the measured index and is effectively ONE automated
/// reposter's TV output in alt.binaries.tv. The daily tallies
/// (`mode=probe7z_stats`) exist precisely because that poster can stop,
/// scramble, or start encrypting headers at any moment - the lane's
/// yield is watched, never assumed.
#[cfg(feature = "indexer")]
pub fn spawn_probe7z(daemon: &Arc<Daemon>, config: &std::path::Path) {
    let config = config.to_path_buf();
    let d = daemon.clone();
    tokio::spawn(async move {
        let mut conn: Option<(nzbkit::config::ServerConfig, nzbkit::nntp::Connection)> = None;
        let mut cooldown: std::collections::HashMap<String, Instant> = Default::default();
        // Token bucket over articles: refills at the hourly budget,
        // caps at ten minutes' worth so an idle stretch cannot bank an
        // afternoon of burst.
        let mut tokens: f64 = 0.0;
        loop {
            tokio::time::sleep(std::time::Duration::from_secs(60)).await;
            let rate = d.index_probe7z_budget.load(Ordering::Relaxed);
            if !d.index_probe7z.load(Ordering::Relaxed)
                || rate == 0
                || d.offline.load(Ordering::Relaxed)
                || d.indexer_off()
                || d.started_at.lock_ok().is_some()
            {
                // Same stand-down shape as the sampler: dropping the
                // connection is the hang-up, and an idle session held
                // against a provider is the account's slot, not ours.
                if let Some((_, c)) = conn.take() {
                    c.quit().await;
                }
                tokens = 0.0;
                continue;
            }
            // The bucket must be allowed to hold at least one probe's
            // worth: the cap is ten minutes of budget (rate/6), and the
            // work gate below needs PROBE7Z_ARTICLES_MAX tokens, so any
            // budget under 48/hr capped below 8 and the lane sat
            // enabled, eligible counting up, probing NOTHING - the
            // silent-zero-yield shape again, this time by configuration.
            // The refill rate still honors the hourly budget; a tiny
            // budget just fires one probe less often.
            tokens = (tokens + rate as f64 / 60.0)
                .min((rate as f64 / 6.0).max(PROBE7Z_ARTICLES_MAX as f64));
            let now = std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|t| t.as_secs() as i64)
                .unwrap_or(0);
            while tokens >= PROBE7Z_ARTICLES_MAX as f64 {
                let Some(cand) =
                    d.with_index(|ix| ix.probe7z_pick(now, 1).ok()?.into_iter().next())
                else {
                    break;
                };
                // Stamp first: even a probe that dies mid-fetch
                // rotates the pick, so one broken release cannot pin
                // the lane (the sampler's rule, same reason).
                d.with_index(|ix| ix.probe7z_mark(cand.id, now).ok());
                let files = d
                    .with_index(|ix| ix.probe7z_files(cand.id).ok())
                    .unwrap_or_default();
                let Some(recipe) = probe_recipe(&files) else {
                    d.with_index(|ix| {
                        ix.probe7z_give_up(cand.id, now).ok();
                        ix.probe7z_note(now, "noshape", 0, 0).ok()
                    });
                    continue;
                };
                // A connection, made or kept. Servers come from the
                // scan policy (enabled, never metered or per-byte
                // billed, one per backbone).
                if conn.is_none() {
                    let servers = match nzbkit::config::Config::load(&config) {
                        Ok(c) => crate::servers::scan_servers(&c),
                        Err(_) => break,
                    };
                    for s in servers {
                        if cooldown.get(&s.host).is_some_and(|&t| Instant::now() < t) {
                            continue;
                        }
                        match nzbkit::nntp::Connection::connect(&s).await {
                            Ok((c, _)) => {
                                cooldown.remove(&s.host);
                                conn = Some((s, c));
                                break;
                            }
                            Err(e) => {
                                let cd = sampler_cap_cooldown(&e, &s)
                                    .unwrap_or(std::time::Duration::from_secs(600));
                                cooldown.insert(s.host.clone(), Instant::now() + cd);
                                warn!(target: "probe7z", "{}: connect: {e}", s.host);
                            }
                        }
                    }
                }
                let Some((_, c)) = conn.as_mut() else { break };
                let mut spent = (0u64, 0u64);
                // Both arms land in one ProbeRun shape so the budget,
                // retire, give-up and stats steps below stay one copy;
                // the RAR arm rides along its content key and dialect,
                // the two things its apply and retire need that the 7z
                // arm's do not.
                let probed = match &recipe {
                    ProbeRecipe::SevenzTail(vols) => run_sevenz_probe(c, vols, &mut spent)
                        .await
                        .map(|r| (r, None, None, false)),
                    ProbeRecipe::RarHead => run_rar_probe(c, &files, &mut spent).await.map(|r| {
                        // Terminal verdicts give the row up exactly as
                        // the 7z arm's do; a missed head rotates and
                        // retries under the try counter.
                        let give_up = matches!(
                            r.outcome,
                            "named" | "junkname" | "parsefail" | "encrypted" | "positional"
                        );
                        (
                            ProbeRun {
                                outcome: r.outcome,
                                give_up,
                                name: r.name,
                                articles: r.articles,
                                bytes: r.bytes,
                            },
                            r.key,
                            r.enc_kind,
                            true,
                        )
                    }),
                };
                match probed {
                    Ok((run, key, enc_kind, is_rar)) => {
                        tokens -= (run.articles.max(1)) as f64;
                        if run.outcome == "encrypted" {
                            // A fact about the bytes, recorded as the
                            // terminal classification rather than as a
                            // saturated try counter: the fact stays
                            // revisable by a bump of ENC_CLASS, the
                            // counter never would. See index/encrypted.rs.
                            d.with_index(|ix| {
                                ix.probe7z_retire_encrypted(
                                    cand.id,
                                    enc_kind.unwrap_or(nzbkit::index::EncKind::SevenzAesHeader),
                                    now,
                                )
                                .ok()
                            });
                        } else if run.give_up {
                            d.with_index(|ix| ix.probe7z_give_up(cand.id, now).ok());
                        }
                        let mut outcome = run.outcome;
                        if let Some(name) = &run.name {
                            // The claims layer is the write path: a
                            // BodyProbe claim at the top tier, applied
                            // now unless a strictly stronger proof
                            // already named the row.
                            use nzbkit::index::ProvenOutcome;
                            let verdict = if is_rar {
                                d.with_index_mut(|ix| {
                                    ix.apply_rar_named(cand.id, name, key.as_deref(), now).ok()
                                })
                                .flatten()
                            } else {
                                d.with_index_mut(|ix| ix.apply_probed_name(cand.id, name, now).ok())
                                    .flatten()
                            };
                            match verdict {
                                Some(ProvenOutcome::Applied | ProvenOutcome::Replaced) => {
                                    info!(
                                        target: "probe7z",
                                        "release {} named from its own archive: {name}",
                                        cand.id
                                    );
                                }
                                Some(ProvenOutcome::Confirmed) => {}
                                // The byte-probe read a name that
                                // DISAGREES with an equal-or-stronger
                                // name already on the row (an exact-leg
                                // relay name). For this near-ground-truth
                                // band that is a real signal, not noise -
                                // give it its own count. The claims layer
                                // has already logged the specifics.
                                Some(ProvenOutcome::Conflict) => outcome = "conflict",
                                // Read bytes fine, but the name did not
                                // land: a blob title the gate refused, an
                                // association-only record, or a path-like
                                // name the sanitiser rejected.
                                _ => outcome = "junkname",
                            }
                        }
                        d.with_index(|ix| {
                            ix.probe7z_note(now, outcome, run.articles, run.bytes).ok()
                        });
                    }
                    Err(e) => {
                        // Connection trouble: log, cool the host off,
                        // reconnect on a later tick. The stamped row
                        // retries on its own rotation. The spend paid
                        // before the failure still counts - against the
                        // tally AND the token bucket.
                        tokens -= (spent.0.max(1)) as f64;
                        d.with_index(|ix| ix.probe7z_note(now, "fetchfail", spent.0, spent.1).ok());
                        if let Some((s, c)) = conn.take() {
                            warn!(target: "probe7z", "{}: {e}", s.host);
                            cooldown.insert(
                                s.host.clone(),
                                Instant::now() + std::time::Duration::from_secs(600),
                            );
                            c.quit().await;
                        }
                        break;
                    }
                }
            }
            // Give the slot back between ticks once downloads are
            // idle past the server's release timeout - same reasoning
            // as the sampler, same per-server gate.
            if let Some((s, _)) = &conn
                && !d.sampler_may_hold(s)
                && let Some((_, c)) = conn.take()
            {
                c.quit().await;
            }
        }
    });
}
