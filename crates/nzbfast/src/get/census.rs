//! The post-drain census (TODO 106 phase 2.1, cut 4): per-server stats,
//! dead servers and distinct backbones, post age, the per-slot
//! completeness walk (including the size-lie sparse scan), and the
//! recovery-data damage ledger. Body is a verbatim move from the
//! orchestrator; the returned struct's fields keep the inline names.

use super::workers::CauseSplit;
use crate::*;
use tracing::{info, warn};

/// Is this slot's name Usenet furniture - metadata a short article must
/// not fail the job over?
///
/// The extension test half of issue #23's spare rule. The caller owns
/// the other half (the recovery set must NOT cover the file: if it does,
/// repair can heal it and sparing would skip a heal we can actually do).
///
/// Shared rather than restated because the two consumers HAD drifted:
/// the census spared the file and reported `incomplete == 0`, while
/// `settle`'s uncovered-hole scan re-derived the same question straight
/// off the slot counters with no junk test. The two agreed only while a
/// job took no damage - the moment repair ran, the spared file failed
/// the job anyway, so a payload PAR2 had rebuilt and MD5-proved was
/// reported Failed and an *arr blocklisted a good release. One
/// predicate, one answer, both arms.
///
/// An obfuscated slot with no usable extension is never spared: we
/// cannot tell furniture from payload, and guessing wrong hands an *arr
/// a directory missing its video.
pub(super) fn is_spared_metadata(hint: &str) -> bool {
    let name = nzbkit::disk::sanitize_filename(hint).to_ascii_lowercase();
    let ext = std::path::Path::new(&name)
        .extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default();
    !ext.is_empty() && crate::smart::is_junk_ext(&ext)
}

/// What the settle/repair phase and the failure summary need to know
/// about how the network phase ended.
pub(super) struct Census {
    pub(super) total: u64,
    pub(super) dead_servers: Vec<String>,
    /// Servers that connected and served, then LEFT before the run
    /// ended - a permanent refusal, a spent prepaid block or quota, the
    /// outage budget blown, the connect-attempt cap. Kept apart from
    /// `dead_servers` because they are a different sentence for the
    /// user (this one worked) and a different exclusion downstream: the
    /// quorum shrank part-way through, so the survivors' 430s on the
    /// segments this server alone carried were never unanimous
    /// (error-detection audit 20 Aug, A3).
    pub(super) left_servers: Vec<String>,
    pub(super) backbones: Vec<String>,
    pub(super) post_age_days: u32,
    pub(super) sniff_bootstrap: Option<usize>,
    pub(super) incomplete: usize,
    /// Files that came up short but must NOT fail the job: Usenet
    /// furniture (`.nfo`, `.sfv`, `.txt`, …) that the recovery set does
    /// not cover, so no repair could ever heal it. Named so the log can
    /// say what was left behind. See the spare rule in the walk below.
    pub(super) incomplete_spared: Vec<String>,
    pub(super) missing_segments: u64,
    pub(super) total_segments: u64,
    pub(super) sparse_slots: Vec<String>,
    pub(super) recovery_errs: u64,
    pub(super) derrs: u64,
    /// Segments never requested for retention, over EVERY slot - what
    /// the console line reports, because a `.par2` article that went
    /// unrequested still did.
    pub(super) retention_skipped: u64,
    /// The payload-only share of it (sweep 8, M7). Diagnosis reads
    /// this: retention on a parity article says nothing about whether
    /// the payload is there.
    pub(super) retention_skipped_payload: u64,
    pub(super) recovery_missing: u64,
}

#[expect(clippy::too_many_arguments)]
pub(super) fn take_census(
    servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
    stats: &[nzbkit::pool::PoolStats],
    nzb: &Arc<Nzb>,
    slots: &[Arc<FileSlot>],
    sniff: &Arc<SniffCtl>,
    verifier: &Arc<nzbkit::live::LiveVerifier>,
    extractor: &Arc<nzbkit::extract::Extractor>,
    decode_errors: &Arc<AtomicU64>,
    retention_excluded: &Arc<CauseSplit>,
    decoded_bytes: &Arc<AtomicU64>,
    elapsed: std::time::Duration,
) -> Census {
    let total: u64 = stats.iter().map(|s| s.bytes).sum();
    info!(
        target: "get",
        "{:.1} MB raw in {:.2?} → {:.1} MB/s ({:.2} Gbps); {:.1} MB written",
        total as f64 / 1e6,
        elapsed,
        total as f64 / 1e6 / elapsed.as_secs_f64(),
        total as f64 * 8.0 / 1e9 / elapsed.as_secs_f64(),
        decoded_bytes.load(Ordering::Relaxed) as f64 / 1e6,
    );
    // Servers that never held a usable connection: their articles' fates
    // were decided by the others alone, and the failure summary must say
    // so - one dead backup silently turns a single 430 into "missing".
    let mut dead_servers: Vec<String> = Vec::new();
    // Servers that DID work and then walked out mid-run. `ever_connected`
    // stays true for them, so until this list existed they were invisible
    // to every guard downstream while `live_mask` quietly dropped them
    // from the quorum.
    let mut left_servers: Vec<String> = Vec::new();
    for ((s, _), st) in servers.iter().zip(stats) {
        if st.ever_connected {
            // Session-end breakdown, printed only when something died:
            // "12 reconnects" alone never said WHO hung up, which is what
            // made the 6 Aug churn investigation eliminate six hypotheses
            // by exclusion (research/PROVIDER-CHURN-2026-08-06.md).
            let e = st.ends;
            let why = if e.peer + e.protocol + e.prebyte + e.stall + e.ours == 0 {
                String::new()
            } else {
                let mut parts: Vec<String> = Vec::new();
                for (n, label) in [
                    (e.peer, "peer closed"),
                    (e.protocol, "protocol"),
                    (e.prebyte, "our pre-byte budget"),
                    (e.stall, "our stall deadline"),
                    (e.ours, "we hung up"),
                ] {
                    if n > 0 {
                        parts.push(format!("{n} {label}"));
                    }
                }
                format!(" [{}]", parts.join(", "))
            };
            // Write-side wait: time this server's workers spent parked
            // because decode/verify/disk could not keep up. Printed when
            // it is a visible slice of the run, because it is what tells
            // a NETWORK dip from a DISK one - the question a periodic
            // throughput sawtooth asks.
            let blocked = if st.blocked_ms >= 500 {
                format!(
                    " · {:.1}s blocked on the write side",
                    st.blocked_ms as f64 / 1000.0
                )
            } else {
                String::new()
            };
            info!(
                target: "get",
                "{:<28} {:>8.1} MB · {} conns, {} reconnects{}{}",
                s.host,
                st.bytes as f64 / 1e6,
                st.connects,
                st.reconnects,
                why,
                blocked
            );
            if st.left_mid_run {
                warn!(
                    target: "get",
                    "{:<28} served for part of the run and then stopped (refused, out of quota, or unreachable for too long)",
                    s.host
                );
                left_servers.push(s.host.clone());
            }
        } else {
            warn!(
                target: "get",
                "{:<28} no usable connection for the entire run (unreachable, or it refused the login)",
                s.host
            );
            dead_servers.push(s.host.clone());
        }
    }
    // Distinct BACKBONES that actually took part. Five resellers of one
    // backbone are one opinion, not five, and "no server had it" reads
    // like five independent votes - so the failure summary counts the
    // opinions, not the hostnames.
    let mut backbones: Vec<String> = servers
        .iter()
        .zip(stats)
        .filter(|(_, st)| st.ever_connected)
        .map(|((s, _), _)| nzbkit::oracle::backbone_of(&s.host))
        // A server addressed by IP names no backbone. It cannot support
        // a claim about independent opinions either way, so it sits the
        // clause out rather than being printed as though it were a
        // provider. Both tests are needed: since sweep 8's L9 an
        // address keys as ITSELF (it used to key as one octet - every
        // IPv4 host answered with its third), and an IPv6 literal
        // carries letters, so the no-letters test alone would start
        // printing `2001:db8::1` as a backbone name.
        .filter(|b| {
            b.chars().any(|c| c.is_ascii_alphabetic()) && b.parse::<std::net::IpAddr>().is_err()
        })
        .collect();
    backbones.sort();
    backbones.dedup();
    // The post's own age - as young as its youngest article. A post
    // nobody carries YET and a post nobody carries ANY MORE are the same
    // picture from in here (every article 430, not a byte arrived), and
    // only the calendar tells them apart: a release grabbed minutes after
    // its pre routinely 430s everywhere while it propagates, and that is
    // precisely the case the one automatic retry exists for. An NZB whose
    // dates are missing or unusable reads as age 0, which keeps it out of
    // the "gone" verdict - unknown is not old.
    let post_age_days = nzb
        .files
        .iter()
        .map(|f| nzb_age_days(f.date))
        .min()
        .unwrap_or(0);
    // Recovery data, by whichever route it was identified: issue #14's
    // in-stream sniff, or the NZB naming a file `.par2` outright. Such a
    // slot's counters describe recovery data, not payload - deferred
    // articles are a CHOICE, and a 430 on the bootstrap volume is a
    // shortfall the repair arithmetic will surface if it ever matters.
    // Counting either as "incomplete" failed a job whose payload was
    // perfect (the recovery set is duplicated per volume, so a bootstrap
    // hole rarely even dents activation). So the completeness accounting
    // below skips every recovery slot - the runtime analogue of an
    // NZB-classified Par2Volume, which never gets a slot at all.
    //
    // `is_par2()` and not the narrower "sniffed" test: a plainly-named
    // .par2 is recovery data for exactly the same reason a sniffed one
    // is, and excluding only the sniffed ones failed a job whose payload
    // was complete and byte-correct because the recovery data it never
    // needed arrived corrupt (or not at all). What losing recovery data
    // actually costs is ASSURANCE, not bytes, and that is reported as
    // such below rather than by failing the job. A post carrying no par2
    // at all has always succeeded on this same path.
    let sniff_bootstrap = sniff.bootstrap_slot();
    let slot_recovery = |i: usize| slots[i].is_par2();
    let deferred_arts = sniff.deferred_articles.load(Ordering::Relaxed);
    if deferred_arts > 0 {
        info!(
            target: "par2",
            "in-stream PAR2 identification deferred {deferred_arts} article(s) - \
         {:.1} MB of recovery data not downloaded",
            sniff.deferred_bytes.load(Ordering::Relaxed) as f64 / 1e6
        );
    }
    let mut incomplete = 0;
    let mut incomplete_spared: Vec<String> = Vec::new();
    // Segment-level totals for the failure summary. A file count alone
    // cannot tell "94 files short one segment each" (a repair away) from
    // "94 files short every segment" (the post is gone) - and those are
    // the two ends of what one user actually needs to know.
    let mut missing_segments: u64 = 0;
    let mut total_segments: u64 = 0;
    // Which slots the coverage census below may NOT speak for, because
    // this run's interval map is not the whole story about their bytes
    // (Codex sweep 2, 3 Aug M2 - see the census itself for why each
    // one is here).
    let set_names: Option<std::collections::HashSet<String>> = verifier.set().map(|set| {
        set.files
            .iter()
            .map(|f| nzbkit::disk::sanitize_filename(&f.name).to_lowercase())
            .collect()
    });
    let reconciled: std::collections::HashSet<usize> =
        sniff.state.lock_ok().reconciled.iter().copied().collect();
    // Slots that arrived complete by every counter and STILL do not
    // cover the range the post declared. Carried out of the loop
    // because the repair branch has to fail on them too: they sit
    // outside the recovery set by construction, so no repair can heal
    // them, and its own hole scan only looks at slots with a non-zero
    // counter.
    let mut sparse_slots: Vec<String> = Vec::new();
    for (i, slot) in slots.iter().enumerate() {
        if slot_recovery(i) {
            continue;
        }
        let miss = slot.missing.load(Ordering::Relaxed);
        let unresolved = slot.remaining.load(Ordering::Relaxed);
        // Disjoint by construction: `remaining` counts down as articles
        // resolve, `missing` counts the ones that resolved to nothing.
        total_segments += slot.total_segments as u64;
        missing_segments += (miss + unresolved) as u64;
        if miss > 0 || unresolved > 0 {
            // Issue #23. A post's METADATA coming up short must not fail
            // a download whose payload is whole. The reporter's every job
            // died on one missing article in a single-segment `.nfo`,
            // while the video verified clean in-stream against a set with
            // 51 spare recovery blocks - and their cleanup settings would
            // have deleted that .nfo seconds later. SABnzbd completes the
            // identical NZB against the identical servers.
            //
            // The rule is narrow on purpose, and both halves are load
            // bearing:
            //
            // - Only `JUNK_EXTS`, the "Usenet furniture" list `sweep_junk`
            //   already uses. It deliberately excludes archives and
            //   executables, so a missing .rar or .mkv still fails the
            //   job, which is the whole point of the check.
            // - Only when the recovery set does NOT cover the file. If it
            //   does, repair can rebuild it and the repair branch is where
            //   that belongs; sparing it here would skip a heal we can
            //   actually do.
            //
            // An obfuscated slot with no usable extension is not spared -
            // we cannot tell furniture from payload, and guessing wrong
            // would hand an *arr a directory missing its video.
            let name = nzbkit::disk::sanitize_filename(&slot.hint).to_ascii_lowercase();
            let covered = set_names.as_ref().is_some_and(|n| n.contains(&name));
            if !covered && is_spared_metadata(&slot.hint) {
                warn!(
                    target: "get",
                    "{}: {} missing of {} segment(s) - metadata the recovery set \
                     does not cover, so the download is still complete",
                    slot.hint,
                    miss + unresolved,
                    slot.total_segments
                );
                incomplete_spared.push(slot.hint.clone());
                continue;
            }
            incomplete += 1;
            warn!(
                target: "get",
                "{}: {} missing, {} unresolved of {} segments",
                slot.hint, miss, unresolved, slot.total_segments
            );
            continue;
        }
        // Every article accounted for, but did the bytes actually COVER
        // the file the post declared? The decoder validates each part
        // against its own `=ypart` range and deliberately not against
        // `=ybegin size` (posters do misstate totals, and rejecting on
        // that would break real posts), while the writer is sized from
        // exactly that untrusted total. So a self-consistent post can
        // declare 16 MiB, ship one CRC-valid byte, retire every counter
        // to zero, and leave a file that is one byte plus a hole - which
        // used to complete green (Codex sweep 3 Aug M7). The interval
        // map is the ground truth and costs one lock to ask.
        //
        // The interval map records what THIS run's decoder wrote, which
        // is not the same as what the file legitimately holds, so some
        // slots have to sit the census out. Which ones is a PER-SLOT
        // question, and asking it globally - `verifier.set().is_none()
        // && deferred_arts == 0` - exempted every slot in the job the
        // moment any set existed or anything anywhere was deferred
        // (Codex sweep 2, 3 Aug M2). A sparse out-of-set `.nfo` beside
        // a healthy covered RAR therefore completed green with a
        // one-byte-plus-hole file, and one unactivatable sniffed
        // recovery volume exempted the entire payload of the post.
        //
        // The two real exemptions, both narrow:
        //  - the recovery set NAMES the file, or the verifier has
        //    matched this slot to one of its entries: repair rebuilds
        //    such a file from parity, bytes no decoder in this run ever
        //    wrote, and the set's own verification is the stronger
        //    statement about it anyway;
        //  - the slot was deferred as par2-shaped and then reconciled
        //    back to payload, whose bytes arrive by side fetch
        //    (`fetch_volumes` straight to disk) rather than through the
        //    writer.
        // Both were real false positives on the e2e suite. A stable
        // plain slot outside the set is neither, and is exactly the
        // case where NOTHING else checks the bytes - `slot_uncovered`
        // itself returns None for the mapped and chased shapes that
        // legitimately hold less than they declare.
        // The name test uses the name the BYTES WERE WRITTEN UNDER, not
        // the NZB subject's guess at it. `slot.hint` comes off the
        // subject line; the writer opens the file under the yEnc
        // `name=`, and that is also the only thing `LiveVerifier` ever
        // matches on, so it is the name a PAR2 FileDesc would carry.
        // Granting an exemption on the hint meant a post whose subject
        // disagreed with its yEnc header - a copy-pasted subject block,
        // a repost - could be excused by a set that does not speak for
        // it at all, which is a false green in the one place nothing
        // else checks the bytes. It also makes the test WORK for an
        // obfuscated post, whose hint is a hash and therefore matched
        // nothing: there the on-disk name is the real one.
        let written_as = extractor.slot_file_info(i).map(|(n, _)| n);
        let covered_by_set = verifier.slot_in_set(i)
            || match (&set_names, &written_as) {
                (Some(n), Some(name)) => {
                    n.contains(&nzbkit::disk::sanitize_filename(name).to_lowercase())
                }
                _ => false,
            };
        if !covered_by_set
        && !reconciled.contains(&i)
        && slot.deferred.load(Ordering::Relaxed) == 0
        // A par-race abandonment leaves exactly this shape (articles
        // that will never arrive), but it is accounted as damage and
        // healed by repair - not a size-header lie.
        && slot.abandoned.load(Ordering::Relaxed) == 0
        && let Some(gap) = extractor.slot_uncovered(i)
        && gap > 0
        {
            incomplete += 1;
            sparse_slots.push(slot.hint.clone());
            warn!(
                target: "get",
                "{}: every article arrived but {:.1} MB of the declared \
             {:.1} MB was never written - the post's size header and its \
             parts disagree",
                slot.hint,
                gap as f64 / 1e6,
                extractor
                    .slot_file_info(i)
                    .map(|(_, sz)| sz)
                    .unwrap_or_default() as f64
                    / 1e6,
            );
        }
    }
    // Same exclusion for decode/write errors: one charged to a recovery
    // slot (a deferred straggler, a bootstrap article, the main .par2
    // itself) is a recovery-data problem for the repair arithmetic, not a
    // payload failure.
    let recovery_errs: u64 = slots
        .iter()
        .enumerate()
        .filter(|(i, _)| slot_recovery(*i))
        .map(|(_, s)| s.errors.load(Ordering::Relaxed) as u64)
        .sum();
    let derrs = decode_errors
        .load(Ordering::Relaxed)
        .saturating_sub(recovery_errs);
    if derrs > 0 {
        warn!(target: "get", "{derrs} decode/write errors");
    }
    // What the exclusions above just held back. Not a failure, but not
    // nothing either: it is the whole reason a job can finish with its
    // payload complete and no way to prove it. `remaining` is safe to
    // read as loss here because deferral decrements it (a deferred
    // article is a choice, counted separately).
    let recovery_missing: u64 = slots
        .iter()
        .enumerate()
        .filter(|(i, _)| slot_recovery(*i))
        .map(|(_, s)| {
            (s.missing.load(Ordering::Relaxed) + s.remaining.load(Ordering::Relaxed)) as u64
        })
        .sum();
    let retention_skipped = retention_excluded.total();
    let retention_skipped_payload = retention_excluded.payload();
    if retention_skipped > 0 {
        warn!(
            target: "get",
            "{retention_skipped} segment(s) never requested: older than every \
         server's configured retention (retention_days in the server settings)"
        );
    }
    if incomplete == 0 && derrs == 0 {
        // Payload slots only - the same set the census just walked. Saying
        // "all 4 files complete" while the 4th is a .par2 that arrived
        // corrupt would be a plain untruth, and now that recovery damage
        // no longer fails the job this line is reachable with one broken.
        info!(
            target: "get",
            "all {} files complete ✔",
            slots.iter().filter(|s| !s.is_par2()).count()
        );
    }
    Census {
        total,
        dead_servers,
        left_servers,
        backbones,
        post_age_days,
        sniff_bootstrap,
        incomplete,
        incomplete_spared,
        missing_segments,
        total_segments,
        sparse_slots,
        recovery_errs,
        derrs,
        retention_skipped,
        retention_skipped_payload,
        recovery_missing,
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::AtomicUsize;

    /// Issue #23's spare rule, pinned on the ONE predicate both the
    /// census and `settle`'s uncovered-hole scan now ask.
    ///
    /// They used to ask it separately, and only the census knew about
    /// junk extensions - so a `.nfo` the census spared was failed by
    /// settle the moment a job took any damage, and a payload PAR2 had
    /// rebuilt and MD5-proved reported Failed. Sharing the predicate is
    /// the fix; this pins its answers so a future edit cannot quietly
    /// widen it into archives or narrow it out of furniture.
    #[test]
    fn spared_metadata_is_furniture_only() {
        for f in [
            "movie.nfo",
            "MOVIE.NFO",
            "release.sfv",
            "notes.txt",
            "hashes.md5",
            "info.diz",
        ] {
            assert!(is_spared_metadata(f), "{f} is furniture and must spare");
        }
        for f in [
            // Payload. A short .rar or .mkv still fails the job - that
            // is the whole point of the check.
            "movie.mkv",
            "movie.part01.rar",
            "setup.exe",
            "movie.r00",
            // No usable extension: we cannot tell furniture from
            // payload, and guessing wrong hands an *arr a directory
            // with no video in it.
            "abcdef0123456789",
            "",
        ] {
            assert!(!is_spared_metadata(f), "{f} must still fail the job");
        }
    }

    fn srv(host: &str) -> (ServerConfig, nzbkit::pool::PoolConfig) {
        (
            ServerConfig {
                host: host.into(),
                port: 563,
                tls: false,
                username: None,
                password: None,
                connections: 4,
                pin_connections: false,
                rcvbuf: None,
                level: 0,
                group: None,
                retention_days: 0,
                block_bytes: None,
                block_account: false,
                bind_ip: None,
                socks5: None,
                enabled: true,
                warm_pool: false,
                idle_release_secs: None,
                idle_keep: None,
                max_source_ips: None,
            },
            nzbkit::pool::PoolConfig::default(),
        )
    }

    fn stat(bytes: u64, ever_connected: bool) -> nzbkit::pool::PoolStats {
        nzbkit::pool::PoolStats {
            bytes,
            connects: 1,
            reconnects: 0,
            ever_connected,
            left_mid_run: false,
            ends: Default::default(),
            blocked_ms: 0,
        }
    }

    /// A server that connected, served, and then walked out mid-run.
    fn stat_left(bytes: u64) -> nzbkit::pool::PoolStats {
        nzbkit::pool::PoolStats {
            left_mid_run: true,
            ..stat(bytes, true)
        }
    }

    fn slot(
        hint: &str,
        is_par2_main: bool,
        total: usize,
        remaining: usize,
        missing: usize,
        errors: usize,
    ) -> Arc<FileSlot> {
        Arc::new(FileSlot {
            hint: hint.into(),
            is_par2_main,
            sample_skipped: false,
            par2_sniffed: std::sync::atomic::AtomicBool::new(false),
            total_segments: total,
            remaining: AtomicUsize::new(remaining),
            missing: AtomicUsize::new(missing),
            errors: AtomicUsize::new(errors),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        })
    }

    fn nzb(xml: &str) -> Arc<Nzb> {
        Arc::new(Nzb::parse(xml.as_bytes()).expect("test NZB parses"))
    }

    struct Rig {
        dir: PathBuf,
        sniff: Arc<SniffCtl>,
        verifier: Arc<nzbkit::live::LiveVerifier>,
        extractor: Arc<nzbkit::extract::Extractor>,
    }

    fn rig(name: &str, n: &Arc<Nzb>, n_slots: usize) -> Rig {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-get-census-{name}-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        Rig {
            sniff: Arc::new(SniffCtl {
                nzb: n.clone(),
                slot_file: (0..n_slots).collect(),
                allow_bootstrap: false,
                state: Default::default(),
                deferred_articles: AtomicUsize::new(0),
                deferred_bytes: AtomicU64::new(0),
                fetch_done: Arc::new(AtomicU64::new(0)),
            }),
            verifier: Arc::new(nzbkit::live::LiveVerifier::with_partials_cap(
                n_slots,
                1 << 20,
            )),
            extractor: Arc::new(nzbkit::extract::Extractor::with_resume(
                &dir, n_slots, false, false,
            )),
            dir,
        }
    }

    #[expect(clippy::too_many_arguments)]
    fn census(
        servers: &[(ServerConfig, nzbkit::pool::PoolConfig)],
        stats: &[nzbkit::pool::PoolStats],
        n: &Arc<Nzb>,
        slots: &[Arc<FileSlot>],
        r: &Rig,
        decode_errors: u64,
        retention: u64,
        elapsed: std::time::Duration,
    ) -> Census {
        take_census(
            servers,
            stats,
            n,
            slots,
            &r.sniff,
            &r.verifier,
            &r.extractor,
            &Arc::new(AtomicU64::new(decode_errors)),
            &{
                let c = CauseSplit::default();
                for _ in 0..retention {
                    c.add(false);
                }
                Arc::new(c)
            },
            &Arc::new(AtomicU64::new(0)),
            elapsed,
        )
    }

    /// One damaged job exercising the issue-#23 spare rule, the dead-
    /// server and backbone accounting, the recovery-slot exclusion, and
    /// a zero elapsed (which must print inf, not panic).
    #[test]
    fn spares_furniture_counts_payload_and_excludes_recovery() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"cens.mkv" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">a@t</segment></segments>
 </file>
 <file subject='"cens.nfo" yEnc (1/1)'>
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">b@t</segment></segments>
 </file>
</nzb>"#);
        let slots = [
            // Short furniture the recovery set does not cover: spared.
            slot("foo.nfo", false, 1, 0, 1, 0),
            // Short payload: incomplete.
            slot("foo.mkv", false, 4, 1, 1, 0),
            // Short with no usable extension: never spared.
            slot("noext", false, 2, 0, 2, 0),
            // Recovery slot: excluded from the payload census entirely.
            slot("set.par2", true, 10, 3, 2, 4),
        ];
        let servers = [
            srv("news.alphaprov.com"),
            srv("eu.alphaprov.com"),
            srv("news.betaprov.com"),
            srv("127.0.0.1"),
            srv("news.deadprov.com"),
        ];
        let stats = [
            stat(100, true),
            stat(50, true),
            stat(25, true),
            stat(10, true),
            stat(0, false),
        ];
        let r = rig("damaged", &n, slots.len());
        let c = census(
            &servers,
            &stats,
            &n,
            &slots,
            &r,
            6,
            1,
            std::time::Duration::ZERO,
        );
        assert_eq!(c.total, 185);
        assert_eq!(c.dead_servers, ["news.deadprov.com"]);
        // Resellers of one backbone dedup, dead servers get no vote, and
        // a host with no ASCII letters names no backbone at all.
        assert_eq!(c.backbones, ["alphaprov", "betaprov"]);
        // One file undated: unknown is not old.
        assert_eq!(c.post_age_days, 0);
        assert_eq!(c.sniff_bootstrap, None);
        assert_eq!(c.incomplete, 2);
        assert_eq!(c.incomplete_spared, ["foo.nfo"]);
        // Payload slots only: 1 + 4 + 2 totals, (0+1) + (1+1) + (0+2) short.
        assert_eq!(c.total_segments, 7);
        assert_eq!(c.missing_segments, 5);
        assert!(c.sparse_slots.is_empty());
        // The par2 slot's errors and shortfall are recovery accounting.
        assert_eq!(c.recovery_errs, 4);
        assert_eq!(c.derrs, 2);
        assert_eq!(c.recovery_missing, 5);
        assert_eq!(c.retention_skipped, 1);
        let _ = std::fs::remove_dir_all(&r.dir);
    }

    /// A clean job: nothing incomplete, nothing spared, and the post's
    /// age is the age of its YOUNGEST article.
    #[test]
    fn a_clean_job_counts_nothing_and_dates_by_youngest() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"old.mkv" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">a@t</segment></segments>
 </file>
 <file subject='"young.mkv" yEnc (1/1)' date="1710000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">b@t</segment></segments>
 </file>
</nzb>"#);
        let slots = [slot("old.mkv", false, 2, 0, 0, 0)];
        let servers = [srv("news.alphaprov.com")];
        let stats = [stat(20, true)];
        let r = rig("clean", &n, slots.len());
        let c = census(
            &servers,
            &stats,
            &n,
            &slots,
            &r,
            0,
            0,
            std::time::Duration::from_secs(1),
        );
        assert_eq!(c.incomplete, 0);
        assert!(c.incomplete_spared.is_empty());
        assert!(c.dead_servers.is_empty());
        assert_eq!(c.backbones, ["alphaprov"]);
        assert_eq!(c.missing_segments, 0);
        assert_eq!(c.total_segments, 2);
        assert_eq!(c.derrs, 0);
        assert_eq!(c.recovery_missing, 0);
        // Sweep 8, L9: a server addressed by IP names no backbone, in
        // either family. An address keys as ITSELF now (it used to key
        // as one octet), so the no-letters test alone would start
        // printing an IPv6 literal as a provider name.
        let ip_servers = [
            srv("news.alphaprov.com"),
            srv("127.0.0.1"),
            srv("[2001:db8::1]:563"),
        ];
        let ip_stats = [stat(20, true), stat(20, true), stat(20, true)];
        let c_ip = census(
            &ip_servers,
            &ip_stats,
            &n,
            &slots,
            &r,
            0,
            0,
            std::time::Duration::from_secs(1),
        );
        assert_eq!(
            c_ip.backbones,
            ["alphaprov"],
            "an address cannot support a claim about independent opinions"
        );
        assert_eq!(c.post_age_days, nzb_age_days(1_710_000_000));
        let _ = std::fs::remove_dir_all(&r.dir);
    }

    /// A3: a server that served and then LEFT is its own list, separate
    /// from the servers that never connected at all.
    ///
    /// `ever_connected` is true for both a server that carried the whole
    /// run and one that carried ten minutes of it and then walked out, so
    /// before `left_mid_run` existed the census could not tell them
    /// apart - and downstream, `post_gone` and the auto-retry gate both
    /// read a quorum that had silently shrunk as though it were whole.
    /// The leaver still counts as a backbone opinion: it DID answer, for
    /// as long as it was there.
    #[test]
    fn a_server_that_left_mid_run_is_listed_apart_from_a_dead_one() {
        let n = nzb(r#"<?xml version="1.0"?>
<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
 <file subject='"left.mkv" yEnc (1/1)' date="1700000000">
  <groups><group>alt.binaries.test</group></groups>
  <segments><segment bytes="10" number="1">a@t</segment></segments>
 </file>
</nzb>"#);
        let slots = [slot("left.mkv", false, 2, 0, 1, 0)];
        let servers = [
            srv("news.alphaprov.com"),
            srv("news.betaprov.com"),
            srv("news.deadprov.com"),
        ];
        // Beta served and then walked out; dead never connected at all.
        let stats = [stat(100, true), stat_left(40), stat(0, false)];
        let r = rig("leftmidrun", &n, slots.len());
        let c = census(
            &servers,
            &stats,
            &n,
            &slots,
            &r,
            0,
            0,
            std::time::Duration::from_secs(1),
        );
        assert_eq!(c.left_servers, ["news.betaprov.com"]);
        assert_eq!(c.dead_servers, ["news.deadprov.com"]);
        assert_eq!(c.backbones, ["alphaprov", "betaprov"]);
        let _ = std::fs::remove_dir_all(&r.dir);
    }
}
