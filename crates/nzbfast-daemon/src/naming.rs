//! What a finished job ends up called: the download root, the
//! auto-rename style, the disambiguating suffix, episode titles, the
//! identity resolve that decides WHICH release this is, and
//! `finalize_names`, which is where all of it is spent.
//!
//! Split off `crates/nzbfast-daemon/src/daemon.rs` (TODO 106) when that file regrew past
//! its size-gate entry. A sibling module of `daemon`, declared in
//! `serve/mod.rs`, so `super` is still `serve` and every `pub(super)`
//! on the moved methods keeps the visibility it had - the trap the
//! `daemon_index.rs` round hit (a child of `daemon` re-points `super`
//! and takes 174 call sites with it).

use super::*;

/// Current download root (live-swappable - see the `out_root` field).
/// Cloned per call; callers were all one-shot (enqueue, stats), never
/// hot loops.
pub fn out_dir(d: &Daemon) -> PathBuf {
    d.out_root.read_ok().clone()
}

/// Current auto-rename name style, read from the live toggles.
pub(super) fn rename_style(d: &Daemon) -> crate::wall::NameStyle {
    crate::wall::NameStyle {
        resolution: d.rename.resolution.load(Ordering::Relaxed),
        video_codec: d.rename.vcodec.load(Ordering::Relaxed),
        audio_codec: d.rename.acodec.load(Ordering::Relaxed),
        source: d.rename.source.load(Ordering::Relaxed),
        group: d.rename.group.load(Ordering::Relaxed),
        year_parens: d.rename.year_parens.load(Ordering::Relaxed),
        quality_brackets: d.rename.quality_brackets.load(Ordering::Relaxed),
        extra_words: d.rename.extra_words.load(Ordering::Relaxed),
    }
}

/// The quality suffix a job's files WOULD carry if it were filed right
/// now: the auto-rename toggle gates it, and the tokens come from the
/// job's own stem under the live NameStyle - exactly as
/// [`finalize_names`](Daemon::finalize_names) computes it.
///
/// Guesswork, because all three inputs are live settings. A job filed
/// weeks ago carries [`Job::filed_suffix`] instead, and only a record
/// written before that field existed falls back to here (see
/// [`delete_tail`]). If the naming settings changed since filing,
/// the recomputed suffix no longer matches the file on disk and the
/// delete becomes a no-op: a leftover, which is the cheap mistake,
/// rather than a destroyed episode, which is not.
pub fn job_suffix(d: &Daemon, name: &str) -> String {
    if !d.auto_rename.load(Ordering::Relaxed) {
        return String::new();
    }
    crate::wall::quality_suffix(&crate::wall::parse_release(name), &rename_style(d))
}

/// TODO 142 / issue #32: does a job in `cat` take its finished name
/// from the .nzb file?
///
/// The category's own answer when it gave one, the global switch
/// otherwise - the same precedence every other `cat_meta` field
/// uses, so "change the download category to allow or disallow it"
/// (the reporter's words) is one edit in one place. An unlisted
/// category, which is most of them, follows the global.
pub(super) fn name_from_nzb(d: &Daemon, cat: &str) -> bool {
    d.cat_meta
        .lock_ok()
        .get(cat)
        .and_then(|m| m.nzb_name)
        .unwrap_or_else(|| d.rename.from_nzb.load(Ordering::Relaxed))
}

/// The episode titles a TV job's rename may use: the show's cached
/// TVmaze episode list, and NOTHING else.
///
/// CACHE-ONLY, and that is the whole design (TODO 78). The list is
/// written by the watchlist's 12-hourly calendar refresher, which
/// runs on a blocking watcher thread where a network call belongs;
/// this reads the blob it left. A show the cache has never heard of
/// returns empty and the file gets the name it would have got
/// anyway - no request, no waiting, and no second rename later,
/// which is what would actually hurt (a rename that lands after an
/// *arr imported the file breaks the import).
///
/// v1 is English-only by consequence rather than by choice: TVmaze
/// publishes original-language titles and that is what the blob
/// holds. The setting says so.
pub(super) fn episode_titles(d: &Daemon, stem: &str) -> crate::smart::EpisodeTitles {
    use crate::smart::EpisodeTitles;
    if !d.rename.episode_titles.load(Ordering::Relaxed) {
        return EpisodeTitles::default();
    }
    let p = crate::wall::parse_release(stem);
    if p.kind != crate::wall::Kind::Tv || p.title.trim().is_empty() {
        return EpisodeTitles::default();
    }
    // Same key the calendar writes: `eplist:<normalised show title>`.
    #[cfg(feature = "indexer")]
    let key = format!("eplist:{}", crate::wall::norm_title(&p.title));
    #[cfg(feature = "indexer")]
    let eps: Vec<crate::wall::EpInfo> = d
        .with_index_read(|ix| ix.kv_get(&key))
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .and_then(|v| serde_json::from_value(v["episodes"].clone()).ok())
        .unwrap_or_default();
    // Slim build: no index, so no cached episode list to consult.
    #[cfg(not(feature = "indexer"))]
    let eps: Vec<crate::wall::EpInfo> = Vec::new();
    EpisodeTitles::new(eps.into_iter().map(|e| (e.season, e.episode, e.name)))
}

/// Ask what this finished download actually is, and remember what we
/// learn (the `identity` ladder). Blocking: reads the finished
/// directory and may make up to two third-party requests.
///
/// Called before the cleanup sweep, because the sweep is what
/// deletes the `.par2` sidecars this reads. Every rung is optional
/// and every failure is silence: an offline daemon resolves nothing
/// and files the job exactly as it would have before.
pub(super) fn resolve_identity(
    d: &Daemon,
    nzo_id: &str,
    out_dir: &std::path::Path,
    posted: &str,
    inner_crc: u32,
) -> crate::identity::Identity {
    use nzbkit::release;
    let mut id = crate::identity::Identity::default();
    // Slim build: the only reader of `nzo_id` is the phase-3
    // correlation verdict below, which needs the index.
    #[cfg(not(feature = "indexer"))]
    let _ = nzo_id;
    if !d.identity_lookup.load(Ordering::Relaxed) {
        return id;
    }
    // The local facts first - they cost a directory read and no
    // request, and the fingerprints are needed either way (a job we
    // CAN name is one this table wants to learn from).
    #[cfg(feature = "indexer")]
    let sidecar = crate::identity::par_sidecar(out_dir);
    #[cfg(feature = "indexer")]
    let prints: Vec<(String, String)> = sidecar
        .as_ref()
        .map(|s| s.pairs.clone())
        .unwrap_or_default();
    // The whole-stem verdict, so a `blob.7z` job still reaches the
    // remembered PAR-hash and Matroska-title recovery below - the
    // raw function called that stem readable and skipped both (M7).
    let obfuscated = !release::stem_is_a_name(posted);
    // The full repost-table hit, matched hash included - the hash is
    // the proving key the claims layer records below.
    #[cfg(feature = "indexer")]
    let remembered_hit = obfuscated
        .then(|| d.with_index_read(|ix| ix.par_hash_lookup(&prints).ok().flatten()))
        .flatten();
    let facts = crate::identity::Facts {
        posted: posted.to_string(),
        // Only an unnameable job asks these two: they can improve on
        // nothing else, and `decide_name` would decline them anyway.
        // Reads go on the read-only connection: this runs on a job
        // tail, and parking it behind a long ingest batch would
        // hold the finished job's rename and move behind the
        // scanner.
        #[cfg(feature = "indexer")]
        remembered: remembered_hit
            .as_ref()
            .map(|(_, n, t)| (n.clone(), t.clone())),
        #[cfg(not(feature = "indexer"))]
        remembered: None,
        mkv_title: obfuscated
            .then(|| {
                crate::smart::main_video(out_dir).and_then(|v| crate::identity::container_title(&v))
            })
            .flatten(),
        // One request per completed job, cached for the process, and
        // impossible at all on a header-encrypted set (no CRC).
        srr: (inner_crc != 0)
            .then(|| crate::srrdb::archive_crc(inner_crc))
            .flatten(),
    };
    if let Some((name, src)) = crate::identity::decide_name(&facts) {
        id.name = name;
        id.src = src;
    }
    // Phase 3: a byte-level answer settles any correlation claim on
    // this release - confirmed names feed the precision meter and
    // arm the exact legs with the proven pairing; contradicted ones
    // are revoked before the wrong name outlives the evidence.
    // mkv-title deliberately does not qualify: it is an unverified
    // claim, and the meter must count only proof.
    #[cfg(feature = "indexer")]
    if matches!(id.src, "srrdb" | "par-hash") {
        let now = std::time::SystemTime::now()
            .duration_since(std::time::UNIX_EPOCH)
            .map(|t| t.as_secs() as i64)
            .unwrap_or(0);
        // Bounded like the tail's other index work: this runs on a
        // finished job's post-processing thread, and a wedged index
        // lane must not hold a completion behind a correlation
        // verdict. See `with_index_for_tail`.
        let verdict = d.with_index_for_tail(nzo_id, |ix| {
            ix.pre_corr_verdict(posted, &id.name, now).ok().flatten()
        });
        match verdict {
            Some(true) => {
                info!(target: "predb", "correlation CONFIRMED by {}: {}", id.src, id.name)
            }
            Some(false) => info!(
                target: "predb",
                "correlation REJECTED by {} - real name: {}",
                id.src, id.name
            ),
            None => {}
        }
        // §131 identity substrate: the same byte-level proof,
        // recorded as a provenance-tagged claim on the scan row
        // itself, so the truth lands in the index whether or not a
        // correlation record exists. Only an unambiguous stem match
        // may be claimed: crossposted stems can name several rows
        // and a proof that cannot be aimed is not applied - the
        // same line pre_corr_verdict draws.
        use nzbkit::index::{NameClaim, NameEvidence};
        let claim = if id.src == "srrdb" {
            NameClaim {
                name: id.name.clone(),
                evidence: NameEvidence::Crc32Len,
                key: format!("{inner_crc:08x}"),
                source: "srrdb".into(),
            }
        } else {
            NameClaim {
                name: id.name.clone(),
                evidence: NameEvidence::Hash16kLen,
                key: remembered_hit
                    .as_ref()
                    .map(|(h, _, _)| h.clone())
                    .unwrap_or_default(),
                source: "par-hash".into(),
            }
        };
        // The sidecar's Recovery Set ID is a stronger key for the
        // same name - but only when the name itself is byte-proven
        // (srrdb). Crediting a hash16k-remembered name at
        // par2-set-id tier would launder weak evidence into a
        // strong one.
        let set_claim = (id.src == "srrdb")
            .then_some(sidecar.as_ref())
            .flatten()
            .map(|sc| NameClaim {
                name: id.name.clone(),
                evidence: NameEvidence::Par2SetId,
                key: sc.set_id.clone(),
                source: "srrdb".into(),
            });
        let applied = d.with_index_for_tail(nzo_id, |ix| {
            let rids = ix.release_ids_by_stem(posted).unwrap_or_default();
            let [rid] = rids[..] else { return None };
            let out = ix.apply_proven_name(rid, &claim, now).ok()?;
            if let Some(sc) = &set_claim {
                let _ = ix.apply_proven_name(rid, sc, now);
            }
            Some((rid, out))
        });
        if let Some((rid, out)) = applied {
            info!(
                target: "claims",
                "release {rid}: {} proof for {:?} -> {out:?}",
                id.src, id.name
            );
        }
    }
    id.imdb = facts
        .srr
        .as_ref()
        .map(|h| h.imdb.clone())
        .unwrap_or_default();
    // Whatever we now believe this release is called is what the id
    // hunt and the repost table both key on.
    let best = if id.name.is_empty() { posted } else { &id.name };
    #[cfg(feature = "indexer")]
    let parsed = release::parse_release(best);
    // Our own index may already hold the id, in which case xREL must
    // not be asked - see `xrel_query`.
    #[cfg(feature = "indexer")]
    if id.imdb.is_empty() {
        id.imdb = d
            .with_index_read(|ix| ix.title_get(&parsed.key).ok().flatten())
            .map(|t| t.imdb)
            .unwrap_or_default();
    }
    if let Some(q) = crate::identity::xrel_query(best, &id.imdb) {
        let hits = crate::xrel::search_p2p(&q);
        let found = crate::xrel::imdb_for_release(best, &hits);
        if !found.is_empty() {
            id.imdb = found;
            // Only xREL's own doing when nothing else spoke; a name
            // from srrdb keeps its attribution.
            if id.src.is_empty() {
                id.src = "xrel";
            }
        }
    }
    // Teach the repost table. Only from a job we can actually name -
    // filing a fingerprint under an obfuscated stem would hand every
    // future repost of these bytes the same non-answer, permanently.
    //
    // AND ONLY AT THE TIER THAT ACTUALLY PROVED IT (W7-02). This
    // guard is a SHAPE test: `stem_is_a_name` asks whether a string
    // looks like a name, never whether that name was proved, and
    // every one of a crossed FileDesc name, a stray release's SFV
    // entry, a decoy set's name and a bare subject parse looks
    // perfectly like one. So what is recorded beside the name is
    // what stands behind it, and the table decides for itself
    // whether that is enough to displace or to contest what it
    // already holds. srrdb is the one rung here with a byte-level
    // proof (the archive header's own CRC32 of an inner file);
    // everything else - the posted stem, a Matroska Title - is an
    // unverified claim ABOUT these bytes, which is the weak tier by
    // name. (The table's own earlier answer used to be a third
    // member of that list and is now refused outright - see below.)
    // Crediting any of them higher would launder weak evidence
    // into strong, the same line the set_claim above draws.
    //
    // AND NEVER FROM THE TABLE'S OWN ANSWER (W7-14). `id.src ==
    // "par-hash"` is the one case where `best` is not a fact this
    // job established - it is what the table just said - so
    // teaching it back adds no evidence, only SPREAD. One `prints`
    // vector feeds both the lookup and the teach, and the lookup
    // may answer off a single member: release Z arrives obfuscated
    // with members p1..p5, only p1 collides with an earlier release
    // X's 16 KiB head, so the table answers "X" with nothing to
    // disagree with - and the teach then filed p2..p5, which are
    // Z's OWN fingerprints, under X's name. Four fresh fingerprints
    // poisoned by one collision, with no bytes of X anywhere near
    // this job. W7-01..04 bounded that (a `Par2SetId` proof of Z
    // corrects them) and did not close it: an honest WEAK naming of
    // Z later is EQUAL rank, so it can only CONTEST, never correct,
    // and the fingerprints of a release nothing ever proves end up
    // refused rather than right.
    //
    // What is given up is a second-order recall gain, and it was
    // MEASURED before it was given up. If Z really is a repost of
    // X then Z's members ARE X's bytes, so the table already holds
    // what it holds; the echo only ever ADDS members X's own teach
    // did not cover, so that a third post sharing one of THOSE
    // resolves. Against that: a wrong name filed permanently, at a
    // tier only a proof can lift, against bytes nothing has ever
    // named. The trade is asymmetric, and the census says the
    // upside is not merely small but unobserved - 2,329 rows over
    // 473 releases and 12.8 days of a real index, and every one of
    // the 473 acquired all of its fingerprints in a SINGLE teach
    // (max within-name `at` spread: 0 seconds). Nothing has ever
    // spread. `research/PAR-HASH-COLLISION-CENSUS-2026-08-31.md`.
    //
    // Note what this deliberately does NOT do: it does not stop
    // teaching. The common good case the 2026-07-28 gap analysis
    // argues for - a job named from its OWN .nzb whose repost later
    // arrives obfuscated - has `id.src` empty and is untouched, as
    // are srrdb and mkv-title, which are first-hand reads of these
    // bytes rather than the table quoting itself.
    //
    // The other remedy on offer - teach the echo at a tier strictly
    // BELOW the row that answered - was read and REFUSED rather
    // than deferred. `Adjacency` is the only thing under
    // `Hash16kLen`, `par_hash_lookup` does not filter by tier at
    // all, so an Adjacency row would still NAME a repost - which
    // the ladder says it may never do - and teaching lookup to skip
    // it makes the rows write-only, which is a cost with no reader.
    #[cfg(feature = "indexer")]
    if !prints.is_empty() && id.src != "par-hash" && release::stem_is_a_name(best) {
        let tier = if id.src == "srrdb" {
            nzbkit::index::NameEvidence::Crc32Len
        } else {
            nzbkit::index::NameEvidence::Hash16kLen
        };
        d.with_index_for_tail(nzo_id, |ix| {
            ix.par_hash_remember(&prints, best, &parsed.key, unix_now(), tier)
                .ok()
        });
    }
    if !id.is_empty() {
        info!(
            target: "identity",
            "{posted:?} -> {:?} {} (via {})",
            id.name, id.imdb, id.src
        );
    }
    id
}

/// Post-unpack naming & cleanup for a completed, unlocked job (blocking
/// file ops - call from `spawn_blocking`). Removes junk / keeps only
/// media (movie & TV only), then auto-renames: a movie's folder + main
/// file, or TV episodes (Season-filed when `tv_sort`, else in place).
///
/// Returns the new out_dir when the folder moved (else None), and the
/// quality suffix the naming actually used. The suffix is returned
/// rather than recomputed later because this is the only moment that
/// knows it: the settings behind it are live, and by the time a delete
/// needs to match the files on disk they may say something else. The
/// caller stores it as [`Job::filed_suffix`].
pub fn finalize_names(d: &Daemon, out_dir: &std::path::Path, job: &FinalizeJob<'_>) -> Finalized {
    let (name, cat, tv_sort) = (job.name, job.cat, job.tv_sort);
    let auto_rename = d.auto_rename.load(Ordering::Relaxed);
    let style = rename_style(d);
    // TODO 142 / issue #32: this job's name comes from the .nzb file
    // rather than from what the release parses as. A sibling of the
    // auto-rename layer and mutually exclusive with it - the two are
    // different answers to the same question, and running both would
    // mean naming the file twice.
    //
    // Season filing outranks it, which is why `tv_sort` is in the
    // condition rather than checked later. That rule does not name a
    // file, it decides a whole directory SHAPE
    // (`Show/Season 01/Show - S01E02.mkv`), it is opt-in per Smart
    // Folder rule, and half-applying it - the shape without the
    // matching filename - produces a library nothing can import.
    let nzb_naming = !tv_sort && name_from_nzb(d, cat);
    // TODO 24D: user categories classify ahead of the built-ins, and
    // the behaviors below are gated on the release's BASE BEHAVIOR,
    // not its kind: built-in Movie/Tv map to themselves, a custom
    // kind to the base its category DECLARED (movie-like / tv-like /
    // none). Explicit, because a kind that is silently neither loses
    // junk-sweep and rename - a coupling that produced bugs twice in
    // the week this was designed.
    let cats = d.custom_categories.read_ok().clone();
    let mut p = nzbkit::categories::classify(name, &cats);
    let mut base = nzbkit::categories::base_of(&p.kind, &cats);
    use nzbkit::categories::BaseBehavior as Base;
    // Wave-7 Axis A: `name` came from the .nzb, and settle has since
    // named the payload from the recovery set's own FileDesc packets
    // and a whole-file MD5 pair. These two arms are what happens
    // when those disagree, and they are disjoint by construction -
    // the job name either classified or it did not.
    //
    // Records that `p` and `base` describe the PAYLOAD rather than
    // the .nzb, which is a fact the keep-media arm below has to
    // know. Nothing else downstream needs it: `p` is local to this
    // function and its `key` field is read by nobody here.
    let mut from_disk = false;
    if matches!(base, Base::None) {
        // W7-05: a fully obfuscated post's job name is a hash, so it
        // parses to no kind and NOTHING fires - no sweep, no folder
        // rename, no quality suffix - for exactly the posts
        // deobfuscation just did the most work for. The user-visible
        // result is the worst of both: a correctly named movie
        // inside a hash-named folder, beside the junk everybody
        // else's job had swept.
        //
        // MOVIE-LIKE ONLY, and that is a stated limit rather than an
        // oversight. The TV arms below take the JOB NAME and apply
        // it to every episode in the directory, so a season pack
        // re-classified from `main_video` would have one member's
        // stem renaming the whole pack. Naming a pack from disk is a
        // different question and needs the disk name carried into
        // `tv_rename` and `episode_titles`; an obfuscated TV pack
        // therefore keeps today's behaviour exactly.
        //
        // What such a job STOPS getting is the `Base::None` arm's
        // synthesised naming, and that loss is empty by
        // construction rather than by luck: `payload_release_stem`
        // required the feature's own stem to read as a name, so
        // `nameless_video` declines on it either way, and a post
        // with no video at all never reaches here. Where
        // `movie_name` itself declines, the `None` arm below runs
        // both passes exactly as this one used to.
        if let Some(stem) = crate::smart::payload_release_stem(out_dir) {
            let disk = nzbkit::categories::classify(&stem, &cats);
            if matches!(nzbkit::categories::base_of(&disk.kind, &cats), Base::Movie) {
                info!(
                    target: "smart",
                    "{name}: classified from the payload instead - {stem:?}"
                );
                p = disk;
                base = Base::Movie;
                from_disk = true;
            }
        }
    } else if auto_rename
        && !nzb_naming
        && matches!(base, Base::Movie | Base::Tv)
        && let Some(stem) = crate::smart::proved_release_stem(out_dir)
    {
        // W7-06: the job name classified, and the renamers below are
        // about to put ITS parse on a payload a recovery set proved.
        // GH #63 decided which of two names for one payload is the
        // real one; that predicate has zero callers under `serve/`,
        // so the question was being asked again here and answered by
        // whoever ran last - which is the one with the weakest
        // evidence. `adopt_proved_identity` carries the answer, and
        // corrects only TITLE and YEAR: see its own note for why
        // refusing the rename outright would retire the metadata
        // renamer for the whole population.
        //
        // `auto_rename && !nzb_naming` is a COST gate and not a
        // policy one: those two are what every consumer of `p`
        // below is already gated on, so with either of them off
        // there is nothing for a correction to reach - and
        // `proved_release_stem` costs a second bounded PAR2 read on
        // the tail, on top of the one the sweep below makes. The
        // sweep is what DELETES the `.par2`, so this question can
        // only be asked here; sharing one read with the sweep means
        // changing both sweeps' signatures and is worth doing only
        // if that read ever shows up in a job tail's profile.
        let proved = nzbkit::release::parse_release(&stem);
        if nzbkit::release::adopt_proved_identity(&mut p, &proved) {
            info!(
                target: "smart",
                "{name}: the set declares {stem:?} - filing as that release instead"
            );
        }
    }
    // Junk / keep-media deletes apply to movie-like & TV-like only -
    // never a software payload, an unclassifiable (obfuscated) set,
    // or a custom category that declared no base (keep-media-only
    // DELETES non-media files, which for a comics or audiobook
    // category is the payload).
    // The counts come back with the record (Finalized::swept): these
    // sweeps delete files out of a finished download, and a count
    // computed and dropped meant the deletes were invisible - the
    // history drawer's cleanup line is built from it.
    let mut swept = 0usize;
    if matches!(base, Base::Movie | Base::Tv) {
        // W7-05's safety direction, and the one thing that ruling
        // refuses outright: a DISK-DERIVED classification may arm
        // the folder rename, the quality suffix, `measured_res` and
        // `sweep_junk` - never `keep_media_only`. The four are gated
        // on one `base` today and they do not deserve the same
        // confidence. `sweep_junk` deletes a NAMED list of furniture
        // extensions and spares whatever the recovery set declares
        // (M4-54); `keep_media_only` deletes by EXCLUSION, so it
        // does not need a file to be on any list, and arming it over
        // a job classified from a name a weak tier may have produced
        // is a permanent delete taken on the weakest evidence there
        // is. Row F1 gave it the set claim, which is the precondition
        // for this arm existing at all; it is not a reason to skip
        // the rest of the ruling.
        //
        // The keep-media user is not left with nothing: they fall
        // through to the safer sweep, which removes the furniture
        // they asked to have removed and no more.
        let keep_media = d.rename.media_only.load(Ordering::Relaxed) && !from_disk;
        if keep_media {
            swept = crate::smart::keep_media_only(out_dir);
        } else if d.rename.junk.load(Ordering::Relaxed) {
            swept = crate::smart::sweep_junk(out_dir);
        }
    }
    // The category's own name is NOT necessarily its folder: §129 2b
    // lets a category rename its subfolder, and `base_out_dir` is
    // what placed the job. Rebuilding the parent from the raw name
    // here re-parented every folder-renaming arm into a directory
    // the user never configured. `base_out_dir` with an empty stem
    // gives exactly the parent it chose, sanitization included.
    let parent = d.cat_dir(cat);
    // The container outranks the subject line: a "1080p" post over a
    // 720p stream gets the tag its bytes deserve. A measurement only
    // ever REPLACES a differing claim or ADDS an HD one - a name that
    // claimed nothing is not decorated with "480p" noise.
    if auto_rename
        && !nzb_naming
        && style.resolution
        && matches!(base, Base::Movie | Base::Tv)
        && let Some(measured) = crate::smart::measured_res(out_dir)
    {
        let claim = p.res.as_deref();
        if claim.is_some_and(|c| c != measured)
            || (claim.is_none() && matches!(measured, "720p" | "1080p" | "2160p"))
        {
            p.res = Some(measured.to_string());
        }
    }
    // A yearless post can still name its film when OUR OWN index
    // already knows the title by exactly one year (the enricher
    // resolved it). Ambiguity declines inside movie_year: a remade
    // title must never guess between its years.
    #[cfg(feature = "indexer")]
    if auto_rename
        && !nzb_naming
        && matches!(base, Base::Movie)
        && p.year.is_none()
        && let Some(y) = d.with_index_read(|ix| {
            ix.movie_year(&nzbkit::release::norm_title(&p.title))
                .ok()
                .flatten()
        })
    {
        p.year = Some(y);
    }
    // Empty under nzb naming, and that is not a detail: `suffix` and
    // `filed_title` are what the delete and play paths MATCH the
    // files on disk with (see `Job::filed_suffix`). Filing wrote the
    // bare .nzb name, so claiming a " [1080p]" tail it never wrote
    // would make every later lookup miss.
    let suffix = if auto_rename && !nzb_naming {
        crate::wall::quality_suffix(&p, &style)
    } else {
        String::new()
    };
    // One cache read per finished job, and only for a TV stem with
    // the setting on. Gated on auto_rename with the other naming
    // sub-settings: with the master switch off, filing still writes
    // the bare episode base, and decorating THAT would be a rename
    // the user asked not to have.
    let titles = if auto_rename && !nzb_naming {
        episode_titles(d, name)
    } else {
        crate::smart::EpisodeTitles::default()
    };
    // What filing will actually have written after the base, kept
    // for the delete and play paths. See `smart::FiledTail`.
    let filed_title = crate::smart::filed_title_segment(name, &suffix, &titles);
    let renamed = if tv_sort {
        // Season-filing carries the quality suffix when auto-rename is on.
        crate::smart::tv_organize(&parent, name, out_dir, &suffix, &titles)
    } else if nzb_naming {
        // The folder and the ONE biggest payload file. Every other
        // file - the rest of an episode pack, the sample, the subs,
        // the .nfo - keeps the name it arrived with; see
        // `smart::nzbname` for why that is the shape rather than a
        // limitation.
        //
        // Deliberately NOT gated on `auto_rename`: that switch is
        // the metadata renamer's, and someone who turned it off
        // because they disliked the names it invents is exactly who
        // asks for this one.
        crate::smart::rename_from_nzb(&parent, out_dir, name)
    } else if auto_rename {
        match base {
            Base::Tv => {
                crate::smart::tv_rename(out_dir, name, &suffix, &titles);
                None
            }
            // Movie-like only - software installers, obfuscated blobs
            // and no-base customs are left as posted (movie_name also
            // guards on year/quality, and still declines event posts
            // whose identity lives after the year - the F1 guard).
            //
            // When it declines, "left as posted" can still mean an
            // obfuscated blob of a filename inside a perfectly good
            // folder, so fall back to naming the video after the
            // release itself. See rename_obfuscated_video.
            Base::Movie => match crate::wall::movie_name(&p, &style) {
                Some(base) => crate::smart::rename_movie(&parent, out_dir, &base),
                None => {
                    crate::smart::rename_obfuscated_audio(out_dir);
                    crate::smart::rename_obfuscated_video(out_dir, name);
                    None
                }
            },
            // No declared base behaviour: we do not reshape the
            // payload, but an obfuscated video can still take the
            // release name. This is also where a FULLY obfuscated
            // post lands - it parses to no kind at all - so it is
            // the arm synthesised naming actually fires in.
            // An obfuscated MUSIC post lands here too, and the
            // release name cannot name eleven tracks - only the
            // tracks themselves can (issue #55). Beside the video
            // pass rather than instead of it: the two ask different
            // questions of different files.
            //
            // BEFORE it, and that order is deliberate. The two
            // sniffs overlap on exactly one shape - an audio-only
            // ISO-BMFF file, which is a container `video_ext`'s
            // probe has to walk the tracks of before it can decline
            // - and a probe that cannot finish leaves the sniff
            // standing, so a file with tags naming it could still
            // be offered to `nameless_video` as the feature. Tags
            // are the stronger evidence, so they are asked first:
            // once the audio pass has named a file it no longer
            // looks obfuscated, and the video pass leaves it alone.
            Base::None => {
                crate::smart::rename_obfuscated_audio(out_dir);
                crate::smart::rename_obfuscated_video(out_dir, name);
                None
            }
        }
    } else {
        None
    };
    // Last rung, and the only one that asks anything outside this
    // machine: when every pass above has left the feature wearing a
    // hash, the file's own facts may still identify it. Never for
    // TV - see `identify_video` and the module docs.
    //
    // LAST on purpose, and that ordering is the whole relationship
    // with `crate::identity`. Those four oracles read an exact key -
    // an archive CRC, a PAR2 fingerprint, the muxer's own Title -
    // and when one answers, `naming` above is already the canonical
    // release name and the video has been renamed off it. This rung
    // infers from runtime and year, which is the weakest evidence
    // here, so it only ever speaks when they were all silent:
    // `nameless_video` returns None the moment any of them landed a
    // name, and no request goes out.
    // Nzb naming silences this rung too. It is the weakest evidence
    // in the whole ladder, it costs network, and the user has just
    // told us in as many words which name they want on the file -
    // "we asked a film database and disagreed" is not a reply to
    // that.
    let identified = if auto_rename && !nzb_naming && !tv_sort && !matches!(base, Base::Tv) {
        d.identify_video(out_dir, job)
    } else {
        String::new()
    };
    // C: the move-completed relocation does NOT run here any more.
    // This whole function sits on the finalize tail, and the runner
    // awaits that tail before it may start the next job - so a
    // multi-minute NAS copy used to stall the entire queue. The
    // caller marks the job `move_pending` instead and the mover
    // worker (spawn_mover) runs `relocate_completed` off-path.
    let moved = renamed;
    // #20: the modes go on LAST, once the payload has stopped moving
    // here. The mover applies them again after its relocation, for
    // the same reason and with the destination root.
    let umask = d.out_umask.load(Ordering::Relaxed);
    if umask <= 0o777 {
        let final_dir = moved.as_deref().unwrap_or(out_dir);
        let root = d.out_root.read_ok().clone();
        crate::smart::apply_out_umask(final_dir, Some(&root), umask);
    }
    Finalized {
        moved,
        suffix,
        filed_title,
        identify: identified,
        swept,
    }
}

#[cfg(test)]
mod tests;

/// The repost table's round trip: what a later arrival of the SAME
/// bytes is told, when an earlier job already named that fingerprint.
#[cfg(all(test, feature = "indexer"))]
mod repost_tests;

/// Axis A: which name owns a job once settle has named its payload -
/// W7-05's reclassification, W7-06's evidence order, W7-08's decline.
#[cfg(test)]
mod authority_tests;
