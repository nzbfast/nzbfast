//! M29 availability oracle v1: learn which BACKBONES still carry which
//! posts, keyed by (backbone, group family, age bucket), and predict a
//! release's completability before a byte is downloaded.
//!
//! Data sources (both free or near-free):
//! - every real download's per-article outcomes (a 222/223 is a labeled
//!   "backbone had it", a 430/423 a labeled "backbone lost it") - the
//!   pool feeds an [`OracleSink`] which is flushed to the ledger per job;
//! - an idle STAT sampler in the daemon probing indexed releases on
//!   spare connections (throttled; the daemon owns the schedule).
//!
//! Availability clusters by backbone SPOOL, not provider brand and not
//! owner, so even a single user's traffic learns fast: one Highwinds
//! reseller's 430 pattern predicts every Highwinds reseller. It does
//! NOT predict Eweka, which the same company owns on a separate spool
//! under a different takedown regime - see [`BACKBONE_ALIASES`].

use crate::sync::MutexExt;
use std::collections::HashMap;
use std::sync::Mutex;

// The ledger persistence below is the module's only sqlite; everything
// else (buckets, backbone/family naming, the in-memory sink, Snapshot
// math) compiles in slim builds too - the core download path uses it.
#[cfg(feature = "indexer")]
use rusqlite::Connection;

/// Age buckets (days → bucket index). Availability changes with post age
/// (retention limits, takedown waves hit recent posts), so the ledger
/// never mixes a 2-day-old sample with a 2-year-old one.
/// 0: 0-1d, 1: 1-7d, 2: 7-30d, 3: 30-90d, 4: 90-365d, 5: 1-3y, 6: 3y+.
pub const N_BUCKETS: u8 = 7;

pub fn age_bucket(age_days: u32) -> u8 {
    match age_days {
        0..=1 => 0,
        2..=7 => 1,
        8..=30 => 2,
        31..=90 => 3,
        91..=365 => 4,
        366..=1095 => 5,
        _ => 6,
    }
}

/// Human label for a bucket (diagnostics / future UI tooltips).
pub fn bucket_label(b: u8) -> &'static str {
    match b {
        0 => "0-1d",
        1 => "1-7d",
        2 => "7-30d",
        3 => "30-90d",
        4 => "90-365d",
        5 => "1-3y",
        _ => "3y+",
    }
}

/// Known resellers of the major backbones. Keys are the normalized
/// second-level host label (after digit/subdomain stripping); values the
/// backbone the ledger clusters them under. Unlisted hosts key under
/// their own normalized label - still correct, just unclustered.
///
/// A value is a SPOOL, not a company. Takedowns propagate within one
/// spool and stop at its edge, so two brands belong to the same key only
/// if an article removed from one is thereby removed from the other.
/// Common ownership is not that: Omicron Media owns three separate
/// spools and this table used to fold all three into one `omicron` key,
/// which cost real accuracy three ways. The ledger read Highwinds misses
/// as evidence about Eweka and could mark content "gone" on a spool that
/// still carried it (Highwinds answers DMCA takedowns, Eweka and Base-IP
/// answer Dutch NTD notices, so they genuinely diverge). `whyslow`'s
/// "unrelated providers report the same gaps" receipt and `census`'s
/// failure summary both count DISTINCT keys as independent opinions, so
/// a user on Newshosting + Eweka + TweakNews had three opinions counted
/// as one.
///
/// The bias runs one way on purpose: a MISSING cluster only slows
/// learning and under-states independence, while a WRONG cluster
/// fabricates agreement between spools that do not share takedowns. So
/// a brand whose spool the public maps disagree about keeps its own key
/// rather than being guessed into a cluster (see `fastusenet` below).
///
/// Verified 20 Aug 2026 against cogipas.com/usenet-backbones (updated
/// 2026-01-03), datahoarder.io/usenet-backbone-map (2026-05-20) and
/// usenet.org/providers. Community maps shift; re-check before trusting
/// an entry for anything expensive.
///
/// UNRESOLVED, and the one thing that could overturn the Omicron split:
/// this repo's own `diversity` check (`sysbench.rs`, which clusters
/// servers by MEASURED missing-article overlap and consults nothing in
/// this table) once reported Newshosting = Eweka = TweakNews at 100%
/// shared gaps on a six-provider live config - one spool by measurement,
/// three by every published map. Either reading can be true of a real
/// sample: retention-purged articles go missing on all three at the
/// same age whatever the takedown regime, and the run's own note warns
/// that a double-bracketed STAT id once faked a 100% overlap. Re-run
/// `nzbfast diversity` on an age-controlled sample before treating
/// either answer as settled - and note which way the risk runs if the
/// spools really are one: `whyslow` and `census` would then read three
/// keys as three independent opinions when there is one, over-stating
/// a "nobody has this" claim.
const BACKBONE_ALIASES: &[(&str, &str)] = &[
    // Omicron Media spool 1 of 3: Highwinds ("HW Media"), US + NL,
    // DMCA takedowns. Astraweb retired its own spool onto this one, and
    // is no longer an independent backbone.
    ("newshosting", "highwinds"),
    ("usenetserver", "highwinds"),
    ("easynews", "highwinds"),
    ("newsgroupninja", "highwinds"),
    ("astraweb", "highwinds"),
    // Omicron Media spool 2 of 3: Eweka, NL, NTD. One brand, its own
    // spool - which is exactly why folding it into `omicron` was wrong.
    ("eweka", "eweka"),
    // Omicron Media spool 3 of 3: Base-IP, NL, NTD. Keyed `baseip`
    // rather than `base-ip` so a Base-IP host that is NOT in this table
    // still folds here: `backbone_of` strips non-alphabetics, so
    // news.base-ip.net normalizes to `baseip` on its own.
    ("baseip", "baseip"),
    ("tweaknews", "baseip"),
    ("xlned", "baseip"),
    ("sunnyusenet", "baseip"),
    ("pureusenet", "baseip"),
    ("usenetbucket", "baseip"),
    // UsenetExpress, US, DMCA.
    ("usenetexpress", "usenetexpress"),
    ("newsdemon", "usenetexpress"),
    ("newsgroupdirect", "usenetexpress"),
    ("maximumusenet", "usenetexpress"),
    ("thecubenet", "usenetexpress"),
    ("thundernews", "usenetexpress"),
    ("usenetprime", "usenetexpress"),
    // ViperNews (operator Uzo Reto), NL, NTD - its OWN backbone. This
    // table had it under UsenetExpress; every 2026 map consulted lists
    // it as an independent spool.
    ("vipernews", "vipernews"),
    ("viper", "vipernews"),
    // Abavia, NL. XS News is Abavia's own consumer brand, not a
    // separate backbone; HitNews rides it too (its ~2,100-day retention
    // is Abavia's, nothing like Omicron's).
    ("abavia", "abavia"),
    ("xsnews", "abavia"),
    ("xsusenet", "abavia"),
    ("bulknews", "abavia"),
    ("cheapnews", "abavia"),
    ("stingyusenet", "abavia"),
    ("hitnews", "abavia"),
    // Netnews, US. BlockNews is a reseller of it, not a backbone.
    ("netnews", "netnews"),
    ("blocknews", "netnews"),
    ("usenetnow", "netnews"),
    // Giganews (UNS Holdings), also powers Supernews. Sibling to
    // Netnews under the same owner, separate spool.
    ("giganews", "giganews"),
    ("supernews", "giganews"),
    // Usenet.farm, NL, NTD. Aliased from the bare label because
    // `backbone_of` reduces news.usenet.farm to `farm` - ".farm" is a
    // real TLD but too long for the TLD-ish tail rule, so the brand
    // label it lands on is the TLD itself.
    ("usenetfarm", "usenetfarm"),
    ("farm", "usenetfarm"),
    // Deliberately NOT clustered, because the public maps disagree and
    // a wrong cluster is worse than none (see the note above):
    // - fastusenet: usenet.org puts Fast Usenet on Omicron without
    //   naming WHICH of the three spools, and no map consulted places
    //   it. It keys as `fastusenet`. It was under `usenetexpress` here,
    //   which no source supports.
    // - frugalusenet: cogipas lists Frugal Usenet under Netnews AND
    //   under Usenet.farm. It keys as `frugalusenet`.
];

/// Normalize a server host to its backbone key: take the registrable
/// label (skipping TLD-ish tails like "co.uk"), strip digits/dashes
/// (news2, ssl-eu), then apply the reseller alias map.
/// news.newshosting.com → newshosting → highwinds; news.eweka.nl →
/// eweka (its own spool); news2.blocknews.net → blocknews → netnews.
pub fn backbone_of(host: &str) -> String {
    let host = host.to_ascii_lowercase();
    let host = host.split(':').next().unwrap_or(&host); // strip :port
    let labels: Vec<&str> = host.split('.').filter(|l| !l.is_empty()).collect();
    // Walk from the end past TLD-ish labels (short, or common ccTLD
    // second levels like "co"/"com"); the first substantive label is the
    // brand. A bare hostname (tests, LAN) is its own label.
    const TLDISH: &[&str] = &["co", "com", "net", "org", "ac", "gov"];
    let mut base = *labels.last().unwrap_or(&"");
    for (i, l) in labels.iter().enumerate().rev() {
        let last = i + 1 == labels.len();
        if last && (l.len() <= 3 || TLDISH.contains(l)) {
            continue; // TLD
        }
        if !last && TLDISH.contains(l) {
            continue; // second-level TLD (co.uk)
        }
        base = l;
        break;
    }
    let stripped: String = base.chars().filter(|c| c.is_ascii_alphabetic()).collect();
    let key = if stripped.is_empty() {
        base.to_string()
    } else {
        stripped
    };
    for (alias, backbone) in BACKBONE_ALIASES {
        if key == *alias {
            return (*backbone).to_string();
        }
    }
    key
}

/// The backbone `host` belongs to, but ONLY when that name came from
/// the alias table - an unlisted host keys under its own label, which
/// is a perfectly good ledger key and a useless thing to show a user.
///
/// The caller is the dashboard's mirror-group suggestion: it offers a
/// `group` string for the server being edited, so it has to tell "this
/// brand is one of the shared networks we know about" from "this is
/// some hostname". Recognition tests the table's VALUES, not its keys,
/// so if the aliases are ever split into finer spools the suggestion
/// follows whatever [`backbone_of`] starts returning, with no second
/// list to keep in step.
pub fn known_backbone_of(host: &str) -> Option<String> {
    let key = backbone_of(host);
    BACKBONE_ALIASES
        .iter()
        .any(|(_, backbone)| *backbone == key)
        .then_some(key)
}

/// Collapse a newsgroup to its family: strip the "alt.binaries." (or
/// abbreviated "a.b.") prefix and keep the first remaining component -
/// takedown/retention behavior tracks the content family, not the exact
/// group. alt.binaries.hdtv.x264 → hdtv; alt.binaries.teevee → teevee.
pub fn group_family(grp: &str) -> String {
    let g = grp.trim().to_ascii_lowercase();
    let rest = g
        .strip_prefix("alt.binaries.")
        .or_else(|| g.strip_prefix("a.b."))
        .unwrap_or(&g);
    let fam = rest.split('.').next().unwrap_or("").trim();
    if fam.is_empty() {
        "misc".to_string()
    } else {
        fam.to_string()
    }
}

/// One aggregated ledger observation, ready to ingest: `host` is the raw
/// server host (mapped to a backbone at ingest), `bucket` an age-bucket
/// index.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Sample {
    pub host: String,
    pub family: String,
    pub bucket: u8,
    pub hits: u64,
    pub misses: u64,
}

/// In-memory accumulator the pool's workers feed per article outcome -
/// NEVER a per-article sqlite write. The job runner installs one per
/// download, the pool records into it lock-cheap, and the daemon drains
/// it into the ledger once per job.
#[derive(Default)]
pub struct OracleSink {
    /// Pool server order → host (set once at pool build; the pool only
    /// knows server indices).
    servers: Mutex<Vec<String>>,
    /// Group family of the job's release (one NZB ≈ one family).
    family: Mutex<String>,
    /// (server index, age bucket) → (hits, misses, takedown misses).
    /// The third count is the subset of `misses` whose refusal SAID the
    /// article was removed (`crate::nntp::takedown_flavoured`); `drain`
    /// spends it as extra miss weight.
    counts: Mutex<HashMap<(usize, u8), (u64, u64, u64)>>,
}

impl OracleSink {
    /// Install the job context: pool server hosts (pool order) and the
    /// release's group family.
    pub fn set_context(&self, hosts: Vec<String>, family: String) {
        *self.servers.lock_ok() = hosts;
        *self.family.lock_ok() = family;
    }

    /// Record one 222 body served by server `si` for an article
    /// `age_days` old (0 = fresh/unknown - bucketed as fresh; NZBs
    /// without dates are rare enough not to matter).
    pub fn hit(&self, si: usize, age_days: u32) {
        let mut c = self.counts.lock_ok();
        c.entry((si, age_bucket(age_days))).or_insert((0, 0, 0)).0 += 1;
    }

    /// Record one 430/423 from server `si`.
    pub fn miss(&self, si: usize, age_days: u32) {
        let mut c = self.counts.lock_ok();
        c.entry((si, age_bucket(age_days))).or_insert((0, 0, 0)).1 += 1;
    }

    /// Record one TAKEDOWN-FLAVOURED refusal from server `si` - the
    /// server said the article was removed, not merely that it could
    /// not find it. Counted as a miss like any other, plus a tally that
    /// `drain` turns into extra miss weight: an explicit removal notice
    /// is a statement about gone-ness that a bare 430 (which may be
    /// propagation, a backfill hole, or a frontend wobble) is not.
    /// Absence of the flavour is NO evidence the other way - most
    /// backbones never name the reason - so plain misses keep exactly
    /// the weight they had.
    pub fn miss_takedown(&self, si: usize, age_days: u32) {
        let mut c = self.counts.lock_ok();
        let e = c.entry((si, age_bucket(age_days))).or_insert((0, 0, 0));
        e.1 += 1;
        e.2 += 1;
    }

    /// Empty the accumulator into ingest-ready samples, one per LEDGER
    /// cell (backbone × bucket) and each clamped to
    /// [`JOB_SAMPLE_WEIGHT`]. Counts recorded for a server index the
    /// context never named are dropped (can't attribute them).
    pub fn drain(&self) -> Vec<Sample> {
        let servers = self.servers.lock_ok().clone();
        let family = self.family.lock_ok().clone();
        let counts = std::mem::take(&mut *self.counts.lock_ok());
        let raw: Vec<Sample> = counts
            .into_iter()
            .filter_map(|((si, bucket), (hits, misses, takedowns))| {
                let host = servers.get(si)?.clone();
                Some(Sample {
                    host,
                    family: family.clone(),
                    bucket,
                    hits,
                    // A takedown-flavoured miss counts twice: the server
                    // put "removed" on the record, which a bare 430
                    // never does. Conservative on purpose - the doubled
                    // weight only shifts the hit/miss RATIO where hits
                    // exist beside it (clamp_weight preserves ratios,
                    // and an all-miss cell is all-miss either way), and
                    // the per-job clamp below still bounds the whole
                    // release to one JOB_SAMPLE_WEIGHT observation.
                    misses: misses.saturating_add(takedowns),
                })
            })
            .collect();
        // ONE job contributes one bounded observation per LEDGER cell,
        // not one per article and not one per configured server. A
        // release's articles are not independent trials - they live or
        // die together - so feeding 15,000 raw 430s into a Wilson
        // interval that assumes independence is a category error, and it
        // is what let two doomed postings drive (highwinds, hdtv, 7-30d)
        // to a 0.05 upper bound while 12 other releases in that same
        // cell were 36/36 available. The fold by backbone is the same
        // argument one level up: three Highwinds resellers refusing
        // the same article is one refusal, not three.
        fold_by_backbone(&raw, JOB_SAMPLE_WEIGHT)
    }
}

/// Evidence weight one download contributes to a single (server, age
/// bucket) cell, whatever its article count.
///
/// 5 is exactly the idle STAT sampler's per-release budget -
/// `ceil(oracle_sample / 60)` at the default 300/hour, see
/// `spawn_oracle_sampler` in the daemon. That equality is the point.
/// Article-counted, a single 15,000-segment download outweighed one
/// sampler probe by roughly 3,000:1, so the sampler - the ONLY evidence
/// source that can reach a server routing has stopped dialing - could
/// never correct a cell the download path had poisoned. Weighted the
/// same, the two sources are commensurable and [`MIN_SAMPLES`] means
/// about a dozen distinct postings, which is what it reads like.
pub const JOB_SAMPLE_WEIGHT: u64 = 5;

/// Scale `(hits, misses)` down to `weight` total samples, preserving
/// the ratio: hits round half-up, misses take the remainder. Totals
/// already at or under `weight` pass through untouched, so an all-miss
/// cell stays all-miss and an all-hit cell stays all-hit.
fn clamp_weight(hits: u64, misses: u64, weight: u64) -> (u64, u64) {
    let n = hits + misses;
    if weight == 0 || n <= weight {
        return (hits, misses);
    }
    // u128 so the product cannot wrap on an absurd count; the result is
    // bounded by `weight`, so the cast back is lossless.
    let h = ((hits as u128 * weight as u128 + (n as u128) / 2) / n as u128) as u64;
    (h, weight - h)
}

/// Fold ONE release's (or one job's) samples by BACKBONE, then apply
/// `weight` once per backbone cell.
///
/// Evidence is produced per configured SERVER, but the ledger is keyed
/// by backbone, and a user can have three configured servers that are
/// all the same backbone (Easynews, UsenetServer and Newshosting are
/// all Highwinds). The idle sampler STATs the same article ids against every
/// enabled server in one tick, and a doomed download takes a real 430
/// from each of them - so one release used to arrive as three
/// independent `(0, 5)` samples that ingest summed into `(0, 15)`,
/// crossing [`MIN_SAMPLES`] and marking the whole backbone gone off a
/// single posting. That is the same category error [`clamp_weight`]
/// exists to prevent, just at 3x instead of 3,000x: the three probes are
/// one observation of one release, not three trials.
///
/// The host of the folded sample is the alphabetically first raw host of
/// the group, never a synthesized backbone key - `ingest` still does the
/// host → backbone mapping, and nothing here has to assume
/// `backbone_of` is idempotent on its own output.
///
/// Only WITHIN a batch. Two aliases sampled in separate ingest calls are
/// two different releases and must still merge additively.
pub fn fold_by_backbone(samples: &[Sample], weight: u64) -> Vec<Sample> {
    let mut by: HashMap<(String, String, u8), Sample> = HashMap::new();
    for s in samples {
        let key = (backbone_of(&s.host), s.family.clone(), s.bucket);
        match by.get_mut(&key) {
            Some(e) => {
                e.hits = e.hits.saturating_add(s.hits);
                e.misses = e.misses.saturating_add(s.misses);
                if s.host < e.host {
                    e.host = s.host.clone();
                }
            }
            None => {
                by.insert(key, s.clone());
            }
        }
    }
    let mut out: Vec<Sample> = by
        .into_values()
        .map(|mut s| {
            let (h, m) = clamp_weight(s.hits, s.misses, weight);
            s.hits = h;
            s.misses = m;
            s
        })
        .collect();
    out.sort_by(|a, b| (&a.host, a.bucket).cmp(&(&b.host, b.bucket)));
    out
}

/// Create the ledger table and run its one-shot rescale (idempotent;
/// called from `Index::open`).
#[cfg(feature = "indexer")]
pub fn ensure_schema(db: &Connection) -> rusqlite::Result<()> {
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS oracle(
            backbone TEXT NOT NULL,
            family TEXT NOT NULL,
            bucket INTEGER NOT NULL,
            hits INTEGER NOT NULL DEFAULT 0,
            misses INTEGER NOT NULL DEFAULT 0,
            updated_at INTEGER NOT NULL DEFAULT 0,
            legacy INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(backbone, family, bucket));
         -- The index's own schema creates this first on every real
         -- open; repeated here (same definition, IF NOT EXISTS, so a
         -- no-op there) only so the ledger's migration flag has a home
         -- when this module is handed a bare connection.
         CREATE TABLE IF NOT EXISTS kv(
            k TEXT PRIMARY KEY,
            v TEXT NOT NULL);",
    )?;
    // `legacy` on a ledger that predates it. Non-fatal by design: on a
    // database that already has the column this fails with "duplicate
    // column name" every open, and that error is the expected answer,
    // not a reason to refuse the index.
    let _ = db.execute(
        "ALTER TABLE oracle ADD COLUMN legacy INTEGER NOT NULL DEFAULT 0",
        [],
    );
    rescale_article_counts(db);
    remap_retired_backbones(db);
    Ok(())
}

/// Cells whose key was retired when [`BACKBONE_ALIASES`] moved to
/// per-SPOOL granularity (20 Aug 2026). Two shapes, handled differently
/// because they are different claims about the old evidence.
///
/// `RENAMED` is the same spool under a new key: BlockNews turned out to
/// be a reseller of Netnews rather than a backbone, XS News to be
/// Abavia's own brand, and Astraweb to have retired its spool onto
/// Highwinds. Every sample under the old key was a sample of the new
/// key's spool all along, so those rows are re-keyed and merged
/// ADDITIVELY - exactly what `ingest` would have done had the table been
/// right at the time.
///
/// `SPLIT` is a key that no longer names one spool: `omicron` folded
/// Highwinds, Eweka and Base-IP together, so a row under it is some
/// unknown mixture of three spools' evidence. Nothing recovers which,
/// because the ledger stores counts and never the server that produced
/// them. Those rows are DELETED.
///
/// Deleting is the deliberate choice over the two alternatives.
/// Copying an `omicron` row to all three spools would take Highwinds'
/// DMCA misses and assert them of Eweka, which is the precise error
/// this whole change exists to remove. Re-keying it to `highwinds`
/// alone (the busiest of the three, so statistically the likeliest
/// source) would still be a guess presented as measurement, and one
/// that can only push a real cell toward a false `Gone`. The ledger is
/// cheap to rebuild - [`MIN_SAMPLES`] is about a dozen postings, days
/// at the idle sampler's one release a minute - and the cost of the
/// wrong answer is a user told content is gone when a spool still has
/// it.
///
/// What this CANNOT undo: evidence that was mis-folded at ingest into a
/// key that survives. HitNews and Fast Usenet samples were written into
/// `omicron` (deleted here, so moot) and `usenetexpress`; ViperNews
/// samples went to `usenetexpress`; UsenetBucket samples went to
/// `abavia`. Those counts are summed into rows that also hold correct
/// evidence and cannot be separated. They are bounded (one reseller's
/// share of one user's traffic) and decay as fresh correctly-keyed
/// samples accumulate.
///
/// Non-fatal and flag-guarded like the module's other migrations; if
/// the flag write is lost the whole thing re-runs, and re-running is a
/// no-op once no retired key is left in the table.
#[cfg(feature = "indexer")]
fn remap_retired_backbones(db: &Connection) {
    const FLAG: &str = "oracle_spool_split_v1";
    /// (retired key, spool it was always a sample of).
    const RENAMED: &[(&str, &str)] = &[
        ("astraweb", "highwinds"),
        ("blocknews", "netnews"),
        ("xsnews", "abavia"),
    ];
    /// Keys that named more than one spool - unattributable.
    const SPLIT: &[&str] = &["omicron"];
    if db
        .query_row("SELECT 1 FROM kv WHERE k=?1", [FLAG], |_| Ok(()))
        .is_ok()
    {
        return;
    }
    let Ok(tx) = db.unchecked_transaction() else {
        return;
    };
    let mut ok = true;
    for (old, new) in RENAMED {
        // Read the old rows out before writing: an upsert whose SELECT
        // source is the table it conflicts on is not worth reasoning
        // about, and the ledger is small by construction.
        let rows: Vec<(String, i64, i64, i64, i64, i64)> = match tx
            .prepare("SELECT family, bucket, hits, misses, updated_at, legacy                       FROM oracle WHERE backbone = ?1")
            .and_then(|mut st| {
                st.query_map([old], |r| {
                    Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?, r.get(5)?))
                })
                .and_then(|it| it.collect())
            }) {
            Ok(rows) => rows,
            Err(_) => {
                ok = false;
                continue;
            }
        };
        for (family, bucket, hits, misses, updated_at, legacy) in rows {
            let r = tx.execute(
                "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at, legacy)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)
                 ON CONFLICT(backbone, family, bucket) DO UPDATE SET
                   hits = hits + excluded.hits,
                   misses = misses + excluded.misses,
                   legacy = legacy + excluded.legacy,
                   updated_at = MAX(updated_at, excluded.updated_at)",
                rusqlite::params![new, family, bucket, hits, misses, updated_at, legacy],
            );
            ok &= r.is_ok();
        }
        ok &= tx
            .execute("DELETE FROM oracle WHERE backbone = ?1", [old])
            .is_ok();
    }
    for old in SPLIT {
        ok &= tx
            .execute("DELETE FROM oracle WHERE backbone = ?1", [old])
            .is_ok();
    }
    if ok && tx.commit().is_ok() {
        let _ = db.execute("INSERT OR REPLACE INTO kv(k, v) VALUES(?1, '1')", [FLAG]);
    }
}

/// One-shot migration off article-counted evidence.
///
/// Cells written before [`JOB_SAMPLE_WEIGHT`] counted ARTICLES, so a
/// handful of doomed releases - re-counted on every retry - could bury
/// a cell under tens of thousands of correlated misses and hold it
/// confidently red forever. Those counts cannot be converted into
/// release samples (the release identity was never recorded), but
/// wiping the table would throw away real signal too.
///
/// So scale every cell proportionally down to [`MIN_SAMPLES`] - 1,
/// ratio preserved, and record how much of what survives is that
/// migrated lean in the `legacy` column. Every cell lands just under
/// the evidence bar, which means `backbone_gone` and `carry_rate` stop
/// consulting them the moment this runs, while the ledger keeps its
/// lean for the wall's amber. A dozen fresh release-weighted samples
/// then confirm or refute each cell - at the sampler's one release a
/// minute, days for the cells that matter, not the 11 days of pure
/// sampler budget it would have taken to out-vote 57,000 articles.
///
/// `legacy` is what makes "a dozen fresh samples" true rather than
/// aspirational. Scaling alone left `(0, 15263)` as `(0, 11)`, one
/// sample under the bar - so the very first healthy release, worth
/// [`JOB_SAMPLE_WEIGHT`], made it `(5, 11)`, which is 16 samples with a
/// Wilson upper bound of 0.556 and therefore CONFIDENTLY GONE. Evidence
/// that the backbone serves the family perfectly re-armed a verdict
/// built from 15,263 correlated article misses. Counting only
/// `hits + misses - legacy` toward [`MIN_SAMPLES`] means the migrated
/// lean still shapes the interval but can never license a verdict on
/// its own.
///
/// Non-fatal and self-healing like the index's other migrations: if the
/// flag write is lost the UPDATE re-runs, and its `WHERE` skips every
/// cell already at or under the target. The `legacy` stamp is
/// re-entrant for the same reason - `MIN(hits + misses, target)` on an
/// already-migrated cell writes back the value it already held, and
/// where it does not, it can only over-state the legacy share, which
/// makes the gate stricter and never looser.
///
/// The stamp runs behind a flag of its own. The rescale shipped a
/// release before the `legacy` column existed, so on every ledger that
/// already took it the lean is present and unmarked - the exact
/// population this gate is for. One shared flag would have declared
/// those ledgers migrated and skipped them permanently.
#[cfg(feature = "indexer")]
fn rescale_article_counts(db: &Connection) {
    const FLAG: &str = "oracle_release_weight_v1";
    const STAMP_FLAG: &str = "oracle_legacy_stamp_v1";
    let flagged = |k: &str| {
        db.query_row("SELECT 1 FROM kv WHERE k=?1", [k], |_| Ok(()))
            .is_ok()
    };
    let stamped = flagged(STAMP_FLAG);
    let already_rescaled = flagged(FLAG);
    if stamped && already_rescaled {
        return;
    }
    // `target` is at least 1 and the WHERE keeps the divisor above it,
    // so neither division can be by zero. SQLite evaluates every SET
    // expression against the row's ORIGINAL values, so `misses` reads
    // the pre-update `hits`.
    let target = (MIN_SAMPLES - 1) as i64;
    // Stamp BEFORE the rescale, while the counts are still the article
    // ones: every sample present at this instant is article-counted, and
    // what survives the rescale is `MIN(n, target)` of it. Cells already
    // under the target keep all of their count as legacy - 11 correlated
    // article misses are no more a dozen releases than 15,263 are.
    //
    // The stamp carries its OWN flag because the rescale shipped first:
    // every ledger that already ran it holds the article-derived lean
    // with `legacy` at zero, and those are precisely the ledgers this
    // gate exists to protect. Sharing FLAG would have skipped them for
    // good and left the defect live everywhere it had already been
    // reached. On such a ledger the counts are post-rescale, so samples
    // taken since it ran are stamped as legacy too: that over-states the
    // lean, which asks for more fresh evidence before a verdict and can
    // never license one.
    if !stamped {
        let stamp = db.execute(
            "UPDATE oracle SET legacy = MIN(hits + misses, ?1)",
            [target],
        );
        if stamp.is_ok() {
            let _ = db.execute(
                "INSERT OR REPLACE INTO kv(k, v) VALUES(?1, '1')",
                [STAMP_FLAG],
            );
        }
    }
    if already_rescaled {
        return;
    }
    let rescaled = db.execute(
        "UPDATE oracle
            SET hits   = (hits * ?1 + (hits + misses) / 2) / (hits + misses),
                misses = ?1 - (hits * ?1 + (hits + misses) / 2) / (hits + misses)
          WHERE hits + misses > ?1",
        [target],
    );
    if rescaled.is_ok() {
        let _ = db.execute("INSERT OR REPLACE INTO kv(k, v) VALUES(?1, '1')", [FLAG]);
    }
}

/// Fold a batch of samples into the ledger (one transaction).
#[cfg(feature = "indexer")]
pub fn ingest(db: &Connection, samples: &[Sample], now: i64) -> rusqlite::Result<()> {
    if samples.is_empty() {
        return Ok(());
    }
    let tx = db.unchecked_transaction()?;
    {
        let mut up = tx.prepare_cached(
            "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
             VALUES(?1, ?2, ?3, ?4, ?5, ?6)
             ON CONFLICT(backbone, family, bucket) DO UPDATE SET
               hits = hits + excluded.hits,
               misses = misses + excluded.misses,
               updated_at = excluded.updated_at",
        )?;
        for s in samples {
            if s.hits == 0 && s.misses == 0 {
                continue;
            }
            up.execute(rusqlite::params![
                backbone_of(&s.host),
                s.family,
                s.bucket as i64,
                s.hits as i64,
                s.misses as i64,
                now
            ])?;
        }
    }
    tx.commit()
}

/// The whole ledger in memory - it is tiny by construction (backbones ×
/// families × 7), so verdict computation loads it once per request.
#[derive(Debug, Default, Clone)]
pub struct Snapshot {
    /// (backbone, family, bucket) → (hits, misses).
    cells: HashMap<(String, String, u8), (u64, u64)>,
    /// How much of a cell's count is migrated ARTICLE evidence rather
    /// than release-weighted samples. A parallel map rather than a third
    /// count in `cells`, so `insert`/`cell`/`iter_cells` and every
    /// scoreboard call site keep their two-count shape. Absent = 0.
    legacy: HashMap<(String, String, u8), u64>,
}

impl Snapshot {
    #[cfg(feature = "indexer")]
    pub fn load(db: &Connection) -> rusqlite::Result<Snapshot> {
        // `legacy` arrives with `ensure_schema`'s ALTER, which a
        // read-only open cannot run. A scoreboard pointed at an archived
        // copy of an old index must still print, so a missing column
        // reads as evidence rather than failing - but it reads as ALL
        // legacy, never as none.
        //
        // No column means no ledger this build ever opened for writing,
        // so nothing in it was ever release-weighted: every count in it
        // is the article-counted lean `rescale_article_counts` exists to
        // disarm, and the stamp it would have written is exactly
        // `MIN(hits + misses, target)` of it. Reading the absent column
        // as zero said the opposite - that every historical article
        // outcome was a fresh release sample - so an archived pre-column
        // ledger cleared `MIN_SAMPLES` on its first row and handed
        // `oracle-backtest` (which opens READ-ONLY by design, so it can
        // never take the ALTER) verdicts, reaps, carry rates and skip
        // counts computed from the very evidence the migration retired.
        // Over-stating the legacy share can only ask for more fresh
        // evidence, never license a verdict, which is the safe direction
        // here for the same reason it is in the stamp.
        let cols = if db
            .prepare("SELECT legacy FROM oracle LIMIT 0")
            .map(|_| ())
            .is_ok()
        {
            "SELECT backbone, family, bucket, hits, misses, legacy FROM oracle"
        } else {
            "SELECT backbone, family, bucket, hits, misses, hits + misses FROM oracle"
        };
        let mut stmt = db.prepare(cols)?;
        let rows: Vec<((String, String, u8), (u64, u64), u64)> = stmt
            .query_map([], |r| {
                Ok((
                    (r.get(0)?, r.get(1)?, r.get::<_, i64>(2)? as u8),
                    (r.get::<_, i64>(3)? as u64, r.get::<_, i64>(4)? as u64),
                    r.get::<_, i64>(5)?.max(0) as u64,
                ))
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut snap = Snapshot::default();
        for (key, counts, legacy) in rows {
            if legacy > 0 {
                snap.legacy.insert(key.clone(), legacy);
            }
            snap.cells.insert(key, counts);
        }
        Ok(snap)
    }

    pub fn is_empty(&self) -> bool {
        self.cells.is_empty()
    }

    /// Test/seed helper.
    pub fn insert(&mut self, backbone: &str, family: &str, bucket: u8, hits: u64, misses: u64) {
        self.cells
            .insert((backbone.into(), family.into(), bucket), (hits, misses));
    }

    /// Samples in one cell that are NOT migrated article evidence - what
    /// [`MIN_SAMPLES`] counts. See `rescale_article_counts`: the
    /// migrated lean shapes the Wilson interval but must never be what
    /// carries a cell over the evidence bar, or one fresh release
    /// re-arms a verdict built from tens of thousands of correlated
    /// article outcomes.
    fn fresh(&self, key: &(String, String, u8)) -> u64 {
        let n = self.cells.get(key).map(|(h, m)| h + m).unwrap_or(0);
        n.saturating_sub(self.legacy.get(key).copied().unwrap_or(0))
    }

    /// (hits, misses) evidence for one backbone × release: the exact
    /// (family, bucket) cell when it holds enough samples, else the
    /// backbone's whole-bucket aggregate across families (retention and
    /// takedown waves are mostly family-agnostic; the fallback keeps
    /// verdicts usable while family cells are thin).
    /// Returns (hits, misses, fresh samples): the third is what the
    /// caller must test against [`MIN_SAMPLES`], because a cell can be
    /// wide and still be nothing but migrated article lean.
    fn evidence(&self, backbone: &str, family: &str, bucket: u8) -> (u64, u64, u64) {
        let key = (backbone.to_string(), family.to_string(), bucket);
        let exact = self.cells.get(&key).copied().unwrap_or((0, 0));
        let exact_fresh = self.fresh(&key);
        if exact_fresh >= MIN_SAMPLES {
            return (exact.0, exact.1, exact_fresh);
        }
        let mut agg = (0u64, 0u64);
        let mut agg_legacy = 0u64;
        for ((b, f, k), (h, m)) in &self.cells {
            if b == backbone && *k == bucket {
                agg.0 += h;
                agg.1 += m;
                agg_legacy += self
                    .legacy
                    .get(&(b.clone(), f.clone(), *k))
                    .copied()
                    .unwrap_or(0);
            }
        }
        (agg.0, agg.1, (agg.0 + agg.1).saturating_sub(agg_legacy))
    }

    /// M29 3d takedown fingerprint: content families whose FRESH posts
    /// (≤7 days) are confidently unavailable on the user's backbones.
    ///
    /// Retention can't expire a week-old post, so "fresh AND gone" is the
    /// signature of an active takedown wave reaping a group - as opposed
    /// to the slow, age-driven loss that retention limits cause on old
    /// posts. The wall surfaces these as "this group is being reaped".
    ///
    /// Deliberately uses EXACT (backbone, family, fresh-bucket) cells,
    /// never the cross-family aggregate fallback: a single heavily-reaped
    /// family must not drag its neighbours' verdicts down. Evidence is
    /// summed across the enabled backbones - if fresh posts of a family
    /// are gone everywhere the user can reach, it is being reaped. Sorted
    /// most-reaped (by miss weight) first.
    pub fn reaped_families(&self, backbones: &[String]) -> Vec<Reaped> {
        if backbones.is_empty() {
            return Vec::new();
        }
        // Distinct families present in the ledger.
        let mut fams: Vec<&str> = self.cells.keys().map(|(_, f, _)| f.as_str()).collect();
        fams.sort_unstable();
        fams.dedup();
        let mut out: Vec<Reaped> = Vec::new();
        for fam in fams {
            // Fresh buckets only (0 = 0-1d, 1 = 1-7d).
            let mut best: Option<Reaped> = None;
            for b in [0u8, 1u8] {
                let (mut h, mut m) = (0u64, 0u64);
                let mut legacy = 0u64;
                for bb in backbones {
                    let key = (bb.clone(), fam.to_string(), b);
                    if let Some((hh, mm)) = self.cells.get(&key) {
                        h += *hh;
                        m += *mm;
                        legacy += self.legacy.get(&key).copied().unwrap_or(0);
                    }
                }
                let n = h + m;
                // Fresh samples only. Summing across backbones is what
                // makes this the widest of the four gates: two migrated
                // all-miss cells alone reach 22 article-counted samples
                // and would have named a family reaped with no fresh
                // evidence at all.
                if n.saturating_sub(legacy) < MIN_SAMPLES {
                    continue; // too thin to call a reap
                }
                let (_lo, hi) = wilson(h, n);
                if hi <= RED_HIGH {
                    // Confidently gone. Keep the bucket with the most
                    // misses (the strongest evidence of the wave).
                    let cand = Reaped {
                        family: fam.to_string(),
                        bucket: b,
                        hits: h,
                        misses: m,
                    };
                    if best
                        .as_ref()
                        .map(|r| cand.misses > r.misses)
                        .unwrap_or(true)
                    {
                        best = Some(cand);
                    }
                }
            }
            if let Some(r) = best {
                out.push(r);
            }
        }
        out.sort_by(|a, b| b.misses.cmp(&a.misses).then(a.family.cmp(&b.family)));
        out
    }

    /// M29 opt-in routing: is `backbone` confidently unable to serve
    /// `family` at `age_days`? True only when that ONE backbone's EXACT
    /// (backbone, family, bucket) cell is red with confidence (Wilson
    /// upper ≤ [`RED_HIGH`], ≥ [`MIN_SAMPLES`] samples).
    ///
    /// Deliberately NOT the cross-family aggregate fallback `verdict` may
    /// use: routing must never write off a server for a family it might
    /// still carry just because a *different* family is being reaped on
    /// that backbone. A blind spot (thin exact cell) is never "gone" - it
    /// is kept. Powers the daemon's `oracle_route` demotion of
    /// known-doomed primary attempts to the end of the level ladder.
    pub fn backbone_gone(&self, backbone: &str, family: &str, age_days: u32) -> bool {
        let bucket = age_bucket(age_days);
        let fam = {
            let f = family.trim();
            if f.is_empty() { "misc" } else { f }
        };
        let key = (backbone.to_string(), fam.to_string(), bucket);
        let (h, m) = self.cells.get(&key).copied().unwrap_or((0, 0));
        // FRESH samples, not the raw count: migrated article evidence
        // was scaled to one under the bar precisely so it could not
        // steer routing, and counting it here let a single all-hit
        // release push a legacy cell back over the line and be read as
        // proof the backbone was gone.
        if self.fresh(&key) < MIN_SAMPLES {
            return false; // blind spot - never skip on no evidence
        }
        let (_lo, hi) = wilson(h, h + m);
        hi <= RED_HIGH
    }

    /// Soft scheduling signal (A8 gap-fill): the measured hit fraction
    /// of this EXACT cell when it holds enough samples. None = a blind
    /// spot - callers must treat it as unknown, never as gone: the
    /// ledger measures BODY availability (STAT), while indexing needs
    /// headers, so this may only ever RANK candidates, not skip them.
    pub fn carry_rate(&self, backbone: &str, family: &str, bucket: u8) -> Option<f64> {
        let key = (backbone.to_string(), family.to_string(), bucket);
        let (h, m) = self.cells.get(&key).copied().unwrap_or((0, 0));
        if self.fresh(&key) < MIN_SAMPLES {
            return None;
        }
        Some(h as f64 / (h + m) as f64)
    }

    /// Raw (hits, misses) of one EXACT cell, no thresholds applied.
    /// Diagnostics only: the scoreboard prints the counts a verdict was
    /// computed from, because the M29 failure mode is a cell whose
    /// counts are enormous and correlated, which no rate can show.
    pub fn cell(&self, backbone: &str, family: &str, bucket: u8) -> Option<(u64, u64)> {
        self.cells
            .get(&(backbone.to_string(), family.to_string(), bucket))
            .copied()
    }

    /// Every cell as (backbone, family, bucket, hits, misses). The
    /// ledger is tiny by construction, so the scoreboard enumerates it
    /// to find the cells routing actually has evidence in.
    pub fn iter_cells(&self) -> impl Iterator<Item = (&str, &str, u8, u64, u64)> {
        self.cells
            .iter()
            .map(|((b, f, k), (h, m))| (b.as_str(), f.as_str(), *k, *h, *m))
    }

    /// Predicted verdict for a release in `family`, `age_days` old, given
    /// the user's enabled backbones. None = ledger too thin to say.
    pub fn verdict(&self, backbones: &[String], family: &str, age_days: u32) -> Option<Verdict> {
        if backbones.is_empty() {
            return None;
        }
        let bucket = age_bucket(age_days);
        let fam = {
            let f = family.trim();
            if f.is_empty() { "misc" } else { f }
        };
        let mut informed = 0usize;
        let mut best_low = 0.0f64;
        let mut best_high = 0.0f64;
        for b in backbones {
            let (h, m, fresh) = self.evidence(b, fam, bucket);
            let n = h + m;
            if fresh < MIN_SAMPLES {
                continue; // this backbone is a blind spot
            }
            informed += 1;
            let (low, high) = wilson(h, n);
            best_low = best_low.max(low);
            best_high = best_high.max(high);
        }
        if informed == 0 {
            return None;
        }
        // Green: some enabled backbone is confidently near-complete.
        if best_low >= GREEN_LOW {
            return Some(Verdict::Ok);
        }
        // Red: every enabled backbone is measured, and even the best is
        // confidently poor. Any blind spot demotes to amber, never red -
        // an untested server might still carry the post.
        if informed == backbones.len() && best_high <= RED_HIGH {
            return Some(Verdict::Gone);
        }
        Some(Verdict::Maybe)
    }
}

/// Minimum samples in a cell before it counts as evidence.
///
/// Public so the backtest scoreboard (`nzbfast oracle-backtest`) can
/// print the thresholds a run was measured against: these three numbers
/// ARE the tuning surface, and none of them moves without a run of it.
pub const MIN_SAMPLES: u64 = 12;
/// Green requires the Wilson 95% lower bound of the best backbone's
/// hit-rate at or above this (the M29 gate wants ≥95% green precision).
pub const GREEN_LOW: f64 = 0.95;
/// Red requires the Wilson upper bound of the BEST backbone at or below
/// this - confidently gone everywhere the user can reach.
pub const RED_HIGH: f64 = 0.60;

/// Wilson 95% score interval for `hits` successes in `n` trials.
///
/// Public for the backtest scoreboard: a cell's verdict is the interval,
/// not the point estimate, so a report that printed only hits/(hits+m)
/// would not show why a cell was called red.
pub fn wilson(hits: u64, n: u64) -> (f64, f64) {
    if n == 0 {
        return (0.0, 1.0);
    }
    const Z: f64 = 1.96;
    let n_f = n as f64;
    let p = hits as f64 / n_f;
    let z2 = Z * Z;
    let denom = 1.0 + z2 / n_f;
    let center = p + z2 / (2.0 * n_f);
    let spread = Z * (p * (1.0 - p) / n_f + z2 / (4.0 * n_f * n_f)).sqrt();
    (
        ((center - spread) / denom).max(0.0),
        ((center + spread) / denom).min(1.0),
    )
}

/// M29 3d: one content family caught in a takedown wave (fresh posts
/// confidently gone). `bucket` is the fresh age-bucket the reap was
/// strongest in; `hits`/`misses` are the summed evidence there.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Reaped {
    pub family: String,
    pub bucket: u8,
    pub hits: u64,
    pub misses: u64,
}

/// Wall verdict: predicted "will this complete on your providers".
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Verdict {
    /// Green: predicted complete on ≥1 enabled backbone, high confidence.
    Ok,
    /// Amber: mixed/thin evidence.
    Maybe,
    /// Red: confidently unavailable on every enabled backbone.
    Gone,
}

impl Verdict {
    /// API string ("ok"/"maybe"/"gone") - the wall's JSON vocabulary.
    pub fn as_str(&self) -> &'static str {
        match self {
            Verdict::Ok => "ok",
            Verdict::Maybe => "maybe",
            Verdict::Gone => "gone",
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A takedown-flavoured miss (the server said REMOVED) counts as
    /// two misses in the drained ratio, a bare 430 as one - so the same
    /// mixed cell drains with more miss weight when the removals were
    /// explicit. Conservative by construction: the per-job clamp still
    /// bounds the cell at JOB_SAMPLE_WEIGHT, an all-miss cell is
    /// all-miss either way, and a plain miss keeps exactly the weight
    /// it always had (no flavour = no evidence, most backbones never
    /// name the reason).
    #[test]
    fn a_takedown_miss_outweighs_a_bare_one_in_the_drained_ratio() {
        let drain_mixed = |takedown: bool| {
            let sink = OracleSink::default();
            sink.set_context(vec!["news.a.example".into()], "alt".into());
            for _ in 0..6 {
                sink.hit(0, 10);
            }
            for _ in 0..2 {
                if takedown {
                    sink.miss_takedown(0, 10);
                } else {
                    sink.miss(0, 10);
                }
            }
            let s = sink.drain();
            assert_eq!(s.len(), 1);
            s.into_iter().next().unwrap()
        };
        let plain = drain_mixed(false);
        let flagged = drain_mixed(true);
        assert!(
            flagged.misses > plain.misses,
            "explicit removals must weigh heavier: plain {plain:?} vs flagged {flagged:?}"
        );
        assert_eq!(
            flagged.hits + flagged.misses,
            JOB_SAMPLE_WEIGHT,
            "the per-job clamp still bounds the flavoured cell"
        );
        // An all-miss cell is all-miss whatever the flavour.
        let sink = OracleSink::default();
        sink.set_context(vec!["news.a.example".into()], "alt".into());
        for _ in 0..4 {
            sink.miss_takedown(0, 10);
        }
        let s = sink.drain();
        assert_eq!(s[0].hits, 0);
        assert_eq!(s[0].misses, JOB_SAMPLE_WEIGHT.min(8));
    }

    #[test]
    fn backbone_normalization() {
        // Reseller aliases cluster under the backbone SPOOL.
        assert_eq!(backbone_of("news.usenetserver.com"), "highwinds");
        assert_eq!(backbone_of("news2.newshosting.com"), "highwinds");
        assert_eq!(backbone_of("secure.easynews.com"), "highwinds");
        assert_eq!(backbone_of("usenetexpress.com"), "usenetexpress");
        assert_eq!(backbone_of("news.newsdemon.com"), "usenetexpress");
        assert_eq!(backbone_of("reader.abavia.com"), "abavia");
        assert_eq!(backbone_of("news.giganews.com"), "giganews");
        assert_eq!(backbone_of("news.supernews.com"), "giganews");
        // Digit/dash stripping on the brand label.
        assert_eq!(backbone_of("news2.blocknews.net"), "netnews");
        assert_eq!(backbone_of("ssl-eu.astraweb.com"), "highwinds");
        // Unknown host keys under its own normalized label.
        assert_eq!(backbone_of("nntp.futureprovider.io"), "futureprovider");
        // Port and case are irrelevant; two-part TLDs resolve the brand.
        assert_eq!(backbone_of("News.Eweka.NL:563"), "eweka");
        assert_eq!(backbone_of("news.provider.co.uk"), "provider");
        // Bare hostname (mock servers, LAN) is its own key.
        assert_eq!(backbone_of("localhost"), "localhost");
        // IPs degrade to a stable (if opaque) key - mock/LAN only.
        assert_eq!(backbone_of("127.0.0.1"), "0");
    }

    /// The point of the 20 Aug 2026 split: takedowns propagate within a
    /// SPOOL, so Omicron Media's three spools must never share a key.
    /// Highwinds answers DMCA notices while Eweka and Base-IP answer
    /// Dutch NTD ones, so "gone on Highwinds" is not evidence about the
    /// other two - and a user holding one of each has THREE independent
    /// opinions, which is what `whyslow` and `census` count.
    #[test]
    fn omicron_owns_three_distinct_spools() {
        let highwinds = backbone_of("news.newshosting.com");
        let eweka = backbone_of("news.eweka.nl");
        let baseip = backbone_of("news.tweaknews.eu");
        assert_eq!(highwinds, "highwinds");
        assert_eq!(eweka, "eweka");
        assert_eq!(baseip, "baseip");
        let distinct: std::collections::HashSet<&String> =
            [&highwinds, &eweka, &baseip].into_iter().collect();
        assert_eq!(distinct.len(), 3, "one owner, three spools, three keys");
        // Every brand on a spool lands on that spool's key, and the old
        // `omicron` key is gone from the table entirely.
        for h in [
            "news.usenetserver.com",
            "secure.easynews.com",
            "news.newsgroupninja.com",
            "ssl.astraweb.com",
        ] {
            assert_eq!(backbone_of(h), "highwinds", "{h}");
        }
        for h in [
            "news.xlned.com",
            "news.sunnyusenet.com",
            "news.pureusenet.nl",
            "news.usenetbucket.com",
            "news.base-ip.net",
        ] {
            assert_eq!(backbone_of(h), "baseip", "{h}");
        }
        assert!(
            !BACKBONE_ALIASES.iter().any(|(_, bb)| *bb == "omicron"),
            "`omicron` is an owner, not a spool - it must not be a key"
        );
    }

    /// Brands this table used to put on the wrong spool. Each was
    /// re-checked against the 2026 public backbone maps; see
    /// [`BACKBONE_ALIASES`] for the sources.
    #[test]
    fn corrected_brand_assignments() {
        // ViperNews (operator Uzo Reto) is its own NTD backbone, not a
        // UsenetExpress reseller.
        assert_eq!(backbone_of("news.vipernews.com"), "vipernews");
        assert_eq!(backbone_of("news.viper.com"), "vipernews");
        assert_ne!(backbone_of("news.vipernews.com"), "usenetexpress");
        // XS News is Abavia's own brand; HitNews rides Abavia too.
        assert_eq!(backbone_of("news.xsnews.nl"), "abavia");
        assert_eq!(backbone_of("news.hitnews.com"), "abavia");
        // UsenetBucket is Base-IP, not Abavia.
        assert_eq!(backbone_of("news.usenetbucket.com"), "baseip");
        // BlockNews resells Netnews; it is not a backbone.
        assert_eq!(backbone_of("news.blocknews.net"), "netnews");
        // usenet.farm reduces to the TLD-ish label `farm` without its
        // alias, because ".farm" is too long for the TLD tail rule.
        assert_eq!(backbone_of("news.usenet.farm"), "usenetfarm");
        assert_eq!(backbone_of("usenet.farm"), "usenetfarm");
        // Sources disagree on these two, so they stay UNCLUSTERED - a
        // missing cluster only slows learning, a wrong one fabricates
        // agreement between spools that do not share takedowns.
        assert_eq!(backbone_of("news.fastusenet.org"), "fastusenet");
        assert_eq!(backbone_of("news.frugalusenet.com"), "frugalusenet");
    }

    /// Every alias VALUE must be a fixed point: `backbone_of` is applied
    /// to raw hosts at ingest and to the folded sample's host again, so
    /// a value that itself aliased elsewhere would key a cell nothing
    /// ever reads. (It also catches a typo'd value silently becoming a
    /// backbone of its own.)
    #[test]
    fn alias_values_are_fixed_points() {
        for (alias, bb) in BACKBONE_ALIASES {
            assert_eq!(
                backbone_of(&format!("news.{bb}.com")),
                *bb,
                "alias {alias} points at {bb}, which is not a fixed point"
            );
        }
    }

    /// The suggestion door: a listed brand is a name worth offering the
    /// user, and everything else is not. The ledger is happy to key a
    /// LAN box under "localhost"; the server editor must never propose
    /// that as a provider network.
    #[test]
    fn only_a_listed_backbone_is_worth_suggesting() {
        assert_eq!(known_backbone_of("news.eweka.nl").as_deref(), Some("eweka"));
        assert_eq!(
            known_backbone_of("News.Newshosting.com:563").as_deref(),
            Some("highwinds")
        );
        // Resellers suggest their SPOOL, which is the name that means
        // "these two share takedowns" - Astraweb retired its own spool
        // onto Highwinds, so that is the network worth offering.
        assert_eq!(
            known_backbone_of("ssl-eu.astraweb.com").as_deref(),
            Some("highwinds")
        );
        // Identity entries in the table count: an independent that is
        // its own backbone is still a name two of its hostnames share.
        assert_eq!(
            known_backbone_of("reader.abavia.com").as_deref(),
            Some("abavia")
        );
        // Unlisted, LAN and IP hosts key under their own label, which is
        // a ledger key and not a network name.
        assert_eq!(known_backbone_of("nntp.futureprovider.io"), None);
        assert_eq!(known_backbone_of("localhost"), None);
        assert_eq!(known_backbone_of("127.0.0.1"), None);
        assert_eq!(known_backbone_of(""), None);
    }

    #[test]
    fn family_normalization() {
        assert_eq!(group_family("alt.binaries.teevee"), "teevee");
        assert_eq!(group_family("alt.binaries.hdtv.x264"), "hdtv");
        assert_eq!(group_family("a.b.moovee"), "moovee");
        assert_eq!(group_family("alt.binaries.movies.divx"), "movies");
        assert_eq!(group_family("free.pt"), "free");
        assert_eq!(group_family(""), "misc");
        assert_eq!(group_family("ALT.BINARIES.TEEVEE"), "teevee");
    }

    #[test]
    fn bucket_boundaries() {
        assert_eq!(age_bucket(0), 0);
        assert_eq!(age_bucket(1), 0);
        assert_eq!(age_bucket(2), 1);
        assert_eq!(age_bucket(7), 1);
        assert_eq!(age_bucket(8), 2);
        assert_eq!(age_bucket(30), 2);
        assert_eq!(age_bucket(31), 3);
        assert_eq!(age_bucket(90), 3);
        assert_eq!(age_bucket(91), 4);
        assert_eq!(age_bucket(365), 4);
        assert_eq!(age_bucket(366), 5);
        assert_eq!(age_bucket(1095), 5);
        assert_eq!(age_bucket(1096), 6);
        assert_eq!(age_bucket(u32::MAX), 6);
        for b in 0..N_BUCKETS {
            assert!(!bucket_label(b).is_empty());
        }
    }

    #[test]
    fn sink_accumulates_and_drains() {
        let sink = OracleSink::default();
        sink.set_context(
            vec!["news.eweka.nl".into(), "news.blocknews.net".into()],
            "teevee".into(),
        );
        sink.hit(0, 3); // eweka, bucket 1
        sink.hit(0, 3);
        sink.miss(0, 3);
        sink.miss(1, 400); // blocknews, bucket 5
        sink.hit(9, 3); // unknown server index → dropped
        let mut s = sink.drain();
        s.sort_by(|a, b| a.host.cmp(&b.host));
        assert_eq!(
            s,
            vec![
                Sample {
                    host: "news.blocknews.net".into(),
                    family: "teevee".into(),
                    bucket: 5,
                    hits: 0,
                    misses: 1
                },
                Sample {
                    host: "news.eweka.nl".into(),
                    family: "teevee".into(),
                    bucket: 1,
                    hits: 2,
                    misses: 1
                },
            ]
        );
        // Drain empties.
        assert!(sink.drain().is_empty());
    }

    /// A real download is thousands of correlated articles, not
    /// thousands of independent trials: whatever its size, one job
    /// contributes at most [`JOB_SAMPLE_WEIGHT`] to a cell, and the
    /// hit/miss ratio it measured survives the clamp.
    #[test]
    fn drain_bounds_one_job_to_a_release_sized_sample() {
        let sink = OracleSink::default();
        sink.set_context(vec!["news.eweka.nl".into()], "hdtv".into());
        // The shape that poisoned the live (hdtv, 7-30d) cell: a 15,000
        // segment posting that is simply gone from this backbone.
        for _ in 0..15_000 {
            sink.miss(0, 20);
        }
        let s = sink.drain();
        assert_eq!(s.len(), 1);
        assert_eq!(
            (s[0].hits, s[0].misses),
            (0, JOB_SAMPLE_WEIGHT),
            "a wholly-missing release is one all-miss sample, not 15,000"
        );

        // A three-quarters-carried release keeps its ratio.
        let sink = OracleSink::default();
        sink.set_context(vec!["news.eweka.nl".into()], "hdtv".into());
        for _ in 0..9_000 {
            sink.hit(0, 20);
        }
        for _ in 0..3_000 {
            sink.miss(0, 20);
        }
        let s = sink.drain();
        assert_eq!(s.len(), 1);
        assert_eq!(s[0].hits + s[0].misses, JOB_SAMPLE_WEIGHT);
        assert_eq!(
            (s[0].hits, s[0].misses),
            (4, 1),
            "0.75 of 5 rounds to 4 hits, not to a wiped-out miss"
        );

        // Ten thousand articles across two buckets are TWO cells, each
        // separately bounded - the clamp is per cell, as ingest is.
        let sink = OracleSink::default();
        sink.set_context(vec!["news.eweka.nl".into()], "hdtv".into());
        for _ in 0..5_000 {
            sink.hit(0, 3); // bucket 1
            sink.miss(0, 20); // bucket 2
        }
        let s = sink.drain();
        assert_eq!(s.len(), 2);
        assert!(s.iter().all(|x| x.hits + x.misses == JOB_SAMPLE_WEIGHT));

        // A cell under the weight is untouched - the sampler's own
        // 5-STAT probes must pass through exactly as measured.
        let sink = OracleSink::default();
        sink.set_context(vec!["news.eweka.nl".into()], "hdtv".into());
        sink.hit(0, 20);
        sink.miss(0, 20);
        let s = sink.drain();
        assert_eq!((s[0].hits, s[0].misses), (1, 1));
    }

    /// The clamp's edges: it never invents evidence in either
    /// direction, and never exceeds the weight.
    #[test]
    fn clamp_weight_edges() {
        assert_eq!(clamp_weight(0, 0, 5), (0, 0));
        assert_eq!(clamp_weight(3, 1, 5), (3, 1)); // under weight, verbatim
        assert_eq!(clamp_weight(0, 99_999, 5), (0, 5)); // all miss stays all miss
        assert_eq!(clamp_weight(99_999, 0, 5), (5, 0)); // all hit stays all hit
        assert_eq!(clamp_weight(50, 50, 5), (3, 2)); // half rounds up
        // A vanishing minority rounds away, but only to the side it was
        // already on - it can never flip the cell's lean.
        assert_eq!(clamp_weight(1, 99_999, 5), (0, 5));
        assert_eq!(clamp_weight(99_999, 1, 5), (5, 0));
        // Absurd counts do not wrap, and weight 0 is a no-op guard.
        assert_eq!(clamp_weight(u64::MAX / 2, u64::MAX / 2, 5), (3, 2));
        assert_eq!(clamp_weight(7, 7, 0), (7, 7));
    }

    /// The migration off article-counted cells: every pre-existing cell
    /// must land under the evidence bar (so routing stops consulting it
    /// at once), keep the lean it was measured with, and run once.
    #[cfg(feature = "indexer")]
    #[test]
    fn rescale_drops_legacy_cells_under_the_evidence_bar() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        // Seed AROUND both migration flags ensure_schema just set, as
        // an upgrade from the article-counted era would have on disk: a
        // ledger from that era has taken neither the rescale nor the
        // legacy stamp.
        db.execute(
            "DELETE FROM kv WHERE k IN ('oracle_release_weight_v1', 'oracle_legacy_stamp_v1')",
            [],
        )
        .unwrap();
        let seed = |bb: &str, fam: &str, bucket: u8, h: i64, m: i64| {
            db.execute(
                "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
                 VALUES(?1, ?2, ?3, ?4, ?5, 1)",
                rusqlite::params![bb, fam, bucket, h, m],
            )
            .unwrap();
        };
        // The measured live cell that started this: 2871/57071 on
        // (eweka, hdtv, 7-30d), Wilson upper 0.0496 - two releases.
        // (Recorded against `omicron` at the time; that key was retired
        // when the table split into per-spool keys, and the Eweka half
        // of it is the part `news.eweka.nl` below keeps feeding.)
        seed("eweka", "hdtv", 2, 2871, 57071);
        // A wholly-missing cell, a healthy cell, and one already thin.
        seed("giganews", "hdtv", 2, 0, 15_263);
        seed("baseip", "moovee", 0, 3205, 0);
        seed("abavia", "teevee", 1, 2, 1);

        ensure_schema(&db).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        let cell = |bb: &str, fam: &str, b: u8| {
            *snap
                .cells
                .get(&(bb.to_string(), fam.to_string(), b))
                .expect("cell survives the migration")
        };

        // NOTHING is above the bar any more, so backbone_gone and
        // carry_rate go quiet on every migrated cell.
        for ((bb, fam, b), (h, m)) in &snap.cells {
            assert!(
                h + m < MIN_SAMPLES,
                "({bb},{fam},{b}) = {h}/{m} still counts as evidence"
            );
        }
        assert!(!snap.backbone_gone("eweka", "hdtv", 20));
        assert!(!snap.backbone_gone("giganews", "hdtv", 20));
        assert_eq!(snap.carry_rate("eweka", "hdtv", 2), None);

        // The lean survives: a miss-dominated cell stays miss-leaning,
        // a 100%-miss cell stays 100% miss, a clean cell stays clean.
        let (h, m) = cell("eweka", "hdtv", 2);
        assert!(m > h, "{h}/{m} lost the miss lean it was measured with");
        assert_eq!(cell("giganews", "hdtv", 2), (0, 11));
        assert_eq!(cell("baseip", "moovee", 0), (11, 0));
        // Already under the target - untouched, not inflated to 11.
        assert_eq!(cell("abavia", "teevee", 1), (2, 1));

        // One-shot: fresh post-migration evidence is NOT re-squashed by
        // a later open.
        let s = |host: &str, hits, misses| Sample {
            host: host.into(),
            family: "hdtv".into(),
            bucket: 2,
            hits,
            misses,
        };
        for _ in 0..4 {
            ingest(&db, &[s("news.eweka.nl", 4, 1)], 300).unwrap();
        }
        ensure_schema(&db).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        let (h, m) = *snap.cells.get(&("eweka".into(), "hdtv".into(), 2)).unwrap();
        assert_eq!(
            h + m,
            11 + 20,
            "the migration must not re-run over new release-weighted evidence"
        );
    }

    /// The migration scaled a legacy cell to one sample UNDER the bar,
    /// and one healthy release is worth five - so the first fresh
    /// evidence that a backbone serves a family perfectly used to carry
    /// the cell back over [`MIN_SAMPLES`] at `(5, 11)`, whose Wilson
    /// upper bound of 0.556 reads as "confidently gone". Positive
    /// evidence must never re-arm a verdict, and the dozen fresh samples
    /// the migration promises must actually be a dozen.
    #[cfg(feature = "indexer")]
    #[test]
    fn one_healthy_release_does_not_reanimate_a_legacy_all_miss_cell() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        // Seed AROUND both flags, as an upgrade from the
        // article-counted era would have on disk: 15,263 correlated
        // article misses, and neither migration taken.
        db.execute(
            "DELETE FROM kv WHERE k IN ('oracle_release_weight_v1', 'oracle_legacy_stamp_v1')",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
             VALUES('giganews', 'hdtv', 2, 0, 15263, 1)",
            [],
        )
        .unwrap();
        ensure_schema(&db).unwrap();

        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("giganews", "hdtv", 2), Some((0, 11)));
        assert!(!snap.backbone_gone("giganews", "hdtv", 20));

        // ONE fully healthy release - the idle sampler's entire per-tick
        // budget at the default 300/h, or one clean download.
        let probe = |hits, misses| Sample {
            host: "news.giganews.com".into(),
            family: "hdtv".into(),
            bucket: 2,
            hits,
            misses,
        };
        ingest(&db, &[probe(JOB_SAMPLE_WEIGHT, 0)], 300).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("giganews", "hdtv", 2), Some((5, 11)));
        // The arithmetic that made this a defect rather than a rounding
        // quibble: the interval itself really is red at (5, 16).
        assert!(wilson(5, 16).1 <= RED_HIGH);
        assert!(
            !snap.backbone_gone("giganews", "hdtv", 20),
            "one all-hit release must not re-arm 15,263 legacy article misses"
        );
        assert_eq!(snap.carry_rate("giganews", "hdtv", 2), None);

        // A dozen fresh samples DO license a verdict again - the gate is
        // "count only fresh evidence", not "never speak of this cell".
        for _ in 0..3 {
            ingest(&db, &[probe(0, JOB_SAMPLE_WEIGHT)], 400).unwrap();
        }
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("giganews", "hdtv", 2), Some((5, 26)));
        assert!(
            snap.backbone_gone("giganews", "hdtv", 20),
            "20 fresh samples are the evidence the migration asked for"
        );
    }

    /// The rescale shipped a release before the `legacy` column did, so
    /// the ledgers that matter most - the ones already carrying migrated
    /// lean - reach this code with the v1 flag set and nothing marked.
    /// One shared flag declared them migrated and skipped the stamp for
    /// good, leaving the reanimation above live on exactly the daemons
    /// that had already upgraded once.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_ledger_that_already_rescaled_still_gets_its_legacy_stamp() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        // The on-disk shape after the first migration and before this
        // one: counts already scaled to the target, `legacy` never
        // written, the rescale's flag set.
        db.execute(
            "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at, legacy)
             VALUES('giganews', 'hdtv', 2, 0, 11, 1, 0)",
            [],
        )
        .unwrap();
        db.execute("DELETE FROM kv WHERE k='oracle_legacy_stamp_v1'", [])
            .unwrap();
        db.execute(
            "INSERT OR REPLACE INTO kv(k, v) VALUES('oracle_release_weight_v1', '1')",
            [],
        )
        .unwrap();
        ensure_schema(&db).unwrap();

        // Stamped, and NOT rescaled a second time.
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("giganews", "hdtv", 2), Some((0, 11)));
        let probe = |hits, misses| Sample {
            host: "news.giganews.com".into(),
            family: "hdtv".into(),
            bucket: 2,
            hits,
            misses,
        };
        ingest(&db, &[probe(JOB_SAMPLE_WEIGHT, 0)], 300).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("giganews", "hdtv", 2), Some((5, 11)));
        assert!(
            !snap.backbone_gone("giganews", "hdtv", 20),
            "an already-rescaled ledger must get the same protection as a fresh one"
        );
    }

    /// A ledger opened READ-ONLY cannot take `ensure_schema`'s ALTER,
    /// so an archive predating the `legacy` column reaches the read path
    /// with the column absent and its counts still article-scaled.
    /// `oracle-backtest` opens the index that way on purpose, and its
    /// whole job is to score the ledger's own verdicts - so reading the
    /// missing column as "no legacy lean" handed it the article-counted
    /// evidence back as fresh release samples, and every verdict, reap,
    /// carry rate and skip count it printed came from evidence the
    /// migration had retired. Absent means ALL legacy.
    #[cfg(feature = "indexer")]
    #[test]
    fn a_pre_column_ledger_read_only_is_all_legacy_not_all_fresh() {
        let db = Connection::open_in_memory().unwrap();
        // The pre-column shape, by hand: `ensure_schema` would add the
        // column and stamp it, which is precisely what a read-only open
        // cannot do.
        db.execute_batch(
            "CREATE TABLE oracle(
                backbone TEXT NOT NULL,
                family TEXT NOT NULL,
                bucket INTEGER NOT NULL,
                hits INTEGER NOT NULL DEFAULT 0,
                misses INTEGER NOT NULL DEFAULT 0,
                updated_at INTEGER NOT NULL DEFAULT 0,
                PRIMARY KEY(backbone, family, bucket));",
        )
        .unwrap();
        // The measured live cell from the M29 postmortem, unmigrated:
        // two correlated releases, 57k article misses.
        db.execute(
            "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
             VALUES('highwinds', 'hdtv', 2, 2871, 57071, 1)",
            [],
        )
        .unwrap();
        db.execute(
            "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
             VALUES('giganews', 'hdtv', 2, 0, 15263, 1)",
            [],
        )
        .unwrap();

        let snap = Snapshot::load(&db).unwrap();
        // The lean is still there for the wall's amber...
        assert_eq!(snap.cell("highwinds", "hdtv", 2), Some((2871, 57071)));
        // ...but none of it is evidence a verdict may rest on.
        assert!(
            !snap.backbone_gone("highwinds", "hdtv", 20),
            "57k unmigrated article misses are not a dozen releases"
        );
        assert_eq!(snap.carry_rate("highwinds", "hdtv", 2), None);
        assert!(
            snap.reaped_families(&["highwinds".to_string(), "giganews".to_string()])
                .is_empty(),
            "an unmigrated ledger must not name a reaped family"
        );
    }

    /// `reaped_families` sums the exact cell across every enabled
    /// backbone before applying the evidence bar, so it reached a dozen
    /// samples soonest of all: two migrated all-miss cells alone were 22
    /// "samples" and named a family reaped with nothing fresh at all.
    #[cfg(feature = "indexer")]
    #[test]
    fn migrated_cells_alone_never_name_a_reaped_family() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        db.execute(
            "DELETE FROM kv WHERE k IN ('oracle_release_weight_v1', 'oracle_legacy_stamp_v1')",
            [],
        )
        .unwrap();
        for bb in ["giganews", "highwinds"] {
            db.execute(
                "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at)
                 VALUES(?1, 'warez', 1, 0, 9000, 1)",
                [bb],
            )
            .unwrap();
        }
        ensure_schema(&db).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        let bbs = vec!["giganews".to_string(), "highwinds".to_string()];
        assert!(
            snap.reaped_families(&bbs).is_empty(),
            "22 migrated article misses are not two dozen releases"
        );

        // Fresh evidence agreeing with the lean does license the call.
        for bb in ["news.giganews.com", "news.newshosting.com"] {
            for _ in 0..2 {
                ingest(
                    &db,
                    &[Sample {
                        host: bb.into(),
                        family: "warez".into(),
                        bucket: 1,
                        hits: 0,
                        misses: JOB_SAMPLE_WEIGHT,
                    }],
                    500,
                )
                .unwrap();
            }
        }
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(
            snap.reaped_families(&bbs).first().map(|r| r.family.clone()),
            Some("warez".to_string())
        );
    }

    /// One release probed against three resellers of ONE backbone is one
    /// observation of that release, not three. Eweka, UsenetServer and
    /// Newshosting are all Omicron: unfolded, a single missing posting
    /// arrived as three `(0, 5)` samples that ingest summed to `(0, 15)`,
    /// crossing [`MIN_SAMPLES`] and marking the whole backbone gone off
    /// one posting.
    #[cfg(feature = "indexer")]
    #[test]
    fn one_release_across_aliases_is_one_backbone_sample() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        let s = |host: &str| Sample {
            host: host.into(),
            family: "teevee".into(),
            bucket: 1,
            hits: 0,
            misses: JOB_SAMPLE_WEIGHT,
        };
        // ONE sampler tick: the same article ids against three
        // Highwinds resellers plus an unrelated backbone. Eweka would
        // NOT belong in this list - same owner, different spool.
        let tick = fold_by_backbone(
            &[
                s("news.usenetserver.com"),
                s("secure.easynews.com"),
                s("news.newshosting.com"),
                s("news.blocknews.net"),
            ],
            JOB_SAMPLE_WEIGHT,
        );
        assert_eq!(tick.len(), 2, "highwinds collapses, netnews stands alone");
        ingest(&db, &tick, 100).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("highwinds", "teevee", 1), Some((0, 5)));
        assert_eq!(snap.cell("netnews", "teevee", 1), Some((0, 5)));
        assert!(!snap.backbone_gone("highwinds", "teevee", 3));

        // Same owner, different spools: Omicron's three never fold.
        let three_spools = fold_by_backbone(
            &[
                s("news.newshosting.com"),
                s("news.eweka.nl"),
                s("news.tweaknews.eu"),
            ],
            JOB_SAMPLE_WEIGHT,
        );
        assert_eq!(three_spools.len(), 3, "one owner is not one spool");

        // Different buckets are different cells and never fold together.
        let two_buckets = fold_by_backbone(
            &[
                Sample {
                    bucket: 1,
                    ..s("secure.easynews.com")
                },
                Sample {
                    bucket: 5,
                    ..s("news.newshosting.com")
                },
            ],
            JOB_SAMPLE_WEIGHT,
        );
        assert_eq!(two_buckets.len(), 2);
    }

    /// The download path's twin: a doomed job takes a real 430 from
    /// every configured server, and each one is recorded against its own
    /// server index. The sink must hand the ledger one sample per cell.
    #[test]
    fn sink_folds_alias_servers_into_one_backbone_sample() {
        let sink = OracleSink::default();
        sink.set_context(
            vec![
                "secure.easynews.com".into(),
                "news.newshosting.com".into(),
                "news.usenetserver.com".into(),
                "news.blocknews.net".into(),
            ],
            "hdtv".into(),
        );
        for _ in 0..200 {
            for si in 0..4 {
                sink.miss(si, 20);
            }
        }
        let s = sink.drain();
        assert_eq!(s.len(), 2, "three Highwinds resellers are one cell: {s:?}");
        // Sorted by (host, bucket); the folded sample keeps the
        // alphabetically first raw host of its group.
        assert_eq!(s[0].host, "news.blocknews.net");
        assert_eq!(s[1].host, "news.newshosting.com");
        assert!(
            s.iter()
                .all(|x| (x.hits, x.misses) == (0, JOB_SAMPLE_WEIGHT)),
            "one job is one release-weighted sample per cell: {s:?}"
        );
    }

    /// The 20 Aug 2026 per-spool split, on a ledger written under the
    /// old keys: same-spool renames merge additively, and the one key
    /// that named THREE spools is dropped rather than guessed onto one.
    #[cfg(feature = "indexer")]
    #[test]
    fn retired_backbone_keys_are_remapped_or_dropped() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        // Pretend this ledger predates the split.
        db.execute("DELETE FROM kv WHERE k = 'oracle_spool_split_v1'", [])
            .unwrap();
        let seed = |bb: &str, fam: &str, b: u8, h: i64, m: i64, leg: i64| {
            db.execute(
                "INSERT INTO oracle(backbone, family, bucket, hits, misses, updated_at, legacy)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6, ?7)",
                rusqlite::params![bb, fam, b, h, m, 7, leg],
            )
            .unwrap();
        };
        // A rename with a collision: `blocknews` was always Netnews, so
        // the two rows are two batches of the same spool's evidence.
        seed("blocknews", "teevee", 1, 4, 1, 2);
        seed("netnews", "teevee", 1, 6, 3, 1);
        // A rename with no collision, and one on a different cell.
        seed("xsnews", "moovee", 0, 8, 2, 0);
        seed("astraweb", "hdtv", 3, 5, 5, 5);
        // The split key, and an innocent bystander.
        seed("omicron", "hdtv", 2, 30, 70, 11);
        seed("giganews", "hdtv", 2, 9, 1, 0);

        ensure_schema(&db).unwrap();
        let snap = Snapshot::load(&db).unwrap();

        // Merged additively - counts AND the legacy share.
        assert_eq!(snap.cell("netnews", "teevee", 1), Some((10, 4)));
        assert_eq!(
            snap.legacy
                .get(&("netnews".into(), "teevee".into(), 1))
                .copied(),
            Some(3)
        );
        assert_eq!(snap.cell("blocknews", "teevee", 1), None);
        // Re-keyed onto the spool they were always samples of.
        assert_eq!(snap.cell("abavia", "moovee", 0), Some((8, 2)));
        assert_eq!(snap.cell("highwinds", "hdtv", 3), Some((5, 5)));
        assert_eq!(snap.cell("xsnews", "moovee", 0), None);
        assert_eq!(snap.cell("astraweb", "hdtv", 3), None);
        // Unattributable: dropped, not spread across the three spools
        // and not guessed onto the busiest one.
        assert_eq!(snap.cell("omicron", "hdtv", 2), None);
        for bb in ["highwinds", "eweka", "baseip"] {
            assert_eq!(snap.cell(bb, "hdtv", 2), None, "{bb} inherited a guess");
        }
        // Everything else is untouched.
        assert_eq!(snap.cell("giganews", "hdtv", 2), Some((9, 1)));

        // One-shot, and re-running is a no-op: fresh Netnews evidence
        // is not re-merged or re-counted by a later open.
        ingest(
            &db,
            &[Sample {
                host: "news.blocknews.net".into(),
                family: "teevee".into(),
                bucket: 1,
                hits: 5,
                misses: 0,
            }],
            300,
        )
        .unwrap();
        ensure_schema(&db).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(snap.cell("netnews", "teevee", 1), Some((15, 4)));
    }

    #[cfg(feature = "indexer")]
    #[test]
    fn ledger_roundtrip_merges_backbones() {
        let db = Connection::open_in_memory().unwrap();
        ensure_schema(&db).unwrap();
        let s = |host: &str, hits, misses| Sample {
            host: host.into(),
            family: "teevee".into(),
            bucket: 1,
            hits,
            misses,
        };
        ingest(&db, &[s("news.newshosting.com", 10, 2)], 100).unwrap();
        // A different Highwinds reseller lands in the SAME cell.
        ingest(&db, &[s("news.usenetserver.com", 5, 1)], 200).unwrap();
        let snap = Snapshot::load(&db).unwrap();
        assert_eq!(
            snap.cells.get(&("highwinds".into(), "teevee".into(), 1)),
            Some(&(15, 3))
        );
        let at: i64 = db
            .query_row("SELECT updated_at FROM oracle", [], |r| r.get(0))
            .unwrap();
        assert_eq!(at, 200);
    }

    #[test]
    fn verdict_math() {
        let bbs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut snap = Snapshot::default();
        // Thin ledger → no verdict.
        assert_eq!(snap.verdict(&bbs(&["highwinds"]), "teevee", 3), None);
        snap.insert("highwinds", "teevee", 1, 5, 0); // < MIN_SAMPLES
        assert_eq!(snap.verdict(&bbs(&["highwinds"]), "teevee", 3), None);
        // Confident green: 200/200 → Wilson low ≈ 0.981.
        snap.insert("highwinds", "teevee", 1, 200, 0);
        assert_eq!(
            snap.verdict(&bbs(&["highwinds"]), "teevee", 3),
            Some(Verdict::Ok)
        );
        // Mixed → amber.
        snap.insert("highwinds", "teevee", 2, 60, 40);
        assert_eq!(
            snap.verdict(&bbs(&["highwinds"]), "teevee", 20),
            Some(Verdict::Maybe)
        );
        // Confident red on ALL enabled backbones.
        snap.insert("highwinds", "teevee", 6, 2, 98);
        assert_eq!(
            snap.verdict(&bbs(&["highwinds"]), "teevee", 2000),
            Some(Verdict::Gone)
        );
        // A blind-spot backbone demotes red to amber (never red).
        assert_eq!(
            snap.verdict(&bbs(&["highwinds", "abavia"]), "teevee", 2000),
            Some(Verdict::Maybe)
        );
        // But a blind spot does NOT demote green.
        assert_eq!(
            snap.verdict(&bbs(&["highwinds", "abavia"]), "teevee", 3),
            Some(Verdict::Ok)
        );
        // No backbones configured → no verdict.
        assert_eq!(snap.verdict(&[], "teevee", 3), None);
    }

    #[test]
    fn verdict_family_fallback() {
        let mut snap = Snapshot::default();
        // Nothing for "moovee" specifically, but the backbone's bucket
        // aggregate (via another family) is rich - fallback applies.
        snap.insert("highwinds", "teevee", 1, 300, 0);
        assert_eq!(
            snap.verdict(&["highwinds".to_string()], "moovee", 3),
            Some(Verdict::Ok)
        );
        // An exact family cell with enough samples wins over aggregate.
        snap.insert("highwinds", "warez", 1, 3, 30);
        assert_eq!(
            snap.verdict(&["highwinds".to_string()], "warez", 3),
            Some(Verdict::Gone)
        );
    }

    #[test]
    fn takedown_fingerprint() {
        let bbs = |v: &[&str]| v.iter().map(|s| s.to_string()).collect::<Vec<_>>();
        let mut snap = Snapshot::default();
        // "teevee" fresh posts (bucket 1) confidently gone → a reap.
        snap.insert("highwinds", "teevee", 1, 3, 97);
        // "moovee" fresh posts healthy → not reaped.
        snap.insert("highwinds", "moovee", 1, 200, 0);
        // "warez" is only gone in an OLD bucket (5 = 1-3y) → that's
        // retention expiry, NOT a takedown; must not be flagged.
        snap.insert("highwinds", "warez", 5, 2, 98);
        // "xxx" fresh misses but too few samples → not enough to call.
        snap.insert("highwinds", "xxx", 0, 1, 5);

        let reaped = snap.reaped_families(&bbs(&["highwinds"]));
        let fams: Vec<&str> = reaped.iter().map(|r| r.family.as_str()).collect();
        assert_eq!(fams, vec!["teevee"], "{reaped:?}");
        assert_eq!(reaped[0].bucket, 1);
        assert_eq!(reaped[0].misses, 97);

        // A blind spot backbone doesn't manufacture reaps, and an
        // unreachable backbone's evidence isn't summed in.
        assert!(snap.reaped_families(&bbs(&["abavia"])).is_empty());
        // No backbones → nothing.
        assert!(snap.reaped_families(&[]).is_empty());

        // Cross-family fallback must NOT leak: a thin fresh family in a
        // bucket dominated by another family's reap stays unflagged.
        snap.insert("highwinds", "thinfam", 1, 0, 2); // < MIN_SAMPLES
        let reaped = snap.reaped_families(&bbs(&["highwinds"]));
        assert!(
            reaped.iter().all(|r| r.family != "thinfam"),
            "aggregate fallback must not flag a thin family: {reaped:?}"
        );
    }

    #[test]
    fn backbone_gone_is_exact_and_conservative() {
        let mut snap = Snapshot::default();
        // highwinds/teevee/bucket1 confidently gone.
        snap.insert("highwinds", "teevee", 1, 3, 97);
        assert!(snap.backbone_gone("highwinds", "teevee", 3));
        // A different backbone with no data for this family: NOT gone.
        assert!(!snap.backbone_gone("abavia", "teevee", 3));
        // A different family on the same backbone/bucket: NOT gone (no
        // aggregate-fallback leak - routing must not skip on it).
        assert!(!snap.backbone_gone("highwinds", "moovee", 3));
        // A different age bucket: NOT gone.
        assert!(!snap.backbone_gone("highwinds", "teevee", 2000));
        // Thin evidence never counts as gone.
        snap.insert("highwinds", "warez", 0, 1, 5);
        assert!(!snap.backbone_gone("highwinds", "warez", 0));
        // A healthy cell is not gone.
        snap.insert("highwinds", "moovee", 1, 200, 0);
        assert!(!snap.backbone_gone("highwinds", "moovee", 3));
    }

    /// carry_rate is the A8 ranking signal: exact-cell only, None on a
    /// blind spot (it must rank, never skip), the plain hit fraction
    /// once a cell holds enough samples.
    #[test]
    fn carry_rate_is_exact_cell_only() {
        let mut snap = Snapshot::default();
        assert!(snap.is_empty());
        assert_eq!(snap.carry_rate("highwinds", "teevee", 1), None);
        snap.insert("highwinds", "teevee", 1, 3, 1); // < MIN_SAMPLES
        assert!(!snap.is_empty());
        assert_eq!(snap.carry_rate("highwinds", "teevee", 1), None);
        snap.insert("highwinds", "teevee", 1, 75, 25);
        assert_eq!(snap.carry_rate("highwinds", "teevee", 1), Some(0.75));
        // No cross-family or cross-bucket leakage.
        assert_eq!(snap.carry_rate("highwinds", "moovee", 1), None);
        assert_eq!(snap.carry_rate("highwinds", "teevee", 2), None);
        assert_eq!(snap.carry_rate("abavia", "teevee", 1), None);
    }

    /// The wall's JSON vocabulary is a stable three-word contract.
    #[test]
    fn verdict_api_strings() {
        assert_eq!(Verdict::Ok.as_str(), "ok");
        assert_eq!(Verdict::Maybe.as_str(), "maybe");
        assert_eq!(Verdict::Gone.as_str(), "gone");
    }

    /// An empty family string normalizes to "misc" on both verdict
    /// paths, so blank newsgroup metadata still keys a real cell.
    #[test]
    fn blank_family_reads_as_misc() {
        let mut snap = Snapshot::default();
        snap.insert("highwinds", "misc", 1, 200, 0);
        assert_eq!(
            snap.verdict(&["highwinds".to_string()], "  ", 3),
            Some(Verdict::Ok)
        );
        snap.insert("highwinds", "misc", 0, 2, 98);
        assert!(snap.backbone_gone("highwinds", "", 0));
    }

    #[test]
    fn wilson_sanity() {
        let (lo, hi) = wilson(0, 0);
        assert_eq!((lo, hi), (0.0, 1.0));
        let (lo, hi) = wilson(100, 100);
        assert!(lo > 0.95 && hi > 0.999, "lo={lo} hi={hi}");
        let (lo, hi) = wilson(0, 100);
        assert!(lo == 0.0 && hi < 0.05, "lo={lo} hi={hi}");
        let (lo, hi) = wilson(50, 100);
        assert!(lo > 0.40 && lo < 0.5 && hi > 0.5 && hi < 0.60);
    }
}
