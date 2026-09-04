//! §131 identity substrate: the provenance-aware name-claims layer.
//!
//! Every naming lane - PAR2 sidecars, archive byte-probes, posted-NZB
//! ingestion, the download-tail oracles, one day an exchange - proves
//! "release X is really called N" with some piece of evidence. Before
//! this layer, each lane wrote its truth somewhere different (or
//! nowhere: `pre_corr_verdict` drops the proof on the floor when no
//! correlation row happens to exist), and a one-hit table like
//! `par_hashes` let the first writer win forever. That table now
//! borrows this ladder rather than carrying a second one - see
//! `Index::par_hash_remember` - which is why [`NameEvidence::rank`] is
//! reachable from the rest of `index` and not private here.
//!
//! Here every proof is a ROW - claimed name, evidence tier, proving
//! key, producing lane - and the strongest eligible claim is what gets
//! applied to the release. Competing claims coexist; nothing is lost
//! for want of a correlation record; and the evidence tier is stored
//! so a future consumer (the wall, an *arr response, an exchange
//! export) can decide for itself how much proof it wants.
//!
//! The tier ladder orders evidence by how hard it is to fake or to
//! collide: message-id sets and PAR2 set ids at the top, MD5(first
//! 16 KiB) explicitly WEAK - it collides across same-intro encodes, so
//! it never names a release on its own, only with independent
//! corroboration - and time/size adjacency recorded as association
//! evidence that can never name anything.
//!
//! The reverse message-id lookup lives here too: `msgid_map` keys a
//! bounded sample of each file's segment message-ids back to its
//! release, so a set of message-ids from a posted NZB, a spot, or an
//! *arr handoff can join to dark scan rows - the join `par_hashes`
//! structurally cannot do (scan rows have no content hash until
//! somebody downloads them; they always have message-ids).

use super::*;

/// How strong a piece of naming evidence is - the Codex ladder,
/// strongest first. Stored in `name_claims.tier` as the stable `tag()`
/// string, so variants may be added but tags must never be reused.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NameEvidence {
    /// A name read directly out of the release's OWN payload bytes,
    /// fetched by this release's own message-ids: a 7z end-header's
    /// inner filename, a RAR continuation-volume header. Nothing was
    /// cross-referenced, so there is no binding to get wrong - which
    /// is why it sits at the top. (A Matroska Title is NOT this: it is
    /// read from the payload too, but it is an unverified claim by
    /// whoever muxed the file, not the archive's own record of what
    /// the archive contains.)
    BodyProbe,
    /// The exact message-id set of a posted NZB matched this release's
    /// articles (multi-id quorum - a single id can be seeded).
    MsgidSet,
    /// The PAR2 Recovery Set ID of the release's own sidecar.
    Par2SetId,
    /// A canonical sorted {full MD5, exact length} file manifest.
    Md5Manifest,
    /// Sparse BLAKE3 + exact length (the cheap local re-key).
    SparseBlake3,
    /// Full yEnc CRC32 + exact length (srrdb-class identity).
    Crc32Len,
    /// MD5 of the first 16 KiB + length. WEAK: collides across
    /// same-intro encodes and is trivially copyable, so it may only
    /// name a release when an independent claim agrees.
    Hash16kLen,
    /// Time/size/session adjacency. Association evidence only - it is
    /// recorded for audit and can corroborate nothing and name nothing.
    Adjacency,
}

impl NameEvidence {
    /// The stable storage tag. Never reuse a retired tag.
    pub fn tag(self) -> &'static str {
        match self {
            NameEvidence::BodyProbe => "body-probe",
            NameEvidence::MsgidSet => "msgid-set",
            NameEvidence::Par2SetId => "par2-set-id",
            NameEvidence::Md5Manifest => "md5-manifest",
            NameEvidence::SparseBlake3 => "sparse-blake3",
            NameEvidence::Crc32Len => "crc32-len",
            NameEvidence::Hash16kLen => "hash16k-len",
            NameEvidence::Adjacency => "adjacency",
        }
    }

    pub fn parse(tag: &str) -> Option<NameEvidence> {
        Some(match tag {
            "body-probe" => NameEvidence::BodyProbe,
            "msgid-set" => NameEvidence::MsgidSet,
            "par2-set-id" => NameEvidence::Par2SetId,
            "md5-manifest" => NameEvidence::Md5Manifest,
            "sparse-blake3" => NameEvidence::SparseBlake3,
            "crc32-len" => NameEvidence::Crc32Len,
            "hash16k-len" => NameEvidence::Hash16kLen,
            "adjacency" => NameEvidence::Adjacency,
            _ => return None,
        })
    }

    /// Ordering within the ladder. The NUMBERS are not stored anywhere -
    /// only compared - so they can be renumbered when a tier is added.
    ///
    /// Reachable from the rest of `index` because the repost table
    /// (`Index::par_hash_remember`) decides the same question with the
    /// same ladder: a second copy of this ordering is how two naming
    /// tiers start disagreeing about which evidence outranks which.
    pub(super) fn rank(self) -> i32 {
        match self {
            NameEvidence::BodyProbe => 7,
            NameEvidence::MsgidSet => 6,
            NameEvidence::Par2SetId => 5,
            NameEvidence::Md5Manifest => 4,
            NameEvidence::SparseBlake3 => 3,
            NameEvidence::Crc32Len => 2,
            NameEvidence::Hash16kLen => 1,
            NameEvidence::Adjacency => 0,
        }
    }

    /// May a claim at this tier name a release with no second opinion?
    /// The hash16k line is the load-bearing one: the §131 red-team's
    /// condition is that it must NEVER auto-name alone.
    fn applies_alone(self) -> bool {
        self.rank() >= NameEvidence::Crc32Len.rank()
    }
}

/// One lane's proof about one release.
#[derive(Debug, Clone)]
pub struct NameClaim {
    /// The real release name being claimed.
    pub name: String,
    pub evidence: NameEvidence,
    /// The proving value - set id hex, crc hex, hash16k hex, msgid-set
    /// digest. What makes two claims "independent" for corroboration.
    pub key: String,
    /// The lane that produced it ("srrdb", "par-hash", "posted-nzb",
    /// "pesto-par2", ...). Rendered into the release's provenance label.
    pub source: String,
}

/// What `apply_proven_name` did.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProvenOutcome {
    /// Named a previously unnamed release.
    Applied,
    /// Displaced a weaker name (a correlation guess, or weaker proof).
    Replaced,
    /// Agrees with the name already applied (which may have had its
    /// provenance upgraded to this claim's).
    Confirmed,
    /// Stored, but not applied: the tier cannot name alone yet, or the
    /// evidence is association-only.
    Recorded,
    /// Stored, but the release keeps an equal-or-stronger DIFFERENT
    /// name. Logged; never auto-resolved here.
    Conflict,
    /// Unusable claim (empty or path-like name, unknown release).
    Rejected,
}

/// 64-bit key of a message-id for `msgid_map`: first 8 bytes of the
/// MD5 of the id with any angle brackets and whitespace stripped, so
/// the OVER form (`<x@y>`) and the NZB form (`x@y`) hash alike. MD5
/// rather than a rustc hasher because the value is PERSISTED - the
/// std hasher is not stable across releases - and truncated because 22
/// million rows at 64 bits see no birthday collisions worth a wider
/// key (and every consumer requires multi-id agreement anyway).
pub(super) fn msgid_hash(msgid: &str) -> i64 {
    use crate::md5fast::{Digest, Md5};
    let d = Md5::digest(norm_msgid(msgid).as_bytes());
    i64::from_le_bytes(d[..8].try_into().unwrap())
}

/// A message-id reduced to the form every lane can compare: trimmed,
/// with one pair of angle brackets removed. The OVER form (`<x@y>`) and
/// the NZB form (`x@y`) are the same article, and two lanes that
/// disagree about that would either miss a join or invent one.
///
/// One definition, because three things depend on agreeing exactly:
/// [`msgid_hash`]'s persisted key, [`msgid_set_key`]'s claim key, and
/// ingest's generation test - which asks whether two articles claiming
/// the same part of the same file are the same article.
pub(super) fn norm_msgid(msgid: &str) -> &str {
    let m = msgid.trim();
    let m = m.strip_prefix('<').unwrap_or(m);
    m.strip_suffix('>').unwrap_or(m)
}

/// How many of a file's lowest-numbered segments get keyed into
/// `msgid_map`. Three, not one, because most dark rows are single-file
/// (obfuscated per-file stems never cluster: 7.62M files over 7.16M
/// releases on the live index), and a single key would make the
/// multi-id quorum that guards against seeded NZBs impossible for
/// exactly the rows the lookup exists to name.
///
/// Public because quorum callers size their threshold from it: a row
/// can never match more ids than it holds, so "matched >= min(this,
/// keys the row holds)" is the honest bar, not a hardcoded 3.
pub const MSGID_KEYS_PER_FILE: usize = 3;

/// The canonical `NameClaim.key` for a [`NameEvidence::MsgidSet`]
/// claim: MD5 hex over the matched message-ids, each normalized the
/// way [`msgid_hash`] normalizes (trimmed, one pair of angle brackets
/// stripped), byte-sorted, joined with `\n`. One definition so every
/// lane derives the same key for the same id set - two lanes proving
/// the same join must corroborate, not look independent.
pub fn msgid_set_key<I, S>(msgids: I) -> String
where
    I: IntoIterator<Item = S>,
    S: AsRef<str>,
{
    use crate::md5fast::{Digest, Md5};
    let mut norm: Vec<String> = msgids
        .into_iter()
        .map(|m| norm_msgid(m.as_ref()).to_string())
        .collect();
    norm.sort();
    norm.dedup();
    let mut h = Md5::new();
    for (i, m) in norm.iter().enumerate() {
        if i > 0 {
            h.update(b"\n");
        }
        h.update(m.as_bytes());
    }
    crate::par2::hex16(&h.finalize().into())
}

/// Key one file's message-ids into the reverse map. `msgids` must be
/// in ascending part order; only the first [`MSGID_KEYS_PER_FILE`] are
/// stored. Rows are append-only per release (a later batch that
/// reveals lower part numbers just adds keys - the old ones still
/// belong to this release and still join).
pub(super) fn msgid_map_insert<'a>(
    db: &Connection,
    rid: i64,
    msgids: impl Iterator<Item = &'a str>,
) -> rusqlite::Result<()> {
    let mut ins =
        db.prepare_cached("INSERT OR IGNORE INTO msgid_map(h, release_id) VALUES(?1, ?2)")?;
    for m in msgids.take(MSGID_KEYS_PER_FILE) {
        ins.execute(rusqlite::params![msgid_hash(m), rid])?;
    }
    Ok(())
}

/// Retroactive `msgid_map` fill for files rows written before the
/// table existed. Chunked with a kv rowid cursor, time-bounded, and
/// resumed by the next open - the nsegs-fill shape, for the nsegs-fill
/// reasons (a one-shot UPDATE loses the write lock to a live scanner
/// and an unbounded loop stalls every daemon start).
pub(super) fn msgid_map_backfill(db: &mut Connection) {
    msgid_map_backfill_slice(db, std::time::Duration::from_secs(2));
}

/// One time-bounded slice of the retroactive fill. Returns true when
/// the fill is COMPLETE (or cannot proceed), false while rows remain.
///
/// Why this is a per-lap leg and not only an open-time one (measured
/// 2 Sep 2026, research/LIVE-INDEX-CENSUS-2026-09-02.md): the open-time
/// call gets two seconds per daemon start, and on an index that had
/// 31M rows before the table existed that cursor had reached files
/// rowid 18.9M after weeks of restarts - so 19.4M releases (every row
/// first seen 29 Jul to 3 Aug) had NO map entry, and 231 of 231
/// indexer NZBs the seed lane grabbed that day joined nothing, not
/// because of the quorum rule but because the ids were unlisted. The
/// maintenance slice now loops this the way it loops the folds; the
/// 2 s open-time call is kept so a small index still finishes at once.
pub(super) fn msgid_map_backfill_slice(db: &mut Connection, budget: std::time::Duration) -> bool {
    let done: Option<String> = db
        .query_row("SELECT v FROM kv WHERE k='msgid_map_fill'", [], |r| {
            r.get(0)
        })
        .ok();
    if done.as_deref() == Some("1") {
        return true;
    }
    let deadline = std::time::Instant::now() + budget;
    let mut complete = false;
    let _ = (|| -> rusqlite::Result<()> {
        loop {
            // IMMEDIATE for the same reason as every cursor walk here:
            // a deferred lock upgrade returns SQLITE_BUSY without the
            // busy timeout and parks the cursor mid-pass.
            let tx =
                rusqlite::Transaction::new_unchecked(db, rusqlite::TransactionBehavior::Immediate)?;
            let cursor: i64 = tx
                .query_row("SELECT v FROM kv WHERE k='msgid_map_at'", [], |r| {
                    r.get::<_, String>(0)
                })
                .ok()
                .and_then(|v| v.parse().ok())
                .unwrap_or(0);
            let rows: Vec<(i64, i64, SegList)> = {
                let mut sel = tx.prepare_cached(
                    "SELECT rowid, release_id, segments FROM files
                      WHERE rowid > ?1 ORDER BY rowid LIMIT 2000",
                )?;
                sel.query_map([cursor], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?)))?
                    .collect::<rusqlite::Result<_>>()?
            };
            let Some(&(last, _, _)) = rows.last() else {
                tx.execute(
                    "INSERT INTO kv(k, v) VALUES('msgid_map_fill','1')
                     ON CONFLICT(k) DO UPDATE SET v='1'",
                    [],
                )?;
                tx.commit()?;
                complete = true;
                return Ok(());
            };
            for (_, rid, segs) in &rows {
                let mut parsed = segs.0.clone();
                // Serialized from a BTreeMap so already ascending, but
                // the sort is cheap insurance against a hand-edited row.
                parsed.sort_by_key(|(n, _, _)| *n);
                msgid_map_insert(&tx, *rid, parsed.iter().map(|(_, id, _)| id.as_str()))?;
            }
            tx.execute(
                "INSERT INTO kv(k, v) VALUES('msgid_map_at', ?1)
                 ON CONFLICT(k) DO UPDATE SET v=excluded.v",
                [last.to_string()],
            )?;
            tx.commit()?;
            if std::time::Instant::now() >= deadline {
                return Ok(());
            }
        }
    })();
    complete
}

impl Index {
    /// One budgeted slice of the retroactive `msgid_map` fill, for the
    /// maintenance lap. True when nothing remains. See
    /// [`msgid_map_backfill_slice`] for why the open-time call alone
    /// never finished on a real index.
    pub fn msgid_map_backfill_slice(&mut self, budget: std::time::Duration) -> bool {
        msgid_map_backfill_slice(&mut self.db, budget)
    }

    /// Progress of that fill for a log line: `(files rowid cursor,
    /// map rows)`. Both are cheap reads.
    pub fn msgid_map_progress(&self) -> (i64, i64) {
        let at = self
            .db
            .query_row("SELECT v FROM kv WHERE k='msgid_map_at'", [], |r| {
                r.get::<_, String>(0)
            })
            .ok()
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let n = self
            .db
            .query_row("SELECT count(*) FROM msgid_map", [], |r| r.get(0))
            .unwrap_or(0);
        (at, n)
    }
}

/// How strongly the release's CURRENT name is held, on the same scale
/// `apply_proven_name` scores an incoming winner (10 + tier rank).
///
/// Exact-leg relay names (plain `predb`/`predb/<relay src>`) are held
/// at MAX on purpose: a relay-paired filename and a byte proof should
/// agree, and when they do not, that is a fight to SURFACE, not one
/// this layer referees automatically - the same line
/// `pre_corr_verdict` draws. Correlation guesses (auto or manual) sit
/// at 0: any claim strong enough to apply at all displaces them,
/// which is exactly what the download-time verdict already does.
fn applied_strength(pre_title: &str, pre_source: &str) -> i32 {
    if pre_title.is_empty() {
        return -1;
    }
    if let Some(rest) = pre_source.strip_prefix("proven:") {
        let tag = rest.split(':').next().unwrap_or("");
        return 10 + NameEvidence::parse(tag).map_or(0, |e| e.rank());
    }
    if pre_source.starts_with("predb/corr:") || pre_source.starts_with("predb/manual+corr:") {
        return 0;
    }
    i32::MAX
}

/// The `pre_source` a release carries when the claims layer named it:
/// `proven:<tier>` with the lane appended when it named itself. ONE
/// definition, because two things must agree exactly - what
/// `apply_proven_name` stamps, and what a lane that applies its own
/// name (spot promotion) stamps for the same claim. A lane that writes
/// some other string is what `applied_strength` reads as "not proven at
/// all" and grades at `i32::MAX`, above every byte proof.
pub(super) fn proven_label(evidence: NameEvidence, source: &str) -> String {
    let s = source.trim();
    if s.is_empty() {
        format!("proven:{}", evidence.tag())
    } else {
        format!("proven:{}:{}", evidence.tag(), s)
    }
}

/// Does the readable stem AGREE with the claim once its sibling-file
/// noise is folded off? The measured shapes (:6789 log, 10 Aug) are the
/// release's own furniture joined by its posted NZB's msgid set:
/// "sample-<name>", "<name>-sample", "<name>.sample.mkv", and
/// "<name>.mkv.png" screenshot posts. The wall already folds these
/// (ingest's furniture scoring); the claims gate was calling every one
/// a Conflict, which both spams the log and pollutes the conflict
/// telemetry that exists to flag REAL disagreements.
///
/// Only edge tokens from a closed list are folded - never a generic
/// "short trailing token", which would eat the tail of a real title and
/// let a season-pack claim swallow a per-episode stem (the exact hazard
/// the readable-stem rule defends: an episode screenshot's folded stem
/// still disagrees with its pack's claim, so it still stands loudly).
/// An empty residue ("sample.mkv" alone) counts as agreement: that stem
/// says nothing the claim could contradict.
fn agrees_modulo_furniture(stem: &str, wnkey: &str) -> bool {
    // The affix vocabulary of ingest's FURNITURE scoring, as tokens.
    const FURNITURE: [&str; 12] = [
        "sample", "proof", "nfo", "srr", "sfv", "srs", "nzb", "idx", "sub", "subs", "srt", "par2",
    ];
    // Container/image extensions that ride those stems as a second
    // layer ("….sample.mkv", "….mkv.png"). Whole tokens only.
    const NOISE_EXTS: [&str; 20] = [
        "mkv", "mp4", "avi", "wmv", "m2ts", "ts", "vob", "mpg", "mpeg", "mov", "divx", "jpg",
        "jpeg", "png", "gif", "bmp", "webp", "zip", "rar", "7z",
    ];
    let furn = |t: &&str| FURNITURE.iter().any(|f| t.eq_ignore_ascii_case(f));
    let ext = |t: &&str| NOISE_EXTS.iter().any(|f| t.eq_ignore_ascii_case(f));
    let mut toks: Vec<&str> = stem
        .split(['.', '_', '-', ' '])
        .filter(|t| !t.is_empty())
        .collect();
    let mut folded = false;
    loop {
        let before = toks.len();
        while toks.last().is_some_and(&ext) {
            toks.pop();
        }
        while toks.last().is_some_and(&furn) {
            toks.pop();
        }
        while toks.first().is_some_and(&furn) {
            toks.remove(0);
        }
        if toks.len() == before {
            break;
        }
        folded = true;
    }
    if !folded {
        return false;
    }
    let key = crate::predb::match_key(&toks.join("."));
    key.is_empty() || key == wnkey
}

impl Index {
    /// Put one lane's claim on file WITHOUT re-deciding the release's
    /// name. `false` means the claim was refused outright (a path is
    /// not a release name from any source, and sanitising must leave
    /// something) - the same refusals [`Index::apply_proven_name`]
    /// applies, because it is this method that applies them for it.
    ///
    /// The ledger and the decision are separable because one lane does
    /// not need the decision: spot promotion BUILDS the release out of
    /// the spot's own NZB, so there is no competing name to arbitrate
    /// and no readable stem worth preferring - the stem is one filename
    /// out of the very NZB the title announces. What it does need is
    /// the row: provenance for whatever proves the release's name
    /// later, and an honest count for anything that ranks lanes by the
    /// ledger.
    pub(super) fn record_name_claim(
        &self,
        rid: i64,
        claim: &NameClaim,
        now: i64,
    ) -> rusqlite::Result<bool> {
        let raw = claim.name.trim();
        if raw.contains('/') || raw.contains('\\') || raw.starts_with('.') {
            return Ok(false);
        }
        let name = crate::release::sanitize_name(raw);
        if name.is_empty() {
            return Ok(false);
        }
        self.db
            .prepare_cached(
                "INSERT OR IGNORE INTO name_claims(release_id, name, tier, key, source, at)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
            )?
            .execute(rusqlite::params![
                rid,
                name,
                claim.evidence.tag(),
                claim.key,
                claim.source,
                now
            ])?;
        Ok(true)
    }

    /// Record one lane's proof that release `rid` is really called
    /// `claim.name`, and apply the strongest eligible claim now on
    /// file. THE entry point for body/download truth: it works with no
    /// correlation row, no predb row and no prior claim - nothing a
    /// lane proves is lost for want of somewhere to put it.
    ///
    /// What "apply" respects, in order:
    /// - a claim whose tier cannot name alone waits, recorded, until an
    ///   independent claim agrees (hash16k), or forever (adjacency);
    /// - an unnamed release takes the winner;
    /// - a correlation-applied name (auto or human-picked) yields to any
    ///   applying claim, and the pre_corr row is settled
    ///   confirmed/rejected exactly as the download-time verdict would;
    /// - a weaker proven name yields to a strictly stronger one;
    /// - an exact-leg relay name is never displaced - a disagreeing
    ///   proof is recorded and logged as a conflict.
    pub fn apply_proven_name(
        &mut self,
        rid: i64,
        claim: &NameClaim,
        now: i64,
    ) -> rusqlite::Result<ProvenOutcome> {
        // One decision, one commit. The body is a read-decide-write
        // across several statements (claim insert, revoke, apply,
        // corr settle), and a second WRITER PROCESS exists by design:
        // the CLI census (`nzbfast nzb-import --apply`) runs beside
        // the daemon against the same WAL index. Without the
        // savepoint, its stale read could revoke a name a stronger
        // lane applied in the gap, and a crash between revoke and
        // apply left a release nameless with nothing to retry. Inside
        // it, a write from a stale snapshot fails (BUSY_SNAPSHOT) and
        // rolls back whole - an error the caller logs, never a
        // half-applied decision.
        self.db.execute_batch("SAVEPOINT apply_pn")?;
        let out = self.apply_proven_name_locked(rid, claim, now);
        match &out {
            Ok(_) => self.db.execute_batch("RELEASE apply_pn")?,
            Err(_) => {
                let _ = self
                    .db
                    .execute_batch("ROLLBACK TO apply_pn; RELEASE apply_pn");
            }
        }
        out
    }

    fn apply_proven_name_locked(
        &mut self,
        rid: i64,
        claim: &NameClaim,
        now: i64,
    ) -> rusqlite::Result<ProvenOutcome> {
        // Read the release BEFORE recording: an unknown id is Rejected
        // and must not leave an orphan ledger row behind (the AFTER
        // DELETE trigger cleans rows whose release existed, never rows
        // whose release never did).
        let Some((stem, pre_title, pre_source)) = self
            .db
            .prepare_cached("SELECT stem, pre_title, pre_source FROM releases WHERE id=?1")?
            .query_row([rid], |r| {
                Ok((
                    r.get::<_, String>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })
            .optional()?
        else {
            return Ok(ProvenOutcome::Rejected);
        };
        if !self.record_name_claim(rid, claim, now)? {
            return Ok(ProvenOutcome::Rejected);
        }

        // Pick the winner among everything now on file for this
        // release. Corroboration is an INDEPENDENT agreeing claim:
        // same name (separator-insensitively), different evidence -
        // and association-tier rows corroborate nothing, or adjacency
        // would launder hash16k into an auto-name.
        struct Scored<'a> {
            e: NameEvidence,
            name: &'a str,
            key: &'a str,
            source: &'a str,
            at: i64,
            /// `match_key(name)` - what "the same name" means here.
            nkey: String,
        }
        let rows: Vec<(String, String, String, String, i64)> = {
            let mut sel = self.db.prepare_cached(
                "SELECT name, tier, key, source, at FROM name_claims WHERE release_id=?1",
            )?;
            sel.query_map([rid], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let scored: Vec<Scored> = rows
            .iter()
            .filter_map(|(n, t, k, s, at)| {
                Some(Scored {
                    e: NameEvidence::parse(t)?,
                    name: n,
                    key: k,
                    source: s,
                    at: *at,
                    nkey: crate::predb::match_key(n),
                })
            })
            .collect();
        // An INDEPENDENT agreeing claim: same name key, but not the
        // same (tier, proving key) - re-proving the identical fact is
        // not a second opinion. Association-tier rows never count.
        // An EMPTY name key never agrees with anything: match_key
        // keeps ASCII alphanumerics only, so two entirely different
        // non-Latin names can both collapse to "" - "agreement" that
        // would let two disagreeing hash16k claims corroborate each
        // other into an auto-name.
        let corrob_of = |c: &Scored| {
            scored
                .iter()
                .filter(|o| {
                    o.e.rank() >= NameEvidence::Hash16kLen.rank()
                        && !c.nkey.is_empty()
                        && o.nkey == c.nkey
                        && !(o.e.tag() == c.e.tag() && o.key == c.key)
                })
                .count()
        };
        let winner = scored
            .iter()
            .filter(|c| {
                c.e.rank() >= NameEvidence::Hash16kLen.rank()
                    && (c.e.applies_alone() || corrob_of(c) >= 1)
            })
            .max_by_key(|c| (c.e.rank(), corrob_of(c), c.at, c.nkey.clone()));
        let Some((we, wname, wsource, wnkey)) = winner.map(|c| {
            (
                c.e,
                c.name.to_string(),
                c.source.to_string(),
                c.nkey.clone(),
            )
        }) else {
            return Ok(ProvenOutcome::Recorded);
        };
        let win_strength = 10 + we.rank();

        // Everything the pre_corr settle needs, read BEFORE any
        // mutation (revoke stomps both the status and pre_title).
        let prior: Option<(i64, String, String, String)> = self
            .db
            .prepare_cached(
                "SELECT c.predb_id, c.status, COALESCE(p.title,''), COALESCE(p.filename,'')
                   FROM pre_corr c LEFT JOIN predb p ON p.id=c.predb_id
                  WHERE c.release_id=?1 AND c.status IN ('suggested','applied','confirmed')",
            )?
            .query_row([rid], |r| Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?)))
            .optional()?;
        let corr_applied =
            pre_source.starts_with("predb/corr:") || pre_source.starts_with("predb/manual+corr:");

        let cur = applied_strength(&pre_title, &pre_source);
        // Same empty-key rule as corroboration: a name whose key
        // collapses to "" agrees with nothing.
        let agreed_with_current = !pre_title.is_empty()
            && !wnkey.is_empty()
            && crate::predb::match_key(&pre_title) == wnkey;
        let label = proven_label(we, &wsource);
        let outcome = if pre_title.is_empty() {
            // "Unnamed" means the stem SAYS nothing - not merely that
            // no pre_title was applied. A readable stem is the
            // poster's own name for the post, and it is usually MORE
            // specific than a joined claim: the measured failure shape
            // (posted-NZB census, 10 Aug) is a season-pack NZB whose
            // msgid-set quorum joins its own per-episode rows, where
            // applying would stamp the pack's name over every episode.
            // A claim that AGREES with the stem (separator- and
            // case-insensitively) still applies - that is a canonical
            // spelling and provenance upgrade, not a rename.
            // `stem_is_a_name` is THE shared verdict, the same one the
            // byte-probe picks use to decide a row is dark. Asking it a
            // different way here is what turned the byte prober's first
            // eight production names - correct, read out of the
            // archives' own headers - into Conflict rows instead of
            // applies (measured 10 Aug, :6789).
            if crate::release::stem_is_a_name(&stem) && crate::predb::match_key(&stem) != wnkey {
                if agrees_modulo_furniture(&stem, &wnkey) {
                    // The stem IS the claim's name wearing sibling-file
                    // noise ("sample-<name>", "<name>-sample",
                    // "<name>.mkv.png" screens) - the release's own NZB
                    // joins its furniture rows, so these claims arrive
                    // constantly and they are not conflicts. Not an
                    // apply either: apply_named re-derives junk from
                    // the clean title, and a 10 MB+ sample row scored
                    // by the release's name walks onto the wall as a
                    // duplicate release. The stem stands, quietly.
                    tracing::debug!(
                        target: "claims",
                        "release {rid}: {} claim {wname:?} agrees with the \
                         furniture stem {stem:?} - recorded, stem stands",
                        we.tag()
                    );
                    ProvenOutcome::Recorded
                } else {
                    warn!(
                        target: "claims",
                        "release {rid}: {} claim says {wname:?} but the readable \
                         stem {stem:?} stands - recorded, not applied",
                        we.tag()
                    );
                    ProvenOutcome::Conflict
                }
            } else {
                self.apply_pre_name(rid, &wname, &label, now)?;
                ProvenOutcome::Applied
            }
        } else if cur < win_strength {
            // Displace the weaker name: back to the stem, then apply
            // the winner the same way ingest would - the release must
            // be indistinguishable from one named at ingest.
            self.revoke_pre_name(rid)?;
            self.apply_pre_name(rid, &wname, &label, now)?;
            if agreed_with_current {
                ProvenOutcome::Confirmed
            } else {
                ProvenOutcome::Replaced
            }
        } else if agreed_with_current {
            ProvenOutcome::Confirmed
        } else if crate::release::undoubled(&pre_title)
            .is_some_and(|half| crate::predb::match_key(half) == wnkey)
        {
            // The standing name is THIS claim's own name written twice
            // (`crate::release::undoubled`). Without this arm the
            // corruption defends itself: a doubled name and its correct
            // half reach `applied_strength` at the SAME tier - both are
            // `proven:msgid-set:…`, since the doubling rides the poster's
            // own quoted filename into every lane that reads that post's
            // stem - so `cur < win_strength` is false, the keys disagree,
            // and every future correct claim on the row is recorded and
            // refused, forever. Measured 1 Sep 2026: 285 of 24,996 named
            // releases stood exactly there.
            //
            // Confirmed, not Replaced: nothing is being renamed. This is
            // the same name with its duplicate half folded off - a
            // canonical-spelling upgrade, the reading the empty-stem arm
            // above already takes for a claim that agrees modulo
            // furniture.
            //
            // The narrowest possible arm, deliberately: it fires only
            // when the standing name is exactly its own doubling AND the
            // claim is precisely its half. It cannot let any other weaker
            // or equal claim in, so the equal-or-stronger rule below is
            // untouched.
            self.revoke_pre_name(rid)?;
            self.apply_pre_name(rid, &wname, &label, now)?;
            tracing::info!(
                target: "claims",
                "release {rid}: applied name {pre_title:?} was {wname:?} \
                 written twice - folded to the claim"
            );
            ProvenOutcome::Confirmed
        } else {
            warn!(
                target: "claims",
                "release {rid} ({stem}): {} claim says {wname:?} but the \
                 applied name {pre_title:?} ({pre_source}) is equal or \
                 stronger - recorded, not applied",
                we.tag()
            );
            ProvenOutcome::Conflict
        };

        // Settle a live correlation record the way the download-time
        // verdict would: proof agreeing with what correlation claimed
        // is 'confirmed' (and arms the exact legs with the proven
        // pairing), proof disagreeing is 'rejected'. Only correlation's
        // own claims are settled - a 'suggested' row's candidate title,
        // or an applied name that came from the corr legs.
        //
        // Never on Conflict: there the layer itself judged the winner
        // insufficient to name the row (a readable stem or an
        // equal-or-stronger name stands), and a verdict is only as
        // good as the evidence behind it. Settling a suggestion
        // against a REFUSED claim would permanently reject a
        // suggestion that agrees with the standing name - and those
        // false verdicts feed the precision meters the auto-apply
        // decision reads.
        if !matches!(outcome, ProvenOutcome::Conflict)
            && let Some((predb_id, status, cand_title, cand_fn)) = prior
        {
            let claimed = if status == "suggested" {
                cand_title
            } else if corr_applied {
                pre_title.clone()
            } else {
                String::new()
            };
            if !claimed.trim().is_empty() {
                let agree = crate::predb::match_key(&claimed) == wnkey;
                self.db.execute(
                    "UPDATE pre_corr SET status=?2, at=?3 WHERE release_id=?1",
                    rusqlite::params![rid, if agree { "confirmed" } else { "rejected" }, now],
                )?;
                if agree && cand_fn.is_empty() && predb_id > 0 {
                    let fnstem = stem.to_ascii_lowercase();
                    let fnkey = crate::predb::match_key(&fnstem);
                    self.db.execute(
                        "UPDATE predb SET filename=?2, fnstem=?3, fnkey=?4, tried_at=0
                          WHERE id=?1 AND filename=''",
                        rusqlite::params![predb_id, stem, fnstem, fnkey],
                    )?;
                    self.predb = true;
                }
            }
        }
        Ok(outcome)
    }

    /// Re-run the naming decision for releases that hold recorded
    /// claims but no applied name. Nothing re-fires the decision on
    /// its own: a claim refused by a since-fixed gate (the byte
    /// prober's first seven production names sat exactly there), or
    /// left Recorded waiting for corroboration another process wrote
    /// but never re-decided, would otherwise strand in the ledger
    /// until a user happened to download the release. Re-submitting
    /// the strongest stored claim is a no-op insert (OR IGNORE) plus
    /// the full decision over everything on file, all gates enforced -
    /// idempotent, upgrade-only, offline. Bounded by `limit`; meant to
    /// run once per daemon start. Returns how many releases gained a
    /// name.
    ///
    /// The window WALKS, on a durable cursor, and wraps when it runs
    /// out. An uncursored `LIMIT n` re-selected the same front rows on
    /// every start, and the rows it selects are by definition ones the
    /// decision does not name - readable conflicts, lone weak claims -
    /// so they stay selectable forever. `limit` of them was enough to
    /// hide every later stranded claim from every future start (M5,
    /// 10 Aug sweep). Ordering by release id makes the walk total; the
    /// wrap means a run that reaches the end re-examines from the
    /// front, which is what makes a re-decidable row re-decidable after
    /// a gate is fixed.
    pub fn claims_replay(&mut self, now: i64, limit: usize) -> rusqlite::Result<usize> {
        const CURSOR: &str = "claims_replay_at";
        let cursor: i64 = self
            .kv_get(CURSOR)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let select = |from: i64| -> rusqlite::Result<Vec<i64>> {
            let mut sel = self.db.prepare_cached(
                "SELECT DISTINCT c.release_id
                   FROM name_claims c JOIN releases r ON r.id=c.release_id
                  WHERE r.pre_title='' AND c.release_id > ?1
                  ORDER BY c.release_id LIMIT ?2",
            )?;
            sel.query_map(rusqlite::params![from, limit as i64], |r| r.get(0))?
                .collect()
        };
        let mut rids = select(cursor)?;
        // Past the end: start the next pass at the front rather than
        // stopping there for good.
        if rids.is_empty() && cursor > 0 {
            rids = select(0)?;
        }
        let next = rids.last().copied().unwrap_or(0);
        let mut applied = 0usize;
        for rid in rids {
            let Some((name, tier, key, source, _)) = self.name_claims(rid)?.into_iter().next()
            else {
                continue;
            };
            let Some(evidence) = NameEvidence::parse(&tier) else {
                continue;
            };
            let claim = NameClaim {
                name,
                evidence,
                key,
                source,
            };
            if matches!(
                self.apply_proven_name(rid, &claim, now)?,
                ProvenOutcome::Applied | ProvenOutcome::Replaced
            ) {
                applied += 1;
            }
        }
        // Advance the durable cursor only once every row in the window
        // was decided: persisting it up front meant a mid-window error
        // (a SQLITE_BUSY_SNAPSHOT from apply_proven_name) skipped the
        // remaining rows until the walk lapped the whole population.
        // On error the cursor stays put and the SAME window retries.
        let _ = self.kv_set(CURSOR, &next.to_string());
        Ok(applied)
    }

    /// Everything on file for one release: `(name, tier, key, source,
    /// at)`, strongest tier first. The audit view of a name.
    pub fn name_claims(
        &self,
        rid: i64,
    ) -> rusqlite::Result<Vec<(String, String, String, String, i64)>> {
        let mut sel = self.db.prepare_cached(
            "SELECT name, tier, key, source, at FROM name_claims WHERE release_id=?1",
        )?;
        let mut rows: Vec<(String, String, String, String, i64)> = sel
            .query_map([rid], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?, r.get(3)?, r.get(4)?))
            })?
            .collect::<rusqlite::Result<_>>()?;
        rows.sort_by_key(|(_, t, _, _, at)| {
            (-NameEvidence::parse(t).map_or(-1, |e| e.rank()), -*at)
        });
        Ok(rows)
    }

    /// Join a set of message-ids (a posted NZB, a spot NZB, an *arr
    /// handoff) to the scan rows that carry them. Returns
    /// `(release_id, distinct ids matched)`, best first. The CALLER
    /// owns the quorum decision - a single matched id is association,
    /// not identity, because a hostile NZB can embed one real id.
    ///
    /// Probe with every id you have: only a bounded sample per file is
    /// keyed on the map side, so extra probes miss harmlessly, but a
    /// probe set that skips ids can miss the keyed ones.
    pub fn find_releases_by_msgids<I, S>(&self, msgids: I) -> rusqlite::Result<Vec<(i64, u32)>>
    where
        I: IntoIterator<Item = S>,
        S: AsRef<str>,
    {
        use std::collections::{HashMap, HashSet};
        let mut sel = self
            .db
            .prepare_cached("SELECT release_id FROM msgid_map WHERE h=?1")?;
        let mut probed: HashSet<i64> = HashSet::new();
        let mut hits: HashMap<i64, u32> = HashMap::new();
        for m in msgids {
            let h = msgid_hash(m.as_ref());
            if !probed.insert(h) {
                continue;
            }
            let rids = sel.query_map([h], |r| r.get::<_, i64>(0))?;
            for rid in rids {
                *hits.entry(rid?).or_default() += 1;
            }
        }
        let mut out: Vec<(i64, u32)> = hits.into_iter().collect();
        out.sort_by_key(|&(rid, n)| (std::cmp::Reverse(n), rid));
        Ok(out)
    }

    /// The release rows a posted name resolves to (same derivation the
    /// ingest clustering used), capped at 3 - callers only need to
    /// distinguish none / exactly one / ambiguous. Exact match first
    /// (indexed), then the case-folded fallback for a case-mangled
    /// name, split into two BOUNDED arms.
    ///
    /// The fallback used to be one `WHERE LOWER(stem)=?1`, described
    /// here as an acceptable scan because it "only runs on the rare
    /// case-mangled miss and only on the download tail, which already
    /// pays the same scan in `pre_corr_verdict`". Both halves of that
    /// were wrong. `pre_corr_verdict` drives its join from `pre_corr`
    /// (967 rows on a long-running install), so it pays nothing of that
    /// kind; and
    /// `LOWER()` disqualifies the BINARY `idx_rel_stem`, so this was
    /// `SCAN releases` over 38 M rows of a 55.9 GB database - taken
    /// under `with_index_mut`, the write mutex, on the tail of every
    /// finished obfuscated download. The exact same trap, in the exact
    /// same shape, that `idx_rel_stem_lower` was created to close for
    /// the predb sweep (see `schema.rs`).
    ///
    /// So the fallback asks that partial index for the unnamed rows it
    /// covers, and asks `idx_rel_pre_named` for the already-named
    /// remainder - 13 k rows there against 38 M here, measured at 27 ms
    /// on a total miss. Two indexed questions, same answer set as the
    /// one scan: nothing is given up but the wedge.
    pub fn release_ids_by_stem(&self, posted: &str) -> rusqlite::Result<Vec<i64>> {
        let stem = crate::names::release_stem(posted);
        if stem.is_empty() {
            return Ok(Vec::new());
        }
        let mut ids: Vec<i64> = {
            let mut sel = self
                .db
                .prepare_cached("SELECT id FROM releases WHERE stem=?1 LIMIT 3")?;
            sel.query_map([&stem], |r| r.get(0))?
                .collect::<rusqlite::Result<_>>()?
        };
        if ids.is_empty() {
            let lower = stem.to_ascii_lowercase();
            // The `pre_title` arms are what make each query indexable,
            // and between them they cover every row: keep them exactly
            // complementary, or a stem stops resolving.
            for sql in [
                "SELECT id FROM releases WHERE pre_title='' AND LOWER(stem)=?1 LIMIT 3",
                "SELECT id FROM releases WHERE pre_title<>'' AND LOWER(stem)=?1 LIMIT 3",
            ] {
                let mut sel = self.db.prepare_cached(sql)?;
                ids.extend(
                    sel.query_map([&lower], |r| r.get::<_, i64>(0))?
                        .collect::<rusqlite::Result<Vec<_>>>()?,
                );
                if ids.len() >= 3 {
                    ids.truncate(3);
                    break;
                }
            }
        }
        Ok(ids)
    }

    /// One-shot repair for releases whose applied name is exactly its
    /// own text twice: put the single half back, through the naming
    /// seam.
    ///
    /// # Why a repair is needed at all
    ///
    /// The doubling is the POSTER's - it rides the quoted filename in
    /// that post's own subjects (`crate::release::undoubled`) - so every
    /// lane reading that release's stem mints the same doubled name at
    /// the same evidence tier. `apply_named` now folds it on the way in,
    /// but the rows written before that cannot heal on their own: a
    /// correct claim and a doubled standing name grade EQUAL in
    /// `applied_strength`, so the correct one is recorded and refused,
    /// every time, forever. Measured 1 Sep 2026 on the live index: 285
    /// of 24,996 named releases (1.14%).
    ///
    /// `apply_proven_name` now folds that exact pair too, but only when
    /// a claim happens to arrive; this walks the rows that already carry
    /// their own answer inside their own name.
    ///
    /// # Driving it
    ///
    /// Straight off `releases`, which the CDATA repair beside it
    /// refuses to do - and it is safe HERE because `idx_rel_pre_named`
    /// is a partial index on exactly `pre_title<>''`: ~25 K entries on a
    /// 22 M-row table, not a table scan. There is no narrower driver -
    /// unlike the spot repairs, this defect is not confined to one lane.
    ///
    /// The name is cleared and re-applied through `apply_named` rather
    /// than UPDATEd, so `title_key`, `kind`, `junk`, the FTS row and the
    /// watchlist all re-derive from the corrected title - and the row's
    /// OWN `pre_source` is re-stamped, never a hardcoded label, or a
    /// `proven:` row would be demoted to the unarbitrable `i32::MAX`
    /// grade `applied_strength` gives anything without that prefix. One
    /// transaction per row for the clear-and-reapply pair: as two
    /// autocommit statements a kill between them leaves the row un-named
    /// AND outside this pass's own predicate, so the re-run never
    /// revisits it.
    ///
    /// The `stem` is deliberately LEFT ALONE, doubled and all: it is the
    /// wire's own filename and half of a release's identity key, so
    /// rewriting it would only make the next scan of the same unchanged
    /// post mint a second row beside this one.
    pub fn repair_doubled_pre_titles(&mut self, now: i64) -> rusqlite::Result<usize> {
        if self.kv_get("doubled_pre_title_fix_v1").is_some() {
            return Ok(0);
        }
        let broken: Vec<(i64, String, String)> = {
            let mut stmt = self
                .db
                .prepare("SELECT id, pre_title, pre_source FROM releases WHERE pre_title<>''")?;
            let rows = stmt.query_map([], |r| {
                Ok((
                    r.get::<_, i64>(0)?,
                    r.get::<_, String>(1)?,
                    r.get::<_, String>(2)?,
                ))
            })?;
            rows.filter_map(|r| match r {
                Ok((id, title, label)) => {
                    crate::release::undoubled(&title).map(|half| Ok((id, half.to_string(), label)))
                }
                Err(e) => Some(Err(e)),
            })
            .collect::<rusqlite::Result<Vec<_>>>()?
        };
        let mut fixed = 0usize;
        for (rid, half, label) in &broken {
            let tx = rusqlite::Transaction::new_unchecked(
                &self.db,
                rusqlite::TransactionBehavior::Immediate,
            )?;
            tx.execute("UPDATE releases SET pre_title='' WHERE id=?1", [rid])?;
            if self.apply_named(*rid, half, label, now)? {
                fixed += 1;
            }
            tx.commit()?;
        }
        self.kv_set("doubled_pre_title_fix_v1", "1")?;
        Ok(fixed)
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};
    use crate::predb::{PreKind, PreLine};

    /// One tag, one test. Two tests sharing a tag share the directory
    /// under a plain `cargo test --lib` (one process, threaded), where
    /// this wipe races the other test's run - nextest hides it by
    /// giving every test its own pid.
    fn dir(tag: &str) -> std::path::PathBuf {
        let d =
            std::env::temp_dir().join(format!("nzbfast-index-claims-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).unwrap();
        d
    }

    fn claim(name: &str, e: NameEvidence, key: &str, src: &str) -> NameClaim {
        NameClaim {
            name: name.into(),
            evidence: e,
            key: key.into(),
            source: src.into(),
        }
    }

    fn named(ix: &Index, rid: i64) -> (String, String) {
        ix.db
            .query_row(
                "SELECT pre_title, pre_source FROM releases WHERE id=?1",
                [rid],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap()
    }

    /// One obfuscated single-file release, freshly ingested; returns id.
    fn seed(ix: &mut Index, stem: &str, msgid: &str) -> i64 {
        ix.ingest(
            "alt.binaries.test",
            &[entry(
                &format!(r#""{stem}.rar" yEnc (1/1)"#),
                "p@x",
                msgid,
                900,
            )],
            1000,
        )
        .unwrap();
        let ids = ix.release_ids_by_stem(&format!("{stem}.rar")).unwrap();
        assert_eq!(ids.len(), 1, "seed release should resolve unambiguously");
        ids[0]
    }

    const NAME: &str = "Real.Show.S01E01.720p.WEB-GRP";

    /// The ledger can outrun the decision: a second process (the CLI
    /// census) writes a claim row and dies before deciding, or a gate
    /// bug refuses a correct claim and the fix lands later. Nothing
    /// re-fires apply_proven_name for those rows on its own -
    /// claims_replay is that re-fire, and it must name a release whose
    /// stored claims already prove the name under today's rules.
    #[test]
    fn replay_applies_a_name_the_ledger_already_proves() {
        let d = dir("replay");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "aj7dkQ9c2mZpQvB1x", "r1@x");
        // A lone hash16k claim records - it cannot name alone...
        assert_eq!(
            ix.apply_proven_name(
                rid,
                &claim(NAME, NameEvidence::Hash16kLen, "h1", "par-hash"),
                100,
            )
            .unwrap(),
            ProvenOutcome::Recorded
        );
        // ...and the INDEPENDENT agreeing claim that would tip it over
        // lands only in the ledger (the writer died before deciding).
        ix.db
            .execute(
                "INSERT INTO name_claims(release_id, name, tier, key, source, at)
                 VALUES(?1, ?2, ?3, ?4, ?5, 101)",
                rusqlite::params![rid, NAME, NameEvidence::Hash16kLen.tag(), "h2", "srrdb"],
            )
            .unwrap();
        assert_eq!(named(&ix, rid).0, "", "nothing decided yet");

        assert_eq!(ix.claims_replay(200, 100).unwrap(), 1);
        assert_eq!(named(&ix, rid).0, NAME);
        // Idempotent: a second pass finds nothing left to do.
        assert_eq!(ix.claims_replay(300, 100).unwrap(), 0);
        teardown(&d, ix);
    }

    /// Every other fixture here posts a `.rar`, which `release_stem`
    /// strips, so the stored stem comes out bare and the "is the stem
    /// readable?" gate sees a single token. A bare `.7z` is NOT
    /// stripped, so the whole `.7z` band stores stems like
    /// "uHpvK7XR….7z" - two tokens, which the whole-stem detector calls
    /// readable. The byte prober's first eight production names were
    /// correct, read out of the archives' own end headers, and every
    /// one of them was refused on that basis (:6789, 10 Aug).
    #[test]
    fn a_blob_stem_that_kept_its_extension_is_not_a_readable_name() {
        let d = dir("ext7z");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[entry(
                r#""uHpvK7XRYNxbvVQbxuW2fGBAPRpMkJuc.7z" yEnc (1/1)"#,
                "p@x",
                "z1",
                900,
            )],
            1000,
        )
        .unwrap();
        let rid = ix
            .release_ids_by_stem("uHpvK7XRYNxbvVQbxuW2fGBAPRpMkJuc.7z")
            .unwrap()[0];
        let stem: String = ix
            .db
            .query_row("SELECT stem FROM releases WHERE id=?1", [rid], |r| r.get(0))
            .unwrap();
        assert!(
            stem.ends_with(".7z"),
            "the band's shape: the extension survives into the stem, got {stem:?}"
        );

        let out = ix
            .apply_proven_name(
                rid,
                &claim(NAME, NameEvidence::BodyProbe, "7z1", "body/7z"),
                100,
            )
            .unwrap();
        assert_eq!(
            out,
            ProvenOutcome::Applied,
            "a blob stem carrying an extension is not a name worth keeping"
        );
        assert_eq!(named(&ix, rid).0, NAME);
        teardown(&d, ix);
    }

    /// The other half of the same gate: stripping the extension must
    /// not turn a genuinely readable post into a rename target. This is
    /// R6's trap row, wearing a `.7z`.
    #[test]
    fn a_readable_stem_still_stands_under_its_extension() {
        let d = dir("ext7zok");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[entry(
                r#""Other.Show.S02E05.1080p.WEB-DL.x264-GRP.7z" yEnc (1/1)"#,
                "p@x",
                "z2",
                900,
            )],
            1000,
        )
        .unwrap();
        let rid = ix
            .release_ids_by_stem("Other.Show.S02E05.1080p.WEB-DL.x264-GRP.7z")
            .unwrap()[0];
        let out = ix
            .apply_proven_name(
                rid,
                &claim(NAME, NameEvidence::BodyProbe, "7z2", "body/7z"),
                100,
            )
            .unwrap();
        assert_eq!(
            out,
            ProvenOutcome::Conflict,
            "the poster's own readable name outranks a disagreeing claim"
        );
        assert_eq!(named(&ix, rid).0, "", "and it must not be overwritten");
        teardown(&d, ix);
    }

    /// The furniture-agreement gate, on the shapes measured live
    /// (:6789, 10 Aug): a release's own sample/screenshot rows are
    /// joined by its posted NZB's msgid set, and their stems are the
    /// claim's own name wearing noise. Those stand QUIETLY (Recorded,
    /// no conflict, never renamed - apply_named would re-score junk
    /// from the clean title and surface the furniture row on the
    /// wall). A furniture stem that still disagrees after the fold -
    /// an episode screenshot against its season pack's claim, an
    /// abbreviated sample name - keeps standing as a loud Conflict.
    #[test]
    fn furniture_wearing_the_claims_own_name_stands_quietly() {
        let d = dir("furniture");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let quiet = [
            // prefix noise, live row 2312356
            (
                "sample-all.star.family.feud.nz.s01e02.720p.hdtv.x264-fihtv.mkv",
                "All.Star.Family.Feud.NZ.S01E02.720p.HDTV.x264-FiHTV",
            ),
            // suffix noise, live row 2310400
            (
                "alaska.mega.machines.s01e02.720p.hdtv.x264-dhd-sample.mkv",
                "Alaska.Mega.Machines.S01E02.720p.HDTV.x264-DHD",
            ),
            // furniture under a media extension, live row 988862
            (
                "futbol.360.jugadas.maestras.s01e02.hdtv.x264-cbfm.sample.mkv",
                "Futbol.360.Jugadas.Maestras.S01E02.HDTV.x264-CBFM",
            ),
            // screenshot post: the double media extension IS the noise
            (
                "Costao.2025.1080p.ZEE5.WEB-DL.DDP5.1.H.264-DTR.mkv.png",
                "Costao.2025.1080p.ZEE5.WEB-DL.DDP5.1.H.264-DTR",
            ),
        ];
        for (i, (posted, claimed)) in quiet.iter().enumerate() {
            ix.ingest(
                "alt.binaries.test",
                &[entry(
                    &format!(r#""{posted}" yEnc (1/1)"#),
                    "p@x",
                    &format!("furn{i}"),
                    900,
                )],
                1000,
            )
            .unwrap();
            let rid = *ix
                .db
                .prepare("SELECT id FROM releases ORDER BY id DESC LIMIT 1")
                .unwrap()
                .query_map([], |r| r.get::<_, i64>(0))
                .unwrap()
                .next()
                .unwrap()
                .as_ref()
                .unwrap();
            let out = ix
                .apply_proven_name(
                    rid,
                    &claim(
                        claimed,
                        NameEvidence::MsgidSet,
                        &format!("mk{i}"),
                        "nzb-import",
                    ),
                    100,
                )
                .unwrap();
            assert_eq!(
                out,
                ProvenOutcome::Recorded,
                "furniture agreeing with the claim is not a conflict: {posted:?}"
            );
            assert_eq!(named(&ix, rid).0, "", "and the stem stands: {posted:?}");
        }
        // The rule's reason to exist, unchanged: a per-episode
        // screenshot still DISAGREES with its season pack's claim
        // after the fold, and an abbreviated sample name is not the
        // claim's name at all. Both keep standing as conflicts.
        let loud = [
            (
                "Gram.Chikitsalay.S01E05.Bohni.1080p.AMZN.WEB-DL.DDP5.1.H.264-DTR.mkv.png",
                "Gram.Chikitsalay.S01.1080p.AMZN.WEB-DL.DDP5.1.H.264-DTR",
            ),
            (
                "np-primal-sample.avi",
                "Primal.German.AC3.2010.DVDRip.XviD-NOPiTY",
            ),
        ];
        for (i, (posted, claimed)) in loud.iter().enumerate() {
            ix.ingest(
                "alt.binaries.test",
                &[entry(
                    &format!(r#""{posted}" yEnc (1/1)"#),
                    "p@x",
                    &format!("loud{i}"),
                    900,
                )],
                1000,
            )
            .unwrap();
            let rid = *ix
                .db
                .prepare("SELECT id FROM releases ORDER BY id DESC LIMIT 1")
                .unwrap()
                .query_map([], |r| r.get::<_, i64>(0))
                .unwrap()
                .next()
                .unwrap()
                .as_ref()
                .unwrap();
            let out = ix
                .apply_proven_name(
                    rid,
                    &claim(
                        claimed,
                        NameEvidence::MsgidSet,
                        &format!("lk{i}"),
                        "nzb-import",
                    ),
                    100,
                )
                .unwrap();
            assert_eq!(
                out,
                ProvenOutcome::Conflict,
                "a folded stem that still disagrees keeps standing loudly: {posted:?}"
            );
            assert_eq!(named(&ix, rid).0, "", "{posted:?}");
        }
        teardown(&d, ix);
    }

    /// The replay recovers a verdict a past gate got wrong, and touches
    /// nothing else. All three rows carry a stored claim and none has a
    /// `pre_title`; only the first is a stale VERDICT rather than a
    /// decision the gate meant to make.
    #[test]
    fn replay_recovers_stale_verdicts_and_leaves_judgements_alone() {
        let d = dir("replay-verdicts");
        let mut ix = Index::open(&d.join("index.db")).unwrap();

        // 1. The stranded shape: blob stem, top-tier claim, unapplied.
        //    Written straight to name_claims - the state the old gate
        //    left behind, which today's gate can no longer produce.
        let dark = seed(&mut ix, "9f2c1ab7e40d6835bb", "r1");
        // 2. A readable stem the gate refused ON PURPOSE.
        let readable = {
            ix.ingest(
                "alt.binaries.test",
                &[entry(
                    r#""Some.Show.S01E04.Real.Episode.Title.1080p.WEB-GRP.7z" yEnc (1/1)"#,
                    "p@x",
                    "r2",
                    900,
                )],
                1000,
            )
            .unwrap();
            ix.release_ids_by_stem("Some.Show.S01E04.Real.Episode.Title.1080p.WEB-GRP.7z")
                .unwrap()[0]
        };
        // 3. A blob whose only claim is too weak to name alone.
        let weak = seed(&mut ix, "c81de4470aa9f2b6d3", "r3");

        for (rid, tier, key) in [
            (dark, "body-probe", "k1"),
            (readable, "body-probe", "k2"),
            (weak, "hash16k-len", "k3"),
        ] {
            ix.db
                .execute(
                    "INSERT INTO name_claims(release_id, name, tier, key, source, at)
                     VALUES(?1, ?2, ?3, ?4, 'body/7z', 50)",
                    rusqlite::params![rid, NAME, tier, key],
                )
                .unwrap();
        }

        assert_eq!(
            ix.claims_replay(200, 1000).unwrap(),
            1,
            "only the blob-stem row with a name-alone claim is a stale verdict"
        );
        assert_eq!(named(&ix, dark).0, NAME, "the stranded name is recovered");
        assert_eq!(
            named(&ix, readable).0,
            "",
            "a readable stem is a judgement the gate meant - never replayed over"
        );
        assert_eq!(
            named(&ix, weak).0,
            "",
            "replay is not a licence to relax the evidence ladder"
        );

        // Idempotent: a second start must not re-apply or re-count.
        assert_eq!(ix.claims_replay(200, 1000).unwrap(), 0);
        teardown(&d, ix);
    }

    /// A replay window full of rows it cannot name must not hide the
    /// row it can.
    ///
    /// The selection is exactly "unnamed release with a claim on file",
    /// and a row the decision refuses stays in that set for good - so an
    /// uncursored `LIMIT n` handed every future start the same n
    /// unnameable rows and never reached row n+1 (M5, 10 Aug sweep).
    /// With `limit` 2 and three rows, the stranded name at the back has
    /// to be reached by a later pass.
    #[test]
    fn replay_walks_past_a_window_of_rows_it_cannot_name() {
        let d = dir("replay-walk");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        // Two rows whose only claim is too weak to name alone - they can
        // never leave the selection - and then the stranded one.
        let weak1 = seed(&mut ix, "aa11bb22cc33dd44e1", "w1");
        let weak2 = seed(&mut ix, "aa11bb22cc33dd44e2", "w2");
        let stranded = seed(&mut ix, "aa11bb22cc33dd44e3", "w3");
        assert!(
            weak1 < weak2 && weak2 < stranded,
            "the stranded row must sit BEHIND the window"
        );
        for (rid, tier, key) in [
            (weak1, "hash16k-len", "k1"),
            (weak2, "hash16k-len", "k2"),
            (stranded, "body-probe", "k3"),
        ] {
            ix.db
                .execute(
                    "INSERT INTO name_claims(release_id, name, tier, key, source, at)
                     VALUES(?1, ?2, ?3, ?4, 'body/7z', 50)",
                    rusqlite::params![rid, NAME, tier, key],
                )
                .unwrap();
        }
        // First pass sees only the two it cannot name...
        assert_eq!(ix.claims_replay(200, 2).unwrap(), 0);
        assert_eq!(named(&ix, stranded).0, "");
        // ...and the next one reaches the row behind them.
        assert_eq!(ix.claims_replay(300, 2).unwrap(), 1);
        assert_eq!(
            named(&ix, stranded).0,
            NAME,
            "the walk never reached the stranded claim"
        );
        teardown(&d, ix);
    }

    /// The load-bearing red-team rule: hash16k never auto-names alone,
    /// adjacency never names (and never corroborates), and an
    /// independent agreeing claim is what tips a weak tier over.
    #[test]
    fn weak_evidence_waits_for_independent_corroboration() {
        let d = dir("weak");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "a9f3c77d0b12e4f5a6", "w1");

        let out = ix
            .apply_proven_name(rid, &claim(NAME, NameEvidence::Hash16kLen, "h1", "t"), 100)
            .unwrap();
        assert_eq!(out, ProvenOutcome::Recorded);
        assert_eq!(named(&ix, rid).0, "", "hash16k alone must not name");

        // Association evidence is recorded but corroborates nothing.
        let out = ix
            .apply_proven_name(rid, &claim(NAME, NameEvidence::Adjacency, "adj", "t"), 101)
            .unwrap();
        assert_eq!(out, ProvenOutcome::Recorded);
        assert_eq!(named(&ix, rid).0, "", "adjacency must not corroborate");

        // Re-proving the identical fact is not a second opinion.
        let out = ix
            .apply_proven_name(rid, &claim(NAME, NameEvidence::Hash16kLen, "h1", "t"), 102)
            .unwrap();
        assert_eq!(out, ProvenOutcome::Recorded);
        assert_eq!(
            ix.name_claims(rid).unwrap().len(),
            2,
            "identical re-claims must not duplicate"
        );

        // An independent agreeing hash is what tips it over.
        let out = ix
            .apply_proven_name(rid, &claim(NAME, NameEvidence::Hash16kLen, "h2", "t2"), 103)
            .unwrap();
        assert_eq!(out, ProvenOutcome::Applied);
        let (title, source) = named(&ix, rid);
        assert_eq!(title, NAME);
        assert!(
            source.starts_with("proven:hash16k-len"),
            "provenance names the tier: {source}"
        );
        assert_eq!(ix.name_claims(rid).unwrap().len(), 3);
        teardown(&d, ix);
    }

    /// Strong evidence names at once; stronger displaces weaker; equal
    /// strength never flips a name; the audit trail keeps every claim.
    #[test]
    fn the_strongest_claim_wins_and_equal_strength_never_flips() {
        let d = dir("strong");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "b2c4e6a8d0f1234567", "s1");

        let out = ix
            .apply_proven_name(
                rid,
                &claim(NAME, NameEvidence::Crc32Len, "cafe1234", "srrdb"),
                100,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Applied);
        let (title, source) = named(&ix, rid);
        assert_eq!(title, NAME);
        assert!(source.starts_with("proven:crc32-len:srrdb"), "{source}");

        // A stronger tier with a DIFFERENT name displaces it.
        const OTHER: &str = "Other.Show.S02E05.1080p.WEB-XYZ";
        let out = ix
            .apply_proven_name(
                rid,
                &claim(OTHER, NameEvidence::Par2SetId, "setid01", "pesto"),
                200,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Replaced);
        let (title, source) = named(&ix, rid);
        assert_eq!(title, OTHER);
        assert!(source.starts_with("proven:par2-set-id:pesto"), "{source}");

        // A weaker disagreeing claim is recorded; the winner stands.
        let out = ix
            .apply_proven_name(
                rid,
                &claim(NAME, NameEvidence::Crc32Len, "beef5678", "srrdb"),
                300,
            )
            .unwrap();
        assert_eq!(
            out,
            ProvenOutcome::Confirmed,
            "winner still agrees with itself"
        );
        assert_eq!(named(&ix, rid).0, OTHER);

        // An EQUAL-strength disagreeing claim never flips the name.
        const THIRD: &str = "Third.Show.S03E01.2160p.WEB-AAA";
        let out = ix
            .apply_proven_name(
                rid,
                &claim(THIRD, NameEvidence::Par2SetId, "setid02", "pesto"),
                400,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Conflict);
        assert_eq!(named(&ix, rid).0, OTHER, "equal strength must not flip");
        assert_eq!(ix.name_claims(rid).unwrap().len(), 4);
        teardown(&d, ix);
    }

    /// Unusable claims are refused whole: paths are not release names,
    /// and an unknown release has nowhere to put a claim.
    #[test]
    fn path_shaped_names_and_unknown_releases_are_rejected() {
        let d = dir("reject");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "c1d2e3f4a5b6789012", "r1");
        for bad in ["../../etc/Evil-GRP", "a\\b-GRP", ".hidden-GRP", "  "] {
            let out = ix
                .apply_proven_name(rid, &claim(bad, NameEvidence::Par2SetId, "k", "t"), 100)
                .unwrap();
            assert_eq!(out, ProvenOutcome::Rejected, "{bad:?}");
        }
        assert!(ix.name_claims(rid).unwrap().is_empty());
        let out = ix
            .apply_proven_name(
                999_999,
                &claim(NAME, NameEvidence::Par2SetId, "k", "t"),
                100,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Rejected);
        teardown(&d, ix);
    }

    /// Body truth settles a live correlation record exactly the way the
    /// download-time verdict would: disagreement rejects (and the wrong
    /// name comes off), agreement confirms and arms the exact legs with
    /// the proven pairing.
    #[test]
    fn proven_names_settle_correlation_claims() {
        let d = dir("settle");
        let mut ix = Index::open(&d.join("index.db")).unwrap();

        // (a) disagreement: the human-picked correlation name is wrong.
        let rid = seed(&mut ix, "d4e5f6a7b8c9012345", "x1");
        ix.predb_store(
            &[PreLine {
                kind: PreKind::New,
                title: NAME.into(),
                source: "PRE".into(),
                ..Default::default()
            }],
            50,
        )
        .unwrap();
        let predb_id: i64 = ix
            .db
            .query_row("SELECT id FROM predb WHERE title=?1", [NAME], |r| r.get(0))
            .unwrap();
        assert!(ix.pre_assign(rid, predb_id, 60).unwrap());
        assert_eq!(named(&ix, rid).0, NAME);

        const TRUTH: &str = "Actually.This.S05E05.1080p.WEB-TRU";
        let out = ix
            .apply_proven_name(rid, &claim(TRUTH, NameEvidence::Par2SetId, "sid", "t"), 100)
            .unwrap();
        assert_eq!(out, ProvenOutcome::Replaced);
        assert_eq!(named(&ix, rid).0, TRUTH);
        let status: String = ix
            .db
            .query_row(
                "SELECT status FROM pre_corr WHERE release_id=?1",
                [rid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(status, "rejected");

        // (b) agreement: confirmed, and the proven pairing back-feeds
        // the predb row's filename so the exact legs arm for reposts.
        let rid2 = seed(&mut ix, "e5f6a7b8c9d0123456", "x2");
        const NAME2: &str = "Second.Show.S02E02.720p.WEB-GRP";
        ix.predb_store(
            &[PreLine {
                kind: PreKind::New,
                title: NAME2.into(),
                source: "PRE".into(),
                ..Default::default()
            }],
            50,
        )
        .unwrap();
        let predb_id2: i64 = ix
            .db
            .query_row("SELECT id FROM predb WHERE title=?1", [NAME2], |r| r.get(0))
            .unwrap();
        assert!(ix.pre_assign(rid2, predb_id2, 60).unwrap());
        let out = ix
            .apply_proven_name(
                rid2,
                &claim(NAME2, NameEvidence::Par2SetId, "sid2", "t"),
                100,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Confirmed);
        let (title, source) = named(&ix, rid2);
        assert_eq!(title, NAME2, "agreement keeps the name");
        assert!(
            source.starts_with("proven:"),
            "provenance upgraded: {source}"
        );
        let (status, fed): (String, String) = ix
            .db
            .query_row(
                "SELECT c.status, p.filename FROM pre_corr c
                   JOIN predb p ON p.id=c.predb_id WHERE c.release_id=?1",
                [rid2],
                |r| Ok((r.get(0)?, r.get(1)?)),
            )
            .unwrap();
        assert_eq!(status, "confirmed");
        assert_eq!(
            fed, "e5f6a7b8c9d0123456",
            "proven pairing arms the exact legs"
        );
        teardown(&d, ix);
    }

    /// An exact-leg relay name is never displaced automatically - a
    /// disagreeing proof is recorded as a conflict to surface, exactly
    /// the fight `pre_corr_verdict` also refuses to referee.
    #[test]
    fn exact_leg_names_are_never_displaced() {
        let d = dir("exact");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        // Feed first, so ingest itself pairs the posted filename.
        ix.predb_store(
            &[PreLine {
                kind: PreKind::New,
                title: NAME.into(),
                filename: "f0e1d2c3b4a5968778.rar".into(),
                source: "PRE".into(),
                ..Default::default()
            }],
            50,
        )
        .unwrap();
        let rid = seed(&mut ix, "f0e1d2c3b4a5968778", "e1");
        let (title, source) = named(&ix, rid);
        assert_eq!(title, NAME);
        assert!(source.starts_with("predb"), "{source}");

        const OTHER: &str = "Some.Other.Thing.S01E01.720p-ZZZ";
        let out = ix
            .apply_proven_name(
                rid,
                &claim(OTHER, NameEvidence::MsgidSet, "digest", "t"),
                100,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Conflict);
        assert_eq!(named(&ix, rid).0, NAME, "relay fact stays put");
        assert_eq!(ix.name_claims(rid).unwrap().len(), 1, "truth is kept");
        teardown(&d, ix);
    }

    /// The reverse message-id map: the lowest parts of each file are
    /// keyed at ingest (bracket-insensitively), joins count DISTINCT
    /// ids per release, and deleting a release cleans its rows so a
    /// reused rowid can never inherit someone else's identity.
    #[test]
    fn msgid_lookup_joins_keys_and_eviction_cleans_up() {
        let d = dir("msgid");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let subj = |n: u32| format!(r#""aa11bb22cc33dd44ee.rar" yEnc ({n}/5)"#);
        let parts: Vec<_> = (1..=5)
            .map(|n| entry(&subj(n), "p@x", &format!("a{n}"), 900))
            .collect();
        ix.ingest("alt.binaries.test", &parts, 1000).unwrap();
        let a = ix.release_ids_by_stem("aa11bb22cc33dd44ee").unwrap()[0];
        let b = seed(&mut ix, "bb22cc33dd44ee55ff", "b1");

        // NZB-side probes carry brackets or not; both hash alike. Only
        // the 3 lowest parts are keyed, extra probes miss harmlessly.
        let hits = ix
            .find_releases_by_msgids(["<a1>", "a2", "a3", "a4", "a5", "<b1>", "nope"])
            .unwrap();
        assert_eq!(hits, vec![(a, 3), (b, 1)]);

        // A claim rides on the release; deleting the release must strip
        // both its claims and its map rows (rowids get reused).
        ix.apply_proven_name(a, &claim(NAME, NameEvidence::Adjacency, "", "t"), 10)
            .unwrap();
        ix.db
            .execute("DELETE FROM releases WHERE id=?1", [a])
            .unwrap();
        let hits = ix.find_releases_by_msgids(["a1", "b1"]).unwrap();
        assert_eq!(hits, vec![(b, 1)]);
        let orphans: i64 = ix
            .db
            .query_row(
                "SELECT COUNT(*) FROM name_claims WHERE release_id=?1",
                [a],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(orphans, 0);
        teardown(&d, ix);
    }

    /// A readable stem IS a name: a disagreeing claim - the measured
    /// case is a season-pack NZB quorum-joining its own per-episode
    /// rows - must not stamp over it, while an agreeing claim may
    /// still land as a canonical-spelling and provenance upgrade.
    #[test]
    fn a_readable_stem_is_a_name_the_claims_layer_respects() {
        let d = dir("readable");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[entry(
                r#""Great.Show.S01E03.1080p.WEB-GRP.rar" yEnc (1/1)"#,
                "p@x",
                "rs1",
                900,
            )],
            1000,
        )
        .unwrap();
        let rid = ix
            .release_ids_by_stem("Great.Show.S01E03.1080p.WEB-GRP.rar")
            .unwrap()[0];

        // The season-pack shape: strong join, wrong specificity.
        let out = ix
            .apply_proven_name(
                rid,
                &claim(
                    "Great.Show.S01.COMPLETE.1080p.WEB-GRP",
                    NameEvidence::MsgidSet,
                    "packkey",
                    "posted-nzb",
                ),
                100,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Conflict);
        assert_eq!(named(&ix, rid).0, "", "the readable stem stands");

        // An agreeing claim is corroboration, and may apply.
        let out = ix
            .apply_proven_name(
                rid,
                &claim(
                    "Great Show S01E03 1080p WEB GRP",
                    NameEvidence::MsgidSet,
                    "epkey",
                    "posted-nzb",
                ),
                200,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Applied);
        assert_eq!(named(&ix, rid).0, "Great Show S01E03 1080p WEB GRP");
        teardown(&d, ix);
    }

    /// The canonical msgid-set key: bracket/order/duplicate-insensitive,
    /// so every lane derives the same key for the same id set and two
    /// lanes proving the same join corroborate instead of colliding.
    #[test]
    fn the_msgid_set_key_is_canonical() {
        let a = msgid_set_key(["<x@1>", "y@2", "z@3"]);
        let b = msgid_set_key(["z@3", "<y@2>", "x@1", "y@2"]);
        assert_eq!(a, b);
        assert_eq!(a.len(), 32);
        assert!(a.chars().all(|c| c.is_ascii_hexdigit()));
        assert_ne!(
            a,
            msgid_set_key(["x@1", "y@2"]),
            "a subset is a different set"
        );
    }

    /// A name read out of the release's own bytes outranks every
    /// cross-referenced binding, an NZB msgid join included.
    #[test]
    fn a_body_probe_outranks_an_nzb_join() {
        let d = dir("body");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "9a8b7c6d5e4f321098", "bp1");
        let out = ix
            .apply_proven_name(
                rid,
                &claim(NAME, NameEvidence::MsgidSet, "setkey", "posted-nzb"),
                100,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Applied);
        const TRUTH: &str = "Inner.Truth.S04E04.1080p.WEB-TRU";
        let out = ix
            .apply_proven_name(
                rid,
                &claim(TRUTH, NameEvidence::BodyProbe, "", "body/7z"),
                200,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Replaced);
        let (title, source) = named(&ix, rid);
        assert_eq!(title, TRUTH);
        assert!(source.starts_with("proven:body-probe:body/7z"), "{source}");
        teardown(&d, ix);
    }

    /// Rows ingested before the map existed are keyed by the chunked
    /// backfill, and the done-stamp keeps it from re-running.
    #[test]
    fn the_backfill_keys_pre_existing_rows_once() {
        let d = dir("backfill");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "0011223344556677aa", "bf1");
        // Simulate a pre-substrate database: rows exist, map does not.
        ix.db.execute("DELETE FROM msgid_map", []).unwrap();
        ix.db
            .execute(
                "DELETE FROM kv WHERE k IN ('msgid_map_fill','msgid_map_at')",
                [],
            )
            .unwrap();
        assert!(ix.find_releases_by_msgids(["bf1"]).unwrap().is_empty());
        msgid_map_backfill(&mut ix.db);
        assert_eq!(ix.find_releases_by_msgids(["bf1"]).unwrap(), vec![(rid, 1)]);
        assert_eq!(ix.kv_get("msgid_map_fill").as_deref(), Some("1"));
        teardown(&d, ix);
    }

    /// The per-lap slice reports whether the fill is COMPLETE, so a
    /// caller's slice loop can stop early: a zero budget still lands one
    /// chunk and reports "more to do", and the call after the last chunk
    /// reports done and stamps the flag. This is the contract the
    /// maintenance lap relies on; the open-time call alone left a real
    /// index 19.4M releases short (see `msgid_map_backfill_slice`).
    #[test]
    fn the_backfill_slice_says_when_it_is_finished() {
        let d = dir("backfill_slice");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "0011223344556677bb", "bs1");
        ix.db.execute("DELETE FROM msgid_map", []).unwrap();
        ix.db
            .execute(
                "DELETE FROM kv WHERE k IN ('msgid_map_fill','msgid_map_at')",
                [],
            )
            .unwrap();
        // First slice: one chunk lands (the only row), deadline already
        // past, so it returns before discovering the table is drained.
        assert!(!ix.msgid_map_backfill_slice(std::time::Duration::ZERO));
        assert_eq!(ix.find_releases_by_msgids(["bs1"]).unwrap(), vec![(rid, 1)]);
        assert_eq!(ix.kv_get("msgid_map_fill"), None);
        let (cursor, keys) = ix.msgid_map_progress();
        assert!(
            cursor > 0 && keys >= 1,
            "progress reads the cursor and the key count"
        );
        // Second slice: nothing left, flag stamped, done.
        assert!(ix.msgid_map_backfill_slice(std::time::Duration::ZERO));
        assert_eq!(ix.kv_get("msgid_map_fill").as_deref(), Some("1"));
        // And once done it stays a cheap no-op that still says done.
        assert!(ix.msgid_map_backfill_slice(std::time::Duration::from_secs(1)));
        teardown(&d, ix);
    }

    // ---- H5: the apply_pn savepoint (Codex 10 Aug read-only sweep) ---
    //
    // `apply_proven_name` is a read-decide-write across several
    // statements - claim insert, revoke, apply, correlation settle - and
    // a second WRITER PROCESS exists by design: the CLI census
    // (`nzbfast nzb-import --apply`) runs beside the daemon against the
    // same WAL index. The savepoint makes the decision atomic. Codex
    // filed the finding as needing "a genuine second-process regression
    // test" and nothing exercised either half of the contract.
    //
    // Two connections IS the second writer here: the daemon and the CLI
    // are two connections on one WAL file, and everything the savepoint
    // defends against is visible at that boundary.

    /// A concurrent writer's commit cannot make this connection publish
    /// half a decision. The second handle names the release while this
    /// one is holding an older snapshot; SQLite refuses the stale write
    /// (BUSY_SNAPSHOT - the busy handler is deliberately not consulted,
    /// because retrying a stale snapshot can never succeed), and the
    /// caller gets an error rather than a partly-applied name.
    ///
    /// Worth being exact about what this pins and what it does not: it
    /// passes with the savepoint REMOVED, because the stale write is
    /// refused at the very first statement and autocommit rolls that one
    /// statement back on its own. What it pins is the boundary - that
    /// the conflict surfaces as an error at all, that it is the stale
    /// writer and not the committed one that loses, and that the loser
    /// leaves no orphan claim row. The savepoint's own contract is
    /// pinned by `a_failed_apply_never_leaves_the_release_nameless`,
    /// which fails without it.
    #[test]
    fn a_second_writers_commit_cannot_half_apply_a_name() {
        let d = dir("h5-two-writers");
        let db = d.join("index.db");
        let mut a = Index::open(&db).unwrap();
        let rid = seed(&mut a, "5f1c0d99ab7e26340c", "h5a");
        let mut b = Index::open(&db).unwrap();

        // Handle A takes a read snapshot and holds it. This is the
        // daemon mid-decision: it has read the release's naming state
        // and has not written yet.
        a.db.execute_batch("BEGIN").unwrap();
        assert_eq!(named(&a, rid).0, "");

        // Handle B - the census process - names the release and commits.
        assert_eq!(
            b.apply_proven_name(
                rid,
                &claim(
                    "Kilo.Film.2024.1080p.BluRay.x264-GRP",
                    NameEvidence::Par2SetId,
                    "sid-b",
                    "census"
                ),
                200,
            )
            .unwrap(),
            ProvenOutcome::Applied
        );

        // A now writes from its stale snapshot. It must fail WHOLE.
        let out = a.apply_proven_name(
            rid,
            &claim(
                "Lima.Film.2024.1080p.BluRay.x264-GRP",
                NameEvidence::Par2SetId,
                "sid-a",
                "daemon",
            ),
            201,
        );
        assert!(
            out.is_err(),
            "a write from a stale snapshot was allowed to land: {out:?}"
        );
        a.db.execute_batch("ROLLBACK").unwrap();

        // B's name stands, and A's rolled-back attempt left nothing -
        // no orphan claim row, no blanked name.
        assert_eq!(named(&b, rid).0, "Kilo.Film.2024.1080p.BluRay.x264-GRP");
        let stale: i64 =
            b.db.query_row(
                "SELECT COUNT(*) FROM name_claims WHERE release_id=?1 AND source='daemon'",
                [rid],
                |r| r.get(0),
            )
            .unwrap();
        assert_eq!(stale, 0, "the failed decision left a claim row behind");
        drop(a);
        teardown(&d, b);
    }

    /// The window the savepoint actually exists to close: a stronger
    /// claim displaces a weaker name by REVOKING it and then applying
    /// the winner. As two autocommit statements a failure in between
    /// left the release nameless with nothing to retry - strictly worse
    /// than either name.
    ///
    /// The failure is injected with a trigger rather than raced, so the
    /// test pins the atomicity instead of a timing window.
    #[test]
    fn a_failed_apply_never_leaves_the_release_nameless() {
        let d = dir("h5-atomic");
        let mut ix = Index::open(&d.join("index.db")).unwrap();
        let rid = seed(&mut ix, "77aa22bb44cc66dd88", "h5b");

        // A weaker-but-applied name, the state a displacement starts
        // from. Par2SetId applies alone and BodyProbe outranks it, so
        // the stronger claim below takes the revoke-then-apply path.
        assert_eq!(
            ix.apply_proven_name(
                rid,
                &claim(
                    "Mike.Film.2024.720p.WEB.x264-GRP",
                    NameEvidence::Par2SetId,
                    "k1",
                    "lane1"
                ),
                100,
            )
            .unwrap(),
            ProvenOutcome::Applied
        );
        let (before_title, before_source) = named(&ix, rid);
        assert_eq!(before_title, "Mike.Film.2024.720p.WEB.x264-GRP");

        // Make the APPLY half fail while the revoke half succeeds
        // (revoke writes pre_title='', the apply writes the new name).
        ix.db
            .execute_batch(
                "CREATE TRIGGER h5_fail_apply AFTER UPDATE OF pre_title ON releases
                   WHEN new.pre_title = 'November.Film.2024.2160p.BluRay.x265-GRP'
                 BEGIN SELECT RAISE(ABORT, 'injected apply failure'); END;",
            )
            .unwrap();
        let out = ix.apply_proven_name(
            rid,
            &claim(
                "November.Film.2024.2160p.BluRay.x265-GRP",
                NameEvidence::BodyProbe,
                "k3",
                "lane3",
            ),
            102,
        );
        assert!(
            out.is_err(),
            "the injected failure did not surface: {out:?}"
        );
        ix.db.execute_batch("DROP TRIGGER h5_fail_apply").unwrap();

        // The release still carries the name it had. Without the
        // savepoint the revoke would have committed on its own and this
        // would be ("", "").
        assert_eq!(
            named(&ix, rid),
            (before_title, before_source),
            "a failed displacement left the release without a name"
        );
        teardown(&d, ix);
    }

    /// The doubling defect, end to end.
    ///
    /// The poster's own quoted filename carries the release name twice
    /// (measured 1 Sep 2026 against the article subjects), so the stem
    /// and every name derived from it arrive doubled. Three things have
    /// to hold: the naming seam folds it on the way IN, a row that was
    /// named before that heals when a correct claim arrives, and the
    /// one-shot repair heals the rest without waiting for one.
    #[test]
    fn a_name_written_twice_is_folded_at_the_seam_and_cannot_hold_off_its_own_half() {
        const HALF: &str = "A Bona Fide Killer  S01E06";
        let doubled = format!("{HALF}{HALF}");
        let d = dir("doubled");
        let mut ix = Index::open(&d.join("index.db")).unwrap();

        // 1. The seam. A lane handing `apply_named` the doubled name
        //    stores one copy - no lane has to remember the rule.
        let a = seed(&mut ix, "q8Wm2xL4vRt7pYh3n", "d1@x");
        assert!(
            ix.apply_named(a, &doubled, "proven:msgid-set:posted-nzb", 100)
                .unwrap()
        );
        assert_eq!(named(&ix, a).0, HALF);

        // 2. The arbitration. Write the pre-fix state directly - a row
        //    named by a posted-NZB claim carrying the doubled name -
        //    and hand it the correct half at the SAME evidence tier,
        //    which is the tie that used to lose. `applied_strength`
        //    grades both at `10 + MsgidSet.rank()`, so without the fold
        //    this is "equal or stronger - recorded, not applied", every
        //    time, forever.
        let b = seed(&mut ix, "z3Kd9sQ1wN6bV0jT2", "d2@x");
        ix.db
            .execute(
                "UPDATE releases SET pre_title=?2, pre_source='proven:msgid-set:posted-nzb'
                  WHERE id=?1",
                rusqlite::params![b, &doubled],
            )
            .unwrap();
        let out = ix
            .apply_proven_name(
                b,
                &claim(HALF, NameEvidence::MsgidSet, "spotkey", "spot"),
                200,
            )
            .unwrap();
        assert_eq!(
            out,
            ProvenOutcome::Confirmed,
            "the half is the same name, not a rename"
        );
        let (title, source) = named(&ix, b);
        // The claim's own spelling, which the ledger canonicalised on
        // the way in (`sanitize_name` collapses the poster's double
        // space) - a claim is applied as recorded, doubling or no.
        assert_eq!(title, "A Bona Fide Killer S01E06");
        assert_eq!(
            source, "proven:msgid-set:spot",
            "the winner's provenance is stamped"
        );

        // A DIFFERENT name at the same tier is still refused: the arm
        // fires only for this claim's own doubling, nothing wider.
        let c = seed(&mut ix, "m5Rp8tY2xB4kW7qF1", "d3@x");
        ix.db
            .execute(
                "UPDATE releases SET pre_title=?2, pre_source='proven:msgid-set:posted-nzb'
                  WHERE id=?1",
                rusqlite::params![c, &doubled],
            )
            .unwrap();
        let out = ix
            .apply_proven_name(
                c,
                &claim(NAME, NameEvidence::MsgidSet, "otherkey", "spot"),
                200,
            )
            .unwrap();
        assert_eq!(out, ProvenOutcome::Conflict);
        assert_eq!(
            named(&ix, c).0,
            doubled,
            "an unrelated claim changes nothing"
        );

        // 3. The repair, which does not wait for a claim to arrive. It
        //    keeps the row's OWN label - re-stamping a hardcoded one
        //    would demote a `proven:` row to the unarbitrable grade -
        //    and re-derives what the name determines, so the card
        //    searches under the corrected title.
        let n = ix.repair_doubled_pre_titles(300).unwrap();
        assert_eq!(n, 1, "only the still-doubled row");
        let (title, source) = named(&ix, c);
        assert_eq!(title, HALF);
        assert_eq!(source, "proven:msgid-set:posted-nzb");
        let key: String = ix
            .db
            .query_row("SELECT title_key FROM releases WHERE id=?1", [c], |r| {
                r.get(0)
            })
            .unwrap();
        assert_eq!(key, crate::categories::classify(HALF, &ix.custom).key);

        // kv-guarded: a second pass is a no-op even with a fresh row.
        let e = seed(&mut ix, "h2Nc6vZ9dJ3xS8mL5", "d4@x");
        ix.db
            .execute(
                "UPDATE releases SET pre_title=?2, pre_source='proven:msgid-set:posted-nzb'
                  WHERE id=?1",
                rusqlite::params![e, &doubled],
            )
            .unwrap();
        assert_eq!(ix.repair_doubled_pre_titles(400).unwrap(), 0);
        assert_eq!(named(&ix, e).0, doubled);
        teardown(&d, ix);
    }
}
