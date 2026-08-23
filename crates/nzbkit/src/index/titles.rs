//! Title and person metadata (TODO 106 phase 2.2, cut 4): the titles
//! table (seed, fill, identity, lanes), credits, people and their photo
//! queue. Bodies are verbatim moves from the old index.rs.

use super::*;

/// A title with at least one release the wall would actually show.
///
/// Enrichment is the scarcest thing the daemon does - MusicBrainz allows
/// one request a second, and Wikimedia 429s at three - so spending it on
/// a card nobody can see is the most expensive kind of waste. Measured
/// on a live 7,755-title index before this existed: of 5,243 lookups
/// that cost a network call, **3,910 (75%) went to titles with no
/// release passing the junk gate**. They are not rare edge cases; they
/// are most of the budget.
///
/// `junk < 50` is the wall's own default threshold, so this asks exactly
/// "would the wall list this?" rather than inventing a second policy.
///
/// It defers rather than drops. Junk scores are recomputed on every
/// ingest touch and a mid-upload release sheds junk as its parts arrive,
/// so a title that is invisible now and becomes visible later is simply
/// picked up on a later pass - it stays `checked=0` throughout. Nothing
/// is permanently skipped, which matters because the enricher's one-shot
/// `checked` stamp has no way back (see the tri-state plan in
/// research/indexer-realtime-and-enrichment-plan-2026-07-26.md §11.1).
const VISIBLE: &str = "EXISTS (SELECT 1 FROM releases r WHERE r.title_key = t.key AND r.junk < 50)";

/// What it means for a title to be waiting on the TVDB backfill lane,
/// as one predicate over the `t`-aliased `titles` row.
///
/// One literal because two callers have to agree about it exactly: the
/// lane that DRAINS this queue, and the caps gate that will not promise
/// `tvdbid` until it is empty (Codex sweep 7, M1). A drifted second copy
/// would advertise the parameter against rows the lane is never going to
/// reach, which is the false promise TODO 187 exists to prevent. See
/// [`Index::titles_missing_tvdb`] for what each clause is doing.
pub(super) fn tvdb_queue_where() -> String {
    format!(
        "kind = 'tv' AND checked > 0 AND tvdb_tried = 0 AND tvdb = 0
           AND tmdb_id <> 0 AND id_src = 'tvmaze' AND {VISIBLE}"
    )
}

/// What it means for a title to be waiting on the enricher's FIRST
/// lookup, in one lane, as one predicate over the `t`-aliased row.
///
/// One literal for the same reason [`tvdb_queue_where`] is one: the
/// pick and the EXISTS pre-check that decides whether to run the pick
/// have to describe the same queue, and a drifted copy makes the
/// pre-check answer about a different set than the one that gets
/// drained.
///
/// `checked = 0` is written out because `idx_titles_unchecked` is
/// PARTIAL on exactly that term, and SQLite reaches a partial index
/// only when the statement's own WHERE implies its predicate. Without
/// it every call here is a full pass over `titles` (see the note on
/// the index in schema.rs, and the plan gate that keeps the pairing
/// honest).
pub(super) fn pending_lane_where(lane: Lane) -> String {
    format!("checked = 0 AND {} AND {VISIBLE}", lane.sql())
}

/// What it means for a title to be waiting on the release-date
/// backfill, in one lane. Same contract as the two above; the partial
/// index this one has to reach is `idx_titles_air_backfill`, on
/// `air_tried = 0`.
pub(super) fn missing_date_where(lane: Lane) -> String {
    format!(
        "checked > 0 AND air_tried = 0 AND air_date = ''
           AND tmdb_id <> 0 AND {} AND {VISIBLE}",
        lane.sql()
    )
}

/// M28's priority: newest upload first, ranked over the releases the
/// wall would actually show. No index can carry this - the sort key is
/// a correlated subquery - so a statement ordering by it always builds
/// a temp B-tree. What keeps that affordable is the candidate SET, and
/// that is what the partial indexes and the EXISTS pre-checks are for.
const NEWEST_FIRST: &str = "COALESCE((SELECT MAX(r.first_posted) FROM releases r
                                WHERE r.title_key=t.key AND r.junk < 50), 0) DESC";

/// The statement [`Index::titles_pending_lane`] prepares.
///
/// A builder rather than an inline `format!` for one reason: the plan
/// gate in plan_tests.rs then plans the shape the daemon actually runs,
/// instead of a re-typed paraphrase that can drift away from it while
/// the test keeps passing. The three below are the same bargain.
pub(super) fn pending_lane_sql(lane: Lane) -> String {
    format!(
        "SELECT {} FROM titles t WHERE {}
         ORDER BY {NEWEST_FIRST}
         LIMIT ?1",
        Index::TITLE_COLS,
        pending_lane_where(lane)
    )
}

/// The statement [`Index::titles_missing_date`] prepares.
pub(super) fn missing_date_sql(lane: Lane) -> String {
    format!(
        "SELECT {} FROM titles t WHERE {}
         ORDER BY {NEWEST_FIRST}
         LIMIT ?1",
        Index::TITLE_COLS,
        missing_date_where(lane)
    )
}

/// The statement [`Index::titles_missing_tvdb`] prepares. The `t.key`
/// tie-break is part of the shape, not decoration - see that function.
pub(super) fn missing_tvdb_sql() -> String {
    format!(
        "SELECT {} FROM titles t WHERE {}
         ORDER BY {NEWEST_FIRST}, t.key ASC
         LIMIT ?1",
        Index::TITLE_COLS,
        tvdb_queue_where()
    )
}

/// The cheap "is this queue drained?" statement, for any of the
/// where-builders above.
pub(super) fn titles_any_sql(whr: &str) -> String {
    format!("SELECT EXISTS(SELECT 1 FROM titles t WHERE {whr})")
}

/// What a lookup learned about one title. A struct rather than the ten
/// positional arguments this used to take: the "found nothing" callers
/// passed a row of bare `""`s in which nothing said which field was
/// which, and every new field made that worse.
#[derive(Debug, Clone, Default)]
pub struct TitleFill<'a> {
    pub tmdb_id: i64,
    /// Which provider's numbering `tmdb_id` above is in - that provider's
    /// own name, '' when nothing resolved one. It travels WITH the id
    /// because it is the only thing that makes the id readable: the
    /// column carries a TVmaze show id, an AniList media id, a TMDB id
    /// and an OMDb-supplied IMDb number, and a reader that guesses from
    /// `kind` alone resolves one namespace's id in another's (Codex
    /// sweep 7, H2). Anything that PRESERVES `tmdb_id` across a write -
    /// the manual wall-fix arm, a poster upload - must preserve this
    /// with it, or the id silently reverts to unlabelled.
    pub id_src: &'a str,
    pub overview: &'a str,
    pub rating: f64,
    pub genres: &'a str,
    /// Local art FILENAMES, not provider URLs - the caller downloads the
    /// images before filling.
    pub poster: &'a str,
    pub backdrop: &'a str,
    pub imdb: &'a str,
    pub actors: &'a str,
    /// ISO `YYYY-MM-DD`, or empty when the provider had no date.
    pub air_date: &'a str,
}

/// One person's credit on one title, as a provider gave it to us.
///
/// The identity fields are what make this more than the comma-joined
/// name string `titles.actors` already holds: TVmaze hands over a person
/// id and Wikidata a Q-id, and each is the handle its own filmography
/// endpoint takes. A provider that gives neither (OMDb, TMDB) still
/// produces a usable credit - it just cannot be followed off-index.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Credit {
    pub name: String,
    /// actor | director | writer | composer | creator | producer | …
    /// Free text, because crew vocabularies differ per provider and
    /// flattening them to an enum loses the useful ones ("Director of
    /// Photography"). Empty is stored as "actor".
    pub role: String,
    /// The part they played, when the provider models it (TVmaze
    /// `character.name`, Wikidata's P453 qualifier). Empty for crew.
    pub character: String,
    /// Billing order, lower first. 0 when unranked.
    pub ord: i64,
    pub tvmaze_id: i64,
    pub wikidata_qid: String,
    /// IMDb `nm…` id. Unlike the two handles above this one is shared
    /// vocabulary rather than a provider's own numbering, so it is the
    /// only field that can identify the same human across providers.
    pub imdb: String,
    /// Date of birth, ISO `YYYY-MM-DD`, empty when unknown. Not an
    /// identifier - it is the disambiguator `person_upsert` uses to tell
    /// two same-named people apart, and it earns that job by being the
    /// one fact BOTH cast providers publish (TVmaze `person.birthday`,
    /// Wikidata P569).
    pub born: String,
    /// Headshot: a provider URL as parsed, swapped for the local
    /// art-cache filename once the enricher has fetched it.
    pub photo: String,
}

/// A credit joined to its resolved person (what the detail sheet shows).
#[derive(Debug, Clone)]
pub struct PersonCredit {
    pub person_id: i64,
    pub name: String,
    pub photo: String,
    pub role: String,
    pub character: String,
    pub ord: i64,
}

#[derive(Debug, Clone, Default)]
pub struct PersonRow {
    pub id: i64,
    pub name: String,
    pub imdb: String,
    pub tvmaze_id: i64,
    pub wikidata_qid: String,
    pub bio: String,
    pub born: String,
    pub photo: String,
}

/// One title on a person page's "in your index" half.
#[derive(Debug, Clone)]
pub struct PersonTitle {
    pub key: String,
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub poster: String,
    pub air_date: String,
    /// Every role they hold on this title, comma-joined - one person can
    /// star in a show AND produce it.
    pub role: String,
    /// The part they played, from the acting credit; empty for crew-only.
    pub character: String,
    pub ord: i64,
    pub n_releases: i64,
}

#[derive(Debug, Clone)]
pub struct PersonHit {
    pub id: i64,
    pub name: String,
    pub photo: String,
    /// How many visible titles they are credited on - the ranking signal
    /// and the honest answer to "is this person actually in my index".
    pub n_titles: i64,
}

/// One pending title row waiting to be seeded - what the wall knows
/// about a card it is showing without metadata yet.
///
/// Carried as a value rather than four positional arguments because the
/// wall queues these to the enricher instead of writing them on the HTTP
/// request path ([`Index::title_seed_many`]).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct TitleSeed {
    /// `titles.key` - the card's identity.
    pub key: String,
    /// `titles.kind`: movie / tv / music / book / software / other. It
    /// decides which enricher lane picks the row up.
    pub kind: String,
    /// Display title, parsed from the release stem when the card has none.
    pub title: String,
    /// Release year, 0 when unknown.
    pub year: u32,
}

/// One cached title-metadata row (M13 wall).
///
/// `Default` is the "row that does not exist yet" value, and it is what
/// the seed-then-act endpoints in `serve::api::wall` fill from: a row
/// they just seeded holds nothing but its identity, and every metadata
/// column below is empty by construction.
#[derive(Debug, Clone, Default)]
pub struct TitleRow {
    pub key: String,
    pub kind: String,
    pub title: String,
    pub year: u32,
    pub tmdb_id: i64,
    pub overview: String,
    pub rating: f64,
    pub genres: String,
    pub poster: String,
    pub backdrop: String,
    pub checked: i64,
    /// IMDb tconst ("tt0133093") when a provider resolved one - joins
    /// against the imdb_ratings snapshot at wall time.
    pub imdb: String,
    /// Top-billed cast, comma-joined.
    pub actors: String,
    /// Original release / first-air date, ISO `YYYY-MM-DD`, or empty when
    /// the provider had none. `year` is the coarse fallback.
    pub air_date: String,
    /// Which provider's numbering `tmdb_id` is in - see
    /// [`TitleFill::id_src`]. '' on a row written before the column
    /// existed.
    pub id_src: String,
}

impl Index {
    /// M13 title-metadata cache (dumb storage - TMDB lookups live in the
    /// daemon; this just remembers results, including "looked, found
    /// nothing" so a missing title is fetched once, not every poll).
    /// Insert a pending row for a parsed title if we've never seen it.
    pub fn title_seed(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            Self::TITLE_SEED_SQL,
            rusqlite::params![key, kind, title, year],
        )?;
        Ok(())
    }

    const TITLE_SEED_SQL: &'static str =
        "INSERT OR IGNORE INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)";

    /// Seed a whole page of pending title rows in ONE transaction.
    ///
    /// [`Self::title_seed`] autocommits, so seeding the wall's viewport a
    /// row at a time was one write-lock acquisition per card - and each
    /// one can sit in the 10 s `busy_timeout` behind a scan chunk's
    /// IMMEDIATE transaction. IMMEDIATE here for the reason
    /// `ingest::ingest_pass` writes up: a DEFERRED transaction upgrades
    /// its lock lazily and SQLite skips the busy timeout on that upgrade.
    ///
    /// Every row is `INSERT OR IGNORE`, so re-offering a batch costs
    /// nothing and callers need not track what they have already seeded.
    pub fn title_seed_many(&mut self, seeds: &[TitleSeed]) -> rusqlite::Result<usize> {
        if seeds.is_empty() {
            return Ok(0);
        }
        let tx = self
            .db
            .transaction_with_behavior(rusqlite::TransactionBehavior::Immediate)?;
        let mut n = 0usize;
        {
            let mut stmt = tx.prepare_cached(Self::TITLE_SEED_SQL)?;
            for s in seeds {
                n += stmt.execute(rusqlite::params![s.key, s.kind, s.title, s.year])?;
            }
        }
        tx.commit()?;
        Ok(n)
    }

    fn title_row(r: &rusqlite::Row) -> rusqlite::Result<TitleRow> {
        Ok(TitleRow {
            key: r.get(0)?,
            kind: r.get(1)?,
            title: r.get(2)?,
            year: r.get::<_, i64>(3)? as u32,
            tmdb_id: r.get(4)?,
            overview: r.get(5)?,
            rating: r.get(6)?,
            genres: r.get(7)?,
            poster: r.get(8)?,
            backdrop: r.get(9)?,
            checked: r.get(10)?,
            imdb: r.get(11)?,
            actors: r.get(12)?,
            air_date: r.get(13)?,
            id_src: r.get(14)?,
        })
    }

    pub(super) const TITLE_COLS: &'static str =
        "key, kind, title, year, tmdb_id, overview, rating, genres,
         poster, backdrop, checked, imdb, actors, air_date, id_src";

    /// All cached title rows (the wall joins them to parsed releases).
    pub fn titles(&self) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self
            .db
            .prepare(&format!("SELECT {} FROM titles", Self::TITLE_COLS))?;
        let rows = stmt.query_map([], Self::title_row)?;
        rows.collect()
    }

    /// Titles never looked up (checked=0), oldest-seeded first.
    pub fn titles_pending(&self, limit: u32) -> rusqlite::Result<Vec<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE checked=0 LIMIT ?1",
            Self::TITLE_COLS
        ))?;
        let rows = stmt.query_map([limit], Self::title_row)?;
        rows.collect()
    }

    /// Pending titles split into the enricher's lanes: one thread each,
    /// because every provider's rate limit is independent and a serial
    /// loop makes each kind queue behind the slowest one.
    pub fn titles_pending_lane(&self, limit: u32, lane: Lane) -> rusqlite::Result<Vec<TitleRow>> {
        // A drained queue answers here, without the sort (N1). The lane
        // thread asks this every 15 s forever, and on a settled install
        // the honest answer is always "nothing" - but finding that out
        // through the pick below means computing the correlated MAX for
        // every candidate row and building a temp B-tree over the
        // result, under the index WRITE mutex, to return zero rows.
        // EXISTS stops at the first row and needs no ordering at all,
        // the same trade [`Self::tvdb_backfill_pending`] makes for the
        // caps gate.
        if !self.titles_any(&pending_lane_where(lane))? {
            return Ok(Vec::new());
        }
        // M28: enrich in the order the wall shows cards - newest upload
        // first (idx_rel_title_key makes the correlated MAX cheap), junk
        // groups last. Fresh titles used to queue behind the whole
        // historical backlog in rowid order, so a new post's art could
        // be hours away on a big index.
        //
        // The temp B-tree is inherent to that ordering - the sort key is
        // a correlated subquery, which no index can carry - so what the
        // partial index buys is the candidate SET: the sort runs over
        // the rows still waiting rather than over every title ever seen.
        let mut stmt = self.db.prepare(&pending_lane_sql(lane))?;
        let rows = stmt.query_map(rusqlite::params![limit], Self::title_row)?;
        rows.collect()
    }

    /// Is any `titles` row still matching `whr`? The cheap question the
    /// three enricher lanes ask before paying for a prioritised pick.
    ///
    /// `whr` is SQL built by this module's own where-builders - static
    /// text only, never a caller-supplied value.
    fn titles_any(&self, whr: &str) -> rusqlite::Result<bool> {
        self.db.query_row(&titles_any_sql(whr), [], |r| {
            r.get::<_, i64>(0).map(|n| n != 0)
        })
    }

    /// M30: viewport-priority enrichment - the still-pending subset of
    /// `keys` (what the wall is showing right now) for one lane.
    ///
    /// Deliberately NOT filtered by `VISIBLE`, unlike the backlog query:
    /// these keys are cards the user has on screen this moment, which is
    /// the strongest possible evidence a title is wanted. A junk-scored
    /// card only reaches here when they have turned "show hidden" on and
    /// are looking straight at it - enriching that is answering a
    /// request, not spending the budget on nobody.
    pub fn titles_hot(&self, keys: &[String], lane: Lane) -> rusqlite::Result<Vec<TitleRow>> {
        let mut out = Vec::new();
        let mut stmt = self.db.prepare_cached(&format!(
            "SELECT {} FROM titles t WHERE key=?1 AND checked=0 AND {}",
            Self::TITLE_COLS,
            lane.sql()
        ))?;
        for k in keys {
            let mut rows = stmt.query_map(rusqlite::params![k], Self::title_row)?;
            if let Some(row) = rows.next() {
                out.push(row?);
            }
        }
        Ok(out)
    }

    /// M30: seed titles rows for recent, wall-visible releases that
    /// have none - the enricher only works from the titles table, and
    /// after M28 nothing seeded it except a wall page view. Called
    /// after each scan pass; newest first, bounded per call. Returns
    /// how many were seeded.
    pub fn seed_missing_titles(&self, max_age_days: u32, limit: u32) -> rusqlite::Result<u32> {
        let rows: Vec<(String, String, String)> = {
            let mut stmt = self.db.prepare_cached(
                "SELECT r.title_key, r.kind, MAX(r.stem)
                 FROM releases r
                 WHERE r.junk < 50 AND r.title_key != ''
                   AND r.kind NOT IN ('software','other','')
                   AND r.first_posted > strftime('%s','now') - ?1 * 86400
                   AND NOT EXISTS(SELECT 1 FROM titles t WHERE t.key = r.title_key)
                 GROUP BY r.title_key
                 ORDER BY MAX(r.first_posted) DESC LIMIT ?2",
            )?;

            stmt.query_map(rusqlite::params![max_age_days, limit], |r| {
                Ok((r.get(0)?, r.get(1)?, r.get(2)?))
            })?
            .collect::<rusqlite::Result<_>>()?
        };
        let mut n = 0;
        for (key, kind, stem) in rows {
            let p = crate::release::parse_release(&stem);
            self.title_seed(&key, &kind, &p.title, p.year.unwrap_or(0))?;
            n += 1;
        }
        Ok(n)
    }

    /// M30: merge one card into another - every release under `src`
    /// re-keys to `dst`, then src's title row (and any hide) goes away.
    /// The classic fix for a parser split ("Show (Alt Title)" vs
    /// "Show") that left two cards for one series.
    pub fn merge_title(&self, src: &str, dst: &str) -> rusqlite::Result<u64> {
        if src == dst || src.is_empty() || dst.is_empty() {
            return Ok(0);
        }
        // All five statements or none. They used to autocommit one by
        // one, and the failure is unrecoverable rather than merely
        // untidy: if the releases re-key and the credit copy commit but
        // the DELETE then loses a race for the writer (a scan chunk or a
        // retention prune holding it past the 10 s busy timeout), the
        // credits exist under BOTH keys and src's titles row survives -
        // while every release has already moved to dst, so the src card
        // has vanished from the wall and nothing will ever prompt a
        // re-merge. The orphans are permanent, and they inflate the
        // visible credit counts on the destination.
        let tx = self.db.unchecked_transaction()?;
        let n = tx.execute(
            "UPDATE releases SET title_key=?2 WHERE title_key=?1",
            rusqlite::params![src, dst],
        )?;
        // Credits follow their releases. OR IGNORE because the two cards
        // may already share a person in the same role (the usual reason a
        // card split is a parser artifact of ONE title), and the
        // destination's own credit is the one to keep.
        tx.execute(
            "INSERT OR IGNORE INTO title_people(key, person_id, role, character, ord)
             SELECT ?2, person_id, role, character, ord FROM title_people WHERE key=?1",
            rusqlite::params![src, dst],
        )?;
        tx.execute("DELETE FROM title_people WHERE key=?1", [src])?;
        tx.execute("DELETE FROM titles WHERE key=?1", [src])?;
        tx.execute("DELETE FROM wall_hidden WHERE key=?1", [src])?;
        tx.commit()?;
        Ok(n as u64)
    }

    /// One title row by key (the fix/scrub endpoints read-modify-write).
    pub fn title_get(&self, key: &str) -> rusqlite::Result<Option<TitleRow>> {
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE key=?1",
            Self::TITLE_COLS
        ))?;
        let mut rows = stmt.query_map([key], Self::title_row)?;
        rows.next().transpose()
    }

    /// M31b: fetch the cached rows for a set of title_keys in one prepared
    /// pass (the taste-profile build needs genres/kind/year for a few
    /// hundred keys). Missing keys are simply absent from the map.
    pub fn titles_for_keys(
        &self,
        keys: &[String],
    ) -> rusqlite::Result<std::collections::HashMap<String, TitleRow>> {
        let mut out = std::collections::HashMap::with_capacity(keys.len());
        let mut stmt = self.db.prepare(&format!(
            "SELECT {} FROM titles WHERE key=?1",
            Self::TITLE_COLS
        ))?;
        for k in keys {
            if out.contains_key(k) {
                continue;
            }
            let mut rows = stmt.query_map([k], Self::title_row)?;
            if let Some(row) = rows.next().transpose()? {
                out.insert(k.clone(), row);
            }
        }
        Ok(out)
    }

    /// M16 wall-fix: overwrite a title's IDENTITY (kind/title/year - what
    /// lookups search under and the wall displays) without touching the
    /// cached metadata/art columns. Upserts so it also works for keys the
    /// enricher hasn't seeded yet.
    ///
    /// The ONE exception is `tvdb`, which is cleared whenever the
    /// identity actually changes. It is not a cached detail of the old
    /// title, it is a claim about WHICH SERIES this row is, and
    /// [`Self::title_fill`] deliberately never rewrites it - so
    /// correcting a card from series A to series B left A's TVDB id
    /// behind, `tvdbid=<A>` answered Sonarr with B's releases,
    /// `tvdbid=<B>` answered with nothing, and the row could never
    /// self-heal because [`Self::titles_missing_tvdb`] wants
    /// `tvdb_tried = 0 AND tvdb = 0` (Codex sweep 7, M3). `tvdb_tried`
    /// goes with it, which is what puts the row back in the backfill
    /// queue; clearing is NOT conditional on being able to refill,
    /// because a wrong id is worse than a missing one.
    ///
    /// Only on a real change, which is why the CASE is here rather than
    /// an unconditional clear: the same call is how a metadata refresh
    /// re-states an unchanged identity, and retiring a correct id on
    /// every one of those would keep the backfill lane re-asking TVmaze
    /// forever. In SQLite every assignment's right-hand side sees the
    /// ORIGINAL row, so the comparison reads the stored values.
    pub fn title_set_identity(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
    ) -> rusqlite::Result<()> {
        self.db.execute(
            "INSERT INTO titles(key, kind, title, year) VALUES(?1, ?2, ?3, ?4)
             ON CONFLICT(key) DO UPDATE SET kind=?2, title=?3, year=?4,
               tvdb = CASE WHEN titles.kind<>?2 OR titles.title<>?3 OR titles.year<>?4
                           THEN 0 ELSE titles.tvdb END,
               tvdb_tried = CASE WHEN titles.kind<>?2 OR titles.title<>?3 OR titles.year<>?4
                                 THEN 0 ELSE titles.tvdb_tried END",
            rusqlite::params![key, kind, title, year],
        )?;
        Ok(())
    }

    /// M16 wall-fix: the identity write and the metadata that belongs to
    /// the NEW identity, both or neither.
    ///
    /// The wall-fix endpoint ran these as two autocommitting writes, and
    /// the second one can lose the writer (a scan chunk or a retention
    /// prune holding it past the 10 s busy timeout) after the first has
    /// landed. That leaves the row renamed to the picked series wearing
    /// the OLD series' poster, overview, rating and ids - and nothing
    /// will ever prompt a re-fix, because the card now reads as a title
    /// somebody already identified. The same unrecoverable-rather-than-
    /// untidy shape as [`Self::merge_title`], and the same remedy.
    ///
    /// `unchecked_transaction` is deferred, which is safe here for the
    /// reason the custom-category cursor needed IMMEDIATE and this does
    /// not: the first statement inside is itself a write, so the write
    /// lock is taken with the busy timeout applied rather than upgraded
    /// from a read (a deferred upgrade returns SQLITE_BUSY at once).
    pub fn title_set_identity_and_fill(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
        m: &TitleFill<'_>,
        now: i64,
    ) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        self.title_set_identity(key, kind, title, year)?;
        // The identity CASE compares kind/title/year, but a wall-fix can
        // move a card to a DIFFERENT series wearing the identical display
        // identity - two shows with one name, and TV seeds commonly carry
        // year 0, which reduces the CASE to a byte-equal title compare.
        // The id pair is the actual series claim, so a changed id retires
        // the old TVDB answer exactly as a changed title does (and puts
        // the row back in the backfill queue). Before `title_fill`, which
        // is what overwrites the stored pair being compared.
        if m.tmdb_id != 0 {
            self.db.execute(
                "UPDATE titles SET tvdb = 0, tvdb_tried = 0
                  WHERE key = ?1 AND (tmdb_id <> ?2 OR id_src <> ?3)",
                rusqlite::params![key, m.tmdb_id, m.id_src],
            )?;
        }
        self.title_fill(key, m, now)?;
        tx.commit()
    }

    /// The re-fetch arm of the same endpoint: rename, then hand the row
    /// back to the enricher, both or neither.
    ///
    /// Atomic for a sharper reason than the fill above. The reset is what
    /// sets `checked=0`, and `checked=0` is the ONLY thing that puts the
    /// row back in the enrichment queue - so a rename that commits
    /// without it produces a row that is renamed, still stamped as
    /// checked, and therefore never re-enriched. The user pressed
    /// "re-fetch" and got a rename with no fetch, permanently.
    pub fn title_set_identity_and_reset(
        &self,
        key: &str,
        kind: &str,
        title: &str,
        year: u32,
    ) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        self.title_set_identity(key, kind, title, year)?;
        self.title_reset(key)?;
        tx.commit()
    }

    /// M16 wall-refresh: wipe a title's cached metadata and mark it
    /// pending (checked=0) so the enricher fetches it fresh. Identity and
    /// the release rows are untouched. Returns whether the row existed.
    pub fn title_reset(&self, key: &str) -> rusqlite::Result<bool> {
        let n = self.db.execute(
            "UPDATE titles SET tmdb_id=0, id_src='', overview='', rating=0, genres='',
                    poster='', backdrop='', imdb='', actors='', air_date='',
                    air_tried=0, tvdb=0, tvdb_tried=0, checked=0
             WHERE key=?1",
            [key],
        )?;
        Ok(n > 0)
    }

    /// What a title blanked by a failed lookup looks like on disk.
    ///
    /// Every metadata column at its default with `checked` stamped: that
    /// is exactly what `title_fill(&Default::default())` writes, and
    /// before TODO 26c the enricher wrote it for a 429, a 503 and a
    /// DNS blip as readily as for a real "no such film".
    ///
    /// It cannot tell those two apart retroactively - nothing recorded
    /// WHY - so the sweep below is deliberately a superset: a row that
    /// genuinely has no metadata anywhere costs one more lookup and is
    /// stamped again, while a row a blip blanked gets its card. That
    /// trade is only sound ONCE, which is why the caller is a kv-guarded
    /// one-off and not a recurring pass.
    ///
    /// `kind` is the guard that keeps it from being a `titles_reset_all`
    /// with extra steps: obfuscated and unparseable rows land on
    /// `Kind::Other`, and the enricher stamps those without asking any
    /// provider at all. Sweeping them back in would re-queue every junk
    /// stem on the wall to be stamped again unlooked, forever.
    ///
    /// A Wikipedia-only card (no provider id, but a plot or a poster)
    /// fails the empty-column tests and is left alone, which is right -
    /// it is a real answer.
    const BLANKED: &'static str = "checked > 0 AND kind IN ('tv','movie','music','book')
           AND tmdb_id = 0 AND id_src = '' AND overview = '' AND genres = ''
           AND poster = '' AND backdrop = '' AND imdb = '' AND actors = ''
           AND air_date = '' AND rating = 0";

    /// kv keys for the one-off sweep: how far it has walked, and that it
    /// is finished. The `_v1` is the re-arm handle - see
    /// [`Self::titles_unstamp_rearm`].
    const UNSTAMP_CURSOR: &'static str = "enrich_unstamp_cursor";
    const UNSTAMP_DONE: &'static str = "enrich_unstamp_v1";

    /// TODO 26c: put back the titles a transient provider failure
    /// blanked before the enricher could tell "no such film" from "ask
    /// later". Returns (rows re-queued this call, sweep finished).
    ///
    /// A one-off, guarded by [`Self::UNSTAMP_DONE`], because the
    /// predicate above is a superset and re-running it on a schedule
    /// would put every genuinely-unknown title back in the queue on
    /// every pass - an enricher that never settles.
    ///
    /// Sliced on the rowid with the cursor persisted, for the reason
    /// `split_merge` is: the caller holds the shared index write mutex
    /// for the whole call, so a live index's worth of `titles` cannot be
    /// one statement. A LIMIT would not do instead - an un-stamped row
    /// leaves the set, so each successive slice would rescan everything
    /// already swept to find the next match.
    pub fn titles_unstamp_blanked(
        &self,
        budget: std::time::Duration,
    ) -> rusqlite::Result<(usize, bool)> {
        if self.kv_get(Self::UNSTAMP_DONE).is_some() {
            return Ok((0, true));
        }
        const STRIDE: i64 = 20_000;
        let started = std::time::Instant::now();
        let mut cursor: i64 = self
            .kv_get(Self::UNSTAMP_CURSOR)
            .and_then(|v| v.parse().ok())
            .unwrap_or(0);
        let top: i64 = self
            .db
            .query_row("SELECT COALESCE(MAX(rowid),0) FROM titles", [], |r| {
                r.get(0)
            })?;
        let mut n = 0usize;
        let sql = format!(
            "UPDATE titles SET checked=0, air_tried=0
              WHERE rowid>?1 AND rowid<=?2 AND {}",
            Self::BLANKED
        );
        let done = loop {
            let hi = cursor.saturating_add(STRIDE).min(top);
            n += self.db.prepare_cached(&sql)?.execute([cursor, hi])?;
            cursor = hi;
            if hi >= top {
                break true;
            }
            self.kv_set(Self::UNSTAMP_CURSOR, &cursor.to_string())?;
            if started.elapsed() >= budget {
                break false;
            }
        };
        if done {
            self.kv_set(Self::UNSTAMP_DONE, "1")?;
            self.db
                .execute("DELETE FROM kv WHERE k=?1", [Self::UNSTAMP_CURSOR])?;
        }
        Ok((n, done))
    }

    /// Forget that the sweep above has run, so it runs again from the
    /// start. The manual half of the one-off: `wall_refresh&value=blanked`
    /// is how an install that collected blanked rows AFTER the automatic
    /// sweep (a long outage, say) asks for another.
    pub fn titles_unstamp_rearm(&self) -> rusqlite::Result<()> {
        self.db.execute(
            "DELETE FROM kv WHERE k IN (?1,?2)",
            [Self::UNSTAMP_DONE, Self::UNSTAMP_CURSOR],
        )?;
        Ok(())
    }

    /// M16: reset EVERY title's metadata (fresh enrichment pass over the
    /// whole wall). Returns how many rows were reset.
    pub fn titles_reset_all(&self) -> rusqlite::Result<usize> {
        self.db.execute(
            "UPDATE titles SET tmdb_id=0, id_src='', overview='', rating=0, genres='',
                    poster='', backdrop='', imdb='', actors='', air_date='',
                    air_tried=0, tvdb=0, tvdb_tried=0, checked=0",
            [],
        )
    }

    /// Titles the enricher already matched but has never asked for a
    /// release date - rows written before air_date existed. The backfill
    /// lane drains these when it has nothing pending, so the release-date
    /// sort becomes useful on an existing library instead of only on
    /// titles indexed from here on. tmdb_id<>0 skips the rows no provider
    /// recognised: there is no date to go and fetch for those.
    pub fn titles_missing_date(&self, limit: u32, lane: Lane) -> rusqlite::Result<Vec<TitleRow>> {
        // Drained-queue fast path, as in `titles_pending_lane` - and it
        // matters most here, because this lane is a BACKFILL: it exists
        // to be finished, and once it is, every 15 s tick for the life
        // of the install is asking a question whose answer is no.
        if !self.titles_any(&missing_date_where(lane))? {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.prepare(&missing_date_sql(lane))?;
        let rows = stmt.query_map(rusqlite::params![limit], Self::title_row)?;
        rows.collect()
    }

    /// TV titles the enricher matched but never asked for a TVDB id -
    /// every row enriched before the column existed, which on a live
    /// index is all of them. Sonarr's primary series lookup is
    /// `tvdbid`, and the newznab facade will not advertise the
    /// parameter until this lane has put ids in the column (TODO 187),
    /// so this backfill is what turns the feature on for an existing
    /// library rather than only for titles indexed from here on.
    ///
    /// `tmdb_id <> 0` is not a nicety: the backfill asks TVmaze with
    /// that number, so a row without one has no cheap question to ask.
    ///
    /// `id_src = 'tvmaze'` is what makes asking TVmaze with it safe.
    /// Under the keyless default a TV row holds an AniList media id
    /// whenever TVmaze missed the title (the routine anime case), and
    /// with a TMDB key it holds a TMDB series id - neither addresses
    /// TVmaze. The consequence was not a miss but a permanent wrong
    /// write: `tvdb_of_show`'s only guard is that the payload is about
    /// the show we asked about, which a foreign id satisfies exactly
    /// whenever it is also a live TVmaze show id, so an unrelated
    /// series' thetvdb id was stamped on the row with `tvdb_tried=1` and
    /// Sonarr's `tvdbid=` then resolved to the wrong title key (Codex
    /// sweep 7, H2). The legacy '' rows used to be admitted on the
    /// assumption that unlabelled meant TVmaze - but the AniList
    /// fallback was writing media ids into `tmdb_id` for three weeks
    /// BEFORE the `id_src` column landed, so '' proves nothing and an
    /// unlabelled anime row fed this lane exactly the wrong-write above
    /// (bug sweep 20 Aug). Those rows simply never backfill.
    ///
    /// The `t.key` tie-break is not cosmetic either: this queue is
    /// head-stable, so ties left to SQLite's row order make the head SET
    /// itself undefined, and the lane's backoff bookkeeping is reasoning
    /// about which rows it just skipped (Codex sweep 7, M2).
    pub fn titles_missing_tvdb(&self, limit: u32) -> rusqlite::Result<Vec<TitleRow>> {
        // The caps gate has always taken the EXISTS route (below); the
        // lane that DRAINS the queue used to pay for the full pick on
        // every idle tick even after the last row was filled. Same
        // question, same predicate, so ask it the same cheap way first.
        if !self.titles_any(&tvdb_queue_where())? {
            return Ok(Vec::new());
        }
        let mut stmt = self.db.prepare(&missing_tvdb_sql())?;
        let rows = stmt.query_map(rusqlite::params![limit], Self::title_row)?;
        rows.collect()
    }

    /// Does the TVDB backfill lane still have work? The caps gate's
    /// question, and the reason it is not `titles_missing_tvdb(1)`:
    /// that query orders by newest release first, which means computing
    /// a correlated MAX for every candidate row, and `t=caps` is a
    /// request an *arr can make at any time. `EXISTS` stops at the
    /// first row and needs no ordering at all - the caps gate does not
    /// care WHICH row is outstanding, only whether one is (Codex sweep
    /// 7, M1).
    pub fn tvdb_backfill_pending(&self) -> rusqlite::Result<bool> {
        self.titles_any(&tvdb_queue_where())
    }

    /// Store a backfilled TVDB id. `0` records only that TVmaze was
    /// asked and published none, which is what stops the backfill lane
    /// returning to the same show on every pass - the same contract
    /// [`Self::title_set_air_date`] has for an empty date.
    pub fn title_set_tvdb(&self, key: &str, tvdb: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET tvdb=?2, tvdb_tried=1 WHERE key=?1",
            rusqlite::params![key, tvdb.max(0)],
        )?;
        Ok(())
    }

    /// Store a backfilled release date. An empty `date` records only that
    /// the provider was asked and had none, which is what stops the
    /// backfill lane asking about the same title on every pass.
    pub fn title_set_air_date(&self, key: &str, date: &str) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET air_date=?2, air_tried=1 WHERE key=?1",
            rusqlite::params![key, date],
        )?;
        Ok(())
    }

    /// Record a lookup result (tmdb_id=0 ⇒ nothing found; checked stamps
    /// the attempt either way).
    ///
    /// Deliberately does not touch `tvdb`. Only TVmaze publishes a TVDB
    /// id and only [`Self::title_set_tvdb`] writes one, so the column
    /// has exactly one writer - the lane that actually ASKED. A zero
    /// written from here would mean "this provider does not carry it",
    /// and stamping `tvdb_tried` with it would retire the row from
    /// [`Self::titles_missing_tvdb`] unasked: how a column stays empty
    /// while every row claims to have been filled.
    pub fn title_fill(&self, key: &str, m: &TitleFill<'_>, now: i64) -> rusqlite::Result<()> {
        self.db.execute(
            "UPDATE titles SET tmdb_id=?2, overview=?3, rating=?4, genres=?5,
                    poster=?6, backdrop=?7, imdb=?8, actors=?9, air_date=?10,
                    id_src=?11, air_tried=1, checked=?12
             WHERE key=?1",
            rusqlite::params![
                key, m.tmdb_id, m.overview, m.rating, m.genres, m.poster, m.backdrop, m.imdb,
                m.actors, m.air_date, m.id_src, now
            ],
        )?;
        Ok(())
    }

    // ---- cast and crew as entities -----------------------------------

    /// Resolve a credit to a `people.id`, creating or completing the row.
    ///
    /// Handles win over names, in the order a provider can be trusted: a
    /// TVmaze person id, a Wikidata Q-id and an IMDb `nm…` id each
    /// identify exactly one human, so any one of them matching IS the
    /// person. Only when a credit carries no handle at all (OMDb and
    /// TMDB give bare names) does the name decide - and then only
    /// against a row that contradicts none of what the credit knows.
    ///
    /// **Why the name fallback has to allow a cross-handle match.** The
    /// two provider handles live in disjoint id spaces: nothing TVmaze
    /// publishes about a person appears in Wikidata and vice versa, so a
    /// human seen by both arrives as a name plus a tvmaze id on one side
    /// and a name plus a qid on the other. Refusing that match forks one
    /// human into two rows, which is what
    /// `people_identity_credits_and_the_search_leg` pins against.
    ///
    /// **Why that used to fuse two different people** (finding D2): the
    /// same shape - a name plus one handle on each side - is also what
    /// two same-named strangers look like, and until both sides carried
    /// a fact in a SHARED vocabulary there was nothing to tell the cases
    /// apart. `born` is that shared fact, and it is here because it is
    /// the one both cast providers actually publish: TVmaze hands the
    /// birthday over in the cast payload itself, and Wikidata's P569
    /// rides along with P345 in one batched query.
    ///
    /// The IMDb id would have been the better join, and `imdb` is
    /// populated and matched for exactly that reason - but only Wikidata
    /// can supply it. Measured 27 Jul 2026 against the live API: TVmaze
    /// exposes no IMDb id for a person anywhere (no `externals` on the
    /// person object embedded or standalone, `/lookup/people?imdb=` is
    /// 404, and the public person page carries no IMDb link), and
    /// Wikidata has no TVmaze *person* property either - P8600 and
    /// friends are series, season, episode and character only. So `imdb`
    /// alone would have separated only people the qid already separated.
    ///
    /// Both disagreement tests are one-sided on purpose: a blank on
    /// either side never blocks a match, so a provider that gave us
    /// nothing cannot fork a person it simply failed to describe.
    ///
    /// Two residual risks, both accepted:
    ///
    /// - Two same-named people with no handles and no birth dates still
    ///   merge. That is the behaviour `titles.actors` already had (it is
    ///   a plain string of names), and unlike a wrong split it is
    ///   visible and fixable.
    /// - Two providers disagreeing on one real person's birthday split
    ///   them. Day-precision only (see `parse_person_facts`) keeps the
    ///   common "Wikidata knows only the year" case out of the
    ///   comparison entirely, which is where the disagreements were.
    pub fn person_upsert(&self, c: &Credit) -> rusqlite::Result<i64> {
        let name = c.name.trim();
        if name.is_empty() {
            return Err(rusqlite::Error::InvalidParameterName(
                "empty person name".into(),
            ));
        }
        // Each handle lookup REPEATS its partial index's predicate, and
        // none of the three is redundant with the Rust-side guard beside
        // it. `idx_people_tvmaze` is `... WHERE tvmaze_id > 0` and the
        // other two are `<> ''`; SQLite will not use a partial index
        // unless the query's own WHERE clause proves the row is inside
        // it, so without these the planner falls back to a full scan of
        // `people` - three of them, per credit, under the index write
        // mutex. Same trap `query.rs` documents for `idx_titles_imdb`.
        let mut existing: Option<i64> = None;
        if c.tvmaze_id > 0 {
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people WHERE tvmaze_id=?1 AND tvmaze_id > 0",
                    [c.tvmaze_id],
                    |r| r.get(0),
                )
                .optional()?;
        }
        if existing.is_none() && !c.wikidata_qid.is_empty() {
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people WHERE wikidata_qid=?1 AND wikidata_qid <> ''",
                    [&c.wikidata_qid],
                    |r| r.get(0),
                )
                .optional()?;
        }
        if existing.is_none() && !c.imdb.is_empty() {
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people WHERE imdb=?1 AND imdb <> ''",
                    [&c.imdb],
                    |r| r.get(0),
                )
                .optional()?;
        }
        if existing.is_none() {
            // Name fallback, guarded by every fact both sides hold. Each
            // clause reads "one of us does not know, or we agree", so a
            // blank never blocks a match and a contradiction always
            // does.
            //
            // The two handle clauses can only ever refuse a row whose
            // SAME handle differs - a TVmaze credit says nothing about a
            // Wikidata row - which is why the name match still crosses
            // handle types, and why it used to fuse two same-named
            // people. `imdb` and `born` are the clauses that carry
            // across: both come from vocabularies a provider does not
            // own, so a Wikidata-identified row and a TVmaze-identified
            // credit finally have something to disagree about. See the
            // doc comment for why `born` does the cross-provider work
            // and `imdb` mostly does not.
            existing = self
                .db
                .query_row(
                    "SELECT id FROM people
                      WHERE name=?1 COLLATE NOCASE
                        AND (?2 = 0  OR tvmaze_id = 0     OR tvmaze_id = ?2)
                        AND (?3 = '' OR wikidata_qid = '' OR wikidata_qid = ?3)
                        AND (?4 = '' OR imdb = ''         OR imdb = ?4)
                        AND (?5 = '' OR born = ''         OR born = ?5)
                      ORDER BY id LIMIT 1",
                    rusqlite::params![name, c.tvmaze_id, c.wikidata_qid, c.imdb, c.born],
                    |r| r.get(0),
                )
                .optional()?;
        }
        let Some(id) = existing else {
            self.db.execute(
                "INSERT INTO people(name, imdb, tvmaze_id, wikidata_qid, born, photo)
                 VALUES(?1, ?2, ?3, ?4, ?5, ?6)",
                rusqlite::params![name, c.imdb, c.tvmaze_id, c.wikidata_qid, c.born, c.photo],
            )?;
            return Ok(self.db.last_insert_rowid());
        };
        // Fill blanks only. A second provider adds the handle the first
        // one lacked; it never overwrites one that is already set, or a
        // photo the user may have replaced.
        self.db.execute(
            "UPDATE people SET
                imdb         = CASE WHEN imdb=''         THEN ?2 ELSE imdb END,
                tvmaze_id    = CASE WHEN tvmaze_id=0     THEN ?3 ELSE tvmaze_id END,
                wikidata_qid = CASE WHEN wikidata_qid='' THEN ?4 ELSE wikidata_qid END,
                born         = CASE WHEN born=''         THEN ?5 ELSE born END,
                photo        = CASE WHEN photo=''        THEN ?6 ELSE photo END
              WHERE id=?1",
            rusqlite::params![id, c.imdb, c.tvmaze_id, c.wikidata_qid, c.born, c.photo],
        )?;
        Ok(id)
    }

    /// Replace one title's credits. Whole-set replacement, in one
    /// transaction: a re-enrichment that found fewer people must not
    /// leave the ones it no longer believes in behind, and a half-written
    /// cast is worse than the old one.
    pub fn title_credits_set(&self, key: &str, credits: &[Credit]) -> rusqlite::Result<()> {
        let tx = self.db.unchecked_transaction()?;
        tx.execute("DELETE FROM title_people WHERE key=?1", [key])?;
        for c in credits {
            if c.name.trim().is_empty() {
                continue;
            }
            let id = self.person_upsert(c)?;
            // OR REPLACE, not OR IGNORE: (key, person, role) is the
            // primary key, so an actor credited twice (dual role) keeps
            // the later character rather than failing the whole set.
            tx.execute(
                "INSERT OR REPLACE INTO title_people(key, person_id, role, character, ord)
                 VALUES(?1, ?2, ?3, ?4, ?5)",
                rusqlite::params![
                    key,
                    id,
                    if c.role.is_empty() { "actor" } else { &c.role },
                    c.character,
                    c.ord
                ],
            )?;
        }
        tx.commit()
    }

    /// One title's credits, billing order first (the detail sheet's cast
    /// chips). Crew follow the cast, since `ord` is 0 for them.
    pub fn title_credits(&self, key: &str, limit: u32) -> rusqlite::Result<Vec<PersonCredit>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT p.id, p.name, p.photo, tp.role, tp.character, tp.ord
               FROM title_people tp JOIN people p ON p.id = tp.person_id
              WHERE tp.key = ?1
              ORDER BY (tp.role <> 'actor'), tp.ord, p.name
              LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![key, limit], |r| {
            Ok(PersonCredit {
                person_id: r.get(0)?,
                name: r.get(1)?,
                photo: r.get(2)?,
                role: r.get(3)?,
                character: r.get(4)?,
                ord: r.get(5)?,
            })
        })?;
        rows.collect()
    }

    pub fn person_get(&self, id: i64) -> rusqlite::Result<Option<PersonRow>> {
        self.db
            .query_row(
                "SELECT id, name, imdb, tvmaze_id, wikidata_qid, bio, born, photo
                   FROM people WHERE id=?1",
                [id],
                |r| {
                    Ok(PersonRow {
                        id: r.get(0)?,
                        name: r.get(1)?,
                        imdb: r.get(2)?,
                        tvmaze_id: r.get(3)?,
                        wikidata_qid: r.get(4)?,
                        bio: r.get(5)?,
                        born: r.get(6)?,
                        photo: r.get(7)?,
                    })
                },
            )
            .optional()
    }

    /// The person page's "in your index" half: every title they are
    /// credited on that the wall would actually show.
    ///
    /// Curation is not optional here. A title hidden with "Not
    /// interested", or filtered out by a learned language/group rule,
    /// must stay gone on this surface too - otherwise clicking a cast
    /// member is a way to walk straight back into what the user just
    /// told us to stop showing them.
    pub fn person_titles(&self, id: i64) -> rusqlite::Result<Vec<PersonTitle>> {
        let mut wheres: Vec<String> = vec!["r.junk < 50".into()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = vec![Box::new(id)];
        self.curation_wheres("r.", &mut wheres, &mut params)?;
        // Undated titles sort last rather than heading a date-ordered
        // list - a Wikidata film with no P577 is not "the newest".
        // GROUPed by title, not one row per credit: someone who both
        // stars in a show and produces it holds two `title_people` rows,
        // and listing their own filmography twice is a bug the join
        // produces for free. The roles collapse into one comma-joined
        // list and the character comes from the acting credit.
        let sql = format!(
            "SELECT t.key, t.kind, t.title, t.year, t.poster, t.air_date,
                    GROUP_CONCAT(DISTINCT tp.role),
                    MAX(CASE WHEN tp.role='actor' THEN tp.character ELSE '' END),
                    MIN(tp.ord),
                    (SELECT COUNT(*) FROM releases r2
                      WHERE r2.title_key = t.key AND r2.junk < 50)
               FROM title_people tp JOIN titles t ON t.key = tp.key
              WHERE tp.person_id = ?1
                AND EXISTS(SELECT 1 FROM releases r
                            WHERE r.title_key = t.key AND {})
              GROUP BY t.key
              ORDER BY (COALESCE(NULLIF(t.air_date,''),
                                 NULLIF(CAST(t.year AS TEXT),'0')) IS NULL),
                       COALESCE(NULLIF(t.air_date,''),
                                NULLIF(CAST(t.year AS TEXT),'0')) DESC,
                       t.title",
            wheres.join(" AND ")
        );
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| {
            Ok(PersonTitle {
                key: r.get(0)?,
                kind: r.get(1)?,
                title: r.get(2)?,
                year: r.get::<_, i64>(3)? as u32,
                poster: r.get(4)?,
                air_date: r.get(5)?,
                role: r.get(6)?,
                character: r.get(7)?,
                ord: r.get(8)?,
                n_releases: r.get(9)?,
            })
        })?;
        rows.collect()
    }

    /// Name search over `people`. FTS5 prefix match so "tom cru" finds
    /// Tom Cruise mid-type; the LIKE arm keeps a non-FTS build working.
    /// Only people with at least one visible credit are returned - a
    /// crew name from a title the user has hidden is not a search hit.
    pub(super) fn people_search_once(
        &self,
        q: &str,
        limit: u32,
    ) -> rusqlite::Result<Vec<PersonHit>> {
        let q = q.trim();
        if q.is_empty() {
            return Ok(Vec::new());
        }
        let credited = "(SELECT COUNT(*) FROM title_people tp
                          WHERE tp.person_id = p.id
                            AND EXISTS(SELECT 1 FROM releases r
                                        WHERE r.title_key = tp.key AND r.junk < 50
                                          AND r.title_key NOT IN
                                              (SELECT key FROM wall_hidden)))";
        let (sql, param): (String, Box<dyn rusqlite::ToSql>) = if self.people_fts {
            // Quote every token and append * to the last: FTS5 syntax
            // characters in a user's query would otherwise be operators
            // (or a parse error that returns nothing).
            let mut toks: Vec<String> = q
                .split_whitespace()
                .map(|w| format!("\"{}\"", w.replace('"', "\"\"")))
                .collect();
            if let Some(last) = toks.last_mut() {
                last.push('*');
            }
            (
                format!(
                    "SELECT p.id, p.name, p.photo, {credited} n
                       FROM people_fts f JOIN people p ON p.id = f.rowid
                      WHERE people_fts MATCH ?1 AND n > 0
                      ORDER BY n DESC, p.name LIMIT ?2"
                ),
                Box::new(toks.join(" ")),
            )
        } else {
            (
                format!(
                    "SELECT p.id, p.name, p.photo, {credited} n
                       FROM people p
                      WHERE p.name LIKE ?1 AND n > 0
                      ORDER BY n DESC, p.name LIMIT ?2"
                ),
                Box::new(format!("%{q}%")),
            )
        };
        let mut stmt = self.db.prepare(&sql)?;
        let binds: Vec<Box<dyn rusqlite::ToSql>> = vec![param, Box::new(limit as i64)];
        let rows = stmt.query_map(rusqlite::params_from_iter(binds.iter()), |r| {
            Ok(PersonHit {
                id: r.get(0)?,
                name: r.get(1)?,
                photo: r.get(2)?,
                n_titles: r.get(3)?,
            })
        })?;
        rows.collect()
    }

    /// Title keys a set of people are credited on, curated - the search
    /// leg that turns "tom cruise" into the cards the user actually has.
    pub fn titles_for_people(&self, ids: &[i64], limit: u32) -> rusqlite::Result<Vec<String>> {
        if ids.is_empty() {
            return Ok(Vec::new());
        }
        let mut wheres: Vec<String> = vec!["r.junk < 50".into()];
        let mut params: Vec<Box<dyn rusqlite::ToSql>> = Vec::new();
        self.curation_wheres("r.", &mut wheres, &mut params)?;
        // ids are i64 read from our own table, so inlining them cannot
        // carry a caller string into the SQL.
        let list = ids
            .iter()
            .map(|i| i.to_string())
            .collect::<Vec<_>>()
            .join(",");
        params.push(Box::new(limit as i64));
        let n = params.len();
        let sql = format!(
            "SELECT tp.key FROM title_people tp
              WHERE tp.person_id IN ({list})
                AND EXISTS(SELECT 1 FROM releases r
                            WHERE r.title_key = tp.key AND {})
              GROUP BY tp.key
              ORDER BY MIN(tp.ord), tp.key LIMIT ?{n}",
            wheres.join(" AND ")
        );
        let mut stmt = self.db.prepare(&sql)?;
        let rows = stmt.query_map(rusqlite::params_from_iter(params.iter()), |r| r.get(0))?;
        rows.collect()
    }

    /// (id, headshot URL) for people credited on a visible title, paged
    /// by id - the headshot lane's work queue.
    ///
    /// An id cursor rather than "most credited first": the caller skips
    /// the ones already on disk, and a popularity order would re-offer
    /// the same top rows on every pass and never reach the tail.
    pub fn people_photo_queue(
        &self,
        after_id: i64,
        limit: u32,
    ) -> rusqlite::Result<Vec<(i64, String)>> {
        let mut stmt = self.db.prepare_cached(
            "SELECT p.id, p.photo FROM people p
              WHERE p.id > ?1 AND p.photo LIKE 'http%'
                AND EXISTS(SELECT 1 FROM title_people tp
                            JOIN releases r ON r.title_key = tp.key
                           WHERE tp.person_id = p.id AND r.junk < 50)
              ORDER BY p.id LIMIT ?2",
        )?;
        let rows = stmt.query_map(rusqlite::params![after_id, limit], |r| {
            Ok((r.get(0)?, r.get(1)?))
        })?;
        rows.collect()
    }

    /// Drop a headshot URL that will never work (404, not an image), so
    /// the queue stops offering it.
    pub fn person_clear_photo(&self, id: i64) -> rusqlite::Result<()> {
        self.db
            .execute("UPDATE people SET photo='' WHERE id=?1", [id])?;
        Ok(())
    }

    /// Every title key currently classified into `kind`. Used by eviction
    /// protection for a watch item that intentionally names a whole custom
    /// category (empty title): protecting only a 200-card browse page would
    /// make the rest of that category disappear under size pressure.
    pub fn title_keys_for_kind(&self, kind: &str) -> rusqlite::Result<Vec<String>> {
        let mut stmt = self.db.prepare(
            "SELECT DISTINCT title_key FROM releases
             WHERE kind=?1 AND title_key <> ''",
        )?;
        stmt.query_map([kind], |r| r.get(0))?
            .collect::<rusqlite::Result<Vec<_>>>()
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::index::testutil::{entry, teardown};

    /// TODO 26c: the one-off that puts back titles a transient provider
    /// failure blanked, and - just as important - what it must NOT
    /// touch.
    ///
    /// The live index accumulated these for months, because the
    /// enricher stamped `checked` on any miss and `title_fill` writes
    /// the card and that stamp in one statement. Nothing recorded WHY a
    /// row came back empty, so the sweep works off the shape a blanked
    /// row leaves behind - which makes it a superset, and makes running
    /// it exactly once the whole design.
    #[test]
    fn the_transient_unstamp_sweep_re_queues_blanks_and_spares_everything_else() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-unstamp-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        let blank = |key: &str, kind: &str| {
            ix.title_seed(key, kind, key, 0).unwrap();
            // Exactly what the lane wrote for a 429 before this landed.
            ix.title_fill(key, &TitleFill::default(), 100).unwrap();
        };
        blank("m:blanked", "movie");
        blank("t:blanked", "tv");
        // Junk: `Kind::Other` is stamped WITHOUT asking any provider, so
        // sweeping it back in would re-queue every obfuscated stem on
        // the wall to be stamped again unlooked, forever.
        blank("x:junk", "other");
        // A real answer, and a Wikipedia-only card - no provider id, but
        // a plot. Both are verdicts and must be left alone.
        ix.title_seed("m:real", "movie", "Real", 1999).unwrap();
        ix.title_fill(
            "m:real",
            &TitleFill {
                tmdb_id: 603,
                id_src: "tmdb",
                overview: "Neo.",
                ..Default::default()
            },
            100,
        )
        .unwrap();
        ix.title_seed("m:wikionly", "movie", "Wiki Only", 0)
            .unwrap();
        ix.title_fill(
            "m:wikionly",
            &TitleFill {
                overview: "A film about something.",
                ..Default::default()
            },
            100,
        )
        .unwrap();
        // ...and one row nobody has looked at yet, which is already in
        // the queue and must not be counted twice.
        ix.title_seed("m:fresh", "movie", "Fresh", 0).unwrap();

        let budget = std::time::Duration::from_secs(30);
        let (n, done) = ix.titles_unstamp_blanked(budget).unwrap();
        assert_eq!((n, done), (2, true), "swept the wrong set of rows");
        let checked = |k: &str| ix.title_get(k).unwrap().unwrap().checked;
        assert_eq!(checked("m:blanked"), 0, "a blanked movie was left retired");
        assert_eq!(checked("t:blanked"), 0, "a blanked show was left retired");
        assert_eq!(
            checked("x:junk"),
            100,
            "a junk row was put back in the queue"
        );
        assert_eq!(checked("m:real"), 100, "a real card was re-queued");
        assert_eq!(
            checked("m:wikionly"),
            100,
            "a Wikipedia-only card is an ANSWER and must not be re-queued"
        );

        // ONE-OFF. The predicate is a superset - a title no provider
        // has ever heard of looks identical to one a 429 blanked - so a
        // sweep on every maintenance pass would re-queue the genuinely
        // unknown forever and the enricher would never settle.
        ix.title_fill("m:blanked", &TitleFill::default(), 200)
            .unwrap();
        assert_eq!(
            ix.titles_unstamp_blanked(budget).unwrap(),
            (0, true),
            "the sweep ran a second time"
        );
        assert_eq!(checked("m:blanked"), 200);

        // ...and the manual re-arm is what re-opens it, for an install
        // that collected more blanks after the automatic sweep.
        ix.titles_unstamp_rearm().unwrap();
        assert_eq!(ix.titles_unstamp_blanked(budget).unwrap(), (1, true));
        assert_eq!(checked("m:blanked"), 0);
        teardown(&dir, ix);
    }

    /// TODO 187: the TVDB backfill lane's eligibility, and the trap
    /// underneath it.
    ///
    /// The lane is what makes `tvdbid` work on an existing library, so
    /// what retires a row from it matters as much as what it fills. A
    /// provider that does not carry TVDB ids at all (every one in the
    /// chain except TVmaze, plus the wall's own match-fixing path) must
    /// not be able to stamp `tvdb_tried` by writing a 0 - that is how a
    /// column stays empty while every row claims to have been asked.
    #[test]
    fn the_tvdb_backfill_only_retires_a_row_that_was_asked() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-tvdb-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        ix.ingest(
            "alt.binaries.test",
            &[
                entry(
                    "\"Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv\" yEnc (1/1)",
                    "c@c",
                    "b1",
                    1 << 30,
                ),
                entry(
                    "\"Top.Gun.Maverick.2022.1080p.BluRay.x264-GRP.mkv\" yEnc (1/1)",
                    "a@a",
                    "t1",
                    1 << 30,
                ),
            ],
            1_000,
        )
        .unwrap();
        let key = |s: &str| {
            ix.browse_cards(
                &BrowseQuery::default(),
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap()
            .0
            .into_iter()
            .find(|c| c.title_key.contains(s))
            .unwrap_or_else(|| panic!("no card for {s}"))
            .title_key
        };
        let (bb, tg) = (key("breaking"), key("maverick"));
        ix.title_seed(&bb, "tv", "Breaking Bad", 0).unwrap();
        ix.title_seed(&tg, "movie", "Top Gun Maverick", 2022)
            .unwrap();
        let pending = |ix: &Index| -> Vec<String> {
            ix.titles_missing_tvdb(10)
                .unwrap()
                .into_iter()
                .map(|r| r.key)
                .collect()
        };

        // Unenriched: nothing to ask TVmaze WITH, so not yet eligible.
        assert!(pending(&ix).is_empty());

        // An unlabelled id is not eligible either - '' names no
        // namespace, so the lane must not ask TVmaze with it.
        ix.title_fill(
            &bb,
            &TitleFill {
                tmdb_id: 431,
                ..Default::default()
            },
            5,
        )
        .unwrap();
        assert!(pending(&ix).is_empty(), "'' id_src must not queue");

        // Enriched: the row now carries the TVmaze show id the lane
        // asks WITH, so it becomes eligible. Enrichment itself never
        // writes tvdb - one writer, and it is the lane that asked.
        // Labelled, as the enricher writes it since the id_src column
        // landed. An UNLABELLED id is deliberately ineligible: '' rows
        // may hold AniList media ids written before the column existed,
        // and asking TVmaze with one of those is the permanent
        // wrong-write documented on `titles_missing_tvdb`.
        ix.title_fill(
            &bb,
            &TitleFill {
                tmdb_id: 431,
                id_src: "tvmaze",
                ..Default::default()
            },
            5,
        )
        .unwrap();
        ix.title_fill(
            &tg,
            &TitleFill {
                tmdb_id: 361743,
                ..Default::default()
            },
            5,
        )
        .unwrap();
        // Movies are never in this lane: only TV rows have a TVDB id.
        assert_eq!(pending(&ix), vec![bb.clone()]);

        // TVmaze answered "no id for this show". That IS an answer, and
        // it retires the row - otherwise the lane asks forever.
        ix.title_set_tvdb(&bb, 0).unwrap();
        assert!(pending(&ix).is_empty());
        assert!(ix.title_key_for_tvdb(0).unwrap().is_empty());

        // And an id fills the column, resolves, and stays out of the
        // lane.
        ix.title_set_tvdb(&bb, 81189).unwrap();
        assert_eq!(
            ix.title_key_for_tvdb(81189).unwrap(),
            std::slice::from_ref(&bb)
        );
        assert!(pending(&ix).is_empty());
        assert!(ix.has_tvdb_ids().unwrap());
        // An id we hold nothing for is None, which the facade renders as
        // an empty feed - never as the whole index.
        assert!(ix.title_key_for_tvdb(999_999).unwrap().is_empty());

        // The reverse direction, which the wall's pull-search asks with
        // (a card knows its title key, not its ids). Same kind filter,
        // for the same reason: a movie row must not be able to
        // contribute something called a tvdbid.
        assert_eq!(ix.tvdb_id_for_title(&bb).unwrap(), Some(81189));
        assert_eq!(ix.tvdb_id_for_title(&tg).unwrap(), None);
        assert_eq!(ix.tvdb_id_for_title("nope").unwrap(), None);
        assert_eq!(ix.tvdb_id_for_title("").unwrap(), None);

        // A re-enrichment must not wipe the id it has no opinion about
        // - it is not the writer of this column.
        ix.title_fill(&bb, &TitleFill::default(), 6).unwrap();
        assert_eq!(
            ix.title_key_for_tvdb(81189).unwrap(),
            std::slice::from_ref(&bb)
        );

        // A hand-triggered reset is the one thing that DOES clear it,
        // and it puts the row back in the lane.
        ix.title_reset(&bb).unwrap();
        assert!(!ix.has_tvdb_ids().unwrap());
        ix.title_fill(
            &bb,
            &TitleFill {
                tmdb_id: 431,
                id_src: "tvmaze",
                ..Default::default()
            },
            7,
        )
        .unwrap();
        assert_eq!(pending(&ix), vec![bb.clone()]);

        // Codex sweep 7, H2: the lane asks TVmaze `/shows/<tmdb_id>`, so
        // a row whose id belongs to somebody else's numbering must never
        // be offered. This is the worst of the namespace mixing, because
        // it is a permanent WRONG WRITE rather than a miss: `tvdb_of_show`
        // only checks that the payload is about the show we asked about,
        // which any AniList media id that is also a live TVmaze show id
        // satisfies exactly - so an unrelated series' thetvdb id gets
        // stamped on this row with tvdb_tried=1, and Sonarr's `tvdbid=`
        // then resolves to the wrong title key for good.
        ix.title_reset(&bb).unwrap();
        ix.title_fill(
            &bb,
            &TitleFill {
                tmdb_id: 431,
                id_src: "anilist",
                ..Default::default()
            },
            8,
        )
        .unwrap();
        assert!(
            pending(&ix).is_empty(),
            "an AniList media id was queued to be asked of TVmaze"
        );
        // The caps gate reads the same queue through a cheaper door, and
        // the two must never disagree about what is outstanding.
        assert!(!ix.tvdb_backfill_pending().unwrap());
        // ...and the same row, once TVmaze is what actually answered.
        ix.title_fill(
            &bb,
            &TitleFill {
                tmdb_id: 431,
                id_src: "tvmaze",
                ..Default::default()
            },
            9,
        )
        .unwrap();
        assert_eq!(pending(&ix), vec![bb.clone()]);
        assert!(ix.tvdb_backfill_pending().unwrap());

        // Codex sweep 7, M3: the id is a claim about WHICH SERIES this
        // row is, so an identity correction has to drop it - the wall's
        // candidate arm swaps the provider identity and title_fill will
        // never rewrite this column, so series A's TVDB id used to
        // survive onto series B with no way back (the queue above wants
        // tvdb_tried=0 AND tvdb=0).
        ix.title_set_tvdb(&bb, 81189).unwrap();
        assert!(pending(&ix).is_empty());
        // Re-stating the SAME identity is a metadata refresh, not a
        // correction, and must keep it - or the lane re-asks TVmaze
        // about the same show on every refresh forever.
        ix.title_set_identity(&bb, "tv", "Breaking Bad", 0).unwrap();
        assert_eq!(
            ix.title_key_for_tvdb(81189).unwrap(),
            std::slice::from_ref(&bb)
        );
        assert!(pending(&ix).is_empty());
        // A real change drops it, and puts the row back in the queue.
        ix.title_set_identity(&bb, "tv", "Better Call Saul", 0)
            .unwrap();
        assert!(
            ix.title_key_for_tvdb(81189).unwrap().is_empty(),
            "the superseded series' tvdbid still names this row"
        );
        assert_eq!(pending(&ix), vec![bb]);
        teardown(&dir, ix);
    }

    /// A page of seeds is ONE transaction, and it lands exactly what a
    /// page of `title_seed` calls landed.
    ///
    /// The wall used to run one autocommit INSERT per unenriched card on
    /// the HTTP request path, each able to wait out the 10 s busy_timeout
    /// behind a scan chunk. The batch entry point has to keep both of the
    /// properties that made the loop safe to re-run: `OR IGNORE`, so an
    /// already-seeded key is untouched (in particular it must NOT reset
    /// an enriched row back to pending), and no bookkeeping demanded of
    /// the caller.
    #[test]
    fn a_page_of_title_seeds_is_one_transaction_and_never_overwrites() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-index-seedmany-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        let seed = |key: &str, kind: &str, title: &str, year: u32| TitleSeed {
            key: key.into(),
            kind: kind.into(),
            title: title.into(),
            year,
        };

        assert_eq!(ix.title_seed_many(&[]).unwrap(), 0, "no rows, no txn");
        let page = vec![
            seed("m:top gun maverick:2022", "movie", "Top Gun Maverick", 2022),
            seed("t:breaking bad", "tv", "Breaking Bad", 0),
        ];
        assert_eq!(ix.title_seed_many(&page).unwrap(), 2);
        assert_eq!(
            ix.title_get("t:breaking bad").unwrap().map(|r| r.title),
            Some("Breaking Bad".to_string())
        );

        // Enrichment stamps one of them; the next wall poll re-offers
        // the same page (the queue does not remember what it sent).
        ix.title_fill(
            "t:breaking bad",
            &TitleFill {
                tmdb_id: 1396,
                overview: "chemistry",
                id_src: "tvmaze",
                ..Default::default()
            },
            1,
        )
        .unwrap();
        assert_eq!(
            ix.title_seed_many(&page).unwrap(),
            0,
            "every key already exists: nothing is written"
        );
        let row = ix.title_get("t:breaking bad").unwrap().expect("the row");
        assert_eq!(
            (row.checked, row.tmdb_id, row.overview.as_str()),
            (1, 1396, "chemistry"),
            "a re-offered seed must not undo enrichment"
        );

        // A new card mixed into an already-seeded page still lands.
        let mut page2 = page.clone();
        page2.push(seed("m:dune:2021", "movie", "Dune", 2021));
        assert_eq!(ix.title_seed_many(&page2).unwrap(), 1);
        assert!(ix.title_get("m:dune:2021").unwrap().is_some());
        teardown(&dir, ix);
    }

    #[test]
    fn people_identity_credits_and_the_search_leg() {
        let dir = std::env::temp_dir().join(format!("nzbfast-index-people-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let mut ix = Index::open(&dir.join("index.db")).unwrap();
        assert!(ix.people_fts, "bundled sqlite is expected to ship FTS5");
        let mk = |f: &str, from: &str, id: &str| {
            entry(&format!("\"{f}\" yEnc (1/1)"), from, id, 4 << 30)
        };
        ix.ingest(
            "alt.binaries.test",
            &[
                mk(
                    "Top.Gun.Maverick.2022.1080p.BluRay.x264-GRP.mkv",
                    "a@a",
                    "t1",
                ),
                mk(
                    "Mission.Impossible.1996.1080p.BluRay.x264-GRP.mkv",
                    "b@b",
                    "m1",
                ),
                mk("Breaking.Bad.S01E01.720p.WEB.x264-GRP.mkv", "c@c", "b1"),
            ],
            1_000,
        )
        .unwrap();
        let key = |s: &str| {
            ix.browse_cards(
                &BrowseQuery::default(),
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap()
            .0
            .into_iter()
            .find(|c| c.title_key.contains(s))
            .unwrap_or_else(|| panic!("no card for {s}"))
            .title_key
        };
        let (tg, mi, bb) = (key("maverick"), key("mission"), key("breaking"));
        for (k, kind, title, year) in [
            (&tg, "movie", "Top Gun Maverick", 2022),
            (&mi, "movie", "Mission Impossible", 1996),
            (&bb, "tv", "Breaking Bad", 0),
        ] {
            ix.title_seed(k, kind, title, year).unwrap();
            ix.title_fill(
                k,
                &TitleFill {
                    tmdb_id: 1,
                    ..Default::default()
                },
                5,
            )
            .unwrap();
        }

        // A person seen first by Wikidata and later by TVmaze is ONE
        // person: the second provider fills the handle the first lacked
        // rather than forking the row.
        let cruise_wd = Credit {
            name: "Tom Cruise".into(),
            role: "actor".into(),
            character: "Maverick".into(),
            ord: 1,
            wikidata_qid: "Q37079".into(),
            ..Default::default()
        };
        ix.title_credits_set(&tg, std::slice::from_ref(&cruise_wd))
            .unwrap();
        ix.title_credits_set(
            &mi,
            &[Credit {
                name: "Tom Cruise".into(),
                role: "actor".into(),
                character: "Ethan Hunt".into(),
                ord: 1,
                tvmaze_id: 555,
                photo: "https://example.invalid/tc.jpg".into(),
                ..Default::default()
            }],
        )
        .unwrap();
        let n_people: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_people, 1, "one person, two providers");
        let p = ix.people_search("tom cru", 5).unwrap();
        assert_eq!(p.len(), 1, "prefix name search: {p:?}");
        assert_eq!((p[0].name.as_str(), p[0].n_titles), ("Tom Cruise", 2));
        let pid = p[0].id;
        let row = ix.person_get(pid).unwrap().unwrap();
        assert_eq!(
            (row.tvmaze_id, row.wikidata_qid.as_str()),
            (555, "Q37079"),
            "both handles landed on the one row"
        );

        // The person page's in-index half, newest release first.
        let mine = ix.person_titles(pid).unwrap();
        assert_eq!(mine.len(), 2);
        assert_eq!(
            mine[0].title, "Top Gun Maverick",
            "ordered by release date: {mine:?}"
        );
        assert_eq!(mine[0].character, "Maverick");

        // The search leg: "tom cruise" appears in no stem at all, so
        // before this it matched nothing.
        let found = |q: &str| {
            ix.browse_cards(
                &BrowseQuery {
                    q: q.into(),
                    max_junk: Some(50),
                    curated: true,
                    ..Default::default()
                },
                CardSort::Latest,
                false,
                false,
                None,
            )
            .unwrap()
            .1
        };
        assert_eq!(found("tom cruise"), 2, "the people leg found no titles");
        // …and it is an OR, so stem search is untouched.
        assert_eq!(found("maverick"), 1);
        assert_eq!(found("nobody at all"), 0);

        // Curation is not optional on person surfaces: hiding a title
        // must remove it from the person page and from the search leg,
        // or a cast chip is a way back into what the user just hid.
        ix.hide_title(&tg).unwrap();
        assert_eq!(
            ix.person_titles(pid).unwrap().len(),
            1,
            "hidden title still listed"
        );
        assert_eq!(
            found("tom cruise"),
            1,
            "hidden title still searchable by cast"
        );
        assert_eq!(ix.people_search("tom cru", 5).unwrap()[0].n_titles, 1);
        ix.unhide_title(&tg).unwrap();

        // A DIFFERENT person who happens to share the name must not be
        // absorbed once either side carries a handle.
        ix.title_credits_set(
            &bb,
            &[Credit {
                name: "Tom Cruise".into(),
                role: "actor".into(),
                tvmaze_id: 999,
                ..Default::default()
            }],
        )
        .unwrap();
        let n_people: i64 = ix
            .db
            .query_row("SELECT COUNT(*) FROM people", [], |r| r.get(0))
            .unwrap();
        assert_eq!(n_people, 2, "a conflicting handle forks, it does not merge");
        // They stay separate people with separate filmographies, but a
        // name search legitimately matches both - the searcher typed a
        // name, not an identity.
        assert_eq!(
            ix.person_titles(pid).unwrap().len(),
            2,
            "the fork stole a credit"
        );
        assert_eq!(found("tom cruise"), 3);

        // Re-enrichment replaces the whole set rather than accumulating
        // credits the provider no longer believes in.
        ix.title_credits_set(&tg, &[cruise_wd]).unwrap();
        assert_eq!(ix.title_credits(&tg, 40).unwrap().len(), 1);

        // A merged card keeps its credits.
        ix.merge_title(&mi, &tg).unwrap();
        assert!(ix.person_titles(pid).unwrap().iter().any(|t| t.key == tg));
        assert_eq!(
            ix.db
                .query_row(
                    "SELECT COUNT(*) FROM title_people WHERE key=?1",
                    [&mi],
                    |r| r.get::<_, i64>(0)
                )
                .unwrap(),
            0,
            "the merged-away key still holds credits"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn title_identity_reset_roundtrip() {
        let dir = std::env::temp_dir().join(format!("nzbfast-titles-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();

        // Upsert works with no prior seed, then survives a later seed
        // attempt (INSERT OR IGNORE must not clobber the correction).
        ix.title_set_identity("m:matrix", "movie", "The Matrix", 1999)
            .unwrap();
        ix.title_seed("m:matrix", "other", "matrix", 0).unwrap();
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!(
            (t.kind.as_str(), t.title.as_str(), t.year),
            ("movie", "The Matrix", 1999)
        );
        assert_eq!(t.checked, 0); // never looked up → pending

        // Fill, then re-scrub identity: metadata columns are preserved.
        ix.title_fill(
            "m:matrix",
            &TitleFill {
                tmdb_id: 603,
                overview: "Neo.",
                rating: 8.7,
                genres: "Sci-Fi",
                poster: "p.jpg",
                backdrop: "b.jpg",
                imdb: "tt0133093",
                actors: "Keanu",
                air_date: "1999-03-30",
                id_src: "tmdb",
            },
            111,
        )
        .unwrap();
        ix.title_set_identity("m:matrix", "movie", "The Matrix", 1998)
            .unwrap();
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!(
            (t.year, t.tmdb_id, t.overview.as_str()),
            (1998, 603, "Neo.")
        );
        assert_eq!(t.checked, 111);
        assert_eq!(t.air_date, "1999-03-30");

        // Reset wipes metadata (incl. imdb/actors) but keeps identity,
        // and flags pending.
        assert!(ix.title_reset("m:matrix").unwrap());
        let t = ix.title_get("m:matrix").unwrap().unwrap();
        assert_eq!((t.title.as_str(), t.year), ("The Matrix", 1998));
        assert_eq!((t.tmdb_id, t.checked), (0, 0));
        assert!(t.overview.is_empty() && t.poster.is_empty());
        assert!(t.imdb.is_empty() && t.actors.is_empty() && t.air_date.is_empty());
        assert!(!ix.title_reset("nope").unwrap());

        // Reset-all counts rows and pends everything.
        ix.title_seed("t:show", "tv", "Show", 0).unwrap();
        ix.title_fill(
            "t:show",
            &TitleFill {
                tmdb_id: 7,
                overview: "x",
                rating: 1.0,
                ..Default::default()
            },
            5,
        )
        .unwrap();
        assert_eq!(ix.titles_reset_all().unwrap(), 2);
        assert_eq!(ix.titles_pending(10).unwrap().len(), 2);

        // Enricher lanes partition `titles` - every pending row must be
        // claimed by exactly one lane, or a kind silently stops being
        // enriched (which is what happened to music and books).
        ix.title_seed("o:junk", "other", "junk", 0).unwrap();
        ix.title_seed("s:app", "software", "App", 0).unwrap();
        ix.title_seed("mu:album", "music", "Artist - Album", 0)
            .unwrap();
        ix.title_seed("bk:book", "book", "Author - Book", 0)
            .unwrap();
        // Every one needs a listable release: the backlog lane only
        // considers titles the wall would show, and a titles row with no
        // releases behind it is not a state the indexer ever produces.
        for (i, key) in [
            "m:matrix", "t:show", "o:junk", "s:app", "mu:album", "bk:book",
        ]
        .iter()
        .enumerate()
        {
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, title_key, junk, first_posted)
                     VALUES(?1,'p','g',?2,0,?3)",
                    rusqlite::params![format!("rel{i}"), key, 100 - i as i64],
                )
                .unwrap();
        }
        let lane = |l: Lane| -> Vec<String> {
            ix.titles_pending_lane(10, l)
                .unwrap()
                .into_iter()
                .map(|t| t.key)
                .collect()
        };
        assert_eq!(lane(Lane::Movies), ["m:matrix"]);
        let mut media = lane(Lane::MusicBooks);
        media.sort();
        assert_eq!(media, ["bk:book", "mu:album"]);
        let shows = lane(Lane::Shows);
        assert_eq!(shows.len(), 3);
        for k in ["m:matrix", "mu:album", "bk:book"] {
            assert!(!shows.contains(&k.to_string()), "{k} is in two lanes");
        }
        // The partition must be total: no pending row belongs to none.
        let all = ix.titles_pending(10).unwrap().len();
        assert_eq!(all, lane(Lane::Movies).len() + media.len() + shows.len());
        teardown(&dir, ix);
    }

    /// Enrichment is the scarcest resource here, and 75% of it was going
    /// to titles the wall would never list. The backlog query asks for a
    /// release that passes the junk gate; the viewport query deliberately
    /// does not (see `titles_hot`).
    #[test]
    fn the_backlog_lane_skips_titles_the_wall_would_not_show() {
        let dir = std::env::temp_dir().join(format!("nzbfast-vis-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let db = dir.join("index.db");
        let ix = Index::open(&db).unwrap();

        // Two titles, both pending: one with a listable release, one
        // whose only release is junk-gated.
        for (key, stem, junk) in [
            ("m:seen:2024", "Seen.Film.2024.1080p.BluRay.x264-GRP", 0),
            (
                "m:hidden:2024",
                "Hidden.Film.2024.1080p.BluRay.x264-GRP",
                70,
            ),
        ] {
            ix.title_seed(key, "movie", "x", 2024).unwrap();
            ix.db
                .execute(
                    "INSERT INTO releases(stem, poster, grp, title_key, kind, junk,
                                          first_posted)
                     VALUES(?1,'p','g',?2,'movie',?3,100)",
                    rusqlite::params![stem, key, junk],
                )
                .unwrap();
        }
        let pending: Vec<String> = ix
            .titles_pending_lane(10, Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert_eq!(pending, ["m:seen:2024"], "a junk-only title cost a lookup");

        // Viewport priority ignores the filter: on screen means wanted.
        let hot: Vec<String> = ix
            .titles_hot(&["m:hidden:2024".to_string()], Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert_eq!(
            hot,
            ["m:hidden:2024"],
            "an on-screen card must still enrich"
        );

        // Deferred, not dropped: junk is recomputed on every ingest touch
        // and a mid-upload release sheds it as parts arrive, so the title
        // must become eligible the moment it would be listed.
        ix.db
            .execute(
                "UPDATE releases SET junk=0 WHERE title_key='m:hidden:2024'",
                [],
            )
            .unwrap();
        let pending: Vec<String> = ix
            .titles_pending_lane(10, Lane::Movies)
            .unwrap()
            .into_iter()
            .map(|t| t.key)
            .collect();
        assert!(
            pending.contains(&"m:hidden:2024".to_string()),
            "a title that became visible was skipped for good: {pending:?}"
        );
        teardown(&dir, ix);
    }

    /// A wall-fix that loses the writer half way through must leave the
    /// row exactly as it was.
    ///
    /// The endpoint's two arms each used to autocommit the rename and
    /// then its second half separately, and the failure is silent and
    /// permanent rather than merely untidy: a renamed row wearing the
    /// previous series' metadata reads as a title somebody has already
    /// identified, so nothing ever prompts a re-fix. The injected
    /// failures below are what a scan chunk or a retention prune holding
    /// the writer past the busy timeout does to the second statement.
    #[test]
    fn a_refused_wall_fix_leaves_no_half_renamed_row() {
        let dir = std::env::temp_dir().join(format!("nzbfast-titles-fix-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        fn fill<'a>(tmdb: i64, plot: &'a str, art: &'a str) -> TitleFill<'a> {
            TitleFill {
                tmdb_id: tmdb,
                overview: plot,
                poster: art,
                ..Default::default()
            }
        }
        ix.title_set_identity("t:showa", "tv", "Show A", 2001)
            .unwrap();
        ix.title_fill("t:showa", &fill(11, "A's plot", "a.jpg"), 100)
            .unwrap();

        // The candidate arm: the fill half fails. `UPDATE OF tmdb_id`
        // cannot be tripped by the identity upsert, which sets only
        // kind/title/year.
        ix.db
            .execute_batch(
                "CREATE TRIGGER fix_fail_fill AFTER UPDATE OF tmdb_id ON titles
                   WHEN new.tmdb_id = 22
                 BEGIN SELECT RAISE(ABORT, 'injected fill failure'); END;",
            )
            .unwrap();
        let out = ix.title_set_identity_and_fill(
            "t:showa",
            "tv",
            "Show B",
            2019,
            &fill(22, "B's plot", "b.jpg"),
            200,
        );
        assert!(
            out.is_err(),
            "the injected failure did not surface: {out:?}"
        );
        ix.db.execute_batch("DROP TRIGGER fix_fail_fill").unwrap();

        // Two autocommitting writes left ("Show B", 2019) here with all
        // of A's metadata under it.
        let t = ix.title_get("t:showa").unwrap().unwrap();
        assert_eq!(
            (
                t.title.as_str(),
                t.year,
                t.tmdb_id,
                t.overview.as_str(),
                t.poster.as_str(),
                t.checked
            ),
            ("Show A", 2001, 11, "A's plot", "a.jpg", 100),
            "a refused fill left the row renamed"
        );

        // Unobstructed, both halves land.
        ix.title_set_identity_and_fill(
            "t:showa",
            "tv",
            "Show B",
            2019,
            &fill(22, "B's plot", "b.jpg"),
            200,
        )
        .unwrap();
        let t = ix.title_get("t:showa").unwrap().unwrap();
        assert_eq!(
            (t.title.as_str(), t.year, t.tmdb_id, t.checked),
            ("Show B", 2019, 22, 200)
        );

        // The re-fetch arm, where the stakes are sharper: `checked=0` is
        // the only thing that puts the row back in the enrichment queue,
        // so a rename committing without the reset is a rename that
        // never fetches. `air_tried` separates the two statements -
        // the reset writes 0, every fill writes 1.
        ix.db
            .execute_batch(
                "CREATE TRIGGER fix_fail_reset AFTER UPDATE OF air_tried ON titles
                   WHEN new.air_tried = 0
                 BEGIN SELECT RAISE(ABORT, 'injected reset failure'); END;",
            )
            .unwrap();
        let out = ix.title_set_identity_and_reset("t:showa", "tv", "Show C", 2020);
        assert!(
            out.is_err(),
            "the injected failure did not surface: {out:?}"
        );
        ix.db.execute_batch("DROP TRIGGER fix_fail_reset").unwrap();
        let t = ix.title_get("t:showa").unwrap().unwrap();
        assert_eq!(
            (t.title.as_str(), t.year, t.tmdb_id, t.checked),
            ("Show B", 2019, 22, 200),
            "a refused reset left the row renamed and still stamped as checked"
        );

        // And unobstructed: renamed, wiped, pending.
        ix.title_set_identity_and_reset("t:showa", "tv", "Show C", 2020)
            .unwrap();
        let t = ix.title_get("t:showa").unwrap().unwrap();
        assert_eq!(
            (t.title.as_str(), t.year, t.tmdb_id, t.checked),
            ("Show C", 2020, 0, 0)
        );
        assert!(t.overview.is_empty() && t.poster.is_empty());
        teardown(&dir, ix);
    }
}
