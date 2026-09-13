//! The FTS5 virtual tables the index searches through, and the triggers
//! that keep them in step with their content tables: the two release
//! indexes (raw stems, and the predb feed) plus the people index.
//!
//! Its own file rather than a block in `schema.rs`, which stood at 3,469
//! of the size gate's 4,000-line file ceiling on 7 Sep 2026 (claim
//! `debt-split-hot-files-7sep`). One subject - an OPTIONAL subsystem
//! whose absence the rest of the schema is written to tolerate, which is
//! why both entry points hand back an availability flag rather than an
//! error - and two callers, both in [`super::Index::open`]. Verbatim
//! move; the only rewrite is `fn` -> `pub(super) fn`.

use super::*;

/// The two release FTS tables; (fts, pre_fts) availability flags.
pub(super) fn ensure_fts(db: &Connection) -> (bool, bool) {
    // M28: FTS5 over raw stems (unicode61 tokenizer already treats
    // ./-/_ as separators, so no normalized shadow column is needed).
    // External-content table + triggers stay in sync with prune
    // deletes; stems are immutable so no UPDATE trigger. Wrapped in
    // is_ok() so a non-FTS build just keeps the LIKE path.
    let fts = db
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS rel_fts
               USING fts5(stem, content='releases', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS rel_fts_ai AFTER INSERT ON releases BEGIN
               INSERT INTO rel_fts(rowid, stem) VALUES(new.id, new.stem); END;
             CREATE TRIGGER IF NOT EXISTS rel_fts_ad AFTER DELETE ON releases BEGIN
               INSERT INTO rel_fts(rel_fts, rowid, stem)
                 VALUES('delete', old.id, old.stem); END;",
        )
        .is_ok();
    // A SECOND, tiny FTS index over the names the pre feed supplied.
    //
    // Not a column added to `rel_fts`: that is an external-content
    // table over millions of stems, and widening it means dropping,
    // recreating and rebuilding the whole thing at open - a minutes-
    // long startup stall on a large index, paid by every install
    // including the ones that never turn the feed on. This one only
    // ever holds rows that HAVE a fed name, so on a default install
    // it stays empty and costs a table definition.
    //
    // Unlike stems, a fed name arrives by UPDATE (the retro sweep
    // names a release long after it was inserted), so this one does
    // need the update trigger the stem index can do without.
    let pre_fts = db
        .execute_batch(
            "CREATE VIRTUAL TABLE IF NOT EXISTS pre_fts
               USING fts5(pre_title, content='releases', content_rowid='id');
             CREATE TRIGGER IF NOT EXISTS pre_fts_ai AFTER INSERT ON releases
               WHEN new.pre_title<>'' BEGIN
                 INSERT INTO pre_fts(rowid, pre_title)
                   VALUES(new.id, new.pre_title); END;
             CREATE TRIGGER IF NOT EXISTS pre_fts_ad AFTER DELETE ON releases
               WHEN old.pre_title<>'' BEGIN
                 INSERT INTO pre_fts(pre_fts, rowid, pre_title)
                   VALUES('delete', old.id, old.pre_title); END;
             CREATE TRIGGER IF NOT EXISTS pre_fts_au
               AFTER UPDATE OF pre_title ON releases BEGIN
                 INSERT INTO pre_fts(pre_fts, rowid, pre_title)
                   SELECT 'delete', old.id, old.pre_title WHERE old.pre_title<>'';
                 INSERT INTO pre_fts(rowid, pre_title)
                   SELECT new.id, new.pre_title WHERE new.pre_title<>''; END;",
        )
        .is_ok();
    (fts, pre_fts)
}

/// People + credits schema (fatal on failure, unlike the migrations)
/// and the people_fts index; returns whether people_fts is usable.
pub(super) fn ensure_people(db: &Connection) -> rusqlite::Result<bool> {
    // Cast and crew as entities rather than a rendered string.
    // `titles.actors` stays exactly as it is - it is what every card
    // renders today, and nothing may regress while this join table
    // fills in behind it. The join table is what the person page,
    // name search and cast-overlap affinity read.
    db.execute_batch(
        "CREATE TABLE IF NOT EXISTS people(
            id           INTEGER PRIMARY KEY,
            name         TEXT NOT NULL,
            imdb         TEXT NOT NULL DEFAULT '',
            -- The two filmography handles. TVmaze's person id answers
            -- 'what else did they do on TV'; the Wikidata Q-id answers
            -- the film half. Neither source covers the other, so a
            -- person legitimately carries both.
            tvmaze_id    INTEGER NOT NULL DEFAULT 0,
            wikidata_qid TEXT NOT NULL DEFAULT '',
            bio          TEXT NOT NULL DEFAULT '',
            born         TEXT NOT NULL DEFAULT '',
            -- The provider's headshot URL, and unlike titles.poster
            -- it stays a URL. The cached file is evictable (a large
            -- index would otherwise quietly fill a NAS with
            -- headshots), and after an eviction the URL is the only
            -- thing that can fetch it back.
            photo        TEXT NOT NULL DEFAULT '',
            checked      INTEGER NOT NULL DEFAULT 0);
         CREATE TABLE IF NOT EXISTS title_people(
            key       TEXT NOT NULL,
            person_id INTEGER NOT NULL,
            role      TEXT NOT NULL DEFAULT 'actor',
            character TEXT NOT NULL DEFAULT '',
            ord       INTEGER NOT NULL DEFAULT 0,
            PRIMARY KEY(key, person_id, role));
         CREATE INDEX IF NOT EXISTS idx_tp_person ON title_people(person_id, ord);
         -- Partial uniques, so the handle-first upsert cannot race two
         -- threads into two rows for one person. They must stay
         -- partial: the default 0 / '' is 'no handle', and a plain
         -- UNIQUE would let exactly one person exist without one.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_tvmaze
           ON people(tvmaze_id) WHERE tvmaze_id > 0;
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_qid
           ON people(wikidata_qid) WHERE wikidata_qid <> '';
         -- Same rule for the IMDb id, and safe to add to an existing
         -- database: nothing ever wrote this column before the
         -- Wikidata P345 lane did, so every pre-existing row holds
         -- '' and falls outside the partial index. It carries the
         -- same trade the other two already do - the blank-fill
         -- UPDATE can collide when the handle-first lookup lands on
         -- a row whose blank belongs to another row's id, which
         -- fails that one title's credit write and lets the next
         -- enrichment retry it. Duplicate Wikidata items for one
         -- person, which is the common way two rows share an nm id,
         -- resolve through the lookup instead and merge cleanly.
         CREATE UNIQUE INDEX IF NOT EXISTS idx_people_imdb
           ON people(imdb) WHERE imdb <> '';
         CREATE INDEX IF NOT EXISTS idx_people_name ON people(name COLLATE NOCASE);",
    )?;
    // Name search. Unlike rel_fts there IS an UPDATE trigger: a
    // person row's name improves when a second provider supplies a
    // better-cased or fuller spelling, and an external-content FTS
    // that missed the update returns the row under a name it no
    // longer has.
    let people_fts = db.execute_batch(
        "CREATE VIRTUAL TABLE IF NOT EXISTS people_fts
           USING fts5(name, content='people', content_rowid='id');
         CREATE TRIGGER IF NOT EXISTS people_fts_ai AFTER INSERT ON people BEGIN
           INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;
         CREATE TRIGGER IF NOT EXISTS people_fts_ad AFTER DELETE ON people BEGIN
           INSERT INTO people_fts(people_fts, rowid, name)
             VALUES('delete', old.id, old.name); END;
         CREATE TRIGGER IF NOT EXISTS people_fts_au
           AFTER UPDATE OF name ON people BEGIN
           INSERT INTO people_fts(people_fts, rowid, name)
             VALUES('delete', old.id, old.name);
           INSERT INTO people_fts(rowid, name) VALUES(new.id, new.name); END;",
    );
    Ok(people_fts.is_ok())
}
