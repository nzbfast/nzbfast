//! Upload-session siblings: the first consumer of the `sess_idx`/
//! `sess_total` columns the ingest side has persisted since §131
//! ("a future pass can stitch the per-file rows into one release" -
//! this is that pass, read-only).
//!
//! Motivation (research/FINGERPRINT-next-episode-2026-08-14.md): 84%
//! of obfuscated next-episodes are posted in the SAME session as the
//! episode in hand, and the durable cross-post signal is the posting
//! tool, not the poster handle (which rotates per post for 86% of the
//! obfuscated cohort). Given one identified release, its session
//! siblings are very probably the rest of the season.
//!
//! Everything returned here is ASSOCIATION evidence in the
//! [`super::NameEvidence::Adjacency`] sense: it may rank and surface,
//! it may never name. No claim rows are written and no release is
//! renamed by this module.

use super::*;

/// Why a sibling was linked to the anchor, strongest first. The order
/// is the measured order: counter streams held for 91% of fingerprinted
/// episode pairs, a repeated poster handle is rare but decisive when it
/// happens, session tags are a self-declared position in one upload
/// run, and bare time+size adjacency is the weakest cut.
#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub enum SessionLink {
    /// Both releases carry pesto message-id counters from the same
    /// per-session stream (ranges overlap or sit within one gap).
    Counter,
    /// Same poster handle. Obfuscated uploaders rotate handles, so
    /// when one repeats inside the window it is the same person.
    Poster,
    /// Matching `[i/N]` session tags: both posts declare membership of
    /// one N-file upload run.
    Tags,
    /// Posted together (tight window, comparable size). The weakest
    /// link and the only one that needs the size band.
    Time,
}

impl SessionLink {
    /// Stable wire tag for the API payload.
    pub fn tag(self) -> &'static str {
        match self {
            SessionLink::Counter => "counter",
            SessionLink::Poster => "poster",
            SessionLink::Tags => "tags",
            SessionLink::Time => "time",
        }
    }
}

/// One session sibling of an anchor release.
#[derive(Debug, Clone)]
pub struct SessionSibling {
    /// The sibling release itself.
    pub rel: Release,
    /// What linked it to the anchor. The sort key ahead of `dt`, so
    /// the strongest link kind comes first whatever the times say.
    pub link: SessionLink,
    /// Candidate minus anchor `first_posted`, seconds. Display only -
    /// pesto randomizes Date headers, so this can lie for counter-
    /// linked rows.
    pub dt: i64,
}

/// How far apart two counter ranges may sit and still read as one
/// stream. Measured on the recovered-name cohort: gaps 0..5000 covered
/// 21 of 23 true episode pairs.
const CTR_GAP: i64 = 5_000;

/// Sides of the time window around the anchor's `first_posted`. 84% of
/// true siblings land inside an hour; four gives slow posts room.
const TIME_WINDOW: i64 = 4 * 3600;

/// Floor under candidate payloads. Sidecars and junk singles sit far
/// below it; nothing episode-shaped does.
const MIN_BYTES: i64 = 20_000_000;

/// The declared-total floor for a `[i/N]` tag link: `[1/2]`-style
/// totals repeat across unrelated posts constantly, a 10+ file session
/// declaration inside the same window does not.
const TAGS_MIN_TOTAL: i64 = 3;

/// Extra per-row columns the linking needs on top of [`REL_COLS`].
const SESS_EXTRA: &str = "pesto_ctr_min, pesto_ctr_max, sess_total, title_key, junk";

struct SessRow {
    rel: Release,
    ctr_min: Option<i64>,
    ctr_max: Option<i64>,
    sess_total: Option<i64>,
    title_key: String,
}

fn sess_row(r: &rusqlite::Row) -> rusqlite::Result<SessRow> {
    Ok(SessRow {
        rel: release_from_row(r)?,
        ctr_min: r.get(19)?,
        ctr_max: r.get(20)?,
        sess_total: r.get(21)?,
        title_key: r.get(22)?,
    })
}

impl Index {
    /// The upload-session siblings of one release: other posts in the
    /// same group that look like members of the same upload run, linked
    /// by counter stream, repeated poster, session tags, or bare
    /// time+size adjacency - strongest link first, then nearest in
    /// time. Read-only; see the module doc for what this may never do.
    pub fn session_siblings(
        &self,
        release_id: i64,
        limit: usize,
    ) -> rusqlite::Result<Vec<SessionSibling>> {
        let anchor = match self
            .db
            .prepare_cached(&format!(
                "SELECT {REL_COLS}, {SESS_EXTRA} FROM releases WHERE id=?1"
            ))?
            .query_row([release_id], sess_row)
            .optional()?
        {
            Some(a) => a,
            None => return Ok(Vec::new()),
        };

        // Time arm: posted around the anchor. Junk 100 is the spam
        // verdict; every obfuscation score below it stays in - the
        // obfuscated rows ARE the quarry (cohort junk profile:
        // 0/55/60/70, with junk=100 at 7 rows of 9,141).
        let mut rows: Vec<SessRow> = self
            .db
            .prepare_cached(&format!(
                "SELECT {REL_COLS}, {SESS_EXTRA} FROM releases
                  WHERE grp=?1 AND id<>?2
                    AND first_posted BETWEEN ?3 AND ?4
                    AND total_bytes >= ?5 AND junk < 100"
            ))?
            .query_map(
                rusqlite::params![
                    anchor.rel.grp,
                    release_id,
                    anchor.rel.first_posted - TIME_WINDOW,
                    anchor.rel.first_posted + TIME_WINDOW,
                    MIN_BYTES
                ],
                sess_row,
            )?
            .collect::<rusqlite::Result<_>>()?;

        // Counter arm: same stream regardless of what the Date headers
        // claim (pesto randomizes them). Rides the partial
        // idx_rel_pesto(grp, pesto_ctr_min) index.
        if let (Some(a_min), Some(a_max)) = (anchor.ctr_min, anchor.ctr_max) {
            let more: Vec<SessRow> = self
                .db
                .prepare_cached(&format!(
                    "SELECT {REL_COLS}, {SESS_EXTRA} FROM releases
                      WHERE grp=?1 AND id<>?2
                        AND pesto_ctr_min IS NOT NULL
                        AND pesto_ctr_min <= ?3 AND pesto_ctr_max >= ?4
                        AND total_bytes >= ?5 AND junk < 100"
                ))?
                .query_map(
                    rusqlite::params![
                        anchor.rel.grp,
                        release_id,
                        a_max + CTR_GAP,
                        a_min - CTR_GAP,
                        MIN_BYTES
                    ],
                    sess_row,
                )?
                .collect::<rusqlite::Result<_>>()?;
            let seen: std::collections::HashSet<i64> = rows.iter().map(|c| c.rel.id).collect();
            rows.extend(more.into_iter().filter(|c| !seen.contains(&c.rel.id)));
        }

        let mut out: Vec<SessionSibling> = rows
            .into_iter()
            .filter(|c| anchor.title_key.is_empty() || c.title_key != anchor.title_key)
            .filter_map(|c| {
                let counter = match (anchor.ctr_min, anchor.ctr_max, c.ctr_min, c.ctr_max) {
                    (Some(am), Some(ax), Some(cm), Some(cx)) => {
                        cm <= ax + CTR_GAP && cx >= am - CTR_GAP
                    }
                    _ => false,
                };
                let dt = c.rel.first_posted - anchor.rel.first_posted;
                let in_window = dt.abs() <= TIME_WINDOW;
                let link = if counter {
                    SessionLink::Counter
                } else if in_window && !c.rel.poster.is_empty() && c.rel.poster == anchor.rel.poster
                {
                    SessionLink::Poster
                } else if in_window
                    && anchor.sess_total.is_some()
                    && anchor.sess_total == c.sess_total
                    && anchor.sess_total.unwrap_or(0) >= TAGS_MIN_TOTAL
                {
                    SessionLink::Tags
                } else if in_window
                    && anchor.rel.total_bytes > 0
                    && c.rel.total_bytes >= anchor.rel.total_bytes / 3
                    && c.rel.total_bytes <= anchor.rel.total_bytes.saturating_mul(3)
                {
                    SessionLink::Time
                } else {
                    return None;
                };
                Some(SessionSibling {
                    rel: c.rel,
                    link,
                    dt,
                })
            })
            .collect();
        out.sort_by_key(|s| (s.link, s.dt.abs(), s.rel.id));
        out.truncate(limit);
        Ok(out)
    }
}

/// A sibling joined to the anchor release it was linked through, for
/// title-scoped callers (the wall sheet shows one title, not one row).
#[derive(Debug, Clone)]
pub struct TitleSibling {
    /// The sibling, exactly as a row-scoped scan found it.
    pub sib: SessionSibling,
    /// Which of the title's releases it was linked THROUGH. A title
    /// scan runs several anchors, so without this a caller cannot say
    /// what a sibling is a sibling of.
    pub anchor_id: i64,
}

/// How many of a title's releases get a sibling scan. Newest first:
/// the fresh episode's session is the one whose remainder is still
/// interesting.
const TITLE_ANCHORS: usize = 8;

impl Index {
    /// Session siblings for a whole title: scan its newest releases as
    /// anchors, merge, keep each sibling once under its strongest link.
    pub fn title_session_siblings(
        &self,
        title_key: &str,
        limit: usize,
    ) -> rusqlite::Result<Vec<TitleSibling>> {
        if title_key.is_empty() {
            return Ok(Vec::new());
        }
        let anchors: Vec<i64> = self
            .db
            .prepare_cached(
                "SELECT id FROM releases WHERE title_key=?1
                  ORDER BY first_posted DESC LIMIT ?2",
            )?
            .query_map(rusqlite::params![title_key, TITLE_ANCHORS as i64], |r| {
                r.get(0)
            })?
            .collect::<rusqlite::Result<_>>()?;
        let mut best: std::collections::HashMap<i64, TitleSibling> =
            std::collections::HashMap::new();
        for a in anchors {
            for s in self.session_siblings(a, limit)? {
                let id = s.rel.id;
                let cand = TitleSibling {
                    sib: s,
                    anchor_id: a,
                };
                match best.get(&id) {
                    Some(prev)
                        if (prev.sib.link, prev.sib.dt.abs())
                            <= (cand.sib.link, cand.sib.dt.abs()) => {}
                    _ => {
                        best.insert(id, cand);
                    }
                }
            }
        }
        let mut out: Vec<TitleSibling> = best.into_values().collect();
        out.sort_by_key(|t| (t.sib.link, t.sib.dt.abs(), t.sib.rel.id));
        out.truncate(limit);
        Ok(out)
    }
}

#[cfg(test)]
mod session_tests {
    use super::super::testutil::*;
    use super::*;

    fn fixture(name: &str) -> (std::path::PathBuf, Index) {
        let dir = std::env::temp_dir().join(format!("nzbfast-sess-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ix = Index::open(&dir.join("index.db")).unwrap();
        (dir, ix)
    }

    fn post(ix: &mut Index, grp: &str, stem: &str, from: &str, id: &str, posted: i64) {
        let mut e = entry(
            &format!("\"{stem}.mkv\" yEnc (1/1)"),
            from,
            id,
            4_000_000_000,
        );
        e.date = posted;
        ix.ingest(grp, &[e], posted).unwrap();
    }

    fn id_of(ix: &Index, stem: &str) -> i64 {
        ix.db
            .query_row(
                "SELECT id FROM releases WHERE stem LIKE ?1 || '%'",
                [stem],
                |r| r.get(0),
            )
            .unwrap()
    }

    #[test]
    fn counter_stream_links_across_rotated_posters_and_lying_dates() {
        let (dir, mut ix) = fixture("ctr");
        // Same pesto counter stream, different handles, dates far apart
        // (the tool randomizes Date - the counter arm must not care).
        post(
            &mut ix,
            "g",
            "aaaa1111",
            "x1@r",
            "00000000000000ab.0100.0000000000000001@d1",
            1_000_000,
        );
        post(
            &mut ix,
            "g",
            "bbbb2222",
            "x2@r",
            "00000000000000ac.0200.0000000000000002@d2",
            2_000_000,
        );
        let a = id_of(&ix, "aaaa1111");
        let sibs = ix.session_siblings(a, 10).unwrap();
        assert_eq!(sibs.len(), 1, "{sibs:?}");
        assert_eq!(sibs[0].link, SessionLink::Counter);
        assert!(sibs[0].rel.stem.starts_with("bbbb2222"));
        teardown(&dir, ix);
    }

    #[test]
    fn time_link_needs_the_window_and_the_size_band() {
        let (dir, mut ix) = fixture("time");
        post(&mut ix, "g", "anchor00", "p1@r", "a1@d", 5_000_000);
        post(&mut ix, "g", "near0000", "p2@r", "a2@d", 5_000_000 + 600);
        post(
            &mut ix,
            "g",
            "far00000",
            "p3@r",
            "a3@d",
            5_000_000 + 9 * 3600,
        );
        let a = id_of(&ix, "anchor00");
        let sibs = ix.session_siblings(a, 10).unwrap();
        assert_eq!(sibs.len(), 1, "{sibs:?}");
        assert_eq!(sibs[0].link, SessionLink::Time);
        assert!(sibs[0].rel.stem.starts_with("near0000"));
        teardown(&dir, ix);
    }

    #[test]
    fn a_repeated_poster_outranks_a_time_link() {
        let (dir, mut ix) = fixture("poster");
        post(&mut ix, "g", "anchor00", "same@r", "b1@d", 5_000_000);
        post(&mut ix, "g", "mine0000", "same@r", "b2@d", 5_000_000 + 3000);
        post(&mut ix, "g", "other000", "else@r", "b3@d", 5_000_000 + 60);
        let a = id_of(&ix, "anchor00");
        let sibs = ix.session_siblings(a, 10).unwrap();
        assert_eq!(sibs.len(), 2, "{sibs:?}");
        assert_eq!(sibs[0].link, SessionLink::Poster, "{sibs:?}");
        assert!(sibs[0].rel.stem.starts_with("mine0000"));
        assert_eq!(sibs[1].link, SessionLink::Time);
        teardown(&dir, ix);
    }

    #[test]
    fn spam_and_the_anchors_own_title_stay_out() {
        let (dir, mut ix) = fixture("excl");
        post(&mut ix, "g", "anchor00", "p1@r", "c1@d", 5_000_000);
        post(&mut ix, "g", "spam0000", "p2@r", "c2@d", 5_000_000 + 60);
        post(&mut ix, "g", "sametit0", "p3@r", "c3@d", 5_000_000 + 120);
        ix.db
            .execute(
                "UPDATE releases SET junk=100 WHERE stem LIKE 'spam0000%'",
                [],
            )
            .unwrap();
        // Give anchor and one candidate the same title_key: already on
        // the same card, so the sheet must not repeat it.
        ix.db
            .execute(
                "UPDATE releases SET title_key='t:x' WHERE stem LIKE 'anchor00%' OR stem LIKE 'sametit0%'",
                [],
            )
            .unwrap();
        let a = id_of(&ix, "anchor00");
        let sibs = ix.session_siblings(a, 10).unwrap();
        assert!(sibs.is_empty(), "{sibs:?}");
        teardown(&dir, ix);
    }
}
