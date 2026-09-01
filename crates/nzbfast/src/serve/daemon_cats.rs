//! Which category a job is, and which directory it lands in (TODO 106
//! code motion out of daemon.rs).
//!
//! Two halves of one question. WHICH CATEGORY: the set the daemon
//! offers clients (`cat_list`), the first-seen registration that writes
//! a newly-met one through to settings (`register_cat`), the defaults
//! every install starts with before anyone configures anything
//! (`DEFAULT_CATS`), and the per-category overrides a user can set
//! (`CatMeta`). WHICH DIRECTORY: the folder a category's jobs are
//! placed under (`cat_dir`), the canonical pre-collision path for one
//! job in it (`base_out_dir`), and who already owns a candidate path
//! (`dir_claim`), which is what `choose_out_dir` asks before it accepts
//! one.
//!
//! They are one module because the second half READS the first, and the
//! two incidents recorded below are both that reading going wrong. A
//! category's `dir` override is the entire difference between `cat_dir`
//! and `out_dir().join(category)`, and recomputing the second where the
//! first was meant silently re-parented every renamed payload out of the
//! folder the user had configured. `register_cat` is the same shape one
//! level out: it writes the category list, and taking a snapshot of that
//! list outside the settings critical section lost a concurrently
//! registered category on the next restart.
//!
//! A second `impl Daemon` in a child module of `daemon`, so `Daemon`'s
//! private fields (`cats`, `cat_meta`, `queue`, `history`, `reserved`)
//! stay in scope exactly as they were inline. `pub(super)` becomes
//! `pub(in crate::serve)` here, because `super` is `daemon` from inside
//! a child. The two data items are re-exported from daemon.rs, so
//! `crate::serve::daemon::CatMeta` in startup.rs and settings_apply.rs
//! and the four unqualified `DEFAULT_CATS` call sites all still resolve.

use super::*;

/// §129 2b (decision 5): one category's real behavior. Stored in
/// settings.json under `cat_meta` as `{name: {dir, priority, script}}`;
/// every field defaults to "as before".
#[derive(Debug, Clone, Default, PartialEq, serde::Serialize, serde::Deserialize)]
pub(in crate::serve) struct CatMeta {
    /// Subfolder of the download root this category lands in (may
    /// nest, "tv/anime"). Empty = a subfolder named after the
    /// category. Absolute destinations stay the mover's job
    /// (`move_completed_cats`).
    #[serde(default)]
    pub dir: String,
    /// Default priority for adds that did not name one (-100). None =
    /// no default. SAB range: -1 low, 0 normal, 1 high, 2 force.
    #[serde(default)]
    pub priority: Option<i32>,
    /// Post-processing script for this category; empty = the global
    /// script setting. A job-level `script=` param still wins.
    #[serde(default)]
    pub script: String,
    /// TODO 142 / issue #32: does a finished job in this category take
    /// its name from the .nzb file? `None` = follow the global
    /// [`rename_from_nzb`](Daemon::rename_from_nzb) switch; `Some` is an
    /// explicit allow or disallow for this category alone, which is the
    /// control the reporter asked for. Here rather than in a new
    /// `rename_from_nzb_cats` string because per-category behaviour
    /// already has a home: this struct, one editor row, one saved map.
    #[serde(default)]
    pub nzb_name: Option<bool>,
    /// TODO 218: auto-assignment. Comma-separated patterns (regex or
    /// keyword, Smart Folders rules) matched against the NZB's own
    /// `<meta type="category">` and its newsgroups when an add names no
    /// category - SABnzbd's "Indexer Categories / Groups" field, which is
    /// what a reporter moving over from SAB missed first. Matching an
    /// NZB's meta category to a category's own NAME needs no pattern at
    /// all (see [`Daemon::infer_category`]).
    #[serde(default)]
    pub groups: String,
}

/// The categories every install offers before anyone configures one.
///
/// These are the *arr family's own out-of-the-box values, so a default
/// install of one of them passes its connection test against a default
/// install of ours. `*` is SABnzbd's "no category" entry and must stay
/// first. Categories cost nothing until a job uses one: the directory is
/// created at download time, not here.
///
/// THE LIST DOES NOT COVER THE WHOLE FAMILY, and until 31 Aug 2026 this
/// comment said it did - it named Readarr's default as `books`, which
/// Readarr has never used. Every default below was then read off the
/// client's OWN `downloadclient/schema`, which is what its Add dialog
/// pre-fills, rather than off a convention:
///
/// | Client                  | its default SAB category | here |
/// |-------------------------|--------------------------|------|
/// | Sonarr 4.0.19           | `tv`                     | yes  |
/// | Radarr 6.3.0            | `movies`                 | yes  |
/// | Lidarr 3.1.0            | `music`                  | yes  |
/// | Whisparr 2.2.0 (v2)     | `tv`                     | yes  |
/// | Whisparr 3.4.0 (eros)   | `whisparr`               | NO   |
/// | Readarr 0.4.18          | `Readarr`                | NO   |
///
/// The two `NO` rows FAIL their connection test against a default
/// install, with "Category does not exist" - the very failure this list
/// exists to prevent - and both are fixed by the user naming the
/// category once, at either end. That is a real gap and it is left open
/// deliberately: what every install offers in its category dropdown is a
/// product judgement, not a lane's, and one of the two clients is EOL
/// upstream. `books` stays because it is the category a Readarr user is
/// told to switch to, not because Readarr ships it.
///
/// Whisparr v2 passing on `tv` is a fork artifact and not a decision: it
/// is a Sonarr v3 fork that kept the `tvCategory` field and its default,
/// so a user running both has them sharing one folder unless one of them
/// is changed. Measured in
/// `research/ARR-CERTIFICATION-LIDARR-READARR-WHISPARR-2026-08-31.md`,
/// which also records what the two `NO` rows cost and how to clear them.
pub(in crate::serve) const DEFAULT_CATS: &[&str] = &["*", "tv", "movies", "music", "books"];

impl Daemon {
    /// The categories offered to clients, `*` excluded, as the comma list
    /// the `categories` setting round-trips.
    pub(in crate::serve) fn cat_list(&self) -> String {
        self.cats
            .lock_ok()
            .iter()
            .filter(|c| *c != "*")
            .cloned()
            .collect::<Vec<_>>()
            .join(", ")
    }

    /// Remember a category, and write it through to settings the first
    /// time it is seen.
    ///
    /// The list used to live only in memory, rebuilt at startup from the
    /// categories still present in `queue.json` - so a category survived
    /// exactly as long as a job carrying it stayed in history, and a
    /// fresh install offered nothing but the built-ins. Sonarr and Radarr
    /// validate their configured category against this list and refuse to
    /// connect when it is absent, so a user whose category was anything
    /// other than a built-in met "Category does not exist" before they
    /// could add the first job that would have registered it.
    pub(in crate::serve) fn register_cat(&self, cat: &str) {
        if cat.is_empty() || cat == "*" {
            return;
        }
        if !self.cats.lock_ok().insert(cat.to_string()) {
            return;
        }
        // ADDITIVE, because this is a first-seen registration and the
        // list it appends to is not this worker's to replace. The old
        // code took `cat_list()` after dropping the lock and wrote that
        // snapshot whole, so two workers registering different new
        // categories could interleave: B wrote {a,b}, then A overwrote
        // it with {a}. Live memory still held both, so nothing looked
        // wrong until a restart - and then category B was simply gone,
        // and an *arr configured against it failed its category test.
        //
        // Merging inside the settings critical section makes the write
        // order stop mattering: whatever else has landed on disk stays.
        let mine = self.cat_list();
        update_settings(&self.settings_path, |map| {
            let on_disk = map.get("categories").and_then(Value::as_str).unwrap_or("");
            map.insert("categories".into(), json!(merge_cat_list(on_disk, &mine)));
        });
    }

    /// Who, if anyone, already owns `p`. The claim rule `choose_out_dir`
    /// runs, shared by the enqueue path and by a retry that has to move a
    /// TV-filed job off the shared season folder.
    ///
    /// Takes no job lock it does not release, and must never be called
    /// while holding one belonging to a job that is still in the queue or
    /// history - it locks every job in both.
    pub(in crate::serve) fn dir_claim(&self, p: &std::path::Path) -> DirClaim {
        // Reserved but not yet recorded: a recategorize picked this
        // folder and is moving a payload into it. No record names it
        // yet, so the queue/history scan below cannot see it.
        if self.reserved.lock_ok().contains(p) {
            return DirClaim::Active;
        }
        let active = {
            let q = self.queue.lock_ok();
            q.iter().any(|j| j.lock_ok().out_dir == *p)
        } || self.history.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.out_dir == *p && !matches!(g.state, JobState::Completed | JobState::Failed)
        });
        if active {
            return DirClaim::Active;
        }
        let completed = self.history.lock_ok().iter().any(|j| {
            let g = j.lock_ok();
            g.out_dir == *p && g.state == JobState::Completed
        });
        // Only while the files are actually there: a result the user
        // deleted, or that `move_completed` relocated, must release the
        // name, or every re-add of a popular release would climb .2,
        // .3, .4 forever.
        if completed && p.exists() {
            DirClaim::Payload
        } else {
            DirClaim::Free
        }
    }

    /// The directory a category's jobs are placed UNDER - the download
    /// root for an empty category, and otherwise the category's own
    /// subfolder.
    ///
    /// §129 2b: a category can rename that subfolder (SAB's relative
    /// "Folder"). Sanitized per component so "tv/anime" nests and
    /// nothing escapes the download root; the default stays the
    /// category's own name, exactly as before.
    ///
    /// Split out because `finalize_names` needs the SAME answer and was
    /// recomputing it as `out_dir().join(category)` from the raw name -
    /// which silently re-parented every renamed payload out of the
    /// folder the user configured, whenever the two disagreed.
    pub(in crate::serve) fn cat_dir(&self, category: &str) -> PathBuf {
        if category.is_empty() {
            return self.out_dir();
        }
        let sub = self
            .cat_meta
            .lock_ok()
            .get(category)
            .map(|m| m.dir.clone())
            .unwrap_or_default();
        if sub.is_empty() {
            return self.out_dir().join(category);
        }
        let mut p = self.out_dir();
        for c in sub
            .split(['/', '\\'])
            .filter(|c| !c.is_empty() && *c != "." && *c != "..")
        {
            p = p.join(nzbkit::disk::sanitize_filename_capped(c));
        }
        p
    }

    /// The canonical (pre-collision) output directory for a name+category.
    pub(in crate::serve) fn base_out_dir(&self, category: &str, dir_stem: &str) -> PathBuf {
        self.cat_dir(category).join(dir_stem)
    }
}

#[cfg(test)]
mod default_cats_tests {
    use super::DEFAULT_CATS;

    /// Every category here is the out-of-the-box SABnzbd category of a
    /// client we have certified against, so trimming one breaks that
    /// client's connection test on a fresh install with "Category does
    /// not exist" - and nothing else in the tree would say so, because
    /// the failure is entirely on the client's side of the wire.
    ///
    /// The pairs are the measurement, not a convention: each was read
    /// off that client's own `downloadclient/schema`, which is what its
    /// Add dialog pre-fills. Whisparr v2 is on the list because it is a
    /// Sonarr v3 fork that kept `tvCategory` and its default, which is
    /// why it names `tv` rather than anything of its own.
    ///
    /// Two clients are deliberately NOT here, and this test passes if a
    /// later lane adds them, because adding them can only help: Whisparr
    /// 3.4.0 (eros) defaults to `whisparr` and Readarr 0.4.18 to
    /// `Readarr`, and both fail their test against a default install
    /// until the user names the category at one end or the other. The
    /// reasoning for leaving that open is on `DEFAULT_CATS` itself.
    #[test]
    fn the_builtin_list_covers_every_certified_client_default() {
        for (client, cat) in [
            ("Sonarr 4.0.19", "tv"),
            ("Radarr 6.3.0", "movies"),
            ("Lidarr 3.1.0", "music"),
            ("Whisparr 2.2.0 (v2)", "tv"),
        ] {
            assert!(
                DEFAULT_CATS.contains(&cat),
                "{client} ships category {cat:?} out of the box and it is no \
                 longer a built-in, so a fresh install of it now fails its \
                 connection test with \"Category does not exist\""
            );
        }
    }

    /// `*` is SABnzbd's "no category" entry and callers index past it.
    #[test]
    fn the_wildcard_stays_first_and_the_list_is_a_clean_set() {
        assert_eq!(DEFAULT_CATS.first(), Some(&"*"));
        let mut seen = std::collections::BTreeSet::new();
        for c in DEFAULT_CATS {
            assert!(!c.is_empty(), "an empty category would name the root");
            assert!(seen.insert(*c), "{c} is listed twice");
        }
    }
}
