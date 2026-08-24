//! Ingest gates (M12) - decide which releases enter the index at scan
//! time. These are the VOLUME gates: everything here is provable from
//! the subject line alone (kind / year / resolution / language / title /
//! size). Taste filters that need metadata (genre, rating) stay
//! wall-side where they're reversible; an ingest drop needs a rescan.
//!
//! JSON config file (every field optional; absent = permissive):
//! ```json
//! {
//!   "kinds": ["movie", "tv"],
//!   "min_year": 2000, "max_year": 0,
//!   "res": ["1080p", "2160p"],
//!   "languages": ["english"],
//!   "title_allow": [],
//!   "title_deny": ["hardcoded"],
//!   "min_size": "200M", "max_size": "0"
//! }
//! ```
//! Semantics: `kinds` defaults to movie+tv (add `"other"` to keep
//! obfuscated junk); year/res gates only apply when the stem yields a
//! value - unknowns pass, gates filter what they can prove; `languages`
//! is an allow-list where an untagged release counts as "english" and
//! "multi" always passes; title lists are case-insensitive substrings of
//! the parsed title; sizes are SAB-style strings ("500M") enforced by
//! post-scan pruning, since a release's total only exists after
//! clustering. `min_size` is the indexer-spam killer: a tiny release
//! whose upload has finished (one solo .m3u/.nfo) gets pruned, while a
//! mid-upload release is spared until its parts stop arriving.

use std::path::Path;

use serde::Deserialize;

use crate::wall::Kind;

#[derive(Debug, Clone, Default, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Gates {
    kinds: Option<Vec<String>>,
    min_year: u32,
    max_year: u32,
    res: Vec<String>,
    languages: Vec<String>,
    title_allow: Vec<String>,
    title_deny: Vec<String>,
    min_size: Option<String>,
    max_size: Option<String>,
}

/// Largest size a gate may name. The bounds end up in `prune_size`,
/// which binds them as SQLite INTEGERs (`max as i64`), so anything past
/// this wraps NEGATIVE there - and `DELETE FROM releases WHERE
/// total_bytes > <negative>` matches every row: the whole index gone,
/// printed as a successful prune. `parse_size` reaches that easily,
/// since it ends in a saturating `f64 as u64` ("99999999T" alone yields
/// `u64::MAX`). 8 EiB is unbounded for any real index, so no legitimate
/// gate is refused.
const MAX_SIZE_BYTES: u64 = i64::MAX as u64;

impl Gates {
    pub fn load(path: &Path) -> anyhow::Result<Gates> {
        let text = std::fs::read_to_string(path)
            .map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))?;
        Self::from_json(&text).map_err(|e| anyhow::anyhow!("{}: {e}", path.display()))
    }

    /// Parse + validate gates JSON (the settings UI sends raw text).
    pub fn from_json(text: &str) -> anyhow::Result<Gates> {
        let g: Gates = serde_json::from_str(text)?;
        for s in [&g.min_size, &g.max_size].into_iter().flatten() {
            let n = crate::sizes::parse_size(s)
                .ok_or_else(|| anyhow::anyhow!("gates: can't parse size {s:?}"))?;
            // REJECT rather than clamp, because there is no safe value to
            // clamp to: pushing `max` down to MAX_SIZE_BYTES is harmless,
            // but pushing `min` up to it means "prune every release under 8
            // EiB" - the same index wipe by the other door. Telling the
            // user is the only answer that can't destroy anything, and it
            // is cheap here: the settings API returns the message
            // (`set_index_gates`, in serve/settings_index.rs), a saved
            // setting that somehow holds one is logged and ignored rather
            // than fatal, and `index --gates FILE` fails the command with
            // the file named.
            if n > MAX_SIZE_BYTES {
                anyhow::bail!(
                    "gates: size {s:?} is out of range ({n} bytes; the limit is \
                     {MAX_SIZE_BYTES}) - use 0 for unbounded"
                );
            }
        }
        Ok(g)
    }

    /// (min, max) byte bounds for post-scan pruning; 0 = unbounded.
    ///
    /// Second line of defence behind `from_json`'s range check, for a
    /// `Gates` deserialized straight through serde: a bound that cannot
    /// be represented is reported as UNBOUNDED (0), never as a clamp to
    /// `MAX_SIZE_BYTES`. Both gates are inputs to a DELETE, so the only
    /// fail-safe direction is the one that prunes nothing - and 0 is the
    /// value `prune_size` already skips outright.
    pub fn size_bounds(&self) -> (u64, u64) {
        let p = |o: &Option<String>| {
            o.as_deref()
                .and_then(crate::sizes::parse_size)
                .filter(|n| *n <= MAX_SIZE_BYTES)
                .unwrap_or(0)
        };
        (p(&self.min_size), p(&self.max_size))
    }

    /// Does a release with this stem enter the index? No custom
    /// categories - only the tests take this shortcut; the index path
    /// always has the user's list to hand and calls `allows_with`.
    #[cfg(test)]
    pub fn allows(&self, stem: &str) -> bool {
        self.allows_with(stem, &[])
    }

    /// [`allows_with`] applies the user's custom categories first: a
    /// stem a category claims carries that category's slug as its kind,
    /// so `"kinds": ["movie", "formula-1"]` does what it reads as.
    pub fn allows_with(&self, stem: &str, cats: &[nzbkit::categories::CustomCategory]) -> bool {
        let p = nzbkit::categories::classify(stem, cats);
        let kind = nzbkit::index::kind_str(&p.kind);
        match &self.kinds {
            Some(ks) => {
                if !ks.iter().any(|k| k.eq_ignore_ascii_case(kind)) {
                    return false;
                }
            }
            None => {
                // Junk classes (obfuscated + software) need an explicit
                // kinds opt-in; the default gate is for the video wall.
                // A custom category is the OPPOSITE of junk - the user
                // defined it, so its releases pass the default gate.
                if matches!(p.kind, Kind::Other | Kind::Software) {
                    return false;
                }
            }
        }
        if let Some(y) = p.year
            && ((self.min_year > 0 && y < self.min_year)
                || (self.max_year > 0 && y > self.max_year))
        {
            return false;
        }
        if !self.res.is_empty()
            && let Some(r) = &p.res
            && !self.res.iter().any(|a| a.eq_ignore_ascii_case(r))
        {
            return false;
        }
        if !self.languages.is_empty() {
            let tagged: &[String] = &p.langs;
            let english = [String::from("english")];
            let tagged = if tagged.is_empty() {
                &english[..]
            } else {
                tagged
            };
            let ok = tagged
                .iter()
                .any(|l| l == "multi" || self.languages.iter().any(|a| a.eq_ignore_ascii_case(l)));
            if !ok {
                return false;
            }
        }
        let title = p.title.to_ascii_lowercase();
        if self
            .title_deny
            .iter()
            .any(|d| title.contains(&d.to_ascii_lowercase()))
        {
            return false;
        }
        if !self.title_allow.is_empty()
            && !self
                .title_allow
                .iter()
                .any(|a| title.contains(&a.to_ascii_lowercase()))
        {
            return false;
        }
        true
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn gates(json: &str) -> Gates {
        serde_json::from_str(json).unwrap()
    }

    #[test]
    fn default_gates_drop_junk_only() {
        let g = gates("{}");
        assert!(g.allows("The.Matrix.1999.1080p.BluRay.x264-GRP"));
        assert!(g.allows("Severance.S02E03.720p.WEB-DL"));
        assert!(!g.allows("2137d880a074beefcafe1234")); // obfuscated
        assert!(!g.allows("CCleaner.Professional.Plus.v6.36.11041.x64")); // software
        assert!(g.allows("Unknown.Res.Movie.2024")); // unknowns pass
        assert_eq!(g.size_bounds(), (0, 0));
    }

    #[test]
    fn year_res_language_title_gates() {
        let g = gates(
            r#"{"min_year": 2000, "res": ["1080p", "2160p"],
                "languages": ["english"], "title_deny": ["blocked"]}"#,
        );
        assert!(g.allows("New.Film.2020.1080p.WEB"));
        assert!(!g.allows("Old.Film.1999.1080p.WEB")); // year
        assert!(g.allows("No.Year.Show.S01E01.2160p")); // year unknown → passes
        assert!(!g.allows("New.Film.2020.720p.WEB")); // res
        assert!(g.allows("New.Film.2020.WEB")); // res unknown → passes
        assert!(!g.allows("Der.Film.2020.German.1080p.WEB")); // language
        assert!(g.allows("Some.Film.2020.MULTi.1080p.WEB")); // multi passes
        assert!(g.allows("Plain.Film.2020.1080p.WEB")); // untagged = english
        assert!(!g.allows("Blocked.Film.2020.1080p.WEB")); // title deny
    }

    #[test]
    fn kinds_and_allow_list() {
        let g = gates(r#"{"kinds": ["tv"], "title_allow": ["severance", "slow horses"]}"#);
        assert!(g.allows("Severance.S02E03.1080p.WEB"));
        assert!(!g.allows("Severance.The.Movie.2030.1080p.WEB")); // movie
        assert!(!g.allows("Other.Show.S01E01.1080p.WEB")); // not on allow-list
        let junk_ok = gates(r#"{"kinds": ["movie", "tv", "other"]}"#);
        assert!(junk_ok.allows("2137d880a074beefcafe1234"));
    }

    /// 24D: a custom category's slug works in `kinds` exactly like a
    /// built-in, and custom releases pass the DEFAULT gate (they are the
    /// opposite of junk - the user defined them).
    #[test]
    fn custom_categories_reach_the_kinds_gate() {
        let cats = vec![nzbkit::categories::CustomCategory {
            slug: "formula-1".into(),
            name: "Formula 1".into(),
            pattern: r"^formula\.?1\.".into(),
            not_match: String::new(),
            base: nzbkit::categories::BaseBehavior::Movie,
        }];
        let f1 = "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p-MWR";
        // Default gate: custom passes (it would have passed as Movie
        // before, but the point holds for a custom claiming an Other
        // stem too - user-defined means wanted).
        assert!(gates("{}").allows_with(f1, &cats));
        // kinds allow-list: the slug is a first-class kind value…
        let only_f1 = gates(r#"{"kinds": ["formula-1"]}"#);
        assert!(only_f1.allows_with(f1, &cats));
        assert!(!only_f1.allows_with("The.Matrix.1999.1080p.BluRay.x264-GRP", &cats));
        // …and a kinds list WITHOUT the slug excludes the category, even
        // though the same stem parses as Movie underneath. This is the
        // "reaches every enumeration" property: the classified kind is
        // what gates see, not the built-in one.
        let movies_only = gates(r#"{"kinds": ["movie"]}"#);
        assert!(!movies_only.allows_with(f1, &cats));
        assert!(movies_only.allows_with(f1, &[])); // no categories → Movie
    }

    #[test]
    fn sizes_validate_and_parse() {
        let g = gates(r#"{"min_size": "200M", "max_size": "80G"}"#);
        assert_eq!(g.size_bounds(), (200_000_000, 80_000_000_000));
        assert!(Gates::load(Path::new("/nonexistent")).is_err());
    }

    /// Regression: an absurd size gate must never reach `prune_size` as a
    /// value that wraps when bound as an i64. Unvalidated,
    /// `max_size: "99999999T"` arrived at SQLite NEGATIVE, so
    /// `DELETE ... WHERE total_bytes > ?1` matched every row: the whole
    /// index gone, printed as a successful prune.
    #[test]
    fn oversized_size_gates_are_rejected_and_never_wrap() {
        // parse_size saturates at u64::MAX here - the exact value the old
        // code handed straight to `as i64`.
        assert_eq!(crate::sizes::parse_size("99999999T"), Some(u64::MAX));
        assert_eq!(u64::MAX as i64, -1, "…which is a negative SQLite bound");

        for s in ["99999999T", "10000000T", "18446744073709551615"] {
            // 1. Validation refuses it, with a message the settings API
            //    and `index --gates` both surface.
            for key in ["max_size", "min_size"] {
                let e = Gates::from_json(&format!(r#"{{"{key}": "{s}"}}"#))
                    .expect_err(&format!("{key} {s:?} must be rejected"))
                    .to_string();
                assert!(e.contains("out of range"), "unhelpful error: {e}");
            }

            // 2. And if one is deserialized straight through serde anyway,
            //    the bound reads as UNBOUNDED (0) - never as a clamp to
            //    MAX_SIZE_BYTES, which for `min` would prune every
            //    complete release: the same wipe by the other door.
            let (min, max) =
                gates(&format!(r#"{{"max_size": "{s}", "min_size": "{s}"}}"#)).size_bounds();
            assert_eq!((min, max), (0, 0), "out-of-range bound must read unbounded");
            // The exact conversion prune_size performs on the bind.
            assert!(
                max as i64 >= 0 && min as i64 >= 0,
                "bound wraps negative for {s:?}"
            );
        }

        // In-range gates - including an absurd-but-representable 9 EB -
        // are accepted and pass through intact.
        let g = Gates::from_json(r#"{"min_size": "1", "max_size": "9000000T"}"#).unwrap();
        assert_eq!(g.size_bounds(), (1, 9_000_000_000_000_000_000));
        assert!(9_000_000_000_000_000_000u64 as i64 > 0);
    }
}
