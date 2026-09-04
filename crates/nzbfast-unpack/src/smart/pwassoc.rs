//! §99: try-order heuristic for the SAB/NZBGet passwords file.
//!
//! The file itself stays the single list, tried top to bottom
//! (`read_password_file`). What this module adds is a remembered
//! association - which password unlocked a download from which NZB
//! source site and which Usenet poster - kept in a sidecar next to the
//! file, so the next passworded job tries the likely line FIRST. A
//! site match outranks a poster match (passwords correlate with the
//! site that supplied the NZB far more than with the poster, who is
//! often randomized per upload), and everything else keeps the file's
//! own order - so the worst case degrades to exactly today's flat
//! order. Order matters because a wrong password is not free: a RAR4
//! set carries no password check, so every wrong candidate is paid for
//! in real unpack work.
//!
//! The sidecar holds password VALUES, so it lives under the passwords
//! file's own rules: written 0600, never surfaced through get_config,
//! never printed to any log. Only passwords still PRESENT in the file
//! are ever promoted - deleting a line from the file retires its
//! associations with it, keeping the file the one list that exists.

use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};

/// Most-recent-first (key, password) pairs. Vecs, not maps: recency is
/// the eviction order, and every scan is over at most [`CAP`] entries.
#[derive(Default, Serialize, Deserialize)]
struct PwAssoc {
    #[serde(default)]
    site: Vec<(String, String)>,
    #[serde(default)]
    poster: Vec<(String, String)>,
}

/// Entries kept per key kind. Sites are few; posters are often
/// randomized per upload (Gary's own caveat with the idea), so an
/// unbounded poster list would mostly hold keys that never recur.
const CAP: usize = 64;

/// The sidecar path: `passwords.txt` -> `passwords.txt.assoc`, derived
/// so a custom `password_file` path carries its associations with it.
fn assoc_path(pw_file: &Path) -> PathBuf {
    let mut name = pw_file.file_name().unwrap_or_default().to_os_string();
    name.push(".assoc");
    pw_file.with_file_name(name)
}

/// A missing or unparseable sidecar is an empty map, never an error -
/// like the passwords file itself, the operator may delete it.
fn load(pw_file: &Path) -> PwAssoc {
    std::fs::read(assoc_path(pw_file))
        .ok()
        .and_then(|b| serde_json::from_slice(&b).ok())
        .unwrap_or_default()
}

/// Record "this password unlocked a download from this site / this
/// poster". Called when a job's own password or a passwords-file line
/// unlocks in the finalize ladder, and for the in-stream probe's
/// verified winner; a no-op when there is nothing to key on (an
/// uploaded NZB has no source site, an attribute-less NZB no poster).
/// The last unlock wins per key. A concurrent recorder can lose one
/// update (last rename wins) but never tear the file.
pub fn record_password_assoc(pw_file: &Path, site: &str, poster: &str, pw: &str) {
    if pw.is_empty() || (site.is_empty() && poster.is_empty()) {
        return;
    }
    let mut a = load(pw_file);
    let put = |list: &mut Vec<(String, String)>, key: &str| {
        if key.is_empty() {
            return;
        }
        list.retain(|(k, _)| k != key);
        list.insert(0, (key.to_string(), pw.to_string()));
        list.truncate(CAP);
    };
    put(&mut a.site, site);
    put(&mut a.poster, poster);
    if let Ok(bytes) = serde_json::to_vec(&a) {
        // Atomic and 0600, like every daemon-private file that can
        // hold credentials.
        let _ = crate::persist::write_atomic(&assoc_path(pw_file), &bytes);
    }
}

/// Reorder the passwords-file candidates for one job: the password
/// last associated with `site` first, then the one last associated
/// with `poster`, then the rest in file order. Promotes only values
/// still present in `list`, and with no sidecar or no match returns
/// `list` unchanged.
pub fn order_passwords(list: Vec<String>, pw_file: &Path, site: &str, poster: &str) -> Vec<String> {
    if site.is_empty() && poster.is_empty() {
        return list;
    }
    let a = load(pw_file);
    let hit = |pairs: &[(String, String)], key: &str| -> Option<String> {
        if key.is_empty() {
            return None;
        }
        pairs.iter().find(|(k, _)| k == key).map(|(_, v)| v.clone())
    };
    let mut front: Vec<String> = Vec::new();
    for cand in [hit(&a.site, site), hit(&a.poster, poster)]
        .into_iter()
        .flatten()
    {
        if list.contains(&cand) && !front.contains(&cand) {
            front.push(cand);
        }
    }
    if front.is_empty() {
        return list;
    }
    let mut out = front.clone();
    out.extend(list.into_iter().filter(|p| !front.contains(p)));
    out
}

/// The NZB's dominant `poster` attribute - the most common across its
/// files, so a sidecar posted under another identity cannot claim the
/// job. Empty when no file carries one.
pub fn dominant_poster(nzb: &nzbkit::nzb::Nzb) -> String {
    let mut counts: Vec<(&str, usize)> = Vec::new();
    for f in &nzb.files {
        if f.poster.is_empty() {
            continue;
        }
        match counts.iter_mut().find(|(p, _)| *p == f.poster) {
            Some((_, n)) => *n += 1,
            None => counts.push((&f.poster, 1)),
        }
    }
    counts
        .into_iter()
        .max_by_key(|&(_, n)| n)
        .map(|(p, _)| p.to_string())
        .unwrap_or_default()
}

/// [`dominant_poster`] read back off the job's spooled NZB, for the
/// finalize ladder (which holds a path, not a parse). Empty on any
/// read or parse failure - the ladder then runs in plain file order.
pub fn nzb_poster(nzb_path: &Path) -> String {
    let Ok(bytes) = std::fs::read(nzb_path) else {
        return String::new();
    };
    match nzbkit::nzb::Nzb::parse(&bytes) {
        Ok(nzb) => dominant_poster(&nzb),
        Err(_) => String::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::super::testkit::scratch;
    use super::*;

    fn pw_file(dir: &Path, lines: &[&str]) -> PathBuf {
        let p = dir.join("passwords.txt");
        std::fs::write(&p, lines.join("\n")).unwrap();
        p
    }

    fn list(p: &Path) -> Vec<String> {
        crate::smart::read_password_file(p)
    }

    #[test]
    fn no_sidecar_is_flat_order() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a", "b", "c"]);
        assert_eq!(
            order_passwords(list(&p), &p, "indexer", "poster"),
            ["a", "b", "c"]
        );
    }

    #[test]
    fn site_match_outranks_poster_match() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a", "b", "c"]);
        record_password_assoc(&p, "", "bob", "b");
        record_password_assoc(&p, "indexer", "", "c");
        assert_eq!(
            order_passwords(list(&p), &p, "indexer", "bob"),
            ["c", "b", "a"]
        );
        // Poster alone still promotes when the site is unknown.
        assert_eq!(order_passwords(list(&p), &p, "", "bob"), ["b", "a", "c"]);
    }

    #[test]
    fn deleted_line_is_never_promoted() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a", "b"]);
        record_password_assoc(&p, "indexer", "", "gone");
        assert_eq!(order_passwords(list(&p), &p, "indexer", ""), ["a", "b"]);
    }

    #[test]
    fn last_unlock_wins_and_dedupes_front() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a", "b", "c"]);
        record_password_assoc(&p, "indexer", "bob", "a");
        record_password_assoc(&p, "indexer", "", "b");
        // Site says "b", poster still says "a": both move up, site first.
        assert_eq!(
            order_passwords(list(&p), &p, "indexer", "bob"),
            ["b", "a", "c"]
        );
        // Same password on both keys is promoted once.
        record_password_assoc(&p, "indexer", "bob", "c");
        assert_eq!(
            order_passwords(list(&p), &p, "indexer", "bob"),
            ["c", "a", "b"]
        );
    }

    #[test]
    fn empty_keys_and_empty_password_record_nothing() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a"]);
        record_password_assoc(&p, "", "", "a");
        record_password_assoc(&p, "indexer", "bob", "");
        assert!(!assoc_path(&p).exists());
    }

    #[test]
    fn cap_evicts_oldest() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["first", "later"]);
        record_password_assoc(&p, "site0", "", "first");
        for i in 1..=CAP {
            record_password_assoc(&p, &format!("site{i}"), "", "later");
        }
        assert_eq!(
            order_passwords(list(&p), &p, "site0", ""),
            ["first", "later"]
        );
        assert_eq!(
            order_passwords(list(&p), &p, "site1", ""),
            ["later", "first"]
        );
    }

    #[cfg(unix)]
    #[test]
    fn sidecar_is_owner_only() {
        use std::os::unix::fs::PermissionsExt;
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a"]);
        record_password_assoc(&p, "indexer", "", "a");
        let mode = std::fs::metadata(assoc_path(&p))
            .unwrap()
            .permissions()
            .mode();
        assert_eq!(mode & 0o777, 0o600);
    }

    #[test]
    fn corrupt_sidecar_is_flat_order() {
        let dir = scratch("pwassoc");
        let p = pw_file(&dir, &["a", "b"]);
        std::fs::write(assoc_path(&p), b"not json").unwrap();
        assert_eq!(order_passwords(list(&p), &p, "indexer", "bob"), ["a", "b"]);
        // A record over the corrupt file starts a fresh map.
        record_password_assoc(&p, "indexer", "", "b");
        assert_eq!(order_passwords(list(&p), &p, "indexer", ""), ["b", "a"]);
    }

    #[test]
    fn dominant_poster_is_the_majority() {
        let xml = br#"<nzb xmlns="http://www.newzbin.com/DTD/2003/nzb">
  <file subject="a" poster="bob@example.com" date="1700000000">
    <groups><group>g</group></groups>
    <segments><segment bytes="1" number="1">m1@x</segment></segments>
  </file>
  <file subject="b" poster="bob@example.com" date="1700000000">
    <groups><group>g</group></groups>
    <segments><segment bytes="1" number="1">m2@x</segment></segments>
  </file>
  <file subject="c" poster="spam@example.com" date="1700000000">
    <groups><group>g</group></groups>
    <segments><segment bytes="1" number="1">m3@x</segment></segments>
  </file>
</nzb>"#;
        let nzb = nzbkit::nzb::Nzb::parse(xml).unwrap();
        assert_eq!(dominant_poster(&nzb), "bob@example.com");
        let dir = scratch("pwassoc-poster");
        let path = dir.join("j.nzb");
        std::fs::write(&path, xml).unwrap();
        assert_eq!(nzb_poster(&path), "bob@example.com");
        assert_eq!(nzb_poster(&dir.join("missing.nzb")), "");
    }
}
