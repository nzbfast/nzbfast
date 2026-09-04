//! DEV-ONLY: serve the web assets from a directory on disk instead of
//! the copies compiled into the binary.
//!
//! Everything in `assets.rs` is `include_str!`/`include_bytes!`, which
//! is the right shipping shape - an install is one self-contained file -
//! and a miserable editing shape: a one-character change to
//! `web/dashboard.html` costs a full rebuild and a daemon restart before
//! it can be looked at. That cycle is the entire reason
//! `.claude/skills/verify-dashboard` exists. With
//! `NZBFAST_DEV_WEB_DIR=<repo>/web` exported, the same edit is a browser
//! reload.
//!
//! Four rules hold this to a dev tool rather than a feature:
//!
//! 1. **Opt-in, off by default, undocumented outside `docs/ENVIRONMENT.md`.**
//!    Unset - which is every install, every release and every test that
//!    does not ask for it - this module resolves to `None` on its first
//!    call and every accessor is a pass-through returning the embedded
//!    bytes. Nothing user-facing mentions it.
//!
//! 2. **Not a file server.** The only names that reach `read` are the
//!    ones the embedded table already knows, and that is enforced by
//!    construction rather than by a second list that could drift from
//!    the first: every call site is INSIDE the match arm that already
//!    resolved the embedded copy, so the relative name is a literal
//!    sitting beside its own `include_bytes!`. The one name with a
//!    request-derived part is the i18n catalogue, and the route only
//!    consults us after `i18n_catalog()` has matched the tag against its
//!    own arm list. `confine` below is the belt over that brace: it
//!    re-derives the path from scratch and refuses anything that is not
//!    a plain relative name. The HTTP surface here is hostile territory
//!    (a general file server rooted at a user-settable path is exactly
//!    what the api-key story exists to keep off it), so the traversal
//!    argument is structural, not a sanitizer.
//!
//! 3. **Per-asset fallback.** A missing file falls back to the embedded
//!    copy with one log line, so pointing this at a half-populated
//!    directory degrades one asset instead of blanking the dashboard.
//!
//! 4. **Never the thing that was verified.** The embedded copy is what
//!    ships, so the final live-verify in the verify-dashboard skill
//!    stays a rebuilt binary with this unset.
//!
//! Caching: a dev-served body must never carry a build-time validator
//! for bytes that have since changed on disk. The shell path handles
//! that by skipping the shell cache entirely and hashing the rendered
//! bytes (`webasset::shell_page`); the catalogues switch from
//! `respond_static` (build-time ETag) to `respond_page` (ETag over the
//! body just read); the icons, which carry no ETag at all and a
//! day-long `max-age`, switch to `no-cache`.
//!
//! Not covered, deliberately: the 16 manuals. They are built from
//! `docs/MANUAL*.html` by `build.rs`, not from `web/`, so a `web/`
//! override has nothing to point at.

use std::borrow::Cow;
use std::collections::BTreeSet;
use std::path::{Path, PathBuf};
use std::sync::{Mutex, OnceLock};

use super::*;

/// The opt-in switch. A path to a checkout's `web/` directory.
pub(super) const DEV_WEB_ENV: &str = "NZBFAST_DEV_WEB_DIR";

/// The configured directory, or `None` for every ordinary run.
///
/// Resolved once. A value that is not a directory is refused loudly and
/// latched as `None` rather than retried per request: a typo in the
/// export should say so once and then cost nothing.
pub fn dev_web_dir() -> Option<&'static Path> {
    static DIR: OnceLock<Option<PathBuf>> = OnceLock::new();
    DIR.get_or_init(|| {
        let raw = std::env::var_os(DEV_WEB_ENV)?;
        let path = PathBuf::from(raw);
        if !path.is_dir() {
            warn!(
                "{DEV_WEB_ENV}={} is not a directory - serving the compiled-in web assets",
                path.display()
            );
            return None;
        }
        warn!(
            "{DEV_WEB_ENV}={} - DEV MODE: web assets are served from disk, \
             not from this binary. Unset it to serve what ships.",
            path.display()
        );
        Some(path)
    })
    .as_deref()
}

/// A relative name resolved under the dev directory, or `None` if it is
/// not a plain relative name.
///
/// The rule is deliberately narrower than "does not escape": every
/// component must be a bare `[a-z0-9._-]+` and must not be `.` or `..`,
/// so a Windows separator, a leading `/`, a drive letter, an empty
/// component and a percent-decoded `..` are all refused by the same
/// test - there is no normalisation step to disagree with the OS about,
/// and every name our own call sites pass is already of that shape.
///
/// A SYMLINK inside the dev directory is followed, and that is not a
/// hole: the directory is one the developer exported by hand on their
/// own machine, and its contents are theirs. The surface this guards is
/// the request, which cannot reach here with a name of its own.
fn confine(dir: &Path, rel: &str) -> Option<PathBuf> {
    let mut out = dir.to_path_buf();
    let mut components = 0usize;
    for part in rel.split('/') {
        if part.is_empty() || part == "." || part == ".." {
            return None;
        }
        if !part.bytes().all(|b| {
            b.is_ascii_lowercase() || b.is_ascii_digit() || matches!(b, b'.' | b'_' | b'-')
        }) {
            return None;
        }
        out.push(part);
        components += 1;
    }
    (components > 0).then_some(out)
}

/// Read one asset from the dev directory, or `None` to use the embedded
/// copy. Announces a fallback once per name, not once per request - dev
/// mode rebuilds the page on every reload, and a missing file would
/// otherwise print a line per keystroke-and-refresh.
fn read(rel: &str) -> Option<Vec<u8>> {
    let dir = dev_web_dir()?;
    let Some(path) = confine(dir, rel) else {
        warn_once(
            rel,
            format_args!("{DEV_WEB_ENV}: refusing asset name {rel:?}"),
        );
        return None;
    };
    match std::fs::read(&path) {
        Ok(body) => Some(body),
        Err(e) => {
            warn_once(
                rel,
                format_args!(
                    "{DEV_WEB_ENV}: {} unreadable ({e}) - using the compiled-in copy",
                    path.display()
                ),
            );
            None
        }
    }
}

/// One warning per asset name for the life of the process.
fn warn_once(rel: &str, msg: std::fmt::Arguments<'_>) {
    static SAID: Mutex<BTreeSet<String>> = Mutex::new(BTreeSet::new());
    if SAID.lock_ok().insert(rel.to_string()) {
        warn!("{msg}");
    }
}

/// The disk copy of a text asset, or the embedded one.
///
/// Lossy UTF-8 for the same reason `user_css` is: a stray byte in a
/// comment must not throw away the page around it, and in dev mode the
/// alternative is a blank tab with no explanation.
pub(super) fn text_or(rel: &str, embedded: &'static str) -> Cow<'static, str> {
    match read(rel) {
        Some(body) => Cow::Owned(String::from_utf8_lossy(&body).into_owned()),
        None => Cow::Borrowed(embedded),
    }
}

/// The disk copy of a binary asset, or the embedded one.
pub(super) fn bytes_or(rel: &str, embedded: &'static [u8]) -> Cow<'static, [u8]> {
    match read(rel) {
        Some(body) => Cow::Owned(body),
        None => Cow::Borrowed(embedded),
    }
}

/// The disk copy of a UI locale's catalogue, for a tag the embedded
/// table has already matched. `None` means "serve the embedded one".
pub fn i18n_json(lang: &str) -> Option<String> {
    // Second brace over the one name with a request-derived part. The
    // route only asks after `i18n_catalog()` matched the tag, so this
    // can only narrow.
    if !UI_LOCALES.contains(&lang) {
        return None;
    }
    read(&format!("i18n/{lang}.json")).map(|b| String::from_utf8_lossy(&b).into_owned())
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The names our own call sites pass all resolve, and every
    /// traversal shape is refused - including the ones an OS-level
    /// normalisation would disagree about.
    #[test]
    fn confine_takes_our_names_and_refuses_everything_else() {
        let dir = Path::new("/tmp/web");
        for ok in [
            "dashboard.html",
            "wall.html",
            "ui-tokens.html",
            "ui-sound.html",
            "site.webmanifest",
            "i18n/fr.json",
            "icons/favicon-16.png",
            "screens/dash-wide.jpg",
        ] {
            assert_eq!(
                confine(dir, ok),
                Some(dir.join(ok)),
                "{ok} is a name the embedded table knows"
            );
        }
        for bad in [
            "",
            "..",
            "../config.json",
            "i18n/../../config.json",
            "/etc/passwd",
            "i18n//fr.json",
            "i18n/fr.json/",
            "..\\config.json",
            "C:/config.json",
            "i18n/FR.json",
            "i18n/f r.json",
            "i18n/fr.json\0",
            "~/secrets",
            "$HOME/secrets",
        ] {
            assert_eq!(confine(dir, bad), None, "{bad:?} must not resolve");
        }
    }

    /// With the switch unset - every install, every release, and every
    /// test that does not ask for it - the accessors hand back the
    /// embedded value untouched, and hand it back BORROWED, so the
    /// shipping path pays no copy for the override existing.
    #[test]
    fn unset_is_a_pass_through() {
        assert!(
            dev_web_dir().is_none(),
            "the suite must not run with {DEV_WEB_ENV} exported"
        );
        assert!(matches!(
            text_or("dashboard.html", "EMBEDDED"),
            Cow::Borrowed("EMBEDDED")
        ));
        assert!(matches!(
            bytes_or("icons/favicon-16.png", b"EMBEDDED"),
            Cow::Borrowed(b"EMBEDDED")
        ));
        assert_eq!(i18n_json("fr"), None);
    }
}
