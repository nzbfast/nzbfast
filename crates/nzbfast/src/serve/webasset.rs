use std::io::{Read as _, Write as _};
use std::sync::{Arc, Mutex};

use super::*;

/// Compressed, validated delivery for the embedded pages (TODO §129
/// phase 0c, extended by R10 / Codex C9). The dashboard is ~1.2 MB of
/// HTML fetched on every visit: with no validator and no content
/// encoding it re-crossed the wire in full each time, which a LAN never
/// notices and a phone on a remote link always pays for. The validator
/// hashes the FINAL bytes, so any change that alters the served page
/// changes the ETag and a 304 can never pin a stale substitution.
/// Cache-Control stays no-cache on purpose - the browser may keep a copy
/// but must revalidate, so a daemon upgrade reaches the UI on the next
/// load as it always has, now as a 304-sized check instead of a full
/// transfer.
///
/// Three kinds of page arrive here, and the difference between them is
/// only ever WHEN the compression and the hash happen:
///
///   - `respond_static` - pages that cannot change between builds (the
///     i18n catalogues, the manuals). Compressed and hashed by build.rs;
///     nothing to do per request but pick an encoding.
///   - `respond_shell` - the dashboard and the wall, which are stamped
///     with daemon state before their first paint. Built once per
///     distinct set of inputs and kept compressed in a small cache, so a
///     revalidation answers from the ETag alone.
///   - `respond_page` - genuinely per-request bodies (the user's own
///     stylesheet, read from disk each time). Hash and deflate on the
///     spot, as all three used to.
///
/// The first two exist because the old comment here was wrong about its
/// own cost: a page load re-ran five 1.2 MB substitutions, an FNV over
/// the result and a deflate of it - about 11 ms - and a 304, the case
/// the ETag was added to make cheap, paid every bit of that before
/// discovering it had nothing to send.
pub(super) fn respond_page(req: tiny_http::Request, body: String, ctype: &str) {
    let etag = fnv_etag(body.as_bytes());
    let (gzip_ok, unchanged) = negotiate(&req, &etag);
    if unchanged {
        return respond_304(req, &etag);
    }
    // Tiny bodies (an absent stylesheet, 404 fallbacks and the like) are
    // not worth a gzip member's overhead.
    match gzip_ok
        .then(|| {
            (body.len() >= GZIP_FLOOR)
                .then(|| gzip(body.as_bytes()))
                .flatten()
        })
        .flatten()
    {
        Some(gz) => send(req, gz, true, ctype, &etag),
        None => send(req, body.into_bytes(), false, ctype, &etag),
    }
}

/// An asset the binary carries ALREADY compressed, with its validator
/// computed at build time (`precompress_pages` in build.rs).
#[derive(Clone, Copy)]
pub(super) struct Precompressed {
    /// The gzip member. Its INFLATED bytes are what `etag` covers, and
    /// what an identity client is given.
    pub gz: &'static [u8],
    /// FNV-1a over those inflated bytes, already quoted.
    pub etag: &'static str,
}

/// Serve a build-time compressed asset.
///
/// The whole request is two header reads and a write: no substitution,
/// no hash, no deflate. A 304 does not even touch the body.
pub(super) fn respond_static(req: tiny_http::Request, asset: Precompressed, ctype: &str) {
    let (gzip_ok, unchanged) = negotiate(&req, asset.etag);
    if unchanged {
        return respond_304(req, asset.etag);
    }
    let body = if gzip_ok {
        asset.gz.to_vec()
    } else {
        inflate(asset.gz)
    };
    send(req, body, gzip_ok, ctype, asset.etag);
}

/// Which compiled-in shell page a request wants.
#[derive(Clone, Copy, PartialEq, Eq)]
pub(super) enum Shell {
    Dashboard,
    #[cfg(feature = "indexer")]
    Wall,
}

/// EVERY input that can change a served shell page.
///
/// This type is both the cache key and the only thing `render` may
/// read, and that is the entire safety argument: a substitution whose
/// input is not a field here cannot reach the page, so a cached page
/// cannot be pinned by an input the key does not know about. A
/// `__NZBFAST_*` token added to either page without a field added here
/// reddens `every_shell_substitution_is_a_key_field` below.
///
/// The shared design tokens are not a field: they are another
/// compiled-in file, constant for the life of the binary.
#[derive(PartialEq, Eq)]
struct ShellKey {
    page: Shell,
    /// §5 i18n: the daemon-default locale, stamped in so an embedded
    /// webview localizes with no saved browser pref.
    locale: String,
    /// The built-in indexer's master switch. Both pages hide whole
    /// regions when it is off, and an answer arriving with the first API
    /// response is too late: the nav, the cards and the wall's poster
    /// grid would all render, then disappear.
    index_on: bool,
    /// Spots are a third thing /wall can search, switched on
    /// independently - same reason, same timing.
    spots: bool,
    /// How many third-party Newznab accounts are configured and enabled.
    /// With the built-in indexer off, that count is what decides whether
    /// /wall is still worth a nav pill: it is the pull-search surface
    /// too, and hiding it would take the commercial indexers with it.
    indexers: usize,
}

impl ShellKey {
    /// Read the daemon once, up front.
    ///
    /// The locale is CLONED out of its mutex HERE rather than borrowed
    /// into the response. As a temporary in the argument expression the
    /// guard lived until the `;`, so the lock was held across the gzip
    /// and the whole socket write - up to tiny_http's 30 s write timeout
    /// on a slow reader, with every other locale reader and writer
    /// queued behind it.
    fn of(d: &Daemon, page: Shell) -> Self {
        Self {
            page,
            locale: d.ui_locale.lock_ok().clone(),
            index_on: !d.indexer_off(),
            spots: d.spot_enabled.load(Ordering::Relaxed),
            indexers: d.enabled_indexers(),
        }
    }

    /// The page this key describes, substitutions and all.
    fn render(&self) -> String {
        let src = match self.page {
            Shell::Dashboard => DASHBOARD_HTML,
            #[cfg(feature = "indexer")]
            Shell::Wall => WALL_HTML,
        };
        let bit = |on: bool| if on { "1" } else { "0" };
        ui_themed(src)
            .replace("__NZBFAST_INDEX__", bit(self.index_on))
            .replace("__NZBFAST_SPOTS__", bit(self.spots))
            .replace("__NZBFAST_INDEXERS__", &self.indexers.to_string())
            .replace("__NZBFAST_LOCALE__", &self.locale)
    }
}

/// A built shell page, kept only in the form the wire wants.
struct ShellPage {
    key: ShellKey,
    etag: String,
    body: Vec<u8>,
    /// False only if the deflate failed, which writing to a `Vec`
    /// cannot do - it is here so that impossible case degrades to an
    /// identity body instead of an empty one.
    gzipped: bool,
}

/// Built shell pages, most recently served first.
///
/// Bounded at four because a key only moves when a SETTING moves: two
/// pages times the handful of (locale, indexer state) combinations one
/// daemon ever serves, and a fifth entry would mean someone is flipping
/// settings while the browser reloads. Only the COMPRESSED form is
/// kept - 380 KB for the dashboard rather than the 1.2 MB of the page
/// itself - because the identity client that has to pay a
/// decompression for that is rare, and the resident bytes are paid by
/// everyone.
static SHELL_CACHE: Mutex<Vec<Arc<ShellPage>>> = Mutex::new(Vec::new());
const SHELL_CACHE_MAX: usize = 4;

/// Serve the dashboard or the wall.
pub(super) fn respond_shell(req: tiny_http::Request, d: &Daemon, page: Shell) {
    let entry = shell_page(ShellKey::of(d, page));
    let (gzip_ok, unchanged) = negotiate(&req, &entry.etag);
    if unchanged {
        // The point of the cache: a revalidation compares two headers.
        // It used to re-substitute and re-hash 1.2 MB to answer "you
        // already have this".
        return respond_304(req, &entry.etag);
    }
    let (body, gzipped) = match (entry.gzipped, gzip_ok) {
        (true, true) => (entry.body.clone(), true),
        (true, false) => (inflate(&entry.body), false),
        (false, _) => (entry.body.clone(), false),
    };
    send(req, body, gzipped, "text/html", &entry.etag);
}

/// The cached page for this key, built if nobody has built it yet.
fn shell_page(key: ShellKey) -> Arc<ShellPage> {
    if let Some(hit) = promote(&key) {
        return hit;
    }
    // Built OUTSIDE the lock. This is the ~11 ms of substitution, hash
    // and deflate the whole change exists to stop repeating, and two
    // browsers arriving together must not queue behind each other for
    // it; a racing thread's copy is simply dropped at the insert below.
    let body = key.render();
    let etag = fnv_etag(body.as_bytes());
    let (body, gzipped) = match gzip(body.as_bytes()) {
        Some(gz) => (gz, true),
        None => (body.into_bytes(), false),
    };
    let built = Arc::new(ShellPage {
        key,
        etag,
        body,
        gzipped,
    });

    let mut cache = SHELL_CACHE.lock_ok();
    if let Some(i) = cache.iter().position(|e| e.key == built.key) {
        return cache[i].clone();
    }
    cache.insert(0, built.clone());
    cache.truncate(SHELL_CACHE_MAX);
    built
}

/// Find this key's entry and move it to the front, so the oldest
/// UNUSED page is the one a fifth key evicts.
fn promote(key: &ShellKey) -> Option<Arc<ShellPage>> {
    let mut cache = SHELL_CACHE.lock_ok();
    let at = cache.iter().position(|e| e.key == *key)?;
    let hit = cache.remove(at);
    cache.insert(0, hit.clone());
    Some(hit)
}

/// Bodies below this are not worth a gzip member's overhead.
const GZIP_FLOOR: usize = 1024;

/// FNV-1a over the served bytes, quoted as an ETag.
///
/// Not cryptographic and does not need to be: the tag only has to
/// change when the body changes. build.rs computes the same function
/// over the assets it compresses, so both kinds of page carry the same
/// shape of validator.
fn fnv_etag(body: &[u8]) -> String {
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in body {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    format!("\"{h:016x}\"")
}

/// Deflate a body at the request path's level 6. `None` only if flate2
/// fails, which writing to a `Vec` does not.
fn gzip(body: &[u8]) -> Option<Vec<u8>> {
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(6));
    enc.write_all(body).ok().and_then(|()| enc.finish().ok())
}

/// Inflate a gzip member back to the bytes its ETag covers.
///
/// Only an identity client reaches this - every browser sends
/// Accept-Encoding, `curl` does not - so the daemon pays a rare
/// decompression instead of keeping a second, larger copy of every page
/// resident for everyone.
pub(super) fn inflate(gz: &[u8]) -> Vec<u8> {
    let mut out = Vec::new();
    let _ = flate2::read::GzDecoder::new(gz).read_to_end(&mut out);
    out
}

/// The two request headers that decide the answer: may the body be
/// compressed, and does the client already hold this exact one?
fn negotiate(req: &tiny_http::Request, etag: &str) -> (bool, bool) {
    let (mut gzip_ok, mut unchanged) = (false, false);
    for hdr in req.headers() {
        if hdr.field.equiv("Accept-Encoding") {
            gzip_ok |= gzip_accepted(hdr.value.as_str());
        } else if hdr.field.equiv("If-None-Match") {
            // May carry a list; substring match is exact enough because
            // our tags are fixed-width hex in quotes.
            unchanged |= hdr.value.as_str().contains(etag);
        }
    }
    (gzip_ok, unchanged)
}

fn header(k: &str, v: &str) -> tiny_http::Header {
    tiny_http::Header::from_bytes(k.as_bytes(), v.as_bytes()).unwrap()
}

/// A revalidation that succeeded: the validator and nothing else.
fn respond_304(req: tiny_http::Request, etag: &str) {
    let _ = req.respond(
        tiny_http::Response::empty(304)
            .with_header(header("ETag", etag))
            .with_header(header("Cache-Control", "no-cache")),
    );
}

/// A 200 with the house headers.
fn send(req: tiny_http::Request, body: Vec<u8>, gzipped: bool, ctype: &str, etag: &str) {
    let resp = tiny_http::Response::from_data(body);
    let resp = match gzipped {
        true => resp.with_header(header("Content-Encoding", "gzip")),
        false => resp,
    };
    let _ = req.respond(
        resp.with_header(header("Content-Type", ctype))
            .with_header(header("Cache-Control", "no-cache"))
            .with_header(header("Vary", "Accept-Encoding"))
            .with_header(header("ETag", etag)),
    );
}

/// Does this `Accept-Encoding` value permit a gzip body?
///
/// A token scan with the ONE quality value that changes the answer:
/// `q=0` means "not acceptable", so a client that spells out
/// `gzip;q=0` (or `*;q=0` with no gzip token of its own) must get
/// identity. Plain `contains("gzip")` handed it a gzip body it had just
/// said it would not take (L11, 10 Aug sweep). Any other q is a
/// preference between encodings we do not have, and reads as plain
/// acceptance.
fn gzip_accepted(value: &str) -> bool {
    let mut wildcard: Option<bool> = None;
    for tok in value.split(',') {
        let mut parts = tok.split(';').map(str::trim);
        let name = parts.next().unwrap_or("");
        if !name.eq_ignore_ascii_case("gzip") && name != "*" {
            continue;
        }
        let ok = !parts.any(|p| {
            p.strip_prefix("q=")
                .or_else(|| p.strip_prefix("Q="))
                .and_then(|q| q.trim().parse::<f32>().ok())
                .is_some_and(|q| q <= 0.0)
        });
        // A gzip token of its own is the answer; `*` only decides when
        // gzip is not named at all.
        if name == "*" {
            wildcard = Some(ok);
        } else {
            return ok;
        }
    }
    wildcard.unwrap_or(false)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `q=0` is a refusal, not a preference. The old substring scan
    /// compressed for a client that had explicitly said it could not
    /// take a compressed body (L11, 10 Aug sweep).
    #[test]
    fn a_zero_quality_gzip_is_a_refusal() {
        assert!(gzip_accepted("gzip, deflate, br"));
        assert!(gzip_accepted("gzip;q=1.0, identity;q=0.5"));
        assert!(gzip_accepted("GZIP"));
        assert!(gzip_accepted("*"));
        assert!(!gzip_accepted("gzip;q=0"));
        assert!(!gzip_accepted("deflate, gzip;q=0.0"));
        assert!(!gzip_accepted("identity"));
        assert!(!gzip_accepted(""));
        assert!(!gzip_accepted("*;q=0"));
        // A named gzip decides even when a wildcard disagrees.
        assert!(gzip_accepted("*;q=0, gzip"));
        assert!(!gzip_accepted("*, gzip;q=0"));
    }

    fn key(page: Shell) -> ShellKey {
        ShellKey {
            page,
            locale: "en".to_string(),
            index_on: true,
            spots: true,
            indexers: 2,
        }
    }

    /// THE risk in caching a built page: a substitution input the key
    /// does not carry pins a page built from someone else's state.
    ///
    /// So the placeholders in the pages are enumerated from the pages
    /// themselves and checked against the ones `render` actually
    /// substitutes. Adding `__NZBFAST_ANYTHING__` to dashboard.html
    /// without adding a `ShellKey` field fails here, at `cargo test`,
    /// rather than by serving one visitor another visitor's daemon.
    #[test]
    fn every_shell_substitution_is_a_key_field() {
        // The tokens placeholder is substituted from a compiled-in file,
        // so it is constant for the life of the binary and needs no key
        // field; the other four are `ShellKey`'s state fields.
        const KEYED: [&str; 5] = [
            "__NZBFAST_UI_TOKENS__",
            "__NZBFAST_INDEX__",
            "__NZBFAST_SPOTS__",
            "__NZBFAST_INDEXERS__",
            "__NZBFAST_LOCALE__",
        ];
        #[cfg_attr(not(feature = "indexer"), expect(unused_mut))]
        let mut pages: Vec<(&str, &str)> = vec![("dashboard", DASHBOARD_HTML)];
        #[cfg(feature = "indexer")]
        pages.push(("wall", WALL_HTML));
        for (name, src) in pages {
            for (at, _) in src.match_indices("__NZBFAST_") {
                let rest = &src[at + "__NZBFAST_".len()..];
                let end = rest
                    .find("__")
                    .unwrap_or_else(|| panic!("{name}: unterminated placeholder"));
                let found = &src[at..at + "__NZBFAST_".len() + end + 2];
                assert!(
                    KEYED.contains(&found),
                    "{name} substitutes {found}, which is not an input ShellKey carries - \
                     add a field for it, or the page cache will serve it stale"
                );
            }
        }
        // ...and nothing is left behind once they are all applied.
        assert!(
            !key(Shell::Dashboard).render().contains("__NZBFAST_"),
            "a placeholder survived rendering"
        );
    }

    /// Every field of the key has to MATTER, or it is not really an
    /// input and the enumeration above proves nothing. Flip each one in
    /// turn: each must move the bytes, and therefore the validator.
    #[test]
    fn each_key_field_changes_the_page() {
        let base = key(Shell::Dashboard);
        let rendered = base.render();
        let variants = [
            (
                "locale",
                ShellKey {
                    locale: "de".to_string(),
                    ..key(Shell::Dashboard)
                },
            ),
            (
                "index_on",
                ShellKey {
                    index_on: false,
                    ..key(Shell::Dashboard)
                },
            ),
            (
                "spots",
                ShellKey {
                    spots: false,
                    ..key(Shell::Dashboard)
                },
            ),
            (
                "indexers",
                ShellKey {
                    indexers: 0,
                    ..key(Shell::Dashboard)
                },
            ),
        ];
        for (name, v) in variants {
            assert_ne!(v.render(), rendered, "{name} does not change the page");
            assert_ne!(
                fnv_etag(v.render().as_bytes()),
                fnv_etag(rendered.as_bytes()),
                "{name} does not change the validator"
            );
        }
    }

    /// The cache answers per key, keeps the entry stable while the
    /// inputs are, and stays bounded.
    #[test]
    fn the_cache_is_keyed_bounded_and_stable() {
        let en = shell_page(key(Shell::Dashboard));
        let de = shell_page(ShellKey {
            locale: "de".to_string(),
            ..key(Shell::Dashboard)
        });
        assert_ne!(en.etag, de.etag, "two locales, two pages");
        // The same inputs come back as the SAME entry, not a rebuild.
        let again = shell_page(key(Shell::Dashboard));
        assert_eq!(again.etag, en.etag);
        assert!(Arc::ptr_eq(&again, &en), "a hit rebuilt the page");
        // And the store never grows past its bound, however many
        // distinct keys walk through it.
        for i in 0..12 {
            let _ = shell_page(ShellKey {
                indexers: i,
                ..key(Shell::Dashboard)
            });
        }
        assert!(SHELL_CACHE.lock_ok().len() <= SHELL_CACHE_MAX);
    }

    /// What is cached is what goes on the wire: the stored member
    /// inflates back to the page the key describes, and the ETag covers
    /// those inflated bytes.
    #[test]
    fn the_stored_member_inflates_back_to_the_page() {
        let k = key(Shell::Dashboard);
        let want = k.render();
        let page = shell_page(k);
        assert!(page.gzipped, "the dashboard is worth compressing");
        assert_eq!(String::from_utf8(inflate(&page.body)).unwrap(), want);
        assert_eq!(page.etag, fnv_etag(want.as_bytes()));
        assert!(
            page.body.len() * 3 < want.len(),
            "gzip earned its keep: {} vs {}",
            page.body.len(),
            want.len()
        );
    }

    /// The build-time half: every asset build.rs compressed inflates,
    /// and its precomputed ETag is the same FNV the request path would
    /// have produced. A mismatch here is a browser that can never
    /// revalidate.
    #[test]
    fn precompressed_assets_carry_the_validator_of_their_own_bytes() {
        let mut seen = 0;
        for lang in UI_LOCALES {
            if let Some(cat) = i18n_catalog(lang) {
                let plain = inflate(cat.gz);
                assert!(
                    serde_json::from_slice::<serde_json::Value>(&plain).is_ok(),
                    "{lang} catalogue does not inflate to JSON"
                );
                assert_eq!(cat.etag, fnv_etag(&plain), "{lang} catalogue tag");
                seen += 1;
            }
        }
        assert_eq!(
            seen,
            UI_LOCALES.len() - 1,
            "one catalogue per locale but en"
        );
        for lang in UI_LOCALES {
            let Some(man) = manual_i18n(lang) else {
                continue;
            };
            let plain = inflate(man.gz);
            assert_eq!(man.etag, fnv_etag(&plain), "{lang} manual tag");
            let plain = String::from_utf8(plain).expect("a manual is UTF-8");
            // build.rs folded the design tokens in, so the placeholder is
            // gone and the tokens themselves are there.
            assert!(
                !plain.contains("__NZBFAST_"),
                "{lang} manual kept a placeholder"
            );
            assert!(
                plain.contains("--surface:"),
                "{lang} manual lost the tokens"
            );
        }
    }
}
