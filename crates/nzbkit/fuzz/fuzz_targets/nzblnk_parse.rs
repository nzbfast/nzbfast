#![no_main]
//! Fuzz the NZBLNK link parser on arbitrary bytes.
//!
//! The input is a string a user pasted off a web page, so it is fully
//! attacker-shaped: any byte sequence, any length, any encoding. Beyond
//! "must not panic", this asserts the guarantees the daemon's resolution
//! ladder relies on - a successful parse always yields a non-empty
//! header within its cap, deduped groups that really look like groups,
//! and a title that is never empty (it falls back to the header).
use libfuzzer_sys::fuzz_target;

fuzz_target!(|data: &[u8]| {
    let s = String::from_utf8_lossy(data);
    // Cheap scheme test must never disagree with the parse about
    // whether this is a link at all: the UI gates on `looks_like` and
    // the daemon then runs `parse`, so a disagreement is a link the
    // dashboard accepts and the API refuses.
    let looks = nzbkit::nzblnk::looks_like(&s);
    match nzbkit::nzblnk::parse(&s) {
        Err(nzbkit::nzblnk::NzbLnkError::NotALink) => assert!(!looks, "looks_like lied: {s:?}"),
        Err(nzbkit::nzblnk::NzbLnkError::NoHeader) => assert!(looks, "parsed a non-link: {s:?}"),
        Ok(l) => {
            assert!(looks, "parsed a non-link: {s:?}");
            assert!(!l.header.is_empty());
            assert!(l.header.chars().count() <= 1024);
            assert!(
                !l.title.is_empty(),
                "a title must always fall back to the header"
            );
            assert!(l.title.chars().count() <= 512);
            assert!(l.password.chars().count() <= 512);
            assert!(l.groups.len() <= 32);
            for (i, g) in l.groups.iter().enumerate() {
                assert!(
                    g.contains('.') && !g.is_empty(),
                    "junk group survived: {g:?}"
                );
                assert!(!l.groups[..i].contains(g), "duplicate group: {g:?}");
            }
        }
    }
});
