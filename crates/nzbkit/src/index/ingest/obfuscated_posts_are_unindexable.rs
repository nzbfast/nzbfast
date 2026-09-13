/// Why a header-scanning index cannot see a fully obfuscated release,
/// however many groups it scans.
///
/// Traced from a real one: Supergirl.2026.2160p, which downloaded
/// perfectly and which DOGnzb lists, but which does not appear in our
/// index. Every theory about coverage was wrong - the article range WAS
/// scanned (1,933 neighbours from the same hour are stored), the
/// neighbours ARE obfuscated so obfuscation alone is not disqualifying,
/// and servers[0] DOES carry the articles.
///
/// The nzb lies. Its <groups>, subject= and poster= are all indexer
/// metadata, not what is on the wire. Fetched live from the provider,
/// the same message-id carries:
///
///   Newsgroups: alt.binaries.encrypted   (nzb said alt.binaries.teevee)
///   Subject:    ZvbiaQJJpLvLZpY          (nzb said "30fb7ada….10" yEnc (1/260))
///   From:       wQXbPchc1NPZZqPmbWr5 …   (nzb said e24e6f0f… )
///
/// So it is in a group nobody would index for TV, under a subject with
/// no filename, no part marker and no relationship to the release. The
/// indexers that list it are not scanning headers - they hold a
/// message-id mapping from the uploader.
#[test]
fn a_real_obfuscated_subject_carries_nothing_to_index_on() {
    // What the nzb claims: parses fine, which is why this looked
    // indexable right up until the article itself was read.
    let claimed = "\"30fb7ada0c0b15e12135927afe355933.10\" yEnc (1/260)";
    let (base, part, total) =
        super::split_subject(claimed).unwrap_or_else(|| (claimed.to_string(), 1, 1));
    assert!(part != 0 && total != 0);
    assert!(
        super::quoted_name(&base).is_some(),
        "the nzb's version is parseable"
    );

    // What is actually on the wire. ingest() requires a quoted filename
    // and skips the entry without one, so this can never become a row -
    // no filename, no part marker, nothing to key a release on.
    let real = "ZvbiaQJJpLvLZpY";
    let (rbase, _, _) = super::split_subject(real).unwrap_or_else(|| (real.to_string(), 1, 1));
    assert!(
        super::quoted_name(&rbase).is_none(),
        "the real subject has no quoted filename, so ingest skips it"
    );
}
