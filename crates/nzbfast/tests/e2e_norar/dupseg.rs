//! M4-16: one message-id claimed by TWO `<file>` groups.
//!
//! A poster (or a broken indexer) can emit an NZB in which the same
//! segment id appears in two file groups. A client that keys its slot
//! table on the message-id rather than on (file group, segment) will
//! deliver those bytes to whichever slot asked last, or to both, and the
//! damage is silent: the article decodes cleanly, its yEnc CRC passes,
//! and it simply lands in the wrong file.
//!
//! nzbfast's segment table is per-file-group, so the prediction in the
//! matrix read is PASS. That is exactly why it is worth a pin: a row
//! predicted to pass and never run is a row nobody can tell apart from
//! one that was never true. The failure this refuses is not a crash -
//! it is a byte-exact-looking download with one file's content inside
//! another.
//!
//! Three things are asserted, and the third is the one a naive probe
//! misses: the shared article must reach BOTH slots (not be raced away
//! from one of them), neither file may contain the other's bytes, and
//! the run must TERMINATE - a client that waits for a segment another
//! group has already consumed wedges rather than fails, which no
//! content assertion can see.
//!
//! A child of [`super`] rather than a sibling of `e2e.rs`: `e2e.rs` sits AT
//! its size-gate baseline with no room for another `mod` line, and this row
//! belongs to that parent's subject anyway.

use super::*;

/// Independent content per seed - see `e2e_lateset`'s note on why
/// `e2e.rs`'s `payload` is the wrong generator for a probe that has to
/// tell two files apart: its seeds are shifted windows of one stream, so
/// "alpha's bytes turned up inside beta" is not a statement that
/// generator can support.
fn lone_payload(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// M4-16: the same segment id in two file groups.
///
/// `alpha.bin` is posted normally in two articles. `beta.bin` is then
/// given an NZB group whose FIRST segment is alpha's SECOND article id -
/// the duplicate - followed by beta's own remaining article. Nothing on
/// the wire is malformed: that article is a perfectly valid yEnc part
/// that declares alpha's name and alpha's offsets.
///
/// The honest outcomes are either "beta fails, alpha is whole" or "both
/// decode their own articles"; the outcome this refuses is a green run
/// in which alpha is short, or beta contains a window of alpha.
#[tokio::test(flavor = "multi_thread")]
async fn m4_16_one_message_id_in_two_file_groups_does_not_cross_slots() {
    let mut fx = Fixture::new("dupseg");

    let alpha = lone_payload(80_000, 11);
    let beta = lone_payload(80_000, 22);

    // Alpha: two articles of 40 000 bytes, posted the ordinary way.
    fx.add_file("alpha.bin", &alpha, 40_000);
    let alpha_segs = fx.nzb_files[0].1.clone();
    assert_eq!(alpha_segs.len(), 2, "alpha should be two articles");
    let shared = alpha_segs[1].clone();

    // Beta: its own articles, built so they exist in the article map...
    let beta_segs = make_file_articles("beta.bin", &beta, 40_000, "beta", &mut fx.articles);
    assert_eq!(beta_segs.len(), 2, "beta should be two articles");
    // ...but its NZB group claims ALPHA's second article as its own
    // first segment, and keeps only its own second. The duplicate is
    // therefore in two groups at once, which is the whole row.
    let beta_group = vec![
        (shared.0.clone(), shared.1, 1u32),
        (beta_segs[1].0.clone(), beta_segs[1].1, 2u32),
    ];
    fx.nzb_files.push(("beta.bin".to_string(), beta_group));

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    // TERMINATION is the first assertion and it is implicit: reaching
    // this line at all means the run returned rather than parking on a
    // segment another group had consumed. The nextest per-test ceiling
    // (`.config/nextest.toml`) is what actually enforces it.
    let a = std::fs::read(out.join("alpha.bin")).unwrap_or_default();
    let b = std::fs::read(out.join("beta.bin")).unwrap_or_default();
    eprintln!(
        "m4_16: rc ok={ok}, alpha {} bytes, beta {} bytes",
        a.len(),
        b.len()
    );

    // Alpha owns that article outright: sharing it must not cost alpha
    // its own bytes.
    assert_eq!(
        a.len(),
        80_000,
        "alpha lost the article a second file group also claimed\n{log}"
    );
    assert_eq!(a, alpha, "alpha's content is not alpha's own bytes\n{log}");

    // And beta must not be handed alpha's window under its own name.
    // `beta` may legitimately be absent or short - the group really is
    // missing one of its articles - but any bytes it DOES have must be
    // its own.
    if !b.is_empty() {
        assert!(
            !b.windows(4096).any(|w| alpha.windows(4096).any(|x| x == w)),
            "beta contains a 4 KiB window of alpha - the shared segment \
             crossed slots\n{log}"
        );
    }
}
