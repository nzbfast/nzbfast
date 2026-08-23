//! TODO 211 over mock NNTP, both fixes: (b) a byte split of a single
//! `.rar` mapped ONE-PASS as a single volume with seams in it (the parts
//! never touch disk, the member is the only thing written), and (a) the
//! tail's LAST rung - the same split with the one-pass mapping switched
//! off (`NZBFAST_NO_RAR_SPLIT=1`), which no arm can open, rescued by
//! joining the parts after the demoted-volume unpack ladder has already
//! failed on them. The (a) legs are the regression test for the hatch:
//! (b) on, they would be one-pass legs and the rescue banner they assert
//! would be missing.
//!
//! (b) landed 22 Aug 2026 and moved one leg's door: a COMPRESSED split's
//! head now declines the top-level chase (a chase drives one frontier
//! per volume, and a split head's bytes arrive through N alias slots),
//! so its demote reason is the mapper's `compressed or encrypted
//! entries` rather than the chase's `chase failed: …`, and it lands on
//! the tail's FIRST arm - which falls through to the same rescue. The
//! module note below on "which arm" predates that and is kept as the
//! measurement it was; the compressed leg asserts the new reason.
//!
//! A child module so e2e.rs stays inside its size-gate baseline (the
//! e2e_sample / e2e_chip6 pattern: harness reached through `super::*`).
//!
//! `rescue_split_after_failed_unpack` has three call sites and until now
//! only two of them were tested: `splitjoin_tests::
//! a_split_of_a_single_rar_is_joined_once_the_rar_arm_fails` reaches it
//! through `extract_one_level` step 7, and `repair_tests::
//! reextract_dir_rescues_a_split_container_after_repair` through
//! `reextract_dir`. Neither goes anywhere near `crate::get::tail`, whose
//! pair of sites is the one the field shape actually lands on: until this
//! file the only thing that had ever run it was one hand-driven leg of
//! the disk-shape bench round, on a box kept for that.
//!
//! # Which of the tail's two sites a split container can reach
//!
//! The tail calls `try_unrar_spent` twice and both arms fall through to
//! the rescue on a `None`. The first arm is for demote reasons naming a
//! COMPRESSED set, or an encrypted one with a password in hand; the
//! second is for every reason nobody else owns. Every split-container
//! shape these legs can build lands on the SECOND, and that is a
//! measurement, not a reading:
//!
//! * store RAR5 -> `data area exceeds volume` (the mapper's
//!   volume-bounds guard),
//! * encrypted store RAR5 WITH the password -> the same reason, because
//!   `RarMap::entry_blocker` answers None for an encrypted store entry
//!   once a password is in hand, so the mapper goes on to map and it is
//!   the guard that stops it, not the encryption,
//! * compressed RAR5, single volume or multi -> `chase failed: … input
//!   is too short`, because the top-level chase claims compressed sets
//!   now and its own failure reason names no format at all.
//!
//! All three are unowned by `fallback_needs_disk_unpack`. The first arm
//! needs `MapBlocker::NotStore`'s "compressed or encrypted entries",
//! which the chase gets to first for every compressed shape a fixture
//! can write, so nothing here fakes a leg for it.
//!
//! # The unrar canary, which these legs could not set until 22 Aug 2026
//!
//! The integration suites shut the external unpacker per child with
//! `NZBFAST_TEST_FORBID_UNRAR=1`, and for a day these legs were the only
//! ones that could not. The canary used to short-circuit
//! `rarfix::try_unrar_spent` at its very top - ahead of
//! `try_rars_native`, not beside the `external_unrar_closed` hatch
//! further down - so it closed the NATIVE engine too, and the rescue
//! extracts the container it joined by calling straight back into that
//! same function. With the canary set the join happened and then nothing
//! could unpack the result. It now sits at the hatch's rung and closes
//! only the subprocess, so these legs set it like every sibling suite
//! does, and they are the regression test for that placement: put the
//! check back at the top of the function and all three go red on the
//! native completion line the rescue depends on.
//!
//! The route assertions the legs used instead are KEPT, because they say
//! something the canary cannot: not just that no external unpacker ran,
//! but that the rescue is what delivered. An arm that unpacked the
//! `.001` set would leave the rescue banner out of the log, and the
//! `split_once` below panics rather than passing; one that unpacked the
//! JOINED container by some other route would leave the native engine's
//! own completion line out, and that is asserted too. Note the canary
//! cannot be read off the log the obvious way: "unpacking archive with
//! unrar…" is printed BEFORE the hatch is consulted, so its absence
//! proves nothing and its presence is not a spawn.

use super::*;

/// Uniform byte split, exactly what hjsplit and `split -b` produce:
/// every part the split size, the last one the remainder.
fn split_parts(arch: &[u8], n: usize) -> Vec<&[u8]> {
    let parts: Vec<&[u8]> = arch.chunks(arch.len().div_ceil(n)).collect();
    assert_eq!(parts.len(), n, "fixture must really split into {n}");
    parts
}

/// Half-entropy bytes: compressible enough that the RAR writer keeps the
/// compressed method (it silently stores an incompressible entry, which
/// would put the leg back on the store path it is not testing).
fn compressible(n: usize) -> Vec<u8> {
    let mut s = 0x9e3779b97f4a7c15u64;
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect()
}

/// Everything each leg wants to say about a rescued job, read off one
/// log: that the demote happened for `reason`, that the ladder really did
/// put its unpacker on the parts and really did fail, that the rescue
/// then ran and joined, and that the NATIVE engine is what unpacked what
/// it joined, out of the scratch dir. Returns nothing - a failure here is
/// the assertion.
fn assert_rescued_through_the_tail(log: &str, reason: &str) {
    assert!(
        log.contains(reason),
        "the set did not demote for '{reason}', so this is not the arm \
         under test:\n{log}"
    );
    // The rescue's banner, and the seam the rest is read against. Its
    // ABSENCE is what a masking unrar would look like.
    let (_ladder, rescue) = log
        .split_once("no arm could open the split archive")
        .unwrap_or_else(|| panic!("the TODO 211 rescue never ran:\n{log}"));
    // The ladder's failure is a WARN, and since §80's level split (22 Aug
    // 2026) warnings go to stderr while the banner above is stdout; the
    // harness concatenates the two streams, so the failure cannot be read
    // as "before the seam" - only as present. The rescue only runs once
    // the ladder has failed, so presence plus the banner is the same fact.
    assert!(
        log.contains("native unpack failed for"),
        "the disk-unpack ladder never failed on the parts, so the rescue \
         below it is not what delivered:\n{log}"
    );
    assert!(
        !log.contains("could not be unpacked"),
        "an unpack arm failed the job instead of falling through to the \
         rescue:\n{log}"
    );
    assert!(
        rescue.contains("split join complete"),
        "the parts were never joined:\n{log}"
    );
    // Read off the line rather than matched against a path literal, so
    // Windows' separators do not matter.
    let native = rescue
        .lines()
        .find(|l| l.contains("native unpack complete"))
        .unwrap_or_else(|| panic!("the joined container was not unpacked natively:\n{log}"));
    assert!(
        native.contains(".nzbfast-nest"),
        "the native unpack did not name the container the rescue built in \
         its scratch dir:\n{native}"
    );
}

/// Nothing the rescue consumed may survive it: the parts are spent, and
/// so is the container built out of them.
fn assert_parts_are_spent(out: &Path, names: &[String], base: &str) {
    for name in names {
        assert!(!out.join(name).exists(), "{name} is spent and must be gone");
    }
    assert!(
        !out.join(base).exists(),
        "{base} - the container the rescue built - is spent too"
    );
    assert!(
        !out.join(".nzbfast-nest").exists(),
        "the rescue's scratch dir must be lifted back and removed"
    );
}

/// Post `arch` as `stage.rar.001`..`.00n`, with a PAR2 set over the
/// parts the way a real poster covers them. Returns the part names.
fn post_split(fx: &mut Fixture, arch: &[u8], n: usize) -> Vec<String> {
    let names: Vec<String> = (1..=n).map(|i| format!("stage.rar.{i:03}")).collect();
    for (name, part) in names.iter().zip(split_parts(arch, n)) {
        fx.add_file(name, part, 60_000);
    }
    let refs: Vec<&str> = names.iter().map(|s| s.as_str()).collect();
    assert!(fx.add_par2(10, &refs, 60_000), "par2 create failed");
    names
}

/// Everything a one-pass split leg wants to say, off one log and one
/// output directory: the job delivered the member byte for byte, the
/// shape badge claims the one-pass, the head never demoted (no bounds
/// refusal, no rescue banner, no unpack ladder), and no part was ever
/// a file in the output directory. The last clause is the whole of (b)
/// over (a): the rescue also leaves nothing behind, but only after
/// writing the parts AND the joined container first.
fn assert_mapped_one_pass(log: &str, out: &Path, names: &[String], inner: &[u8]) {
    assert!(
        log.contains("one-pass"),
        "the shape badge must claim the one-pass:\n{log}"
    );
    for tell in [
        "data area exceeds volume",
        "no arm could open the split archive",
        "split join complete",
        "native unpack",
        "unpacking archive",
    ] {
        assert!(
            !log.contains(tell),
            "'{tell}' means the set took the disk path, not the map:\n{log}"
        );
    }
    assert_eq!(
        std::fs::read(out.join("film.mkv")).expect("the member the split held"),
        inner,
        "the archive member must arrive byte for byte"
    );
    for name in names {
        assert!(
            !out.join(name).exists(),
            "{name} must never have been a file"
        );
    }
    assert!(!out.join("stage.rar").exists(), "nothing was ever joined");
    assert!(!out.join(".nzbfast-nest").exists(), "no rescue scratch dir");
}

/// TODO 211 (b), the field shape one-pass: the same four-part split of a
/// standalone store `stage.rar`, declared from the NZB's file list, maps
/// as ONE volume with seams in it - part 1's mapper spans the whole set
/// and parts 2..4 alias onto it at their logical offsets. The member is
/// the only file the job writes.
#[tokio::test(flavor = "multi_thread")]
async fn split_of_a_single_store_rar_maps_one_pass() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarsplitonepass");
    let inner = payload(900_000, 63);
    let arch = fixtures::rar5_volume(&[("film.mkv", inner.len() as u64, &inner, false, false)]);
    let names = post_split(&mut fx, &arch, 4);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();

    assert!(ok, "the one-pass job must exit 0:\n{log}");
    assert_mapped_one_pass(&log, &fx.dir.join("out"), &names, &inner);
}

/// (b) with a PASSWORD: an encrypted store split, unlocked off the
/// `Name{{pw}}.nzb` convention, maps the same way - the mapper takes an
/// encrypted store entry once a password is in hand, and the finish
/// decrypt turns the routed ciphertext into the member. Before (b) this
/// exact fixture was the encrypted rescue leg below.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_split_maps_one_pass_with_the_job_password() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarsplitenconepass");
    let inner = payload(600_000, 64);
    let f = fixtures::encrypt_file("splitpw", &inner, 17);
    let arch =
        fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let names = post_split(&mut fx, &arch, 4);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{splitpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &locked, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();

    assert!(ok, "the one-pass encrypted job must exit 0:\n{log}");
    assert!(
        log.contains("· encrypted"),
        "the fixture is not the encrypted shape this leg is about:\n{log}"
    );
    assert_mapped_one_pass(&log, &fx.dir.join("out"), &names, &inner);
}

/// The field shape from `research/DISKSHAPE-ROUND-2026-08-21.md` §2.2, at
/// four parts instead of sixty-two: one standalone store `stage.rar` cut
/// on byte boundaries into `stage.rar.001`..`.004`. Part 1 is a RAR head
/// over a quarter of the archive, so the in-stream mapper refuses it
/// (`data area exceeds volume`) and the whole set lands on disk; parts
/// 2..4 are raw continuation bytes carrying no signature at all, so
/// nothing claims them either.
///
/// That is the route into the tail's unowned-fallback arm: the demote
/// reason is nobody else's, `try_unrar_spent` cannot open a `.001` that
/// is a quarter of an archive, and before TODO 211 the job ended rc=1
/// with every part still on disk and nothing delivered.
#[tokio::test(flavor = "multi_thread")]
async fn split_of_a_single_store_rar_is_rescued_by_the_tails_unowned_arm() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarsplitrescue");
    let inner = payload(900_000, 61);
    let arch = fixtures::rar5_volume(&[("film.mkv", inner.len() as u64, &inner, false, false)]);
    let names = post_split(&mut fx, &arch, 4);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(
            &cfg,
            &nzb,
            &out,
            &[
                ("NZBFAST_TEST_FORBID_UNRAR", "1"),
                ("NZBFAST_NO_RAR_SPLIT", "1"),
            ],
        )
    })
    .await
    .unwrap();

    assert!(ok, "the rescued job must exit 0:\n{log}");
    assert_rescued_through_the_tail(&log, "data area exceeds volume");
    assert_eq!(
        std::fs::read(fx.dir.join("out/film.mkv")).expect("the member the split held"),
        inner,
        "the archive member must arrive byte for byte"
    );
    assert_parts_are_spent(&fx.dir.join("out"), &names, "stage.rar");
}

/// The same rescue with a PASSWORD threaded through it: a byte split of a
/// single encrypted store `.rar`, unlocked off the `Name{{pw}}.nzb`
/// convention. `rescue_split_after_failed_unpack` takes the job password
/// and hands it to the extraction it runs over what it joined, and
/// nothing anywhere tested that argument.
///
/// The demote reason is the plaintext one, and deliberately asserted as
/// such: see the module note on which of the tail's two sites a split
/// container reaches.
#[tokio::test(flavor = "multi_thread")]
async fn encrypted_split_is_rescued_with_the_job_password() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarsplitenc");
    let inner = payload(600_000, 62);
    let f = fixtures::encrypt_file("splitpw", &inner, 17);
    let arch =
        fixtures::rar5_volume_enc(&[("film.mkv", &f, 0..f.cipher.len(), false, false)], None);
    let names = post_split(&mut fx, &arch, 4);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let locked = fx.dir.join("release{{splitpw}}.nzb");
    std::fs::rename(&nzb, &locked).unwrap();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(
            &cfg,
            &locked,
            &out,
            &[
                ("NZBFAST_TEST_FORBID_UNRAR", "1"),
                ("NZBFAST_NO_RAR_SPLIT", "1"),
            ],
        )
    })
    .await
    .unwrap();

    assert!(ok, "the rescued encrypted job must exit 0:\n{log}");
    assert!(
        log.contains("· encrypted"),
        "the fixture is not the encrypted shape this leg is about:\n{log}"
    );
    assert_rescued_through_the_tail(&log, "data area exceeds volume");
    // The payload IS the proof the password reached the inner extraction:
    // without it the join still happens and nothing decrypts.
    assert_eq!(
        std::fs::read(fx.dir.join("out/film.mkv")).expect("the member the split held"),
        inner,
        "the decrypted member must arrive byte for byte"
    );
    assert_parts_are_spent(&fx.dir.join("out"), &names, "stage.rar");
}

/// A byte split of a COMPRESSED `.rar`, which is the same rung reached by
/// a different door: the top-level chase claims a compressed set rather
/// than leaving it to the store mapper, so the demote reason is its own
/// (`chase failed: … input is too short`) and names no format. That reason
/// is unowned too, so it lands on the same arm - which is the whole of the
/// module note's finding, held here as a test rather than as prose.
///
/// The rescue's inner extraction has real work to do on this one: the
/// joined container is genuinely compressed, so what comes back out is a
/// decompression rather than a store copy.
#[tokio::test(flavor = "multi_thread")]
async fn compressed_split_is_rescued_after_the_chase_fails_on_the_parts() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("rarsplitcomp");
    let inner = compressible(600_000);
    let arch = rars::rar50::Rar50Writer::new(rars::rar50::WriterOptions::default())
        .compressed_entries(&[rars::rar50::CompressedEntry {
            name: b"film.mkv",
            data: &inner,
            mtime: None,
            attributes: 0,
            host_os: 0,
        }])
        .finish()
        .unwrap();
    assert!(
        arch.len() < inner.len(),
        "the writer stored the entry instead of compressing it: {} bytes",
        arch.len()
    );
    let names = post_split(&mut fx, &arch, 4);
    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");

    let (log, ok) = tokio::task::spawn_blocking(move || {
        run_get(&cfg, &nzb, &out, &[("NZBFAST_TEST_FORBID_UNRAR", "1")])
    })
    .await
    .unwrap();

    assert!(ok, "the rescued compressed job must exit 0:\n{log}");
    assert!(
        log.contains("· compressed"),
        "the fixture is not the compressed shape this leg is about:\n{log}"
    );
    // (b) moved this door: the split head declines the chase, so the
    // demote is the mapper's own reason and the tail's FIRST arm runs
    // the ladder - and falls through to the same rescue.
    assert_rescued_through_the_tail(&log, "compressed or encrypted entries");
    assert_eq!(
        std::fs::read(fx.dir.join("out/film.mkv")).expect("the member the split held"),
        inner,
        "the decompressed member must arrive byte for byte"
    );
    assert_parts_are_spent(&fx.dir.join("out"), &names, "stage.rar");
}
