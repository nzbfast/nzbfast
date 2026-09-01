//! X5-24 (30 Aug 2026 ruling): the RESIDUAL half of the late-set pass -
//! `get::latesets::apply_nonactivated_disk_sets`, which is the seam the
//! row's own prediction missed.
//!
//! The row predicted the capability was MISSING and blocked by the
//! stray-set guard in `get/settle.rs`. Probed on 30 Aug 2026 the
//! prediction is INVERTED: the capability already SHIPPED, and it
//! shipped UNGATED - a recovery set for a file the post never offers a
//! slot for was materialised, and two equal-length wholly missing
//! members were BOTH materialised. The product ruling of 30 Aug 2026 was
//! option A then B: fix the honest failure first, then allow residual
//! assignment gated on GLOBAL UNIQUENESS, with the ambiguous and foreign
//! controls declining. Option C - pair up whatever is left over - was
//! rejected.
//!
//! So all three of these are PINS on shipped behaviour, not predicted
//! reds: one capability and two controls that must decline. The gate
//! they hold is documented at
//! [`nzbfast::get::latesets`]'s `keep_uniquely_assignable_residuals`.
//!
//! Sibling directory rather than lines in `e2e.rs`, for the size gate.
//! `e2e_residual` is the same ROW at the OTHER seam (the in-stream
//! stray-release guard, `get/residual.rs`) and the two are complements:
//! that one decides whether an ACTIVE set may be spent, this one
//! whether a set the stream never activated may keep what it rebuilt.

use super::*;
use crate::payloads;

// The same late-set pass, asked two further questions by the 31 Aug 2026
// capability round. Children of this module rather than siblings of
// `e2e.rs`: they are the SAME seam (`apply_nonactivated_disk_sets`), and
// `e2e.rs` is at its size-gate baseline with no room for another `mod`
// line.
mod chainset;
mod donorshare;

/// `par2 create` one named set over `files` with an explicit redundancy
/// and block size, post every produced `.par2` under hash subjects AND
/// hash yEnc names, then delete them from the fixture dir. Two calls
/// with different block sizes give two sets with different ids over the
/// same member.
fn add_named_par2_obfuscated(
    fx: &mut Fixture,
    base: &str,
    redundancy: u32,
    block: u64,
    files: &[&str],
    art_size: usize,
) -> Option<Vec<String>> {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg(format!("-s{block}"))
        .arg("-q")
        .arg(base)
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return None,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    let mut ids = Vec::new();
    for (i, p) in par2s.iter().enumerate() {
        let data = std::fs::read(p).unwrap();
        // The hash subject must be unique ACROSS sets: `base` is what
        // separates them, and two sets sharing a prefix silently
        // overwrite each other in the article map.
        let hash = format!("{base}{i:02}zXm9rTb");
        let tag = format!("{base}-obf-{i}");
        let segs = make_file_articles(&hash, &data, art_size, &tag, &mut fx.articles);
        ids.extend(segs.iter().map(|(id, _, _)| format!("<{id}>")));
        fx.nzb_files.push((hash, segs));
        std::fs::remove_file(p).unwrap();
    }
    Some(ids)
}

/// One `get` run against an in-process mock server, with the output
/// directory left exactly as the caller prepared it (the X5 rows plant
/// aliases in there before the job starts).
async fn run_wave5(fx: &Fixture, chaos: Chaos) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    if std::env::var("WAVE5_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
    }
    (log, ok, out)
}

// ---------------------------------------------------------------- X5-24

/// X5-24's fixture: `n` fully obfuscated ONE-FILE recovery sets, each
/// over a payload of a UNIQUE length, each with 100% parity. Payloads
/// listed in `posted` ride the wire; the rest have their NZB slot but
/// every article refused, so they arrive WHOLLY MISSING.
///
/// Returns the Fixture (it owns the scratch guard - dropping it before
/// the assertions deletes the tree being graded), the log, rc and out.
async fn run_x5_24(
    tag: &str,
    members: &[(&str, usize)],
    posted: &[usize],
    extra_foreign: Option<(&str, usize)>,
) -> (Fixture, String, bool, PathBuf) {
    let mut fx = Fixture::new(tag);
    let mut chaos = Chaos::default();

    for (i, (name, len)) in members.iter().enumerate() {
        let data = payloads::unique_payload(*len, 40 + i as u64);
        std::fs::write(fx.dir.join(name), &data).unwrap();
        // 100% parity: the set alone can rebuild its member.
        assert!(
            add_named_par2_obfuscated(&mut fx, &format!("setx{i}"), 100, 10_000, &[name], 40_000)
                .is_some(),
            "par2 create failed for {name}"
        );
        std::fs::remove_file(fx.dir.join(name)).unwrap();

        // Every member has an NZB slot under a HASH subject and a HASH
        // yEnc name - nothing on the wire carries the real name.
        let hash = format!("Xx{i}4vNq83Lm");
        let before = fx.nzb_files.len();
        fx.add_file_obfuscated(&hash, &hash, &data, 40_000);
        if !posted.contains(&i) {
            // Wholly missing: the slot exists, the articles do not.
            for (id, _, _) in &fx.nzb_files[before].1 {
                chaos.missing.insert(format!("<{id}>"));
            }
        }
    }

    // The foreign-set control: a set over a file that has NO NZB slot at
    // all. It must never be assigned to anything.
    if let Some((name, len)) = extra_foreign {
        let data = payloads::unique_payload(len, 200);
        std::fs::write(fx.dir.join(name), &data).unwrap();
        assert!(
            add_named_par2_obfuscated(&mut fx, "setfgn", 100, 10_000, &[name], 40_000).is_some(),
            "par2 create failed for the foreign set"
        );
        std::fs::remove_file(fx.dir.join(name)).unwrap();
    }

    let (log, ok, out) = run_wave5(&fx, chaos).await;
    (fx, log, ok, out)
}

/// X5-24 (capability): three obfuscated one-file sets with unique member
/// lengths; two payloads arrive and claim their sets; the third arrives
/// with ZERO bytes but its set carries 100% parity.
///
/// **MEASURED 30 Aug 2026 and the row's prediction is WRONG.** Codex
/// predicted the stray-set guard in `get/settle.rs` would classify the
/// residual set as foreign and never invoke its parity. It does not get
/// the chance: a set that never activated in-stream is applied wholesale
/// by `apply_nonactivated_disk_sets` (`get/latesets.rs`), which rebuilt
/// the member byte-exact. The capability ALREADY SHIPS - so this probe
/// PASSES and is a pin, not a red row.
///
/// Two pins, because the row is two halves. The REBUILD is the option-B
/// half - the uniqueness gate must not decline the honest case. The
/// `ok` is option A: on the baseline the job that had just reconstructed
/// and MD5-proved every member still exited nonzero with "download
/// incomplete: 1 file(s) with missing segments; 5 of 12 segment(s)
/// never arrived", counting articles that never arrived for a file it
/// had produced.
#[tokio::test(flavor = "multi_thread")]
async fn x5_24_a_uniquely_assignable_missing_member_is_rebuilt() {
    if !have_par2() {
        eprintln!("x5_24: par2 unavailable - skipping");
        return;
    }
    let members = [
        ("Alpha.One.bin", 100_000),
        ("Bravo.Two.bin", 140_000),
        ("Charlie.Three.bin", 180_000),
    ];
    let (_fx, log, ok, out) = run_x5_24("wave5x524", &members, &[0, 1], None).await;

    let landed = std::fs::read(out.join("Charlie.Three.bin")).unwrap_or_default();
    eprintln!(
        "x5_24: rc ok={ok}, Charlie.Three.bin {} bytes",
        landed.len()
    );
    assert_eq!(
        landed.len(),
        180_000,
        "the wholly missing member was not rebuilt from its own 100% \
         parity\n{log}"
    );
    assert!(
        ok,
        "every member is on disk and MD5-proved, but the job still \
         reports the segments that never arrived for the one the late \
         set rebuilt\n{log}"
    );
}

/// X5-24 (foreign control): the same shape PLUS a recovery set over a
/// file the NZB never offers a slot for.
///
/// **MEASURED red 30 Aug 2026.** `Not.Ours.bin` was materialised.
/// `apply_nonactivated_disk_sets` applies EVERY non-activated disk set
/// and its design note accepts that ("a success can only ADD named,
/// verified files") - so another release's sidecar left in the NZB gets
/// that release's file reconstructed into this download's folder, at the
/// cost of fetching its parity. The product ruling of 30 Aug 2026
/// narrows that: residual assignment must be gated on GLOBAL
/// UNIQUENESS, and a genuinely foreign set must decline.
#[tokio::test(flavor = "multi_thread")]
async fn x5_24_control_a_foreign_set_must_never_be_assigned() {
    if !have_par2() {
        eprintln!("x5_24 foreign: par2 unavailable - skipping");
        return;
    }
    let members = [
        ("Alpha.One.bin", 100_000),
        ("Bravo.Two.bin", 140_000),
        ("Charlie.Three.bin", 180_000),
    ];
    let (_fx, log, ok, out) = run_x5_24(
        "wave5x524f",
        &members,
        &[0, 1],
        Some(("Not.Ours.bin", 90_000)),
    )
    .await;

    assert!(
        !out.join("Not.Ours.bin").exists(),
        "a recovery set for a file this post never offers was \
         materialised\n{log}"
    );
    // The honest half, beside the foreign one: option A was ruled FIRST,
    // so a foreign set in the same post must not cost the assignable
    // member its rebuild. A gate that declined on a bare count of
    // leftover sets against incomplete slots would pass the assertion
    // above and fail these two.
    assert_eq!(
        std::fs::read(out.join("Charlie.Three.bin"))
            .unwrap_or_default()
            .len(),
        180_000,
        "the foreign set cost the uniquely assignable member its \
         rebuild\n{log}"
    );
    assert!(ok, "the assignable rebuild was not credited\n{log}");
}

/// X5-24 (ambiguous control): TWO wholly missing members of EQUAL
/// length, so the residual pairing is not unique.
///
/// **MEASURED red 30 Aug 2026** - both were materialised (150000 /
/// 150000). Ambiguity must decline rather than pick, which is the other
/// half of the uniqueness gate.
#[tokio::test(flavor = "multi_thread")]
async fn x5_24_control_an_ambiguous_residual_must_decline() {
    if !have_par2() {
        eprintln!("x5_24 ambiguous: par2 unavailable - skipping");
        return;
    }
    let members = [
        ("Alpha.One.bin", 100_000),
        ("Delta.Four.bin", 150_000),
        ("Echo.Five.bin", 150_000),
    ];
    let (_fx, log, ok, out) = run_x5_24("wave5x524a", &members, &[0], None).await;

    let d = std::fs::read(out.join("Delta.Four.bin")).unwrap_or_default();
    let e = std::fs::read(out.join("Echo.Five.bin")).unwrap_or_default();
    assert!(
        d.is_empty() && e.is_empty(),
        "two equal-length wholly missing members are not uniquely \
         assignable, but {} / {} bytes were materialised\n{log}",
        d.len(),
        e.len()
    );
    // A silent decline is how the next reader concludes the capability
    // was never there - which is what this row's own author concluded
    // about the version of the pass that declined nothing.
    assert!(
        log.contains("lost more than one whole file of that size"),
        "the decline was not explained\n{log}"
    );
    // And declining must not turn a short download green.
    assert!(!ok, "a declined rebuild was credited anyway\n{log}");
}

// ------------------------------------------------------------------ X-4

/// X-4 (31 Aug 2026): a leftover set that adopts ONE member must not
/// buy its OTHER member a free pass.
///
/// The X5-24 gate asked "did this repair have bytes of its own to work
/// from" of the WHOLE repair, because
/// `nzbkit::par2repair::RepairReport` could only answer it that way:
/// `blocks_adopted` and friends are totals. So a two-file leftover set
/// whose first member happened to be on disk under a hash - which is
/// F12's own shape, and legitimately ungated - reported adoption for
/// the SET, and the second member, rebuilt from parity with no bytes of
/// it anywhere, skipped `keep_uniquely_assignable_residuals` entirely.
/// Another release's payload, materialised into this download's output
/// directory under a real name, which is what an *arr imports.
///
/// **MEASURED on origin/main before the fix: `Not.Ours.Two.bin` was
/// materialised at 120,000 bytes.** The gate never ran on it.
///
/// Both halves are asserted, because a blanket refusal would pass the
/// first assertion and is the wrong fix: `Not.Ours.One.bin` HAS the
/// cryptographic tie (the set matched its own FileDesc against bytes
/// already here) and must still land. Per-target, not per-set.
///
/// The post loses nothing at all, so there is no short slot for the
/// residual to be - the sharpest form of the decline, and the one the
/// old code could not reach.
#[tokio::test(flavor = "multi_thread")]
async fn x4_a_sibling_adoption_does_not_excuse_a_parity_only_member() {
    if !have_par2() {
        eprintln!("x4: par2 unavailable - skipping");
        return;
    }
    let mut fx = Fixture::new("wave5x4");

    // This post's own member and its own recovery set, added FIRST so
    // that set is the one the stream activates. Without it the leftover
    // set below is the only set there is, the stream activates THAT,
    // and the whole probe lands on the in-stream seam
    // (`get::residual`) instead of this one - measured while building
    // it: extract renamed the hash to `Not.Ours.One.bin` and the active
    // repair rebuilt the other member before `latesets` ever ran.
    fx.add_file(
        "Alpha.One.bin",
        &payloads::unique_payload(60_000, 3),
        40_000,
    );
    assert!(
        add_named_par2_obfuscated(&mut fx, "setmine", 10, 10_000, &["Alpha.One.bin"], 40_000)
            .is_some(),
        "par2 create failed for this post's own set"
    );

    // A LEFTOVER release's two-file recovery set, 100% parity, its
    // packets posted under hashes so they land at the job root and this
    // job publishes them - but no active set of ours names them, so it
    // is unvouched and its rebuilds are the gate's subject.
    //
    // Independent seeds through `payloads::unique_payload`, so
    // `Not.Ours.Two.bin` is genuinely absent from the directory. Under
    // `e2e.rs`'s `payload` the two members would be shifted copies of
    // each other, Two would be ADOPTED out of One, and the probe would
    // grade the fixture rather than the gate (chip queue X-2).
    let one = payloads::unique_payload(80_000, 61);
    let two = payloads::unique_payload(120_000, 62);
    std::fs::write(fx.dir.join("Not.Ours.One.bin"), &one).unwrap();
    std::fs::write(fx.dir.join("Not.Ours.Two.bin"), &two).unwrap();
    assert!(
        add_named_par2_obfuscated(
            &mut fx,
            "setleft",
            100,
            10_000,
            &["Not.Ours.One.bin", "Not.Ours.Two.bin"],
            40_000,
        )
        .is_some(),
        "par2 create failed for the leftover set"
    );
    std::fs::remove_file(fx.dir.join("Not.Ours.One.bin")).unwrap();
    std::fs::remove_file(fx.dir.join("Not.Ours.Two.bin")).unwrap();

    // ONE of the two rides the wire, wholly obfuscated: it lands under
    // its hash, so the leftover set adopts it and writes out the real
    // name. The OTHER has no NZB slot at all - nothing but the parity
    // can produce it.
    fx.add_file_obfuscated("Lf1q7vZk20", "Lf1q7vZk20", &one, 40_000);

    let (log, ok, out) = run_wave5(&fx, Chaos::default()).await;

    let landed_two = std::fs::read(out.join("Not.Ours.Two.bin")).unwrap_or_default();
    eprintln!(
        "x4: rc ok={ok}, One {} bytes, Two {} bytes",
        std::fs::read(out.join("Not.Ours.One.bin"))
            .unwrap_or_default()
            .len(),
        landed_two.len()
    );
    assert!(
        landed_two.is_empty(),
        "a leftover set's wholly-missing member was materialised because \
         its SIBLING adopted - {} byte(s) of another release in this \
         download's output directory\n{log}",
        landed_two.len()
    );
    assert!(
        log.contains("this post lost no whole file of that size"),
        "the decline was not explained\n{log}"
    );
    // The other half: the tightening is per TARGET. The member whose
    // bytes really were here keeps F12's behaviour and is named.
    assert_eq!(
        std::fs::read(out.join("Not.Ours.One.bin"))
            .unwrap_or_default()
            .len(),
        80_000,
        "the member the set adopted has a cryptographic tie to bytes \
         this job put here and must still be named\n{log}"
    );
    // And a declined foreign rebuild must not fail a job that lost
    // nothing.
    assert!(
        ok,
        "a clean job was failed by a leftover set's decline\n{log}"
    );
}

/// X-4's other half, and the reason it is not a control: asking the
/// question per TARGET changes what an unvouched set can be CREDITED
/// with, not only what it may keep.
///
/// A leftover set that adopted a sibling used to produce no residual at
/// all, so `assigned` stayed all-`None` and
/// `residual_accounts_for_the_shortfall` could never fire: the set
/// rebuilt this post's genuinely lost member, dropped it in the output
/// directory ungated, and the job still exited nonzero counting the
/// segments that never arrived for a file sitting right there. That is
/// X5-24's option-A defect surviving in the one shape its own probe
/// could not reach, because that probe's sets are single-file and this
/// one needs a sibling to do the adopting.
///
/// So this is a capability pin and the green direction, which is the
/// one that needs a guard: it fires only through the SAME uniqueness
/// gate as everything else - `Charlie.Three.bin` is kept because the
/// post admits exactly one whole loss it can be, and the job is green
/// because that one loss is the whole of the shortfall.
#[tokio::test(flavor = "multi_thread")]
async fn x4_a_kept_residual_still_accounts_for_the_shortfall_beside_an_adoption() {
    if !have_par2() {
        eprintln!("x4 credit: par2 unavailable - skipping");
        return;
    }
    let mut fx = Fixture::new("wave5x4c");
    let mut chaos = Chaos::default();

    // This post's own member and set, added first so THIS is what the
    // stream activates - see the probe above for what happens without
    // it.
    fx.add_file(
        "Alpha.One.bin",
        &payloads::unique_payload(60_000, 3),
        40_000,
    );
    assert!(
        add_named_par2_obfuscated(&mut fx, "setmine", 10, 10_000, &["Alpha.One.bin"], 40_000)
            .is_some(),
        "par2 create failed for this post's own set"
    );

    // A set the stream never activates, over two files: a donor that
    // arrives hash-named, and one of THIS post's members that arrives
    // not at all.
    let donor = payloads::unique_payload(80_000, 71);
    let lost = payloads::unique_payload(180_000, 72);
    std::fs::write(fx.dir.join("Leftover.Donor.bin"), &donor).unwrap();
    std::fs::write(fx.dir.join("Charlie.Three.bin"), &lost).unwrap();
    assert!(
        add_named_par2_obfuscated(
            &mut fx,
            "setlate",
            100,
            10_000,
            &["Leftover.Donor.bin", "Charlie.Three.bin"],
            40_000,
        )
        .is_some(),
        "par2 create failed for the late set"
    );
    std::fs::remove_file(fx.dir.join("Leftover.Donor.bin")).unwrap();
    std::fs::remove_file(fx.dir.join("Charlie.Three.bin")).unwrap();

    fx.add_file_obfuscated("Dn3w8pQr51", "Dn3w8pQr51", &donor, 40_000);
    // Charlie has a slot and a declared byte count - the length band's
    // own input - and every one of its articles refused.
    let before = fx.nzb_files.len();
    fx.add_file_obfuscated("Ch5m2bYt09", "Ch5m2bYt09", &lost, 40_000);
    for (id, _, _) in &fx.nzb_files[before].1 {
        chaos.missing.insert(format!("<{id}>"));
    }

    let (log, ok, out) = run_wave5(&fx, chaos).await;

    let landed = std::fs::read(out.join("Charlie.Three.bin")).unwrap_or_default();
    eprintln!(
        "x4 credit: rc ok={ok}, Charlie.Three.bin {} bytes",
        landed.len()
    );
    assert_eq!(
        landed.len(),
        180_000,
        "the uniquely assignable loss was not rebuilt - a sibling's \
         adoption must not cost it its rebuild\n{log}"
    );
    assert!(
        ok,
        "the job counts segments that never arrived for a file the late \
         set rebuilt and the gate KEPT, because the set's other member \
         was adopted\n{log}"
    );
}

// ------------------------------------------------------- X-8 (name vs path)

/// X-8 (31 Aug 2026): a leftover set whose two descriptors land at ONE
/// destination is judged by the wrong file - so the one the engine had
/// to rename survives the gate that exists to remove it.
///
/// `par2repair` REPORTS a file by its FileDesc name
/// (`report.files_created.push(t.file.name.clone())`) and LANDS it at a
/// path it may have had to disambiguate: two descriptors whose names
/// sanitize to one destination would otherwise share a file - silent
/// data loss - so the second is renamed `<name>.dup-<first 6 bytes of
/// file_id>`. [`residual_creations`] rebuilt a path from the NAME, so
/// the disambiguated file was never a `Residual` at all and
/// [`keep_uniquely_assignable_residuals`] could not see it. On the
/// `!mine` arm that is precisely what the gate exists to refuse.
///
/// # The fixture, and why it is spelled with a case variant
///
/// The collision has to be a WITHIN-SET one, and that is a correction to
/// the row's own premise rather than a detail of the fixture. A
/// CROSS-set collision reaches a different arm and stays there:
/// `contested` disambiguates every set's target for such a name, so
/// neither takes the plain path and the shape below never arises. When
/// this fixture was written that arm could not fire at all - the entry
/// point `apply_nonactivated_disk_sets` uses passed a DEFAULT
/// `DirContext`, and two sets each declaring `Contested.bin` for
/// different content both took the plain path with the second
/// overwriting the first (measured 31 Aug 2026 at the engine, fixed the
/// same day, pinned in `par2repair_namepath.rs`). Either way it is a
/// SEPARATE defect from this one and not what this probe grades.
///
/// So the set declares ONE file under TWO spellings that differ only in
/// case. On the case-insensitive volumes this fleet develops on those
/// are one destination, `path_identity_key` folds them, and the second
/// target is renamed - which is the shape a real post reaches through a
/// trailing dot or a zero-width format character just as well, and the
/// only one `par2 create` can be made to produce here (two files that
/// differ only in case cannot coexist on the volume).
///
/// **MEASURED red on origin/main: `Not.Ours.Dup.bin.dup-<fid>` was left
/// in the output directory**, 100,000 bytes of another release under a
/// machine name, while the gate spent both of its declines on the ONE
/// file it could see - the second `remove_file` landing on a path the
/// first had already unlinked.
///
/// The post loses nothing at all, so neither rebuild can be any loss of
/// it: both must be declined and both must go.
#[tokio::test(flavor = "multi_thread")]
async fn x8_a_disambiguated_leftover_rebuild_is_gated_like_any_other() {
    if !have_par2() {
        eprintln!("x8: par2 unavailable - skipping");
        return;
    }
    let mut fx = Fixture::new("wave5x8");

    // This post's own member and its own recovery set, added FIRST so
    // that set is the one the stream activates - X-4's trap, and
    // without it the leftover set below is the only set there is and
    // the probe lands on `get::residual` instead of this seam.
    fx.add_file(
        "Alpha.One.bin",
        &payloads::unique_payload(60_000, 3),
        40_000,
    );
    assert!(
        add_named_par2_obfuscated(&mut fx, "setmine", 10, 10_000, &["Alpha.One.bin"], 40_000)
            .is_some(),
        "par2 create failed for this post's own set"
    );

    // The leftover set: ONE file on disk, declared under TWO spellings.
    // `par2 create` opens both and writes two FileDescs with distinct
    // file ids, which is exactly the pair the engine must disambiguate.
    let dup = payloads::unique_payload(100_000, 71);
    std::fs::write(fx.dir.join("Not.Ours.Dup.bin"), &dup).unwrap();
    assert!(
        add_named_par2_obfuscated(
            &mut fx,
            "setleft",
            100,
            10_000,
            &["Not.Ours.Dup.bin", "NOT.OURS.DUP.BIN"],
            40_000,
        )
        .is_some(),
        "par2 create failed for the leftover set"
    );
    std::fs::remove_file(fx.dir.join("Not.Ours.Dup.bin")).unwrap();

    let (log, ok, out) = run_wave5(&fx, Chaos::default()).await;

    let left: Vec<String> = std::fs::read_dir(&out)
        .map(|d| {
            d.filter_map(|e| {
                let n = e.ok()?.file_name().to_string_lossy().into_owned();
                n.contains(".dup-").then_some(n)
            })
            .collect()
        })
        .unwrap_or_default();
    eprintln!("x8: rc ok={ok}, disambiguated leftovers {left:?}");
    assert!(
        left.is_empty(),
        "a leftover set's rebuild the engine had to rename survived the \
         uniqueness gate - {left:?} left in this download's output \
         directory\n{log}"
    );
    // The half a blanket sweep would also satisfy: the gate must have
    // RUN on it and said why, not merely have left the directory tidy.
    assert!(
        log.contains("this post lost no whole file of that size"),
        "the decline was not explained\n{log}"
    );
    // And the plain-named twin goes for the same reason.
    assert!(
        !out.join("Not.Ours.Dup.bin").exists(),
        "the leftover set's plain-named rebuild was left behind\n{log}"
    );
    // A declined foreign rebuild must not fail a job that lost nothing.
    assert!(
        ok,
        "a clean job was failed by a leftover set's decline\n{log}"
    );
}
