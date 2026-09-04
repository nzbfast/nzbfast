//! X-8 (31 Aug 2026): what a `RepairReport` says a file is CALLED and
//! where the repair actually PUT it are two different facts, and the
//! second one is now carried.
//!
//! `par2repair` reports every target by its FileDesc name
//! (`report.files_created.push(t.file.name.clone())`) and lands it at
//! `join_out_name(dir, &sanitize_out_name(&d.name))` - then
//! DISAMBIGUATES that destination where two descriptors would otherwise
//! share a file, renaming the second to `<name>.dup-<first 6 bytes of
//! file_id>`. Sharing a destination is silent data loss (the claim loop
//! in `par2repair.rs` records what it cost when the block was absent),
//! so the rename is right; what was missing is any way for a caller to
//! learn about it. `FileRepair::path` is that way, and these two tests
//! are the pins on it.
//!
//! # Why this matters outside the engine
//!
//! `nzbfast::get::latesets` gates a rebuild made by a recovery set the
//! stream never activated: a set NOTHING vouches for has produced a
//! file under a real name in this download's output directory, and the
//! losing arm of that gate DELETES it. It resolved the file by
//! rebuilding a path out of the reported name, so a disambiguated
//! target was never gated at all - measured 31 Aug 2026 as
//! `Not.Ours.Dup.bin.dup-673dcaa8b1ab`, 100,000 bytes of a leftover
//! release, left behind while both of the gate's declines landed on the
//! ONE path a name could reach (`nzbfast`'s
//! `e2e_lateset::x8_a_disambiguated_leftover_rebuild_is_gated_like_any_other`).
//!
//! # And the sibling defect this file first PINNED and now guards
//!
//! Both of `DirContext`'s name sets were EMPTY on the entry point that
//! pass uses: `repair_dir_set_with_donors_scoped` passed
//! `DirContext::default()`, so `apply_nonactivated_disk_sets` applying
//! every non-activated set in turn got neither protection. Measured
//! 31 Aug 2026 and pinned here as SHIPPED BEHAVIOUR, then fixed the
//! same day - that entry point now builds a COMPLETE catalog and
//! derives both sets from it, so the two assertions below have moved to
//! the fixed reading and are the guard against a default coming back.
//!
//! `contested` empty cost an OVERWRITE:
//! [`two_sets_claiming_one_name_through_the_scoped_entry_point`]
//! measured set B patching over set A's landed, MD5-proved file. That
//! is the opposite of the defect above - here the rename happens and
//! the caller cannot see it, there it did not happen at all.
//! `declared` empty cost a DELETE, which is worse:
//! [`a_neighbouring_sets_declared_payload_is_never_a_spent_donor`]
//! measured a set's only payload being named as its neighbour's spent
//! donor, which `get::latesets` then sweeps (to the Trash under
//! `cleanup_recoverable`, a hard unlink otherwise).
//! The private notes for 31 Aug 2026 on the late-set pass's empty
//! `DirContext` carry that item, and its fix;
//! `research/LATESETS-NAME-VS-PATH-2026-08-31.md` carries this file's
//! own measurement.

use nzbkit::par2repair::{
    PacketScope, RepairStatus, disk_set_ids, repair_dir_set_with_donors_scoped,
};
use std::path::{Path, PathBuf};
use std::process::Command;

use crate::scratch;

/// Per-test scratch directory. `nzbkit-` prefixed so the sweeper in
/// `scratch` reclaims it, and process-id tagged so two shards cannot
/// share one.
fn scratch_dir(tag: &str) -> scratch::ScratchDir {
    scratch::ScratchDir::attach(
        &std::env::temp_dir().join(format!("nzbkit-{tag}-{}", std::process::id())),
    )
}

fn have_par2() -> bool {
    let ok = Command::new("par2")
        .arg("-V")
        .output()
        .is_ok_and(|o| o.status.success());
    assert!(
        ok || std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
        "NZBFAST_REQUIRE_PAR2 is set but `par2 -V` does not run - the PAR2 tests \
         would have skipped and the run would have looked green"
    );
    ok
}

/// Deterministic, NON-periodic contents. A repeating pattern lets the
/// sliding adoption scan find a block's content intact elsewhere, which
/// would turn a parity rebuild into an adoption and grade the fixture
/// instead of the seam.
fn payload(n: usize, seed: u64) -> Vec<u8> {
    let mut x = seed | 1;
    (0..n)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

fn par2_create(dir: &Path, base: &str, files: &[&str]) {
    // Every input is asserted to EXIST first, and that is not belt and
    // braces - it is the guard for the way this helper actually failed.
    // `par2 create` SKIPS an input it cannot open and STILL EXITS 0, so
    // the `st.success()` below cannot see it: a fixture that names a
    // file it never wrote builds a set with fewer descriptors than the
    // test is about, and says nothing. That is exactly how the
    // case-alias fixture this file used to carry reached CI - on ext4
    // `RES.TWO.BIN` did not exist, par2 quietly emitted ONE descriptor,
    // and the nightly failed 100 lines later on a count nobody could
    // read back to its cause. The fixture is portable now; this is what
    // stops the next one failing the same unreadable way.
    for f in files {
        assert!(
            dir.join(f).exists(),
            "fixture names {f:?}, which is not on disk - `par2 create` \
             would skip it and still exit 0, building a set with fewer \
             descriptors than this test is about"
        );
    }
    let st = Command::new("par2")
        .args(["create", "-r100", "-s10000", "-q", base])
        .args(files)
        .current_dir(dir)
        .status()
        .expect("par2 create");
    assert!(st.success(), "par2 create failed for {base}");
}

/// Apply every set in `dir` the way `get::latesets` does - one set at a
/// time, by id, through the scoped entry point - and hand back each
/// `Repaired` report.
fn apply_every_set(dir: &Path) -> Vec<nzbkit::par2repair::RepairReport> {
    let mut out = Vec::new();
    for id in disk_set_ids(dir).expect("disk_set_ids") {
        // `true` is `get::latesets`' own argument: its shortfall is the
        // last word on the set, so it opts into patching an existing
        // member - see `par2repair::status::publishable`.
        //
        // `None` for the applicability whitelist (F6): this helper
        // applies EVERY set it finds, so every set is applicable and the
        // directory-wide reading is the right one. The narrowed reading
        // has its own fixture below.
        match repair_dir_set_with_donors_scoped(dir, &id, &[], PacketScope::Nested, true, None) {
            Ok(RepairStatus::Repaired(r)) => out.push(r),
            Ok(other) => eprintln!("set {id:02x?}: {other:?}"),
            Err(e) => panic!("set {id:02x?} failed: {e}"),
        }
    }
    out
}

fn names_in(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().file_name().to_string_lossy().into_owned())
        .filter(|n| !n.ends_with(".par2"))
        .collect();
    v.sort();
    v
}

/// A target the repair had to rename is reported with the path it
/// LANDED at, and every path in the census is a file that exists.
///
/// The set declares TWO files whose names differ by a TRAILING DOT, so
/// both are real files on every volume and both `sanitize_out_name` to
/// one destination - the collision the claim loop exists to resolve.
///
/// THE CASE COLLISION THAT USED TO BUILD THIS FIXTURE WAS NOT PORTABLE,
/// and it reddened nightly rather than this suite. It declared one file
/// under two spellings differing only in case, which needs BOTH a volume
/// where the two cannot coexist (so `par2 create` folds them to one
/// payload) AND `path_identity_key(fold: true)` to fold the destinations
/// - two properties of the case-INSENSITIVE volumes this fleet develops
/// on, and neither true on a runner. On ext4 `par2 create` simply does
/// not find `RES.TWO.BIN`, declares ONE descriptor, and the
/// `per_file.len() == 2` assertion below fails in 0.02 s. It was
/// invisible per-push because no per-push job installs `par2`, so the
/// guard above skips it there; the only jobs that ever ran it are
/// nightly's, on ext4, where it could never pass. Measured 31 Aug 2026
/// by reproducing it byte-identically on a case-sensitive APFS image
/// (`research/NIGHTLY-RED-2026-08-31-1800Z-TRIAGE.md`).
///
/// The trailing dot is portable because the fold is: the trailing
/// dot-and-space trim in `sanitize_filename_for` is NOT gated on
/// `windows` - it runs everywhere, deliberately, so a published name is
/// stable across platforms - so both spellings reach one out name
/// whatever the volume, and the destinations collide with no dependence
/// on `fold`. A trailing space and a zero-width format character reach
/// the same arm; the dot is simply the one that survives a shell, a
/// diff and this comment intact. Do NOT "simplify" this back to a case
/// pair: it passes on a developer Mac and cannot pass in CI.
///
/// The assertion is deliberately not "the second entry ends in
/// `.dup-`": what a caller needs is that `path` names a file the repair
/// wrote, that the two entries name DIFFERENT files, and that neither
/// is the guess `join_out_name(dir, name)` would have made. Pinning the
/// tag spelling would pin an implementation detail of the claim loop.
#[test]
fn a_disambiguated_target_reports_the_path_it_landed_at() {
    if !have_par2() {
        eprintln!("namepath: par2 unavailable - skipping");
        return;
    }
    let g = scratch_dir("par2repair-namepath-dup");
    let dir: &Path = &g;
    // Two DIFFERENT payloads, so a run that landed both descriptors on
    // one path would destroy one of them rather than merely overwrite a
    // file with its own bytes - the data loss the claim loop prevents.
    std::fs::write(dir.join("Res.Two.bin"), payload(100_000, 0x5eed_0001)).unwrap();
    std::fs::write(dir.join("Res.Two.bin."), payload(100_000, 0x5eed_0002)).unwrap();
    par2_create(dir, "setc", &["Res.Two.bin", "Res.Two.bin."]);
    // Both spellings gone: only the parity can produce them.
    std::fs::remove_file(dir.join("Res.Two.bin")).unwrap();
    std::fs::remove_file(dir.join("Res.Two.bin.")).unwrap();

    let reports = apply_every_set(dir);
    assert_eq!(reports.len(), 1, "one set, one report");
    let r = &reports[0];
    assert_eq!(
        r.per_file.len(),
        2,
        "the set declares two descriptors: {:?}",
        r.per_file
    );

    // Every census path is a file the repair actually wrote.
    for f in &r.per_file {
        assert!(
            f.path.is_file(),
            "census entry {:?} names {:?}, which the repair never wrote - \
             dir holds {:?}",
            f.name,
            f.path,
            names_in(dir)
        );
    }
    // Two descriptors, two destinations. Sharing one is the data loss
    // the claim loop exists to prevent.
    assert_ne!(
        r.per_file[0].path, r.per_file[1].path,
        "two targets landed at one path"
    );

    // And the guess this field replaces is WRONG for exactly one of the
    // two - which is the whole finding. A run where it were right for
    // both would pass every assertion above while proving nothing, so
    // say it out loud.
    //
    // The guess is `join_out_name(dir, &sanitize_out_name(name))`, which
    // is what the module header says the repair lands a target at BEFORE
    // the claim loop disambiguates it - so the one miss is the RENAME and
    // nothing else. Without the `sanitize_out_name` the count depends on
    // which descriptor the claim loop reaches first: `Res.Two.bin` sorts
    // ahead of `Res.Two.bin.` and so takes the plain destination, leaving
    // exactly one miss, but in the other order BOTH guesses miss and this
    // reads 2 - and the extra miss is the TRIM, not the rename, which is
    // the weaker question wearing the same number. Sanitizing makes it
    // order-independent and keeps it about the claim loop.
    let guessed_wrong = r
        .per_file
        .iter()
        .filter(|f| {
            nzbkit::disk::join_out_name(dir, &nzbkit::disk::sanitize_out_name(&f.name)) != f.path
        })
        .count();
    assert_eq!(
        guessed_wrong,
        1,
        "the fixture did not produce a disambiguated target, so this test \
         graded nothing - dir holds {:?}, census {:?}",
        names_in(dir),
        r.per_file
    );
}

/// The SECOND consequence of that same empty `DirContext`, and the one
/// that cost a DELETE rather than an overwrite.
///
/// `ctx.declared` is "every name any set in the directory declares", and
/// the spent-donor sweep's own comment says why it is consulted: "a name
/// any set in the directory declares is somebody's payload and is never
/// swept, whatever it hashes to". On the scoped entry point that set was
/// EMPTY, so the guard degraded to this set's own target names - and a
/// file that is another set's DECLARED payload, byte-identical to a
/// target this repair just landed, was reported in `consumed_sources`.
///
/// The engine never deletes, so nothing was lost here. The caller does:
/// `get::latesets` does `spent.extend_from_slice(&r.consumed_sources)`
/// and ends the pass with `crate::repair::sweep_spent_sources(&spent)`,
/// which unlinks (to the Trash where `cleanup_recoverable` is on, hard
/// otherwise). So the set that reported `NoDamage` about its own intact
/// payload had that payload removed by its neighbour's repair.
///
/// MEASURED 31 Aug 2026: set A's report named `SetB.Twin.bin`, which is
/// set B's only declared file. FIXED the same day - the entry point
/// derives `declared` from a complete catalog - so this now asserts the
/// EMPTY report, and it is the guard against a default coming back.
///
/// The `Repaired` verdict is asserted too, and is the half that keeps
/// this from passing for the wrong reason: the guard stops set A
/// REPORTING the twin as spent, and must not stop it ADOPTING from
/// it. A run where set A simply failed would report no consumed
/// sources either.
///
/// Adjacent and NOT the same item: `proven-spent-majority-bar` is about
/// how weak the per-byte proof is for a donor that IS junk; this is
/// about a file the sweep must never weigh at all, whatever it hashes
/// to. That arm is untouched here - `declared_names` short-circuits
/// before `proven_spent` is ever reached.
#[test]
fn a_neighbouring_sets_declared_payload_is_never_a_spent_donor() {
    if !have_par2() {
        eprintln!("namepath declared: par2 unavailable - skipping");
        return;
    }
    let g = scratch_dir("par2repair-namepath-declared");
    let dir: &Path = &g;
    // ONE content, TWO declared names, in TWO different sets. Set A's
    // copy is then renamed to set B's name, so A's payload is ABSENT and
    // B's is on disk and byte-identical to what A is about to rebuild.
    std::fs::write(dir.join("SetA.Payload.bin"), payload(100_000, 0x5eed_0004)).unwrap();
    par2_create(dir, "seta", &["SetA.Payload.bin"]);
    std::fs::rename(dir.join("SetA.Payload.bin"), dir.join("SetB.Twin.bin")).unwrap();
    par2_create(dir, "setb", &["SetB.Twin.bin"]);

    let reports = apply_every_set(dir);
    // Set A had to rebuild its absent payload, so a report is what says
    // the fixture graded the guard rather than a failed repair.
    assert!(
        reports
            .iter()
            .any(|r| r.per_file.iter().any(|f| f.name == "SetA.Payload.bin")),
        "set A never repaired, so nothing here weighed a donor: {reports:?}"
    );
    let named: Vec<String> = reports
        .iter()
        .flat_map(|r| r.consumed_sources.iter())
        .filter_map(|p| p.file_name().map(|n| n.to_string_lossy().into_owned()))
        .collect();
    assert_eq!(
        named,
        Vec::<String>::new(),
        "a name another set in this directory declares was reported as a \
         spent donor - `declared` is not reaching this entry point, and \
         `get::latesets` unlinks what it is told is spent"
    );
    // Both payloads are on disk under their own declared names.
    assert_eq!(
        names_in(dir),
        vec!["SetA.Payload.bin".to_string(), "SetB.Twin.bin".to_string()],
        "the two sets' payloads did not both survive"
    );
    // The engine is not the one that deletes, and saying so here is what
    // stops a reader concluding the loss was ever in nzbkit.
    assert!(
        dir.join("SetB.Twin.bin").is_file(),
        "the engine unlinked a consumed source - it never has and must not"
    );
}

/// Two sets claiming ONE destination name for DIFFERENT content, through
/// the entry point `get::latesets` uses: each lands under its own
/// disambiguated path and BOTH payloads survive.
///
/// This measured the opposite on origin/main until 31 Aug 2026.
/// `repair_dir_set_with_donors_scoped` passed a default `DirContext`, so
/// `contested` was empty and the arm that renames both targets could not
/// fire - a repair drops every foreign packet before a target is built,
/// so the claim loop inside one set sees only that set. Both sets
/// reported `Repaired`, the directory ended with ONE file, and set A's
/// landed, MD5-proved 100,000 bytes were gone with nothing said.
///
/// The fix is the entry point deriving the context from a COMPLETE
/// catalog; this is now the guard against a default coming back. Note
/// what it deliberately does NOT assert: that either target keeps the
/// plain `Contested.bin`. Neither does - a contested name is
/// disambiguated in EVERY set, because the sets are repaired
/// independently and there is no order in which one of them may claim
/// the bare name without the other having to know. A name a SINGLE set
/// collides with itself is a different question and keeps its old
/// answer, which is what
/// [`a_disambiguated_target_reports_the_path_it_landed_at`] above pins.
#[test]
fn two_sets_claiming_one_name_through_the_scoped_entry_point() {
    if !have_par2() {
        eprintln!("namepath contested: par2 unavailable - skipping");
        return;
    }
    let g = scratch_dir("par2repair-namepath-contested");
    let dir: &Path = &g;
    std::fs::write(dir.join("Contested.bin"), payload(100_000, 0x5eed_0002)).unwrap();
    par2_create(dir, "seta", &["Contested.bin"]);
    std::fs::write(dir.join("Contested.bin"), payload(140_000, 0x5eed_0003)).unwrap();
    par2_create(dir, "setb", &["Contested.bin"]);
    std::fs::remove_file(dir.join("Contested.bin")).unwrap();

    let reports = apply_every_set(dir);
    assert_eq!(reports.len(), 2, "two sets, two reports: {reports:?}");
    let paths: Vec<PathBuf> = reports
        .iter()
        .flat_map(|r| r.per_file.iter().map(|f| f.path.clone()))
        .collect();
    assert_ne!(
        paths[0], paths[1],
        "the two sets took ONE destination, so `contested` is not reaching \
         this entry point and the second set overwrote the first"
    );
    for p in &paths {
        assert!(
            p.is_file(),
            "census entry {p:?} names no file: {:?}",
            names_in(dir)
        );
    }
    // Both payloads survive, and the sizes are what says so: 100,000 is
    // set A's, which the shipped default let set B patch over.
    let mut sizes: Vec<u64> = paths
        .iter()
        .map(|p| std::fs::metadata(p).unwrap().len())
        .collect();
    sizes.sort_unstable();
    assert_eq!(
        sizes,
        vec![100_000, 140_000],
        "one of the two sets' payloads did not survive: dir holds {:?}",
        names_in(dir)
    );
    assert_eq!(names_in(dir).len(), 2, "dir holds {:?}", names_in(dir));
}

/// A set the caller will NEVER apply does not cost a running set's
/// target its declared name - F6, 1 Sep 2026.
///
/// `get::latesets` discovers sets with `PacketScope::Nested`, so the
/// walk reaches a recovery set that came out of an extracted archive and
/// whose packets live only in a subdirectory. That pass then REFUSES
/// such a set in every round: `published_here` wants every packet either
/// directly in the output directory or at a path an ACTIVE set declares,
/// and `named` is derived once from the active sets and never grows. The
/// set can therefore never land a file - but its FileDesc names were
/// still voting in `PacketCatalog::declared_and_contested`, so a root
/// set's `X.bin` was contested against a competitor that would never
/// run, and `dupclaim` retargeted it to `X.bin.dup-<file id>`. The
/// payload is kept, under a name nothing downstream imports, beside
/// whatever damaged original was on disk (a declared name is never
/// swept).
///
/// Both arms run on the SAME fixture, which is what makes either
/// assertion mean anything:
///
/// - narrowed (`Some({root})`, what the late-set pass now passes): the
///   root set's member lands at its DECLARED name.
/// - directory-wide (`None`, which every other entry point keeps and
///   `repair_sets_catalog` relies on): it is still disambiguated. That
///   is today's behaviour, it proves the fixture really does produce a
///   cross-set collision, and it is the guard against the narrowing
///   being widened into a blanket "never contest".
#[test]
fn a_set_the_caller_cannot_apply_does_not_contest_a_declared_name() {
    if !have_par2() {
        eprintln!("namepath phantom: par2 unavailable - skipping");
        return;
    }
    // Root set declares `X.bin`; a set whose packets exist ONLY under
    // `sub/` declares `X.bin` too, for DIFFERENT content, so the two
    // descriptors differ and the name is genuinely contested when both
    // sets are allowed to vote.
    fn fixture(dir: &Path) -> [u8; 16] {
        std::fs::write(dir.join("X.bin"), payload(100_000, 0x5eed_0006)).unwrap();
        par2_create(dir, "setroot", &["X.bin"]);
        let sub = dir.join("sub");
        std::fs::create_dir(&sub).unwrap();
        std::fs::write(sub.join("X.bin"), payload(140_000, 0x5eed_0007)).unwrap();
        par2_create(&sub, "setsub", &["X.bin"]);
        // The subdirectory set's own payload goes: only its PACKETS
        // matter here, and leaving 140,000 bytes of a foreign release
        // about would grade the adoption scan instead of the vote.
        std::fs::remove_file(sub.join("X.bin")).unwrap();
        // Only the parity can produce the root set's member now, so the
        // repair has to build a target and the claim loop has to route
        // it somewhere.
        std::fs::remove_file(dir.join("X.bin")).unwrap();
        // FLAT discovery, so this is the ROOT set and nothing else - the
        // one the late-set pass would attempt.
        let root = disk_set_ids(dir).expect("disk_set_ids");
        assert_eq!(
            root.len(),
            1,
            "the flat walk must see exactly the root set: {root:02x?}"
        );
        root[0]
    }
    fn repaired(
        dir: &Path,
        id: &[u8; 16],
        applicable: Option<&std::collections::HashSet<[u8; 16]>>,
    ) -> nzbkit::par2repair::RepairReport {
        match repair_dir_set_with_donors_scoped(dir, id, &[], PacketScope::Nested, true, applicable)
        {
            Ok(RepairStatus::Repaired(r)) => r,
            other => panic!("the root set did not repair: {other:?}"),
        }
    }

    let g = scratch_dir("par2repair-namepath-phantom");
    let dir: &Path = &g;
    let root = fixture(dir);
    let only_root: std::collections::HashSet<[u8; 16]> = std::iter::once(root).collect();
    let r = repaired(dir, &root, Some(&only_root));
    assert_eq!(r.per_file.len(), 1, "one declared file: {:?}", r.per_file);
    assert_eq!(
        r.per_file[0].path,
        nzbkit::disk::join_out_name(dir, &nzbkit::disk::sanitize_out_name(&r.per_file[0].name)),
        "the root set's member was disambiguated against a set the caller \
         refuses to apply - dir holds {:?}",
        names_in(dir)
    );
    assert!(
        dir.join("X.bin").is_file(),
        "nothing landed at the declared name: dir holds {:?}",
        names_in(dir)
    );

    // Same fixture, no whitelist: the directory-wide reading still
    // contests, so the narrowing above is the whitelist and not a
    // loosening of the collision rule itself.
    let g2 = scratch_dir("par2repair-namepath-phantom-wide");
    let wide: &Path = &g2;
    let root2 = fixture(wide);
    let r2 = repaired(wide, &root2, None);
    assert_eq!(r2.per_file.len(), 1, "one declared file: {:?}", r2.per_file);
    assert_ne!(
        r2.per_file[0].path,
        nzbkit::disk::join_out_name(wide, &nzbkit::disk::sanitize_out_name(&r2.per_file[0].name)),
        "the directory-wide reading did not contest, so this fixture never \
         built a cross-set collision and the narrowed arm above graded \
         nothing - dir holds {:?}",
        names_in(wide)
    );
}
