//! W4-07: two members whose names differ ONLY IN CASE, delivered onto a
//! genuinely CASE-SENSITIVE volume.
//!
//! Publication folds names before it tests for a collision, and whether
//! it folds is not a constant: `unpack::published_names` asks the real
//! output directory with `nzbkit::disk::case_insensitive_dir`. So on the
//! volume this fleet actually runs on - APFS, case-insensitive by
//! default - `Alpha.txt` and `alpha.txt` are ONE name and the
//! disambiguating `{slot:03}-` prefix is correct and necessary. On a
//! case-sensitive volume they are two legal, distinct names, and that
//! same prefix would be a file the user did not ask for under a name the
//! poster never wrote.
//!
//! W4-16 is the collision row on the ordinary volume and is already
//! pinned and confirmed correct. This is the OTHER arm of the same
//! matrix and, until this probe, nobody had run it: the fold is decided
//! by a runtime probe that no test had ever exercised against a
//! filesystem where it answers the other way. A capability decided by a
//! probe nobody has run on the volume it exists for is a capability
//! nobody has measured.
//!
//! ## Why a disk image and not a fixture flag
//!
//! Forcing `fold = false` in a unit test would exercise the branch and
//! prove nothing about the thing that can actually be wrong, which is
//! the PROBE - whether `case_insensitive_dir` gets the right answer on a
//! real case-sensitive filesystem, and whether publication then honours
//! it end to end. `hdiutil` makes one for free, needs no sudo, and is
//! measured on this box: `hdiutil create -fs "Case-sensitive APFS"`,
//! attach, and `Alpha.txt` / `alpha.txt` coexist as two directory
//! entries.
//!
//! macOS only, and it SKIPS rather than fails elsewhere - the same
//! contract `have_par2` already sets in these suites. The sibling arm,
//! W4-08 (NFC/NFD twins on a normalization-SENSITIVE volume), cannot be
//! built here at all: APFS is normalization-insensitive, so the two
//! spellings collide into one entry whatever the case setting. That arm
//! needs an ext4 runner and is recorded as a platform gap rather than
//! faked.
//!
//! A child of [`super`] rather than a sibling of `e2e.rs`: `e2e.rs` sits AT
//! its size-gate baseline with no room for another `mod` line, and this row
//! belongs to that parent's subject anyway.

use super::*;

/// An attached disk image that detaches itself.
///
/// A leaked mount is worse than a failed test: it holds a `/Volumes`
/// entry and a backing file for the life of the box, and the next run
/// picks a fresh name and leaks another. `Drop` runs on the panic path
/// too, which is the whole reason this is a guard rather than two calls
/// around the assertions.
struct CaseVolume {
    mount: PathBuf,
    image: PathBuf,
}

impl Drop for CaseVolume {
    fn drop(&mut self) {
        let _ = Command::new("hdiutil")
            .args(["detach", "-quiet", "-force"])
            .arg(&self.mount)
            .status();
        let _ = std::fs::remove_file(&self.image);
    }
}

/// Create and attach a case-sensitive APFS image, or `None` if this box
/// cannot make one. The volume name carries the pid so two suites on one
/// machine cannot land on the same mount point.
fn attach_case_sensitive(dir: &Path) -> Option<CaseVolume> {
    if !cfg!(target_os = "macos") {
        return None;
    }
    let vol = format!("NZBFASTCS{}", std::process::id());
    let image = dir.join(format!("{vol}.dmg"));
    let ok = Command::new("hdiutil")
        .args([
            "create",
            "-size",
            "50m",
            "-fs",
            "Case-sensitive APFS",
            "-volname",
        ])
        .arg(&vol)
        .arg("-quiet")
        .arg(&image)
        .status();
    if !matches!(ok, Ok(s) if s.success()) {
        return None;
    }
    let mount = PathBuf::from("/Volumes").join(&vol);
    let att = Command::new("hdiutil")
        .args(["attach", "-nobrowse", "-quiet"])
        .arg(&image)
        .status();
    if !matches!(att, Ok(s) if s.success()) || !mount.is_dir() {
        let _ = std::fs::remove_file(&image);
        return None;
    }
    Some(CaseVolume { mount, image })
}

/// W4-07: on a case-sensitive volume both spellings must land under
/// their OWN names, with their own bytes and no disambiguating prefix.
#[tokio::test(flavor = "multi_thread")]
async fn w4_07_case_only_twins_both_land_unprefixed_on_a_case_sensitive_volume() {
    let mut fx = Fixture::new("casevol");
    let Some(vol) = attach_case_sensitive(&fx.dir) else {
        eprintln!("w4_07: no case-sensitive volume available - skipping");
        return;
    };

    // The volume must really be case-sensitive, or every assertion below
    // is vacuous and would pass on an ordinary APFS directory. This is
    // the probe under test, so it is checked directly before it is
    // trusted.
    assert!(
        !nzbkit::disk::case_insensitive_dir(&vol.mount),
        "the image attached but reports case-INsensitive, so this probe \
         would prove nothing"
    );

    let upper = vec![0xA1u8; 40_000];
    let lower = vec![0x5Cu8; 40_000];
    fx.add_file("Alpha.txt", &upper, 40_000);
    fx.add_file("alpha.txt", &lower, 40_000);

    let srv = MockServer::start(fx.articles.clone(), Chaos::default()).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = vol.mount.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();

    let mut names: Vec<String> = std::fs::read_dir(&out)
        .map(|rd| {
            rd.filter_map(|e| e.ok().map(|e| e.file_name().to_string_lossy().into_owned()))
                .collect()
        })
        .unwrap_or_default();
    names.sort();
    eprintln!("w4_07: rc ok={ok}, tree {names:?}");

    let up = std::fs::read(out.join("Alpha.txt")).unwrap_or_default();
    let lo = std::fs::read(out.join("alpha.txt")).unwrap_or_default();
    // Read both BEFORE the guard drops, or the assertions are graded
    // against a detached volume.
    drop(vol);

    assert_eq!(
        up, upper,
        "Alpha.txt did not land with its own bytes on a case-sensitive \
         volume; tree {names:?}\n{log}"
    );
    assert_eq!(
        lo, lower,
        "alpha.txt did not land with its own bytes on a case-sensitive \
         volume; tree {names:?}\n{log}"
    );
    // The disambiguation is correct on APFS and wrong here: two legal
    // names must not cost one of them a prefix the poster never wrote.
    assert!(
        !names
            .iter()
            .any(|n| n.ends_with("-Alpha.txt") || n.ends_with("-alpha.txt")),
        "a disambiguating prefix was applied on a volume where both \
         names are legal; tree {names:?}\n{log}"
    );
    assert!(
        ok,
        "both members landed byte-exact but the job is not green\n{log}"
    );
}

/// The same volume, asked through a SYMLINK - the one shape where the
/// case probe's answer is not merely unmeasured but WRONG.
///
/// [`nzbkit::disk::case_insensitive_dir`] writes its scratch name
/// through a no-follow open, whose refusal of a symlink at the leaf's
/// immediate parent lands on the probed directory itself; the probe then
/// answered nothing and the guess `cfg!(any(target_os = "macos",
/// target_os = "windows"))` stood in for it. On the volume this fleet
/// runs on that guess is right, which is why the unit pin beside
/// `case_insensitive_dir` has to assert the volume was ASKED rather than
/// what it said. Here it is right that it was asked AND what it said:
/// this image is case-SENSITIVE and macOS, so the guess and the truth
/// disagree, and an unresolved probe returns a boolean that is flatly
/// false about the volume underneath it.
///
/// That boolean is the `fold` gate. Scored insensitive on this volume,
/// `Alpha.txt` and `alpha.txt` - two legal entries, the row above - fold
/// to one key, and publication disambiguates or drops one of a pair the
/// poster wrote as two.
///
/// Costs one 50 MB image and no download; the row above pays the same
/// price for the whole delivery.
///
/// `#[cfg(unix)]` because it plants a real symlink and `hdiutil` is
/// macOS-only anyway - on Linux [`attach_case_sensitive`] answers `None`
/// and it skips, exactly as the row above does.
#[cfg(unix)]
#[test]
fn a_case_sensitive_volume_reached_through_a_link_is_still_measured() {
    let dir = std::env::temp_dir().join(format!("nzbfast-cslink-{}", std::process::id()));
    std::fs::remove_dir_all(&dir).ok();
    std::fs::create_dir_all(&dir).unwrap();
    let Some(vol) = attach_case_sensitive(&dir) else {
        eprintln!("cslink: no case-sensitive volume available - skipping");
        std::fs::remove_dir_all(&dir).ok();
        return;
    };

    // Ground truth from the filesystem, not from the probe under test.
    std::fs::write(vol.mount.join("Ground.txt"), b"x").unwrap();
    let truth = std::fs::metadata(vol.mount.join("ground.txt")).is_ok();

    let link = dir.join("link");
    std::os::unix::fs::symlink(&vol.mount, &link).unwrap();

    let direct = nzbkit::disk::case_insensitive_dir(&vol.mount);
    let through = nzbkit::disk::case_insensitive_dir(&link);
    let unborn = nzbkit::disk::case_insensitive_dir(&link.join("out"));
    drop(vol);

    assert_eq!(
        direct, truth,
        "the image attached but the probe disagrees with it directly, so \
         nothing below would prove anything"
    );
    assert!(
        !truth,
        "a case-INsensitive image makes this row vacuous: the platform \
         guess and the truth would agree and an unresolved probe would \
         pass"
    );
    assert_eq!(
        through, truth,
        "reached through a link the volume was never probed, so callers \
         got the macOS guess (case-insensitive) for a case-SENSITIVE \
         volume - the fold gate then merges two names the poster wrote \
         as two"
    );
    assert_eq!(
        unborn, truth,
        "an output directory that does not exist yet under the link must \
         still be measured - the walk stops at the link"
    );

    std::fs::remove_dir_all(&dir).ok();
}
