//! Zero-byte placeholders declared by a checksum sidecar - matrix row
//! M4-07 of the wave-4 read, and a product ruling of 30 Aug 2026.
//!
//! A disc tree posts placeholders: `VIDEO_TS/VTS_02_0.VOB` at 0 bytes is
//! ordinary DVD furniture, and an AVCHD or BD-J tree carries several.
//! Nothing goes on the wire for one - a zero-length post is yEnc framing
//! and no payload - so no settled slot can ever carry that name, and the
//! sidecar's entry is the ONLY record that the file was meant to exist.
//!
//! [`super::sfvname`] cannot land it. That tier proves a name by
//! checksumming a settled file, and it filters candidates to `len() > 0`
//! because an empty read has no bytes for a checksum to speak about. The
//! with-set tier that DOES materialize placeholders
//! ([`super::emptydesc`]) needs a PAR2 FileDesc, whose empty MD5 is its
//! proof. On a no-PAR2 post neither runs, so before this module the disc
//! tree simply came out one file short and said nothing about it -
//! measured red 30 Aug 2026 by
//! `an_sfv_zero_crc_entry_materializes_its_empty_placeholder`.
//!
//! BOTH SIDECAR FORMATS, and the second one is an extension of the
//! ruling rather than a restatement of it. M4-07 was ruled on CRC32, and
//! M4-20/M4-27 then taught [`super::sfvname`] to read `.md5` sidecars
//! too - which makes an `.md5` declaring `d41d8cd98f00b204e9800998ecf8427e`
//! for a placeholder the identical defect in the sibling format, newly
//! reachable the day that lane landed. The ruling's REASONING is what
//! generalises: a checksum computed over the empty input is a constant
//! of the hash function, so an entry declaring it is self-proving. That
//! is format-independent, it is literally [`super::emptydesc`]'s own
//! argument (which is MD5-based), and MD5 is the STRONGER of the two
//! claims - so acting on it is safer than the case already ruled on, not
//! a widening of risk. Shipping the CRC arm alone would have left a
//! known asymmetry that this module's own header could not justify.
//!
//! What rescues the case is [`super::emptydesc`]'s argument with a
//! different constant. A CRC32 over the empty input is `00000000`, fixed
//! by construction, so an entry declaring that value is proven against
//! any empty file without reading a byte: CREATING the empty file IS the
//! check the checksum tier would have run. That is a stronger claim than
//! this tier's ordinary one, not a weaker one - the usual objection to a
//! 32-bit checksum is that some other content could collide with it, and
//! there is no other content here to collide.
//!
//! Four rules, all of them the ruling's own bounds:
//!
//! * ONLY the exact empty CRC creates. Every other value is a claim
//!   about bytes this tier does not have; inventing a file for one would
//!   be a guess, which is what
//!   `an_sfv_entry_with_a_nonempty_crc_and_no_match_creates_nothing`
//!   pins.
//! * NEVER touch a file already at the path. `create_new` is the whole
//!   guarantee - this tier may create and may not truncate, replace or
//!   open for writing. Pinned by
//!   `an_sfv_zero_crc_entry_never_truncates_a_file_already_there`.
//! * The path goes through [`nzbkit::disk::sanitize_out_name`] and
//!   [`nzbkit::disk::prepare_out_path`], the same containment every
//!   other publish uses, so a hostile line cannot escape `out_dir`: a
//!   name carrying `..`, an absolute path or a drive prefix is not a
//!   safe relpath, and the fallback flattens it to one component.
//! * Bounded. The sidecar cap is a megabyte and an entry is tens of
//!   bytes, so a crafted sidecar could ask for tens of thousands of
//!   files; [`PLACEHOLDER_CAP`] refuses past a ceiling that no real disc
//!   tree comes near, out loud.
//!
//! STATED LIMIT: this materializes, it does not PAIR. A post that really
//! did ship an empty article keeps that slot under its posted name, the
//! same as any other slot the sidecar could not speak for. Pairing would
//! mean renaming a zero-length file onto the entry on the strength of
//! its length alone, and unlike [`super::emptydesc`] - which has a
//! FileDesc length AND the NZB's posted-bytes belt behind it - there is
//! nothing here to tell an intended placeholder from a slot that
//! finished empty for some other reason.
//!
//! It also takes no [`crate::unpack::PublishedNames`] claim, and that is
//! deliberate: that registry disambiguates SLOT publishes and is keyed
//! by slot index, and a materialized placeholder has no slot behind it.
//! What it would buy - nothing renaming over the new file later - is
//! already had by running LAST, after [`super::sfvname`]'s rename loop.
//! It is protected from the other side too, and independently: the SFV
//! tier's own weak publish asks the FILESYSTEM and declines a target
//! that exists, so neither guarantee routes through the registry.
//!
//! VETOED PER ENTRY, NEVER GATED PER JOB (M4-05, 30 Aug 2026), and this
//! is the bound that is easiest to lose. The hazard is real and is worth
//! stating before the answer: `00000000` is a legal 8-hex CRC field, so
//! a lazy or hostile generator emits it for a file it never checksummed.
//! Let that reach this tier over a name some descriptor declares at
//! gigabytes - a file repair could not rebuild - and it CREATES it at 0
//! bytes, after the repair decision, where nothing downstream
//! contradicts it. An honest "missing entirely" and a red verdict become
//! a green job with a truncated file in it, which is strictly worse than
//! the absence M4-07 exists to fix; the row is explicit that its wrong
//! answer must be an honest miss and never a silent one.
//!
//! This module SHIPPED with that refused by a per-JOB gate - the caller
//! ran the tier only when no recovery set was present - and named the
//! per-entry form as the follow-up. The gate is the coarser instrument
//! and it refuses M4-05's genuine shape along with the hazard: a MIXED
//! post, PAR2 over some files and a checksum sidecar over the rest, with
//! the sidecar-only ones legitimately empty. There the set present is
//! not about the placeholder at all. Measured 30 Aug 2026 on the tree
//! that shipped the gate: such a post completes at rc 0 with the
//! placeholder simply absent and NOTHING in the log about it, which is
//! the silent miss the row forbids.
//!
//! So the caller now hands in `declared_with_bytes` - every name a
//! descriptor in this post declares at a NONZERO length - and each such
//! entry is declined, out loud, with the contradiction named. What that
//! buys over the gate is that it is the question the hazard actually
//! asks. A descriptor declaring the name at length ZERO is not a veto:
//! the two sources then AGREE, and there is nothing to protect. A post
//! with no sets at all yields an empty veto list, so the no-set path
//! this module was written for behaves exactly as it did.
//!
//! See [`super::sfvname::names_declared_with_bytes`] for how the list is
//! built, including why it reads `nonrecovery` beside `files` and why it
//! does not come off `settle::union_set_names` (which is convenient,
//! `pub(super)`, and drops the one field this needs).

use super::sfvname::{Entry, Sum};
use std::path::Path;
use tracing::{info, warn};

/// The CRC32 of the empty input - one of the two checksums a zero-byte
/// file can honestly declare.
const EMPTY_CRC32: u32 = 0;

/// The MD5 of the empty input, `d41d8cd98f00b204e9800998ecf8427e` - the
/// other one, and the value [`super::emptydesc`] proves a zero-length
/// FileDesc against. Spelled again here rather than imported so this
/// module's two constants sit side by side; they are the same fact about
/// two hash functions, and a reader checking one should see both.
const EMPTY_MD5: [u8; 16] = [
    0xd4, 0x1d, 0x8c, 0xd9, 0x8f, 0x00, 0xb2, 0x04, 0xe9, 0x80, 0x09, 0x98, 0xec, 0xf8, 0x42, 0x7e,
];

/// Whether a sidecar entry's checksum is the one its format computes
/// over an empty input - the whole test this tier turns on.
fn is_empty_sum(sum: Sum) -> bool {
    match sum {
        Sum::Crc32(v) => v == EMPTY_CRC32,
        Sum::Md5(v) => v == EMPTY_MD5,
    }
}

/// Ceiling on placeholders materialized from one post's sidecars. A DVD
/// `VIDEO_TS` is tens of files and a BD-J tree low hundreds, so this is
/// an order of magnitude of headroom over any real disc structure while
/// still bounding what a crafted megabyte of sidecar can ask a job to
/// create.
const PLACEHOLDER_CAP: usize = 4096;

/// Materialize the empty file behind every sidecar entry whose CRC is
/// the empty CRC32, at the entry's sanitized path under `out_dir`.
///
/// Runs AFTER the checksum rename loop, so a name that loop published -
/// including the astronomically unlikely case of a real file whose CRC32
/// is `00000000` - is already on disk and takes the never-touch arm
/// rather than being renamed over afterwards.
///
/// Entries are taken RAW, before the caller's duplicate-CRC ambiguity
/// decline, and that is the one place this tier reads its input
/// differently from the rename loop beside it. There, two entries
/// sharing a CRC is a coincidence nobody may guess between. Here it is
/// the ordinary case - a tree with two placeholders in it declares
/// `00000000` twice, correctly - because the value is a constant rather
/// than a fingerprint, and both entries name a file whose content is
/// fully determined.
///
/// A sidecar listing one name twice therefore asks twice and gets one
/// file, and `create_new` is the whole of what makes that true. A
/// by-name dedupe was written first and DELETED: it made the same
/// guarantee, so neither it nor `create_new` could be falsified - break
/// either and the tests stayed green (measured). One guard, driven by
/// `two_placeholders_both_land_and_a_repeat_is_one_file`.
pub(super) fn materialize_empty_sfv_entries(
    entries: &[Entry],
    out_dir: &Path,
    declared_with_bytes: &std::collections::HashSet<String>,
) -> usize {
    let mut made = 0usize;
    let mut asked = 0usize;
    for e in entries {
        if !is_empty_sum(e.sum) {
            continue;
        }
        let real = nzbkit::disk::sanitize_out_name(&e.name);
        // M4-05's veto, and the whole of what makes this tier safe with a
        // set present. Two of the post's own records disagree about
        // whether this file has bytes in it, so nothing here is entitled
        // to settle that - and the direction that costs the user is
        // creating it, because a 0-byte file at the name is a job that
        // reports success. Said out loud: the row is explicit that this
        // tier's wrong answer must be an honest miss and never a silent
        // one, and a decline is a miss.
        if declared_with_bytes.contains(&real.to_lowercase()) {
            warn!(
                target: "verify",
                "a checksum sidecar declares {real} as an empty file, and a PAR2 \
                 descriptor in this post declares it with bytes in it - this post \
                 contradicts itself, so no placeholder was created (a descriptor's \
                 length is the stronger claim, and an absent file is honest where a \
                 truncated one is not)"
            );
            continue;
        }
        // Counted per ENTRY rather than per distinct name, so the cap
        // bounds the syscalls a crafted sidecar can ask for and not
        // merely the files it can leave behind.
        asked += 1;
        if asked > PLACEHOLDER_CAP {
            warn!(
                target: "verify",
                "the sidecars declare more than {PLACEHOLDER_CAP} zero-byte placeholders - \
                 refusing the rest rather than creating them (no disc structure is this \
                 large; this reads as a crafted sidecar)"
            );
            break;
        }
        // Made INSIDE the directory the walk validated, anchored on the
        // output root - the same binding the payload writes take, and
        // the same `CreateNew` mode: a declared placeholder must never
        // truncate a file already at the name. See
        // `nzbkit::disk::open_out_leaf_under`.
        let target = nzbkit::disk::join_out_name(out_dir, &real);
        match nzbkit::disk::open_out_leaf_under(out_dir, &real, nzbkit::disk::LeafOpen::CreateNew) {
            Ok(_) => {
                info!(
                    target: "verify",
                    "✔ {real} - materialized empty, declared by a checksum sidecar as the \
                     checksum of an empty file (which is that entry's own, by construction)"
                );
                made += 1;
            }
            // Already correct - a re-download into the same folder, or a
            // sidecar naming the same placeholder twice under two
            // spellings that sanitize alike. Nothing to do and nothing
            // to complain about.
            Err(e) if e.kind() == std::io::ErrorKind::AlreadyExists => {
                // X6-04's rule (get/emptydesc.rs): `symlink_metadata`,
                // never `metadata` - a symlink at the target pointing at
                // any empty file OUTSIDE the job would otherwise answer
                // `len() == 0` too, and this tier would count it as made
                // with nothing ever written inside the job directory.
                if !std::fs::symlink_metadata(&target).is_ok_and(|m| m.is_file() && m.len() == 0) {
                    warn!(
                        target: "verify",
                        "{real} already exists and is not an empty regular file - left \
                         alone (an empty-checksum entry may create a file, never \
                         replace one or follow a link)"
                    );
                }
            }
            Err(e) => {
                warn!(target: "verify", "could not materialize {real}: {e}");
            }
        }
    }
    made
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The veto list a post with no PAR2 in it hands this tier - which is
    /// every case below but the two that are ABOUT the veto. Spelled once
    /// so a signature change does not read as a behaviour change in six
    /// tests that have nothing to say about descriptors.
    fn no_sets() -> std::collections::HashSet<String> {
        std::collections::HashSet::new()
    }

    /// A veto list naming `n`, the shape `sfvname::names_declared_with_bytes`
    /// builds from a descriptor with bytes in it: sanitized and lowercased.
    fn declared(n: &str) -> std::collections::HashSet<String> {
        std::iter::once(nzbkit::disk::sanitize_out_name(n).to_lowercase()).collect()
    }

    /// A scratch directory that removes itself - the in-crate idiom
    /// (`dupefill_tests`, `resumeout`), because `tempfile` is a
    /// dependency of the integration targets and not of this crate's
    /// own unit tests. The name is per TEST and not merely per process:
    /// these run concurrently in one binary.
    struct TmpDir(std::path::PathBuf);

    impl TmpDir {
        fn new(name: &str) -> TmpDir {
            let d = std::env::temp_dir()
                .join(format!("nzbfast-sfvempty-{name}-{}", std::process::id()));
            let _ = std::fs::remove_dir_all(&d);
            std::fs::create_dir_all(&d).expect("scratch dir");
            TmpDir(d)
        }
        fn path(&self) -> &Path {
            &self.0
        }
    }

    impl Drop for TmpDir {
        fn drop(&mut self) {
            let _ = std::fs::remove_dir_all(&self.0);
        }
    }

    /// Every regular file under `dir`, recursively.
    fn walk(dir: &Path) -> Vec<std::path::PathBuf> {
        let mut v = Vec::new();
        let Ok(rd) = std::fs::read_dir(dir) else {
            return v;
        };
        for e in rd.flatten() {
            let p = e.path();
            if p.is_dir() {
                v.extend(walk(&p));
            } else {
                v.push(p);
            }
        }
        v
    }

    /// An `Entry` in one line, so the fixtures read as data.
    fn crc(name: &str, v: u32) -> Entry {
        Entry {
            name: name.to_string(),
            sum: Sum::Crc32(v),
        }
    }

    fn md5(name: &str, v: [u8; 16]) -> Entry {
        Entry {
            name: name.to_string(),
            sum: Sum::Md5(v),
        }
    }

    /// Only the empty CRC creates, and what it creates is empty. The
    /// non-empty entry beside it is the pin that this tier never invents
    /// a file for a checksum it cannot check.
    #[test]
    fn the_empty_crc_creates_and_other_values_do_not() {
        let dir = TmpDir::new("onlyempty");
        let entries = vec![
            crc("VIDEO_TS/VTS_02_0.VOB", 0),
            crc("Never.Posted.mkv", 0xDEAD_BEEF),
        ];
        assert_eq!(
            materialize_empty_sfv_entries(&entries, dir.path(), &no_sets()),
            1
        );
        let made = dir.path().join("VIDEO_TS").join("VTS_02_0.VOB");
        assert_eq!(std::fs::metadata(&made).unwrap().len(), 0);
        assert!(!dir.path().join("Never.Posted.mkv").exists());
    }

    /// The never-touch rule at the unit level: whatever is already at
    /// the path survives byte-for-byte, and the run reports it created
    /// nothing rather than counting the squatter as a success.
    #[test]
    fn a_file_already_at_the_path_is_never_truncated() {
        let dir = TmpDir::new("keepexisting");
        std::fs::create_dir_all(dir.path().join("VIDEO_TS")).unwrap();
        let at = dir.path().join("VIDEO_TS").join("VTS_02_0.VOB");
        std::fs::write(&at, b"real bytes from a previous run").unwrap();
        let entries = vec![crc("VIDEO_TS/VTS_02_0.VOB", 0)];
        assert_eq!(
            materialize_empty_sfv_entries(&entries, dir.path(), &no_sets()),
            0
        );
        assert_eq!(
            std::fs::read(&at).unwrap(),
            b"real bytes from a previous run"
        );
    }

    /// Two placeholders in one tree is the ordinary case and not
    /// ambiguity - the empty CRC is a constant, not a fingerprint - so
    /// both land where the rename loop's duplicate-CRC rule would
    /// correctly decline both. A name repeated is still one file.
    #[test]
    fn two_placeholders_both_land_and_a_repeat_is_one_file() {
        let dir = TmpDir::new("twoholes");
        let entries = vec![
            crc("VIDEO_TS/VTS_01_0.VOB", 0),
            crc("VIDEO_TS/VTS_02_0.VOB", 0),
            crc("VIDEO_TS/VTS_02_0.VOB", 0),
        ];
        assert_eq!(
            materialize_empty_sfv_entries(&entries, dir.path(), &no_sets()),
            2
        );
    }

    /// A hostile entry cannot write outside `out_dir`: a traversal and
    /// an absolute path are flattened to one component inside it.
    ///
    /// The output directory is deliberately NESTED two levels under the
    /// scratch root, and the assertion walks the ROOT rather than
    /// `out`. Walking `out` is the version that cannot fail: a file
    /// that escaped is by definition not under `out`, so every survivor
    /// is trivially contained and the test passes against a build with
    /// no sanitizer at all - measured, it did. The nesting is what puts
    /// both escape targets back inside a directory this test owns and
    /// can therefore see.
    #[test]
    fn a_traversal_entry_stays_inside_the_output_directory() {
        let root = TmpDir::new("traversal");
        let out = root.path().join("nest").join("out");
        std::fs::create_dir_all(&out).unwrap();
        let entries = vec![
            // Unsanitized these land at <root>/nest/escaped.bin and
            // <root>/escaped2.bin - inside the walked root, outside out.
            crc("../escaped.bin", 0),
            crc("../../escaped2.bin", 0),
            crc("/etc/passwd", 0),
            crc("a/../../b.bin", 0),
        ];
        materialize_empty_sfv_entries(&entries, &out, &no_sets());
        let made = walk(root.path());
        assert!(!made.is_empty(), "the tier created nothing to check");
        for m in &made {
            assert!(
                m.starts_with(&out),
                "{} escaped the output directory",
                m.display()
            );
        }
    }

    /// The cap refuses past its ceiling rather than creating everything
    /// a crafted megabyte of sidecar asks for.
    #[test]
    fn the_placeholder_cap_bounds_a_crafted_sidecar() {
        let dir = TmpDir::new("cap");
        let entries: Vec<Entry> = (0..PLACEHOLDER_CAP + 50)
            .map(|i| crc(&format!("ph{i}.bin"), 0))
            .collect();
        assert_eq!(
            materialize_empty_sfv_entries(&entries, dir.path(), &no_sets()),
            PLACEHOLDER_CAP
        );
    }

    /// The `.md5` arm, which M4-20/M4-27 made reachable: an `.md5`
    /// sidecar declaring the MD5 of the empty input is the same
    /// self-proving claim as `00000000` in an `.sfv`, and a non-empty
    /// digest beside it still creates nothing.
    #[test]
    fn the_empty_md5_creates_too_and_other_digests_do_not() {
        use md5::Digest as _;
        let dir = TmpDir::new("emptymd5");
        let empty: [u8; 16] = md5::Md5::digest(b"").into();
        assert_eq!(empty, EMPTY_MD5, "the empty-MD5 constant has drifted");
        let entries = vec![
            md5("VIDEO_TS/VTS_02_0.VOB", empty),
            md5("Never.Posted.mkv", md5::Md5::digest(b"not empty").into()),
        ];
        assert_eq!(
            materialize_empty_sfv_entries(&entries, dir.path(), &no_sets()),
            1
        );
        let made = dir.path().join("VIDEO_TS").join("VTS_02_0.VOB");
        assert_eq!(std::fs::metadata(&made).unwrap().len(), 0);
        assert!(!dir.path().join("Never.Posted.mkv").exists());
    }

    /// M4-05's veto, from the side that costs the user if it is missing:
    /// a name a descriptor declares WITH BYTES IN IT gets no placeholder,
    /// however honestly the sidecar declares the empty checksum for it.
    ///
    /// This is the hazard the tier's original per-job no-set gate stood
    /// in for, asked as the question it actually is. Deleting the veto
    /// makes this test create the file, which is what says the veto and
    /// not something else is holding it - there is deliberately no second
    /// guard beside it, for `create_new`'s own reason (two guards, either
    /// sufficient, make both unfalsifiable).
    #[test]
    fn a_name_a_descriptor_declares_with_bytes_gets_no_placeholder() {
        let dir = TmpDir::new("vetoed");
        let entries = vec![crc("Real.Feature.mkv", 0), crc("VIDEO_TS/VTS_02_0.VOB", 0)];
        assert_eq!(
            materialize_empty_sfv_entries(&entries, dir.path(), &declared("Real.Feature.mkv")),
            1,
            "the vetoed entry was created, or the un-vetoed one was not"
        );
        assert!(
            !dir.path().join("Real.Feature.mkv").exists(),
            "a sidecar manufactured a 0-byte file over a descriptor that declares it \
             with bytes - the exact defect the veto exists to refuse"
        );
        assert_eq!(
            std::fs::metadata(dir.path().join("VIDEO_TS").join("VTS_02_0.VOB"))
                .unwrap()
                .len(),
            0,
            "the sidecar-only placeholder beside it did not land - the veto is too \
             coarse, which is the per-job gate's own defect restated"
        );
    }

    /// The veto is keyed the way the caller builds it - sanitized and
    /// lowercased - so a descriptor spelling a name differently in case,
    /// or in a form the sanitizer flattens, still vetoes it. Without the
    /// fold this is a veto a hostile or merely sloppy post walks around
    /// by changing one letter's case.
    #[test]
    fn the_veto_matches_across_case_and_sanitization() {
        let dir = TmpDir::new("vetofold");
        let entries = vec![crc("VIDEO_TS/Real.Feature.MKV", 0)];
        assert_eq!(
            materialize_empty_sfv_entries(
                &entries,
                dir.path(),
                &declared("VIDEO_TS/real.feature.mkv")
            ),
            0
        );
        assert!(walk(dir.path()).is_empty());
    }
}
