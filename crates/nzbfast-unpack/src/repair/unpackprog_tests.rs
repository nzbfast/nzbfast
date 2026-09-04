//! TODO 205 follow-up: the two ladder routes that reported a volume
//! count and no byte lane.
//!
//! The change that closed #47 took `rarfix::write_archives_to_spending`,
//! which is every RAR volume-set unpack the ladder does, and its own
//! scope note named what it had left: `reextract_dir_outcome`'s PLAIN
//! branch, which feeds the volumes to nzbkit's own `Extractor` instead,
//! and the nested 7z/zip pass over what an outer extraction produced -
//! on both of which the queue row said "unpacking 130 volumes" and then
//! held its last figure for the duration.
//!
//! A child module rather than more of `repair_tests`, which is 2,775 of
//! the size gate's 3,000 lines: same rule as `ladder_tests` beside it.
//!
//! The daemon-payload half - that these counters reach the queue row,
//! on the right row - is `serve::daemon_tests::unpack_progress_tests`.

use super::*;

fn dir_for(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-unpackprog-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

/// A two-volume RAR5 set holding one member split across both. Same
/// shape as `repair_tests::reex_vols` and duplicated rather than shared
/// because these two modules are siblings, not a parent and a child.
fn rar_pair(member: &str, total: &[u8]) -> [Vec<u8>; 2] {
    use nzbkit::rar::fixtures;
    let n = total.len() as u64;
    let half = total.len() / 2;
    [
        fixtures::rar5_volume_n(&[(member, n, &total[..half], false, true)], 0),
        fixtures::rar5_volume_n(&[(member, n, &total[half..], true, false)], 1),
    ]
}

/// A single-volume RAR5 archive holding `member` whole.
fn rar_of(member: &str, body: &[u8]) -> Vec<u8> {
    nzbkit::rar::fixtures::rar5_volume_n(&[(member, body.len() as u64, body, false, false)], 0)
}

/// Arm the ladder over `owner` and hand back the progress entry the
/// queue payload reads, plus the arm itself - which must outlive the
/// extraction, since its Drop takes the hub entry down with it.
fn armed(
    volumes: u64,
) -> (
    std::sync::Arc<crate::streamhub::StreamHub>,
    crate::unpackprog::UnpackArm,
    std::sync::Arc<crate::unpackprog::UnpackProgress>,
) {
    let hub = std::sync::Arc::new(crate::streamhub::StreamHub::default());
    let arm = crate::unpackprog::arm(Some(&hub.unpack), "nzo-205", volumes);
    let p = hub
        .unpack
        .lock_ok()
        .get("nzo-205")
        .cloned()
        .expect("the arm registers the job");
    (hub, arm, p)
}

/// The PLAIN feed branch of `reextract_dir_outcome` - a repaired or
/// resumed named set with no eating armed and readable headers, which
/// is the ordinary shape of a post-PAR2 re-extract.
///
/// It never touches `write_archives_to_spending`: it hands the volumes
/// to nzbkit's own `Extractor` a chunk at a time, so it had no `written`
/// accumulator to publish and no header total to declare. It reports
/// from the extractor's OWN output writers now - the very ones the
/// in-stream lane reads - which is why the total is DISCOVERED here
/// rather than known before the first byte moves.
#[test]
fn the_plain_feed_route_publishes_bytes_and_not_only_a_volume_count() {
    let total: Vec<u8> = (0..400_000u32)
        .map(|i| (i as u8).wrapping_mul(29).wrapping_add(11))
        .collect();
    let vols = rar_pair("film.mkv", &total);
    let dir = dir_for("plain");
    // `.rar`/`.r00`, so the collector takes them by NAME and the native
    // whole-set shortcut above it does not fire (nothing is header
    // encrypted and no eating is armed under test).
    std::fs::write(dir.join("x.rar"), &vols[0]).unwrap();
    std::fs::write(dir.join("x.r00"), &vols[1]).unwrap();

    let (hub, arm, p) = armed(2);
    assert_eq!(
        (p.volumes(), p.total(), p.done()),
        (2, 0, 0),
        "the count is knowable before anything runs; the bytes are not"
    );

    assert!(reextract_dir(&dir, None).unwrap(), "the set must extract");
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), total);
    // One member split across two volumes: the lane must show the file,
    // not the file times the volume count.
    assert_eq!(p.total(), 400_000, "the route published no total");
    assert_eq!(p.done(), 400_000, "the route published no bytes");

    drop(arm);
    assert!(hub.unpack.lock_ok().is_empty());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The nested pass, on the shape it exists for: an outer RAR set whose
/// payload is one more container. The zip arm's bytes are a SECOND set
/// on the same ladder, so this also pins the accumulation - the outer
/// unpack's figures must be banked, not restarted at zero and not
/// dropped.
#[test]
fn a_nested_zip_pass_carries_the_lane_past_the_outer_unpack() {
    use nzbkit::zip::fixtures::{Spec, zip_of};
    let payload: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(7).wrapping_add(3))
        .collect();
    let inner = zip_of(&[Spec::stored("film.mkv", &payload)]);
    let dir = dir_for("nested-zip");
    std::fs::write(dir.join("x.rar"), rar_of("inner.zip", &inner)).unwrap();

    let (_hub, _arm, p) = armed(1);
    // Depth 1 is the daemon's post-download pass, the call that reaches
    // the nested arms at all.
    assert!(
        crate::unpack::extract_nested(&dir, None, 1)
            .unwrap()
            .produced()
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), payload);

    assert_eq!(
        p.total(),
        inner.len() as u64 + payload.len() as u64,
        "the nested zip's bytes never joined the outer set's"
    );
    assert_eq!(p.done(), p.total(), "every byte reported by the end");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// The same for the 7z arm, which is the commoner nested container of
/// the two in the field and reports through its own entry point.
#[test]
fn a_nested_7z_pass_carries_the_lane_too() {
    let payload: Vec<u8> = (0..250_000u32)
        .map(|i| (i as u8).wrapping_mul(19).wrapping_add(4))
        .collect();
    let container = {
        let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
        w.push_archive_entry(
            sevenz_rust2::ArchiveEntry::new_file("film.mkv"),
            Some(payload.as_slice()),
        )
        .unwrap();
        w.finish().unwrap().into_inner()
    };
    let dir = dir_for("nested-7z");
    std::fs::write(dir.join("x.rar"), rar_of("inner.7z", &container)).unwrap();

    let (_hub, _arm, p) = armed(1);
    assert!(
        crate::unpack::extract_nested(&dir, None, 1)
            .unwrap()
            .produced()
    );
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), payload);

    assert_eq!(
        p.total(),
        container.len() as u64 + payload.len() as u64,
        "the nested 7z's bytes never joined the outer set's"
    );
    assert_eq!(p.done(), p.total());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// A container that takes several password candidates is ONE set, and
/// only the attempt that opened it may reach the row. Every candidate
/// folded as though it were a fresh set would leave the lane parked at
/// a fraction of a total the extraction can never reach - the reason
/// `unpackprog::attempt` is separate from `watch`.
#[test]
fn a_password_shortlist_publishes_one_total_not_one_per_candidate() {
    use nzbkit::zip::fixtures::{Encrypt, Spec, zip_of};
    let payload: Vec<u8> = (0..90_000u32)
        .map(|i| (i as u8).wrapping_mul(31).wrapping_add(17))
        .collect();
    let dir = dir_for("zip-shortlist");
    let mut spec = Spec::stored("film.mkv", &payload);
    spec.encrypt = Some(Encrypt::ZipCrypto {
        password: "correct-horse",
    });
    std::fs::write(dir.join("payload.zip"), zip_of(&[spec])).unwrap();
    // A sibling text file the level above would have extracted: the
    // harvester reads it, so the arm walks a shortlist rather than a
    // single value.
    std::fs::write(
        dir.join("password.txt"),
        "wrong-one\nalso-wrong\ncorrect-horse\n",
    )
    .unwrap();

    let (_hub, _arm, p) = armed(0);
    assert!(crate::rarfix::extract_zip(
        &dir,
        &nzbkit::zip::scan(&dir),
        None
    ));
    assert_eq!(std::fs::read(dir.join("film.mkv")).unwrap(), payload);
    assert_eq!(
        p.total(),
        payload.len() as u64,
        "each refused candidate was banked as a set of its own"
    );
    assert_eq!(p.done(), p.total());
    std::fs::remove_dir_all(&dir).unwrap();
}

/// Write `.rev` recovery volumes covering `data`, in the shape
/// `rarfix::try_rev_reconstruct` reads: it matches volumes to REV slots
/// by size and CRC32 and never parses them, so the real RAR volumes
/// below go in as opaque blobs.
///
/// A local copy of `rarfix_rev_recovery_tests::build_named_set`'s
/// parity half rather than a share, on this tree's sibling-module rule
/// - and because that one synthesises its own data volumes, where this
/// has to cover a set that must really extract.
fn rev_volumes_for(dir: &Path, release: &str, data: &[Vec<u8>]) {
    use rars::recovery::rar5::encode_parity_shards;
    let mut shard_len = data.iter().map(Vec::len).max().unwrap_or(0);
    shard_len += shard_len & 1;
    let padded: Vec<Vec<u8>> = data
        .iter()
        .map(|v| {
            let mut shard = vec![0u8; shard_len];
            shard[..v.len()].copy_from_slice(v);
            shard
        })
        .collect();
    let refs: Vec<&[u8]> = padded.iter().map(Vec::as_slice).collect();
    let parity = encode_parity_shards(&refs, 1).unwrap();
    let payload = &parity[0];
    let mut body = vec![1u8];
    body.extend_from_slice(&(data.len() as u16).to_le_bytes());
    body.extend_from_slice(&1u16.to_le_bytes());
    body.extend_from_slice(&(data.len() as u16).to_le_bytes());
    body.extend_from_slice(&crc32fast::hash(payload).to_le_bytes());
    for v in data {
        body.extend_from_slice(&(v.len() as u64).to_le_bytes());
        body.extend_from_slice(&crc32fast::hash(v).to_le_bytes());
    }
    let mut rev = Vec::new();
    rev.extend_from_slice(b"Rar!\x1aRev");
    rev.extend_from_slice(&[0u8; 4]);
    rev.extend_from_slice(&(body.len() as u32).to_le_bytes());
    rev.extend_from_slice(&body);
    let header_crc = crc32fast::hash(&rev[12..16 + body.len()]);
    rev[8..12].copy_from_slice(&header_crc.to_le_bytes());
    rev.extend_from_slice(payload);
    std::fs::write(dir.join(format!("{release}.part01.rev")), &rev).unwrap();
}

/// A RETRY of one set must not be banked as a second set.
///
/// `unpack::unpack_named_rar` has three rungs and every one of them is
/// another go at the SAME directory: the first extraction, the same
/// extraction again once `.rev` reconstruction has rebuilt a missing
/// volume, and the recovery-record repair under those. Each re-enters
/// `try_unrar_outcome`, whose group loop banks a set per group - so
/// before [`crate::unpackprog::mark`] the second rung added a whole
/// extra copy of this set's header total, and a set that needed its
/// `.rev` volumes reported twice the bytes it can ever produce with the
/// lane under it parked at half.
///
/// The set really extracts and really needs the rung, so this is the
/// defect end to end and not a stub of it.
#[test]
fn a_retried_rar_set_reports_its_own_total_and_not_two_of_them() {
    let total: Vec<u8> = (0..300_000u32)
        .map(|i| (i as u8).wrapping_mul(13).wrapping_add(5))
        .collect();
    let vols = rar_pair("film.mkv", &total);
    let dir = dir_for("rar-retry");
    let data = vec![vols[0].clone(), vols[1].clone()];
    std::fs::write(dir.join("set.part01.rar"), &data[0]).unwrap();
    std::fs::write(dir.join("set.part02.rar"), &data[1]).unwrap();
    rev_volumes_for(&dir, "set", &data);
    // The volume the first rung will fail for want of, and the second
    // will rebuild from the `.rev` beside it.
    std::fs::remove_file(dir.join("set.part02.rar")).unwrap();

    let (_hub, _arm, p) = armed(2);
    // One LEVEL, not the nested walk: the arm keeps the volumes it did
    // not prove spent, so a second level extracts the same member again
    // as a legitimately new set - which is a true accumulation and would
    // hide the one this test is about. The level's own verdict is
    // `Failed` either way, on the synthetic `.rev` beside the set (no
    // arm owns it, so the pass reports "unsupported archive signature"),
    // and that judgement is not what is under test here: the payload and
    // the lane are.
    crate::unpack::extract_one_level(&dir, None, 1).unwrap();
    assert_eq!(
        std::fs::read(dir.join("film.mkv")).unwrap(),
        total,
        "the set must extract once its missing volume is rebuilt"
    );
    assert_eq!(
        p.total(),
        total.len() as u64,
        "the failed first rung was banked as a set of its own"
    );
    assert_eq!(p.done(), p.total(), "the lane must reach its own total");
    std::fs::remove_dir_all(&dir).unwrap();
}
