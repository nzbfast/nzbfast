//! The digest cache through real creates: a set written from a validated
//! record is byte-identical to one written by the chain, on every scan arm,
//! and a stale or torn record, or a cancelled create, leaves the store
//! right. The store and the record format are pinned in
//! `digest_cache_tests.rs`.

use super::*;
use crate::digest_cache::{DigestCache, FLAG_CREATE, MemberDigest};
use md5::Digest;
use std::sync::Arc;

const BS: u64 = 1 << 20;

struct Tmp(PathBuf);

impl Tmp {
    fn new(tag: &str) -> Tmp {
        static SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-digest-{tag}-{}-{}",
            std::process::id(),
            SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }

    fn write(&self, name: &str, data: &[u8]) -> Member {
        let path = self.0.join(name);
        std::fs::write(&path, data).unwrap();
        Member {
            name: name.to_string(),
            path,
        }
    }
}

impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn payload(len: usize, seed: u32) -> Vec<u8> {
    let mut x = seed.wrapping_mul(2654435761).max(1);
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 17;
            x ^= x << 5;
            (x >> 24) as u8
        })
        .collect()
}

fn md5_of(data: &[u8]) -> [u8; 16] {
    md5::Md5::digest(data).into()
}

/// Every file of a set keyed by its name with the base taken off, so two
/// sets written side by side under different bases compare byte for byte
/// (no packet carries the set's own file name).
fn create(dir: &Path, members: &[Member], base: &str) -> Vec<(String, Vec<u8>)> {
    let names = create_into_exact(dir, members, base, Some(BS), 3, CreatePlan::ENGINE)
        .unwrap_or_else(|e| panic!("create {base}: {e}"));
    let mut files: Vec<(String, Vec<u8>)> = names
        .iter()
        .map(|n| {
            (
                n.strip_prefix(base)
                    .expect("named under its base")
                    .to_string(),
                std::fs::read(dir.join(n)).unwrap(),
            )
        })
        .collect();
    files.sort();
    files
}

fn store(t: &Tmp) -> Arc<DigestCache> {
    Arc::new(DigestCache::new(t.0.join("store")).with_floor(0))
}

fn records(cache: &DigestCache) -> Vec<PathBuf> {
    std::fs::read_dir(cache.dir()).map_or_else(
        |_| Vec::new(),
        |rd| {
            rd.flatten()
                .map(|e| e.path())
                .filter(|p| p.extension().is_some_and(|x| x == "pfd"))
                .collect()
        },
    )
}

/// The fused arm for this thread's creates, off again on drop.
struct Fused;

impl Fused {
    fn on() -> Fused {
        scan::FUSE_FOR_TESTS.with(|f| f.set(true));
        Fused
    }
}

impl Drop for Fused {
    fn drop(&mut self) {
        scan::FUSE_FOR_TESTS.with(|f| f.set(false));
    }
}

/// Fresh, enrolling and validated creates of the same members write the
/// same bytes, and the store saw exactly one enrolment and one hit per
/// member. A hit is counted whether the chain was abandoned or finished
/// first and agreed, so this holds on a member small enough to race.
fn round_trip(tag: &str, sizes: &[usize], fused: bool) {
    let t = Tmp::new(tag);
    let members: Vec<Member> = sizes
        .iter()
        .enumerate()
        .map(|(i, &n)| t.write(&format!("m{i}.bin"), &payload(n, i as u32 + 1)))
        .collect();
    let _fused = fused.then(Fused::on);
    let fresh = create(&t.0, &members, "fresh");
    let cache = store(&t);
    let _store = crate::digest_cache::use_on_this_thread(cache.clone());
    let enrolled = create(&t.0, &members, "enrol");
    assert_eq!(
        cache.stats().enrolled,
        sizes.len() as u64,
        "{tag}: {:?}",
        cache.stats()
    );
    assert_eq!(records(&cache).len(), sizes.len());
    let hit = create(&t.0, &members, "hit");
    let st = cache.stats();
    assert_eq!(st.hits, sizes.len() as u64, "{tag}: {st:?}");
    assert_eq!(
        (st.stale, st.corrupt, st.store_errors),
        (0, 0, 0),
        "{tag}: {st:?}"
    );
    assert!(fresh == enrolled, "{tag}: enrolling changed the set");
    assert!(fresh == hit, "{tag}: a validated digest changed the set");
}

#[test]
fn a_repeat_create_of_one_member_takes_its_validated_digest() {
    round_trip("single", &[12 << 20], false);
}

/// The fused arm forced: the member ENROLS on the fused pass (no record
/// yet), and the repeat, finding its record waiting, takes the split scan.
#[test]
fn a_repeat_fused_create_takes_its_validated_digest() {
    round_trip("fused", &[12 << 20], true);
}

/// Three members, one under the parallel scan's 8 MiB floor, so the serial
/// arm takes a record too.
#[test]
fn a_repeat_create_of_several_members_takes_every_validated_digest() {
    round_trip("several", &[9 << 20, 12 << 20, 3 << 20], false);
}

/// A member changed in place since its record: the record is stale, is
/// replaced, and the set is the one a create with no cache writes over the
/// changed bytes.
#[test]
fn a_member_changed_since_its_record_writes_the_fresh_set() {
    let t = Tmp::new("stale");
    let mut data = payload(12 << 20, 21);
    let members = vec![t.write("m.bin", &data)];
    let cache = store(&t);
    {
        let _store = crate::digest_cache::use_on_this_thread(cache.clone());
        create(&t.0, &members, "enrol");
    }
    data[5_000_000] ^= 0x5a;
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut w = std::fs::File::options()
            .write(true)
            .open(&members[0].path)
            .unwrap();
        w.seek(SeekFrom::Start(5_000_000)).unwrap();
        w.write_all(&data[5_000_000..5_000_001]).unwrap();
    }
    let fresh = create(&t.0, &members, "fresh");
    let _store = crate::digest_cache::use_on_this_thread(cache.clone());
    let again = create(&t.0, &members, "again");
    let st = cache.stats();
    assert_eq!((st.stale, st.hits), (1, 0), "{st:?}");
    assert!(fresh == again, "a stale record changed the set");
    let bytes = std::fs::read(&records(&cache)[0]).unwrap();
    assert_eq!(
        &bytes[80..96],
        &md5_of(&data),
        "the record now carries the changed MD5"
    );
}

/// A torn record is a miss: the create is the chain's, the record is
/// written afresh.
#[test]
fn a_torn_record_is_replaced_and_the_set_is_unchanged() {
    let t = Tmp::new("torn");
    let members = vec![t.write("m.bin", &payload(12 << 20, 31))];
    let fresh = create(&t.0, &members, "fresh");
    let cache = store(&t);
    let _store = crate::digest_cache::use_on_this_thread(cache.clone());
    create(&t.0, &members, "enrol");
    let record = records(&cache).pop().expect("enrolled");
    let mut bytes = std::fs::read(&record).unwrap();
    bytes[90] ^= 0x01;
    std::fs::write(&record, &bytes).unwrap();
    let again = create(&t.0, &members, "again");
    let st = cache.stats();
    assert_eq!((st.corrupt, st.hits, st.enrolled), (1, 0, 2), "{st:?}");
    assert!(fresh == again);
}

/// A create that is cancelled writes no record, even for a member whose
/// pass had already resolved.
#[test]
fn a_cancelled_create_records_nothing() {
    let t = Tmp::new("cancel");
    let members = vec![t.write("m.bin", &payload(12 << 20, 41))];
    let cache = store(&t);
    let _store = crate::digest_cache::use_on_this_thread(cache.clone());
    let gate = crate::par2repair::PauseGate::new();
    let trip = gate.clone();
    let control = control::CreateControl::new(
        Some(Arc::new(move |phase: CreatePhase, _: u64, _: u64| {
            if phase == CreatePhase::Write {
                trip.cancel();
            }
        })),
        Some(gate),
    );
    let r = create_into_exact_controlled(
        &t.0,
        &members,
        "cancelled",
        Some(BS),
        3,
        CreatePlan::ENGINE,
        None,
        &control,
    );
    assert!(matches!(r, Err(Par2GenError::Cancelled)), "{r:?}");
    assert!(
        records(&cache).is_empty(),
        "a cancelled create recorded a digest"
    );
    assert_eq!(cache.stats().enrolled, 0);
}

/// Each arm the scan can take stops its chain for a record that has
/// already validated, and its head and block products are the ones the
/// chain-running pass wrote; the resolved MD5 is the content's.
#[test]
fn every_scan_arm_leaves_its_chain_to_a_validated_record() {
    let t = Tmp::new("arms");
    let data = payload(12 << 20, 51);
    let m = t.write("arm.bin", &data);
    let len = data.len() as u64;
    let n_blocks = len.div_ceil(BS) as usize;
    let cache = store(&t);
    let control = control::CreateControl::default();

    let open = || std::fs::File::open(&m.path).unwrap();
    let reference = {
        let f = open();
        let d = MemberDigest::begin(Some(&cache), &f, &m.path, len, FLAG_CREATE);
        let (whole, head, blocks) =
            scan::scan_parallel_positional(&f, &m.path, len, BS, n_blocks, 4, &control, &d)
                .unwrap();
        let whole = whole.expect("an enrolment never stops the chain");
        assert_eq!(whole, md5_of(&data));
        let (_, pending) = d.resolve(Some(whole)).unwrap();
        pending.expect("enrolment").commit();
        (head, blocks)
    };
    let validated = |f: &std::fs::File| {
        let d = MemberDigest::begin(Some(&cache), f, &m.path, len, FLAG_CREATE);
        let t0 = std::time::Instant::now();
        while !d.chain_abandoned() {
            assert!(t0.elapsed().as_secs() < 60, "the record never validated");
            std::thread::sleep(std::time::Duration::from_millis(2));
        }
        d
    };

    let f = open();
    let d = validated(&f);
    let (whole, head, blocks) =
        scan::scan_parallel_positional(&f, &m.path, len, BS, n_blocks, 4, &control, &d).unwrap();
    assert!(whole.is_none(), "positional");
    assert!((head, blocks) == reference, "positional products");
    assert_eq!(d.resolve(whole).unwrap().0, md5_of(&data));

    let mut f = open();
    let d = validated(&f);
    let (whole, head, blocks) = scan::scan_parallel_streamed(
        &mut f,
        &m.path,
        len,
        BS as usize,
        n_blocks,
        1 << 20,
        &control,
        &d,
    )
    .unwrap();
    assert!(whole.is_none(), "streamed");
    assert!((head, blocks) == reference, "streamed products");
    assert_eq!(d.resolve(whole).unwrap().0, md5_of(&data));

    let f = open();
    let d = validated(&f);
    let map = MappedMember::open(&m.path, len).unwrap().unwrap();
    let (whole, head, blocks) = scan::scan_mapped(&map, BS as usize, n_blocks, 4, &control, &d);
    assert!(whole.is_none(), "mapped");
    assert!((head, blocks) == reference, "mapped products");
    assert_eq!(d.resolve(whole).unwrap().0, md5_of(&data));
    assert_eq!(cache.stats().hits, 3);
}

/// The whole-file verify enrols a clean member, then answers the next
/// verify - and `-O`'s MD5 door - from the validated record with no chain;
/// a damaged member never validates and is judged by the full pass.
#[test]
fn a_whole_file_verify_enrols_then_answers_from_the_validated_record() {
    let t = Tmp::new("verify");
    let mut data = payload(12 << 20, 61);
    let members = vec![t.write("m.bin", &data)];
    let names = create_into_exact(&t.0, &members, "set", Some(BS), 3, CreatePlan::ENGINE).unwrap();
    let blobs: Vec<Vec<u8>> = names
        .iter()
        .map(|n| std::fs::read(t.0.join(n)).unwrap())
        .collect();
    let refs: Vec<&[u8]> = blobs.iter().map(|b| b.as_slice()).collect();
    let set = crate::par2::Par2Set::parse(&refs).unwrap();
    let file = &set.files[0];
    let path = &members[0].path;
    let cache = store(&t);
    let _store = crate::digest_cache::use_on_this_thread(cache.clone());

    let first = crate::par2repair::verify_pass1_tiered(path, file, BS as usize, 4, false).unwrap();
    assert!(first.clean && first.intact);
    assert_eq!(cache.stats().enrolled, 1, "{:?}", cache.stats());

    let second = crate::par2repair::verify_pass1_tiered(path, file, BS as usize, 4, false).unwrap();
    assert!(second.clean && second.intact && second.resume.is_none());
    assert_eq!(cache.stats().hits, 1, "{:?}", cache.stats());
    assert!(crate::par2::verify_file_md5_path(path, file).unwrap());
    assert_eq!(cache.stats().hits, 2, "{:?}", cache.stats());

    data[7_000_000] ^= 0x33;
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut w = std::fs::File::options().write(true).open(path).unwrap();
        w.seek(SeekFrom::Start(7_000_000)).unwrap();
        w.write_all(&data[7_000_000..7_000_001]).unwrap();
    }
    let damaged =
        crate::par2repair::verify_pass1_tiered(path, file, BS as usize, 4, false).unwrap();
    assert!(
        !damaged.clean && !damaged.intact,
        "a damaged member must not verify from its record"
    );
    let present = damaged.present.expect("a block map for the damaged member");
    assert_eq!(
        present.iter().filter(|&&b| !b).count(),
        1,
        "exactly the poked block is missing"
    );
    assert!(!crate::par2::verify_file_md5_path(path, file).unwrap());
    assert_eq!(cache.stats().hits, 2, "nothing validated after the damage");
}

/// A same-length in-place write to a member DURING a fused create, past its
/// 16 KiB head and with the old mtime put back, is refused: the fold has
/// already read some of the old bytes, so a set written from it would
/// describe bytes that are no longer the file. The head MD5 cannot see a
/// write past the head, and no digest store is active here, so the source
/// identity check in `FusedScan::finish_all` is the only thing that can.
///
/// This is the Windows A/B for that check. Until 15 Sep 2026 the Windows
/// stamp was the LENGTH alone (`identity` was `#[cfg(unix)]`), and this
/// create returned Ok there; unix always refused on ctime. The refusal text
/// is only ever produced by `finish_all`, so it also pins that the fused
/// arm ran.
#[test]
fn a_same_length_write_during_a_fused_create_is_refused() {
    use std::io::{Seek, SeekFrom, Write};
    use std::sync::atomic::{AtomicBool, Ordering};
    let t = Tmp::new("fused-write");
    let data = payload(12 << 20, 61);
    let member = t.write("m.bin", &data);
    let modified = std::fs::metadata(&member.path)
        .and_then(|m| m.modified())
        .expect("mtime");
    let wrote = Arc::new(AtomicBool::new(false));
    let sink = {
        let wrote = wrote.clone();
        let path = member.path.clone();
        move |phase: control::CreatePhase, done: u64, _total: u64| {
            if phase != control::CreatePhase::Fold
                || done == 0
                || wrote.swap(true, Ordering::SeqCst)
            {
                return;
            }
            std::thread::sleep(std::time::Duration::from_millis(20));
            // No truncate: Windows refuses to shorten a file with a mapped view.
            let mut w = std::fs::File::options()
                .write(true)
                .open(&path)
                .expect("writer");
            w.seek(SeekFrom::Start(1 << 20)).expect("seek");
            w.write_all(&payload(11 << 20, 62)).expect("rewrite");
            w.set_modified(modified).expect("put the mtime back");
        }
    };
    let control = control::CreateControl::new(Some(Arc::new(sink)), None);
    let _fused = Fused::on();
    let got = create_into_exact_controlled(
        &t.0,
        std::slice::from_ref(&member),
        "set",
        Some(BS),
        3,
        CreatePlan::ENGINE,
        None,
        &control,
    );
    assert!(
        wrote.load(Ordering::SeqCst),
        "the write was never injected, so this proves nothing"
    );
    assert_eq!(
        std::fs::metadata(&member.path).unwrap().len(),
        data.len() as u64
    );
    let err = got.expect_err("a create over a member written mid-fold must refuse");
    assert!(
        err.to_string()
            .contains("changed while the PAR2 set was being built"),
        "refused, but not by the fused source check: {err}"
    );
}
