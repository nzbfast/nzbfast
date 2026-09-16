//! The store, the record format and a member pass, on small real files
//! with the floor at zero. The create and verify paths that consume a pass
//! are pinned beside them (`par2gen/digest_cache_tests.rs`,
//! `par2repair`'s unit tests).

use super::*;
use md5::Digest;

/// A scratch directory that goes when the test does, pass or fail.
struct Scratch(PathBuf);

impl Scratch {
    fn new(tag: &str) -> Scratch {
        static SEQ: AtomicU64 = AtomicU64::new(0);
        let dir = std::env::temp_dir().join(format!(
            "nzbkit-digest-cache-{}-{}-{tag}",
            std::process::id(),
            SEQ.fetch_add(1, Ordering::Relaxed)
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).expect("scratch dir");
        Scratch(dir)
    }
}

impl Drop for Scratch {
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

fn store(s: &Scratch) -> Arc<DigestCache> {
    Arc::new(DigestCache::new(s.0.join("store")).with_floor(0))
}

fn record_count(cache: &DigestCache) -> usize {
    std::fs::read_dir(cache.dir()).map_or(0, |rd| {
        rd.flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".pfd"))
            .count()
    })
}

/// Enrol `path` (whose content is `data`) through a real pass, as a create
/// would: begin, resolve with the chain's MD5, commit.
fn enrol(cache: &Arc<DigestCache>, path: &Path, data: &[u8]) {
    let f = File::open(path).expect("open member");
    let pass = MemberDigest::begin(Some(cache), &f, path, data.len() as u64, FLAG_CREATE);
    let (md5, pending) = pass.resolve(Some(md5_of(data))).expect("enrol resolves");
    assert_eq!(md5, md5_of(data));
    pending.expect("an enrolment owes a write").commit();
}

fn wait_abandoned(pass: &MemberDigest) -> bool {
    let t0 = std::time::Instant::now();
    while t0.elapsed() < std::time::Duration::from_secs(60) {
        if pass.chain_abandoned() {
            return true;
        }
        std::thread::sleep(std::time::Duration::from_millis(2));
    }
    false
}

fn sample_record() -> Record {
    Record {
        flags: FLAG_CREATE,
        length: 123_456_789,
        mtime: 1_757_000_000_123_456_789,
        ctime: -7,
        enrolled_unix_s: 1_757_000_000,
        blake3: [0xa5; 32],
        md5: [0x3c; 16],
    }
}

/// Every byte of a record is covered: one flipped bit anywhere, a short
/// read, another format version or another magic is not a record.
#[test]
fn a_record_round_trips_and_every_corruption_is_refused() {
    let r = sample_record();
    let bytes = r.encode();
    assert_eq!(Record::decode(&bytes), Some(r.clone()));
    for i in 0..RECORD_LEN {
        let mut bad = bytes;
        bad[i] ^= 0x01;
        assert_eq!(
            Record::decode(&bad),
            None,
            "a flipped bit at byte {i} must not decode"
        );
    }
    assert_eq!(Record::decode(&bytes[..RECORD_LEN - 1]), None);
    // A consistent record of ANOTHER version or magic: the checksum is
    // right, so only the version and magic checks can refuse these.
    for at in [8usize, 0] {
        let mut other = bytes;
        other[at] ^= 0x40;
        let sum = blake3::hash(&other[..CHECKED_LEN]);
        other[CHECKED_LEN..].copy_from_slice(sum.as_bytes());
        assert_eq!(Record::decode(&other), None, "field at {at} changed");
    }
}

/// Writes land by rename (no temp left behind), the prune keeps the most
/// recently used, and `clear` empties the store.
#[test]
fn the_store_writes_by_rename_and_prunes_the_least_recently_used() {
    let s = Scratch::new("prune");
    let cache = store(&s);
    let base = std::time::SystemTime::now() - std::time::Duration::from_secs(1000);
    for i in 0..5u64 {
        let id = Identity {
            volume: 1,
            index: i,
            length: 10,
            mtime: 0,
            ctime: 0,
        };
        cache.write(&id, &sample_record()).expect("write");
        let f = File::options()
            .write(true)
            .open(cache.record_path(&id))
            .expect("record");
        f.set_modified(base + std::time::Duration::from_secs(i * 10))
            .expect("stamp");
    }
    assert_eq!(record_count(&cache), 5);
    cache.prune_to(3);
    let mut kept: Vec<String> = std::fs::read_dir(cache.dir())
        .expect("dir")
        .flatten()
        .map(|e| e.file_name().to_string_lossy().into_owned())
        .collect();
    kept.sort();
    let want: Vec<String> = (2..5u64)
        .map(|i| format!("{:016x}-{:016x}.pfd", 1, i))
        .collect();
    assert_eq!(
        kept, want,
        "the three most recently used survive, and no temp file"
    );
    assert_eq!(cache.clear().expect("clear"), 3);
    assert_eq!(record_count(&cache), 0);
}

/// The whole loop: an enrolment records both digests of the content, and
/// the next pass over the unchanged file validates and hands back the MD5
/// with no chain behind it.
#[test]
fn an_enrolled_file_is_a_hit_with_no_chain() {
    let s = Scratch::new("hit");
    let cache = store(&s);
    let data = payload(3 << 20, 1);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");

    enrol(&cache, &path, &data);
    assert_eq!(cache.stats().enrolled, 1);
    let f = File::open(&path).expect("open");
    let id = Identity::of(&f).expect("identity");
    let Lookup::Found(record) = cache.load(&id) else {
        panic!("the enrolment wrote no record");
    };
    assert_eq!(record.md5, md5_of(&data));
    assert_eq!(&record.blake3, blake3::hash(&data).as_bytes());
    assert_eq!(record.length, data.len() as u64);

    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);
    assert!(
        wait_abandoned(&pass),
        "a matching record releases the chain"
    );
    let (md5, pending) = pass.resolve(None).expect("a hit resolves with no chain");
    assert_eq!(md5, md5_of(&data));
    pending.expect("a hit refreshes its record").commit();
    let st = cache.stats();
    assert_eq!((st.hits, st.stale, st.corrupt), (1, 0, 0));
}

/// One byte changed in place, same length: the record no longer validates,
/// the chain is never released, and the record is replaced from this pass.
#[test]
fn a_changed_byte_of_the_same_length_is_stale_and_re_enrolled() {
    let s = Scratch::new("stale");
    let cache = store(&s);
    let mut data = payload(2 << 20, 2);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    enrol(&cache, &path, &data);

    data[1_000_000] ^= 0xff;
    {
        use std::io::{Seek, SeekFrom};
        let mut w = File::options().write(true).open(&path).expect("reopen");
        w.seek(SeekFrom::Start(1_000_000)).expect("seek");
        w.write_all(&data[1_000_000..1_000_001]).expect("poke");
    }
    let f = File::open(&path).expect("open");
    let mut pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_VERIFY);
    assert_eq!(
        pass.validated_md5(),
        None,
        "stale content must not validate"
    );
    assert!(!pass.chain_abandoned());
    let (md5, pending) = pass.resolve(Some(md5_of(&data))).expect("stale resolves");
    assert_eq!(md5, md5_of(&data));
    pending.expect("a stale record is replaced").commit();
    assert_eq!(cache.stats().stale, 1);
    let Lookup::Found(record) = cache.load(&Identity::of(&f).expect("identity")) else {
        panic!("no replacement record");
    };
    assert_eq!(record.md5, md5_of(&data));
    assert_eq!(&record.blake3, blake3::hash(&data).as_bytes());
    assert_eq!(record.flags, FLAG_VERIFY);
}

/// A torn record is a miss: deleted on sight, the member enrolled afresh.
#[test]
fn a_corrupt_record_is_a_miss_and_is_replaced() {
    let s = Scratch::new("corrupt");
    let cache = store(&s);
    let data = payload(1 << 20, 3);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    enrol(&cache, &path, &data);

    let f = File::open(&path).expect("open");
    let id = Identity::of(&f).expect("identity");
    let mut bytes = std::fs::read(cache.record_path(&id)).expect("record");
    bytes[85] ^= 0x10;
    std::fs::write(cache.record_path(&id), &bytes).expect("tear");

    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);
    assert!(
        !cache.record_path(&id).exists(),
        "a corrupt record is deleted on sight"
    );
    let (_, pending) = pass.resolve(Some(md5_of(&data))).expect("resolve");
    pending.expect("re-enrolled").commit();
    let st = cache.stats();
    assert_eq!((st.corrupt, st.hits), (1, 0));
    assert!(matches!(cache.load(&id), Lookup::Found(r) if r.md5 == md5_of(&data)));
}

/// A record whose content validates but whose MD5 disagrees with a chain
/// that also ran is not trusted: the member is refused as changed and the
/// record goes. (Only a record this store did not write honestly can say
/// that, so the test writes one by hand.)
#[test]
fn a_validated_record_that_disagrees_with_the_chain_is_refused() {
    let s = Scratch::new("lie");
    let cache = store(&s);
    let data = payload(1 << 20, 4);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    let f = File::open(&path).expect("open");
    let id = Identity::of(&f).expect("identity");
    let mut lie = sample_record();
    lie.length = data.len() as u64;
    lie.blake3 = *blake3::hash(&data).as_bytes();
    lie.md5 = [0u8; 16];
    cache.write(&id, &lie).expect("write");

    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);
    assert!(wait_abandoned(&pass));
    assert!(pass.resolve(Some(md5_of(&data))).is_err());
    assert!(
        !cache.record_path(&id).exists(),
        "the disagreeing record is removed"
    );
}

/// A record for another length is not validated at all: a miss, and the
/// member is enrolled over it.
#[test]
fn a_record_for_another_length_is_a_miss() {
    let s = Scratch::new("length");
    let cache = store(&s);
    let data = payload(1 << 20, 5);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    let f = File::open(&path).expect("open");
    let id = Identity::of(&f).expect("identity");
    let mut other = sample_record();
    other.length = data.len() as u64 + 1;
    other.blake3 = *blake3::hash(&data).as_bytes();
    cache.write(&id, &other).expect("write");

    let mut pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);
    assert_eq!(pass.validated_md5(), None, "nothing to validate");
    assert_eq!(cache.stats().misses, 1);
    let (_, pending) = pass.resolve(Some(md5_of(&data))).expect("resolve");
    pending.expect("enrolled over it").commit();
    assert!(matches!(cache.load(&id), Lookup::Found(r) if r.length == data.len() as u64));
}

/// The pair is only recorded when the member still carries the identity it
/// was taken under: replaced by rename during the pass, nothing is written.
#[test]
fn a_member_replaced_during_the_pass_records_nothing() {
    let s = Scratch::new("replaced");
    let cache = store(&s);
    let data = payload(1 << 20, 6);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    let f = File::open(&path).expect("open");
    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);

    let tmp = s.0.join("member.new");
    std::fs::write(&tmp, payload(1 << 20, 7)).expect("replacement");
    std::fs::rename(&tmp, &path).expect("replace");

    let (_, pending) = pass.resolve(Some(md5_of(&data))).expect("resolve");
    pending.expect("owed").commit();
    assert_eq!(cache.stats().enrolled, 0);
    assert_eq!(record_count(&cache), 0);
}

/// The key is only worth anything if an unchanged file answers the same
/// identity on every open. A file system with no stable file index (ReFS
/// and some network shares on Windows promise none) fails here, and in
/// use that is only ever a miss.
#[test]
fn an_unchanged_file_keeps_its_identity_across_a_reopen() {
    let s = Scratch::new("reopen");
    let path = s.0.join("member.bin");
    std::fs::write(&path, payload(1 << 16, 8)).expect("member");
    let first = Identity::of(&File::open(&path).expect("open")).expect("identity");
    let second = Identity::of(&File::open(&path).expect("reopen")).expect("identity");
    assert_eq!(first, second);
    assert_eq!(first.record_name(), second.record_name());
}

/// An in-place write of the same length that puts the old modification
/// time back during the pass: the change time still moves, so nothing is
/// recorded. Windows keyed on the last write time alone until 15 Sep 2026
/// and recorded the chain's MD5 of the old content here.
#[test]
fn a_write_that_puts_the_mtime_back_records_nothing() {
    let s = Scratch::new("mtime-back");
    let cache = store(&s);
    let data = payload(1 << 20, 9);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    let modified = std::fs::metadata(&path)
        .and_then(|m| m.modified())
        .expect("mtime");
    let f = File::open(&path).expect("open");
    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);

    std::thread::sleep(std::time::Duration::from_millis(20));
    {
        // No truncate: Windows refuses to shorten a file with a mapped view.
        let mut w = File::options().write(true).open(&path).expect("writer");
        w.write_all(&payload(1 << 20, 10)).expect("rewrite");
        w.set_modified(modified).expect("put the mtime back");
    }
    assert_eq!(
        std::fs::metadata(&path)
            .and_then(|m| m.modified())
            .expect("mtime"),
        modified
    );

    let (_, pending) = pass.resolve(Some(md5_of(&data))).expect("resolve");
    pending.expect("owed").commit();
    assert_eq!(cache.stats().enrolled, 0);
    assert_eq!(record_count(&cache), 0);
}

/// A store that cannot be read turns the cache off for the member, and the
/// chain's answer stands.
#[test]
fn an_unreadable_store_turns_the_pass_off() {
    let s = Scratch::new("unreadable");
    let not_a_dir = s.0.join("plain-file");
    std::fs::write(&not_a_dir, b"x").expect("file");
    let cache = Arc::new(DigestCache::new(not_a_dir.join("store")).with_floor(0));
    let data = payload(1 << 20, 8);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    let f = File::open(&path).expect("open");
    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);
    assert!(!pass.chain_abandoned());
    let (md5, pending) = pass.resolve(Some(md5_of(&data))).expect("resolve");
    assert_eq!(md5, md5_of(&data));
    assert!(pending.is_none(), "an unreadable store takes no part");
    assert!(cache.stats().store_errors >= 1);
}

/// Under the floor nothing is looked up and no store is created; a pass
/// dropped unresolved stops and joins its helper and writes nothing.
#[test]
fn the_floor_and_a_dropped_pass_leave_the_store_alone() {
    let s = Scratch::new("floor");
    let data = payload(1 << 20, 9);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");
    let f = File::open(&path).expect("open");

    let high = Arc::new(DigestCache::new(s.0.join("high")).with_floor(data.len() as u64 + 1));
    let pass = MemberDigest::begin(Some(&high), &f, &path, data.len() as u64, FLAG_CREATE);
    assert!(pass.0.is_none(), "under the floor");
    assert!(!high.dir().exists());

    let cache = store(&s);
    let pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_CREATE);
    drop(pass);
    assert_eq!(record_count(&cache), 0);
    assert_eq!(cache.stats().enrolled, 0);
}

/// A pass that ends without a `resolve` names its route, so a verify
/// whose member turns out damaged is not silent under
/// `NZBFAST_REPAIR_TIMING` while the enrolled case prints `hit`
/// (research/DESIGN-DIGEST-CACHE-2026-09-15.md section 9b-3, last
/// bullet). Asserted on the returned route rather than on the log line:
/// the timing switch is an environment variable and these tests share
/// one process, so reading the log would pin it for every test after.
#[test]
fn a_pass_that_records_nothing_names_its_route() {
    let s = Scratch::new("unresolved");
    let cache = store(&s);
    let mut data = payload(2 << 20, 11);
    let path = s.0.join("member.bin");
    std::fs::write(&path, &data).expect("member");

    // No record yet: the verify enrols, and a verify that records
    // nothing says the enrolment did not happen.
    let f = File::open(&path).expect("open");
    let mut pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_VERIFY);
    assert_eq!(pass.validated_md5(), None, "nothing to validate yet");
    assert_eq!(
        pass.unresolved("the member is damaged"),
        Some("miss, not enrolled")
    );
    drop(pass);
    assert_eq!(record_count(&cache), 0, "a declined pass writes nothing");

    // Enrolled, then ONE byte rewritten in place at the same length -
    // the same inode, so the record is found and fails to validate.
    enrol(&cache, &path, &data);
    data[1_000_000] ^= 0xff;
    {
        use std::io::{Seek, SeekFrom};
        let mut w = File::options().write(true).open(&path).expect("reopen");
        w.seek(SeekFrom::Start(1_000_000)).expect("seek");
        w.write_all(&data[1_000_000..1_000_001]).expect("poke");
    }
    let f = File::open(&path).expect("open");
    let mut pass = MemberDigest::begin(Some(&cache), &f, &path, data.len() as u64, FLAG_VERIFY);
    assert_eq!(
        pass.validated_md5(),
        None,
        "stale content must not validate"
    );
    assert_eq!(
        pass.unresolved("the member is damaged"),
        Some("stale record, not re-enrolled"),
        "the route a damaged member's verify takes"
    );
    drop(pass);
    assert_eq!(
        record_count(&cache),
        1,
        "the stale record is left as it was"
    );

    // A record that DOES validate, over a member the caller still
    // refuses: the third route, and not a stale one.
    std::fs::write(&path, &data).expect("rewrite whole");
    let f = File::open(&path).expect("open");
    enrol(&cache, &path, &data);
    let f2 = File::open(&path).expect("open");
    let mut pass = MemberDigest::begin(Some(&cache), &f2, &path, data.len() as u64, FLAG_VERIFY);
    assert!(wait_abandoned(&pass), "the record validates");
    assert_eq!(
        pass.unresolved("the caller refused the member"),
        Some("record validated, nothing recorded")
    );
    drop((pass, f));

    // No store at all is no line: `off()` has no route to name.
    assert_eq!(MemberDigest::off().unresolved("anything"), None);
}

/// The default location is per user and never relative.
#[test]
fn the_default_location_is_absolute_and_ends_in_the_parfast_folder() {
    if let Some(dir) = default_dir() {
        assert!(dir.is_absolute());
        assert!(dir.ends_with(Path::new("parfast").join("digests")));
    }
}
