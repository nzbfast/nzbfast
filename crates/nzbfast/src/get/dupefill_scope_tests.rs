//! TODO 311 over PLAN M31: which SLOTS one recovery set's fill pass may
//! work on.
//!
//! These drive [`super::wanted_files`], which `dupefill_tests.rs` says
//! in its own header it deliberately does not reach - those cases build
//! the `Wanted` list by hand and exercise the wire, the proof and the
//! write below it. So the resolver had no test at all, and the defect
//! these pin lived exactly there.
//!
//! Its own file rather than a block in `dupefill_tests.rs` for the same
//! reason `repair.rs` keeps four test modules beside it: one subject per
//! file, and the numbers only go down.
//!
//! Nothing here needs a network. `wanted_files` reads a report list, an
//! `Extractor` (built disabled, so `slot_path` answers None and the
//! out-dir fallback is what resolves the path), the slots and the
//! verifier - and the verifier is the point, so the sets are activated
//! for real out of in-process PAR2 index bytes and the slots claim their
//! descriptors through `on_data` the way a download's would.

use super::*;
use md5::{Digest, Md5};
use std::sync::atomic::{AtomicBool, AtomicUsize};

// ---- fixtures ----

/// A scratch directory that removes itself. `tempfile` is not a
/// dependency of this crate's unit tests; the in-crate idiom is
/// `std::env::temp_dir()` plus a per-TEST name, and per-test matters -
/// these run concurrently in one binary.
struct TmpDir(std::path::PathBuf);

impl TmpDir {
    fn new(name: &str) -> TmpDir {
        let d = std::env::temp_dir().join(format!(
            "nzbfast-dupefill-scope-{name}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        TmpDir(d)
    }
}

impl Drop for TmpDir {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

fn pseudo(len: usize, seed: u64) -> Vec<u8> {
    let mut v = Vec::with_capacity(len);
    let mut x = seed | 1;
    for _ in 0..len {
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        v.push((x & 0xff) as u8);
    }
    v
}

/// A valid PAR2 packet: magic, length, body MD5, set id, type. Same
/// shape `dupefill_tests` and `par2repair`'s own tests build.
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(nzbkit::par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";

const BS: usize = 4096;

/// Main + FileDesc + IFSC for every member. No recovery slice: this
/// resolver never reads one, and a set with an IFSC table is all it
/// needs to have a block grid at all.
fn par2_index(set_id: [u8; 16], files: &[(&str, &[u8])]) -> Vec<u8> {
    let fid = |i: usize| {
        let mut f = [0u8; 16];
        f[0] = i as u8 + 1;
        // The set id goes in too: two sets naming the SAME file must not
        // hand out the same file_id, or the parser cannot tell their
        // descriptors apart.
        f[1] = set_id[0];
        f
    };
    let mut main = Vec::new();
    main.extend_from_slice(&(BS as u64).to_le_bytes());
    main.extend_from_slice(&(files.len() as u32).to_le_bytes());
    for i in 0..files.len() {
        main.extend_from_slice(&fid(i));
    }
    let mut out = pkt(set_id, TYPE_MAIN, &main);
    for (i, (name, data)) in files.iter().enumerate() {
        let mut desc = Vec::new();
        desc.extend_from_slice(&fid(i));
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(data)));
        let head = &data[..data.len().min(16384)];
        desc.extend_from_slice(&<[u8; 16]>::from(Md5::digest(head)));
        desc.extend_from_slice(&(data.len() as u64).to_le_bytes());
        // FileDesc names are zero-padded to a 4-byte boundary. Spelled
        // with `next_multiple_of` rather than the `% 4 != 0` push loop
        // the older fixtures use: clippy's `manual_is_multiple_of`
        // refuses that shape here, and this says the same thing.
        let mut nb = name.as_bytes().to_vec();
        nb.resize(nb.len().next_multiple_of(4), 0);
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, TYPE_FILEDESC, &desc));
        let mut body = fid(i).to_vec();
        for chunk in data.chunks(BS) {
            let mut padded = chunk.to_vec();
            padded.resize(BS, 0);
            body.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
            body.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        out.extend(pkt(set_id, TYPE_IFSC, &body));
    }
    out
}

fn slot(hint: &str, total: usize) -> Arc<crate::unpack::FileSlot> {
    Arc::new(crate::unpack::FileSlot {
        hint: hint.into(),
        hint_is_posted_name: true,
        name_choice: std::sync::atomic::AtomicU8::new(crate::unpack::NAME_UNDECIDED),
        is_par2_main: false,
        sample_skipped: false,
        par2_sniffed: AtomicBool::new(false),
        total_segments: total,
        remaining: AtomicUsize::new(0),
        missing: AtomicUsize::new(0),
        errors: AtomicUsize::new(0),
        deferred: AtomicUsize::new(0),
        abandoned: AtomicUsize::new(0),
        capture: std::sync::Mutex::new(None),
    })
}

fn report(name: &str, bad: Vec<usize>, length: u64) -> nzbkit::live::SlotReport {
    nzbkit::live::SlotReport {
        par2_name: Some(name.to_string()),
        total_blocks: (length as usize).div_ceil(BS),
        bad_blocks: bad,
        live_blocks: 0,
        readback_blocks: 0,
        length,
    }
}

/// Two one-file recovery sets naming the SAME file, each claimed by its
/// own slot - the per-file-set post's everyday shape once a poster runs
/// par2create twice over one directory, or reposts one track.
///
/// The slots' HINTS differ (`one.bin`, `two.bin`) so each resolves to
/// its own file on disk; their yEnc names are both `shared.bin`, which
/// is what claims a descriptor. `Active`'s flat file index runs set 0's
/// files then set 1's and the exact-name tier takes the first UNCLAIMED
/// candidate in that order, so slot 0 claims set 0's descriptor and slot
/// 1 claims set 1's.
struct Rig {
    _dir: TmpDir,
    out: std::path::PathBuf,
    sets: Vec<Arc<nzbkit::par2::Par2Set>>,
    verifier: Arc<nzbkit::live::LiveVerifier>,
    extractor: Arc<nzbkit::extract::Extractor>,
    slots: Vec<Arc<crate::unpack::FileSlot>>,
    payload: Vec<u8>,
}

impl Rig {
    /// `names` is one yEnc name per slot; every set is one file.
    fn new(scratch: &str, set_files: &[&str], claim_as: &[&str]) -> Rig {
        let dir = TmpDir::new(scratch);
        let out = dir.0.clone();
        let payload = pseudo(4 * BS, 909);
        let indexes: Vec<Vec<u8>> = set_files
            .iter()
            .enumerate()
            .map(|(i, name)| par2_index([i as u8 + 1; 16], &[(name, payload.as_slice())]))
            .collect();
        let verifier = Arc::new(nzbkit::live::LiveVerifier::with_partials_cap(
            claim_as.len(),
            1 << 20,
        ));
        let refs: Vec<&[u8]> = indexes.iter().map(|v| v.as_slice()).collect();
        let sets = verifier.activate(&refs).expect("both indexes parse");
        assert_eq!(
            sets.len(),
            set_files.len(),
            "the fixture meant to adopt one set per index"
        );
        let slots: Vec<Arc<crate::unpack::FileSlot>> = (0..claim_as.len())
            .map(|i| slot(&format!("slot{i}.bin"), 4))
            .collect();
        for (i, name) in claim_as.iter().enumerate() {
            // One block of real bytes at offset 0 is all it takes to
            // give the slot a yEnc name and run the matcher.
            std::fs::write(out.join(format!("slot{i}.bin")), &payload).expect("slot file");
            verifier.on_data(i, name, payload.len() as u64, 0, &payload[..BS]);
            assert!(
                verifier.slot_in_set(i),
                "slot {i} never claimed a descriptor, so this fixture pins nothing"
            );
        }
        Rig {
            extractor: Arc::new(nzbkit::extract::Extractor::new(&out, claim_as.len(), false)),
            _dir: dir,
            out,
            sets,
            verifier,
            slots,
            payload,
        }
    }

    /// The slot indexes `wanted_files` hands back for one set.
    fn wanted(&self, si: usize, reports: &[(usize, nzbkit::live::SlotReport)]) -> Vec<usize> {
        wanted_files(
            &self.sets[si],
            si,
            &self.verifier,
            reports,
            &self.extractor,
            &self.slots,
            &self.out,
        )
        .into_iter()
        .map(|w| w.sidx)
        .collect()
    }

    /// The set member's declared length, which is what a real
    /// `SlotReport` carries. Deliberately not spelled `len` - a `len`
    /// with no `is_empty` beside it is a clippy argument nobody needs
    /// to have about a test fixture.
    fn payload_len(&self) -> u64 {
        self.payload.len() as u64
    }
}

/// THE DEFECT. Only the slot set 1 claimed took damage, and set 0's own
/// pass is asked first - which is the order settle's per-set loop runs
/// in.
///
/// Before the set guard, set 0's pass resolved that report's
/// `par2_name` inside its OWN files (both sets name `shared.bin`), came
/// back with `Wanted { sidx: 1, file: 0 }`, and would have opened slot
/// 1's file on set 0's block grid, proved the borrowed bytes against set
/// 0's IFSC checksums, written them, and then had `apply_to` strike the
/// blocks off - `apply_to` keys on slot index alone and cannot tell
/// which set's pass produced the entry. Set 1's real hole would have
/// gone unrepaired AND unreported.
#[test]
fn a_report_from_a_sibling_set_is_not_this_sets_business() {
    let r = Rig::new(
        "sibling",
        &["shared.bin", "shared.bin"],
        &["shared.bin", "shared.bin"],
    );
    assert_eq!(
        r.verifier.slot_set(0),
        Some(0),
        "fixture: slot 0 must be set 0's"
    );
    assert_eq!(
        r.verifier.slot_set(1),
        Some(1),
        "fixture: slot 1 must be set 1's"
    );
    let reports = vec![(1, report("shared.bin", vec![2], r.payload_len()))];
    assert!(
        r.wanted(0, &reports).is_empty(),
        "set 0 took a sibling set's report as its own"
    );
    assert_eq!(
        r.wanted(1, &reports),
        vec![1],
        "set 1 lost the report for the slot it actually claimed"
    );
}

/// Both slots damaged: each set's pass sees exactly its own. Worth
/// pinning beside the case above because the two fail DIFFERENTLY
/// without the guard - here both reports resolve to one set member, so
/// `wanted_files`' own "one set FILE, one entry" refusal fires and both
/// sets borrow nothing at all, which looks like caution rather than a
/// defect.
#[test]
fn each_sets_pass_sees_only_the_slots_that_set_claimed() {
    let r = Rig::new(
        "both",
        &["shared.bin", "shared.bin"],
        &["shared.bin", "shared.bin"],
    );
    let reports = vec![
        (0, report("shared.bin", vec![1], r.payload_len())),
        (1, report("shared.bin", vec![2], r.payload_len())),
    ];
    assert_eq!(r.wanted(0, &reports), vec![0]);
    assert_eq!(r.wanted(1, &reports), vec![1]);
}

/// The ordinary post: one set, so every report belongs to set 0 and the
/// guard refuses nothing. This is the arm that says the change is a
/// no-op everywhere but a multi-set post.
#[test]
fn a_single_set_post_is_untouched_by_the_set_guard() {
    let r = Rig::new("single", &["only.bin"], &["only.bin"]);
    let reports = vec![(0, report("only.bin", vec![0, 3], r.payload_len()))];
    assert_eq!(r.wanted(0, &reports), vec![0]);
}

/// A report whose slot the verifier cannot place in ANY set is nobody's
/// business rather than everybody's - there is no set vouching for its
/// block grid, so no set may open it. Reached here by naming a slot
/// index no set ever claimed.
#[test]
fn a_slot_no_set_claimed_is_refused_by_every_set() {
    let r = Rig::new("unplaced", &["shared.bin", "shared.bin"], &["shared.bin"]);
    // Slot 0 claimed set 0. Nothing claimed set 1, and the report below
    // names a slot the verifier has no set for.
    assert_eq!(r.verifier.slot_set(0), Some(0));
    let reports = vec![(0, report("shared.bin", vec![1], r.payload_len()))];
    assert_eq!(r.wanted(0, &reports), vec![0]);
    assert!(
        r.wanted(1, &reports).is_empty(),
        "set 1 adopted a slot it never claimed"
    );
}
