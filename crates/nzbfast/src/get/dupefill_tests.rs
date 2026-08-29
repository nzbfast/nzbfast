//! PLAN M31 stage 1 over a real mock server: a post with dead articles
//! plus a duplicate posting that still serves them.
//!
//! These drive [`super::fill_wanted`] - the whole of the wire, the
//! proof and the write - against `nzbkit::mock`. What they deliberately
//! do NOT need is a live `Extractor`: resolving which slots are worth
//! filling is `wanted_files`, one function up, and everything below it
//! takes a recovery set, a list of holes and some donor NZBs.
//!
//! Every fixture builds its PAR2 index in-process (the same packet
//! shapes `par2repair`'s own tests build), so nothing here shells out
//! to the external `par2` binary and nothing needs the par2 guard.

use super::*;
use md5::{Digest, Md5};
use nzbkit::par2;
use std::collections::HashMap;

// ---- fixtures ----

/// A scratch directory that removes itself. `tempfile` is not a
/// dependency of this crate's own unit tests (only of the integration
/// targets), and the in-crate idiom - `std::env::temp_dir()` plus a
/// per-test name - is what `resumeout`'s tests already use. The name
/// must be unique per TEST and not merely per process: these run
/// concurrently in one binary.
struct TmpDir(std::path::PathBuf);

impl TmpDir {
    fn new(name: &str) -> TmpDir {
        let d =
            std::env::temp_dir().join(format!("nzbfast-dupefill-{name}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&d);
        std::fs::create_dir_all(&d).expect("scratch dir");
        TmpDir(d)
    }

    fn path(&self) -> &std::path::Path {
        &self.0
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

/// A valid PAR2 packet: magic, length, body MD5, set id, type.
fn pkt(set_id: [u8; 16], ptype: &[u8; 16], body: &[u8]) -> Vec<u8> {
    let mut p = Vec::new();
    p.extend_from_slice(par2::MAGIC);
    p.extend_from_slice(&(64 + body.len() as u64).to_le_bytes());
    p.extend_from_slice(&[0u8; 16]);
    p.extend_from_slice(&set_id);
    p.extend_from_slice(ptype);
    p.extend_from_slice(body);
    let md5: [u8; 16] = Md5::digest(&p[32..]).into();
    p[16..32].copy_from_slice(&md5);
    p
}

/// The three packet types this fixture writes. Spelled out here rather
/// than reached for in `nzbkit::par2` (they are `pub(crate)` there, and
/// rightly so - nothing outside the parser has business naming them):
/// these sixteen-byte strings are fixed by the PAR2 2.0 spec and are
/// not a detail of our implementation.
const TYPE_MAIN: &[u8; 16] = b"PAR 2.0\0Main\0\0\0\0";
const TYPE_FILEDESC: &[u8; 16] = b"PAR 2.0\0FileDesc";
const TYPE_IFSC: &[u8; 16] = b"PAR 2.0\0IFSC\0\0\0\0";

fn fid(i: usize) -> [u8; 16] {
    let mut f = [0u8; 16];
    f[0] = i as u8 + 1;
    f
}

/// Main + FileDesc + IFSC for every member: everything this pass reads
/// and no recovery slice at all, which is the point - a fill that works
/// spends none.
fn par2_index(set_id: [u8; 16], bs: usize, files: &[(&str, &[u8])]) -> Vec<u8> {
    let mut main = Vec::new();
    main.extend_from_slice(&(bs as u64).to_le_bytes());
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
        let mut nb = name.as_bytes().to_vec();
        while nb.len() % 4 != 0 {
            nb.push(0);
        }
        desc.extend_from_slice(&nb);
        out.extend(pkt(set_id, TYPE_FILEDESC, &desc));
        let mut body = fid(i).to_vec();
        for chunk in data.chunks(bs) {
            let mut padded = chunk.to_vec();
            padded.resize(bs, 0);
            body.extend_from_slice(&<[u8; 16]>::from(Md5::digest(&padded)));
            body.extend_from_slice(&crc32fast::hash(&padded).to_le_bytes());
        }
        out.extend(pkt(set_id, TYPE_IFSC, &body));
    }
    out
}

fn nzb_xml(files: &[(&str, Vec<(String, u64, u32)>)]) -> String {
    let mut x = String::from(
        "<?xml version=\"1.0\"?>\n<nzb xmlns=\"http://www.newzbin.com/DTD/2003/nzb\">\n",
    );
    for (name, segs) in files {
        x.push_str(&format!(
            "<file poster=\"a@b\" date=\"1\" subject=\"&quot;{name}&quot; yEnc (1/{})\">\n<groups><group>alt.bin</group></groups>\n<segments>\n",
            segs.len()
        ));
        for (id, bytes, part) in segs {
            x.push_str(&format!(
                "<segment bytes=\"{bytes}\" number=\"{part}\">{id}</segment>\n"
            ));
        }
        x.push_str("</segments>\n</file>\n");
    }
    x.push_str("</nzb>\n");
    x
}

/// One posting of `payload` under `name`, with its own message-id tag
/// and its own PAR2 index posted beside it. Returns the NZB XML.
///
/// The donor posting differs from the target ONLY in its message-ids
/// (and, where a test asks for it, in the name it posts under) - which
/// is exactly what a repost is, and the only population M31 stage 1 can
/// serve.
fn posting(
    name: &str,
    payload: &[u8],
    bs: usize,
    art: usize,
    idtag: &str,
    set_id: [u8; 16],
    arts: &mut HashMap<String, Vec<u8>>,
) -> String {
    let segs = nzbkit::mock::make_file_articles(name, payload, art, idtag, arts);
    let idx = par2_index(set_id, bs, &[(name, payload)]);
    let p2name = format!("{name}.par2");
    let psegs =
        nzbkit::mock::make_file_articles(&p2name, &idx, 1 << 20, &format!("{idtag}p2"), arts);
    nzb_xml(&[(name, segs), (&p2name, psegs)])
}

/// The target's own parsed recovery set - what the settle pass would
/// hand this module.
fn target_set(bs: usize, files: &[(&str, &[u8])]) -> par2::Par2Set {
    let idx = par2_index([1u8; 16], bs, files);
    par2::Par2Set::parse(&[idx.as_slice()]).expect("index parses")
}

struct Rig {
    _dir: TmpDir,
    out: std::path::PathBuf,
    donor_nzb: std::path::PathBuf,
    payload: Vec<u8>,
    set: par2::Par2Set,
    server: nzbkit::mock::MockServer,
}

const NAME: &str = "The.Release.part01.rar";
const BS: usize = 4096;
const ART: usize = 8192;

/// A target file on disk with `holes` blocks blanked, and a duplicate
/// posting of the very same bytes live on the mock.
async fn rig(
    scratch: &str,
    holes: &[usize],
    donor_name: &str,
    donor_payload: Option<Vec<u8>>,
) -> Rig {
    let payload = pseudo(64 * 1024, 4242);
    let dp = donor_payload.unwrap_or_else(|| payload.clone());
    let mut arts = HashMap::new();
    let donor_xml = posting(donor_name, &dp, BS, ART, "dupe", [2u8; 16], &mut arts);
    let dir = TmpDir::new(scratch);
    let out = dir.path().join(NAME);
    // The target's file as the download left it: right length, with the
    // bad blocks blanked - which is what a lost article leaves behind.
    let mut disk = payload.clone();
    for &b in holes {
        let at = b * BS;
        let end = (at + BS).min(disk.len());
        disk[at..end].fill(0);
    }
    std::fs::write(&out, &disk).expect("write target");
    let donor_nzb = dir.path().join("donor.nzb");
    std::fs::write(&donor_nzb, donor_xml).expect("write donor nzb");
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    Rig {
        _dir: dir,
        out,
        donor_nzb,
        set: target_set(BS, &[(NAME, &payload)]),
        payload,
        server,
    }
}

impl Rig {
    fn wanted(&self, holes: &[usize]) -> Vec<Wanted> {
        vec![Wanted {
            sidx: 0,
            file: 0,
            path: self.out.clone(),
            bad: holes.to_vec(),
        }]
    }

    async fn fill(&self, holes: &[usize]) -> FillReport {
        fill_wanted(
            &[self.server.server_config()],
            &self.set,
            &self.wanted(holes),
            std::slice::from_ref(&self.donor_nzb),
            &[],
            None,
        )
        .await
    }

    /// A §293 donor directory holding `bytes` under `name` - the shape
    /// `serve::tasks::worker::start_next` resolves from a failed
    /// predecessor's `out_dir`.
    fn donor_dir(&self, name: &str, bytes: &[u8]) -> std::path::PathBuf {
        let d = self._dir.path().join("donor-dir");
        std::fs::create_dir_all(&d).expect("donor dir");
        std::fs::write(d.join(name), bytes).expect("donor file");
        d
    }

    async fn fill_with_dirs(&self, holes: &[usize], dirs: &[std::path::PathBuf]) -> FillReport {
        fill_wanted(
            &[self.server.server_config()],
            &self.set,
            &self.wanted(holes),
            std::slice::from_ref(&self.donor_nzb),
            dirs,
            None,
        )
        .await
    }

    fn on_disk(&self) -> Vec<u8> {
        std::fs::read(&self.out).expect("read back")
    }

    /// Does the file now verify whole against the target's own set -
    /// i.e. would repair have nothing left to do?
    fn verifies(&self) -> bool {
        let v = par2::verify_file(&self.set.files[0], self.set.block_size, &self.on_disk());
        v.md5_ok && v.blocks.iter().all(|b| *b)
    }
}

// ---- the M31 gate, on a mock ----

#[tokio::test]
async fn a_post_with_dead_articles_is_completed_by_a_duplicate_posting_with_no_repair() {
    let holes = [2usize, 3, 9];
    let r = rig("complete", &holes, NAME, None).await;
    assert!(!r.verifies(), "the fixture starts damaged");
    let f = r.fill(&holes).await;
    assert_eq!(f.healed, holes.len(), "every hole filled");
    assert_eq!(f.rejected, 0);
    assert_eq!(f.healed_blocks, vec![(0, holes.to_vec())]);
    assert!(f.bodies > 0, "donor articles really came off the wire");
    assert_eq!(r.on_disk(), r.payload, "byte-identical to the original");
    assert!(
        r.verifies(),
        "nothing left for PAR2 repair, so no recovery block is spent"
    );
}

#[tokio::test]
async fn a_healthy_job_fetches_nothing_at_all() {
    // The no-overhead half of M31's gate: a clean file has no bad
    // block, so the pass asks for nothing and touches nothing.
    let r = rig("healthy", &[], NAME, None).await;
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &r.wanted(&[]),
        std::slice::from_ref(&r.donor_nzb),
        &[],
        None,
    )
    .await;
    assert_eq!(f, FillReport::default());
    assert_eq!(r.server.serve_counts().len(), 0, "not one BODY asked for");
}

#[tokio::test]
async fn no_donor_held_means_no_work_and_no_connection() {
    let holes = [1usize];
    let r = rig("nodonor", &holes, NAME, None).await;
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &r.wanted(&holes),
        &[],
        &[],
        None,
    )
    .await;
    assert_eq!(f, FillReport::default());
    assert_eq!(r.server.conns_open(), 0);
    assert!(!r.verifies(), "and the damage is left exactly as it was");
}

#[tokio::test]
async fn a_donor_of_a_different_encode_donates_nothing_and_leaves_the_damage() {
    // The §282 case: another posting of the same release that is not
    // the same bytes. The recovery sets disagree on every digest, so
    // the pass stops after the index fetch - it must NOT write a byte.
    let holes = [2usize, 3];
    let r = rig("otherencode", &holes, NAME, Some(pseudo(64 * 1024, 777))).await;
    let before = r.on_disk();
    let f = r.fill(&holes).await;
    assert_eq!(f.healed, 0);
    assert_eq!(f.rejected, 0, "nothing was even offered");
    assert!(f.healed_blocks.is_empty());
    assert_eq!(r.on_disk(), before, "not one byte written");
    assert!(!r.verifies(), "repair still has the whole job");
}

#[tokio::test]
async fn a_donor_serving_corrupt_bytes_is_rejected_and_the_hole_is_left_for_repair() {
    // The donor's recovery set says the file is the same bytes - it is
    // built over the true payload - but the ARTICLES it serves carry a
    // flipped bit. Structure passes, content does not, and the target's
    // own block checksums are what catch it.
    let holes = [2usize, 3];
    let payload = pseudo(64 * 1024, 4242);
    let mut arts = HashMap::new();
    let donor_xml = posting(NAME, &payload, BS, ART, "dupe", [2u8; 16], &mut arts);
    // Re-post the donor's payload articles over the SAME ids with one
    // byte of the payload changed, leaving its index honest.
    let mut poisoned = payload.clone();
    poisoned[2 * BS + 11] ^= 0x80;
    nzbkit::mock::make_file_articles(NAME, &poisoned, ART, "dupe", &mut arts);
    let dir = TmpDir::new("poison");
    let out = dir.path().join(NAME);
    let mut disk = payload.clone();
    for &b in &holes {
        disk[b * BS..(b + 1) * BS].fill(0);
    }
    std::fs::write(&out, &disk).expect("write");
    let donor_nzb = dir.path().join("donor.nzb");
    std::fs::write(&donor_nzb, donor_xml).expect("write nzb");
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    let set = target_set(BS, &[(NAME, &payload)]);
    let wanted = vec![Wanted {
        sidx: 0,
        file: 0,
        path: out.clone(),
        bad: holes.to_vec(),
    }];
    let f = fill_wanted(
        &[server.server_config()],
        &set,
        &wanted,
        &[donor_nzb],
        &[],
        None,
    )
    .await;
    // Block 2 carries the flipped byte and is refused; block 3 is
    // genuinely the same bytes and is taken. A bad donor costs its own
    // block and no other.
    assert_eq!(f.rejected, 1, "the poisoned block failed this set's MD5");
    assert_eq!(f.healed, 1, "and its healthy neighbour still healed");
    let back = std::fs::read(&out).expect("read");
    assert_eq!(
        &back[3 * BS..4 * BS],
        &payload[3 * BS..4 * BS],
        "the proved block landed"
    );
    assert_ne!(
        &back[2 * BS..3 * BS],
        &poisoned[2 * BS..3 * BS],
        "the refused block was never written"
    );
    let v = par2::verify_file(&set.files[0], set.block_size, &back);
    assert!(!v.blocks[2], "block 2 is still a hole - repair's job");
    assert!(v.blocks[3]);
}

/// Two donor postings of the target's bytes, the first of which serves
/// a CORRUPT copy of block `poison_block`. Returns the two NZB paths in
/// the order given, plus everything else `fill_wanted` needs.
///
/// Both indexes are honest - built over the true payload - so
/// `match_by_content` pairs both donors and the corruption is only ever
/// caught by the target set's own per-block checksums, which is the
/// point.
async fn two_donors(
    scratch: &str,
    holes: &[usize],
    poison_block: usize,
    poison_first: bool,
) -> (
    Vec<u8>,
    par2::Par2Set,
    std::path::PathBuf,
    Vec<std::path::PathBuf>,
    nzbkit::mock::MockServer,
    TmpDir,
) {
    let payload = pseudo(64 * 1024, 4242);
    let mut arts = HashMap::new();
    let bad_xml = posting(NAME, &payload, BS, ART, "bad", [2u8; 16], &mut arts);
    let good_xml = posting(NAME, &payload, BS, ART, "good", [3u8; 16], &mut arts);
    // Re-post the FIRST donor's payload articles over the same ids with
    // one byte of `poison_block` changed, leaving its index honest.
    let mut poisoned = payload.clone();
    poisoned[poison_block * BS + 11] ^= 0x80;
    nzbkit::mock::make_file_articles(NAME, &poisoned, ART, "bad", &mut arts);
    let dir = TmpDir::new(scratch);
    let out = dir.path().join(NAME);
    let mut disk = payload.clone();
    for &b in holes {
        disk[b * BS..(b + 1) * BS].fill(0);
    }
    std::fs::write(&out, &disk).expect("write");
    let bad_nzb = dir.path().join("bad.nzb");
    let good_nzb = dir.path().join("good.nzb");
    std::fs::write(&bad_nzb, bad_xml).expect("write nzb");
    std::fs::write(&good_nzb, good_xml).expect("write nzb");
    let order = if poison_first {
        vec![bad_nzb, good_nzb]
    } else {
        vec![good_nzb, bad_nzb]
    };
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    let set = target_set(BS, &[(NAME, &payload)]);
    (payload, set, out, order, server, dir)
}

#[tokio::test]
async fn a_block_the_first_donor_served_corrupt_is_retried_against_the_second() {
    // The M31 stage-2 item: first bytes win WITHIN a donor, and a block
    // that donor got wrong must not be poisoned for the donor behind
    // it. Donor A serves a flipped bit in block 2 and the true bytes of
    // block 3; donor B serves both correctly.
    let holes = [2usize, 3];
    let (payload, set, out, donors, server, _dir) = two_donors("retry", &holes, 2, true).await;
    let wanted = vec![Wanted {
        sidx: 0,
        file: 0,
        path: out.clone(),
        bad: holes.to_vec(),
    }];
    let f = fill_wanted(&[server.server_config()], &set, &wanted, &donors, &[], None).await;
    assert_eq!(
        f.rejected, 1,
        "donor A's copy of block 2 failed this set's MD5"
    );
    assert_eq!(
        f.healed, 2,
        "block 3 from donor A, block 2 re-opened and healed from donor B"
    );
    assert_eq!(f.healed_blocks, vec![(0, vec![2, 3])]);
    assert_eq!(f.proven, vec![0], "the file's last hole closed");
    let back = std::fs::read(&out).expect("read");
    assert_eq!(back, payload, "and every byte is the true payload");
    let v = par2::verify_file(&set.files[0], set.block_size, &back);
    assert!(v.md5_ok && v.blocks.iter().all(|b| *b));
}

#[tokio::test]
async fn a_good_first_donor_leaves_nothing_for_the_corrupt_one_to_touch() {
    // The same fixture with the donors the other way round. Every block
    // is proved off donor A, so donor B is never asked at all - which is
    // what keeps the retry from being a second chance to be WRONG.
    let holes = [2usize, 3];
    let (payload, set, out, donors, server, _dir) = two_donors("retryrev", &holes, 2, false).await;
    let wanted = vec![Wanted {
        sidx: 0,
        file: 0,
        path: out.clone(),
        bad: holes.to_vec(),
    }];
    let f = fill_wanted(&[server.server_config()], &set, &wanted, &donors, &[], None).await;
    assert_eq!(f.rejected, 0, "nothing was ever refused");
    assert_eq!(f.healed, 2);
    assert_eq!(std::fs::read(&out).expect("read"), payload);
}

#[tokio::test]
async fn a_block_no_donor_can_prove_is_still_left_for_repair() {
    // Both donors serve the same corrupt block. The retry costs one
    // extra attempt and changes nothing else: the block stays a hole,
    // its neighbour still heals, and nothing unproved reaches the disk.
    let holes = [2usize, 3];
    let payload = pseudo(64 * 1024, 4242);
    let mut arts = HashMap::new();
    let a_xml = posting(NAME, &payload, BS, ART, "bad1", [2u8; 16], &mut arts);
    let b_xml = posting(NAME, &payload, BS, ART, "bad2", [3u8; 16], &mut arts);
    let mut poisoned = payload.clone();
    poisoned[2 * BS + 11] ^= 0x80;
    for tag in ["bad1", "bad2"] {
        nzbkit::mock::make_file_articles(NAME, &poisoned, ART, tag, &mut arts);
    }
    let dir = TmpDir::new("bothbad");
    let out = dir.path().join(NAME);
    let mut disk = payload.clone();
    for &b in &holes {
        disk[b * BS..(b + 1) * BS].fill(0);
    }
    std::fs::write(&out, &disk).expect("write");
    let mut donors = Vec::new();
    for (n, xml) in [("d1.nzb", a_xml), ("d2.nzb", b_xml)] {
        let p = dir.path().join(n);
        std::fs::write(&p, xml).expect("write nzb");
        donors.push(p);
    }
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    let set = target_set(BS, &[(NAME, &payload)]);
    let wanted = vec![Wanted {
        sidx: 0,
        file: 0,
        path: out.clone(),
        bad: holes.to_vec(),
    }];
    let f = fill_wanted(&[server.server_config()], &set, &wanted, &donors, &[], None).await;
    assert_eq!(f.rejected, 2, "one block, refused once per donor");
    assert_eq!(f.healed, 1, "its healthy neighbour still healed");
    assert!(
        f.proven.is_empty(),
        "the file is not whole and is not claimed"
    );
    let back = std::fs::read(&out).expect("read");
    assert_ne!(
        &back[2 * BS..3 * BS],
        &poisoned[2 * BS..3 * BS],
        "no unproved byte reached the disk"
    );
    let v = par2::verify_file(&set.files[0], set.block_size, &back);
    assert!(!v.blocks[2], "block 2 is still repair's job");
    assert!(v.blocks[3]);
}

#[tokio::test]
async fn a_donor_posting_the_same_bytes_under_another_name_still_donates() {
    // An obfuscated repost: the payload is identical, the subject is a
    // hash. Matching is by digest, so the name never enters into it -
    // and the donor's OWN index names its own member, which is what
    // bridges back to its NZB.
    let holes = [5usize];
    let r = rig("renamed", &holes, "3f81aa20c9e4.bin", None).await;
    let f = r.fill(&holes).await;
    assert_eq!(f.healed, 1);
    assert!(r.verifies());
}

#[tokio::test]
async fn a_donor_whose_articles_are_gone_too_leaves_the_damage_alone() {
    let holes = [2usize, 3];
    let r = rig("gonedonor", &holes, NAME, None).await;
    let before = r.on_disk();
    r.server.take_down();
    let f = r.fill(&holes).await;
    assert_eq!(f.healed, 0);
    assert!(f.healed_blocks.is_empty());
    assert_eq!(r.on_disk(), before);
}

#[tokio::test]
async fn a_donor_nzb_that_is_not_there_is_not_a_failure() {
    let holes = [1usize];
    let r = rig("missingnzb", &holes, NAME, None).await;
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &r.wanted(&holes),
        &[std::path::PathBuf::from("/nonexistent/never.nzb")],
        &[],
        None,
    )
    .await;
    assert_eq!(f, FillReport::default());
}

#[tokio::test]
async fn a_cancelled_pass_stops_before_it_asks_anyone() {
    let holes = [2usize];
    let r = rig("cancelled", &holes, NAME, None).await;
    let cancel = crate::repair::SideCancel::new();
    cancel.cancel();
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &r.wanted(&holes),
        std::slice::from_ref(&r.donor_nzb),
        &[],
        Some(&cancel),
    )
    .await;
    assert_eq!(f, FillReport::default());
    assert_eq!(r.server.serve_counts().len(), 0);
}

#[tokio::test]
async fn the_last_short_block_of_a_file_heals_like_any_other() {
    // 64 KiB in 4 KiB blocks divides evenly, so this fixture uses a
    // length that does not: the tail block is 1 KiB and its checksum
    // was taken over the zero-padded slice.
    let payload = pseudo(64 * 1024 + 1024, 99);
    let last = payload.len().div_ceil(BS) - 1;
    let mut arts = HashMap::new();
    let donor_xml = posting(NAME, &payload, BS, ART, "dupe", [2u8; 16], &mut arts);
    let dir = TmpDir::new("shorttail");
    let out = dir.path().join(NAME);
    let mut disk = payload.clone();
    disk[last * BS..].fill(0);
    std::fs::write(&out, &disk).expect("write");
    let donor_nzb = dir.path().join("donor.nzb");
    std::fs::write(&donor_nzb, donor_xml).expect("nzb");
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    let set = target_set(BS, &[(NAME, &payload)]);
    let f = fill_wanted(
        &[server.server_config()],
        &set,
        &[Wanted {
            sidx: 0,
            file: 0,
            path: out.clone(),
            bad: vec![last],
        }],
        &[donor_nzb],
        &[],
        None,
    )
    .await;
    assert_eq!(f.healed, 1);
    assert_eq!(std::fs::read(&out).expect("read"), payload);
}

// ---- the helpers the pass leans on ----

#[test]
fn two_donor_files_posting_one_name_identify_neither() {
    let xml = nzb_xml(&[
        ("same.rar", vec![("a@m".into(), 10, 1)]),
        ("same.rar", vec![("b@m".into(), 10, 1)]),
    ]);
    let nzb = nzbkit::nzb::Nzb::parse(xml.as_bytes()).expect("parses");
    assert!(
        donor_files_by_name(&nzb).is_empty(),
        "an ambiguous name donates nothing"
    );
}

#[test]
fn the_name_key_ignores_case_and_path_separators() {
    assert_eq!(fold("The.Release.RAR"), fold("the.release.rar"));
}

// ---- the whole-file proof, which is the one verdict this pass moves ----

#[tokio::test]
async fn closing_a_file_s_last_hole_proves_it_whole_against_the_set() {
    let holes = [2usize, 3, 9];
    let r = rig("proved", &holes, NAME, None).await;
    let f = r.fill(&holes).await;
    assert_eq!(f.healed, holes.len());
    assert_eq!(
        f.proven,
        vec![0],
        "the file was read back whole and matched the set's own MD5"
    );
}

#[tokio::test]
async fn a_file_still_holed_after_the_fill_is_never_claimed_whole() {
    // Two holes, but the donor can only serve one: the block whose
    // bytes it corrupts is refused, so the file is not whole and must
    // not be claimed as such - `incomplete` stands and repair runs.
    let holes = [2usize, 3];
    let payload = pseudo(64 * 1024, 4242);
    let mut arts = HashMap::new();
    let donor_xml = posting(NAME, &payload, BS, ART, "dupe", [2u8; 16], &mut arts);
    let mut poisoned = payload.clone();
    poisoned[2 * BS + 5] ^= 0x11;
    nzbkit::mock::make_file_articles(NAME, &poisoned, ART, "dupe", &mut arts);
    let dir = TmpDir::new("notwhole");
    let out = dir.path().join(NAME);
    let mut disk = payload.clone();
    for &b in &holes {
        disk[b * BS..(b + 1) * BS].fill(0);
    }
    std::fs::write(&out, &disk).expect("write");
    let donor_nzb = dir.path().join("donor.nzb");
    std::fs::write(&donor_nzb, donor_xml).expect("nzb");
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    let set = target_set(BS, &[(NAME, &payload)]);
    let f = fill_wanted(
        &[server.server_config()],
        &set,
        &[Wanted {
            sidx: 0,
            file: 0,
            path: out,
            bad: holes.to_vec(),
        }],
        &[donor_nzb],
        &[],
        None,
    )
    .await;
    assert_eq!(f.healed, 1);
    assert_eq!(f.rejected, 1);
    assert!(
        f.proven.is_empty(),
        "a file with a hole left in it is not proved whole"
    );
}

#[tokio::test]
async fn a_wanted_entry_naming_no_set_file_is_dropped_rather_than_indexed() {
    let holes = [1usize];
    let r = rig("badindex", &holes, NAME, None).await;
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &[Wanted {
            sidx: 0,
            file: 99,
            path: r.out.clone(),
            bad: holes.to_vec(),
        }],
        std::slice::from_ref(&r.donor_nzb),
        &[],
        None,
    )
    .await;
    assert_eq!(f, FillReport::default());
    assert_eq!(r.server.conns_open(), 0, "and nobody was asked");
}

#[tokio::test]
async fn a_wanted_entry_with_no_bad_block_asks_for_nothing() {
    let r = rig("nobad", &[], NAME, None).await;
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &[Wanted {
            sidx: 0,
            file: 0,
            path: r.out.clone(),
            bad: Vec::new(),
        }],
        std::slice::from_ref(&r.donor_nzb),
        &[],
        None,
    )
    .await;
    assert_eq!(f, FillReport::default());
}

#[test]
fn absorb_sums_the_per_set_passes_and_proves_each_file_once() {
    // TODO 311: the pass runs once per recovery set, and a file two
    // sets both name must not be subtracted from `incomplete` twice -
    // that figure is a count of FILES.
    let mut a = FillReport {
        healed: 2,
        rejected: 1,
        bodies: 5,
        bytes: 100,
        local: 4,
        local_bytes: 400,
        stitched: 3,
        stitch_refused: 1,
        proven: vec![0],
        healed_blocks: vec![(0, vec![1, 2])],
    };
    a.absorb(FillReport {
        healed: 1,
        rejected: 0,
        bodies: 3,
        bytes: 50,
        local: 2,
        local_bytes: 200,
        stitched: 2,
        stitch_refused: 0,
        proven: vec![0, 4],
        healed_blocks: vec![(4, vec![7])],
    });
    assert_eq!(a.healed, 3);
    assert_eq!(a.rejected, 1);
    assert_eq!(a.bodies, 8);
    assert_eq!(a.bytes, 150);
    assert_eq!(a.local, 6, "the disk-served blocks sum too");
    assert_eq!(a.local_bytes, 600);
    assert_eq!(a.stitched, 5, "the stitched blocks sum too");
    assert_eq!(a.stitch_refused, 1);
    assert_eq!(a.healed_blocks, vec![(0, vec![1, 2]), (4, vec![7])]);
    assert_eq!(a.proven, vec![0, 0, 4], "absorb concatenates verbatim");
    // And the count that reaches `incomplete` sees slot 0 once. With no
    // slots to consult nothing is counted at all, which is the honest
    // answer: only a slot that really was SHORT may be subtracted.
    assert_eq!(a.whole_files_proved(&[]), 0);
}

// ---- the disk-first source: §293's donor directories ----

#[tokio::test]
async fn the_predecessors_own_files_serve_the_holes_and_no_article_is_fetched() {
    // The finding this arm exists for: `donor_dirs` and `donor_nzbs`
    // are populated from the SAME `alt_from`, so on a switch job the
    // blocks the donor POSTING would be asked for are, in the ordinary
    // case, blocks the predecessor already wrote to its own disk.
    let holes = [2usize, 3, 9];
    let r = rig("dirs-serve", &holes, NAME, None).await;
    let dirs = [r.donor_dir(NAME, &r.payload)];
    let f = r.fill_with_dirs(&holes, &dirs).await;
    assert_eq!(f.healed, holes.len(), "every hole filled");
    assert_eq!(f.local, holes.len(), "and every one of them off local disk");
    assert_eq!(f.rejected, 0);
    assert_eq!(f.bodies, 0, "not one donor article was asked for");
    assert_eq!(f.bytes, 0, "and not one wire byte was spent");
    assert!(f.local_bytes > 0, "the local read really produced bytes");
    assert_eq!(
        r.server.serve_counts().len(),
        0,
        "no BODY reached the server at all"
    );
    assert_eq!(r.on_disk(), r.payload, "byte-identical to the original");
    assert!(r.verifies(), "nothing left for PAR2 repair");
}

#[tokio::test]
async fn a_predecessors_quarantined_partial_is_found_under_its_suffix() {
    // A failed job's output is renamed to `<name>.nzbfast-partial`
    // between attempts, which is exactly the state a donor directory is
    // in when its job failed - so the plain spelling alone would find
    // nothing on the shape this pass was written for.
    let holes = [4usize];
    let r = rig("dirs-partial", &holes, NAME, None).await;
    let dirs = [r.donor_dir(
        &format!("{NAME}{}", nzbkit::journal::PARTIAL_SUFFIX),
        &r.payload,
    )];
    let f = r.fill_with_dirs(&holes, &dirs).await;
    assert_eq!(f.local, 1, "the quarantined partial was read");
    assert_eq!(f.bodies, 0, "so the wire was never asked");
    assert!(r.verifies());
}

#[tokio::test]
async fn a_hole_in_the_donors_own_copy_never_poisons_the_block() {
    // THE CONSTRAINT THAT SHAPES THE WHOLE PASS. First bytes win inside
    // `BlockHealer`, so a block whose first coverage is bad is rejected
    // whole and never retried. A predecessor's file is BLANK where its
    // own articles died - which is the normal case, since that is why
    // it failed - so a disk-first pass that offered what it read would
    // poison exactly the blocks the wire heals today.
    //
    // Nothing is offered until it has already proved, so the donor's
    // own hole costs one local read and changes nothing else.
    let holes = [2usize, 3];
    let r = rig("dirs-holed", &holes, NAME, None).await;
    // The donor is blank over BOTH of the target's holes - the worst
    // case, where the local pass can contribute nothing at all.
    let mut donor = r.payload.clone();
    let n = donor.len();
    for &b in &holes {
        let at = b * BS;
        donor[at..(at + BS).min(n)].fill(0);
    }
    let dirs = [r.donor_dir(NAME, &donor)];
    let f = r.fill_with_dirs(&holes, &dirs).await;
    assert_eq!(f.local, 0, "the donor's own hole proved nothing");
    assert_eq!(f.rejected, 0, "and poisoned nothing - no block was refused");
    assert_eq!(f.healed, holes.len(), "the wire still healed every hole");
    assert!(f.bodies > 0, "off the wire, exactly as before this arm");
    assert!(r.verifies());
}

#[tokio::test]
async fn a_corrupt_donor_file_costs_its_own_block_and_no_other() {
    // The other half of the same guard: bytes that are present and
    // WRONG, rather than absent. Block 2's local copy carries a flipped
    // byte and fails this set's own MD5, so it is not offered and the
    // wire takes it; block 9's local copy is honest and is taken off
    // disk. One bad range costs one local read.
    let holes = [2usize, 9];
    let r = rig("dirs-corrupt", &holes, NAME, None).await;
    let mut donor = r.payload.clone();
    donor[2 * BS + 11] ^= 0xff;
    let dirs = [r.donor_dir(NAME, &donor)];
    let f = r.fill_with_dirs(&holes, &dirs).await;
    assert_eq!(f.local, 1, "only the honest block came off disk");
    assert_eq!(
        f.rejected, 0,
        "the corrupt copy refused itself, not a block"
    );
    assert_eq!(f.healed, 2, "both holes closed");
    assert!(f.bodies > 0, "the wire covered the one the disk could not");
    assert_eq!(r.on_disk(), r.payload);
    assert!(r.verifies());
}

#[tokio::test]
async fn a_donor_directory_that_names_nothing_we_want_is_free() {
    // Matched by NAME, deliberately - §293's sliding scan at repair is
    // what exists for a donor whose layout does not line up with ours.
    // A miss here must cost nothing but the wire pass that was going to
    // run anyway.
    let holes = [1usize];
    let r = rig("dirs-miss", &holes, NAME, None).await;
    let dirs = [r.donor_dir("something.else.rar", &r.payload)];
    let f = r.fill_with_dirs(&holes, &dirs).await;
    assert_eq!(f.local, 0, "nothing matched");
    assert_eq!(f.healed, 1, "and the wire pass ran unchanged");
    assert!(f.bodies > 0);
    assert!(r.verifies());
}

#[tokio::test]
async fn a_donor_directory_alone_is_not_a_reason_to_run_the_pass() {
    // SCOPE. This is a cheaper SOURCE for a pass that was already
    // happening, not a new pass: a job with donor directories and no
    // donor NZB is still repair's business and still reaches §293's
    // adoption scan with nothing taken from under it.
    let holes = [1usize];
    let r = rig("dirs-only", &holes, NAME, None).await;
    let dirs = [r.donor_dir(NAME, &r.payload)];
    let f = fill_wanted(
        &[r.server.server_config()],
        &r.set,
        &r.wanted(&holes),
        &[],
        &dirs,
        None,
    )
    .await;
    assert_eq!(f, FillReport::default(), "no donor NZB, no pass");
    assert!(!r.verifies(), "the hole is still repair's to close");
}

#[tokio::test]
async fn the_pass_asks_for_the_articles_over_the_hole_and_not_the_file_around_it() {
    // The fixture is a 64 KiB file in eight articles - SMALLER than the
    // 1 MiB `SEG_SLACK`, so the blind estimate's guess covers all of it
    // and every segment is a candidate for every hole. That is the
    // whole of what the calibration is for, and this is it end to end,
    // over the real NNTP mock: what the plan asks for is only ever
    // narrowed by the articles that have already come back.
    //
    // Measured on this fixture before the calibration and the ask
    // ordering landed: 3 bodies, 5 bodies, 3 bodies. The arithmetic and
    // its own measurement table are `nzbkit::dupedonor`'s.
    for (holes, bodies) in [(vec![4usize], 1usize), (vec![5], 1), (vec![2, 3, 9], 4)] {
        let r = rig("fewbodies", &holes, NAME, None).await;
        let f = r.fill(&holes).await;
        assert_eq!(f.healed, holes.len(), "holes {holes:?}: every hole filled");
        assert_eq!(f.rejected, 0, "holes {holes:?}");
        assert_eq!(f.bodies, bodies, "holes {holes:?}: donor bodies asked for");
        assert!(r.verifies(), "holes {holes:?}: nothing left for repair");
    }
}

// ---- the geometry §293 adoption cannot bridge, and this pass can ----

/// Block = two articles, which is the whole premise of the section
/// below. `A` is the article and `B` the PAR2 block.
const PB: usize = 8192;
const PA: usize = 4096;

/// The bench-farm shape, shrunk: two postings of one release damaged at
/// COMPLEMENTARY ARTICLE phase inside a block that is two articles
/// wide, so neither posting holds one whole block of the damaged range.
///
/// `kill_donor_parts` takes named articles off the donor's server, so
/// it can serve nothing at all for the block they cover.
/// `corrupt_donor_part` replaces one of its articles with a VALID yEnc
/// body carrying different bytes - poster-side corruption, the one
/// shape a donor's own article CRC cannot catch. The donor's PAR2 index
/// still describes the real release, because a donor whose index
/// disagrees is refused by content matching long before any of this.
struct PhaseRig {
    _dir: TmpDir,
    out: std::path::PathBuf,
    donor_nzb: std::path::PathBuf,
    donor_dir: std::path::PathBuf,
    payload: Vec<u8>,
    donor_disk: Vec<u8>,
    set: par2::Par2Set,
    server: nzbkit::mock::MockServer,
    blocks: usize,
}

async fn phase_rig(
    scratch: &str,
    corrupt_donor_part: Option<u32>,
    kill_donor_parts: &[u32],
) -> PhaseRig {
    let payload = pseudo(64 * 1024, 909);
    let dp = payload.clone();
    let arts_per_file = payload.len().div_ceil(PA);
    let blocks = payload.len().div_ceil(PB);
    assert_eq!(arts_per_file, 2 * blocks, "premise: block is two articles");

    let mut arts = HashMap::new();
    let donor_xml = posting(NAME, &dp, PB, PA, "phase", [2u8; 16], &mut arts);
    // The donor loses the EVEN article of every pair, the target the
    // ODD one - so between them they hold every byte and neither holds
    // one whole block.
    for i in (0..arts_per_file).step_by(2) {
        arts.remove(&format!("<phase-{}@mock>", i + 1));
    }
    for part in kill_donor_parts {
        arts.remove(&format!("<phase-{part}@mock>"));
    }
    if let Some(part) = corrupt_donor_part {
        // Re-encoded at its own offset with its own part CRC, so it
        // decodes cleanly and is placed correctly - and carries bytes
        // that are not this release's. Only the recovery set can tell.
        let i = part as usize - 1;
        let at = i * PA;
        let end = (at + PA).min(dp.len());
        let mut chunk = dp[at..end].to_vec();
        chunk.iter_mut().for_each(|b| *b ^= 0xff);
        let body = nzbkit::yenc::encode(
            NAME,
            dp.len() as u64,
            Some((part, arts_per_file as u32)),
            at as u64 + 1,
            &chunk,
        );
        arts.insert(format!("<phase-{part}@mock>"), body);
    }

    let dir = TmpDir::new(scratch);
    let out = dir.path().join(NAME);
    let mut disk = payload.clone();
    for i in (1..arts_per_file).step_by(2) {
        let at = i * PA;
        let end = (at + PA).min(disk.len());
        disk[at..end].fill(0);
    }
    std::fs::write(&out, &disk).expect("write target");
    let donor_nzb = dir.path().join("donor.nzb");
    std::fs::write(&donor_nzb, donor_xml).expect("write donor nzb");

    // The donor's own OUTPUT as a failed predecessor leaves it on disk -
    // the complement of the target's damage. This is what §293's
    // adoption scan and this pass's donor-directory arm both read.
    let mut donor_disk = dp.clone();
    for i in (0..arts_per_file).step_by(2) {
        let at = i * PA;
        let end = (at + PA).min(donor_disk.len());
        donor_disk[at..end].fill(0);
    }
    let ddir = dir.path().join("donor-dir");
    std::fs::create_dir_all(&ddir).expect("donor dir");
    std::fs::write(ddir.join(NAME), &donor_disk).expect("donor file");

    let set = target_set(PB, &[(NAME, &payload)]);
    let server = nzbkit::mock::MockServer::start(arts, Default::default()).await;
    PhaseRig {
        _dir: dir,
        out,
        donor_nzb,
        donor_dir: ddir,
        payload,
        donor_disk,
        set,
        server,
        blocks,
    }
}

impl PhaseRig {
    async fn fill(&self, bad: &[usize]) -> FillReport {
        fill_wanted(
            &[self.server.server_config()],
            &self.set,
            &[Wanted {
                sidx: 0,
                file: 0,
                path: self.out.clone(),
                bad: bad.to_vec(),
            }],
            std::slice::from_ref(&self.donor_nzb),
            std::slice::from_ref(&self.donor_dir),
            None,
        )
        .await
    }

    /// How many WHOLE blocks of the target's set the donor's own file
    /// holds - which is all §293's block-granular adoption can ever
    /// take off it.
    fn whole_blocks_on_the_donors_disk(&self) -> usize {
        par2::verify_file(&self.set.files[0], self.set.block_size, &self.donor_disk)
            .blocks
            .iter()
            .filter(|b| **b)
            .count()
    }
}

/// The finding this section exists for, both halves on ONE fixture.
///
/// `research/DONOR-ADOPT-ZERO-ON-STORE-RAR-2026-08-28.md` measured a
/// real store-RAR switch whose PAR2 block was exactly two articles wide
/// and whose two postings were damaged at complementary ARTICLE phase.
/// §293's adoption is BLOCK-granular, so it took 22 of 290 - the blocks
/// at the edge of the damaged range - and the job stayed
/// `Unrepairable`. This pass, before the stitch, was no better off: it
/// fetches ARTICLES but assembles BLOCKS, so a donor that can serve
/// only half of one heals nothing at all.
///
/// Between them the two postings hold every byte. The contrast is the
/// measurement, so both halves are asserted here on one fixture rather
/// than split across two that a later edit could move apart.
#[tokio::test]
async fn a_block_two_articles_wide_defeats_block_adoption_and_not_the_article_fill() {
    let r = phase_rig("phase", None, &[]).await;
    let bad: Vec<usize> = (0..r.blocks).collect();
    assert_eq!(
        r.whole_blocks_on_the_donors_disk(),
        0,
        "premise: a BLOCK-granular read of that donor gets nothing off this \
         shape - that is what §293's adoption is limited to"
    );

    let f = r.fill(&bad).await;
    assert_eq!(
        f.healed, r.blocks,
        "every block was recoverable from the donor's live articles plus \
         the target's own surviving half: {f:?}"
    );
    assert_eq!(f.rejected, 0, "{f:?}");
    assert_eq!(f.stitch_refused, 0, "{f:?}");
    assert_eq!(
        f.local, 0,
        "the donor DIRECTORY could prove no block on this shape - it is \
         BLOCK-granular too, and holds not one whole block: {f:?}"
    );
    assert_eq!(
        f.stitched, r.blocks,
        "every block needed the target's OWN surviving half as well as the \
         donor's - that is the whole finding: {f:?}"
    );
    assert!(
        f.bodies > 0,
        "donor articles really came off the wire: {f:?}"
    );
    assert_eq!(
        std::fs::read(&r.out).expect("read back"),
        r.payload,
        "byte-identical to the original"
    );
}

/// The stitch is PART-SERVED ONLY, and this is why that rule is not
/// tidiness.
///
/// A block no donor could touch is one whose gap the target cannot
/// possibly close: the target's copy of it is exactly the copy the
/// recovery set already called bad. Completing it from our own bytes
/// would buy an MD5 and a CRC32 per block to be told so again, and
/// would charge the pass a refusal that says nothing about anything.
#[tokio::test]
async fn a_block_no_donor_could_touch_is_never_stitched_and_never_judged() {
    // Block 0 covers articles 1 and 2. The rig has already taken part 1
    // off the donor (the even phase); taking part 2 as well leaves the
    // donor unable to serve one byte of block 0.
    let r = phase_rig("phasedark", None, &[2]).await;
    let bad: Vec<usize> = (0..r.blocks).collect();
    let f = r.fill(&bad).await;
    assert_eq!(
        f.healed,
        r.blocks - 1,
        "every block but the dark one still heals: {f:?}"
    );
    assert_eq!(
        f.stitched,
        r.blocks - 1,
        "the dark block was not stitched: {f:?}"
    );
    assert_eq!(
        f.stitch_refused, 0,
        "a block nothing served must not be judged at all - not judged and \
         refused: {f:?}"
    );
    assert_eq!(f.rejected, 0, "{f:?}");
    assert!(
        !f.healed_blocks[0].1.contains(&0),
        "block 0 was handed out: {f:?}"
    );
    // ...and it is still a hole, which is repair's business.
    let v = par2::verify_file(
        &r.set.files[0],
        r.set.block_size,
        &std::fs::read(&r.out).expect("read back"),
    );
    assert!(!v.blocks[0], "block 0 must still be bad");
    assert!(
        v.blocks[1..].iter().all(|b| *b),
        "every other block is now good"
    );
}

/// The proof bar is unchanged by the stitch: a block completed out of a
/// donor's bytes and our own is judged by the target set's own MD5 and
/// CRC32, exactly as a wire-assembled one is, and a wrong one costs its
/// own block and no other.
///
/// The refusal is counted APART from `rejected`, which the job report
/// says out loud as a fact about the DONOR - and here the donor served
/// its half perfectly honestly, of a different release.
#[tokio::test]
async fn a_stitched_block_that_fails_the_set_is_refused_and_costs_no_other() {
    // Block 0 covers articles 1 and 2, and the donor serves article 2.
    // Give that one article a valid body carrying different bytes:
    // every other block's donor half is still the real payload.
    let r = phase_rig("phasewrong", Some(2), &[]).await;
    let bad: Vec<usize> = (0..r.blocks).collect();
    let f = r.fill(&bad).await;
    assert_eq!(
        f.stitch_refused, 1,
        "the wrong block was completed and refused: {f:?}"
    );
    assert_eq!(
        f.rejected, 0,
        "the refusal must not be charged to the donor as a bad borrow: {f:?}"
    );
    assert_eq!(
        f.healed,
        r.blocks - 1,
        "one block lost, every other one healed: {f:?}"
    );
    assert!(
        !f.healed_blocks[0].1.contains(&0),
        "the refused block was handed out: {f:?}"
    );
    let disk = std::fs::read(&r.out).expect("read back");
    let v = par2::verify_file(&r.set.files[0], r.set.block_size, &disk);
    assert!(
        !v.blocks[0],
        "block 0 must still be bad, not wrongly filled"
    );
    assert!(
        v.blocks[1..].iter().all(|b| *b),
        "every other block is good"
    );
}
