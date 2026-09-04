//! `par2gen` against the reference implementation.
//!
//! The unit tests beside the creator judge it with OUR OWN reader, which
//! proves the two agree and nothing more: a creator and a parser that
//! share a mistake pass those together. This is the half that cannot be
//! self-consistent - par2cmdline reads what we wrote, verifies the
//! members it names, and REPAIRS damage from the Reed-Solomon slices we
//! computed. Nothing about our own code is on the answering side.
//!
//! Interop is the point rather than a nicety: `nzbfast post`'s no-RAR
//! mode exists so the ecosystem gains a second producer of the shape the
//! Reddit thread is asking every tool to share
//! (`research/REDDIT-NORAR-FOLLOWUP-2026-08-31.md`), and a set only our
//! own client can read would be a private format wearing PAR2's name.

use std::path::{Path, PathBuf};
use std::process::Command;

use nzbkit::par2gen::{Member, Par2Spec, create_into};

/// par2cmdline is not installed everywhere - some development machines
/// in this fleet have none - so every test here opens by asking.
///
/// WHERE IT RUNS, checked rather than assumed (4 Sep 2026, under claim
/// `postfast-par2-conformance-runs-nowhere`): this is a module of
/// nzbkit's `integration` target, which ci-private's `linux-tests`
/// shards run with no par2 installed - so per push these tests skip -
/// and which nightly's `one-process-light` runs (`cargo test -p nzbkit
/// --tests`) with ubuntu's par2 and `NZBFAST_REQUIRE_PAR2` set. That
/// is the one job holding this coverage, and until this commit the
/// probe did not read that variable, so its promise was empty here: a
/// runner that failed to install par2 would have skipped every test in
/// this file and reported a green nightly. The three `par2repair_*`
/// modules beside it have carried this assert since the 22 Aug 2026
/// Windows pass; this is the copy that never got it.
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

/// Deterministic and NON-PERIODIC, and the second half is load-bearing
/// rather than tidy.
///
/// This was `i * 37 + seed * 13` truncated to a byte, whose period is
/// 256 - and every block size these tests use is a multiple of 256, so
/// EVERY full block of the fixture was byte-identical to every other
/// one. A file made of duplicate blocks is the worst possible input to
/// a PAR2 repairer's sliding scan, which looks for a block's content
/// anywhere in the damaged file: it defeats the "damage well past one
/// block, so the repair genuinely has to solve" intent stated below,
/// and par2cmdline 0.8.1 - which is what `apt-get install par2` gives
/// an ubuntu runner, two majors behind every box in this fleet - gets
/// it WRONG, reporting more intact blocks than exist and writing a file
/// that verifies worse than the one it replaced.
///
/// That is a par2cmdline defect and not ours: measured 31 Aug 2026,
/// 0.8.1 fails identically on sets IT created and on 1.3.0's, while
/// 1.3.0 repairs ours and 0.8.1's alike, and 0.8.1 repairs
/// non-periodic data of the same size, block size, redundancy and
/// damage without complaint. But it reached us as a nightly failure
/// whose message accused OUR Reed-Solomon constants of disagreeing
/// with the spec, which is the wrong diagnosis in the loudest possible
/// place. A fixture that is degenerate enough to trip a repairer's
/// duplicate-block handling is not testing what this file is for.
/// `research/PAR2-NIGHTLY-TWO-REDS-RESOLVED-2026-08-31.md` carries the
/// measurement; `par2repair_namepath::payload` next door is the same
/// generator, and its comment gives the same reason from the adoption
/// side.
fn payload(len: usize, seed: u8) -> Vec<u8> {
    let mut x = (seed as u64) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2gen-interop-{tag}-{}",
            std::process::id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn write(&self, name: &str, data: &[u8]) -> Member {
        let path = self.0.join(name);
        std::fs::create_dir_all(path.parent().unwrap()).unwrap();
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

fn par2(dir: &Path, args: &[&str]) -> (bool, String) {
    let out = Command::new("par2")
        .args(args)
        .current_dir(dir)
        .output()
        .expect("par2 runs");
    let mut text = String::from_utf8_lossy(&out.stdout).into_owned();
    text.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.success(), text)
}

#[test]
fn par2cmdline_verifies_a_set_we_created() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = Tmp::new("verify");
    let a = payload(120_000, 3);
    let b = payload(9_001, 11);
    let members = vec![t.write("Show.S01E01.mkv", &a), t.write("readme.nfo", &b)];
    let names = create_into(
        &t.0,
        &members,
        "testset",
        &Par2Spec {
            redundancy_pct: 20,
            block_size: Some(8192),
        },
    )
    .expect("create");
    let (ok, text) = par2(&t.0, &["verify", "-q", &names[0]]);
    assert!(ok, "par2 refused a set we wrote:\n{text}");
    // A pass is not enough on its own: par2 also exits 0 for a set whose
    // files it could not find, so pin that both members were judged.
    for m in &members {
        assert!(
            !text.contains(&format!("{}\" - missing", m.name)),
            "par2 could not find {}:\n{text}",
            m.name
        );
    }
}

#[test]
fn par2cmdline_repairs_from_the_recovery_slices_we_computed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = Tmp::new("repair");
    let a = payload(120_000, 5);
    let members = vec![t.write("payload.bin", &a)];
    let names = create_into(
        &t.0,
        &members,
        "rset",
        &Par2Spec {
            redundancy_pct: 50,
            block_size: Some(8192),
        },
    )
    .expect("create");
    assert!(names.len() > 1, "50% must emit volumes: {names:?}");

    // Damage well past one block, so the repair genuinely has to solve
    // rather than adopt an intact copy from somewhere.
    let mut broken = a.clone();
    broken[10_000..40_000].fill(0x5A);
    std::fs::write(&members[0].path, &broken).unwrap();

    let (ok, text) = par2(&t.0, &["repair", "-q", &names[0]]);
    assert!(ok, "par2 could not repair from our parity:\n{text}");
    assert_eq!(
        std::fs::read(&members[0].path).unwrap(),
        a,
        "par2 repaired to the wrong bytes - our RS constants disagree with the spec"
    );
}

#[test]
fn par2cmdline_reads_the_directory_tree_out_of_our_filedesc_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // The tree is the whole reason the FileDesc name is a relative PATH
    // and not a basename: under obfuscation it is the only place the
    // layout exists.
    let t = Tmp::new("tree");
    let members = vec![
        t.write("VIDEO_TS/VTS_01_1.VOB", &payload(50_000, 7)),
        t.write("VIDEO_TS/VTS_01_0.IFO", &payload(3_000, 9)),
    ];
    let names = create_into(
        &t.0,
        &members,
        "dvd",
        &Par2Spec {
            redundancy_pct: 10,
            block_size: Some(4096),
        },
    )
    .expect("create");
    let (ok, text) = par2(&t.0, &["verify", &names[0]]);
    assert!(ok, "par2 refused the tree set:\n{text}");
    assert!(
        text.contains("VTS_01_1.VOB") && text.contains("VTS_01_0.IFO"),
        "par2 did not name both tree members:\n{text}"
    );
}

/// The multi-member half, and the two things a ONE-MEMBER fixture is
/// structurally unable to see.
///
/// Every other repair case in this file hands `create_into` a single
/// member (`vec![t.write("payload.bin", &a)]`). With one member there is
/// one file id, so the Main packet's list has one entry: it is sorted
/// correctly under every conceivable rule, and the global input-slice
/// index space is just that file's own slices in order. Two spec bugs
/// lived behind exactly that shape until 3 Sep 2026 (`b6ec6aa01`):
///
///   1. the file id was hashed over the NULL-PADDED name, wrong for any
///      member whose name length is not a multiple of 4, and
///   2. the Main packet's id list was sorted BYTEWISE where the spec
///      sorts the ids as 16-byte little-endian numbers - and that order
///      IS the index space every recovery constant is keyed to.
///
/// So the fixture below is deliberate rather than incidental. All four
/// names have a length that is not a multiple of 4, and their ids sort
/// into a DIFFERENT order bytewise than little-endian - the two orders
/// disagree even in first place. A four-member set is not a lucky draw
/// for that: measured over 20,000 random sets, the two orders disagree
/// for 96% of four-member sets and 50% of two-member ones, which is the
/// 1 - 1/n! a pair of independent orderings predicts.
///
/// # And a repair alone cannot see either bug, which is why the
/// # packet-level assertions are here
///
/// Measured 3 Sep 2026 against par2cmdline 1.3.0 and par2cmdline-turbo
/// 1.5.0, over sets built by the pre-fix creator: both bugs produce a
/// set that is internally SELF-CONSISTENT, and a conforming reader takes
/// the file id and the slice order out of the packets it was handed
/// rather than deriving either. Both references verified such a set,
/// repaired damage spanning two members from it, and reconstructed a
/// deleted member from it, byte-perfect every time. A repair test alone
/// would therefore have stayed green through both bugs however many
/// members it used.
///
/// The repair below is still the point of the file - it is the half
/// nothing of ours answers - but the two assertions after it are what
/// pin the SPEC, by restating each rule independently of the creator:
/// the ids ascend little-endian, and each id binds the descriptor's own
/// fields with the name UNPADDED. `research/PAR2GEN-SPEC-BUGS-BLAST-
/// RADIUS-2026-09-03.md` is the measurement.
#[test]
fn a_four_member_set_repairs_and_carries_the_spec_ids_in_the_spec_order() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let t = Tmp::new("multi");
    // Names chosen for the two properties above; sizes keep the set
    // small enough to stay a unit-suite test.
    let fx: [(&str, usize, u8); 4] = [
        ("Feature.2024.1080p.mkv", 120_000, 3),
        ("sample.mkv", 40_000, 11),
        ("release.nfo", 33_000, 23),
        ("cover-art.jpg", 21_000, 41),
    ];
    let bodies: Vec<Vec<u8>> = fx.iter().map(|&(_, n, s)| payload(n, s)).collect();
    let members: Vec<Member> = fx
        .iter()
        .zip(&bodies)
        .map(|(&(name, _, _), body)| t.write(name, body))
        .collect();
    for &(name, _, _) in &fx {
        assert!(
            !name.len().is_multiple_of(4),
            "{name} is a multiple of 4 long, so it cannot see the padded-name id bug"
        );
    }

    let names = create_into(
        &t.0,
        &members,
        "multiset",
        &Par2Spec {
            redundancy_pct: 40,
            block_size: Some(4096),
        },
    )
    .expect("create");
    assert!(names.len() > 1, "40% must emit volumes: {names:?}");

    // Damage spanning TWO members, well past one block each, so the
    // solve has to place recovered slices into the right file at the
    // right global index rather than adopt an intact copy.
    let mut broken0 = bodies[0].clone();
    broken0[8_192..8_192 + 4 * 4096].fill(0xA5);
    std::fs::write(&members[0].path, &broken0).unwrap();
    let mut broken2 = bodies[2].clone();
    broken2[4_096..4_096 + 3 * 4096].fill(0x5A);
    std::fs::write(&members[2].path, &broken2).unwrap();

    let (ok, text) = par2(&t.0, &["repair", "-q", &names[0]]);
    assert!(ok, "par2 could not repair a four-member set:\n{text}");
    for (m, body) in members.iter().zip(&bodies) {
        assert_eq!(
            &std::fs::read(&m.path).unwrap(),
            body,
            "par2 repaired {} to the wrong bytes",
            m.name
        );
    }

    // The spec half. Walk the index file ourselves - deliberately not
    // through our own parser, so one mistake cannot agree with itself.
    let index = std::fs::read(t.0.join(&names[0])).unwrap();
    let (main_ids, descs) = critical_packets(&index);
    assert_eq!(main_ids.len(), 4, "Main should list four ids");

    let mut le_ascending = main_ids.clone();
    le_ascending.sort_by_key(|id| {
        let mut k = *id;
        k.reverse();
        k
    });
    let mut bytewise = main_ids.clone();
    bytewise.sort();
    assert_eq!(
        main_ids, le_ascending,
        "Main lists the recovery-set ids in an order that is not ascending \
         as 16-byte little-endian numbers, which is the order the global \
         input-slice index space is defined by"
    );
    assert_ne!(
        le_ascending, bytewise,
        "this fixture no longer discriminates: its ids sort the same way \
         bytewise and little-endian, so the assertion above proves nothing. \
         Pick different names or sizes rather than deleting the check."
    );

    for id in &main_ids {
        let (name, length, md5_16k) = descs
            .get(id)
            .unwrap_or_else(|| panic!("Main names an id with no FileDesc packet: {id:?}"));
        use md5::{Digest, Md5};
        let mut h = Md5::new();
        h.update(md5_16k);
        h.update(length.to_le_bytes());
        // The name WITHOUT the null padding the packet stores it with.
        h.update(name.as_bytes());
        let want: [u8; 16] = h.finalize().into();
        assert_eq!(
            id, &want,
            "the file id for {name} does not bind its own descriptor - \
             it is MD5(md5_16k | length | name) over the UNPADDED name"
        );
    }
}

/// The Main packet's recovery-set id list, and every FileDesc packet as
/// `id -> (name, length, md5_16k)`.
///
/// A dumb second-opinion walk, like `creator_packet.rs`'s next door: hop
/// by the declared packet length and read the two body layouts by
/// offset. It is a test's own reading of the bytes on purpose.
fn critical_packets(
    bytes: &[u8],
) -> (
    Vec<[u8; 16]>,
    std::collections::HashMap<[u8; 16], (String, u64, [u8; 16])>,
) {
    let mut ids = Vec::new();
    let mut descs = std::collections::HashMap::new();
    let mut i = 0usize;
    while i + 64 <= bytes.len() {
        if &bytes[i..i + 8] != b"PAR2\0PKT" {
            i += 1;
            continue;
        }
        let len = u64::from_le_bytes(bytes[i + 8..i + 16].try_into().unwrap()) as usize;
        if len < 64 || !len.is_multiple_of(4) || i + len > bytes.len() {
            i += 1;
            continue;
        }
        let body = &bytes[i + 64..i + len];
        match &bytes[i + 48..i + 64] {
            // slice size (8), file count (4), then the recovery-set ids.
            b"PAR 2.0\0Main\0\0\0\0" if ids.is_empty() && body.len() >= 12 => {
                let n = u32::from_le_bytes(body[8..12].try_into().unwrap()) as usize;
                for k in 0..n {
                    if 12 + 16 * (k + 1) <= body.len() {
                        ids.push(body[12 + 16 * k..28 + 16 * k].try_into().unwrap());
                    }
                }
            }
            // id (16), md5 (16), md5_16k (16), length (8), padded name.
            b"PAR 2.0\0FileDesc" if body.len() > 56 => {
                let id: [u8; 16] = body[0..16].try_into().unwrap();
                let md5_16k: [u8; 16] = body[32..48].try_into().unwrap();
                let length = u64::from_le_bytes(body[48..56].try_into().unwrap());
                let raw = &body[56..];
                let end = raw.iter().rposition(|&b| b != 0).map_or(0, |p| p + 1);
                let name = String::from_utf8_lossy(&raw[..end]).into_owned();
                descs.insert(id, (name, length, md5_16k));
            }
            _ => {}
        }
        i += len;
    }
    (ids, descs)
}
