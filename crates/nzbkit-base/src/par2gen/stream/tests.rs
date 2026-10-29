//! The streamed create against the file create it must equal.
//!
//! The claim that matters is byte identity: a set streamed from a
//! member's bytes is the set [`create_into_exact_controlled`] writes from
//! the same bytes on disk, under the same block size, recovery count and
//! plan - every file of it. That is judged against the file create, not
//! against a re-derivation of the spec here, so a streamed set inherits
//! everything the file create is already held to (par2cmdline interop in
//! `crates/nzbkit/tests/integration/par2gen_interop.rs`, and the
//! conformance harness). The repair test is the second, independent
//! check: our own repairer puts damage back from a streamed set.
//!
//! No external `par2` here: everything is the engine's own.

use super::*;

/// A temp directory that cleans itself up, as `par2gen_tests.rs` keeps
/// one: the crate has no dev-dependency on tempfile.
struct Tmp(PathBuf);
impl Tmp {
    fn new(tag: &str) -> Tmp {
        let p = std::env::temp_dir().join(format!(
            "nzbfast-par2stream-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&p);
        std::fs::create_dir_all(&p).unwrap();
        Tmp(p)
    }
    fn sub(&self, name: &str) -> PathBuf {
        let p = self.0.join(name);
        std::fs::create_dir_all(&p).unwrap();
        p
    }
}
impl Drop for Tmp {
    fn drop(&mut self) {
        let _ = std::fs::remove_dir_all(&self.0);
    }
}

/// Bytes that do not repeat at any short period, so a wrong slice index
/// or a wrong coefficient cannot cancel out.
fn payload(len: usize, seed: u64) -> Vec<u8> {
    let mut x = seed.wrapping_mul(0x9E37_79B9_7F4A_7C15) | 1;
    (0..len)
        .map(|_| {
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            (x >> 24) as u8
        })
        .collect()
}

/// Feed `data` in pieces whose sizes cycle through `pieces`, so writes
/// straddle slice and window boundaries in every way.
fn feed(s: &mut StreamCreate, data: &[u8], pieces: &[usize]) {
    let mut at = 0usize;
    let mut k = 0usize;
    while at < data.len() {
        let n = pieces[k % pieces.len()].min(data.len() - at);
        s.write(&data[at..at + n]).expect("feed");
        at += n;
        k += 1;
    }
}

/// The streamed set and the file create's set over the same bytes, as
/// (name, bytes) sorted by name.
#[expect(clippy::too_many_arguments)]
fn both(
    tag: &str,
    data: &[u8],
    bs: u64,
    rows: usize,
    recovery: usize,
    plan: CreatePlan,
    comment: Option<&str>,
    window_slices: usize,
    pieces: &[usize],
) -> (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>) {
    let t = Tmp::new(tag);
    let read_dir = t.sub("read");
    let stream_dir = t.sub("stream");
    let name = "set.rar";
    std::fs::write(read_dir.join(name), data).unwrap();
    let member = Member {
        name: name.to_string(),
        path: read_dir.join(name),
    };
    let read_names = create_into_exact_controlled(
        &read_dir,
        std::slice::from_ref(&member),
        "set",
        Some(bs),
        recovery,
        plan,
        comment,
        &CreateControl::default(),
    )
    .expect("file create");
    let mut s = StreamCreate::start(
        &stream_dir,
        "set",
        name,
        bs,
        rows,
        plan.first_exponent,
        data.len() as u64,
        CreateControl::default(),
        window_slices * bs as usize,
    )
    .expect("stream start");
    feed(&mut s, data, pieces);
    let stream_names = s.finish(recovery, plan, comment).expect("stream finish");
    assert_eq!(
        read_names, stream_names,
        "{tag}: the two creates named different files"
    );
    let collect = |dir: &Path, names: &[String]| -> Vec<(String, Vec<u8>)> {
        let mut v: Vec<(String, Vec<u8>)> = names
            .iter()
            .map(|n| (n.clone(), std::fs::read(dir.join(n)).unwrap()))
            .collect();
        v.sort();
        v
    };
    (
        collect(&read_dir, &read_names),
        collect(&stream_dir, &stream_names),
    )
}

fn assert_same(tag: &str, (read, stream): (Vec<(String, Vec<u8>)>, Vec<(String, Vec<u8>)>)) {
    assert_eq!(read.len(), stream.len(), "{tag}: file count");
    for ((rn, rb), (sn, sb)) in read.iter().zip(&stream) {
        assert_eq!(rn, sn, "{tag}: names");
        assert!(
            rb == sb,
            "{tag}: {rn} differs ({} bytes read-created, {} streamed)",
            rb.len(),
            sb.len()
        );
    }
}

#[test]
fn a_streamed_set_is_byte_identical_to_a_read_one() {
    // An odd length, so the last slice is partial and zero-padded; three
    // slices a window, so the stream crosses dozens of windows and waits
    // on its pool; pieces of 1 byte to several slices.
    let bs = 4096u64;
    let data = payload(bs as usize * 61 + 1237, 1);
    assert_same(
        "engine-plan",
        both(
            "engine-plan",
            &data,
            bs,
            12,
            12,
            CreatePlan::ENGINE,
            None,
            3,
            &[1, 7, 4096, 10_000, 333, 65_536],
        ),
    );
}

#[test]
fn every_plan_knob_streams_byte_identically() {
    let bs = 2048u64;
    let data = payload(bs as usize * 40 + 5, 2);
    let plans = [
        (
            "even-interleaved",
            CreatePlan::ENGINE
                .with_volumes(VolumePlan::Even(3))
                .with_critical(CriticalLayout::Interleaved),
        ),
        ("first-exponent", CreatePlan::ENGINE.with_first_exponent(5)),
        (
            "volume-ceiling",
            CreatePlan::ENGINE.with_max_blocks_per_volume(Some(2)),
        ),
    ];
    for (tag, plan) in plans {
        assert_same(
            tag,
            both(tag, &data, bs, 9, 9, plan, None, 4, &[2048, 1, 5000]),
        );
    }
}

/// Fewer recovery slices than the stream was sized for - the case where
/// the caller's estimate of the length was high - and a comment.
#[test]
fn a_lower_recovery_count_and_a_comment_stream_byte_identically() {
    let bs = 1024u64;
    let data = payload(bs as usize * 30 + 17, 3);
    assert_same(
        "fewer-rows",
        both(
            "fewer-rows",
            &data,
            bs,
            20,
            6,
            CreatePlan::ENGINE,
            Some("posted with parfast"),
            5,
            &[999, 1024, 3],
        ),
    );
}

/// A member smaller than one slice, and one smaller than the 16 KiB head
/// the file id hashes.
#[test]
fn a_member_shorter_than_one_slice_streams_byte_identically() {
    let data = payload(700, 4);
    assert_same(
        "short",
        both(
            "short",
            &data,
            4096,
            3,
            3,
            CreatePlan::ENGINE,
            None,
            1,
            &[1, 50],
        ),
    );
}

/// An index-only set: no recovery rows at all, so no fold.
#[test]
fn an_index_only_set_streams_byte_identically() {
    let data = payload(9000, 5);
    assert_same(
        "index-only",
        both(
            "index-only",
            &data,
            1024,
            0,
            0,
            CreatePlan::ENGINE,
            None,
            2,
            &[100],
        ),
    );
}

/// The independent half: our own repairer rebuilds a damaged member from
/// a streamed set.
#[test]
fn a_streamed_set_repairs_damage_in_its_member() {
    let t = Tmp::new("repair");
    let bs = 4096u64;
    let data = payload(bs as usize * 25 + 99, 6);
    std::fs::write(t.0.join("set.rar"), &data).unwrap();
    let mut s = StreamCreate::start(
        &t.0,
        "set",
        "set.rar",
        bs,
        5,
        0,
        data.len() as u64,
        CreateControl::default(),
        2 * bs as usize,
    )
    .expect("start");
    feed(&mut s, &data, &[3000]);
    s.finish(5, CreatePlan::ENGINE, None).expect("finish");
    let mut damaged = data.clone();
    for b in &mut damaged[5000..5000 + 3 * bs as usize] {
        *b ^= 0x5A;
    }
    std::fs::write(t.0.join("set.rar"), &damaged).unwrap();
    let status = crate::par2repair::repair_dir(&t.0).expect("repair");
    assert!(
        matches!(status, crate::par2repair::RepairStatus::Repaired(_)),
        "{status:?}"
    );
    assert!(
        std::fs::read(t.0.join("set.rar")).unwrap() == data,
        "the repaired member is the original"
    );
}

/// A cancel taken while bytes are still arriving leaves nothing on disk:
/// the set is written only by `finish`, and `finish` answers a cancel
/// before it writes.
#[test]
fn a_cancelled_stream_leaves_nothing() {
    let t = Tmp::new("cancel");
    let gate = Arc::new(crate::par2repair::PauseGate::default());
    let control = CreateControl::new(None, Some(gate.clone()));
    let bs = 1024u64;
    let data = payload(bs as usize * 50, 7);
    let mut s = StreamCreate::start(
        &t.0,
        "set",
        "set.rar",
        bs,
        4,
        0,
        0,
        control,
        2 * bs as usize,
    )
    .expect("start");
    s.write(&data[..10_000]).expect("before the cancel");
    gate.cancel();
    // The producer learns at its next window or at finish, whichever
    // comes first; either way the answer is the cancel.
    let r = s
        .write(&data[10_000..])
        .and_then(|()| s.finish(4, CreatePlan::ENGINE, None));
    assert!(matches!(r, Err(Par2GenError::Cancelled)), "{r:?}");
    let left: Vec<_> = std::fs::read_dir(&t.0).unwrap().flatten().collect();
    assert!(left.is_empty(), "a cancelled stream wrote {left:?}");
}

/// The refusals: a recovery count the budget cannot hold in one pass is
/// refused before anything is allocated, `fits` says so first, and an
/// empty member is refused at the end.
#[test]
fn the_refusals_are_refusals() {
    let t = Tmp::new("refuse");
    let huge = 60_000usize;
    let bs = 1u64 << 20;
    assert!(
        !StreamCreate::fits(bs, huge),
        "60,000 MiB of rows fits nothing"
    );
    assert!(StreamCreate::fits(4096, 4), "a few small rows always fit");
    let r = StreamCreate::new(
        &t.0,
        "set",
        "set.rar",
        bs,
        huge,
        0,
        0,
        CreateControl::default(),
    );
    assert!(matches!(r, Err(Par2GenError::Other(_))), "over budget");
    let r = StreamCreate::new(
        &t.0,
        "set",
        "set.rar",
        4098,
        1,
        0,
        0,
        CreateControl::default(),
    );
    assert!(r.is_err(), "a block size that is not a multiple of 4");
    let s = StreamCreate::new(
        &t.0,
        "set",
        "set.rar",
        4096,
        1,
        0,
        0,
        CreateControl::default(),
    )
    .expect("start");
    let r = s.finish(1, CreatePlan::ENGINE, None);
    assert!(
        matches!(r, Err(Par2GenError::Other(_))),
        "empty member: {r:?}"
    );
    let r = StreamCreate::new(
        &t.0,
        "set",
        "set.rar",
        4096,
        2,
        0,
        0,
        CreateControl::default(),
    )
    .expect("start")
    .finish(3, CreatePlan::ENGINE, None);
    assert!(r.is_err(), "more recovery than the stream was sized for");
}
