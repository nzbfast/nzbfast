//! `--fast` must SAY when it did nothing - TODO 340 item 1.
//!
//! The end-to-end half of that item: the decline is recorded deep in
//! `par2repair::forney::joint`, latched in a process global, and read
//! back by `parfast::run_with` after the command returns. The unit
//! tests in `src/lib.rs` pin the wording of every branch, and
//! `joint::tests` pins the verdict `joint_stripe` computes - but
//! neither crosses the latch, and the latch is exactly the wire that
//! was missing. It cannot be crossed inside `cargo test --lib` either:
//! that runs the whole crate in ONE process, so a test that reset the
//! latch and read it back would race every other test that runs a
//! joint solve. Here it is one test, one repair, one binary.
//!
//! No external binary and no reference `par2`: it drives
//! `parfast::run_with` in-process, which is what `src/main.rs` exists
//! to keep possible.

use std::path::{Path, PathBuf};

fn scratch(tag: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR")).join(tag);
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).expect("scratch dir");
    dir
}

fn arg(s: &str) -> String {
    s.to_string()
}

/// A repair that `--fast` cannot help names the reason on stderr, and
/// still repairs.
///
/// The decline provoked is `JointDecline::BlockAlignment` on any build
/// with a fused fold kernel: stage 1's kernels work in whole 32-byte
/// units, PAR2 requires only a multiple of 4, and a set written at a
/// block size of 260 bytes therefore declines.
///
/// It DECLINES on every target; it does not decline for the same reason
/// on every target, and the first version of this test conflated those.
/// On armv7 `multi_fold_width()` is 0, so the Forney route is never
/// selected at any depth and the decline is `NotForney`, reached before
/// the geometry is consulted at all. The host-dependent decline this item came from
/// (`NoScaleKernel`, the GFNI x86 case) cannot be provoked on a machine
/// whose CPU has a vector kernel, which is every machine in this
/// fleet's CI.
///
/// The damage has to be DEEP - `forney::backsub_min_missing` is 1,280
/// on the x86 arms and 704 on NEON, and below it the repair takes a
/// dense route that never offers the joint arm a decision at all. 1,400
/// blocks of 260 bytes is 364 KB of damage, which costs the solve
/// milliseconds and is what makes this test cheap enough to keep.
///
/// What is asserted is the SHAPE - a line, on stderr, naming a reason
/// and a remedy - and not the sentence, which `src/lib.rs`'s unit tests
/// own. Two copies of the wording would mean a change to it reddens
/// here for no reason.
#[test]
fn fast_says_so_when_the_set_geometry_refuses_the_joint_kernel() {
    const BLOCK: usize = 260;
    const BLOCKS: usize = 2000;
    const DAMAGED: usize = 1400;
    assert!(!BLOCK.is_multiple_of(32), "the whole premise of the test");

    let dir = scratch("fast-switch");
    let data = dir.join("payload.bin");
    // Not all one byte: the block digests want distinct blocks, and a
    // damaged block that matches a surviving one would be adopted
    // rather than rebuilt.
    let payload: Vec<u8> = (0..(BLOCK * BLOCKS) as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(&data, &payload).expect("payload");

    let set = dir.join("set.par2");
    let code = parfast::run_with(
        "parfast",
        &[
            arg("c"),
            arg("-q"),
            arg(&format!("-s{BLOCK}")),
            arg(&format!("-c{}", DAMAGED + 100)),
            arg(&set.to_string_lossy()),
            arg(&data.to_string_lossy()),
        ],
        &mut parfast::out::Sink::buffered(),
    );
    assert_eq!(code, 0, "fixture create failed");

    let damage = |path: &std::path::Path| {
        let mut bytes = std::fs::read(path).expect("read back");
        for (i, b) in bytes[..BLOCK * DAMAGED].iter_mut().enumerate() {
            *b = (i as u8) ^ 0xa5;
        }
        std::fs::write(path, &bytes).expect("damage");
    };

    damage(&data);
    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with(
        "parfast",
        &[
            arg("r"),
            arg("-q"),
            arg("--fast"),
            arg(&set.to_string_lossy()),
        ],
        &mut sink,
    );
    let (out, err) = sink.take();
    assert_eq!(
        code, 0,
        "the repair itself must still succeed; stderr: {err}"
    );
    assert_eq!(
        std::fs::read(&data).expect("repaired"),
        payload,
        "the bytes are the gate, not the exit code"
    );
    let line = err
        .lines()
        .find(|l| l.starts_with("parfast: --fast"))
        .unwrap_or_else(|| panic!("no --fast line on stderr.\nstderr:\n{err}"));
    assert!(
        line.contains("did not run") && line.contains("; "),
        "the line must name a reason AND a remedy: {line}"
    );
    // WHICH reason depends on the build, and calling this test "portable
    // by construction" was half right: it is portable in that this set
    // always DECLINES, not in WHY. On armv7 `multi_fold_width()` is 0, so
    // `forney::backsub_gate` is false at EVERY depth, the Forney route is
    // never selected and the decline is `NotForney` - a different
    // sentence, reached before the block size is ever consulted. That
    // took nightly/armv7-cross red on 6140be0f.
    //
    // So the shape is asserted above for every target, and the specific
    // condition here is asserted against the build's own fold width,
    // which is the thing that decides which of the two is reached.
    // BOTH BRANCHES ARE REACHABLE WITHOUT QEMU, which is what makes this
    // checkable before a nightly finds it: `NZBFAST_GF16_MULTI=0` forces
    // `multi_fold_width()` to 0 on any target, so
    //
    //     NZBFAST_GF16_MULTI=0 cargo test -p parfast --test integration fast_switch
    //
    // runs the armv7 shape on the machine you are sitting at. Run it both
    // ways after touching this test; running it one way is what shipped
    // the red.
    if nzbkit::gf16::multi_fold_width() > 0 {
        assert!(
            line.contains("32 bytes"),
            "with a fused fold kernel this set reaches the solver and declines on \
             its BLOCK SIZE, and the line must say which condition it tripped \
             rather than that something went wrong: {line}"
        );
    } else {
        assert!(
            line.contains("solver"),
            "with no fused fold kernel the Forney route is never selected, so the \
             decline is about the SOLVER and not the geometry: {line}"
        );
    }
    assert!(
        !out.contains("--fast"),
        "stdout is par2cmdline-compatible and pinned line for line; \
         the report goes to stderr only.\nstdout:\n{out}"
    );

    // ...and the same repair WITHOUT the switch says nothing about it,
    // so the line is the switch's own report and not a new standing
    // diagnostic on every repair.
    damage(&data);
    let mut sink = parfast::out::Sink::buffered();
    parfast::run_with(
        "parfast",
        &[arg("r"), arg("-q"), arg(&set.to_string_lossy())],
        &mut sink,
    );
    let (_out, err) = sink.take();
    assert!(
        !err.contains("--fast"),
        "an unarmed repair must not mention the switch: {err}"
    );

    let _ = std::fs::remove_dir_all(&dir);
}
