//! The verify tier: parfast's DEFAULT is the per-block verdict (IFSC MD5 +
//! CRC32 per block plus the 16 KiB head, all-core) and `--slow` is the
//! FileDesc whole-file MD5. On an honest set they answer the same, by
//! exit code, by output line and by repaired bytes.
//!
//! The tier itself is pinned in `nzbkit::par2repair`'s unit tests (both
//! tiers over one fixture, plus the one crafted shape they disagree on).
//! This is the CLI half: the switch parses, both settings reach the
//! engine's global (`par2::fast_check_enabled`), and a verify and a repair
//! under each print what the other prints and leave what the other
//! leaves. It drives `parfast::run_with` in-process; every run sets the
//! global explicitly, so the order of runs does not matter.

use crate::scratch::scratch;

fn arg(s: &str) -> String {
    s.to_string()
}

fn run(args: &[String]) -> (u8, String, String) {
    let mut sink = parfast::out::Sink::buffered();
    let code = parfast::run_with("parfast", args, &mut sink);
    let (out, err) = sink.take();
    (code, out, err)
}

/// The default tier and `--slow` match on exit code and stdout for a clean
/// verify, both reach the engine, and a repair under each restores the
/// exact bytes.
#[test]
fn the_default_tier_and_slow_answer_alike_on_an_honest_set() {
    const BLOCK: usize = 65536;
    const BLOCKS: usize = 200;
    let dir = scratch("fast-check");
    let data = dir.join("payload.bin");
    let payload: Vec<u8> = (0..(BLOCK * BLOCKS) as u32)
        .map(|i| (i.wrapping_mul(2654435761) >> 11) as u8)
        .collect();
    std::fs::write(&data, &payload).expect("payload");
    let set = dir.join("set.par2");
    let (code, _, err) = run(&[
        arg("c"),
        arg("-q"),
        arg(&format!("-s{BLOCK}")),
        arg("-c20"),
        arg(&set.to_string_lossy()),
        arg(&data.to_string_lossy()),
    ]);
    assert_eq!(code, 0, "fixture create failed: {err}");

    let (code_fast, out_fast, err_fast) = run(&[arg("v"), arg(&set.to_string_lossy())]);
    assert!(
        nzbkit::par2::fast_check_enabled(),
        "the default reaches the engine as the fast tier"
    );
    let (code_slow, out_slow, _) = run(&[arg("v"), arg("--slow"), arg(&set.to_string_lossy())]);
    assert!(
        !nzbkit::par2::fast_check_enabled(),
        "--slow reaches the engine"
    );
    assert_eq!(code_slow, 0);
    assert_eq!(code_fast, code_slow, "exit code; stderr: {err_fast}");
    assert_eq!(out_fast, out_slow, "stdout");

    let damage = |bytes: &mut [u8]| {
        for b in [3usize, 150] {
            for x in bytes[b * BLOCK + 7..b * BLOCK + 300].iter_mut() {
                *x ^= 0x3c;
            }
        }
    };
    for (label, extra) in [("default", vec![]), ("--slow", vec![arg("--slow")])] {
        let mut damaged = payload.clone();
        damage(&mut damaged);
        std::fs::write(&data, &damaged).expect("damage");
        let mut v = vec![arg("v")];
        v.extend(extra.iter().cloned());
        v.push(arg(&set.to_string_lossy()));
        let (code_v, out_v, _) = run(&v);
        assert_ne!(
            code_v, 0,
            "{label}: a damaged file must not verify clean: {out_v}"
        );
        let mut r = vec![arg("r")];
        r.extend(extra.iter().cloned());
        r.push(arg(&set.to_string_lossy()));
        let (code_r, out_r, err_r) = run(&r);
        assert_eq!(
            code_r, 0,
            "{label}: repair; stdout: {out_r}\nstderr: {err_r}"
        );
        assert_eq!(
            std::fs::read(&data).expect("repaired"),
            payload,
            "{label}: the bytes are the gate"
        );
        let (code_again, _, _) = run(&v);
        assert_eq!(code_again, 0, "{label}: the repaired file verifies clean");
    }
}
