//! Finding 4 (TODO 30): what promoting a classified plain child to a
//! direct writer actually costs - or saves - on the STORE path.
//!
//! The optimisation landed in `3f6c129f` measured on a NESTED (depth-2)
//! loopback leg and never on the flat store shape that is 84% of all
//! bytes, which is what §30a's open line meant by "never measured".
//! This rig is that leg, off the network: the extractor is fed a
//! multi-volume store set article by article, exactly as the decode
//! threads feed it, and nothing else runs in the process.
//!
//! Both legs extract the SAME 1 GiB single-file store set and differ
//! only in article size, because the promotion is a per-ARTICLE saving
//! (one parent lock + one child lock + one child pwrite + one parent
//! re-lock collapse to one off-lock pwrite):
//!
//! * `store_promote_cost_per_article` uses 16 KiB articles - 32,896 of
//!   them over the same bytes - so the per-article term is 43x the
//!   posted leg's against identical disk work, and a saving of a
//!   microsecond an article would be tens of milliseconds here. Quote
//!   its delta PER ARTICLE, never its percentage: the article is 47x
//!   smaller than the wire's, so the percentage is ~43x the real one.
//! * `store_promote_cost_realistic` uses 768,000-byte articles, the
//!   posted shape, and answers the only question a user has - whether
//!   any of this is visible at all on a real set.
//!
//! There is deliberately NO env knob to turn the promotion off (§30's
//! plan rules one out - "three binaries are cleaner"). The A/B is two
//! builds of this file, interleaved:
//!
//! ```sh
//! cargo test -p nzbkit --release --test store_promote_cost --no-run
//! # copy the binary aside, delete the routed_plain insert in
//! # extract/deliver.rs, rebuild, copy that aside, restore the tree,
//! # then alternate the two binaries:
//! <bin> --ignored --nocapture --test-threads=1 <leg>
//! ```
//!
//! `--test-threads=1` and an otherwise idle box, for the reason
//! `tests/delivery_cost.rs` spells out: these legs measure process-wide
//! CPU, so two of them at once measure each other. On THIS repo's dev
//! machine that is not a formality - nine agent lanes compiling put the
//! load average over 100 and swing the same leg's wall from 0.52 s to
//! 14.6 s, of either sign, while its user CPU barely moves. Read `user`
//! first, take minima as well as medians, and say what the load was.

use std::time::Instant;

use nzbkit::extract::Extractor;
use nzbkit::rar::fixtures;

/// One inner file, `VOLS` volumes of `VOL_BYTES` each. 4 MiB volumes are
/// the small end of what posters use and 128 of them is enough set
/// structure for the routing tables the promotion sits in front of
/// without paying for a 16 GiB fixture. Both legs write the SAME half
/// gigabyte, so the disk term - which is most of `sys` - is a constant
/// between them and between the arms.
const VOL_BYTES: usize = 4 << 20;
const VOLS: usize = 128;
const TOTAL: usize = VOL_BYTES * VOLS;

fn payload(n: usize) -> Vec<u8> {
    // Cheap, deterministic, and NOT constant - a run of zeroes would let
    // an APFS sparse write stand in for the real one.
    let mut v = vec![0u8; n];
    let mut x: u32 = 0x9e37_79b9;
    for b in v.iter_mut() {
        x = x.wrapping_mul(1_664_525).wrapping_add(1_013_904_223);
        *b = (x >> 24) as u8;
    }
    v
}

/// Feed the whole set in article order and print wall/user/sys seconds
/// for the extraction alone: the fixture volumes are built inside the
/// loop, so their cost is subtracted from the wall as `build` (the CPU
/// charge for them stays in, identically in both arms).
fn leg(tag: &str, art: usize, data: &[u8]) {
    let dir =
        std::env::temp_dir().join(format!("nzbfast-f4cost-{tag}-{art}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let ex = Extractor::new(&dir, VOLS, true);
    let mut build = 0.0f64;
    let mut arts = 0usize;
    let (u0, s0) = nzbkit::mem::cpu_user_sys_secs().unwrap();
    let t0 = Instant::now();
    for vi in 0..VOLS {
        let b0 = Instant::now();
        let piece = &data[vi * VOL_BYTES..(vi + 1) * VOL_BYTES];
        let vol = fixtures::rar5_volume_n(
            &[("BIG.mkv", TOTAL as u64, piece, vi > 0, vi + 1 < VOLS)],
            vi as u64,
        );
        build += b0.elapsed().as_secs_f64();
        let name = format!("obf{vi:04}.bin");
        for s in (0..vol.len()).step_by(art) {
            let e = (s + art).min(vol.len());
            ex.write(vi, &name, vol.len() as u64, s as u64, &vol[s..e])
                .unwrap();
            arts += 1;
        }
    }
    let rep = ex.finish().unwrap();
    let wall = t0.elapsed().as_secs_f64() - build;
    let (u1, s1) = nzbkit::mem::cpu_user_sys_secs().unwrap();

    // Proof before numbers: a leg that fell back to materialising the
    // volumes measures a different path and its numbers are void.
    assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
    assert_eq!(rep.extracted, vec![("BIG.mkv".to_string(), TOTAL as u64)]);
    let out = std::fs::read(dir.join("BIG.mkv")).unwrap();
    assert!(out == data, "{tag}: output bytes differ from the source");
    for vi in 0..VOLS {
        assert!(
            !dir.join(format!("obf{vi:04}.bin")).exists(),
            "{tag}: volume {vi} materialised"
        );
    }

    let (user, sys) = (u1 - u0, s1 - s0);
    println!(
        "F4COST {tag:<7} art={art:>7} arts={arts:>6} wall {wall:>6.3}s user {user:>6.3}s sys {sys:>6.3}s cpuart {:>6.2}us",
        (user + sys) * 1e6 / arts as f64
    );
    std::fs::remove_dir_all(&dir).unwrap();
}

#[test]
#[ignore = "measurement: Finding 4 promotion, per-article isolation"]
fn store_promote_cost_per_article() {
    let data = payload(TOTAL);
    leg("perart", 16 << 10, &data);
}

#[test]
#[ignore = "measurement: Finding 4 promotion, posted article size"]
fn store_promote_cost_realistic() {
    let data = payload(TOTAL);
    leg("posted", 768_000, &data);
}
