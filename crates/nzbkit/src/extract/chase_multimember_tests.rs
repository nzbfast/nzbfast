//! Multi-member compressed RAR sets through the chase (TODO 358 item
//! 10's finding, 9 Nov 2026): several files through ONE split set, which
//! is what `rar a -v` makes from more than one file and the commonest
//! compressed shape a poster puts on the wire.
//!
//! Until this landed such a set never went one-pass. A chase group
//! keyed on each volume's FIRST entry name, and a chased volume's
//! header parse stops at that first entry, so nothing ever linked the
//! volume that opens on member 1's continuation to the group member 0
//! started: every member past the first formed a group of its own, all
//! of them failed ("split entry is incomplete", "volume set is
//! empty"), and the job fell back to the disk unpack after the
//! download - 30 of 30 legs, +52-55% wall on a 1 GiB set
//! (research/MULTIMEMBER-CHASE-2026-11-09.md). Every compressed
//! multi-volume fixture before this file held ONE member, so nothing
//! saw it.
//!
//! The fix joins a chased volume to the chase of the SET it belongs to
//! by the volume name's release stem, the way the unpacker itself finds
//! the next volume; see `Extractor::set_chase_group`. These cases pin
//! the shape both ways: the set stays one-pass (no fallback at all,
//! every member byte-exact, nothing but the members on disk) across
//! arrival orders, the buffered and the incremental member paths, both
//! nesting depths, RAR4 and encryption; and a damaged set still either
//! repairs or falls back whole and clean.

use super::*;
use crate::rar::fixtures;

use crate::extract::testutil::*;

/// Per volume, its entries as `(name, split_before, split_after)`,
/// read back with the engine's own parser - so a fixture that stopped
/// crossing volume boundaries cannot pass these cases by accident.
fn layout_v5(vols: &[Vec<u8>], password: Option<&str>) -> Vec<Vec<(String, bool, bool)>> {
    vols.iter()
        .map(|v| {
            let opts = crate::mem::rar_read_options(password.map(str::as_bytes));
            rars::rar50::Archive::parse_with_options(v, opts)
                .unwrap()
                .files()
                .map(|f| {
                    (
                        String::from_utf8_lossy(f.name_bytes()).into_owned(),
                        f.is_split_before(),
                        f.is_split_after(),
                    )
                })
                .collect()
        })
        .collect()
}

fn layout_v4(vols: &[Vec<u8>]) -> Vec<Vec<(String, bool, bool)>> {
    vols.iter()
        .map(|v| {
            rars::rar15_40::Archive::parse(v)
                .unwrap()
                .files()
                .map(|f| {
                    (
                        String::from_utf8_lossy(f.name_bytes()).into_owned(),
                        f.is_split_before(),
                        f.is_split_after(),
                    )
                })
                .collect()
        })
        .collect()
}

/// The two facts the defect needed, asserted on the fixture: a member
/// boundary falls INSIDE a volume (one volume holds pieces of two
/// members), and some later volume OPENS on the continuation of a
/// member other than the first - the volume that used to start a chase
/// group of its own.
fn assert_members_cross_volumes(layout: &[Vec<(String, bool, bool)>], first: &str) {
    assert!(
        layout.iter().any(|v| {
            let mut names: Vec<&str> = v.iter().map(|e| e.0.as_str()).collect();
            names.dedup();
            names.len() >= 2
        }),
        "no volume holds two members: {layout:?}"
    );
    assert!(
        layout
            .iter()
            .skip(1)
            .any(|v| v.first().is_some_and(|e| e.1 && e.0 != first)),
        "no volume opens on a later member's continuation: {layout:?}"
    );
}

/// How many chase groups the extractor holds right now.
fn chase_groups(ex: &Extractor) -> usize {
    let inner = ex.inner.lock_ok();
    inner.groups.values().filter(|g| g.chase.is_some()).count()
}

/// Feed every volume of a posted set at depth 0, in `order`, under
/// `name_of(volume index)`, then report how many chase groups formed
/// and finish.
fn run_top(
    dir: &Path,
    vols: &[Vec<u8>],
    order: &[usize],
    name_of: &dyn Fn(usize) -> String,
    password: Option<&str>,
) -> (usize, ExtractReport) {
    let ex = Arc::new(Extractor::new(dir, vols.len(), true));
    ex.anchor();
    if let Some(pw) = password {
        ex.set_password(pw);
    }
    for &vi in order {
        feed(&ex, vi, &name_of(vi), &vols[vi], 7000, 41 + vi as u64);
    }
    let groups = chase_groups(&ex);
    let rep = finish_within(&ex, 120).unwrap();
    (groups, rep)
}

fn part_name(i: usize) -> String {
    format!("release.part{}.rar", i + 1)
}

/// One-pass, byte-exact, nothing else on disk.
fn assert_one_pass(dir: &Path, rep: &ExtractReport, members: &[(&str, &[u8])], what: &str) {
    assert!(rep.fallbacks.is_empty(), "{what}: {:?}", rep.fallbacks);
    for (name, data) in members {
        assert_eq!(
            std::fs::read(dir.join(name)).unwrap_or_default(),
            *data,
            "{what}: {name}"
        );
    }
    let mut want: Vec<String> = members.iter().map(|(n, _)| n.to_string()).collect();
    want.sort();
    assert_eq!(dir_files(dir), want, "{what}");
}

/// The three arrival orders every set here is run through: in order,
/// reversed (every continuation volume lands before the volume its
/// member starts in, so every member's group would have formed first),
/// and shuffled with volume 0 dead last.
fn orders(n: usize) -> Vec<(&'static str, Vec<usize>)> {
    vec![
        ("forward", (0..n).collect()),
        ("reverse", (0..n).rev().collect()),
        ("shuffled, zero last", shuffled_zero_last(n, 0x5eed)),
    ]
}

/// THE defect, at depth 0 - the posted shape the bench measured: four
/// compressed members through one RAR5 set, every member crossing a
/// volume boundary. One chase group, no fallback, every member
/// byte-exact, in every arrival order. Before the fix this formed one
/// group per member and every leg fell back.
#[test]
fn a_multi_member_compressed_set_chases_as_one_set() {
    let data: Vec<Vec<u8>> = (0..4).map(|i| noisy(130_000, 300 + i)).collect();
    let names = ["m0.bin", "m1.bin", "m2.bin", "m3.bin"];
    let members: Vec<(&str, &[u8])> = names
        .iter()
        .zip(&data)
        .map(|(n, d)| (*n, d.as_slice()))
        .collect();
    let vols = compressed_multi_member_volume_set(&members, 45_000, false, None);
    assert!(vols.len() >= 5, "want 5+ volumes, got {}", vols.len());
    for v in &vols {
        assert_not_store(v);
    }
    assert_members_cross_volumes(&layout_v5(&vols, None), "m0.bin");
    for (what, order) in orders(vols.len()) {
        let dir = tmpdir("mm-top");
        let (groups, rep) = run_top(&dir, &vols, &order, &part_name, None);
        assert_one_pass(&dir, &rep, &members, what);
        assert_eq!(groups, 1, "{what}: one set must be one chase");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// Owned members for a case: `(name, bytes)` pairs, borrowed as the
/// fixture builders and `assert_one_pass` want them.
fn borrow(owned: &[(String, Vec<u8>)]) -> Vec<(&str, &[u8])> {
    owned
        .iter()
        .map(|(n, d)| (n.as_str(), d.as_slice()))
        .collect()
}

/// A member past the engine's incremental bar (4 MiB unpacked:
/// `should_stream_decode`) decodes through the GROWING CHAIN, which pulls
/// its next volumes itself and opens the member's sink before it does -
/// a different route from the buffered split the small members of the
/// first case take, and the route the bench's 256 MiB members took.
/// Sandwiched between two small members so both member boundaries fall
/// mid-volume and the chain has to hand the walk back inside its
/// finishing volume.
#[test]
fn a_member_over_the_incremental_bar_chases_through_the_growing_chain() {
    let owned = vec![
        ("head.bin".to_string(), noisy(200_000, 310)),
        ("big.bin".to_string(), noisy(4_600_000, 311)),
        ("tail.bin".to_string(), noisy(150_000, 312)),
    ];
    let members = borrow(&owned);
    // Effort 1: the cheap search, same archive shape - see
    // `compressed_volume_set_at_effort` for why that is safe here.
    let vols = compressed_multi_member_volume_set(&members, 700_000, false, Some(1));
    assert!(vols.len() >= 4, "want 4+ volumes, got {}", vols.len());
    for v in &vols {
        assert_not_store(v);
    }
    let layout = layout_v5(&vols, None);
    assert_members_cross_volumes(&layout, "head.bin");
    for (what, order) in orders(vols.len()) {
        let dir = tmpdir("mm-big");
        let (groups, rep) = run_top(&dir, &vols, &order, &part_name, None);
        assert_one_pass(&dir, &rep, &members, what);
        assert_eq!(groups, 1, "{what}: one set must be one chase");
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The nested shape: the multi-member compressed volumes sit inside a
/// STORE outer, so they arrive as slots of the CHILD extractor, named
/// by the outer's entries. Same rule one level down - one chase, and
/// only the members ever reach disk. Articles of the outer arrive in
/// reverse, so the inner volumes classify last-first.
#[test]
fn a_nested_multi_member_set_chases_as_one_set() {
    let owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("n{i}.bin"), noisy(120_000, 320 + i)))
        .collect();
    let members = borrow(&owned);
    let vols = compressed_multi_member_volume_set(&members, 40_000, false, None);
    assert!(vols.len() >= 4, "want 4+ volumes, got {}", vols.len());
    assert_members_cross_volumes(&layout_v5(&vols, None), "n0.bin");
    let names: Vec<String> = (0..vols.len())
        .map(|i| format!("inner.part{}.rar", i + 1))
        .collect();
    let entries: Vec<(&str, u64, &[u8], bool, bool)> = names
        .iter()
        .zip(&vols)
        .map(|(n, v)| (n.as_str(), v.len() as u64, v.as_slice(), false, false))
        .collect();
    let outer = fixtures::rar5_volume(&entries);
    let dir = tmpdir("mm-nested");
    let ex = Extractor::new(&dir, 1, true);
    let art = 7000usize;
    for i in (0..outer.len().div_ceil(art)).rev() {
        let (s, e) = (i * art, ((i + 1) * art).min(outer.len()));
        ex.write(0, "o.rar", outer.len() as u64, s as u64, &outer[s..e])
            .unwrap();
    }
    let rep = ex.finish().unwrap();
    assert_one_pass(&dir, &rep, &members, "nested");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// SOLID sets (`rar a -s -v`): the members share one decoder window, so
/// they can only decode serially - which is exactly what the chase's
/// sequence driver does. They hit the same grouping defect (one group
/// per member boundary a volume opens on, every one failed) and take
/// the same fix; RAR5 and RAR4 both, every member byte-exact, so the
/// shared window really carried across the volume boundaries.
#[test]
fn a_solid_multi_member_set_chases_as_one_set() {
    let owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("s{i}.bin"), noisy(130_000, 400 + i)))
        .collect();
    let members = borrow(&owned);
    let v5 = compressed_multi_member_volume_set(&members, 45_000, true, None);
    let v4 = rar4_compressed_multi_member_volume_set(&members, 45_000, true);
    for (family, vols, layout) in [
        ("rar5", &v5, layout_v5(&v5, None)),
        ("rar4", &v4, layout_v4(&v4)),
    ] {
        assert_members_cross_volumes(&layout, "s0.bin");
        for (what, order) in orders(vols.len()) {
            let what = format!("{family} solid {what}");
            let dir = tmpdir("mm-solid");
            let (groups, rep) = run_top(&dir, vols, &order, &part_name, None);
            assert_one_pass(&dir, &rep, &members, &what);
            assert_eq!(groups, 1, "{what}: one set must be one chase");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// RAR4 non-solid, both volume-naming schemes: the v4 chase orders its
/// volumes by NAME (a RAR4 header carries no volume number), and the
/// set join reads the same name's stem, so `.partNN.rar` and the
/// old-style `.rar`/`.r00` must both come out as one set.
#[test]
fn a_rar4_multi_member_set_chases_as_one_set() {
    let owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("r{i}.bin"), noisy(130_000, 410 + i)))
        .collect();
    let members = borrow(&owned);
    let vols = rar4_compressed_multi_member_volume_set(&members, 45_000, false);
    assert!(vols.len() >= 4, "want 4+ volumes, got {}", vols.len());
    for v in &vols {
        assert_not_store(v);
    }
    assert_members_cross_volumes(&layout_v4(&vols), "r0.bin");
    let naming: [(&str, Box<dyn Fn(usize) -> String>); 2] = [
        ("partNN", Box::new(|i| format!("inner.part{}.rar", i + 1))),
        (
            "old-style",
            Box::new(|i| {
                if i == 0 {
                    "inner.rar".to_string()
                } else {
                    format!("inner.r{:02}", i - 1)
                }
            }),
        ),
    ];
    for (scheme, name_of) in &naming {
        for (what, order) in orders(vols.len()) {
            let what = format!("{scheme} {what}");
            let dir = tmpdir("mm-v4");
            let (groups, rep) = run_top(&dir, &vols, &order, &**name_of, None);
            assert_one_pass(&dir, &rep, &members, &what);
            assert_eq!(groups, 1, "{what}: one set must be one chase");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }
}

/// Encrypted members (`rar a -p -v`, headers in the clear): with the
/// password in hand the set is one chase and decrypts byte-exact; with
/// none, nothing can decode it anywhere, so the WHOLE set demotes - every
/// volume materializes byte-exact for the password prompt and no partial
/// member survives.
#[test]
fn an_encrypted_multi_member_set_chases_with_its_password_and_demotes_whole_without() {
    let owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("e{i}.bin"), noisy(120_000, 420 + i)))
        .collect();
    let members = borrow(&owned);
    let vols = encrypted_multi_member_volume_set(&members, 45_000, "hunter2");
    assert!(vols.len() >= 4, "want 4+ volumes, got {}", vols.len());
    assert_members_cross_volumes(&layout_v5(&vols, Some("hunter2")), "e0.bin");
    for (what, order) in orders(vols.len()) {
        let dir = tmpdir("mm-enc");
        let (groups, rep) = run_top(&dir, &vols, &order, &part_name, Some("hunter2"));
        assert_one_pass(&dir, &rep, &members, what);
        assert_eq!(groups, 1, "{what}: one set must be one chase");
        std::fs::remove_dir_all(&dir).unwrap();
    }
    let dir = tmpdir("mm-enc-nopw");
    let order: Vec<usize> = (0..vols.len()).collect();
    let (_, rep) = run_top(&dir, &vols, &order, &part_name, None);
    assert!(!rep.fallbacks.is_empty(), "a no-password set must demote");
    let want: Vec<String> = (0..vols.len()).map(part_name).collect();
    assert_eq!(dir_files(&dir), want, "volumes only, no partial member");
    for (vi, v) in vols.iter().enumerate() {
        assert_eq!(std::fs::read(dir.join(part_name(vi))).unwrap(), *v);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}

/// One member damaged: an article inside a LATER member's packed bytes
/// (a volume that opens on member 1's or 2's continuation, so the join
/// is what put it in this chase) never arrives.
///
/// Unrepaired, the set falls back WHOLE and clean - one group, so one
/// demotion; every volume on disk byte-exact outside the hole, the hole
/// zeros, and no member file at all, not even the members the chase had
/// already finished (a fallback abandons every sink it opened, so the
/// disk unpack starts from a clean directory, as it always has).
///
/// Repaired - the rebuilt block arriving through `patch_volume_span`
/// exactly as mapped PAR2 repair delivers it - the parked chase resumes
/// through the fill and the set completes one-pass.
#[test]
fn a_damaged_member_falls_back_whole_or_repairs_one_pass() {
    let owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("d{i}.bin"), noisy(130_000, 430 + i)))
        .collect();
    let members = borrow(&owned);
    let vols = compressed_multi_member_volume_set(&members, 45_000, false, None);
    let layout = layout_v5(&vols, None);
    assert_members_cross_volumes(&layout, "d0.bin");
    let k = (1..vols.len())
        .find(|&k| layout[k][0].1 && layout[k][0].0 != "d0.bin")
        .unwrap();
    let art = 1000usize;
    let lost = {
        let mut m = VolumeMapper::new(vols[k].len() as u64);
        m.feed(0, &vols[k]);
        let e = &m.entries[0];
        ((e.data_off + e.data_len / 2) / art as u64) as usize
    };
    let (ls, le) = (lost * art, ((lost + 1) * art).min(vols[k].len()));
    for repaired in [false, true] {
        let dir = tmpdir("mm-damaged");
        let ex = Arc::new(Extractor::new(&dir, vols.len(), true));
        ex.anchor();
        for (vi, v) in vols.iter().enumerate() {
            for i in 0..v.len().div_ceil(art) {
                if vi == k && i == lost {
                    continue;
                }
                let (s, e) = (i * art, ((i + 1) * art).min(v.len()));
                ex.write(vi, &part_name(vi), v.len() as u64, s as u64, &v[s..e])
                    .unwrap();
            }
        }
        assert_eq!(chase_groups(&ex), 1, "repaired={repaired}: one chase");
        if repaired {
            assert!(!ex.covered(k, ls as u64, (le - ls) as u64));
            ex.patch_volume_span(k, ls as u64, &vols[k][ls..le])
                .unwrap();
        }
        let rep = finish_within(&ex, 120).unwrap();
        if repaired {
            assert_one_pass(&dir, &rep, &members, "repaired");
        } else {
            assert_eq!(
                rep.fallbacks.len(),
                1,
                "one set, one demotion: {:?}",
                rep.fallbacks
            );
            let want: Vec<String> = (0..vols.len()).map(part_name).collect();
            assert_eq!(dir_files(&dir), want, "volumes only, no partial member");
            for (vi, v) in vols.iter().enumerate() {
                let mut expect = v.clone();
                if vi == k {
                    expect[ls..le].fill(0);
                }
                assert_eq!(std::fs::read(dir.join(part_name(vi))).unwrap(), expect);
            }
        }
        std::fs::remove_dir_all(&dir).unwrap();
    }
}

/// The join is per SET: two multi-member sets in one post, their volumes
/// interleaved, form two chases - never one - and both finish one-pass.
/// A join across sets would hand one engine a volume index it already
/// holds (refused) or a foreign volume (a header or CRC failure), so this
/// is the case that would show a stem rule gone too wide.
#[test]
fn two_multi_member_sets_in_one_post_stay_two_chases() {
    let a_owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("a{i}.bin"), noisy(110_000, 440 + i)))
        .collect();
    let b_owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("b{i}.bin"), noisy(110_000, 450 + i)))
        .collect();
    let (a, b) = (borrow(&a_owned), borrow(&b_owned));
    let va = compressed_multi_member_volume_set(&a, 40_000, false, None);
    let vb = compressed_multi_member_volume_set(&b, 40_000, false, None);
    assert_members_cross_volumes(&layout_v5(&va, None), "a0.bin");
    assert_members_cross_volumes(&layout_v5(&vb, None), "b0.bin");
    let dir = tmpdir("mm-two-sets");
    let ex = Arc::new(Extractor::new(&dir, va.len() + vb.len(), true));
    ex.anchor();
    let n = va.len().max(vb.len());
    for i in (0..n).rev() {
        if let Some(v) = va.get(i) {
            feed(
                &ex,
                i,
                &format!("alpha.part{}.rar", i + 1),
                v,
                7000,
                60 + i as u64,
            );
        }
        if let Some(v) = vb.get(i) {
            let slot = va.len() + i;
            feed(
                &ex,
                slot,
                &format!("beta.part{}.rar", i + 1),
                v,
                7000,
                80 + i as u64,
            );
        }
    }
    assert_eq!(chase_groups(&ex), 2, "two sets, two chases");
    let rep = finish_within(&ex, 120).unwrap();
    let mut all = a.clone();
    all.extend(b.iter().copied());
    assert_one_pass(&dir, &rep, &all, "two sets");
    std::fs::remove_dir_all(&dir).unwrap();
}

/// THE STATED LIMIT, pinned so it is not mistaken for coverage: volume
/// names that number no volume (a fully obfuscated post, a random name
/// per file and no shared stem) give the join nothing to read, so such a
/// set keys on first-entry names exactly as before this change, splits
/// at its member boundaries and falls back - cleanly, every volume on
/// disk byte-exact under its posted name for the disk unpack (which is
/// what the post-pass deobfuscation then renames). A one-member set
/// under the same names is unaffected: its every volume shares the one
/// entry name.
#[test]
fn a_multi_member_set_with_no_volume_names_still_falls_back_clean() {
    let owned: Vec<(String, Vec<u8>)> = (0..3)
        .map(|i| (format!("o{i}.bin"), noisy(120_000, 460 + i)))
        .collect();
    let members = borrow(&owned);
    let vols = compressed_multi_member_volume_set(&members, 45_000, false, None);
    assert_members_cross_volumes(&layout_v5(&vols, None), "o0.bin");
    let name_of = |i: usize| {
        format!(
            "{:016x}",
            0x9e37_79b9_7f4a_7c15u64.wrapping_mul(i as u64 + 1)
        )
    };
    let dir = tmpdir("mm-obf");
    let order: Vec<usize> = (0..vols.len()).collect();
    let (_, rep) = run_top(&dir, &vols, &order, &name_of, None);
    assert!(
        !rep.fallbacks.is_empty(),
        "documented limit: no stem, no join"
    );
    let mut want: Vec<String> = (0..vols.len()).map(name_of).collect();
    want.sort();
    assert_eq!(dir_files(&dir), want, "volumes only, no partial member");
    for (vi, v) in vols.iter().enumerate() {
        assert_eq!(std::fs::read(dir.join(name_of(vi))).unwrap(), *v);
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
