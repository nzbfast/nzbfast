//! No-RAR deobfuscation matrix fixtures.
//!
//! Bare files on the wire - random subject, random yEnc `name=` - with
//! the real names living only in the PAR2 FileDesc packets. No archive
//! anywhere. Each test here is one row of the no-RAR capability matrix
//! (research/NORAR-DEOBF-MATRIX-2026-08-29.md): it pins what the engine
//! DOES today, and a row whose today-behavior is a gap says so in its
//! own comment rather than papering over it.
//!
//! A sibling-dir child of e2e.rs (the e2e_sniffedpar2 pattern) so the
//! parent stays inside its size-gate baseline; helpers via `super::*`.
//!
//! Two shapes here cannot come out of par2cmdline at all, so their
//! recovery sets are PATCHED after `par2 create`: a FileDesc for a
//! 0-byte file (par2cmdline prints "Skipping 0 byte file" and omits
//! it), and hostile/duplicate FileDesc names (`../evil.bin`, two
//! descriptors sharing one name). The patch edits the FileDesc body in
//! place and reseals the packet MD5 (offset 16 covers setid+type+body,
//! per the spec header in nzbkit/src/par2.rs), so every packet still
//! verifies; the stored file id is left alone, because readers key
//! Main/FileDesc/IFSC by the STORED id and never recompute it. Real
//! creators (MultiPar, parpar) emit these shapes natively - the patch
//! stands in for them, not for corruption.

// The M4-26/29/30/31/32 extreme rows, a child module for the same reason
// as the ones below - and because `tests/e2e.rs`, where a sibling DIR
// would have to be declared, is exactly on its own baseline. It reaches
// the builders below through `use super::*`.
mod extreme;
mod par2dialect;

/// M4-64 / M4-65 - what a PAR2 packet must earn before it is believed.
/// Its own file, by the same rule as the modules below: `mod.rs` was at
/// 2,912 of its size-gate 3,000-line ceiling on 30 Aug 2026 with several
/// lanes appending to it at once.
mod packettrust;

use super::*;
use md5::Digest as _;

/// Cases 18a/18b/18c, the split-join family - see its own header.
mod join;
use crate::payloads;
use std::collections::HashSet;

/// M4-18 / M4-19 / M4-28 - the polyglot and `.par2`-name rows, split out
/// on 30 Aug 2026 for the same reason and by the same rule as the two
/// below: three M4 lanes were appending here at once and the merge of
/// two of them put this file 11 lines past the ceiling.
mod polyglot;

/// Wave-4 matrix-read rows M4-33 / M4-34 (the spare rule, and the naming
/// tier under a set that names no payload), a CHILD module for the same
/// size-gate reason as its siblings here.
mod furniture;

/// Wave-4 matrix-read pins (M4-10 / M4-15 / M4-17), in their own file so
/// this one stays inside its size-gate ceiling. A CHILD module, so they
/// reach the builders above through `use super::*` without any of them
/// having to be made `pub(crate)`.
mod pins;

/// Wave-4 rows M4-52 / M4-53 / M4-82 (the `.par2`-named leftover, the
/// sniffed-leftover sweep, and the same door one predicate over),
/// likewise a CHILD module for the size gate.
mod leftovers;

/// Wave-4 matrix-read row M4-70 - the extractor latching the FIRST
/// article's yEnc name, so arrival order decided what the file was
/// called. A CHILD module for the same size-gate reason as its siblings
/// here.
mod namelatch;

/// Wave-4 matrix-read FOURTH pins, rows M4-55 and M4-60, likewise a
/// child module for the size gate.
mod wave4d;

/// Wave-4 rows M4-96 / M4-97 (mixed split-tail width, 5-digit tails),
/// a child module for the same size-gate reason as `wave4d` beside it.
mod wave4e;

/// Wave-4 THIRD extreme pass, rows M4-39 and M4-40, in their own file for
/// the same reason and by the same rule. When they were written this file
/// had 65 lines of headroom and three M4 lanes still appending to it, so
/// 228 lines of new rows had to land somewhere else or redden the gate for
/// whoever pushed next.
mod zipzero;

/// M4-101: an SFX is a program, not a name (`nzbkit::sfx::is_launcher_stub`).
mod sfxstub;
// W4-07 (final capability round, 31 Aug 2026): case-only twins on a
// genuinely CASE-SENSITIVE volume. The publication fold is decided by a
// RUNTIME probe (`nzbkit::disk::case_insensitive_dir`) that no test had
// ever run against a filesystem answering the other way - `hdiutil`
// makes one with no sudo. macOS only; skips elsewhere.
mod casevol;
// M4-16 (same round): one message-id claimed by TWO NZB file groups. A
// segment table keyed on the id rather than on (group, segment) hands
// one file's bytes to another under a clean yEnc CRC.
mod dupseg;

/// Follow-up 13a's row - a claimed identical-head twin donating the run
/// it shares, which is what admits it to the adoption scan at all. Its
/// own file for the same reason as the four above: this one was at
/// 2,928 of the size gate's 3,000 lines when the row was written, with
/// three other lanes appending to it.
mod twin_adopt;

/// Follow-up 13a-1's on-disk-recovery row - the `twin_adopt` post with
/// its PAR2 index missing, so half the declared recovery is already on
/// disk when the fetch is sized. A CHILD module for the size gate, the
/// same as its sibling above; its own header carries the arithmetic.
mod ondisk_recovery;

/// Follow-up 13a-3's row - a slot named by an honest yEnc `name=` the
/// recovery set also declares, over bytes that verify nothing. Its own
/// file for the same reason as `twin_adopt` beside it.
mod shiftname;

/// A 16 KiB head is evidence, not authority - the identity rule M4-03
/// and M4-04 hold at the NAME door, measured at the CONTENT door.
/// Its own file for the same reason as its siblings above.
mod headauth;

/// Row M4-48 - an honest subject carrying a year or a sequel number run
/// onto the title, in its own file for the same reason and by the same
/// rule as its siblings above.
mod honestyear;

/// M4-05 - the zero-byte placeholder tier on the with-set path and the
/// per-entry veto that makes it safe there, in its own file for the same
/// reason and by the same rule. It also holds the successor to the pin
/// that used to close this file, `the_sfv_zero_byte_tier_does_not_fire_
/// when_a_set_is_present`, whose fixture WAS M4-05's shape; see the
/// module header there for why it is gone rather than moved.
mod sfvmixed;

/// The checksum-sidecar tier itself - `.sfv`, `.md5`, and the three
/// things a sidecar may never do - gathered out of two ranges of this
/// file on 31 Aug 2026 for the same reason and by the same rule as its
/// siblings above: 2,903 of 3,000 lines with about a dozen wave-4 lanes
/// appending, and 11 of those lines had arrived DURING one survey of the
/// margin. Fourteen rows, one subject; see its module header for why
/// `sfvmixed` beside it stays separate.
mod sidecars;

/// Wave-4 FOURTH extreme pass, rows M4-56 / M4-57 / M4-58 / M4-62, in
/// their own file for the same reason and by the same rule as the four
/// above: this file was 94 lines under the ceiling when they were
/// written, with about a dozen M4 lanes still appending to it.
mod repairpins;

/// Row M4-86 - a PAR2 FileDesc name that is not valid UTF-8, against a
/// yEnc header that spells the same name well-formed. Its own file for
/// the same reason and by the same rule as its siblings above.
mod encoding;

/// The PRODUCER half of this family - `nzbfast post --obfuscate --par2`
/// emitting the shape every other row here consumes, and the round trip
/// back through the real `get`. Claim `post-norar-mode`. Its own file
/// for the same reason and by the same rule as its siblings above.
mod postmode;

/// GH #63's arm of the same guard, on a DAMAGED post - claim
/// `filedesc-refusal-under-damage`. Its own file for the same reason and
/// by the same rule as its siblings above.
mod sixtythreedamage;

/// What the publish PLAN owes a slot that moves and comes BACK - claim
/// `publishplan-model-vs-deferred-rename`, the deferral above crossed
/// with `publishplan::plan_publish_names`. Its own file for the same
/// reason and by the same rule as its siblings above.
mod deferredcross;

/// The PAR2 file id of a would-be FileDesc: MD5 of (md5_16k + length +
/// unpadded name), verified against par2cmdline output. The twin tests
/// use it to ORDER their posts so the live tier's first claim is
/// deterministically the crossed one - Main lists files fid-sorted, and
/// the first head to complete claims the first unclaimed descriptor.
fn par2_file_id(data: &[u8], name: &str) -> [u8; 16] {
    let head = &data[..data.len().min(16384)];
    let h16: [u8; 16] = md5::Md5::digest(head).into();
    let mut h = md5::Md5::new();
    h.update(h16);
    h.update((data.len() as u64).to_le_bytes());
    h.update(name.as_bytes());
    h.finalize().into()
}

/// (start, total_len, type) of every structurally valid packet.
pub(super) fn packets(data: &[u8]) -> Vec<(usize, usize, [u8; 16])> {
    let mut out = Vec::new();
    let mut off = 0usize;
    while off + 64 <= data.len() {
        let Some(rel) = data[off..].windows(8).position(|w| w == b"PAR2\0PKT") else {
            break;
        };
        let start = off + rel;
        if start + 64 > data.len() {
            break;
        }
        let len = u64::from_le_bytes(data[start + 8..start + 16].try_into().unwrap()) as usize;
        if len < 64 || start + len > data.len() {
            off = start + 1;
            continue;
        }
        out.push((start, len, data[start + 48..start + 64].try_into().unwrap()));
        off = start + len;
    }
    out
}

/// Recompute the packet MD5 (offset 16..32 = MD5 of setid+type+body)
/// after a body edit, so the parser's per-packet verification passes.
pub(super) fn reseal(data: &mut [u8], start: usize, len: usize) {
    let sum: [u8; 16] = md5::Md5::digest(&data[start + 32..start + len]).into();
    data[start + 16..start + 32].copy_from_slice(&sum);
}

/// The name region of a FileDesc packet body (null-padded tail).
pub(super) fn filedesc_name(data: &[u8], start: usize, len: usize) -> String {
    let raw = &data[start + 120..start + len];
    let end = raw.iter().rposition(|&b| b != 0).map_or(0, |i| i + 1);
    String::from_utf8_lossy(&raw[..end]).into_owned()
}

/// Rewrite every FileDesc whose name is `from` to carry `to` instead
/// (null-padded into the same region - `to` must fit). Returns how many
/// packets moved; the same critical packets repeat in every volume, so
/// this is normally > 1 across a full set.
pub(crate) fn rename_filedesc(data: &mut Vec<u8>, from: &str, to: &str) -> usize {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0FileDesc" || filedesc_name(data, start, len) != from {
            continue;
        }
        let region = len - 120;
        assert!(to.len() <= region, "patched name must fit the old region");
        data[start + 120..start + len].fill(0);
        data[start + 120..start + 120 + to.len()].copy_from_slice(to.as_bytes());
        reseal(data, start, len);
        hits += 1;
    }
    hits
}

/// Turn the FileDesc for `name` into a 0-BYTE file: length 0, whole-file
/// and 16k MD5s = MD5 of the empty string, and its IFSC packets dropped
/// (a real creator emits none for an empty file). The file id is left
/// as minted from the 1-byte placeholder - readers use the stored id.
fn empty_filedesc(data: &mut Vec<u8>, name: &str) -> usize {
    let empty: [u8; 16] = md5::Md5::digest(b"").into();
    let mut fid: Option<[u8; 16]> = None;
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0FileDesc" || filedesc_name(data, start, len) != name {
            continue;
        }
        fid = Some(data[start + 64..start + 80].try_into().unwrap());
        data[start + 80..start + 96].copy_from_slice(&empty);
        data[start + 96..start + 112].copy_from_slice(&empty);
        data[start + 112..start + 120].copy_from_slice(&0u64.to_le_bytes());
        reseal(data, start, len);
        hits += 1;
    }
    if let Some(fid) = fid {
        // Splice the placeholder's IFSC packets out, back to front so
        // the recorded offsets stay valid while draining.
        let mut spans: Vec<(usize, usize)> = packets(data)
            .into_iter()
            .filter(|&(s, l, t)| {
                &t == b"PAR 2.0\0IFSC\0\0\0\0" && data[s + 64..s + 80] == fid && l >= 80
            })
            .map(|(s, l, _)| (s, l))
            .collect();
        spans.reverse();
        for (s, l) in spans {
            data.drain(s..s + l);
        }
    }
    hits
}

/// `add_par2` with a patch pass over every generated .par2 blob before
/// it is posted (under its real name - the payload carries the
/// obfuscation in these fixtures, the recovery set is announced).
pub(crate) fn add_par2_patched(
    fx: &mut Fixture,
    redundancy: u32,
    files: &[&str],
    art_size: usize,
    patch: impl Fn(&mut Vec<u8>),
) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg(format!("-r{redundancy}"))
        .arg("-q")
        .arg("testset")
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        let mut data = std::fs::read(&p).unwrap();
        patch(&mut data);
        let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
        fx.nzb_files.push((name, segs));
        std::fs::remove_file(&p).unwrap();
    }
    true
}

/// Write a payload into a SUBDIRECTORY of the fixture (so `par2 create`
/// records the relative path in the FileDesc), posted under an
/// obfuscated name - subject and yEnc name both the hash.
fn add_tree_file_obfuscated(fx: &mut Fixture, rel: &str, posted: &str, data: &[u8], art: usize) {
    let path = fx.dir.join(rel);
    std::fs::create_dir_all(path.parent().unwrap()).unwrap();
    std::fs::write(&path, data).unwrap();
    let tag = format!("{}-{}", posted.replace('.', "_"), fx.nzb_files.len());
    let segs = make_file_articles(posted, data, art, &tag, &mut fx.articles);
    fx.nzb_files.push((posted.to_string(), segs));
}

/// One undamaged no-RAR run: mock server, config, `get`, log + rc.
pub(crate) async fn run_norar(fx: &Fixture) -> (String, bool, PathBuf) {
    run_norar_chaos(fx, Chaos::default()).await
}

/// [`run_norar`] with injected faults - wave-2 rows (a damaged article
/// under a manifest-only set, PAR2 articles arriving last) need them.
pub(crate) async fn run_norar_chaos(fx: &Fixture, chaos: Chaos) -> (String, bool, PathBuf) {
    let srv = MockServer::start(fx.articles.clone(), chaos).await;
    let cfg = fx.write_config(&[&srv]);
    let nzb = fx.write_nzb();
    let out = fx.dir.join("out");
    let (log, ok) = tokio::task::spawn_blocking({
        let (cfg, nzb, out) = (cfg.clone(), nzb.clone(), out.clone());
        move || run_get(&cfg, &nzb, &out, &[])
    })
    .await
    .unwrap();
    // Matrix re-runs read the raw engine log per case:
    // NORAR_DUMP_LOG=1 cargo nextest run ... --no-capture. The matrix
    // doc (research/NORAR-DEOBF-MATRIX-2026-08-29.md) quotes these.
    if std::env::var("NORAR_DUMP_LOG").is_ok() {
        eprintln!("==== run log ====\n{log}\n==== end ====");
    }
    (log, ok, out)
}

/// Case 6 of the no-RAR family: a file of EXACTLY 16384 bytes, the
/// boundary where head = whole file and md5_16k = whole-file MD5. The
/// live tier must still claim it and settle must still publish the
/// FileDesc name.
#[tokio::test(flavor = "multi_thread")]
async fn a_file_of_exactly_16384_bytes_lands_under_its_filedesc_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norar16k");
    let data = payload(16384, 50);
    fx.add_file_renamed_by_par2("Exact.Head.bin", "Xk2vRq81LmZ", &data, 6_000);
    assert!(fx.add_par2(20, &["Exact.Head.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "exact-16384 post failed:\n{log}");
    let got = std::fs::read(out.join("Exact.Head.bin"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Xk2vRq81LmZ").exists(),
        "the obfuscated source name survived beside the published one:\n{log}"
    );
}

/// Builds the identical-head twin fixture: two files of the SAME
/// length whose first 16 KiB are IDENTICAL (zero-filled heads - disk
/// images, padded VOBs). The live tier's (length, md5_16k) key cannot
/// tell them apart; it used to take the first unclaimed hit, so WHICH
/// descriptor each slot claimed was a worker-thread race (matrix F1,
/// measured 29 Aug 2026: crossed in roughly 1 run in 5 on a loaded
/// box). The tier now DECLINES the ambiguity and finish settles each
/// slot by whole-file MD5 (live.rs try_match_whole), so the pairing is
/// deterministic. Still posted crossed against fid order, so a matcher
/// that regressed to first-hit would cross again and fail below.
fn twin_fixture(
    tag: &str,
    name_a: &str,
    name_b: &str,
    seeds: (u8, u8),
) -> (Fixture, Vec<u8>, Vec<u8>) {
    let mut fx = Fixture::new(tag);
    let mut a = vec![0u8; 200_000];
    let mut b = vec![0u8; 200_000];
    a[20_000..].copy_from_slice(&payload(180_000, seeds.0));
    b[20_000..].copy_from_slice(&payload(180_000, seeds.1));
    if par2_file_id(&a, name_a) < par2_file_id(&b, name_b) {
        fx.add_file_renamed_by_par2(name_b, "Ty8cKd31VbN", &b, 40_000);
        fx.add_file_renamed_by_par2(name_a, "Jm5nPw72QsX", &a, 40_000);
    } else {
        fx.add_file_renamed_by_par2(name_a, "Jm5nPw72QsX", &a, 40_000);
        fx.add_file_renamed_by_par2(name_b, "Ty8cKd31VbN", &b, 40_000);
    }
    (fx, a, b)
}

/// Case 5 at r=100: both payloads byte-exact under their own FileDesc
/// names, with NO repair spend - the post arrived intact, and since the
/// md5-16k tier declines the twin ambiguity (settled by whole-file MD5
/// at finish, matrix F1 fix) a crossed claim can no longer turn intact
/// twins into 900/1000 "bad" blocks each and a full phantom repair.
#[tokio::test(flavor = "multi_thread")]
async fn an_identical_head_same_length_pair_ends_byte_exact_under_the_right_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (mut fx, a, b) = twin_fixture("norartwin", "Twin.Alpha.vob", "Twin.Beta.vob", (51, 52));
    assert!(fx.add_par2(100, &["Twin.Alpha.vob", "Twin.Beta.vob"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "identical-head pair failed:\n{log}");
    assert!(
        !log.contains("blocks bad"),
        "an intact twin post read as damaged (crossed claim is back):\n{log}"
    );
    assert!(
        !log.contains("repair complete"),
        "an intact twin post paid a repair:\n{log}"
    );
    let got_a = std::fs::read(out.join("Twin.Alpha.vob"))
        .unwrap_or_else(|e| panic!("Twin.Alpha.vob missing: {e}\n{log}"));
    let got_b = std::fs::read(out.join("Twin.Beta.vob"))
        .unwrap_or_else(|e| panic!("Twin.Beta.vob missing: {e}\n{log}"));
    assert!(
        got_a == a,
        "Twin.Alpha.vob carries the wrong bytes (crossed claim published)\n{log}"
    );
    assert!(
        got_b == b,
        "Twin.Beta.vob carries the wrong bytes (crossed claim published)\n{log}"
    );
}

/// Case 5 at a REALISTIC redundancy (r=10) - the fixture that used to
/// pin matrix F1's disjunction: the md5-16k tier took the FIRST
/// unclaimed descriptor, a crossed claim read 900/1000 blocks of each
/// intact twin as damage, 100 recovery blocks lost to 1800 phantoms,
/// and the whole job failed and quarantined - roughly 1 run in 5 on a
/// loaded box. The tier now declines the ambiguity and finish settles
/// each slot by whole-file MD5, so this asserts the always-correct
/// outcome unconditionally: byte-exact, right names, no repair spend.
#[tokio::test(flavor = "multi_thread")]
async fn an_identical_head_pair_at_low_redundancy_is_at_the_claim_races_mercy() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let (mut fx, a, b) = twin_fixture("norartwinlo", "Low.Alpha.vob", "Low.Beta.vob", (66, 67));
    assert!(fx.add_par2(10, &["Low.Alpha.vob", "Low.Beta.vob"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "an intact identical-head pair failed at r=10:\n{log}");
    assert!(
        !log.contains("blocks bad"),
        "an intact twin post read as damaged (crossed claim is back):\n{log}"
    );
    assert!(
        !log.contains("repair complete"),
        "an intact twin post paid a repair:\n{log}"
    );
    let got_a = std::fs::read(out.join("Low.Alpha.vob"))
        .unwrap_or_else(|e| panic!("Low.Alpha.vob missing: {e}\n{log}"));
    let got_b = std::fs::read(out.join("Low.Beta.vob"))
        .unwrap_or_else(|e| panic!("Low.Beta.vob missing: {e}\n{log}"));
    assert!(
        got_a == a && got_b == b,
        "twin published under the wrong name\n{log}"
    );
}

/// Case 5, three ways: THREE same-length files sharing one 16 KiB head.
/// The first slot to finish resolves against three candidates by
/// whole-file MD5, the second against two, the last claims the unique
/// survivor through the ordinary md5-16k tier - every pairing correct,
/// still at r=10 where a single cross would kill the job.
#[tokio::test(flavor = "multi_thread")]
async fn three_identical_head_files_all_land_under_their_own_names() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norartriplet");
    let names = ["Trip.One.vob", "Trip.Two.vob", "Trip.Three.vob"];
    let posted = ["Ab1xQw92LmD", "Cd2yRe83NkF", "Ef3zSt74PjG"];
    let mut payloads = Vec::new();
    for (i, (name, post)) in names.iter().zip(posted).enumerate() {
        let mut d = vec![0u8; 200_000];
        d[20_000..].copy_from_slice(&payload(180_000, 90 + i as u8));
        fx.add_file_renamed_by_par2(name, post, &d, 40_000);
        payloads.push(d);
    }
    assert!(fx.add_par2(10, &names, 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "an intact identical-head triplet failed:\n{log}");
    assert!(
        !log.contains("blocks bad") && !log.contains("repair complete"),
        "an intact triplet read as damaged or paid a repair:\n{log}"
    );
    for (name, want) in names.iter().zip(&payloads) {
        let got =
            std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{name} missing: {e}\n{log}"));
        assert!(got == *want, "{name} carries another twin's bytes\n{log}");
    }
}

/// Case 3, CLOSED: a 0-byte member whose real name lives only in a
/// FileDesc (the VIDEO_TS placeholder shape). No content tier can claim
/// len == 0 (live.rs:1832, adopt.rs:98/249, settle.rs:1461) - and none
/// may loosen - so `get/emptydesc.rs` lands it at settle instead: a
/// zero-length descriptor whose MD5 is the empty digest is proven by
/// construction, and the empty file is materialized (or an arrived
/// empty slot file renamed) under the FileDesc name. par2cmdline
/// refuses to even describe an empty file, so the set here is patched
/// to the shape MultiPar/parpar emit natively. This row used to pin the
/// gap; `zero-byte-filedesc-rename` flipped its last assertion.
/// `e2e_emptydesc` holds the deeper pins (both tiers, red-verified).
#[tokio::test(flavor = "multi_thread")]
async fn a_zero_byte_filedesc_member_materializes_under_its_real_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarzero");
    let data = payload(300_000, 53);
    fx.add_file("Feature.Main.mkv", &data, 40_000);
    // The placeholder exists only long enough for par2 create to
    // describe it; it is never posted, and the patch below rewrites its
    // FileDesc to the 0-byte truth before the set goes on the wire.
    std::fs::write(fx.dir.join("VIDEO_TS.bup"), [0u8]).unwrap();
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["Feature.Main.mkv", "VIDEO_TS.bup"],
        40_000,
        |blob| {
            empty_filedesc(blob, "VIDEO_TS.bup");
        },
    ));
    std::fs::remove_file(fx.dir.join("VIDEO_TS.bup")).unwrap();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(
        ok,
        "a clean post with an empty covered member failed:\n{log}"
    );
    let got = std::fs::read(out.join("Feature.Main.mkv"))
        .unwrap_or_else(|e| panic!("payload missing: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    let bup = std::fs::metadata(out.join("VIDEO_TS.bup"))
        .unwrap_or_else(|e| panic!("the 0-byte member never landed: {e}\n{log}"));
    assert_eq!(bup.len(), 0, "the placeholder must be empty\n{log}");
}

/// Case 4, CLOSED by `relpath-preserve-tree` (fd455c01b): a directory
/// tree in FileDesc names (`VIDEO_TS/VTS_01_1.VOB`) now lands as the
/// TREE - `sanitize_out_name` honors provably safe relative paths and
/// flattens only what it cannot prove safe. This row asserted the old
/// flattening until 30 Aug 2026 and was red from the moment the
/// preservation landed; the deeper pins live in `e2e_relpath`.
#[tokio::test(flavor = "multi_thread")]
async fn a_directory_tree_in_filedesc_names_lands_intact() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norartree");
    let vob = payload(120_000, 54);
    let bup = payload(8_000, 55);
    add_tree_file_obfuscated(
        &mut fx,
        "VIDEO_TS/VTS_01_1.VOB",
        "Gh3sLp94WtY",
        &vob,
        40_000,
    );
    add_tree_file_obfuscated(
        &mut fx,
        "VIDEO_TS/VTS_01_0.BUP",
        "Zc6xNv27KqM",
        &bup,
        40_000,
    );
    assert!(fx.add_par2(
        20,
        &["VIDEO_TS/VTS_01_1.VOB", "VIDEO_TS/VTS_01_0.BUP"],
        40_000
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "tree-named post failed:\n{log}");
    let got_vob = std::fs::read(out.join("VIDEO_TS").join("VTS_01_1.VOB"))
        .unwrap_or_else(|e| panic!("VIDEO_TS/VTS_01_1.VOB missing from the tree: {e}\n{log}"));
    let got_bup = std::fs::read(out.join("VIDEO_TS").join("VTS_01_0.BUP"))
        .unwrap_or_else(|e| panic!("VIDEO_TS/VTS_01_0.BUP missing from the tree: {e}\n{log}"));
    assert!(
        got_vob == vob && got_bup == bup,
        "tree payload not byte-exact\n{log}"
    );
    assert!(
        !out.join("VIDEO_TS_VTS_01_1.VOB").exists(),
        "the old flattened name appeared beside the preserved tree:\n{log}"
    );
}

/// Case 8: duplicate BASENAMES from different directories. Since
/// fd455c01b each keeps its own TREE (`a/readme.txt`, `b/readme.txt`),
/// so no collision arises on this shape at all - previously the
/// flattening kept them apart as `a_readme.txt` / `b_readme.txt`.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_basenames_across_directories_keep_their_trees() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardup");
    let ra = payload(30_000, 56);
    let rb = payload(45_000, 57);
    add_tree_file_obfuscated(&mut fx, "a/readme.txt", "Wq1bXs63JnH", &ra, 40_000);
    add_tree_file_obfuscated(&mut fx, "b/readme.txt", "Fk9mDt48RvC", &rb, 40_000);
    assert!(fx.add_par2(20, &["a/readme.txt", "b/readme.txt"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "dup-basename post failed:\n{log}");
    let got_a = std::fs::read(out.join("a").join("readme.txt"))
        .unwrap_or_else(|e| panic!("a/readme.txt missing: {e}\n{log}"));
    let got_b = std::fs::read(out.join("b").join("readme.txt"))
        .unwrap_or_else(|e| panic!("b/readme.txt missing: {e}\n{log}"));
    assert!(
        got_a == ra && got_b == rb,
        "dup-basename payload not byte-exact\n{log}"
    );
}

/// `sub/movie.mkv` beside `sub_movie.mkv`: before fd455c01b the
/// flattening mapped both onto one on-disk name and the publish claim
/// had to disambiguate (`{slot:03}-` form). With safe trees preserved
/// the pair no longer collides at all - the tree name keeps its
/// directory and the flat name stays flat. Both must land byte-exact
/// and neither may be renamed over the other (published_names.rs still
/// guards the shapes that DO collide, e.g. `../movie.mkv`).
#[tokio::test(flavor = "multi_thread")]
async fn a_tree_name_and_its_flat_lookalike_land_apart() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarcoll");
    let inner = payload(60_000, 58);
    let flat = payload(70_000, 59);
    add_tree_file_obfuscated(&mut fx, "sub/movie.mkv", "Pt4gHj52BwQ", &inner, 40_000);
    add_tree_file_obfuscated(&mut fx, "sub_movie.mkv", "Ln7yVz16McK", &flat, 40_000);
    assert!(fx.add_par2(20, &["sub/movie.mkv", "sub_movie.mkv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "tree-and-flat-lookalike post failed:\n{log}");
    let got_tree = std::fs::read(out.join("sub").join("movie.mkv"))
        .unwrap_or_else(|e| panic!("sub/movie.mkv missing from its tree: {e}\n{log}"));
    let got_flat = std::fs::read(out.join("sub_movie.mkv"))
        .unwrap_or_else(|e| panic!("flat sub_movie.mkv missing: {e}\n{log}"));
    assert!(
        got_tree == inner && got_flat == flat,
        "the lookalike pair's bytes crossed or corrupted\n{log}"
    );
}

/// Case 9, the SECURITY row: a traversal attempt in a FileDesc name
/// (`../evil.bin`). The name is poster-typed bytes; containment is the
/// only right answer. The payload must land INSIDE the job directory
/// and nothing may appear beside it.
#[tokio::test(flavor = "multi_thread")]
async fn a_traversal_filedesc_name_stays_contained() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norartrav");
    let data = payload(50_000, 60);
    fx.add_file_renamed_by_par2("zzzzevil.bin", "Bv2wQm85XdF", &data, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["zzzzevil.bin"],
        40_000,
        |blob| {
            let n = rename_filedesc(blob, "zzzzevil.bin", "../evil.bin");
            assert!(n > 0, "the traversal patch matched no FileDesc");
        }
    ));
    // `fx.dir`'s parent is the PER-USER temp dir, shared by every lane
    // on this box - a stale escapee from some earlier run (one 80 KB
    // `evil.bin` sat there on 29 Aug 2026 and failed this test forever)
    // must not fail this one. The fixture dir itself is fresh and owned,
    // so that probe stays strict; the shared probe asserts no NEW file.
    let outside = fx.dir.join("../evil.bin");
    let outside_pre = outside.exists();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "traversal-named post failed:\n{log}");
    // Nothing escaped: the fixture dir (out's parent) gained no file.
    assert!(
        !fx.dir.join("evil.bin").exists() && (outside_pre || !outside.exists()),
        "a FileDesc name escaped the output directory:\n{log}"
    );
    // The payload is inside, byte-exact, under the sanitized name.
    let contained = std::fs::read_dir(&out)
        .unwrap()
        .flatten()
        .any(|e| std::fs::read(e.path()).is_ok_and(|b| b == data));
    assert!(
        contained,
        "payload not found inside the output directory\n{log}"
    );
}

/// Case 12: two FileDesc entries carrying the SAME name for different
/// files. Content ties each slot to its own descriptor; the publish
/// pass then meets two claims on one name and must keep both files.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_filedesc_names_keep_both_files() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardupfd");
    let one = payload(40_000, 61);
    let two = payload(55_000, 62);
    fx.add_file_renamed_by_par2("dupXa.bin", "Rz5jTn93GcW", &one, 40_000);
    fx.add_file_renamed_by_par2("dupXb.bin", "Hd8pYw41SkV", &two, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["dupXa.bin", "dupXb.bin"],
        40_000,
        |blob| {
            rename_filedesc(blob, "dupXa.bin", "dupfil.bin");
            rename_filedesc(blob, "dupXb.bin", "dupfil.bin");
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "duplicate-FileDesc-name post failed:\n{log}");
    let mut found = 0;
    for e in std::fs::read_dir(&out).unwrap().flatten() {
        if let Ok(bytes) = std::fs::read(e.path())
            && (bytes == one || bytes == two)
        {
            found += 1;
        }
    }
    assert_eq!(found, 2, "a duplicate-named file was lost\n{log}");
}

/// Case 13: the PAR2 set covers only a SUBSET of the post. The covered
/// file deobfuscates; the uncovered one has no name anywhere and must
/// keep its posted hash - and its presence must not fail the job.
#[tokio::test(flavor = "multi_thread")]
async fn par2_covering_a_subset_renames_only_what_it_covers() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarsub");
    let covered = payload(80_000, 63);
    let stray = payload(65_000, 64);
    fx.add_file_renamed_by_par2("Named.By.Par2.bin", "Cw3fJq67ZtL", &covered, 40_000);
    fx.add_file_obfuscated("Ux9kBs25NhD", "Ux9kBs25NhD", &stray, 40_000);
    assert!(fx.add_par2(20, &["Named.By.Par2.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "subset-covered post failed:\n{log}");
    let got = std::fs::read(out.join("Named.By.Par2.bin"))
        .unwrap_or_else(|e| panic!("covered payload missing under its name: {e}\n{log}"));
    assert!(got == covered, "covered payload not byte-exact\n{log}");
    let got_stray = std::fs::read(out.join("Ux9kBs25NhD"))
        .unwrap_or_else(|e| panic!("uncovered payload missing under its posted name: {e}\n{log}"));
    assert!(
        got_stray == stray,
        "uncovered payload not byte-exact\n{log}"
    );
}

/// Case 2, MEASURE ONLY on this path: an extensionless obfuscated
/// payload with NO PAR2 name anywhere. The `get` CLI has no rename
/// ladder of its own - the container-sniff extension resolution
/// (never `.bin`, real extensions only) is the daemon's post-processing
/// pass (smart/videoext.rs, smart/audioname.rs, unit-tested there). So
/// the CLI leg's honest row is: the hash name survives, the bytes are
/// exact, and the file is not deleted as junk.
#[tokio::test(flavor = "multi_thread")]
async fn an_extensionless_unnamed_payload_keeps_its_hash_on_the_cli_path() {
    let mut fx = Fixture::new("norarext");
    // An MPEG-TS shaped payload: 0x47 sync every 188 bytes, which the
    // daemon-side sniff recognises (videoext.rs) and nothing here may
    // delete as junk.
    let mut data = payload(56_400, 65);
    for i in (0..data.len()).step_by(188) {
        data[i] = 0x47;
    }
    fx.add_file_obfuscated("Vn6tRc39PmB", "Vn6tRc39PmB", &data, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "extensionless unnamed post failed:\n{log}");
    let got = std::fs::read(out.join("Vn6tRc39PmB"))
        .unwrap_or_else(|e| panic!("payload missing under its posted hash: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
}

// ---------------------------------------------------------------------------
// Wave 2 (cases 16-25): lighter-weight obfuscation, poster-efficiency
// angle. Same discipline as above - each test pins what the engine DOES
// today, and a gap row says so in its own comment.
// ---------------------------------------------------------------------------

/// `add_par2`, posting ONLY the index file (`<base>.par2` - FileDesc +
/// IFSC + Main, ZERO recovery volumes). par2cmdline always creates the
/// volumes; a manifest-only POSTER simply does not upload them, which is
/// what this models. The redundancy argument only shapes the discarded
/// volumes.
fn add_par2_index_only(fx: &mut Fixture, files: &[&str], art_size: usize) -> bool {
    add_par2_named(fx, "testset", files, art_size, true)
}

/// `add_par2` with the SET BASE NAME as a parameter (two independent
/// sets in one post need two names, like every real multi-set post) and
/// an index-only switch. Collects exactly this base's outputs, so
/// sequential calls compose.
fn add_par2_named(
    fx: &mut Fixture,
    base: &str,
    files: &[&str],
    art_size: usize,
    index_only: bool,
) -> bool {
    let st = Command::new("par2")
        .arg("create")
        .arg("-r20")
        .arg("-q")
        .arg(base)
        .args(files)
        .current_dir(&fx.dir)
        .status();
    match st {
        Ok(s) if s.success() => {}
        _ => return false,
    }
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")
                && p.file_name()
                    .is_some_and(|n| n.to_string_lossy().starts_with(base)))
            .then_some(p)
        })
        .collect();
    par2s.sort();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().to_string();
        if !index_only || name == format!("{base}.par2") {
            let data = std::fs::read(&p).unwrap();
            let tag = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
            let segs = make_file_articles(&name, &data, art_size, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).unwrap();
    }
    true
}

/// Post `data` under an obfuscated subject with a CALLER-CHOSEN yEnc
/// `name=` per part - the per-article-random-name and empty-name rows.
/// The real file is written to disk under `real_name` so `add_par2`
/// covers it; nothing on the wire carries that name.
///
/// `pub(crate)` for ONE reader outside this module:
/// `e2e_resume::a_kill_nine_does_not_leave_a_contested_file_under_the_decoy_name`,
/// which needs this builder AND that module's `kill9_run1`. Copying
/// either into the other module would make a second spelling of a
/// fixture, which is the copy-paste-sibling drift this tree keeps
/// paying for; the M4-70 rows themselves stay here.
pub(crate) fn add_file_yenc_names(
    fx: &mut Fixture,
    real_name: &str,
    subject: &str,
    data: &[u8],
    art_size: usize,
    name_of: impl Fn(u32) -> String,
) {
    std::fs::write(fx.dir.join(real_name), data).unwrap();
    let total = data.len().div_ceil(art_size).max(1) as u32;
    let tag = format!("{}-{}", subject.replace('.', "_"), fx.nzb_files.len());
    let mut segs = Vec::new();
    for (i, chunk) in data.chunks(art_size).enumerate() {
        let part = i as u32 + 1;
        let begin = (i * art_size) as u64 + 1;
        let article = nzbkit::yenc::encode(
            &name_of(part),
            data.len() as u64,
            Some((part, total)),
            begin,
            chunk,
        );
        let id = format!("{tag}-{part}@mock");
        segs.push((id.clone(), article.len() as u64, part));
        fx.articles.insert(format!("<{id}>"), article);
    }
    fx.nzb_files.push((subject.to_string(), segs));
}

/// Post `data` with LYING yEnc headers: every `=ybegin size=` overstates
/// the file by `size_lie` bytes and every `total=` overstates the part
/// count, while the `=ypart begin/end` ranges stay true (a real poster's
/// tooling gets the ranges right or nothing decodes at all).
fn add_file_lying_headers(
    fx: &mut Fixture,
    real_name: &str,
    subject: &str,
    data: &[u8],
    art_size: usize,
    size_lie: u64,
) {
    let lied = data.len() as u64 + size_lie;
    let total = data.len().div_ceil(art_size).max(1) as u32;
    std::fs::write(fx.dir.join(real_name), data).unwrap();
    let tag = format!("{}-{}", subject.replace('.', "_"), fx.nzb_files.len());
    let mut segs = Vec::new();
    for (i, chunk) in data.chunks(art_size).enumerate() {
        let part = i as u32 + 1;
        let begin = (i * art_size) as u64 + 1;
        let article = nzbkit::yenc::encode(
            &format!("{subject}.dat"),
            lied,
            Some((part, total + 9)),
            begin,
            chunk,
        );
        let id = format!("{tag}-{part}@mock");
        segs.push((id.clone(), article.len() as u64, part));
        fx.articles.insert(format!("<{id}>"), article);
    }
    fx.nzb_files.push((subject.to_string(), segs));
}

/// Case 16: MANIFEST-ONLY PAR2 - the poster ships just the .par2 index
/// (FileDesc + IFSC, zero recovery volumes), kilobytes buying names and
/// verification with no redundancy spend. The lightest possible full
/// obfuscation; rename and verify must both work with 0 recovery blocks.
#[tokio::test(flavor = "multi_thread")]
async fn a_manifest_only_par2_set_renames_and_verifies_with_zero_recovery() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarmanif");
    let data = payload(120_000, 70);
    fx.add_file_renamed_by_par2("Manifest.Only.mkv", "Qd7wPk15RzT", &data, 40_000);
    assert!(add_par2_index_only(&mut fx, &["Manifest.Only.mkv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "manifest-only post failed:\n{log}");
    let got = std::fs::read(out.join("Manifest.Only.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Qd7wPk15RzT").exists(),
        "the obfuscated source name survived beside the published one:\n{log}"
    );
}

/// Case 16, the damage half: one corrupt article under a manifest-only
/// set. Zero recovery blocks means nothing can repair it - the job must
/// FAIL CLEANLY (an honest terminal verdict, promptly), never wedge and
/// never publish rc=0 over a known-bad payload.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_article_under_a_manifest_only_set_fails_cleanly() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarmanifbad");
    let data = payload(120_000, 71);
    fx.add_file_renamed_by_par2("Manifest.Dmg.mkv", "Vb3kWn82LqS", &data, 40_000);
    assert!(add_par2_index_only(&mut fx, &["Manifest.Dmg.mkv"], 40_000));
    let chaos = Chaos {
        corrupt: std::iter::once("<Vb3kWn82LqS-0-2@mock>".to_string()).collect(),
        ..Chaos::default()
    };
    let (log, ok, _out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        !ok,
        "a damaged article under a 0-recovery set was called a success:\n{log}"
    );
}

/// Case 17: the PAR2 articles arrive LAST - every payload article has
/// settled before the first recovery-set byte shows up (cold-storage
/// dead air on exactly the par2 ids). The rename must still land; a job
/// finishing under hashes here would mean naming depends on arrival
/// order.
#[tokio::test(flavor = "multi_thread")]
async fn par2_arriving_after_the_payload_settles_still_renames() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarlate");
    let data = payload(80_000, 72);
    fx.add_file_renamed_by_par2("Late.Names.mkv", "Hs4jRb96TmW", &data, 20_000);
    assert!(fx.add_par2(20, &["Late.Names.mkv"], 40_000));
    let slow: std::collections::HashMap<String, u64> = fx
        .articles
        .keys()
        .filter(|k| k.contains("par2"))
        .map(|k| (k.clone(), 800))
        .collect();
    assert!(!slow.is_empty(), "no par2 articles found to delay");
    let chaos = Chaos {
        slow_ttfb: slow,
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "late-par2 post failed:\n{log}");
    let got = std::fs::read(out.join("Late.Names.mkv")).unwrap_or_else(|e| {
        panic!("late names never landed - job finished under hashes: {e}\n{log}")
    });
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// Case 19: per-article RANDOM yEnc `name=` (every article of one file
/// differs) and the EMPTY-name variant. Free for the poster; breaks
/// clients that key articles to files by yEnc name. NZB segment
/// grouping must make us immune.
#[tokio::test(flavor = "multi_thread")]
async fn per_article_random_and_empty_yenc_names_do_not_break_grouping() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarnames");
    let va = payload(90_000, 75);
    let vb = payload(70_000, 76);
    add_file_yenc_names(&mut fx, "Names.Vary.bin", "Cm8pQz62WfR", &va, 30_000, |p| {
        format!("Rnd{p}x{}Qv.tmp", p * 37)
    });
    add_file_yenc_names(
        &mut fx,
        "Names.Empty.bin",
        "Tj3sLk97GbY",
        &vb,
        30_000,
        |_| String::new(),
    );
    assert!(fx.add_par2(20, &["Names.Vary.bin", "Names.Empty.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "random/empty yEnc-name post failed:\n{log}");
    let got_a = std::fs::read(out.join("Names.Vary.bin"))
        .unwrap_or_else(|e| panic!("per-article-name payload missing: {e}\n{log}"));
    let got_b = std::fs::read(out.join("Names.Empty.bin"))
        .unwrap_or_else(|e| panic!("empty-name payload missing: {e}\n{log}"));
    assert!(got_a == va && got_b == vb, "payload not byte-exact\n{log}");
}

/// Case 20 (matrix finding F5, CLOSED): LYING yEnc headers -
/// `=ybegin size=` overstates the file by 77,777 bytes, `total=`
/// overstates the parts, while the `=ypart` ranges stay true. The
/// slot is preallocated at the DECLARED size; until 30 Aug 2026
/// nothing truncated it back, and the published file was the payload
/// plus 77,777 zero bytes of tail at rc=0 with verify green. Settle
/// now holds the published length to the FileDesc length once every
/// covered block verified, so the landed file is byte-exact.
#[tokio::test(flavor = "multi_thread")]
async fn lying_yenc_size_lands_at_the_filedesc_length() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarliar");
    let data = payload(120_000, 77);
    add_file_lying_headers(
        &mut fx,
        "Liar.Size.bin",
        "Dq1fXv85NcM",
        &data,
        40_000,
        77_777,
    );
    assert!(fx.add_par2(20, &["Liar.Size.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "lying-header post failed outright:\n{log}");
    let got = std::fs::read(out.join("Liar.Size.bin"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(
        got == data,
        "published file not byte-exact ({} bytes vs FileDesc {}) - the \
         F5 settle truncation regressed\n{log}",
        got.len(),
        data.len()
    );
}

/// Case 21: UNCOVERED JUNK beside a covered payload - decoy files in
/// the NZB that no PAR2 set describes, one of them the SAME LENGTH as
/// the covered payload (a decoy aimed at content matching). The junk
/// must not fail the job, must not claim the FileDesc name, and the
/// covered payload must land exact.
#[tokio::test(flavor = "multi_thread")]
async fn uncovered_junk_beside_a_covered_payload_neither_fails_nor_claims() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarjunk");
    let covered = payload(100_000, 78);
    let decoy = payload(100_000, 79); // same length, different bytes
    let crumb = payload(5_000, 80);
    fx.add_file_renamed_by_par2("Covered.Real.mkv", "Zt6hKm29PwB", &covered, 40_000);
    fx.add_file_obfuscated("Ae4rYc73JnV", "Ae4rYc73JnV", &decoy, 40_000);
    fx.add_file_obfuscated("Ox8bFs51QdG", "Ox8bFs51QdG", &crumb, 40_000);
    assert!(fx.add_par2(20, &["Covered.Real.mkv"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "junk-beside-payload post failed:\n{log}");
    let got = std::fs::read(out.join("Covered.Real.mkv"))
        .unwrap_or_else(|e| panic!("covered payload missing under its name: {e}\n{log}"));
    assert!(
        got == covered,
        "covered payload not byte-exact (the same-length decoy claimed the name?)\n{log}"
    );
    let got_decoy = std::fs::read(out.join("Ae4rYc73JnV"))
        .unwrap_or_else(|e| panic!("decoy missing under its posted hash: {e}\n{log}"));
    assert!(got_decoy == decoy, "decoy not byte-exact\n{log}");
    assert!(
        out.join("Ox8bFs51QdG").exists(),
        "small junk file was deleted:\n{log}"
    );
}

/// Case 23: TWO INDEPENDENT PAR2 SETS in one post, each covering half
/// the files. Each set must claim only its own; all four payloads land
/// exact under their own FileDesc names.
#[tokio::test(flavor = "multi_thread")]
async fn two_independent_par2_sets_each_claim_only_their_own() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norartwoset");
    let a1 = payload(50_000, 83);
    let a2 = payload(60_000, 84);
    let b1 = payload(55_000, 85);
    let b2 = payload(65_000, 86);
    fx.add_file_renamed_by_par2("SetA.One.bin", "Wm3nRt68KcE", &a1, 40_000);
    fx.add_file_renamed_by_par2("SetA.Two.bin", "Gv5xHp21YsD", &a2, 40_000);
    fx.add_file_renamed_by_par2("SetB.One.bin", "Ly9kQf47BwZ", &b1, 40_000);
    fx.add_file_renamed_by_par2("SetB.Two.bin", "Sc4jMv83TnU", &b2, 40_000);
    assert!(add_par2_named(
        &mut fx,
        "setA",
        &["SetA.One.bin", "SetA.Two.bin"],
        40_000,
        false
    ));
    assert!(add_par2_named(
        &mut fx,
        "setB",
        &["SetB.One.bin", "SetB.Two.bin"],
        40_000,
        false
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "two-set post failed:\n{log}");
    for (name, want) in [
        ("SetA.One.bin", &a1),
        ("SetA.Two.bin", &a2),
        ("SetB.One.bin", &b1),
        ("SetB.Two.bin", &b2),
    ] {
        let got = std::fs::read(out.join(name))
            .unwrap_or_else(|e| panic!("{name} missing under its FileDesc name: {e}\n{log}"));
        assert!(&got == want, "{name} not byte-exact\n{log}");
    }
}

/// Case 24: WINDOWS-HOSTILE FileDesc names - trailing dot/space,
/// reserved device names (CON, NUL). Poster-typed bytes; must land
/// SANITIZED on every host (sanitize_filename applies the Windows rules
/// unconditionally - disk.rs), so the same post lands the same way on
/// mac and Windows and nothing opens a device.
#[tokio::test(flavor = "multi_thread")]
async fn windows_hostile_filedesc_names_land_sanitized() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarhostile");
    let vcon = payload(30_000, 87);
    let vtrail = payload(35_000, 88);
    let vnul = payload(25_000, 89);
    fx.add_file_renamed_by_par2("zzcona.mkv", "Fh6tPb39WrL", &vcon, 40_000);
    fx.add_file_renamed_by_par2("ztrailXX.txt", "Jq8wSk52NvC", &vtrail, 40_000);
    fx.add_file_renamed_by_par2("zznul1.bin", "Ry2dGm74XcA", &vnul, 40_000);
    assert!(add_par2_patched(
        &mut fx,
        20,
        &["zzcona.mkv", "ztrailXX.txt", "zznul1.bin"],
        40_000,
        |blob| {
            assert!(rename_filedesc(blob, "zzcona.mkv", "CON.mkv") > 0);
            assert!(rename_filedesc(blob, "ztrailXX.txt", "trail.txt. ") > 0);
            assert!(rename_filedesc(blob, "zznul1.bin", "NUL") > 0);
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "hostile-name post failed:\n{log}");
    for (landed, want) in [("_CON.mkv", &vcon), ("trail.txt", &vtrail), ("_NUL", &vnul)] {
        let got = std::fs::read(out.join(landed))
            .unwrap_or_else(|e| panic!("{landed} missing (sanitizer moved?): {e}\n{log}"));
        assert!(&got == want, "{landed} not byte-exact\n{log}");
    }
    assert!(
        !out.join("CON.mkv").exists() && !out.join("NUL").exists(),
        "a reserved device name landed raw:\n{log}"
    );
}

/// Case 25: segments listed OUT OF ORDER in the NZB (and files
/// reversed too). The `number` attributes still tell the truth - only
/// the document order lies. Expected free for us: assembly keys on part
/// numbers, never on listing order. A row competitors can fail.
/// (Random From:/poster per ARTICLE is not representable in an NZB -
/// `poster` is a per-file attribute - so that half is a matrix note.)
#[tokio::test(flavor = "multi_thread")]
async fn shuffled_nzb_segment_order_is_harmless() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarshuf");
    let data = payload(160_000, 90);
    fx.add_file_renamed_by_par2("Shuffled.Order.mkv", "Bn7fJc25MtQ", &data, 40_000);
    assert!(fx.add_par2(20, &["Shuffled.Order.mkv"], 40_000));
    for (_, segs) in fx.nzb_files.iter_mut() {
        segs.reverse();
    }
    fx.nzb_files.reverse();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "shuffled-segment post failed:\n{log}");
    let got = std::fs::read(out.join("Shuffled.Order.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(
        got == data,
        "payload not byte-exact under shuffled listing\n{log}"
    );
}

/// Case 7 on the GET path, finding F9 - CLOSED 30 Aug 2026
/// (`join-block-adoption`): a fully obfuscated payload whose first
/// 16 KiB were damaged AFTER the recovery set was built, so no hash
/// tier can ever claim it. Verify counts the whole target missing and
/// the declared parity (20%) is far short of a whole file -
/// `fetch_and_repair` used to bail right there, failing a post whose
/// bytes were 99.9% on disk (the corpus measured 1984/1986 blocks
/// adoptable). The shortfall now falls through to the repair engines
/// when unclaimed candidates exist: the sliding scan harvests the good
/// blocks, recovery rebuilds the damaged ones, and the spent damaged
/// twin is swept (the spent_donors damaged-twin arm) so the finished
/// job holds exactly the repaired file.
///
/// **`unique_payload`, AND THE TWO BLOCK COUNTS BELOW ARE THE ROW'S
/// TEETH** (30 Aug 2026,
/// `research/E2E-PARITY-BUDGET-CENSUS-2026-08-30.md`). On `payload`
/// this row greened with `0 block(s) rebuilt ... 20 block(s) adopted`:
/// that generator is one periodic sequence of period 131,072, so the
/// block the damage destroyed - bytes 0..10,000 - sits verbatim at
/// offset 131,072 of the same 200,000-byte file, and the sliding scan
/// took it from there. Every word of the sentence above was true of the
/// fixture and none of it was TESTED: recovery rebuilt nothing, and the
/// row would have stayed green with the recovery set empty. splitmix64
/// leaves the damaged block nowhere else to be found, so it has to come
/// out of parity, and the counts say which mechanism did what. Do not
/// relax them to a bare `repair complete`.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_head_obfuscated_payload_repairs_on_the_get_path() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardmghead");
    let data = payloads::unique_payload(200_000, 0x0f09_0091);
    std::fs::write(fx.dir.join("Damaged.Head.mkv"), &data).unwrap();
    assert!(fx.add_par2_opts(20, Some(10_000), &["Damaged.Head.mkv"], 40_000));
    std::fs::remove_file(fx.dir.join("Damaged.Head.mkv")).unwrap();
    let mut wire = data.clone();
    wire[1000..1064].copy_from_slice(&payloads::unique_payload(64, 0x0f09_0092));
    fx.add_file_obfuscated("Dh4kQm73XvZ", "Dh4kQm73XvZ", &wire, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "damaged-head obfuscated post failed:\n{log}");
    // 20 blocks of 10,000 over a 200,000-byte file: the hash-named copy
    // carries 19 of them intact and the damaged head is block 0, so the
    // sliding scan may harvest exactly 19 and the recovery set (20%, 4
    // blocks) must rebuild exactly 1. Asserting BOTH is what makes this
    // a test of recovery data rather than of the payload generator.
    assert!(
        log.contains("1 block(s) rebuilt") && log.contains("19 block(s) adopted from"),
        "the damaged head must be rebuilt from parity and the rest \
         adopted - see this row's generator note:\n{log}"
    );
    let got = std::fs::read(out.join("Damaged.Head.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(got == data, "payload not repaired byte-exact\n{log}");
    assert!(
        !out.join("Dh4kQm73XvZ").exists(),
        "the spent damaged twin survived beside the repaired file:\n{log}"
    );
}

/// Finding F10 - CLOSED 30 Aug 2026 (`corpus-wave3-findings`): the
/// DEDUPE POST. Two FileDescs declare identical (MD5, length), one
/// copy is posted. The arrived copy claims one descriptor; the other
/// used to count "missing entirely" and the job died at realistic
/// redundancy on a post carrying every byte it needed (adoption
/// excludes identified targets by design, so the verified twin could
/// never help). `land_duplicate_filedescs` now satisfies the missing
/// descriptor with a hash-verified byte copy of the sibling.
#[tokio::test(flavor = "multi_thread")]
async fn a_dedupe_descriptor_pair_lands_both_names_from_one_posted_copy() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardedupe");
    let data = payload(180_000, 93);
    std::fs::write(fx.dir.join("Copy.One.bin"), &data).unwrap();
    std::fs::write(fx.dir.join("Copy.Two.bin"), &data).unwrap();
    assert!(fx.add_par2_opts(10, Some(10_000), &["Copy.One.bin", "Copy.Two.bin"], 40_000));
    std::fs::remove_file(fx.dir.join("Copy.One.bin")).unwrap();
    std::fs::remove_file(fx.dir.join("Copy.Two.bin")).unwrap();
    fx.add_file_obfuscated("Vd2wRq85XnB", "Vd2wRq85XnB", &data, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "dedupe post failed:\n{log}");
    let one = std::fs::read(out.join("Copy.One.bin"))
        .unwrap_or_else(|e| panic!("Copy.One.bin missing: {e}\n{log}"));
    let two = std::fs::read(out.join("Copy.Two.bin"))
        .unwrap_or_else(|e| panic!("Copy.Two.bin missing: {e}\n{log}"));
    assert!(
        one == data && two == data,
        "dedupe pair not byte-exact\n{log}"
    );
}

/// Finding F11 - CLOSED 30 Aug 2026 (`corpus-wave3-findings`): a
/// DAMAGED PAR2 INDEX beside intact volumes. The index still activated
/// a set naming no files, the with-set path had nothing to verify, and
/// a fully obfuscated post sailed through "clean" and un-named while
/// the volumes carrying intact critical-packet copies were never
/// fetched (NZB-classified volumes have no slot). A zero-file set now
/// routes to the set-less path, which fetches the volumes and runs the
/// disk pass off their packets.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_par2_index_still_names_the_post_from_its_volumes() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardmgidx");
    // ADOPTION IS THE ROW. Nothing here is damaged: the payload is
    // posted ONLY under the hash name below, and `Resilient.Payload.mkv`
    // - the name the set declares - is deleted before the post is built,
    // so every one of its 1954 blocks has to be found inside the
    // obfuscated copy. The disk pass completes `0 block(s) rebuilt
    // across 1 file(s), 1954 block(s) adopted from Wk6dNs31TcF`, which
    // IS "names the post from its volumes"; parity spent on it would be
    // the regression, not the route.
    //
    // This row was invisible to `adoptguard::
    // refuse_a_solve_that_solved_nothing` until 31 Aug 2026, and the
    // reason is worth keeping: `get/settle/noset.rs`'s disk-fallback report
    // printed the rebuilt count with NO adoption clause, so the guard
    // read it as a repair that adopted nothing. It is the first fixture
    // that arm surfaced.
    crate::adoptguard::adoption_is_the_premise(
        &fx.dir,
        "the set's declared target is posted ONLY under a hash name, so \
         no block of it can come from parity - the disk pass finding all \
         1954 inside the obfuscated copy IS the naming this row asserts",
    );
    let data = payload(250_000, 94);
    fx.add_file_obfuscated("Wk6dNs31TcF", "Wk6dNs31TcF", &data, 40_000);
    std::fs::write(fx.dir.join("Resilient.Payload.mkv"), &data).unwrap();
    assert!(add_par2_patched(
        &mut fx,
        15,
        &["Resilient.Payload.mkv"],
        40_000,
        |blob| {
            // Poison only the INDEX (no recovery slices = the small
            // blob); every critical packet also rides in the volumes.
            if blob.len() < 100_000 {
                let at = 200.min(blob.len() - 64);
                for b in &mut blob[at..at + 64] {
                    *b ^= 0xA5;
                }
            }
        }
    ));
    std::fs::remove_file(fx.dir.join("Resilient.Payload.mkv")).unwrap();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "damaged-index post failed:\n{log}");
    let got = std::fs::read(out.join("Resilient.Payload.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its FileDesc name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
}

/// Finding F12 - CLOSED 30 Aug 2026 (`corpus-wave3-findings`): the
/// PAR2-OF-PAR2 chain. Payload and its recovery set both ride under
/// hash names; a small outer set (announced) names the inner par2
/// files. The outer set claims and lands them - and the inner set,
/// which names the payload, never activates (its articles were
/// sniff-deferred and reconciled as the outer set's payload), so the
/// job used to finish "clean" with the payload still hash-named.
/// settle_with_set now applies non-activated on-disk sets after a good
/// job; a junk set that matches nothing still changes nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_par2_of_par2_chain_names_the_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarchain");
    let data = payload(220_000, 95);
    fx.add_file_obfuscated("Bq3fJm77ZsK", "Bq3fJm77ZsK", &data, 40_000);
    // Inner set over the payload, posted under hash names.
    std::fs::write(fx.dir.join("Chained.Payload.mkv"), &data).unwrap();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "inner", "Chained.Payload.mkv"])
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "inner par2 create failed");
    std::fs::remove_file(fx.dir.join("Chained.Payload.mkv")).unwrap();
    let mut inner: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    inner.sort();
    let inner_names: Vec<String> = inner
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for (i, p) in inner.iter().enumerate() {
        let bytes = std::fs::read(p).unwrap();
        let hash = format!("Gx7tPz4{i:02}Qe");
        let tag = format!("chain-inner-{i}");
        let segs = make_file_articles(&hash, &bytes, 40_000, &tag, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
    }
    // Outer set over the inner par2 FILES, announced under real names.
    let inner_refs: Vec<&str> = inner_names.iter().map(String::as_str).collect();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "outer"])
        .args(&inner_refs)
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "outer par2 create failed");
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("outer") && name.ends_with(".par2") {
            let bytes = std::fs::read(&p).unwrap();
            let tag = format!("chain-outer-{}", fx.nzb_files.len());
            let segs = make_file_articles(&name, &bytes, 40_000, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).ok();
    }
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "par2-of-par2 chain failed:\n{log}");
    let got = std::fs::read(out.join("Chained.Payload.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its chained name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Bq3fJm77ZsK").exists(),
        "the obfuscated payload name survived the chain:\n{log}"
    );
}

/// Build a dedupe fan-out fixture: `aliases` FileDescs all declaring the
/// same (MD5, length) over one SMALL payload, of which exactly one copy
/// is posted (obfuscated). Returns the descriptor names in set order.
///
/// Deliberately small bytes and many names - the shape a hostile packet
/// file commands, where the cost is the FAN-OUT and not the payload. A
/// test that scaled the payload instead would allocate real disk to say
/// nothing extra.
fn dedupe_fanout(fx: &mut Fixture, tag: &str, aliases: usize, data: &[u8]) -> Vec<String> {
    let names: Vec<String> = (0..aliases).map(|i| format!("{tag}.{i:03}.bin")).collect();
    for n in &names {
        std::fs::write(fx.dir.join(n), data).unwrap();
    }
    let refs: Vec<&str> = names.iter().map(String::as_str).collect();
    assert!(
        fx.add_par2_opts(10, Some(4096), &refs, 40_000),
        "par2 create over {aliases} aliases failed"
    );
    for n in &names {
        std::fs::remove_file(fx.dir.join(n)).unwrap();
    }
    names
}

/// W4-14, the UNDER-CAP half: a dedupe fan-out inside
/// `DUPLICATE_FANOUT_CAP` lands every alias byte-exact AND reads the
/// source exactly ONCE. Before the fix `land_duplicate_filedescs`
/// re-hashed the whole source per alias, so a group of N cost N full
/// reads to prove one content claim N times over.
#[tokio::test(flavor = "multi_thread")]
async fn a_dedupe_fanout_under_the_cap_hashes_the_source_once() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarfanunder");
    let data = payload(4096, 71);
    let names = dedupe_fanout(&mut fx, "Under", 8, &data);
    fx.add_file_obfuscated("Yh4kTm62WpQ", "Yh4kTm62WpQ", &data, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "under-cap dedupe fan-out failed:\n{log}");
    for n in &names {
        let got = std::fs::read(out.join(n))
            .unwrap_or_else(|e| panic!("{n} missing under its FileDesc name: {e}\n{log}"));
        assert!(got == data, "{n} not byte-exact\n{log}");
    }
    // The read-amplification oracle: one group, one whole-file hash.
    let hashes = log.matches("duplicate-descriptor group").count();
    assert_eq!(
        hashes, 1,
        "the source was hashed {hashes} times for one (MD5, length) group\n{log}"
    );
}

/// W4-14, the OVER-CAP half: a packet file naming hundreds of aliases
/// for one posted payload is hostile metadata, and the product ruling
/// of 30 Aug 2026 is to materialize `DUPLICATE_FANOUT_CAP` of them and
/// REFUSE the rest honestly - the refused descriptors stay on the
/// missing list, so the job reports them rather than claiming a
/// satisfaction it did not produce.
///
/// Before the fix all 200 were copied: a kilobyte of descriptor bought
/// 200 full-file reads and 200 full-file writes, bounded by nothing.
#[tokio::test(flavor = "multi_thread")]
async fn a_dedupe_fanout_past_the_cap_refuses_the_remainder() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    const ALIASES: usize = 200;
    // The shipped ruling, restated here on purpose: a test that read the
    // constant out of the crate could not tell a moved cap from a broken
    // one.
    const CAP: usize = 32;
    let mut fx = Fixture::new("norarfanover");
    let data = payload(4096, 72);
    let names = dedupe_fanout(&mut fx, "Over", ALIASES, &data);
    fx.add_file_obfuscated("Zc9pLr48VmT", "Zc9pLr48VmT", &data, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    let landed = names.iter().filter(|n| out.join(n).exists()).count();
    // One posted copy, renamed onto the descriptor it claimed, plus the
    // capped clones. Nothing else may reach disk.
    assert_eq!(
        landed,
        1 + CAP,
        "fan-out of {ALIASES} materialized {landed} files - the cap is {CAP}\n{log}"
    );
    assert!(
        log.contains("refusing"),
        "a capped fan-out must say what it skipped and why\n{log}"
    );
    assert!(
        !ok,
        "a fan-out past the cap must fail honestly, never report the refused \
         descriptors satisfied\n{log}"
    );
    // Every alias reaching disk holds the real bytes - the cap must
    // truncate the COUNT, never the content.
    for n in names.iter().filter(|n| out.join(n).exists()) {
        assert!(
            std::fs::read(out.join(n)).unwrap() == data,
            "{n} landed but is not byte-exact\n{log}"
        );
    }
}

/// W4-04: an identical-head twin DAMAGED past the head.
///
/// The whole-file MD5 can never name a DAMAGED twin - the difference
/// between the slot and its own descriptor IS the damage - so for its
/// first day this row measured the decline: the slot stayed unclaimed,
/// the set priced its member wholly missing, and the repair coped by
/// recreating the member and adopting 900-odd of its blocks straight
/// out of the damaged slot's own bytes.
///
/// Since sweep item 13 (30 Aug 2026) the twin tier settles it instead,
/// on per-block IFSC evidence - the surviving blocks carry one twin's
/// own PAR2 block checksums and not the other's, so the slot CLAIMS its
/// descriptor and the damage is patched in place. What the log says now
/// is "slot 0 is a damaged member of a 2 identical-head group", and
/// this row asserts that line: the repair needs the blocks the damage
/// really costs rather than the thousand a missing file costs, and
/// nothing is recreated. See `live/twintier.rs` for the rule and for
/// the two shapes it still declines.
///
/// What used to fail after the decline is the VERDICT, and BOTH halves
/// of that fix are still load-bearing here. The leftover hash-named
/// slot was priced "outside the PAR2 set / still incomplete" and failed
/// a job whose output was complete and MD5-proved: `settle.rs` fixed
/// that by having the census's sparse findings join the obfuscated-alias
/// reconciliation instead of being appended after it. The claim tier
/// reopened the same seam from the other side - the census asks whether
/// the verifier has matched a slot BEFORE settle, and this slot matches
/// during it, so its stale sparse finding has to be skipped for a slot
/// the set has since claimed (`merge_sparse_slots`).
///
/// ON THE ORDER THE ROW IS NAMED FOR, which the wave-4 probe's own
/// fixture gets wrong and this one measures instead. The claim these
/// twins race for is not made during the download at all: `try_match`
/// declines both at head time on the 16 KiB ambiguity, and the
/// whole-file tier runs only in `finish_slot`, which `settle_with_set`
/// hands out from a worker pool `cpu_workers().min(12)` wide. So a
/// download-time `stall` on the sibling - the probe's lever - cannot
/// reach it: measured 30 Aug 2026, stalling either twin produced the
/// identical declining path, 127 s apart. Neither can the posting
/// order, on a box wide enough to run both slots at once: both legs
/// below see the damaged slot weigh two still-unclaimed descriptors.
///
/// Both orders are driven anyway, and cost about three seconds each.
/// On a narrow finish pool the slots ARE settled in index order, and
/// then the order decides a real difference: the damaged twin posted
/// SECOND meets one descriptor already claimed and takes the survivor
/// through the ordinary md5-16k tier instead, which is a different code
/// path to the same verdict. Both must be green, whichever way the race
/// falls on the box running them - which is the row's actual claim.
/// The in-place assertion below is therefore made only where the twin
/// tier is the path taken: the md5-16k tier claims a sole survivor by
/// content and prints no line of its own.
#[tokio::test(flavor = "multi_thread")]
async fn a_damaged_identical_head_twin_is_repaired_in_place_in_either_settle_order() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // Article 3 of a 5-article 200 KB file covers bytes 80k..120k, so
    // corrupting it is damage the 16 KiB head cannot see and the
    // whole-file MD5 cannot forgive.
    for (tag, damaged_first) in [("norardmg1st", true), ("norardmglast", false)] {
        let mut fx = Fixture::new(tag);
        let mut a = vec![0u8; 200_000];
        let mut b = vec![0u8; 200_000];
        a[20_000..].copy_from_slice(&payload(180_000, 71));
        b[20_000..].copy_from_slice(&payload(180_000, 72));
        let (dmg, clean) = (
            ("Dmg.Alpha.vob", "Jm5nPw72QsX"),
            ("Dmg.Beta.vob", "Ty8cKd31VbN"),
        );
        let order = if damaged_first {
            [(dmg, &a), (clean, &b)]
        } else {
            [(clean, &b), (dmg, &a)]
        };
        for ((name, post), data) in order {
            fx.add_file_renamed_by_par2(name, post, data, 40_000);
        }
        assert!(fx.add_par2(15, &["Dmg.Alpha.vob", "Dmg.Beta.vob"], 40_000));
        // The damaged article's message id carries the slot index the
        // posting order just chose for it.
        let dmg_slot = usize::from(!damaged_first);
        let chaos = Chaos {
            corrupt: HashSet::from([format!("<{}-{dmg_slot}-3@mock>", dmg.1)]),
            ..Chaos::default()
        };
        let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
        assert!(
            ok,
            "[{tag}] one damaged block in an identical-head twin failed the \
             whole job:\n{log}"
        );
        let got_a = std::fs::read(out.join("Dmg.Alpha.vob"))
            .unwrap_or_else(|e| panic!("[{tag}] Dmg.Alpha.vob missing: {e}\n{log}"));
        let got_b = std::fs::read(out.join("Dmg.Beta.vob"))
            .unwrap_or_else(|e| panic!("[{tag}] Dmg.Beta.vob missing: {e}\n{log}"));
        assert!(
            got_a == a,
            "[{tag}] Dmg.Alpha.vob is not the repaired original\n{log}"
        );
        assert!(
            got_b == b,
            "[{tag}] Dmg.Beta.vob carries the other twin's bytes\n{log}"
        );
        for p in [dmg.1, clean.1] {
            assert!(
                !out.join(p).exists(),
                "[{tag}] the superseded hash-named partial shipped beside the \
                 rebuilt file - an *arr would import {p}\n{log}"
            );
        }
        // Repaired IN PLACE, not recreated: the damaged slot claimed its
        // own descriptor on per-block evidence. Only asserted on the leg
        // where the twin tier is the path taken - see the note above.
        if damaged_first {
            assert!(
                log.contains("is a damaged member of a 2 identical-head group")
                    && log.contains("Dmg.Alpha.vob's own PAR2 block checksums"),
                "[{tag}] the damaged twin was not paired on per-block evidence\n{log}"
            );
            assert!(
                !log.contains("recreated"),
                "[{tag}] the member was recreated from parity - the in-place \
                 claim did not happen\n{log}"
            );
        }
    }
}

/// W4-04's harder half: BOTH identical-head twins damaged past the
/// head. Neither may be claimed by elimination, and the outcome must
/// still be each file byte-exact under its OWN name.
///
/// This is the fixture that refuses the tempting unsafe fix for the row
/// above - "one candidate descriptor is left, so it must be ours". With
/// two damaged twins there is no survivor to eliminate down to, and a
/// pairing picked arbitrarily publishes one twin's bytes under the
/// other's name at rc=0, which is strictly worse than the over-count it
/// would fix. What is sound is asking evidence that actually separates
/// them, which is what sweep item 13 landed: each slot's surviving
/// blocks carry ITS twin's PAR2 block checksums and not the other's, so
/// each claims its own descriptor and is patched in place. Where the
/// evidence does NOT separate them the tier still declines - see
/// `two_identical_head_twins_damaged_in_their_only_distinguishing_block_still_decline`
/// below, which is this row's other half.
///
/// THE REDUNDANCY IS 25% AND WAS 15%, and the reason is worth reading
/// before anybody trims it back. The damage is one 40 KB article in each
/// twin, which at this set's 200-byte blocks is 200 of each file's 1000
/// - 400 of 2000, so an honest in-place repair needs 400 recovery
/// blocks and 15% posts 300. It passed at 15% until 30 Aug 2026 because
/// the tier declined both slots, the set priced both members wholly
/// missing, and the recreate-and-adopt pass ran its SLIDING content scan
/// over the two hash-named files - and these two payloads are not
/// independent: `payload(n, 81)` and `payload(n, 82)` differ by one in
/// every byte, so `a[i] == b[i + 83]` at 84% of offsets (measured) and
/// the scan cross-matched one twin's missing blocks out of the other's
/// file. `par2 v` over the same two damaged files says what a real post
/// would: 1600 of 2000 blocks available, 400 more recovery blocks
/// needed. So 15% was never this row's real parity budget, it was an
/// artefact of the payload generator, and 25% (500 blocks) is what the
/// damage actually costs. A CROSSED pairing still fails loudly at 25%:
/// each file would then verify every block bad, which is 2000.
#[tokio::test(flavor = "multi_thread")]
async fn two_damaged_identical_head_twins_are_never_crossed() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardmgboth");
    let mut a = vec![0u8; 200_000];
    let mut b = vec![0u8; 200_000];
    a[20_000..].copy_from_slice(&payload(180_000, 81));
    b[20_000..].copy_from_slice(&payload(180_000, 82));
    let posted = ["Kq7bVn24MdT", "Ws3gLp68RxC"];
    fx.add_file_renamed_by_par2("Both.Alpha.vob", posted[0], &a, 40_000);
    fx.add_file_renamed_by_par2("Both.Beta.vob", posted[1], &b, 40_000);
    assert!(fx.add_par2(25, &["Both.Alpha.vob", "Both.Beta.vob"], 40_000));
    let chaos = Chaos {
        corrupt: posted
            .iter()
            .enumerate()
            .map(|(i, p)| format!("<{p}-{i}-3@mock>"))
            .collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        ok,
        "two damaged identical-head twins failed the job:\n{log}"
    );
    let got_a = std::fs::read(out.join("Both.Alpha.vob"))
        .unwrap_or_else(|e| panic!("Both.Alpha.vob missing: {e}\n{log}"));
    let got_b = std::fs::read(out.join("Both.Beta.vob"))
        .unwrap_or_else(|e| panic!("Both.Beta.vob missing: {e}\n{log}"));
    assert!(
        got_a == a,
        "Both.Alpha.vob carries the other twin's bytes - a damaged pair was \
         crossed\n{log}"
    );
    assert!(
        got_b == b,
        "Both.Beta.vob carries the other twin's bytes - a damaged pair was \
         crossed\n{log}"
    );
    for p in posted {
        assert!(
            !out.join(p).exists(),
            "a superseded hash-named partial shipped beside the rebuilt \
             file: {p}\n{log}"
        );
    }
    // Each twin paired with its OWN descriptor, which is the row's name
    // said in the log rather than only in the output bytes.
    for name in ["Both.Alpha.vob", "Both.Beta.vob"] {
        assert!(
            log.contains(&format!("{name}'s own PAR2 block checksums")),
            "{name} was not paired on its own per-block evidence\n{log}"
        );
    }
}

/// The refusal the rule above is priced against, and the shape that
/// keeps "claim the one that scores highest" out of the tier: two
/// identical-head twins that differ ONLY in the block each slot is
/// damaged in.
///
/// Every other block is declared identically by both descriptors, so
/// matching one says nothing about WHICH twin these bytes are; the one
/// block that would say is the damaged one, and it matches neither. The
/// tier must therefore decline exactly as it did before the evidence arm
/// existed - and the job must still finish, by the route that always
/// covered this: both members priced missing, both recreated from
/// parity, each block taken back on its own PAR2 evidence.
///
/// 60% redundancy because that is what the route costs: declining prices
/// both members WHOLLY missing, which is 2000 of this set's 200-byte
/// blocks, and the recreate-and-adopt pass has to bring the shortfall
/// under whatever parity is posted. The row above documents why a budget
/// that merely happens to work is not one to copy.
#[tokio::test(flavor = "multi_thread")]
async fn two_identical_head_twins_damaged_in_their_only_distinguishing_block_still_decline() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardmgsame");
    let mut a = vec![0u8; 200_000];
    a[20_000..].copy_from_slice(&payload(180_000, 91));
    // Byte-identical to `a` everywhere but the third article's range,
    // which is the ONE block index that can tell the two apart.
    let mut b = a.clone();
    b[80_000..120_000].copy_from_slice(&payload(40_000, 92));
    let posted = ["Rr4mXt91BgQ", "Vh6dZc27NkL"];
    fx.add_file_renamed_by_par2("Same.Alpha.vob", posted[0], &a, 40_000);
    fx.add_file_renamed_by_par2("Same.Beta.vob", posted[1], &b, 40_000);
    assert!(fx.add_par2(60, &["Same.Alpha.vob", "Same.Beta.vob"], 40_000));
    // Damage each twin in exactly that block.
    let chaos = Chaos {
        corrupt: posted
            .iter()
            .enumerate()
            .map(|(i, p)| format!("<{p}-{i}-3@mock>"))
            .collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        ok,
        "twins the evidence cannot separate must still finish:\n{log}"
    );
    assert!(
        log.contains("per-block PAR2 evidence does not separate them"),
        "the tier claimed a pairing nothing in the bytes supports\n{log}"
    );
    for (name, want) in [("Same.Alpha.vob", &a), ("Same.Beta.vob", &b)] {
        let got =
            std::fs::read(out.join(name)).unwrap_or_else(|e| panic!("{name} missing: {e}\n{log}"));
        assert!(&got == want, "{name} carries the other twin's bytes\n{log}");
    }
    for p in posted {
        assert!(
            !out.join(p).exists(),
            "a superseded hash-named partial shipped beside the rebuilt \
             file: {p}\n{log}"
        );
    }
}

/// Every regular file under `out`, as (out-relative '/'-joined name,
/// bytes). The namespace-collision rows below cannot assert a fixed
/// path - which member is disambiguated depends on which claimed
/// first - so they assert over the whole tree instead.
pub(crate) fn out_tree(out: &Path) -> Vec<(String, Vec<u8>)> {
    fn walk(dir: &Path, base: &Path, v: &mut Vec<(String, Vec<u8>)>) {
        let Ok(rd) = std::fs::read_dir(dir) else {
            return;
        };
        let mut ents: Vec<PathBuf> = rd.flatten().map(|e| e.path()).collect();
        ents.sort();
        for p in ents {
            if p.is_dir() {
                walk(&p, base, v);
            } else if let Ok(bytes) = std::fs::read(&p) {
                let rel = p
                    .strip_prefix(base)
                    .unwrap()
                    .components()
                    .filter_map(|c| match c {
                        std::path::Component::Normal(s) => Some(s.to_string_lossy().into_owned()),
                        _ => None,
                    })
                    .collect::<Vec<_>>()
                    .join("/");
                v.push((rel, bytes));
            }
        }
    }
    let mut v = Vec::new();
    walk(out, out, &mut v);
    v
}

/// W4-17 (codex Wave 4, 30 Aug 2026) - the FILE-VERSUS-DIRECTORY
/// namespace collision, both completion orders.
///
/// `node` and `node/child.bin` are two valid FileDesc members with
/// distinct content, both posted under hashes. They do not collide as
/// STRINGS, which is all the output-name claim used to compare - so
/// whichever published second met a regular file where it needed a
/// directory (or a nonempty directory where it needed a file), the
/// publish warned and returned `None`, and that failure never reached
/// the verdict: rc=0 with one payload still under its hash.
///
/// `flat_first` picks which member the NZB (and so the slot order, and
/// so the claim order) offers first; the OTHER one is the one that has
/// to move. Both orders must keep both payloads and leave no hash name
/// behind.
async fn file_vs_dir_collision_case(tag: &str, flat_first: bool) {
    let mut fx = Fixture::new(tag);
    let flat = payload(50_000, 75);
    let child = payload(50_000, 76);
    // `node` and `node/child.bin` cannot both exist on the fixture disk
    // - that IS the collision - so par2 create sees `nodeX` and the
    // FileDesc is patched to `node` afterwards.
    std::fs::write(fx.dir.join("nodeX"), &flat).unwrap();
    std::fs::create_dir_all(fx.dir.join("node")).unwrap();
    std::fs::write(fx.dir.join("node/child.bin"), &child).unwrap();
    let posted: [(&str, &[u8]); 2] = if flat_first {
        [("Ya6fZq30Cp", &flat), ("Ya6fZq31Cp", &child)]
    } else {
        [("Ya6fZq31Cp", &child), ("Ya6fZq30Cp", &flat)]
    };
    for (hash, bytes) in posted {
        let t = format!("{tag}-{hash}");
        let segs = make_file_articles(hash, bytes, 40_000, &t, &mut fx.articles);
        fx.nzb_files.push((hash.to_string(), segs));
    }
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "testset", "nodeX", "node/child.bin"])
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "par2 create failed");
    let mut par2s: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    par2s.sort();
    for p in par2s {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let mut blob = std::fs::read(&p).unwrap();
        assert!(
            rename_filedesc(&mut blob, "nodeX", "node") > 0,
            "no FileDesc named nodeX in {name}"
        );
        let t = format!("{}-{}", name.replace('.', "_"), fx.nzb_files.len());
        let segs = make_file_articles(&name, &blob, 40_000, &t, &mut fx.articles);
        fx.nzb_files.push((name, segs));
        std::fs::remove_file(&p).unwrap();
    }
    std::fs::remove_file(fx.dir.join("nodeX")).unwrap();
    std::fs::remove_dir_all(fx.dir.join("node")).unwrap();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "file-vs-directory post failed outright:\n{log}");
    let tree = out_tree(&out);
    let have_flat = tree.iter().any(|(_, b)| *b == flat);
    let have_child = tree.iter().any(|(_, b)| *b == child);
    let hash_left = tree.iter().any(|(n, _)| n.contains("Ya6fZq3"));
    assert!(
        have_flat && have_child && !hash_left,
        "the node vs node/child.bin collision stranded a payload \
         (flat={have_flat} child={have_child} hash_left={hash_left}); tree: {:?}\n{log}",
        tree.iter()
            .map(|(n, b)| (n.clone(), b.len()))
            .collect::<Vec<_>>()
    );
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_versus_directory_name_collision_keeps_both_flat_first() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    file_vs_dir_collision_case("norarw417a", true).await;
}

#[tokio::test(flavor = "multi_thread")]
async fn a_file_versus_directory_name_collision_keeps_both_child_first() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    file_vs_dir_collision_case("norarw417b", false).await;
}

/// `out_tree` reduced to "name (bytes)" strings - what the two
/// chain-in-a-tree pins want in a panic, since "the payload is missing"
/// is only useful beside where it actually is.
fn tree_names(out: &Path) -> Vec<String> {
    out_tree(out)
        .into_iter()
        .map(|(n, b)| format!("{n} ({} bytes)", b.len()))
        .collect()
}

/// Wave-4 row W4-06 / M4-06B - CLOSED 30 Aug 2026 (claim
/// `wave4-fix-lateset-tree`). The n27 chain above, with the outer set
/// publishing the INNER PACKET FILES under a safe subdirectory
/// (`META/`) rather than at the job root - which FileDesc publication
/// supports since the relpath-preserve ruling, and which every packet
/// walk in the crate used to be unable to see.
///
/// Measured red on the `wave4-verify` probe branch at `f59a222e2`:
/// publication was correct (`META/inner.par2` and every volume landed),
/// the hash-named payload sat unclaimed at the root so the late-set
/// trigger fired - and `disk_set_ids`' single top-level `read_dir`
/// returned only the OUTER set's own id, so the inner set that names
/// the payload was never applied. rc=0 with the payload still called
/// `Bq3fJm77ZsK`. `apply_nonactivated_disk_sets` now asks for
/// `PacketScope::Nested`; the bounds it keeps are in
/// `nzbkit::par2repair::nested`.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_whose_inner_par2_lands_in_a_tree_still_names_the_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarchaintree");
    let data = payload(220_000, 59);
    fx.add_file_obfuscated("Bq3fJm77ZsK", "Bq3fJm77ZsK", &data, 40_000);
    // Inner set over the payload, built at the root then moved to META/.
    std::fs::write(fx.dir.join("Chained.Payload.mkv"), &data).unwrap();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "inner", "Chained.Payload.mkv"])
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "inner par2 create failed");
    std::fs::remove_file(fx.dir.join("Chained.Payload.mkv")).unwrap();
    std::fs::create_dir_all(fx.dir.join("META")).unwrap();
    let mut moved: Vec<String> = Vec::new();
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        if p.extension().is_some_and(|x| x == "par2") {
            let name = p.file_name().unwrap().to_string_lossy().into_owned();
            std::fs::rename(&p, fx.dir.join("META").join(&name)).unwrap();
            moved.push(format!("META/{name}"));
        }
    }
    moved.sort();
    for (i, rel) in moved.iter().enumerate() {
        let bytes = std::fs::read(fx.dir.join(rel)).unwrap();
        let hash = format!("Nc4gXe7{i:02}Wd");
        let tag = format!("chaintree-inner-{i}");
        let segs = make_file_articles(&hash, &bytes, 40_000, &tag, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
    }
    // Outer announced set naming META/inner*.par2 - tree FileDescs.
    let moved_refs: Vec<&str> = moved.iter().map(String::as_str).collect();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "outer"])
        .args(&moved_refs)
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "outer par2 create failed");
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("outer") && name.ends_with(".par2") {
            let bytes = std::fs::read(&p).unwrap();
            let tag = format!("chaintree-outer-{}", fx.nzb_files.len());
            let segs = make_file_articles(&name, &bytes, 40_000, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).ok();
    }
    std::fs::remove_dir_all(fx.dir.join("META")).unwrap();
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "tree-nested chain failed outright:\n{log}");
    let got = std::fs::read(out.join("Chained.Payload.mkv")).unwrap_or_else(|e| {
        panic!(
            "the tree-landed inner set was invisible to the late-set scan - \
             payload still hash-named: {e}; tree: {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Bq3fJm77ZsK").exists(),
        "the obfuscated payload name survived the tree chain:\n{log}"
    );
}

/// Wave-4 row M4-06A, the sibling shape that was already GREEN on the
/// baseline and must stay green while W4-06 widens discovery: the inner
/// packet files stay at the root and the PAYLOAD is the one in a tree
/// (`VIDEO_TS/VTS_01_1.VOB`). Cursor's prediction was that
/// `apply_nonactivated_disk_sets`' root-only unclaimed test would see a
/// directory rather than a file and return; measured, it does not bite,
/// because the unclaimed hash is still at the root when the scan runs.
/// Kept as a pin so the tree-aware rewrite of that test is held to the
/// answer the root-only one gave.
#[tokio::test(flavor = "multi_thread")]
async fn a_chain_whose_payload_lands_in_a_tree_still_names_the_payload() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarchaintreepay");
    let data = payload(220_000, 61);
    fx.add_file_obfuscated("Bq3fJm77ZsK", "Bq3fJm77ZsK", &data, 40_000);
    std::fs::create_dir_all(fx.dir.join("VIDEO_TS")).unwrap();
    std::fs::write(fx.dir.join("VIDEO_TS/VTS_01_1.VOB"), &data).unwrap();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "inner", "VIDEO_TS/VTS_01_1.VOB"])
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "inner par2 create failed");
    std::fs::remove_dir_all(fx.dir.join("VIDEO_TS")).unwrap();
    let mut inner: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    inner.sort();
    let inner_names: Vec<String> = inner
        .iter()
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    for (i, p) in inner.iter().enumerate() {
        let bytes = std::fs::read(p).unwrap();
        let hash = format!("Hf9sLt2{i:02}Rb");
        let tag = format!("chaintreepay-inner-{i}");
        let segs = make_file_articles(&hash, &bytes, 40_000, &tag, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
    }
    let inner_refs: Vec<&str> = inner_names.iter().map(String::as_str).collect();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "outer"])
        .args(&inner_refs)
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "outer par2 create failed");
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("outer") && name.ends_with(".par2") {
            let bytes = std::fs::read(&p).unwrap();
            let tag = format!("chaintreepay-outer-{}", fx.nzb_files.len());
            let segs = make_file_articles(&name, &bytes, 40_000, &tag, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).ok();
    }
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "tree-payload chain failed outright:\n{log}");
    let got = std::fs::read(out.join("VIDEO_TS/VTS_01_1.VOB")).unwrap_or_else(|e| {
        panic!(
            "payload never landed under its tree FileDesc name: {e}; tree: {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(got == data, "payload not byte-exact\n{log}");
}

// ===== Wave 4 W4-02 / W4-18: a NAME nominates, only CONTENT     =====
// ===== finalizes. Landed as regression pins with the fix        =====
// ===== (30 Aug 2026); each was RED on the tree before it, and   =====
// ===== the three failures are one seam - `SlotState::try_match` =====
// ===== claiming the exact-name descriptor ahead of every        =====
// ===== content tier. Each was written as a probe and measured   =====
// ===== RED in a worktree before the fix existed, then rehomed   =====
// ===== here.                                                    =====

/// W4-02A: two intact payloads whose yEnc names are CROSSED - A's bytes
/// ride under `name=B.bin` and B's under `name=A.bin`, article CRCs
/// truthful for their own bytes throughout. Content must decide, so
/// both land byte-exact under their FileDesc names at zero repair
/// spend.
///
/// Before the fix each slot exactly claimed the OTHER descriptor before
/// any content tier ran: every differing block read as damage, both
/// files verified 1000/1000 bad, and a post carrying every byte it
/// needed died unrepairable at r=10.
#[tokio::test(flavor = "multi_thread")]
async fn crossed_yenc_names_land_by_content_not_by_the_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarcrossname");
    let a = payload(200_000, 11);
    let b = payload(200_000, 12);
    fx.add_file_renamed_by_par2("A.bin", "B.bin", &a, 40_000);
    fx.add_file_renamed_by_par2("B.bin", "A.bin", &b, 40_000);
    assert!(fx.add_par2(10, &["A.bin", "B.bin"], 40_000));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "intact cross-named pair failed at r=10:\n{log}");
    let got_a =
        std::fs::read(out.join("A.bin")).unwrap_or_else(|e| panic!("A.bin missing: {e}\n{log}"));
    let got_b =
        std::fs::read(out.join("B.bin")).unwrap_or_else(|e| panic!("B.bin missing: {e}\n{log}"));
    assert!(
        got_a == a,
        "A.bin carries the wrong bytes (crossed claim)\n{log}"
    );
    assert!(
        got_b == b,
        "B.bin carries the wrong bytes (crossed claim)\n{log}"
    );
    assert!(
        !log.contains("repair complete"),
        "intact bytes paid a phantom repair:\n{log}"
    );
}

/// W4-02B: two FileDescs share the exact name `dup.bin` with DISTINCT
/// content, and both slots post that exact yEnc name. Content must
/// disambiguate them; FileDesc order must not.
///
/// The slot posted FIRST deliberately carries the fid-SECOND
/// descriptor's bytes, so a first-hit exact claim is crossed rather
/// than merely lucky - which is what made this row ORDER-DEPENDENT
/// before the fix: one run landed clean, the next read 2000/2000 blocks
/// bad and paid a full phantom repair at rc=0.
/// [`duplicate_filedesc_names_keep_both_files`] is the same descriptor
/// shape with obfuscated posted names, where content matching always
/// saved it; this is the row that needs the name tier itself to decline.
#[tokio::test(flavor = "multi_thread")]
async fn duplicate_exact_names_are_disambiguated_by_content() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norardupexact");
    let one = payload(200_000, 21);
    let two = payload(200_000, 22);
    std::fs::write(fx.dir.join("One.bin"), &one).unwrap();
    std::fs::write(fx.dir.join("Two.bin"), &two).unwrap();
    let one_first = par2_file_id(&one, "One.bin") < par2_file_id(&two, "Two.bin");
    let (first, second) = if one_first {
        (&two, &one)
    } else {
        (&one, &two)
    };
    for (i, bytes) in [first, second].into_iter().enumerate() {
        let tag = format!("dupexact-{i}");
        let segs = make_file_articles("dup.bin", bytes, 40_000, &tag, &mut fx.articles);
        fx.nzb_files.push((format!("Zk9qLw3{i}Xd"), segs));
    }
    assert!(add_par2_patched(
        &mut fx,
        10,
        &["One.bin", "Two.bin"],
        40_000,
        |blob| {
            rename_filedesc(blob, "One.bin", "dup.bin");
            rename_filedesc(blob, "Two.bin", "dup.bin");
        }
    ));
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "duplicate exact-name pair failed at r=10:\n{log}");
    let tree = out_tree(&out);
    let have_one = tree.iter().any(|(_, b)| *b == one);
    let have_two = tree.iter().any(|(_, b)| *b == two);
    assert!(
        have_one && have_two,
        "a duplicate-named content was lost (one={have_one} two={have_two}); tree: {:?}\n{log}",
        tree.iter()
            .map(|(n, b)| (n.clone(), b.len()))
            .collect::<Vec<_>>()
    );
    assert!(
        !log.contains("repair complete"),
        "intact duplicate-named bytes paid a phantom repair:\n{log}"
    );
}

/// W4-18: a DEDUPE post (two FileDescs declaring identical content, one
/// posted copy) plus an UNCOVERED payload posted honestly under a name
/// the set also uses. The uncovered file must stay out of the set, both
/// payloads must survive, and the duplicate descriptor must still be
/// satisfied from the verified copy.
///
/// Three things had to be true at once and none of them was. The set's
/// exact-name tier claimed the uncovered occupant, which verified
/// 1000/1000 bad and failed the whole intact job. With that fixed the
/// set's own verified copy was pushed onto a `{slot:03}-` name by the
/// occupant, and everything downstream addresses a member BY its
/// descriptor name - so repair RECREATED the member over the occupant,
/// which then existed nowhere. And the duplicate-descriptor rescue
/// rebuilt `out/<name>` from the descriptor instead of consulting where
/// the file actually landed, hashed the occupant, and rejected a
/// perfectly good sibling.
#[tokio::test(flavor = "multi_thread")]
async fn an_uncovered_file_wearing_a_set_members_name_stays_out_of_the_set() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let mut fx = Fixture::new("norarnamesquat");
    let dup = payload(80_000, 77);
    let occupant = payload(80_000, 78);
    std::fs::write(fx.dir.join("Copy.One.bin"), &dup).unwrap();
    std::fs::write(fx.dir.join("Copy.Two.bin"), &dup).unwrap();
    assert!(fx.add_par2(10, &["Copy.One.bin", "Copy.Two.bin"], 40_000));
    std::fs::remove_file(fx.dir.join("Copy.One.bin")).unwrap();
    std::fs::remove_file(fx.dir.join("Copy.Two.bin")).unwrap();
    // One posted copy of the duplicated content, under a hash.
    let segs = make_file_articles(
        "Xe1nGv54BmH",
        &dup,
        40_000,
        "namesquat-dup",
        &mut fx.articles,
    );
    fx.nzb_files.push(("Xe1nGv54BmH".to_string(), segs));
    // ...and an uncovered, different payload already named Copy.One.bin.
    fx.add_file("Copy.One.bin", &occupant, 40_000);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "name-squat dedupe post failed outright:\n{log}");
    let tree = out_tree(&out);
    let dup_copies = tree.iter().filter(|(_, b)| *b == dup).count();
    let have_occupant = tree.iter().any(|(_, b)| *b == occupant);
    assert!(
        have_occupant && dup_copies >= 2,
        "a payload was lost (occupant={have_occupant} dup_copies={dup_copies}); tree: {:?}\n{log}",
        tree.iter()
            .map(|(n, b)| (n.clone(), b.len()))
            .collect::<Vec<_>>()
    );
}

/// The PAR2-OF-PAR2 chain, parameterized: payload posted under a hash,
/// an INNER set naming it posted under hashes, an OUTER announced set
/// naming the inner packet FILES.
///
/// The shape `a_par2_of_par2_chain_names_the_payload` builds inline is
/// this one with `truth == posted` and every inner volume riding; the
/// W4-01 pair below needs the two knobs that test cannot express - a
/// payload that is NOT what the inner manifest describes, and an inner
/// set posted index-only so it has no parity to heal the difference
/// with. Left as a second builder rather than folded into that test,
/// because that test is a shipped regression pin and its own geometry
/// (one obfuscated payload file added the ordinary way) is part of what
/// it pins.
///
/// `inner_r` is the inner redundancy; `keep_inner_volumes` false posts
/// only the inner index. `posted` rides the wire for the payload slot;
/// the inner manifest is built over `truth`.
fn chain_fixture(
    tag: &str,
    truth: &[u8],
    posted: &[u8],
    art: usize,
    inner_r: u32,
    keep_inner_volumes: bool,
) -> Fixture {
    let mut fx = Fixture::new(tag);
    // Payload slot: subject and yEnc name both the hash, bytes = posted.
    {
        let tagp = format!("payslot-{}", fx.nzb_files.len());
        let segs = make_file_articles("Bq3fJm77ZsK", posted, art, &tagp, &mut fx.articles);
        fx.nzb_files.push(("Bq3fJm77ZsK".to_string(), segs));
    }
    // Inner set built over the TRUTH bytes.
    std::fs::write(fx.dir.join("Chained.Payload.mkv"), truth).unwrap();
    let st = Command::new("par2")
        .args([
            "create",
            &format!("-r{inner_r}"),
            "-q",
            "inner",
            "Chained.Payload.mkv",
        ])
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "inner par2 create failed");
    std::fs::remove_file(fx.dir.join("Chained.Payload.mkv")).unwrap();
    let mut inner: Vec<PathBuf> = std::fs::read_dir(&fx.dir)
        .unwrap()
        .filter_map(|e| {
            let p = e.unwrap().path();
            (p.extension().is_some_and(|x| x == "par2")).then_some(p)
        })
        .collect();
    inner.sort();
    let mut inner_names: Vec<String> = Vec::new();
    for (i, p) in inner.iter().enumerate() {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        let is_index = name == "inner.par2";
        if !keep_inner_volumes && !is_index {
            continue;
        }
        let bytes = std::fs::read(p).unwrap();
        let hash = format!("Gx7tPz4{i:02}Qe");
        let tagp = format!("chain-inner-{i}");
        let segs = make_file_articles(&hash, &bytes, art, &tagp, &mut fx.articles);
        fx.nzb_files.push((hash, segs));
        inner_names.push(name);
    }
    // Outer set over the inner packet FILES that actually rode.
    for p in &inner {
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if !inner_names.contains(&name) {
            std::fs::remove_file(p).ok();
        }
    }
    let inner_refs: Vec<&str> = inner_names.iter().map(String::as_str).collect();
    let st = Command::new("par2")
        .args(["create", "-r10", "-q", "outer"])
        .args(&inner_refs)
        .current_dir(&fx.dir)
        .status();
    assert!(st.is_ok_and(|s| s.success()), "outer par2 create failed");
    for e in std::fs::read_dir(&fx.dir).unwrap().flatten() {
        let p = e.path();
        let name = p.file_name().unwrap().to_string_lossy().into_owned();
        if name.starts_with("outer") && name.ends_with(".par2") {
            let bytes = std::fs::read(&p).unwrap();
            let tagp = format!("chain-outer-{}", fx.nzb_files.len());
            let segs = make_file_articles(&name, &bytes, art, &tagp, &mut fx.articles);
            fx.nzb_files.push((name, segs));
        }
        std::fs::remove_file(&p).ok();
    }
    fx
}

/// W4-01A (wave-4 adversarial review, 30 Aug 2026) - FIXED 30 Aug 2026.
/// The late inner set has the parity to heal one missing payload
/// article, and the job must finish clean under the inner FileDesc
/// name. It used to FAIL: the late-set pass was gated on `all_good`, so
/// a short download never reached the one set that could complete it.
///
/// The 10,000-byte articles are load-bearing and were the second half
/// of the same measurement. An article under 16 KiB cannot carry the
/// md5-16k head fingerprint, so every deferred inner par2 file stayed
/// deferred, the outer set priced ten files that were sitting on disk
/// as wholly missing, and the job died having fetched its entire
/// parity - see `SniffCtl::promote_pending_head16`. The identical
/// fixture at 40,000 passed throughout, which is exactly why this one
/// posts small.
#[tokio::test(flavor = "multi_thread")]
async fn a_late_inner_set_repairs_a_missing_payload_article() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(220_000, 95);
    // 22 payload articles; one missing is under 5% of the set, and the
    // inner r20 covers it with slack.
    let fx = chain_fixture("norarchain1a", &data, &data, 10_000, 20, true);
    let chaos = Chaos {
        missing: std::collections::HashSet::from(["<payslot-0-11@mock>".to_string()]),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(
        ok,
        "the late inner set never healed the short payload:\n{log}"
    );
    let got = std::fs::read(out.join("Chained.Payload.mkv"))
        .unwrap_or_else(|e| panic!("payload missing under its chained name: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    assert!(
        !out.join("Bq3fJm77ZsK").exists(),
        "the obfuscated payload name survived:\n{log}"
    );
}

/// W4-01B (wave-4 adversarial review, 30 Aug 2026) - FIXED 30 Aug 2026.
/// The inner manifest is built over payload A and the wire carries a
/// same-length B whose every article decodes with a truthful CRC, so
/// nothing short of the inner FileDesc/IFSC can tell: the inner set is
/// index-only, so it has no parity either. The job must NOT report
/// success. It used to: `apply_nonactivated_disk_sets` logged
/// `Unrepairable` and returned no verdict to its caller.
///
/// This is NOT the foreign-set-decoy rule (matrix row n28, which must
/// keep passing). The outer set cryptographically identifies these
/// packet files as part of THIS post, so what they then say about the
/// payload is this job's own evidence - see `get::latesets`.
#[tokio::test(flavor = "multi_thread")]
async fn an_inner_set_denial_of_swapped_payload_is_not_green() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let truth = payload(220_000, 95);
    let posted = payload(220_000, 96);
    let fx = chain_fixture("norarchain1b", &truth, &posted, 40_000, 5, false);
    let (log, ok, _out) = run_norar(&fx).await;
    assert!(
        !ok,
        "the job reported rc=0 while the inner authoritative set denies the \
         payload bytes:\n{log}"
    );
}

/// M4-37 / M4-38: what a PAR2 packet is allowed to assert about a file.
/// A child module rather than more rows here - this file was 2,658 of
/// its 3,000 size-gate lines on 30 Aug 2026 with a dozen wave-4 lanes
/// appending to it, and `tests/e2e.rs` had ONE line of margin left, so
/// a sibling of `e2e_norar` could not be declared there either.
mod par2trust;

/// M4-102: the late-set door for a leftover BELOW the job root - the
/// composition half of W4-06's tree-aware `has_unclaimed`, which every
/// chain pin in this file leaves at the root. A child module for the
/// same reason `par2trust` is one.
mod latetree;

/// X6-01 - a healed wire error must not cost a byte-exact file its
/// name or its delivery. PASS pins for a monotone counter that four
/// eligibility bands read; its own file for the same reason and by the
/// same rule as its siblings above.
mod healed;
