//! Wave-4 row M4-86: a PAR2 FileDesc name that is not valid UTF-8.
//!
//! A CHILD module of `e2e_norar` for the same reason as its siblings -
//! the builders above are reachable through `use super::*` and `mod.rs`
//! stays inside its size-gate ceiling.

use super::*;

/// [`rename_filedesc`] over RAW bytes, because the name this row is
/// about is not valid UTF-8 and so cannot be spelled as a `&str`.
///
/// The replacement is null-padded into the old region, so the packet
/// length and every file id in the set are untouched - readers key
/// packets by the STORED id and nobody recomputes it, which is the same
/// property `empty_filedesc` and `rename_filedesc` already lean on.
///
/// `pub(super)` so `deferredcross` can build the M4-86 spelling too: the
/// slot that is a MOVER AND A DEFERRER at once is this row's own shape
/// crossed with the publish plan, and duplicating the patcher next door
/// is how two spellings of one rule start.
pub(super) fn rename_filedesc_raw(data: &mut Vec<u8>, from: &str, to: &[u8]) -> usize {
    let mut hits = 0;
    for (start, len, ptype) in packets(data) {
        if &ptype != b"PAR 2.0\0FileDesc" || filedesc_name(data, start, len) != from {
            continue;
        }
        assert!(
            to.len() <= len - 120,
            "patched name must fit the old region"
        );
        data[start + 120..start + len].fill(0);
        data[start + 120..start + 120 + to.len()].copy_from_slice(to);
        reseal(data, start, len);
        hits += 1;
    }
    hits
}

/// The M4-86 post, with the yEnc name's readability as the parameter.
///
/// The payload is staged on disk under `cafe\u{e9}.mkv` so `par2 create`
/// records that name, and every FileDesc is then patched to the CP1252
/// bytes of the SAME name - one byte, `\xE9` where the UTF-8 spelling
/// has `\xC3\xA9`, so the name region and every file id in the set are
/// untouched.
/// 25%, not the 10% this posted until 4 Sep 2026, and the number is
/// derived rather than copied. The damaged row below corrupts ONE
/// 40,000-byte article of a 220,000-byte payload, which par2 prices at
/// 358 bad blocks of 1,965 (18.2%); 10% is 197 recovery blocks and
/// cannot close that, so the row completed only because `payload`
/// repeats every 131,072 bytes and the adoption scan found the damage's
/// twin inside the same file - `52 block(s) rebuilt, 306 adopted from
/// caf\u{e9}.mkv`, on a row that asserts "a repairable post failed"
/// (research/PAYLOAD-TRAP-PATH-DEPENDENT-CENSUS-2026-09-04.md). 25% is
/// 491 blocks, 133 clear of the damage. The payload moved to
/// `payloads::unique_payload` in the same commit, so the recovery set is
/// now the only route and both halves had to change together: converting
/// alone leaves the row unrepairable, raising alone leaves the trap.
fn cp1252_fixture(tag: &str, data: &[u8], posted: &str) -> Fixture {
    let mut fx = Fixture::new(tag);
    fx.add_file_renamed_by_par2("caf\u{e9}.mkv", posted, data, 40_000);
    let hits = std::sync::atomic::AtomicUsize::new(0);
    assert!(
        add_par2_patched(&mut fx, 25, &["caf\u{e9}.mkv"], 40_000, |b| {
            let n = rename_filedesc_raw(b, "caf\u{e9}.mkv", b"caf\xE9.mkv");
            hits.fetch_add(n, std::sync::atomic::Ordering::Relaxed);
        }),
        "par2 create failed"
    );
    assert!(
        hits.load(std::sync::atomic::Ordering::Relaxed) > 0,
        "the fixture patched no FileDesc, so it is not testing M4-86 at all"
    );
    fx
}

/// M4-86 (wave-4 sixth pass, 31 Aug 2026). The poster wrote the file
/// name twice: CP1252 in the PAR2 FileDesc, UTF-8 in the yEnc header.
///
/// `par2::parse_filedesc` decodes with `String::from_utf8_lossy`, so the
/// set's spelling comes back `caf\u{FFFD}.mkv` - and on the 30 Aug 2026
/// baseline the settle rename took it, over a yEnc name that was already
/// correct on disk. Measured: `ok=true`, one file, named
/// `caf\u{FFFD}.mkv`. The job was green and the user had mojibake.
///
/// Nothing here decodes CP1252 - see `get::settle::filedesc_name_is_better`
/// for why an encoding guess is refused for this family, and
/// `nzbkit::par2::parse_unifilen` for where that ruling was made. The
/// set's own name is still unreadable; it just no longer replaces one
/// that reads.
///
/// The `Fixture` binding is held to the end of the body: `out` lives
/// inside it and its `ScratchDir` guard deletes the tree on drop, so an
/// assertion made after it has gone grades an emptied directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_lossy_filedesc_name_does_not_replace_a_readable_one() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(220_000, 91);
    let fx = cp1252_fixture("norarcp1252", &data, "caf\u{e9}.mkv");
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "a fully fetchable post failed:\n{log}");
    let got = std::fs::read(out.join("caf\u{e9}.mkv"))
        .unwrap_or_else(|e| panic!("the readable yEnc name did not survive: {e}\n{log}"));
    assert!(got == data, "payload not byte-exact\n{log}");
    let mojibake: Vec<String> = tree_names(&out)
        .into_iter()
        .filter(|n| n.contains(char::REPLACEMENT_CHARACTER))
        .collect();
    assert!(
        mojibake.is_empty(),
        "a lossily-decoded FileDesc name reached the output tree: {mojibake:?}\n{log}"
    );
}

/// The other half of the same rule, and the reason it costs nothing.
///
/// Same set, same unreadable FileDesc - but the post obfuscates the yEnc
/// name too, so there is no readable name to lose. `caf\u{FFFD}.mkv`
/// carries most of what the poster meant and `Kj8sWm3xPd` carries none,
/// so the rename must still happen. A fix that refused every lossy name
/// outright would leave this file wearing the hash, which is strictly
/// worse than mojibake, and this test is what refuses that fix.
#[tokio::test(flavor = "multi_thread")]
async fn a_lossy_filedesc_name_still_beats_a_hash() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let data = payload(220_000, 93);
    let fx = cp1252_fixture("norarcp1252hash", &data, "Kj8sWm3xPd");
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "a fully fetchable post failed:\n{log}");
    let named: Vec<String> = tree_names(&out)
        .into_iter()
        .filter(|n| n.contains(char::REPLACEMENT_CHARACTER))
        .collect();
    assert_eq!(
        named.len(),
        1,
        "the set's name is unreadable but it is still the best one here, so \
         the hash must have been renamed away: {:?}\n{log}",
        tree_names(&out)
    );
    assert!(
        !out.join("Kj8sWm3xPd").exists(),
        "the payload kept its posted hash:\n{log}"
    );
}

/// The third fixture is the one that decided the DESIGN, and it is here
/// because the obvious fix fails it.
///
/// Refusing the rename outright was built first. It passes both tests
/// above and it is WORSE: the set's spelling is what the disk-side
/// repair looks a member up by, so a file left under the readable name
/// is a member the set cannot find. Measured on this fixture with that
/// version in place - `1913 block(s) adopted from caf\u{e9}.mkv` and then
/// `1 recreated`: two 220,000-byte files, the repaired bytes in
/// `caf\u{FFFD}.mkv` and the DAMAGE left behind in `caf\u{e9}.mkv`, job
/// green. That is issue #9's shape, bought for a cosmetic name. The
/// shipped fix defers instead, so the whole repair runs against the name
/// the set knows.
///
/// So this test is not decoration on the two above: they pass under both
/// designs and only this one tells them apart.
///
/// What must hold: the job succeeds, the payload is byte-exact under the
/// readable name, and there is exactly ONE copy of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_deferred_readable_rename_still_lets_the_set_repair_in_place() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    // `unique_payload`, not `payload`: see `cp1252_fixture`'s note on the
    // recovery percentage. On the repeating generator this row's damage
    // healed itself out of the same file and the set was never
    // load-bearing.
    let data = crate::payloads::unique_payload(220_000, 95);
    let fx = cp1252_fixture("norarcp1252dmg", &data, "caf\u{e9}.mkv");
    let chaos = Chaos {
        corrupt: std::iter::once("<caf\u{e9}_mkv-0-3@mock>".to_string()).collect(),
        ..Chaos::default()
    };
    assert!(
        fx.articles.contains_key("<caf\u{e9}_mkv-0-3@mock>"),
        "the fixture's article ids moved, so nothing is being damaged: {:?}",
        fx.articles.keys().take(4).collect::<Vec<_>>()
    );
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "a repairable post failed:\n{log}");
    let got = std::fs::read(out.join("caf\u{e9}.mkv"))
        .unwrap_or_else(|e| panic!("the readable yEnc name did not survive: {e}\n{log}"));
    assert!(
        got == data,
        "payload not byte-exact after repair: got {} bytes want {}, tree {:?}\n{log}",
        got.len(),
        data.len(),
        tree_names(&out)
    );
    let copies: Vec<String> = tree_names(&out)
        .into_iter()
        .filter(|n| n.starts_with("caf"))
        .collect();
    assert_eq!(
        copies.len(),
        1,
        "the set rebuilt its member under the name it knows, beside the one \
         it repaired - issue #9's shape, and what refusing the rename \
         instead of deferring it measured at: {copies:?}\n{log}"
    );
}
