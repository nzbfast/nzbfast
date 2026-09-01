//! What `get::publishplan::plan_publish_names` owes a slot that MOVES AND
//! COMES BACK - claim `publishplan-model-vs-deferred-rename`, 31 Aug 2026.
//!
//! The planner's first rule is that a slot owns the name it sits under
//! only if it is going to stay there, and `17449b055` made that false for
//! one class of slot without telling the planner. A GH #63 slot - honest
//! subject, hash FileDesc - used to refuse the FileDesc rename and never
//! move; it now DEFERS, taking the set's spelling so the disk-side repair
//! can find its own member and giving the honest name back afterwards.
//! `moves` is built out of the very predicate that used to refuse, so the
//! planner went on classifying it as a stayer: its transient target was
//! nobody's target, and the cycle arm had never seen a slot that moves
//! without appearing in `moves`.
//!
//! MEASURED on the crossed pair below, INTACT, before the fix:
//!
//! ```text
//! [extract] renamed Real.Feature…mkv → 000-Real.Feature…mkv (the recovery set names that file)
//! [extract] renamed 000-Real.Feature…mkv → KpZ7mQx4TvB9nR2sLdFq.mkv (replaced the previous copy)
//! [extract] renamed KpZ7mQx4TvB9nR2sLdFq.mkv → Real.Feature…mkv
//! [verify] verified 2 file(s): 2000 blocks in-stream, 0 by read-back, 0 bad
//! [verify] clean download - no repair, no post-verify pass ✔
//! tree: Real.Feature.2021.1080p-GRP.mkv (220000 bytes)
//! ```
//!
//! Every block of both files verified, `ok=true`, and ONE payload on disk
//! - the deferring slot's bytes wearing the other slot's name. The other
//! payload is gone, on a post that was never damaged, and
//! `replaced the previous copy` is the whole of the trace. The mover was
//! skipped by the seeding loop because movers are leaving, so
//! `PublishedNames` held neither its name nor its inode and the deferring
//! slot's claim read as a PREVIOUS RUN's copy - which the strong tier is
//! entitled to replace.
//!
//! TWO MORE CLAIMS LANDED HERE ON 31 Aug 2026 rather than in a module of
//! their own, because they are the same function's residue and a new
//! `mod` line in `mod.rs` is itself a hazard - inserting one between an
//! existing `///` block and the item it documents silently steals that
//! comment, and `tools/doc-gate.py` cannot see it (claim
//! `doc-gate-stolen-comment`). `publishplan-mover-that-also-defers` is
//! the slot that is in BOTH lists, and `publishplan-two-deferrers-crossing`
//! is the pair that turns out not to exist; each is argued at its own row
//! below.
//!
//! A CHILD module of `e2e_norar` for the same reason as `sixtythreedamage`
//! and `encoding` beside it: `mod.rs` is near its size-gate ceiling with
//! about a dozen M4 lanes still appending to it, and a child reaches the
//! builders through `use super::*` where a sibling directory would need
//! each one made `pub(crate)`.
//!
//! Payloads here are `payloads::unique_payload` and not the `payload` the
//! fixtures next door use: that one is periodic, so two seeds share PAR2
//! blocks, and a damaged row then repairs by ADOPTING from its neighbour
//! instead of from parity - which `tests/adoptguard` refuses by name,
//! because a row that never made the recovery set load-bearing does not
//! test what its name says.

use super::*;

/// The honest posted name, which is also the OTHER slot's FileDesc name.
const HONEST: &str = "Real.Feature.2021.1080p-GRP.mkv";
/// The hash FileDesc name, which is also the other slot's posted name.
const HASH: &str = "KpZ7mQx4TvB9nR2sLdFq.mkv";

/// The crossed pair. Slot 0 is #63's shape - posted `HONEST`, FileDesc
/// `HASH`, so it defers - and slot 1 is the ordinary deobfuscation shape,
/// posted `HASH` with FileDesc `HONEST`, so it is a plain mover. Each
/// slot's target is the other's current name, and only one of the two
/// legs is a `moves` entry.
///
/// `add_file_renamed_by_par2` takes the FileDesc name FIRST and the
/// posted name second, which is why these two calls read as mirror
/// images of each other.
fn crossed_fixture(tag: &str, a: &[u8], b: &[u8]) -> Fixture {
    let mut fx = Fixture::new(tag);
    fx.add_file_renamed_by_par2(HASH, HONEST, a, 40_000);
    fx.add_file_renamed_by_par2(HONEST, HASH, b, 40_000);
    assert!(
        fx.add_par2(10, &[HASH, HONEST], 40_000),
        "par2 create failed"
    );
    fx
}

/// Both payloads, wherever they landed, by content - which is the only
/// question this row is really asking. The names are graded separately,
/// because "under a disambiguated spelling" and "gone" are the two
/// outcomes the whole `{slot:03}-` convention exists to keep apart.
fn payload_survived(out: &Path, want: &[u8]) -> bool {
    out_tree(out).into_iter().any(|(_, bytes)| bytes == want)
}

/// THE ROW. An INTACT crossed pair, where the deferring slot's transient
/// target is the mover's current name.
///
/// What must hold is only this: both payloads are still on disk. Before
/// the fix one of them was renamed over by the other at rc=0 with every
/// block of both files reported verified.
///
/// The names are pinned too, and in the direction rule 2 gives: the
/// FileDesc name belongs to the slot whose descriptor spells it, so the
/// MOVER takes `HONEST` and the deferring slot comes back to the
/// `{slot:03}-` form of the name it started under. That is the same
/// answer the uncrossed control below reaches, which is the point - the
/// cross changes what the plan has to do, not what it has to produce.
///
/// The `Fixture` binding is held to the end of the body: `out` lives
/// inside it and its `ScratchDir` guard deletes the tree on drop, so an
/// assertion made after it has gone grades an emptied directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_deferring_slot_does_not_publish_over_the_mover_it_crosses() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = payloads::unique_payload(220_000, 41);
    let b = payloads::unique_payload(220_000, 42);
    let fx = crossed_fixture("norardefercross", &a, &b);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "an intact crossed pair failed:\n{log}");
    assert!(
        payload_survived(&out, &a) && payload_survived(&out, &b),
        "one payload was renamed over by the other - tree {:?}\n{log}",
        tree_names(&out)
    );
    let got = std::fs::read(out.join(HONEST))
        .unwrap_or_else(|e| panic!("the FileDesc name did not land: {e}\n{log}"));
    assert!(
        got == b,
        "the set member's own descriptor name carries the OTHER slot's \
         bytes - tree {:?}\n{log}",
        tree_names(&out)
    );
    let back = std::fs::read(out.join(format!("000-{HONEST}"))).unwrap_or_else(|e| {
        panic!(
            "the deferred take-back did not land: {e}\ntree {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(back == a, "the take-back carries the wrong bytes\n{log}");
}

/// The same crossed pair with one article of the DEFERRING slot corrupted,
/// which is what puts the transient name to work: the whole reason that
/// slot takes the set's spelling at all is so the disk-side repair can
/// find its own member under it.
///
/// So this grades one thing the intact row cannot - that both members are
/// findable BY NAME during the repair window, with the swap and the aside
/// both in flight - and it is the shape the claim was written against.
#[tokio::test(flavor = "multi_thread")]
async fn the_crossed_pair_repairs_with_both_members_findable_by_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = payloads::unique_payload(220_000, 43);
    let b = payloads::unique_payload(220_000, 44);
    let fx = crossed_fixture("norardefercrossdmg", &a, &b);
    // The FOURTH article of the deferring slot, whose span begins at byte
    // 120,000. Asserted before the run: an id that has moved damages
    // nothing and would make this pass for no reason.
    let damaged = format!("<{}-3@mock>", HONEST.replace('.', "_") + "-0");
    assert!(
        fx.articles.contains_key(&damaged),
        "the fixture's article ids moved, so nothing is being damaged: {:?}",
        fx.articles.keys().take(6).collect::<Vec<_>>()
    );
    let chaos = Chaos {
        corrupt: std::iter::once(damaged).collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "a repairable crossed pair failed:\n{log}");
    assert!(
        payload_survived(&out, &a) && payload_survived(&out, &b),
        "a payload did not survive the repair - tree {:?}\n{log}",
        tree_names(&out)
    );
    assert!(
        !log.contains("recreated"),
        "repair could not find a member under the name the set knows and \
         rebuilt it beside the bytes instead - tree {:?}\n{log}",
        tree_names(&out)
    );
}

/// CONTROL - the deferral crossed with the W4-18 ASIDE instead of with a
/// cycle. Slot 0 is the same #63 shape at `HONEST`; slot 1 is posted
/// under a third name entirely and its FileDesc is `HONEST`, so it wants
/// the deferring slot's name without holding the deferring slot's target.
///
/// This is GREEN on both sides of the fix and that is what it is for: the
/// aside arm hands the deferring slot a `{slot:03}-` leaf, which
/// `nzbkit::release::stem_is_a_name` still reads as a name, so the
/// deferral survives the detour and returns to the disambiguated
/// spelling. A red here means the plan's aside arm or the take-back, not
/// the cycle - which is the half the row above cannot tell apart on its
/// own.
#[tokio::test(flavor = "multi_thread")]
async fn the_deferring_slot_still_steps_aside_for_the_member_that_owns_its_name() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = payloads::unique_payload(220_000, 51);
    let b = payloads::unique_payload(220_000, 52);
    let mut fx = Fixture::new("norardeferaside");
    fx.add_file_renamed_by_par2(HASH, HONEST, &a, 40_000);
    fx.add_file_renamed_by_par2(HONEST, "Ab3xYw92QsLtVn41Dk", &b, 40_000);
    assert!(
        fx.add_par2(10, &[HASH, HONEST], 40_000),
        "par2 create failed"
    );
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "CONTROL: an intact post failed:\n{log}");
    let got = std::fs::read(out.join(HONEST))
        .unwrap_or_else(|e| panic!("CONTROL: the FileDesc name did not land: {e}\n{log}"));
    assert!(
        got == b,
        "CONTROL: the FileDesc name carries the wrong bytes\n{log}"
    );
    let back = std::fs::read(out.join(format!("000-{HONEST}"))).unwrap_or_else(|e| {
        panic!(
            "CONTROL: the deferred take-back did not land - tree {:?}: {e}\n{log}",
            tree_names(&out)
        )
    });
    assert!(
        back == a,
        "CONTROL: the take-back carries the wrong bytes\n{log}"
    );
    assert!(
        !out.join(HASH).exists(),
        "CONTROL: the set's hash survived beside the honest name - tree {:?}\n{log}",
        tree_names(&out)
    );
}

/// CONTROL - the SAME crossed pair with the two slots in the OTHER order,
/// which is green on both sides of the fix and is here to say so.
///
/// Slot order decides which of the two publishes first, and with the
/// MOVER at the lower index it publishes into a name the aside has
/// already vacated, so nothing is ever renamed over. That makes the
/// defect above a coin flip on NZB file order rather than a property of
/// the shape - worth pinning, because "we have never seen it" and "it
/// cannot happen" read the same from a bug report.
///
/// It is not only a note: after the fix this order reaches the swap
/// through a different arrangement - the deferring slot is the one the
/// seeding loop walks SECOND - so the two rows together say the cycle is
/// broken whichever way round the post is written.
#[tokio::test(flavor = "multi_thread")]
async fn the_crossed_pair_is_order_dependent_and_the_other_order_was_always_safe() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = payloads::unique_payload(220_000, 45);
    let b = payloads::unique_payload(220_000, 46);
    let mut fx = Fixture::new("norardefercrossrev");
    // The mover FIRST this time - the only difference from
    // `crossed_fixture`.
    fx.add_file_renamed_by_par2(HONEST, HASH, &b, 40_000);
    fx.add_file_renamed_by_par2(HASH, HONEST, &a, 40_000);
    assert!(
        fx.add_par2(10, &[HASH, HONEST], 40_000),
        "par2 create failed"
    );
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "CONTROL: an intact crossed pair failed:\n{log}");
    assert!(
        payload_survived(&out, &a) && payload_survived(&out, &b),
        "CONTROL: one payload was renamed over by the other - tree {:?}\n{log}",
        tree_names(&out)
    );
    let got = std::fs::read(out.join(HONEST))
        .unwrap_or_else(|e| panic!("CONTROL: the FileDesc name did not land: {e}\n{log}"));
    assert!(
        got == b,
        "CONTROL: the descriptor name carries the other slot's bytes - tree {:?}\n{log}",
        tree_names(&out)
    );
}

/// CONTROL, and the one that settled how WIDE the fix should be: an
/// occupant that STAYS PUT on the deferring slot's transient target.
///
/// The deferring slot takes the set's spelling for exactly one reason -
/// so the disk-side repair can find its own member under it - which
/// reads as an argument for evicting an occupant of that name too, under
/// the same `{slot:03}-` convention W4-18 established for a MOVER's
/// target. That was built first and measured, and the measurement says
/// no. With the occupant seeded at the name, the deferring slot is
/// pushed onto `000-<name>` by the ordinary claim, and repair does not
/// care:
///
/// ```text
/// [extract] renamed Real.Feature…mkv → 000-KpZ7mQx4TvB9nR2sLdFq.mkv
/// [repair] repair complete ✔ (native, mapped: 358 block(s) rebuilt directly into the output)
/// [extract] renamed 000-KpZ7mQx4TvB9nR2sLdFq.mkv → Real.Feature…mkv
/// ```
///
/// It reaches the member through the SLOT, not by looking the name up,
/// so the occupant is never consulted and never at risk. Evicting it
/// would have cost it its name permanently for a name the deferring slot
/// only borrows - so `wanted` covers MOVER targets only, and this row is
/// what says why.
///
/// Slot 0 is the same #63 shape, in the set, posted `HONEST` with the
/// FileDesc `HASH`. Slot 2 is an UNCOVERED payload - no descriptor
/// anywhere - posted under `HASH`. The damage is load-bearing: intact,
/// repair never runs and the question is not asked at all. GREEN on both
/// sides of the fix, which is the point of it.
#[tokio::test(flavor = "multi_thread")]
async fn a_borrowed_transient_target_does_not_evict_the_occupant_sitting_on_it() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let member = payloads::unique_payload(220_000, 61);
    let occupant = payloads::unique_payload(220_000, 62);
    let mut fx = Fixture::new("norardefersquat");
    fx.add_file_renamed_by_par2(HASH, HONEST, &member, 40_000);
    // r=30 and not the 10 the rows above use: a single-file set of this
    // size gets a 112-byte PAR2 block, so ONE corrupt 40,000-byte article
    // costs 358 blocks against 197 of parity at r=10 - recovery-short,
    // and the row would then be graded on the adoption scan rather than
    // on where the files were.
    assert!(fx.add_par2(30, &[HASH], 40_000), "par2 create failed");
    // After the set is built, so the uncovered payload is genuinely
    // outside it - it only shares the NAME the descriptor uses.
    std::fs::remove_file(fx.dir.join(HASH)).unwrap();
    fx.add_file(HASH, &occupant, 40_000);
    let damaged = format!("<{}-3@mock>", HONEST.replace('.', "_") + "-0");
    assert!(
        fx.articles.contains_key(&damaged),
        "the fixture's article ids moved, so nothing is being damaged: {:?}",
        fx.articles.keys().take(6).collect::<Vec<_>>()
    );
    let chaos = Chaos {
        corrupt: std::iter::once(damaged).collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "a repairable post failed:\n{log}");
    let squat = std::fs::read(out.join(HASH)).unwrap_or_else(|e| {
        panic!(
            "CONTROL: the occupant lost the name it never gave up - tree {:?}: {e}\n{log}",
            tree_names(&out)
        )
    });
    assert!(
        squat == occupant,
        "CONTROL: the occupant's name carries somebody else's bytes - tree {:?}\n{log}",
        tree_names(&out)
    );
    let got = std::fs::read(out.join(HONEST))
        .unwrap_or_else(|e| panic!("CONTROL: the honest subject did not come back: {e}\n{log}"));
    assert!(
        got == member,
        "CONTROL: the take-back carries the damage - tree {:?}\n{log}",
        tree_names(&out)
    );
}

/// The M4-86 slot's own posted spelling - readable, well-formed UTF-8,
/// and the name its file actually carries on disk. It is also the OTHER
/// slot's FileDesc target, which is what makes the pair a cycle.
const READABLE: &str = "caf\u{e9}.mkv";
/// What the M4-86 slot is STAGED under for `par2 create`, so there is a
/// name to patch the CP1252 bytes over afterwards. It never appears in
/// the post or on the client's disk.
const STAGED: &str = "cafeA.mkv";
/// The second slot's posted hash. Nobody's target, so this slot is an
/// ordinary deobfuscation mover with no cycle of its own.
const HASHB: &str = "Vv7QpZr2NmKd8Xs.mkv";
/// A third real name, for the CONTROL: the second slot's descriptor
/// names THIS instead of the M4-86 slot's leaf, so nothing crosses.
const OTHER: &str = "Other.Feature.2020.1080p-GRP.mkv";

/// The M4-86 slot crossed with an ordinary mover that wants its leaf.
///
/// Slot 0 satisfies BOTH of the planner's predicates. Its FileDesc
/// decodes to `caf\u{FFFD}.mkv`, which `nzbkit::release::stem_is_a_name`
/// still calls a name, so `filedesc_name_is_better` is TRUE - and
/// `lossy_name_loses_to` fires as well, so `settle_slots` defers it back
/// to the readable leaf it arrived under. Its final resting name is
/// therefore its LEAF, not its target, which is what makes the order the
/// two lists are asked in decide where it goes.
///
/// Slot 1 is a plain mover whose descriptor names slot 0's leaf, which is
/// what brings the cycle arm to slot 0 at all.
///
/// `second_target` is the parameter the CONTROL varies: pass `READABLE`
/// for the cross, a third name for the uncrossed twin.
fn mojibake_cycle_fixture(tag: &str, a: &[u8], b: &[u8], second_target: &str) -> Fixture {
    let mut fx = Fixture::new(tag);
    // Staged under STAGED so `par2 create` records a name the patch can
    // overwrite; POSTED under READABLE, which is what the download lands
    // as on the client's disk.
    fx.add_file_renamed_by_par2(STAGED, READABLE, a, 40_000);
    fx.add_file_renamed_by_par2(second_target, HASHB, b, 40_000);
    let hits = std::sync::atomic::AtomicUsize::new(0);
    assert!(
        add_par2_patched(&mut fx, 10, &[STAGED, second_target], 40_000, |d| {
            let n = super::encoding::rename_filedesc_raw(d, STAGED, b"caf\xE9.mkv");
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

/// THE ROW - claim `publishplan-mover-that-also-defers`, 31 Aug 2026.
///
/// A slot can be in BOTH lists and `plan_publish_names` sorted them
/// exclusively, `moves` first. So the M4-86 slot - whose final name is
/// its LEAF, because it gives the set's spelling back - was classified as
/// a mover, whose final name is its TARGET. Three consequences, and the
/// third is the one that costs a payload its name:
///
/// * the seeding loop SKIPS it, because movers are leaving, so nothing
///   reserves the leaf it is coming back to;
/// * the cycle arm may move it to `.nzbfast-swap-<n>` rather than to the
///   `{slot:03}-` aside a deferrer gets;
/// * that swap temp is what `deferred_name` then reads the return name
///   off, so the file comes to rest named after a build artefact.
///
/// MEASURED on the pre-fix tree, this fixture, intact, rc=0:
///
/// ```text
/// [extract] renamed .nzbfast-swap-0 -> caf\u{FFFD}.mkv
/// [extract] renamed Vv7QpZr2NmKd8Xs.mkv -> caf\u{e9}.mkv
/// [verify] verified 2 file(s): 2000 blocks in-stream, 0 by read-back, 0 bad
/// [extract] renamed caf\u{FFFD}.mkv -> _nzbfast-swap-0
/// tree: _nzbfast-swap-0 (220000 bytes), caf\u{e9}.mkv (220000 bytes)
/// ```
///
/// Both payloads present, every block of both verified, and one of them
/// come to rest under the plan's own temp name - the user's file, named
/// after the machinery that moved it, with nothing in the log or the
/// verdict to say so.
///
/// TWO STEPS OF THE PREDICTED CHAIN CAME OUT THE OTHER WAY, and they are
/// written here because the claim asserted both. `stem_is_a_name` on the
/// swap temp is TRUE, not false - it splits on `.`, `_`, ` ` and `-`, so
/// `.nzbfast-swap-0` is three tokens and no rule below the single-token
/// gate can reach it - which means the deferral FIRES rather than
/// declining, and the file does not stay under the mojibake spelling. And
/// the resting name is `_nzbfast-swap-0` and not `.nzbfast-swap-0`,
/// because `nzbkit::disk::sanitize_out_name` takes the leading dot off on
/// the way through the publish - so the file is not hidden either. The
/// defect is real and its shape is milder than the reading that predicted
/// it: a visible payload under a nonsense name, rather than an invisible
/// one under a wrong name.
///
/// What must hold: both payloads survive, and no output name is a swap
/// temp or otherwise hidden.
///
/// The `Fixture` binding is held to the end of the body: `out` lives
/// inside it and its `ScratchDir` guard deletes the tree on drop, so an
/// assertion made after it has gone grades an emptied directory.
#[tokio::test(flavor = "multi_thread")]
async fn a_slot_that_moves_and_comes_back_is_never_parked_on_a_swap_temp() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = payloads::unique_payload(220_000, 71);
    let b = payloads::unique_payload(220_000, 72);
    let fx = mojibake_cycle_fixture("norarmojicycle", &a, &b, READABLE);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "an intact post failed:\n{log}");
    assert!(
        payload_survived(&out, &a) && payload_survived(&out, &b),
        "one payload was renamed over by the other - tree {:?}\n{log}",
        tree_names(&out)
    );
    let parked: Vec<String> = out_tree(&out)
        .into_iter()
        .map(|(n, _)| n)
        .filter(|n| {
            n.rsplit('/')
                .next()
                .is_some_and(|leaf| leaf.starts_with('.') || leaf.contains("nzbfast-swap"))
        })
        .collect();
    assert!(
        parked.is_empty(),
        "a payload came to rest under the plan's own swap temp: {parked:?} - \
         tree {:?}\n{log}",
        tree_names(&out)
    );
    let got = std::fs::read(out.join(READABLE))
        .unwrap_or_else(|e| panic!("the FileDesc name did not land: {e}\n{log}"));
    assert!(
        got == b,
        "the set member's own descriptor name carries the OTHER slot's \
         bytes - tree {:?}\n{log}",
        tree_names(&out)
    );
    let back = std::fs::read(out.join(format!("000-{READABLE}"))).unwrap_or_else(|e| {
        panic!(
            "the deferred take-back did not land: {e}\ntree {:?}\n{log}",
            tree_names(&out)
        )
    });
    assert!(back == a, "the take-back carries the wrong bytes\n{log}");
    let mojibake: Vec<String> = tree_names(&out)
        .into_iter()
        .filter(|n| n.contains(char::REPLACEMENT_CHARACTER))
        .collect();
    assert!(
        mojibake.is_empty(),
        "a lossily-decoded FileDesc name reached the output tree: {mojibake:?}\n{log}"
    );
}

/// CONTROL - the same M4-86 slot with NOTHING wanting its leaf, so the
/// cycle arm never reaches it.
///
/// GREEN on both sides of the fix, and that is what it is for: it says a
/// red above is the CYCLE and not the M4-86 deferral itself, which is the
/// half the row above cannot tell apart on its own. Slot 1's descriptor
/// names a third file entirely.
#[tokio::test(flavor = "multi_thread")]
async fn the_mojibake_deferral_is_untouched_when_nothing_wants_its_leaf() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let a = payloads::unique_payload(220_000, 73);
    let b = payloads::unique_payload(220_000, 74);
    let fx = mojibake_cycle_fixture("norarmojiplain", &a, &b, OTHER);
    let (log, ok, out) = run_norar(&fx).await;
    assert!(ok, "CONTROL: an intact post failed:\n{log}");
    let got = std::fs::read(out.join(READABLE))
        .unwrap_or_else(|e| panic!("CONTROL: the readable yEnc name did not survive: {e}\n{log}"));
    assert!(
        got == a,
        "CONTROL: the readable name carries the wrong bytes - tree {:?}\n{log}",
        tree_names(&out)
    );
    let other = std::fs::read(out.join(OTHER))
        .unwrap_or_else(|e| panic!("CONTROL: the second descriptor name did not land: {e}\n{log}"));
    assert!(other == b, "CONTROL: the second slot's bytes moved\n{log}");
    let mojibake: Vec<String> = tree_names(&out)
        .into_iter()
        .filter(|n| n.contains(char::REPLACEMENT_CHARACTER))
        .collect();
    assert!(
        mojibake.is_empty(),
        "CONTROL: a lossily-decoded FileDesc name reached the output tree: \
         {mojibake:?}\n{log}"
    );
}

/// The second member's hash FileDesc, for the two-deferrer row below.
const HASH2: &str = "Wq4TnZb8LcRf3Ju.mkv";

/// Claim `publishplan-two-deferrers-crossing`, 31 Aug 2026 - the half of
/// that question that can be BUILT, and a note about the half that
/// cannot.
///
/// # Crossing two deferrers is not constructible, and that is provable
///
/// The claim asks what happens when D1 sits at X and its set names it Y
/// while D2 sits at Y and its set names it X. That shape cannot exist.
/// Write L for a deferrer's current leaf and P for the name its set gives
/// it; `get::settle::set_name_loses_to_held` is what puts a slot in
/// `defers` and it has exactly two arms:
///
/// * BOTH arms require `stem_is_a_name(L)`, so a deferrer's LEAF is
///   always a name;
/// * arm 1 (`lossy_name_loses_to`, M4-86) additionally requires P to
///   contain U+FFFD and L NOT to;
/// * arm 2 (GH #63) additionally requires `!stem_is_a_name(P)`.
///
/// Crossing means D1.P = D2.L and D2.P = D1.L. If D1 is on arm 2 then
/// D1.P is not a name, but D1.P is D2.L, which is - so D1 must be on arm
/// 1 alone, and so must D2. But then D1.P contains U+FFFD while D1.P is
/// D2.L, which arm 1 forbids from containing it. Both arms are refused,
/// so no such pair exists. That argument is about the names as those two
/// predicates read them; the cycle arm compares
/// `nzbkit::disk::sanitize_out_name`d, case-folded, out-relative forms of
/// them, so a sanitizer or a case fold that changed a name's readability
/// would be the joint to re-examine, not this reasoning.
///
/// # What the claim was really asking, and what this row measures
///
/// The substance was the REPAIR WINDOW: with two deferrers in one set,
/// neither member is at the name its set knows while `run_set_repair`
/// runs. That does not need a cross - an occupant sitting on the
/// transient target is enough, and
/// `a_borrowed_transient_target_does_not_evict_the_occupant_sitting_on_it`
/// above measured it for ONE deferrer, which is what the claim says is
/// not established for two.
///
/// So this is that row doubled: two set members, each a GH #63 deferrer,
/// each with an UNCOVERED payload squatting on the hash its descriptor
/// gives it, and BOTH damaged. Both members are therefore pushed onto
/// `{slot:03}-` forms of the set's own spelling before repair runs, and
/// both must still be rebuilt in place.
///
/// The damage is load-bearing: intact, repair never runs and the question
/// is not asked at all. `r=30` and not the 10 the intact rows use -
/// two corrupt 40,000-byte articles is roughly 364 blocks of a 2,000-block
/// set, which `r=10` cannot cover, and the row would then be graded on
/// the adoption scan rather than on where the files were.
///
/// MEASURED, and the answer is that it generalises - repair reaches BOTH
/// members through the slot, exactly as it reached one:
///
/// ```text
/// [extract] renamed Real.Feature...mkv -> 000-KpZ7mQx4TvB9nR2sLdFq.mkv
/// [extract] renamed Other.Feature...mkv -> 001-Wq4TnZb8LcRf3Ju.mkv
/// [verify] verified 2 file(s): 1634 blocks in-stream, 366 by read-back, 366 bad
/// [repair] repair complete ... (native, mapped: 366 block(s) rebuilt directly into the output)
/// [extract] renamed 000-KpZ7mQx4TvB9nR2sLdFq.mkv -> Real.Feature...mkv
/// [extract] renamed 001-Wq4TnZb8LcRf3Ju.mkv -> Other.Feature...mkv
/// ```
///
/// Nothing adopted, nothing recreated, both squatters untouched. So the
/// claim's open half is closed as a NON-ISSUE, with the measurement
/// rather than by argument.
///
/// GREEN on both sides of the `publishplan-mover-that-also-defers` fix
/// above: neither member is a mover under either ordering, so this says
/// what two deferrers do rather than what that fix changed.
#[tokio::test(flavor = "multi_thread")]
async fn two_deferring_members_both_repair_with_neither_at_the_name_the_set_knows() {
    if !have_par2() {
        eprintln!("skipping: par2 not installed");
        return;
    }
    let m1 = payloads::unique_payload(220_000, 81);
    let m2 = payloads::unique_payload(220_000, 82);
    let o1 = payloads::unique_payload(220_000, 83);
    let o2 = payloads::unique_payload(220_000, 84);
    let mut fx = Fixture::new("norardefertwo");
    fx.add_file_renamed_by_par2(HASH, HONEST, &m1, 40_000);
    fx.add_file_renamed_by_par2(HASH2, OTHER, &m2, 40_000);
    assert!(
        fx.add_par2(30, &[HASH, HASH2], 40_000),
        "par2 create failed"
    );
    // After the set is built, so both squatters are genuinely outside it -
    // each only shares the NAME its member's descriptor uses.
    std::fs::remove_file(fx.dir.join(HASH)).unwrap();
    std::fs::remove_file(fx.dir.join(HASH2)).unwrap();
    fx.add_file(HASH, &o1, 40_000);
    fx.add_file(HASH2, &o2, 40_000);
    // The FOURTH article of each member. Asserted before the run: ids that
    // have moved damage nothing and would make this pass for no reason.
    let d1 = format!("<{}-3@mock>", HONEST.replace('.', "_") + "-0");
    let d2 = format!("<{}-3@mock>", OTHER.replace('.', "_") + "-1");
    for id in [&d1, &d2] {
        assert!(
            fx.articles.contains_key(id),
            "the fixture's article ids moved, so nothing is being damaged: {:?}",
            fx.articles.keys().take(8).collect::<Vec<_>>()
        );
    }
    let chaos = Chaos {
        corrupt: [d1, d2].into_iter().collect(),
        ..Chaos::default()
    };
    let (log, ok, out) = run_norar_chaos(&fx, chaos).await;
    assert!(ok, "a repairable post failed:\n{log}");
    for (name, want, what) in [
        (HASH, &o1, "the first squatter"),
        (HASH2, &o2, "the second squatter"),
    ] {
        let got = std::fs::read(out.join(name)).unwrap_or_else(|e| {
            panic!(
                "{what} lost the name it never gave up - tree {:?}: {e}\n{log}",
                tree_names(&out)
            )
        });
        assert!(
            got == *want,
            "{what}'s name carries somebody else's bytes - tree {:?}\n{log}",
            tree_names(&out)
        );
    }
    for (name, want, what) in [
        (HONEST, &m1, "the first member"),
        (OTHER, &m2, "the second member"),
    ] {
        let got = std::fs::read(out.join(name)).unwrap_or_else(|e| {
            panic!(
                "{what}'s honest subject did not come back - tree {:?}: {e}\n{log}",
                tree_names(&out)
            )
        });
        assert!(
            got == *want,
            "{what}'s take-back carries the damage - tree {:?}\n{log}",
            tree_names(&out)
        );
    }
    // The shape, asserted rather than assumed: a green run that never
    // pushed either member off the set's own spelling, or never repaired,
    // would satisfy every assertion above while measuring nothing.
    for want in [
        format!("\u{2192} 000-{HASH}"),
        format!("\u{2192} 001-{HASH2}"),
        "rebuilt directly into the output".to_string(),
    ] {
        assert!(
            log.contains(&want),
            "the row did not reach the shape it grades - no {want:?} in the \
             log, so either a member was never disambiguated off the set's \
             spelling or repair never ran\n{log}"
        );
    }
    assert!(
        !log.contains("recreated"),
        "repair could not find a member under the name the set knows and \
         rebuilt it beside the bytes instead - tree {:?}\n{log}",
        tree_names(&out)
    );
}
