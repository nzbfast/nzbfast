//! The fourth arm of [`super::shortfall_is_final`]: does the strongest
//! evidence the set carries contradict the block grid's damage claim?
//!
//! Its own file rather than a block in `repair.rs`, which was the
//! NARROWEST file in the repo at 5 of the size gate's 3,000 lines free
//! when this landed - the same reason `volpayload`, `shortfall` and
//! `shortfall_gate_tests` are each out here. The body is a verbatim
//! move; its pins stay in `shortfall_gate_tests`, beside the other
//! three arms', because what they are really pinning is the CHAIN.

use super::*;

/// Does the strongest evidence the set carries CONTRADICT the block
/// grid's damage claim? The fourth arm of [`shortfall_is_final`], and
/// the only one that is not about finding more parity.
///
/// M4-69's authority rule, applied where the arithmetic is spent. The
/// FileDesc whole-file MD5 covers every byte of every block, so where it
/// matches, the settled file IS the file the set describes and an IFSC
/// entry disagreeing about those bytes is provably wrong about them, not
/// evidence of damage. `par2repair`'s own verify pass has always
/// answered `clean` that way ([`nzbkit::par2repair::md5_matches`], which
/// `verify_pass1` reads) - which is exactly why the disk path arbitrates
/// this correctly and simply never gets asked: this gate returns first.
///
/// IT IS A COST GATE AND CANNOT BE FALSIFIED BY VERDICT, which is what
/// M4-69's own settle-side latch says of itself, and reading it as a
/// correctness guard is the one way to get this wrong. Falling through
/// does not declare the post repairable; it runs the repair engine,
/// which re-derives everything from disk and reports the honest
/// post-adoption shortfall if there still is one - the property all
/// three arms above already lean on ("a false yes costs one repair pass
/// that ends in the same honest shortfall verdict with better
/// numbers"). What this decides is only whether the read is paid for.
///
/// WHAT IT COSTS, MEASURED 31 Aug 2026 - four shapes, one 8 MiB member,
/// debug build on a box at load 7, this function instrumented at every
/// exit. It is reached ONLY where `have < needed` and every cheaper arm
/// has declined, one statement before the job is reported unrepairable,
/// so nothing on a succeeding job pays anything. That is what separates
/// it from the "hash any damaged file" escalation M4-69 refused on the
/// settle path: that one fires on every damaged download, and damaged
/// downloads mostly succeed.
///
/// * THE WHOLLY-DEAD POST NEVER REACHES IT, which is the answer to the
///   question that held this back. On the §282 shape (195 of 210
///   payload articles refused) `adoption_candidates_present` falls
///   through two arms earlier and the engine reports the honest
///   post-adoption shortfall - ZERO bytes hashed here. Had it been
///   reached, the member was not on disk at all, so the `stat` screen
///   below declines for free.
/// * AN ORDINARY DAMAGED POST THAT CANNOT BE FUNDED pays one pass over
///   the damaged members and nothing else: 603 of 2000 blocks bad
///   against 400 carried, refuted in 82.9-87.0 ms over 8 MiB across
///   runs, then reported unrepairable exactly as before. That is
///   ~1.3 s/GiB, the MD5 figure M4-69 measured - so an 8 GB post that
///   is going to fail fails ~10 s later, against the 22.40 s one
///   SUCCESSFUL 8 GB repair takes when the parity IS there.
/// * THE CASE IT EXISTS FOR confirms in the same time and the job then
///   SUCCEEDS: half the IFSC CRC32 entries forged over byte-exact
///   bytes, `1000/2000 blocks bad` against 400 carried, confirmed in
///   83.2-108.8 ms, `repair complete (native - set already verifies on
///   disk)`.
///
/// TWO SCREENS, and they are the whole design.
///
/// * EVERY member must be on disk at its declared length, by `stat`
///   alone. A set with a member that is absent, short or long has real
///   work to do that no digest can argue away.
/// * Only the members the grid CLAIMS DAMAGED are hashed. That is what
///   keeps the read proportional to the damage claim rather than to the
///   download: on a 57-volume set with three damaged volumes this reads
///   three volumes, not the release.
///
/// A 16 KiB `md5_16k` PRE-SCREEN WAS BUILT, MEASURED AND REMOVED, and
/// it is recorded here so nobody adds it back on the argument that it
/// is obviously free. It is sound (the head is part of the file, so a
/// head that disagrees is a file whose whole-file MD5 cannot match) and
/// it bought NOTHING: on the one measured shape that pays - loss30
/// above - it passed and the full hash still ran. The reason is
/// structural rather than luck. A member is only here because it
/// reached `out_dir` under the name its descriptor declares, and
/// `md5_16k` is precisely what `live::nametier`, `live::matchref` and
/// `live::twintier` match a head against to claim that name - so on
/// this arm's population the screen has already effectively passed
/// before it is asked. Two guards where one is sufficient also make
/// both unfalsifiable, which is the rule `tools/cfg-safety-gate.py`'s
/// entry in CLAUDE.md was written for: no e2e shape could be built that
/// reached this arm with a damaged head, because losing the head is
/// what stops the name tier claiming the file at all (measured: a
/// head-loss fixture fell through at `adoption_candidates_present` and
/// repaired by adoption).
///
/// STATED LIMIT, rather than left to be found: `damaged` is keyed on the
/// `par2_name` a slot claimed IN ITS OWN SET, so where a per-file-set
/// post names one file two different things across two sets, this set
/// sees a shorter list. That is the permissive direction - fewer names
/// hashed, so it can only ever fall through where a longer list would
/// have declined - and a fall-through is one repair pass ending in the
/// same honest verdict.
pub(super) fn whole_file_md5_refutes_the_grid(
    out_dir: &Path,
    set: &nzbkit::par2::Par2Set,
    damaged: &[String],
) -> bool {
    // Nothing on disk is claimed damaged, so there is no claim here to
    // refute - a shortfall made entirely of files that are not there is
    // exactly the arithmetic this must not argue with.
    if damaged.is_empty() || set.files.is_empty() {
        return false;
    }
    let mut targets: Vec<(PathBuf, &nzbkit::par2::Par2File)> = Vec::new();
    for f in &set.files {
        let name = nzbkit::disk::sanitize_out_name(&f.name);
        let path = out_dir.join(&name);
        match std::fs::metadata(&path) {
            Ok(m) if m.is_file() && m.len() == f.length => {}
            _ => return false,
        }
        if damaged.iter().any(|d| *d == name.to_lowercase()) {
            targets.push((path, f));
        }
    }
    if targets.is_empty() {
        return false;
    }
    for (path, f) in &targets {
        // An IO error is not a refutation, and must not be read as one:
        // what a decline says is "this file is not provably the file the
        // descriptor names", which is exactly the honest answer when the
        // file could not be read. `md5_matches` re-checks the length
        // itself, so the `stat` above is a screen and never the proof.
        if !matches!(nzbkit::par2repair::md5_matches(path, f), Ok(true)) {
            return false;
        }
    }
    info!(
        target: "repair",
        "the whole-file MD5 of all {} damaged member(s) matches the set's own \
         descriptor - the block grid's damage claim is contradicted by the \
         strongest evidence this set carries",
        targets.len()
    );
    true
}
