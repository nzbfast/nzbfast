//! The survey a block map is drawn from.
//!
//! `parfast::verify::Survey` is the CLI's answer - per member, a
//! `Found` / `Damaged{have,total}` / `Missing` and three totals - and
//! it is the authority on the VERDICT, because `owed()` and
//! `repairable()` are the rules par2cmdline was measured against. What
//! it has no room for is the two things a picture needs: WHERE the
//! damage is, and whether a member that is not at its own name is
//! nonetheless sitting in the directory under a different one.
//!
//! # The two mechanisms are kept apart, on purpose
//!
//! A file can be recovered without any parity in two completely
//! different ways, and `parfast`'s own comment warns that conflating
//! them left defect G4 open:
//!
//! * a WHOLE-FILE rename - some other file's bytes are exactly this
//!   member, so `-O` renames it and no block is rebuilt. That is
//!   [`FileStatus::Misnamed`], it carries `found_as`, and it is decided
//!   by the same `verify_file_md5_path` call `repair::rename_only`
//!   uses.
//! * BLOCK ADOPTION - individual blocks of this member turn up
//!   elsewhere (or at a shifted offset inside the member itself), and
//!   the fold takes them instead of rebuilding them. Those blocks are
//!   already `present` in the bitmap `parfast::verify::survey_bits`
//!   returns, because the engine's rolling scan put them there, and
//!   they are NEVER drawn as `misnamed`.
//!
//! One picture, two mechanisms, no arithmetic that adds them together.

use std::path::Path;

use serde::{Deserialize, Serialize};

/// One member's state, in the vocabulary the block map and the file
/// table share.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum FileStatus {
    /// Whole-file MD5 matched at the declared length.
    Complete,
    /// Present, and some blocks did not.
    Damaged,
    /// Not on disk at all, and nothing in the directory is it.
    Missing,
    /// Not at its own name, but another file in the directory IS it,
    /// byte for byte. `found_as` names that file.
    Misnamed,
    /// A file in the directory that this set does not describe. Never
    /// produced by [`SurveyModel::from_parfast`]; the host adds these
    /// when it wants the extras listed beside the members.
    Extra,
    /// Being read right now.
    Hashing,
    /// Not looked at yet.
    Pending,
}

/// One row of the file table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct FileRow {
    /// The FileDesc name, exactly as the packet spells it.
    pub name: String,
    /// The length the set declares, in bytes.
    pub size: u64,
    pub status: FileStatus,
    pub blocks_ok: usize,
    pub blocks_total: usize,
    /// Absolute path of the file that turned out to BE this member,
    /// for [`FileStatus::Misnamed`] and nothing else.
    #[serde(skip_serializing_if = "Option::is_none")]
    pub found_as: Option<String>,
    /// How far this member's own hashing has got, 0.0 to 1.0.
    pub progress: f64,
}

/// The whole-set verdict.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Verdict {
    /// The pass is still running.
    Verifying,
    /// Every member is whole.
    Complete,
    /// Damaged, and the recovery data on hand covers what is owed.
    Repairable,
    /// Damaged, and it does not.
    Unrepairable,
    /// A repair ran and the set is whole now.
    Repaired,
    /// A repair ran and it is not.
    Failed,
}

/// A block state code, as `block_runs` encodes it. The numbers are
/// section 4.5's and are wire format: never renumber them.
pub mod block_state {
    pub const PENDING: u8 = 0;
    pub const PRESENT: u8 = 1;
    pub const DAMAGED: u8 = 2;
    pub const MISSING: u8 = 3;
    /// Supplied by a whole file found under another name.
    pub const MISNAMED: u8 = 4;
    pub const HASHING: u8 = 5;
}

/// What a block map draws, and nothing else.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct SurveyModel {
    pub set_name: String,
    pub folder: String,
    pub block_size: u64,
    pub source_blocks: usize,
    pub recovery_available: usize,
    /// Blocks nothing on disk can supply - `Survey::owed()`.
    pub recovery_needed: usize,
    pub verdict: Verdict,
    pub files: Vec<FileRow>,
    /// Run-length encoded over the source blocks in SET order:
    /// `[state, length]` pairs, states per [`block_state`]. Adjacent
    /// runs of one state are merged, including across a file boundary -
    /// the map is one strip, not one strip per file.
    pub block_runs: Vec<[u64; 2]>,
}

impl SurveyModel {
    /// An empty model for a set that has not been read yet, so a host
    /// has something to draw the moment a job starts running.
    pub fn pending(set_name: String, folder: String) -> SurveyModel {
        SurveyModel {
            set_name,
            folder,
            block_size: 0,
            source_blocks: 0,
            recovery_available: 0,
            recovery_needed: 0,
            verdict: Verdict::Verifying,
            files: Vec::new(),
            block_runs: Vec::new(),
        }
    }

    /// Build the model from one `parfast` verify pass.
    ///
    /// `bits` is `parfast::verify::survey_bits`'s second answer: one
    /// row per member in SET order, each row one bool per block, empty
    /// for a member that is not on disk. `candidates` is
    /// `parfast::verify::extra_candidates` - the directory's unclaimed
    /// files, which is where a misnamed member is found.
    ///
    /// The verdict is `Survey::repairable()`, never a second reading of
    /// it: that predicate is what the conformance table pins, and a
    /// picture that disagreed with the exit code would be worse than no
    /// picture.
    pub fn from_parfast(
        loaded: &parfast::verify::Loaded,
        survey: &parfast::verify::Survey,
        bits: &[Vec<bool>],
        candidates: &[std::path::PathBuf],
    ) -> SurveyModel {
        use parfast::verify::Target;

        let bs = loaded.set.block_size;
        let folder = loaded.dir.to_string_lossy().into_owned();
        let set_name = loaded
            .par_files
            .first()
            .and_then(|p| p.file_name())
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_default();

        // A candidate is consumed by the FIRST member it matches, the
        // same rule `repair::rename_only` applies when it does the
        // renaming - otherwise one spare copy would be reported as the
        // rescue of three different missing members.
        let mut unclaimed: Vec<&std::path::Path> = candidates.iter().map(|p| p.as_path()).collect();

        let mut files = Vec::with_capacity(survey.targets.len());
        let mut runs: Vec<[u64; 2]> = Vec::new();
        for (idx, (name, target)) in survey.targets.iter().enumerate() {
            let file = loaded.set.files.iter().find(|f| &f.name == name);
            let size = file.map(|f| f.length).unwrap_or(0);
            let blocks_total = if bs == 0 {
                0
            } else {
                size.div_ceil(bs) as usize
            };
            let row_bits = bits.get(idx).map(Vec::as_slice).unwrap_or(&[]);
            let (status, found_as, blocks_ok) = match target {
                Target::Found => (FileStatus::Complete, None, blocks_total),
                Target::Damaged { have, .. } => (FileStatus::Damaged, None, *have),
                // `blocks_ok` is blocks AT THIS MEMBER'S OWN NAME, so a
                // misnamed member has none - its bytes are under the
                // name in `found_as`. Reporting `blocks_total` here
                // would contradict `recovery_needed`, which counts
                // those same blocks as owed, inside one object.
                Target::Missing => match file.and_then(|f| claim_misnamed(&mut unclaimed, f)) {
                    Some(path) => (FileStatus::Misnamed, Some(path), 0),
                    None => (FileStatus::Missing, None, 0),
                },
            };
            push_blocks(&mut runs, status, row_bits, blocks_total);
            files.push(FileRow {
                name: name.clone(),
                size,
                status,
                blocks_ok,
                blocks_total,
                found_as,
                progress: 1.0,
            });
        }

        // THE VERDICT IS THE CLI'S THREE PREDICATES, CALLED AND NOT
        // RESTATED - the same `damaged()` and `repairable()`, in the
        // same order, that `parfast::verify::print_verdict` turns into
        // an exit code. So `complete` is exactly exit 0, `repairable`
        // exactly exit 1 and `unrepairable` exactly exit 2, and a
        // snapshot cannot carry a verdict that argues with the
        // `exit_code` beside it.
        //
        // IT DID ARGUE, and this is the whole reason the rule is now
        // spelled this way. Until 12 Sep 2026 this read `owed == 0` for
        // complete and subtracted a misnamed member's blocks from what
        // was owed first, on the argument that the bytes are on hand
        // and the engine's adoption pass takes them without parity. The
        // argument is true and the conclusion was wrong: a member that
        // is not at its own name still needs an ACTION - a repair, or
        // `-O`'s rename - and the reference says so, "1 file(s) are
        // missing" and exit 1. The mac lane found it on the corpus's
        // `misnamed` scenario, where the window showed "Complete - no
        // repair needed" in green, with Repair disabled, over a set the
        // CLI repairs. A confident green over a broken set is the worst
        // answer this model can give.
        let owed = survey.owed();
        let verdict = if !survey.damaged() {
            Verdict::Complete
        } else if survey.repairable() {
            Verdict::Repairable
        } else {
            Verdict::Unrepairable
        };

        SurveyModel {
            set_name,
            folder,
            block_size: bs,
            source_blocks: survey.total_blocks,
            recovery_available: survey.recovery_blocks,
            recovery_needed: owed,
            verdict,
            files,
            block_runs: runs,
        }
    }
}

/// The first unclaimed file in the directory whose bytes ARE this
/// member, removed from the pool. The predicate is
/// `nzbkit::par2::verify_file_md5_path`, which is the one
/// `repair::rename_only` renames on - so what the map promises and what
/// `-O` would do cannot disagree.
fn claim_misnamed(pool: &mut Vec<&Path>, file: &nzbkit::par2::Par2File) -> Option<String> {
    let pos = pool
        .iter()
        .position(|c| nzbkit::par2::verify_file_md5_path(c, file).unwrap_or(false))?;
    let path = pool.remove(pos);
    Some(path.to_string_lossy().into_owned())
}

/// Append one member's blocks to the run-length strip, merging with
/// whatever ran into it.
pub(crate) fn push_blocks(
    runs: &mut Vec<[u64; 2]>,
    status: FileStatus,
    bits: &[bool],
    total: usize,
) {
    for i in 0..total {
        let state = match status {
            FileStatus::Complete => block_state::PRESENT,
            FileStatus::Misnamed => block_state::MISNAMED,
            FileStatus::Missing => block_state::MISSING,
            FileStatus::Hashing => block_state::HASHING,
            FileStatus::Pending | FileStatus::Extra => block_state::PENDING,
            // The bitmap is the whole point on a damaged member: it is
            // where the rolling scan's finds are, so a block the engine
            // located at a shifted offset draws PRESENT and not
            // DAMAGED.
            FileStatus::Damaged => {
                if bits.get(i).copied().unwrap_or(false) {
                    block_state::PRESENT
                } else {
                    block_state::DAMAGED
                }
            }
        };
        push_run(runs, state);
    }
}

/// One block onto the strip.
fn push_run(runs: &mut Vec<[u64; 2]>, state: u8) {
    match runs.last_mut() {
        Some(last) if last[0] == u64::from(state) => last[1] += 1,
        _ => runs.push([u64::from(state), 1]),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn strip(pairs: &[(u8, u64)]) -> Vec<[u64; 2]> {
        pairs.iter().map(|&(s, n)| [u64::from(s), n]).collect()
    }

    /// Runs merge ACROSS a file boundary: the map is one strip, and two
    /// adjacent complete files are one run and not two.
    #[test]
    fn adjacent_runs_merge_across_a_file_boundary() {
        let mut runs = Vec::new();
        push_blocks(&mut runs, FileStatus::Complete, &[], 3);
        push_blocks(&mut runs, FileStatus::Complete, &[], 2);
        assert_eq!(runs, strip(&[(block_state::PRESENT, 5)]));
    }

    /// A damaged member draws from the BITMAP, so a block the rolling
    /// scan found at a shifted offset is present, not damaged.
    #[test]
    fn a_damaged_members_strip_comes_from_the_bitmap() {
        let mut runs = Vec::new();
        push_blocks(
            &mut runs,
            FileStatus::Damaged,
            &[true, true, false, true],
            4,
        );
        assert_eq!(
            runs,
            strip(&[
                (block_state::PRESENT, 2),
                (block_state::DAMAGED, 1),
                (block_state::PRESENT, 1),
            ])
        );
    }

    /// A bitmap SHORTER than the member's block count (no IFSC packets
    /// for the tail, or a row this pass never filled) reads as damaged
    /// rather than panicking or as present.
    #[test]
    fn a_short_bitmap_reads_as_damaged_and_never_panics() {
        let mut runs = Vec::new();
        push_blocks(&mut runs, FileStatus::Damaged, &[true], 3);
        assert_eq!(
            runs,
            strip(&[(block_state::PRESENT, 1), (block_state::DAMAGED, 2)])
        );
    }

    /// The four whole-member statuses each draw one state for the whole
    /// member, and a misnamed one is NEVER drawn as present - a reader
    /// has to be able to see that those blocks arrived by a rename.
    #[test]
    fn a_misnamed_member_draws_its_own_state() {
        let mut runs = Vec::new();
        push_blocks(&mut runs, FileStatus::Misnamed, &[], 2);
        push_blocks(&mut runs, FileStatus::Missing, &[], 1);
        assert_eq!(
            runs,
            strip(&[(block_state::MISNAMED, 2), (block_state::MISSING, 1)])
        );
    }

    #[test]
    fn an_empty_member_contributes_no_run() {
        let mut runs = Vec::new();
        push_blocks(&mut runs, FileStatus::Complete, &[], 0);
        assert!(runs.is_empty());
    }

    #[test]
    fn a_pending_model_is_drawable_before_anything_is_read() {
        let m = SurveyModel::pending("x.par2".into(), "/abs".into());
        assert_eq!(m.verdict, Verdict::Verifying);
        assert!(m.block_runs.is_empty());
        let json = serde_json::to_string(&m).expect("serialises");
        assert!(json.contains(r#""verdict":"verifying""#), "{json}");
    }

    /// The wire codes are format, not an implementation detail: a
    /// renumber would silently recolour every block map in both apps.
    #[test]
    fn the_block_state_codes_are_the_contracts_numbers() {
        assert_eq!(block_state::PENDING, 0);
        assert_eq!(block_state::PRESENT, 1);
        assert_eq!(block_state::DAMAGED, 2);
        assert_eq!(block_state::MISSING, 3);
        assert_eq!(block_state::MISNAMED, 4);
        assert_eq!(block_state::HASHING, 5);
    }
}
