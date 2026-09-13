//! The job model: what a host asks for, and what it is shown back.
//!
//! Every shape here is `research/PLAN-PARFAST-GUI-2026-09-12.md`
//! section 4.5, to the letter, because two UI lanes were coding against
//! that section before this crate existed. The rule that follows from
//! that, and it is a hard one: a field may be ADDED and an enum value
//! may be ADDED, and nothing may be renamed or removed. Every addition
//! is recorded in `crates/parfast-ffi/API.md` with the date and the
//! reason.
//!
//! # Why the specs are all-optional on the way in
//!
//! A host builds a `JobSpec` field by field as a human fills a pane in,
//! and a pane that is half filled must still round-trip through
//! `pf_plan_preview`. So everything that CAN be defaulted is, and the
//! refusals happen where they can say something useful - in the planner
//! and the runner, against real paths - rather than in serde, where the
//! only thing a host would learn is that its JSON was wrong.

use std::path::PathBuf;

use serde::{Deserialize, Serialize};

/// One source a create or checksum job protects.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct Source {
    pub path: PathBuf,
    /// Walk a directory rather than taking only the files directly in
    /// it. Meaningless on a file, and ignored there rather than
    /// refused.
    #[serde(default)]
    pub recursive: bool,
}

/// How a source's on-disk path becomes the name inside the packets.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum PathMode {
    /// The file's own name and nothing else, which is what the
    /// reference does with no `-B`.
    #[default]
    Basename,
    /// The path relative to `base_path`, which is `-B`.
    Relative,
}

/// `-s` or `-b`: a block SIZE, or a block COUNT to fit under.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum BlockSpec {
    Size { size: u64 },
    Count { count: u64 },
}

/// `-r` or `-c`: a percentage, a block count, or a target size.
#[derive(Debug, Clone, Copy, PartialEq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum RecoverySpec {
    Percent { percent: f64 },
    Count { count: u64 },
    Size { size: u64 },
}

/// The ceiling a `pow2_limit` scheme puts on a volume.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
#[serde(untagged)]
pub enum Pow2Limit {
    /// `"largest_source"`, which is the reference's `-l`.
    Named(String),
    Blocks {
        blocks: u64,
    },
    Size {
        size: u64,
    },
}

/// The five volume schemes of section 4.5, which map one for one onto
/// `par2gen::VolumePlan` - see [`crate::planner`].
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(tag = "scheme", rename_all = "snake_case")]
pub enum VolumeSpec {
    /// One recovery file. `VolumePlan::Even(1)`.
    None,
    /// Equal-sized volumes. Exactly one of the three fields decides how
    /// many; they are three ways of asking the same question and the
    /// planner refuses more than one.
    Uniform {
        #[serde(default)]
        files: Option<u32>,
        #[serde(default)]
        blocks_per_file: Option<u64>,
        #[serde(default)]
        file_size: Option<u64>,
    },
    /// The exponential 1+2+4+8 split, which is the engine's and the
    /// reference's default.
    #[default]
    Pow2,
    /// The exponential split with a ceiling on each volume.
    Pow2Limit { limit: Pow2Limit },
}

/// The PAR2 unicode-packet policy. `auto` is whatever `par2gen` does
/// today and is the only value guaranteed to be honoured; the other two
/// are gated by `pf_capabilities.unicode_policy`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum UnicodePolicy {
    #[default]
    Auto,
    Never,
    Always,
}

/// The three process-GLOBAL engine knobs, per job. See
/// [`crate::runner`] for why "per job" is a promise the queue's lock
/// keeps and concurrency above 1 breaks.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct Perf {
    #[serde(default)]
    pub threads: Option<usize>,
    #[serde(default)]
    pub memory_mb: Option<u64>,
    #[serde(default)]
    pub low_priority: bool,
}

/// `{"kind":"create","create":{...}}`.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct CreateSpec {
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub path_mode: PathMode,
    #[serde(default)]
    pub base_path: Option<PathBuf>,
    #[serde(default)]
    pub block: Option<BlockSpec>,
    #[serde(default)]
    pub recovery: Option<RecoverySpec>,
    /// The `.par2` to write. The volumes take their base name from it.
    pub output: PathBuf,
    #[serde(default)]
    pub volumes: VolumeSpec,
    #[serde(default)]
    pub first_recovery_block: u64,
    #[serde(default)]
    pub comment: String,
    #[serde(default)]
    pub overwrite: bool,
    /// Spec-style `vol12-22` volume names. Gated by
    /// `pf_capabilities.std_naming`.
    #[serde(default)]
    pub std_naming: bool,
    #[serde(default)]
    pub unicode: UnicodePolicy,
    #[serde(default)]
    pub perf: Perf,
}

/// The switches a verify or a repair reads.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct VerifyOptions {
    /// `-O`: rename what is sitting under the wrong name and
    /// reconstruct nothing.
    #[serde(default)]
    pub rename_only: bool,
    /// `-S`'s companion: skip leading data when searching for blocks.
    #[serde(default)]
    pub data_skipping: bool,
    /// `-S<n>`: how far the skip may reach.
    #[serde(default)]
    pub skip_leaway: Option<u64>,
    /// `--fast`, the EXPERIMENTAL joint solve. `None` leaves the
    /// process default alone.
    #[serde(default)]
    pub fast_solver: Option<bool>,
    #[serde(default)]
    pub threads: Option<usize>,
}

/// `{"kind":"verify","verify":{...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct VerifySpec {
    pub par2: PathBuf,
    /// Extra directories to scan for blocks and for misnamed members -
    /// the bare arguments after the recovery-set name on the command
    /// line.
    #[serde(default)]
    pub extra_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub options: VerifyOptions,
}

/// `{"kind":"repair","repair":{...}}` - a verify spec plus the two
/// switches that only a repair has.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct RepairSpec {
    pub par2: PathBuf,
    #[serde(default)]
    pub extra_dirs: Vec<PathBuf>,
    #[serde(default)]
    pub options: VerifyOptions,
    /// `-p`: delete the recovery files and this run's backups once the
    /// repair has completed.
    #[serde(default)]
    pub purge: bool,
    /// Keep the `<name>.1` copy of each damaged original. The engine's
    /// backup-aside is unconditional; `false` removes the copies after
    /// a repair that completed, which is what the reference's own
    /// `-p` half does for them.
    #[serde(default = "yes")]
    pub keep_damaged: bool,
}

fn yes() -> bool {
    true
}

/// Which checksum file to write or read.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum ChecksumFormat {
    /// `.sfv`: CRC32, `name hex` per line.
    #[default]
    Sfv,
    /// `.md5`: `hex *name` per line, the coreutils/`md5sum` shape.
    Md5,
    Sha1,
    Sha256,
}

impl ChecksumFormat {
    /// The conventional extension, which is also how a host that only
    /// has a path guesses the format.
    pub fn extension(self) -> &'static str {
        match self {
            ChecksumFormat::Sfv => "sfv",
            ChecksumFormat::Md5 => "md5",
            ChecksumFormat::Sha1 => "sha1",
            ChecksumFormat::Sha256 => "sha256",
        }
    }

    /// The format a checksum file's name implies, or `None` for a name
    /// that implies nothing - in which case the CONTENT decides, which
    /// is [`crate::checksum::parse`]'s job and not this one's.
    pub fn from_extension(ext: &str) -> Option<ChecksumFormat> {
        match ext.to_ascii_lowercase().as_str() {
            "sfv" => Some(ChecksumFormat::Sfv),
            "md5" | "md5sum" => Some(ChecksumFormat::Md5),
            "sha1" | "sha1sum" => Some(ChecksumFormat::Sha1),
            "sha256" | "sha256sum" => Some(ChecksumFormat::Sha256),
            _ => None,
        }
    }
}

/// `{"kind":"checksum_create","checksum_create":{...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumCreateSpec {
    #[serde(default)]
    pub sources: Vec<Source>,
    #[serde(default)]
    pub format: ChecksumFormat,
    pub output: PathBuf,
    /// Write names relative to the output file's directory rather than
    /// bare basenames. ON, because that is what makes a checksum file
    /// over a tree usable.
    #[serde(default = "yes")]
    pub relative: bool,
}

/// `{"kind":"checksum_verify","checksum_verify":{...}}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct ChecksumVerifySpec {
    pub file: PathBuf,
}

/// What a host submits. The tag is `kind` and the payload rides in a
/// field named after it, exactly as section 4.5 spells it.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
#[serde(tag = "kind", rename_all = "snake_case")]
pub enum JobSpec {
    Create { create: CreateSpec },
    Verify { verify: VerifySpec },
    Repair { repair: RepairSpec },
    ChecksumCreate { checksum_create: ChecksumCreateSpec },
    ChecksumVerify { checksum_verify: ChecksumVerifySpec },
}

impl JobSpec {
    /// The `kind` string, which is what a snapshot carries.
    pub fn kind(&self) -> JobKind {
        match self {
            JobSpec::Create { .. } => JobKind::Create,
            JobSpec::Verify { .. } => JobKind::Verify,
            JobSpec::Repair { .. } => JobKind::Repair,
            JobSpec::ChecksumCreate { .. } => JobKind::ChecksumCreate,
            JobSpec::ChecksumVerify { .. } => JobKind::ChecksumVerify,
        }
    }

    /// What the queue shows in its Name column: the set, the output
    /// file or the checksum file, whichever this job is about.
    pub fn subject(&self) -> String {
        let p = match self {
            JobSpec::Create { create } => &create.output,
            JobSpec::Verify { verify } => &verify.par2,
            JobSpec::Repair { repair } => &repair.par2,
            JobSpec::ChecksumCreate { checksum_create } => &checksum_create.output,
            JobSpec::ChecksumVerify { checksum_verify } => &checksum_verify.file,
        };
        p.file_name()
            .map(|n| n.to_string_lossy().into_owned())
            .unwrap_or_else(|| p.to_string_lossy().into_owned())
    }
}

/// The five job kinds.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobKind {
    Create,
    Verify,
    Repair,
    ChecksumCreate,
    ChecksumVerify,
}

/// Where a job is in its life.
///
/// `interrupted` is an ADDITION to section 4.5, recorded in
/// `crates/parfast-ffi/API.md`: section 5.5 requires that a job which
/// was running when the app quit comes back marked *Interrupted* and
/// re-runnable, and none of the six states in 4.5 says that. It is
/// reached only by loading a persisted queue.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum JobState {
    Queued,
    Running,
    Paused,
    Done,
    Failed,
    Cancelled,
    Interrupted,
}

impl JobState {
    /// Is this job over? A finished job is the only kind
    /// `pf_job_remove` accepts.
    pub fn finished(self) -> bool {
        matches!(
            self,
            JobState::Done | JobState::Failed | JobState::Cancelled | JobState::Interrupted
        )
    }
}

/// The coarse phase a progress bar labels itself with.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum Phase {
    /// Reading the directory and the packets.
    #[default]
    Scanning,
    /// Reading and hashing the payload.
    Hashing,
    /// The fold and the solve.
    Solving,
    /// Writing recovery volumes, or repaired targets.
    Writing,
    /// The re-verify, the purge, the rename.
    Finishing,
}

/// One written file, as a create's result lists them.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct WrittenFile {
    pub name: String,
    pub size: u64,
}

/// A checksum job's tally.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct ChecksumResult {
    pub ok: usize,
    pub mismatch: usize,
    pub missing: usize,
    /// One row per entry, in the file's own order.
    ///
    /// An ADDITION beyond section 4.5, asked for by the Windows lane on
    /// 12 Sep 2026: section 5.4's Verify table is *Name | Expected |
    /// Status* per file, and three counts cannot draw it. Empty for a
    /// checksum CREATE, which has nothing to compare.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub entries: Vec<crate::checksum::Row>,
}

/// What a finished job produced.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct JobResult {
    #[serde(default)]
    pub repaired_files: usize,
    #[serde(default)]
    pub purged: bool,
    #[serde(default)]
    pub written: Vec<WrittenFile>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub checksum: Option<ChecksumResult>,
    /// The process exit code the equivalent `parfast` command line
    /// would have returned. An ADDITION to section 4.5: the CLI's
    /// dialect is the one thing a script user already knows, and a GUI
    /// that hides it makes its own behaviour unreproducible from a
    /// terminal.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub exit_code: Option<u8>,
}

/// Why a job failed, in the two fields section 4.5 names.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct JobError {
    pub code: String,
    pub message: String,
}

impl JobError {
    pub fn new(code: &str, message: impl Into<String>) -> JobError {
        JobError {
            code: code.to_string(),
            message: message.into(),
        }
    }
}

/// Everything a host is shown about one job.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct JobSnapshot {
    pub id: i64,
    pub kind: JobKind,
    pub state: JobState,
    pub phase: Phase,
    /// The sentence under the bar - "Hashing 7 of 23 files". Built
    /// HERE and not in either app, so the two say the same thing.
    pub phase_text: String,
    /// 0.0 to 1.0 over the whole job, monotone within a phase.
    pub progress: f64,
    pub elapsed_ms: u64,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub eta_ms: Option<u64>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub rate_bytes_per_s: Option<u64>,
    pub low_priority: bool,
    /// RFC 3339 in UTC.
    pub added_at: String,
    pub log_tail: Vec<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub survey: Option<crate::survey::SurveyModel>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub result: Option<JobResult>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub error: Option<JobError>,
    /// The `parfast` command line equivalent to this job, for the
    /// Advanced pane's "show the equivalent command". An ADDITION to
    /// section 4.5; empty for the two checksum kinds, which have no
    /// CLI equivalent.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub command: String,
}

impl JobSnapshot {
    /// A freshly queued job, before a worker has touched it.
    pub fn queued(id: i64, kind: JobKind, added_at: String, low_priority: bool) -> JobSnapshot {
        JobSnapshot {
            id,
            kind,
            state: JobState::Queued,
            phase: Phase::Scanning,
            phase_text: String::new(),
            progress: 0.0,
            elapsed_ms: 0,
            eta_ms: None,
            rate_bytes_per_s: None,
            low_priority,
            added_at,
            log_tail: Vec::new(),
            survey: None,
            result: None,
            error: None,
            command: String::new(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Section 4.5's own create example, parsed field for field. If
    /// this test has to change, two UI lanes have to change with it.
    #[test]
    fn the_contracts_create_spec_parses_as_written() {
        let json = r#"{"kind":"create","create":{
          "sources":[{"path":"/abs/a.bin"},{"path":"/abs/dir","recursive":true}],
          "path_mode":"basename","base_path":"/abs",
          "block":{"size":1048576},
          "recovery":{"percent":10.0},
          "output":"/abs/name.par2",
          "volumes":{"scheme":"uniform","files":7},
          "first_recovery_block":0,"comment":"","overwrite":false,
          "std_naming":false,"unicode":"auto",
          "perf":{"threads":null,"memory_mb":null,"low_priority":false}}}"#;
        let spec: JobSpec = serde_json::from_str(json).expect("4.5's create example parses");
        let JobSpec::Create { create } = &spec else {
            panic!("kind create");
        };
        assert_eq!(create.sources.len(), 2);
        assert!(create.sources[1].recursive);
        assert_eq!(create.block, Some(BlockSpec::Size { size: 1_048_576 }));
        assert_eq!(
            create.recovery,
            Some(RecoverySpec::Percent { percent: 10.0 })
        );
        assert_eq!(
            create.volumes,
            VolumeSpec::Uniform {
                files: Some(7),
                blocks_per_file: None,
                file_size: None,
            }
        );
        assert_eq!(spec.kind(), JobKind::Create);
        assert_eq!(spec.subject(), "name.par2");
    }

    /// The untagged block and recovery spellings must not collide:
    /// `{"count":N}` is a block COUNT and a recovery COUNT in their own
    /// fields, and neither may be read as the other's variant.
    #[test]
    fn the_untagged_allocation_spellings_do_not_collide() {
        let b: BlockSpec = serde_json::from_str(r#"{"count":2000}"#).expect("block count");
        assert_eq!(b, BlockSpec::Count { count: 2000 });
        let b: BlockSpec = serde_json::from_str(r#"{"size":4096}"#).expect("block size");
        assert_eq!(b, BlockSpec::Size { size: 4096 });
        let r: RecoverySpec = serde_json::from_str(r#"{"size":104857600}"#).expect("recovery size");
        assert_eq!(r, RecoverySpec::Size { size: 104_857_600 });
        let r: RecoverySpec = serde_json::from_str(r#"{"count":100}"#).expect("recovery count");
        assert_eq!(r, RecoverySpec::Count { count: 100 });
    }

    /// All five volume schemes of section 4.5, in the exact spellings
    /// the two UI lanes are emitting.
    #[test]
    fn all_five_volume_schemes_parse_in_the_contracts_spellings() {
        let cases: [(&str, VolumeSpec); 7] = [
            (r#"{"scheme":"none"}"#, VolumeSpec::None),
            (
                r#"{"scheme":"uniform","files":7}"#,
                VolumeSpec::Uniform {
                    files: Some(7),
                    blocks_per_file: None,
                    file_size: None,
                },
            ),
            (
                r#"{"scheme":"uniform","blocks_per_file":100}"#,
                VolumeSpec::Uniform {
                    files: None,
                    blocks_per_file: Some(100),
                    file_size: None,
                },
            ),
            (
                r#"{"scheme":"uniform","file_size":10485760}"#,
                VolumeSpec::Uniform {
                    files: None,
                    blocks_per_file: None,
                    file_size: Some(10_485_760),
                },
            ),
            (r#"{"scheme":"pow2"}"#, VolumeSpec::Pow2),
            (
                r#"{"scheme":"pow2_limit","limit":"largest_source"}"#,
                VolumeSpec::Pow2Limit {
                    limit: Pow2Limit::Named("largest_source".to_string()),
                },
            ),
            (
                r#"{"scheme":"pow2_limit","limit":{"blocks":512}}"#,
                VolumeSpec::Pow2Limit {
                    limit: Pow2Limit::Blocks { blocks: 512 },
                },
            ),
        ];
        for (json, want) in cases {
            let got: VolumeSpec =
                serde_json::from_str(json).unwrap_or_else(|e| panic!("{json}: {e}"));
            assert_eq!(got, want, "{json}");
        }
    }

    #[test]
    fn a_verify_spec_defaults_every_option_it_omits() {
        let spec: JobSpec =
            serde_json::from_str(r#"{"kind":"verify","verify":{"par2":"/abs/x.par2"}}"#)
                .expect("a bare verify spec parses");
        let JobSpec::Verify { verify } = &spec else {
            panic!("kind verify");
        };
        assert!(verify.extra_dirs.is_empty());
        assert_eq!(verify.options, VerifyOptions::default());
    }

    /// `keep_damaged` defaults to TRUE and not to serde's `bool`
    /// default, because the copy of a damaged original is the only
    /// thing standing between a wrong repair and a lost file.
    #[test]
    fn keep_damaged_defaults_on() {
        let spec: JobSpec =
            serde_json::from_str(r#"{"kind":"repair","repair":{"par2":"/abs/x.par2"}}"#)
                .expect("a bare repair spec parses");
        let JobSpec::Repair { repair } = &spec else {
            panic!("kind repair");
        };
        assert!(repair.keep_damaged);
        assert!(!repair.purge);
    }

    #[test]
    fn a_finished_state_is_the_only_removable_one() {
        assert!(!JobState::Queued.finished());
        assert!(!JobState::Running.finished());
        assert!(!JobState::Paused.finished());
        for s in [
            JobState::Done,
            JobState::Failed,
            JobState::Cancelled,
            JobState::Interrupted,
        ] {
            assert!(s.finished(), "{s:?}");
        }
    }

    #[test]
    fn checksum_formats_round_trip_through_their_extensions() {
        for f in [
            ChecksumFormat::Sfv,
            ChecksumFormat::Md5,
            ChecksumFormat::Sha1,
            ChecksumFormat::Sha256,
        ] {
            assert_eq!(ChecksumFormat::from_extension(f.extension()), Some(f));
        }
        assert_eq!(ChecksumFormat::from_extension("PAR2"), None);
    }
}
