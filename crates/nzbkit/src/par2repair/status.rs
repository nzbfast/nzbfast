//! What a directory repair hands back: [`RepairReport`] and
//! [`RepairStatus`]. A child module of `par2repair` (the `adopt` /
//! `donate` pattern) so par2repair.rs stays inside its size-gate
//! entry; `use super::*` keeps the parent's bindings in scope exactly
//! as they were inline.

use super::*;

#[derive(Debug)]
pub struct RepairReport {
    /// Input blocks reconstructed via Reed-Solomon.
    pub blocks_rebuilt: usize,
    /// Input blocks whose content was found intact under another name or
    /// offset by the extra-file adoption scan.
    pub blocks_adopted: usize,
    /// File names (as found on disk) that adopted blocks came from.
    pub adopted_from: Vec<String>,
    /// Files whose bytes were patched (includes created ones).
    pub files_patched: Vec<String>,
    /// Subset of `files_patched` that were missing entirely.
    pub files_created: Vec<String>,
    /// Full paths of the extra files this repair CONSUMED as adoption
    /// sources - obfuscated copies whose bytes now also exist under the
    /// name the PAR2 set gives them. The engine never deletes them (it
    /// does not own the directory), so a caller that DOES own it is told
    /// which files are now redundant; on an obfuscated post this is the
    /// difference between a finished folder and two copies of it.
    ///
    /// Recovery-set targets are excluded: a candidate can share a path
    /// with a target (exactly what `used_sources` forces through the
    /// temp+rename path below), and there the "source" IS the restored
    /// payload. Deleting it would undo the repair.
    pub consumed_sources: Vec<PathBuf>,
}

#[derive(Debug)]
pub enum RepairStatus {
    /// Every recovery-set file already verifies - nothing written.
    NoDamage,
    /// Damage found and repaired; every patched file re-verified by MD5.
    Repaired(RepairReport),
    /// Not enough recovery slices on disk for the damage found, with
    /// what adoption found and already subtracted - see [`adopt`].
    Unrepairable {
        needed: usize,
        have: usize,
        adopted: usize,
    },
}
