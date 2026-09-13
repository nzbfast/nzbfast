//! Where a slabbed PAR2 solve keeps its rebuilt blocks between the last
//! slab and the patch phase.
//!
//! Cut out of `par2repair.rs` when slabbing landed (9 Sep 2026): the
//! staging choice is self-contained - it touches the rebuilt output and
//! nothing else in the driver - and the driver was at its size ceiling.

use super::reconstruct;
use crate::par2repair::RepairError;
use std::fs::File;
use std::path::{Path, PathBuf};

/// Where a slabbed solve keeps its rebuilt blocks until the patch phase
/// writes them into the members, and the whole memory trade in one type.
///
/// The disk driver's patch phase consumes the WHOLE rebuilt output - it
/// decides in-place versus temp file, copies present blocks over,
/// interleaves adopted ones and renames - so unlike the mapped driver it
/// cannot write each slab straight out as it is solved. The output has
/// to live somewhere between the last slab and the patch, and the three
/// arms are the three answers in order of preference. The plan picks the
/// first that fits; all three answer `write_block_to` identically, so
/// the patch phase cannot tell them apart.
pub(super) enum RebuiltStore {
    /// ONE slab, and the solve's own buffers are the output. Nothing is
    /// copied and nothing is allocated twice - this is the pre-slab
    /// driver exactly, and it is what an ordinary repair takes.
    Whole(Vec<reconstruct::RebuiltBlock>),
    /// Slabbed, with the assembled output resident. Costs `m x bs` of
    /// memory beside the solve's window and no I/O at all, so it is
    /// preferred over spilling whenever the budget has room for it.
    Assembled(Vec<Vec<u8>>),
    /// Slabbed, with the output staged on disk. The last resort, taken
    /// only when `m x bs` will not fit beside the window: it costs one
    /// write and one read of the whole rebuilt payload against the
    /// repair directory, which is far cheaper than not repairing.
    Spill {
        file: File,
        path: PathBuf,
        bs: u64,
        n: usize,
    },
}

impl RebuiltStore {
    pub(super) fn len(&self) -> usize {
        match self {
            Self::Whole(v) => v.len(),
            Self::Assembled(v) => v.len(),
            Self::Spill { n, .. } => *n,
        }
    }

    /// The scratch file for a spilled solve, in the repair directory:
    /// the one place already known writable and sized for this payload,
    /// and where these bytes are going anyway. `create_new` for the same
    /// reason the repair temps use it - the name must not be able to
    /// land on an existing file or follow a symlink out of the
    /// directory.
    pub(super) fn spill(dir: &Path, n: usize, bs: u64) -> Result<Self, RepairError> {
        let path = dir.join(format!(".nzbfast-repair-slab.{}.tmp", std::process::id()));
        let file = std::fs::OpenOptions::new()
            .read(true)
            .write(true)
            .create_new(true)
            .open(&path)?;
        // Sized up front so a short disk is reported HERE, by name and
        // before any solving, rather than as a truncated write in the
        // middle of the last slab.
        file.set_len(n as u64 * bs)?;
        Ok(Self::Spill { file, path, bs, n })
    }

    /// Park slab `[c0, c0 + w)` of every rebuilt block. Never called on
    /// [`Whole`](Self::Whole), which took the output by move.
    pub(super) fn put_slab(
        &mut self,
        blocks: &[reconstruct::RebuiltBlock],
        c0: usize,
        w: usize,
    ) -> Result<(), RepairError> {
        match self {
            Self::Whole(_) => Ok(()),
            Self::Assembled(v) => {
                for (mi, b) in blocks.iter().enumerate() {
                    v[mi][c0..c0 + w].copy_from_slice(&b[..w]);
                }
                Ok(())
            }
            Self::Spill { file, bs, .. } => {
                for (mi, b) in blocks.iter().enumerate() {
                    crate::disk::write_all_at(file, &b[..w], mi as u64 * *bs + c0 as u64)?;
                }
                Ok(())
            }
        }
    }

    /// Write `take` bytes of rebuilt block `mi` into `dst` at `off` -
    /// the one thing the patch phase asks of this type.
    pub(super) fn write_block_to(
        &self,
        mi: usize,
        take: usize,
        dst: &File,
        off: u64,
    ) -> Result<(), RepairError> {
        match self {
            Self::Whole(v) => crate::disk::write_all_at(dst, &v[mi][..take], off)?,
            Self::Assembled(v) => crate::disk::write_all_at(dst, &v[mi][..take], off)?,
            Self::Spill { file, bs, .. } => {
                let mut buf = vec![0u8; take];
                crate::disk::read_exact_at(file, &mut buf, mi as u64 * *bs)?;
                crate::disk::write_all_at(dst, &buf, off)?;
            }
        }
        Ok(())
    }
}

impl Drop for RebuiltStore {
    fn drop(&mut self) {
        if let Self::Spill { path, .. } = self {
            let _ = std::fs::remove_file(path);
        }
    }
}
