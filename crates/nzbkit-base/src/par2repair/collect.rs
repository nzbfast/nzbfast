//! Which files in a directory are PAR2 PACKET files - by name, and by
//! the content sniff an obfuscated post leaves as the only way to find
//! its recovery volumes.
//!
//! Split out of par2repair.rs on 30 Aug 2026 under the size gate (TODO
//! 106), as one subject: the ceiling on how much attacker-chosen input
//! one directory entry becomes, and the two questions that decide
//! whether an entry pays it. The catalog's incremental `relist` asks the
//! same pair a second time over a stamp cache it maintains itself, which
//! is why the PREDICATE lives in `par2::head_is_packet_file` rather than
//! here - two readers, one rule (M4-65).
//!
//! Reached by `#[path]` from par2repair.rs, so `use super::*` names that
//! module and every call site above is unchanged.

use super::*;

/// Ceiling on one packet file. Every consumer below reads a packet file
/// WHOLE (`std::fs::read`, because `scan_packets` walks a slice and
/// recovery slices are copied straight out of it), so this is the bound
/// on how much attacker-chosen input one directory entry can turn into
/// resident memory.
///
/// It applies by SIZE, never by name: the extension is chosen by the
/// poster, so letting `*.par2` past a bound that extensionless volumes
/// have to clear would make the bound optional - rename the file and it
/// is gone (Codex sweep 10 Aug, M4). A real recovery volume is orders of
/// magnitude under this; a file over it is either not a volume at all or
/// one no repair could afford to load.
pub const MAX_PACKET_FILE_BYTES: u64 = 1 << 30;

/// Gather the PAR2 packet files in `dir`: `*.par2` by name, plus
/// magic-sniffed files (obfuscated posts rename recovery volumes too, and
/// par2cmdline - handed extra files - loads packets from them, so do we).
/// Sniffing costs one 8-byte read per file. Oversized candidates are
/// skipped rather than slurped, by name and by sniff alike - see
/// [`MAX_PACKET_FILE_BYTES`]. Returns (sorted packet files, the subset
/// found by sniff rather than name).
fn collect_packet_files(dir: &Path) -> Result<(Vec<PathBuf>, HashSet<PathBuf>), RepairError> {
    collect_packet_files_bounded(dir, MAX_PACKET_FILE_BYTES)
}

/// [`collect_packet_files`] with the ceiling spelled out, so a test can
/// exercise the bound without writing a gigabyte.
pub(super) fn collect_packet_files_bounded(
    dir: &Path,
    max_bytes: u64,
) -> Result<(Vec<PathBuf>, HashSet<PathBuf>), RepairError> {
    let mut packet_files: Vec<PathBuf> = Vec::new();
    let mut sniffed: HashSet<PathBuf> = HashSet::new();
    for cand in nested::walk_candidates(dir, PacketScope::Flat)? {
        let p = cand.path;
        let len = cand.meta.len();
        if p.extension()
            .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
        {
            if len > max_bytes {
                warn!(
                    file = %p.display(),
                    bytes = len,
                    "skipping oversized .par2 - past the packet-file ceiling"
                );
                continue;
            }
            packet_files.push(p);
        } else if (64..=max_bytes).contains(&len) {
            // A WINDOW, not byte 0 (M4-65): the magic may sit behind a
            // short prefix - a BOM, a stray header - and the volume is
            // still the post's parity. `par2::head_is_packet_file` is
            // the one predicate all three sniff sites share.
            let mut head = [0u8; par2::SNIFF_WINDOW + 8];
            let want = crate::disk::chunk_len(len, head.len());
            let ok = File::open(&p)
                .and_then(|mut f| f.read_exact(&mut head[..want]))
                .is_ok();
            if ok && par2::head_is_packet_file(&head[..want]) {
                sniffed.insert(p.clone());
                packet_files.push(p);
            }
        }
    }
    packet_files.sort();
    Ok((packet_files, sniffed))
}

/// The PAR2 packet files in `dir` that only a content sniff could find:
/// recovery volumes an obfuscated post shipped under an extensionless
/// hash name.
///
/// Deliberately NOT the whole packet set. Files named `*.par2` are
/// already swept by extension wherever that matters; these are the ones
/// no extension rule can ever match, which is why a finished obfuscated
/// download kept its spent recovery set forever (issue #9).
///
/// Directory-wide, so it says nothing about which recovery SET a volume
/// served. A caller holding more than one set must not act on this until
/// every set it cares about has verified.
pub fn sniffed_packet_files(dir: &Path) -> Result<Vec<PathBuf>, RepairError> {
    let (_, sniffed) = collect_packet_files(dir)?;
    let mut out: Vec<PathBuf> = sniffed.into_iter().collect();
    out.sort();
    Ok(out)
}
