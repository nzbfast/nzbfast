//! One validated view of a directory's PAR2 packets, built once and
//! consulted by every pass that used to rescan (B2, 20 Aug audit).
//!
//! The directory repair walk read and MD5-verified the whole packet
//! corpus once per consumer: set discovery, then every qualifying set's
//! repair, then `covered_names` - about twelve full scans for a ten-set
//! pack, plus a complete rerun whenever the NTT fallback retried. This
//! catalog is that one scan, kept: for every packet file (by name or by
//! magic sniff) it holds the validated packet OCCURRENCES - packet MD5,
//! set id, and for a recovery slice its exponent and byte range - plus
//! the parsed critical bodies, deduplicated by packet MD5. Recovery
//! payload bytes are deliberately NOT retained: a recovery slice is a
//! locator here, and the bytes are pread (and re-proven against the
//! packet MD5) only when a repair actually selects that exponent.
//!
//! What consumers replay over these occurrences is exactly the logic
//! they used to run inside the file-read loops - same first-seen set
//! order over sorted file names, same packet-MD5 dedupe, same
//! first-valid duplicate/exponent provenance, same contested-name
//! discovery - so the verdicts cannot move. The scan itself is still
//! [`par2::scan_packets`], so per-packet MD5 validation and the
//! corrupt-packet start+1 resume are untouched.
//!
//! Mutation safety: the catalog is a snapshot, and repairs mutate the
//! directory (patched targets, recreated volumes, `.dup-` twins).
//! [`PacketCatalog::refresh`] re-lists the directory and rescans only
//! files whose identity, size, or mtime moved; every consumer entry
//! point refreshes first. Below stat granularity, a recovery slice
//! served from a snapshot older than the current call is re-proven
//! against its packet MD5 before its bytes are trusted
//! ([`PacketCatalog::read_validated_slice`]).

use super::{RepairError, par2};
use crate::par2::BlockCheck;
use md5::{Digest, Md5};
use std::collections::{HashMap, HashSet};
use std::fs::File;
use std::io::Read;
use std::path::{Path, PathBuf};
use tracing::warn;

/// Size + mtime + filesystem identity of a packet file at scan time -
/// the recheck [`PacketCatalog::refresh`] uses to decide whether a
/// file's cataloged packets are still believable.
#[derive(Clone, PartialEq, Eq)]
struct Stamp {
    len: u64,
    mtime: Option<std::time::SystemTime>,
    /// (dev, ino) where the platform has them; `None` on Windows, where
    /// size+mtime carry the recheck alone.
    ident: Option<(u64, u64)>,
}

impl Stamp {
    fn of(md: &std::fs::Metadata) -> Self {
        #[cfg(unix)]
        let ident = {
            use std::os::unix::fs::MetadataExt;
            Some((md.dev(), md.ino()))
        };
        #[cfg(not(unix))]
        let ident = None;
        Stamp {
            len: md.len(),
            mtime: md.modified().ok(),
            ident,
        }
    }
}

/// Where a validated recovery slice's payload lives on disk. A locator,
/// never the bytes: `md5` is the containing packet's own MD5, so the
/// payload can be re-proven at read time.
#[derive(Clone, Copy)]
pub(super) struct RecLoc {
    /// Index into the catalog's sorted packet-file list.
    pub(super) file: usize,
    pub(super) exp: u32,
    /// Byte offset of the slice payload (past the 4-byte exponent).
    pub(super) off: u64,
    pub(super) len: u32,
    pub(super) md5: [u8; 16],
}

/// One validated packet occurrence, in file order. Duplicates across
/// volumes are KEPT (consumers dedupe where the historical scans did),
/// but parsed critical bodies are stored once per packet MD5.
pub(super) struct Occ {
    pub(super) md5: [u8; 16],
    pub(super) set_id: [u8; 16],
    pub(super) kind: Kind,
}

pub(super) enum Kind {
    /// Anything that is not a usable recovery slice: criticals (their
    /// parsed bodies live in [`PacketCatalog::parsed`], keyed by this
    /// occurrence's MD5), creator packets, unparseable bodies.
    Plain,
    /// exp + payload range of a structurally valid recovery slice.
    RecvSlic { exp: u32, off: u64, len: u32 },
}

/// A parsed critical packet body, stored once per packet MD5.
pub(super) enum Crit {
    Main(u64, Vec<[u8; 16]>),
    FileDesc([u8; 16], par2::Desc),
    Ifsc([u8; 16], Vec<BlockCheck>),
}

struct CatFile {
    path: PathBuf,
    stamp: Stamp,
    /// Found by 8-byte magic sniff rather than `.par2` extension.
    sniffed: bool,
    /// `None` until [`PacketCatalog::scan_file`] reads it (the lazy
    /// prefix `repair_dir` keeps for its verify-overlapped tail scan).
    packets: Option<Vec<Occ>>,
}

/// See the module doc. Build with [`PacketCatalog::build`] (or
/// [`PacketCatalog::build_lazy`] for the single-set path that finishes
/// its scan under the verify pass), then hand it to the repair entry
/// points and name queries for the rest of the directory pass.
pub struct PacketCatalog {
    dir: PathBuf,
    max_bytes: u64,
    files: Vec<CatFile>,
    /// Parsed critical bodies by packet MD5 (identical duplicates across
    /// volumes share one entry). A packet whose body fails its parser has
    /// no entry, exactly as the historical `if let Some(..) = parse_*`
    /// arms gave it no effect.
    parsed: HashMap<[u8; 16], Crit>,
    /// Files seen in the directory that are NOT packet files, with the
    /// stamp under which that was decided - so refresh() only re-sniffs
    /// a non-.par2 file that actually changed.
    nonpacket: HashMap<PathBuf, Stamp>,
    /// Total packet-file bytes read+validated since build (for the
    /// perf harness; not part of any verdict).
    bytes_scanned: u64,
}

impl PacketCatalog {
    /// Scan every packet file in `dir` now. The everyday entry point for
    /// a directory pass that will consult the catalog more than once.
    pub fn build(dir: &Path) -> Result<Self, RepairError> {
        let mut cat = Self::build_lazy(dir)?;
        cat.scan_rest()?;
        Ok(cat)
    }

    /// List and stamp the packet files without reading their bytes yet.
    /// [`scan_file`]/[`scan_rest`] fill them in; `repair_dir` uses this
    /// to keep its historical critical-prefix + background-tail scan.
    ///
    /// [`scan_file`]: Self::scan_file
    /// [`scan_rest`]: Self::scan_rest
    pub fn build_lazy(dir: &Path) -> Result<Self, RepairError> {
        Self::build_lazy_bounded(dir, super::MAX_PACKET_FILE_BYTES)
    }

    /// [`Self::build_lazy`] with the packet-file ceiling spelled out, so a
    /// test can exercise the bound without writing a gigabyte.
    pub(super) fn build_lazy_bounded(dir: &Path, max_bytes: u64) -> Result<Self, RepairError> {
        let mut cat = PacketCatalog {
            dir: dir.to_path_buf(),
            max_bytes,
            files: Vec::new(),
            parsed: HashMap::new(),
            nonpacket: HashMap::new(),
            bytes_scanned: 0,
        };
        cat.relist()?;
        Ok(cat)
    }

    pub(super) fn dir(&self) -> &Path {
        &self.dir
    }

    pub(super) fn is_empty(&self) -> bool {
        self.files.is_empty()
    }

    pub(super) fn path_of(&self, file: usize) -> &Path {
        &self.files[file].path
    }

    pub(super) fn open_file(&self, file: usize) -> std::io::Result<File> {
        File::open(&self.files[file].path)
    }

    /// The packet files found by magic sniff rather than name - the
    /// same subset [`super::sniffed_packet_files`] reports.
    pub(super) fn sniffed_paths(&self) -> HashSet<PathBuf> {
        self.files
            .iter()
            .filter(|f| f.sniffed)
            .map(|f| f.path.clone())
            .collect()
    }

    pub(super) fn packet_paths(&self) -> impl Iterator<Item = &Path> {
        self.files.iter().map(|f| f.path.as_path())
    }

    /// Packet-file bytes read and MD5-validated since build (perf
    /// telemetry for the A/B harness; no verdict depends on it).
    pub fn bytes_scanned(&self) -> u64 {
        self.bytes_scanned
    }

    pub(super) fn crit(&self, md5: &[u8; 16]) -> Option<&Crit> {
        self.parsed.get(md5)
    }

    /// Every scanned occurrence, sorted-file then in-file order - the
    /// exact order the historical read loops presented packets in.
    pub(super) fn walk(&self) -> impl Iterator<Item = (usize, &Occ)> {
        self.files
            .iter()
            .enumerate()
            .flat_map(|(i, f)| f.packets.iter().flatten().map(move |o| (i, o)))
    }

    /// Number of files whose packets are cataloged; `..scanned_prefix()`
    /// of the sorted list is what [`walk`] currently covers when the
    /// catalog was built lazily.
    ///
    /// [`walk`]: Self::walk
    pub(super) fn complete(&self) -> bool {
        self.files.iter().all(|f| f.packets.is_some())
    }

    /// Re-list the directory: keep every file whose path and stamp are
    /// unchanged (packets and all), forget removed ones, pick up new or
    /// changed ones for (re)scanning. Non-.par2 files are re-sniffed
    /// only when their stamp moved.
    fn relist(&mut self) -> Result<(), RepairError> {
        let mut old: HashMap<PathBuf, CatFile> = std::mem::take(&mut self.files)
            .into_iter()
            .map(|f| (f.path.clone(), f))
            .collect();
        let mut nonpacket: HashMap<PathBuf, Stamp> = HashMap::new();
        let mut files: Vec<CatFile> = Vec::new();
        for e in std::fs::read_dir(&self.dir)? {
            let Ok(e) = e else { continue };
            if !e.file_type().is_ok_and(|t| t.is_file()) {
                continue;
            }
            let p = e.path();
            let Ok(md) = e.metadata() else {
                // Historical behavior: an unstattable entry read as
                // "oversized" and was skipped either way.
                continue;
            };
            let stamp = Stamp::of(&md);
            if p.extension()
                .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
            {
                if stamp.len > self.max_bytes {
                    warn!(
                        file = %p.display(),
                        bytes = stamp.len,
                        "skipping oversized .par2 - past the packet-file ceiling"
                    );
                    continue;
                }
                files.push(match old.remove(&p) {
                    Some(f) if f.stamp == stamp => f,
                    _ => CatFile {
                        path: p,
                        stamp,
                        sniffed: false,
                        packets: None,
                    },
                });
            } else if (64..=self.max_bytes).contains(&stamp.len) {
                // Known packet file, unchanged: keep. Known NON-packet
                // file, unchanged: still not one. Anything else: sniff.
                if let Some(f) = old.remove(&p) {
                    if f.stamp == stamp {
                        files.push(f);
                        continue;
                    }
                } else if self.nonpacket.get(&p) == Some(&stamp) {
                    nonpacket.insert(p, stamp);
                    continue;
                }
                let mut head = [0u8; 8];
                let ok = File::open(&p)
                    .and_then(|mut f| f.read_exact(&mut head))
                    .is_ok();
                if ok && &head == par2::MAGIC {
                    files.push(CatFile {
                        path: p,
                        stamp,
                        sniffed: true,
                        packets: None,
                    });
                } else {
                    nonpacket.insert(p, stamp);
                }
            }
        }
        files.sort_by(|a, b| a.path.cmp(&b.path));
        self.files = files;
        self.nonpacket = nonpacket;
        Ok(())
    }

    /// Bring the catalog back in line with the directory: recheck every
    /// file's identity/size/mtime, rescan the changed, adopt the new,
    /// forget the removed. Cheap when nothing moved (one `read_dir` plus
    /// stats). Every consumer entry point calls this first.
    pub(super) fn refresh(&mut self) -> Result<(), RepairError> {
        self.relist()?;
        self.scan_rest()
    }

    /// Scan the first not-yet-scanned file, if any. Returns whether one
    /// was scanned.
    pub(super) fn scan_next(&mut self) -> Result<bool, RepairError> {
        match self.files.iter().position(|f| f.packets.is_none()) {
            Some(i) => {
                self.scan_file(i)?;
                Ok(true)
            }
            None => Ok(false),
        }
    }

    /// Scan every remaining unscanned file.
    pub(super) fn scan_rest(&mut self) -> Result<(), RepairError> {
        while self.scan_next()? {}
        Ok(())
    }

    fn scan_file(&mut self, i: usize) -> Result<(), RepairError> {
        // Stamp before read: a write racing the read leaves the stored
        // stamp older than the bytes, so the next refresh re-scans -
        // the safe direction.
        if let Ok(md) = std::fs::metadata(&self.files[i].path) {
            self.files[i].stamp = Stamp::of(&md);
        }
        let bytes = std::fs::read(&self.files[i].path)?;
        self.bytes_scanned += bytes.len() as u64;
        // Memory-floor gauge (instrument-first): this whole-file read is
        // transient but real RSS while it lives, outside every budget
        // tier - the suspected owner of the damaged-fixture floor. The
        // release below pairs with the drop at the end of this scan.
        crate::memgauge::add(crate::memgauge::Sub::RepairScan, bytes.len() as u64);
        let _scan_gauge = ScanGaugeGuard(bytes.len() as u64);
        let parsed = &mut self.parsed;
        let mut occ: Vec<Occ> = Vec::new();
        par2::scan_packets(&bytes, |pkt| {
            let kind = if pkt.ptype == *par2::TYPE_RECVSLIC && pkt.body.len() >= 4 {
                Kind::RecvSlic {
                    exp: u32::from_le_bytes(pkt.body[0..4].try_into().unwrap()),
                    off: (pkt.body_offset + 4) as u64,
                    len: (pkt.body.len() - 4) as u32,
                }
            } else {
                if let std::collections::hash_map::Entry::Vacant(v) = parsed.entry(pkt.md5) {
                    let crit = if pkt.ptype == *par2::TYPE_MAIN {
                        par2::parse_main(pkt.body).map(|(bsz, ids)| Crit::Main(bsz, ids))
                    } else if pkt.ptype == *par2::TYPE_FILEDESC {
                        par2::parse_filedesc(pkt.body).map(|(fid, d)| Crit::FileDesc(fid, d))
                    } else if pkt.ptype == *par2::TYPE_IFSC {
                        par2::parse_ifsc(pkt.body).map(|(fid, b)| Crit::Ifsc(fid, b))
                    } else {
                        None
                    };
                    if let Some(c) = crit {
                        v.insert(c);
                    }
                }
                Kind::Plain
            };
            occ.push(Occ {
                md5: pkt.md5,
                set_id: pkt.set_id,
                kind,
            });
        });
        self.files[i].packets = Some(occ);
        Ok(())
    }

    /// pread one recovery slice's payload and re-prove it against the
    /// packet's own MD5 (which covers set id + type + body) before any
    /// byte is trusted. `Ok(false)` = the bytes under the locator no
    /// longer hash to the cataloged packet - the file changed below
    /// stat granularity; the caller drops the locator.
    ///
    /// `buf` must be exactly `loc.len` bytes.
    pub(super) fn read_validated_slice(
        &self,
        f: &File,
        loc: &RecLoc,
        buf: &mut [u8],
    ) -> Result<bool, RepairError> {
        debug_assert_eq!(buf.len(), loc.len as usize);
        // The digest region starts at the set-id field, 36 bytes before
        // the payload (16 set id + 16 type + 4 exponent). A short read
        // means the file shrank under the locator - a mutation verdict,
        // not an I/O failure; other errors propagate as ever.
        let mut short = false;
        let mut read = |buf: &mut [u8], off: u64| match crate::disk::read_exact_at(f, buf, off) {
            Ok(()) => Ok(()),
            Err(e) if e.kind() == std::io::ErrorKind::UnexpectedEof => {
                short = true;
                Ok(())
            }
            Err(e) => Err(e),
        };
        let mut head = [0u8; 36];
        read(&mut head, loc.off - 36)?;
        read(buf, loc.off)?;
        if short {
            return Ok(false);
        }
        // The MD5 covers set id, packet type, exponent and payload alike,
        // so one digest equality proves the bytes are the cataloged packet.
        let mut md5 = Md5::new();
        md5.update(head);
        md5.update(&buf[..]);
        Ok(md5.finalize().as_slice() == loc.md5)
    }
}

/// The catalog-sharing faces of the free functions in the parent
/// module: one directory pass (the settle tail runs repair, then
/// `covered_names`, then the sniffed-volume sweep) builds one catalog
/// and asks it everything, instead of paying a full corpus scan per
/// question. Each entry refreshes first, so the answers are exactly
/// what the free function would have said at the same moment.
impl PacketCatalog {
    /// [`super::covered_names`] against this catalog.
    pub fn covered_names(&mut self) -> Result<Vec<String>, RepairError> {
        self.refresh()?;
        Ok(super::covered_names_catalog(self))
    }

    /// [`super::sniffed_packet_files`] against this catalog.
    pub fn sniffed_packet_files(&mut self) -> Result<Vec<PathBuf>, RepairError> {
        self.refresh()?;
        let mut out: Vec<PathBuf> = self.sniffed_paths().into_iter().collect();
        out.sort();
        Ok(out)
    }

    /// [`super::repair_present_sets`] against this catalog.
    pub fn repair_present_sets(&mut self) -> Result<Vec<super::SetOutcome>, RepairError> {
        self.refresh()?;
        super::repair_sets_catalog(self, false)
    }

    /// [`super::repair_present_or_renamed_sets`] against this catalog.
    pub fn repair_present_or_renamed_sets(
        &mut self,
    ) -> Result<Vec<super::SetOutcome>, RepairError> {
        self.refresh()?;
        super::repair_sets_catalog(self, true)
    }
}

/// Load the `needed` smallest selected exponents' payloads, one
/// `block_size` buffer each. With `revalidate`, every slice is re-proven
/// against its packet MD5 as it is read; a slice that no longer proves
/// (the file mutated below stat granularity) is dropped from `by_exp`
/// and the selection re-runs with the next exponent up, exactly as a
/// fresh scan would never have offered the mutated packet. `None` =
/// dropping left fewer than `needed` - the caller's Unrepairable
/// arithmetic reads the shrunken map.
pub(super) fn load_selected_recovery(
    cat: &PacketCatalog,
    by_exp: &mut HashMap<u32, RecLoc>,
    needed: usize,
    bs: usize,
    revalidate: bool,
) -> Result<Option<Vec<(u32, Vec<u8>)>>, RepairError> {
    loop {
        if by_exp.len() < needed {
            return Ok(None);
        }
        let mut exps: Vec<u32> = by_exp.keys().copied().collect();
        exps.sort_unstable();
        exps.truncate(needed);
        let mut loaded: Vec<(u32, Vec<u8>)> = Vec::with_capacity(needed);
        let mut open: HashMap<usize, File> = HashMap::new();
        let mut dropped: Option<u32> = None;
        for e in exps {
            let loc = by_exp[&e];
            let f = match open.entry(loc.file) {
                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => v.insert(cat.open_file(loc.file)?),
            };
            let mut data = vec![0u8; bs];
            if revalidate {
                if !cat.read_validated_slice(f, &loc, &mut data)? {
                    warn!(
                        file = %cat.path_of(loc.file).display(),
                        exponent = e,
                        "recovery packet no longer matches its cataloged MD5 - dropping it"
                    );
                    dropped = Some(e);
                    break;
                }
            } else {
                crate::disk::read_exact_at(f, &mut data, loc.off)?;
            }
            loaded.push((e, data));
        }
        match dropped {
            Some(e) => {
                by_exp.remove(&e);
            }
            None => return Ok(Some(loaded)),
        }
    }
}

/// The recovery slices `repair_mapped` would have selected out of a
/// full harvest, loaded straight from catalog locators: dedupe by
/// exponent (first valid occurrence in sorted-file order wins), smallest
/// exponents first, exactly as many as there are missing blocks, each
/// re-proven against its packet MD5 at pread. Errors carry the same
/// arithmetic `repair_mapped` reports when recovery falls short.
pub(super) fn load_mapped_recovery(
    cat: &mut PacketCatalog,
    set_id: &[u8; 16],
    files: &[(crate::par2::Par2File, Vec<bool>)],
    bs: usize,
) -> Result<Vec<(u32, Vec<u8>)>, RepairError> {
    let n_missing: usize = files
        .iter()
        .map(|(_, present)| present.iter().filter(|&&p| !p).count())
        .sum();
    if n_missing == 0 {
        return Ok(Vec::new());
    }
    cat.refresh()?;
    let mut by_exp: HashMap<u32, RecLoc> = HashMap::new();
    for (file, occ) in cat.walk() {
        if let Kind::RecvSlic { exp, off, len } = occ.kind
            && occ.set_id == *set_id
            && len as usize == bs
        {
            by_exp.entry(exp).or_insert(RecLoc {
                file,
                exp,
                off,
                len,
                md5: occ.md5,
            });
        }
    }
    match load_selected_recovery(cat, &mut by_exp, n_missing, bs, true)? {
        Some(loaded) => Ok(loaded),
        None => Err(RepairError::RecoveryShort {
            have: by_exp.len(),
            need: n_missing,
        }),
    }
}

/// The per-set packet walk `repair_dir_set_inner` used to run inside its
/// file-read loop, replayed over catalog occurrences: packet-MD5 dedupe,
/// first-packet set binding, first-seen Main/FileDesc/IFSC, recovery
/// locators in discovery order. Feed files strictly in catalog order.
pub(super) struct SetReplay {
    pub(super) set_id: Option<[u8; 16]>,
    seen: HashSet<[u8; 16]>,
    pub(super) main: Option<(u64, Vec<[u8; 16]>)>,
    pub(super) descs: HashMap<[u8; 16], par2::Desc>,
    pub(super) ifscs: HashMap<[u8; 16], Vec<BlockCheck>>,
    pub(super) rec_locs: Vec<RecLoc>,
}

impl SetReplay {
    pub(super) fn new(want: Option<[u8; 16]>) -> Self {
        SetReplay {
            set_id: want,
            seen: HashSet::new(),
            main: None,
            descs: HashMap::new(),
            ifscs: HashMap::new(),
            rec_locs: Vec::new(),
        }
    }

    pub(super) fn feed(&mut self, cat: &PacketCatalog, file: usize, occ: &Occ) {
        if !self.seen.insert(occ.md5) {
            return;
        }
        match self.set_id {
            None => self.set_id = Some(occ.set_id),
            Some(id) if id != occ.set_id => return,
            _ => {}
        }
        match occ.kind {
            Kind::RecvSlic { exp, off, len } => self.rec_locs.push(RecLoc {
                file,
                exp,
                off,
                len,
                md5: occ.md5,
            }),
            Kind::Plain => match cat.crit(&occ.md5) {
                Some(Crit::Main(bsz, ids)) => {
                    if self.main.is_none() {
                        self.main = Some((*bsz, ids.clone()));
                    }
                }
                Some(Crit::FileDesc(fid, d)) => {
                    self.descs.entry(*fid).or_insert_with(|| d.clone());
                }
                Some(Crit::Ifsc(fid, b)) => {
                    self.ifscs.entry(*fid).or_insert_with(|| b.clone());
                }
                None => {}
            },
        }
    }

    /// Feed every occurrence of files `from..` (catalog order), returning
    /// the file index feeding stopped at because `stop` turned true (checked
    /// after each file, matching the historical per-file early break).
    pub(super) fn feed_files(
        &mut self,
        cat: &PacketCatalog,
        from: usize,
        mut stop: impl FnMut(&SetReplay) -> bool,
    ) -> usize {
        let mut fed = from;
        for i in from..cat.files.len() {
            let Some(packets) = cat.files[i].packets.as_ref() else {
                break;
            };
            for o in packets {
                self.feed(cat, i, o);
            }
            fed = i + 1;
            if stop(self) {
                break;
            }
        }
        fed
    }

    /// The historical critical-completeness test: Main present and every
    /// declared file id has both its FileDesc and its IFSC.
    pub(super) fn criticals_complete(&self) -> bool {
        self.main.as_ref().is_some_and(|(_, ids)| {
            ids.iter()
                .all(|fid| self.descs.contains_key(fid) && self.ifscs.contains_key(fid))
        })
    }
}

/// RAII release for the scan's transient read gauge: the buffer's bytes
/// leave RSS when `scan_file`'s `bytes` drops, on every path out.
struct ScanGaugeGuard(u64);

impl Drop for ScanGaugeGuard {
    fn drop(&mut self) {
        crate::memgauge::sub(crate::memgauge::Sub::RepairScan, self.0);
    }
}
