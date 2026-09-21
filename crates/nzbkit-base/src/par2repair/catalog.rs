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

use super::slices::slice_fits_block;
use super::{PacketScope, RepairError, par2};
use crate::md5fast::{Digest, Md5};
use crate::par2::BlockCheck;
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

/// Which packet-file list a [`RecLoc`]'s `file` indexes.
///
/// A recovery slice is interchangeable with any other slice carrying
/// the same recovery SET ID - the set id fixes the main packet, and
/// with it the block size and the file ids - so a slice is usable
/// wherever it physically sits. [`SliceSrc`] is how a selection says
/// where it found one, because the two lists are addressed separately:
/// the catalog holds the repair directory's own files, and
/// [`harvest_donor_recovery`] returns the donor volumes' paths beside
/// it rather than inside it (a donor's packets must not reach the
/// catalog's OTHER answers - name discovery, contested names, set
/// discovery - which are all statements about THIS directory).
#[derive(Clone, Copy, PartialEq, Eq, Hash, Debug)]
pub(super) enum SliceSrc {
    /// `file` indexes the catalog's own sorted packet-file list.
    Own,
    /// `file` indexes the donor packet-file list held beside it - see
    /// [`SlicePool`].
    Donor,
}

/// Where a validated recovery slice's payload lives on disk. A locator,
/// never the bytes: `md5` is the containing packet's own MD5, so the
/// payload can be re-proven at read time.
#[derive(Clone, Copy)]
pub(super) struct RecLoc {
    /// Index into the packet-file list `src` names.
    pub(super) file: usize,
    pub(super) exp: u32,
    /// Byte offset of the slice payload (past the 4-byte exponent).
    pub(super) off: u64,
    pub(super) len: u32,
    pub(super) md5: [u8; 16],
    pub(super) src: SliceSrc,
}

impl RecLoc {
    /// Must these bytes be re-proven against the packet MD5 at pread,
    /// given the caller's own answer for the repair directory?
    ///
    /// A DONOR always must, whatever the caller said. `caller` is
    /// driven by `fresh` - "this call listed the catalog and nothing
    /// has consulted it since" - which is a claim about the repair
    /// directory the engine owns. A donor is a predecessor's directory
    /// this repair does not own and another job may be writing to it
    /// right now, so no such claim is available. The proof is one MD5
    /// over one block; buying it unconditionally costs nothing worth
    /// reasoning about.
    fn must_revalidate(&self, caller: bool) -> bool {
        caller || self.src == SliceSrc::Donor
    }
}

/// The packet files a recovery selection may pread: the repair
/// directory's catalog, plus whatever donor volumes were harvested for
/// this set. ONE resolver, so [`load_selected_recovery`] needs no
/// second copy of itself for the donor case.
pub(super) struct SlicePool<'a> {
    pub(super) cat: &'a PacketCatalog,
    /// Donor packet-file paths, addressed by `RecLoc.file` under
    /// [`SliceSrc::Donor`]. Empty for every caller that has no donors.
    pub(super) donor: &'a [PathBuf],
}

impl<'a> SlicePool<'a> {
    /// A pool over the repair directory alone - what every path without
    /// donor directories asks for.
    pub(super) fn own(cat: &'a PacketCatalog) -> Self {
        SlicePool { cat, donor: &[] }
    }

    fn path_of(&self, loc: &RecLoc) -> &Path {
        match loc.src {
            SliceSrc::Own => self.cat.path_of(loc.file),
            SliceSrc::Donor => &self.donor[loc.file],
        }
    }

    fn open(&self, loc: &RecLoc) -> std::io::Result<File> {
        match loc.src {
            SliceSrc::Own => self.cat.open_file(loc.file),
            SliceSrc::Donor => File::open(&self.donor[loc.file]),
        }
    }

    /// [`PacketCatalog::read_validated_slice`] for a locator from
    /// EITHER list. The proof is the containing packet's own MD5 over
    /// the bytes the locator names, so it needs nothing from the
    /// catalog - which is exactly why a donor volume can be proven by
    /// the same call, and why a donor's bytes are never trusted on the
    /// strength of having been scanned a moment ago.
    fn read_validated_slice(
        &self,
        f: &File,
        loc: &RecLoc,
        buf: &mut [u8],
    ) -> Result<bool, RepairError> {
        self.cat.read_validated_slice(f, loc, buf)
    }
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

/// One file's scan, before it is folded into the catalog.
struct ScanOut {
    occ: Vec<Occ>,
    /// Critical bodies in first-seen order WITHIN this file; the fold
    /// applies first-seen-wins across files.
    crits: Vec<([u8; 16], Crit)>,
    scanned: u64,
    stamp: Option<Stamp>,
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
    /// How far below `dir` the listing walk looks. [`PacketScope::Flat`]
    /// for every historical entry point; [`PacketScope::Nested`] only
    /// where a caller has said it wants a set that publication may have
    /// placed in a tree (see `par2repair::nested`).
    scope: PacketScope,
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

/// `NZBFAST_PAR2_CATALOG_WARM=0` skips the page-cache warming thread the
/// parallel scan runs ahead of its groups (see [`PacketCatalog::scan_rest`]).
fn warm_scan_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_PAR2_CATALOG_WARM").as_deref() != Ok("0"))
}

/// `NZBFAST_PAR2_CATALOG_PARALLEL=0` forces the sequential catalog scan.
/// Read once: this is asked per scan and a repair does several.
fn parallel_scan_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_PAR2_CATALOG_PARALLEL").as_deref() != Ok("0"))
}

/// `NZBFAST_PAR2_CATALOG_WINDOWED=0` reads every volume under the slurp
/// threshold whole again - the A/B arm of `par2::scan_file_windowed`.
fn windowed_scan_enabled() -> bool {
    static ON: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *ON.get_or_init(|| std::env::var("NZBFAST_PAR2_CATALOG_WINDOWED").as_deref() != Ok("0"))
}

/// The window `par2::scan_file_windowed` reads a volume through.
///
/// Measured 14 Sep 2026 (M3 Ultra, 1 GiB / 16-member set, m = 192,
/// `parfast r -t4 -m128`, fold arm, two reps each), peak RSS against the
/// whole read's 453-470 MB at 64 KiB blocks and 858-911 MB at 1 MiB:
/// 4 MiB 200-201 / 372-377 MB, **8 MiB 237-239 / 361-385 MB**, 16 MiB
/// 227-232 / 422-473 MB, 32 MiB 292-299 / 479-503 MB. Wider costs memory
/// because up to eight volumes scan at once and each holds its window
/// (four under that `-t4`; since 15 Sep 2026 the windows of one walk come
/// from one [`WindowPool`], which the table above predates).
/// Narrower costs WALL where blocks are large: a 4 MiB window holds under
/// `PAR_SCAN_MIN` of 1 MiB packets, so its MD5s verify serially, and the
/// scan phase went 0.31 s -> 0.56-0.57 s. Eight is the narrowest width
/// with no cost on either block size.
fn scan_window() -> usize {
    8 << 20
}

/// The windows one [`PacketCatalog::scan_rest`] reads its volumes
/// through, kept for the length of the walk so every file's reads land
/// in a buffer that already exists.
///
/// A window per file, allocated and freed, left a freed region per
/// DISTINCT size: a volume under the window gets a window its own size,
/// and PAR2 volumes double, so the small ones never reuse each other's
/// regions, and macOS libmalloc keeps every one of them dirty in the
/// footprint. Every buffer here is reserved at the full width once and
/// only ever truncated, so the regions are as many as the most files that
/// were in flight at once, and each is one width.
///
/// A window is checked out for one file and handed back after it, and
/// [`WindowPool::take`] NEVER WAITS: an empty pool hands out a new buffer.
/// So there is no admission and nothing to block on - the pool is as large
/// as the most workers that held a window at once, which the group loop
/// already bounds - and none of the wait shapes `scan_rest`'s body rejects
/// comes back.
struct WindowPool {
    width: usize,
    bufs: std::sync::Mutex<Vec<Vec<u8>>>,
}

impl WindowPool {
    fn new(width: usize) -> Self {
        WindowPool {
            width,
            bufs: std::sync::Mutex::new(Vec::new()),
        }
    }

    fn take(&self) -> Vec<u8> {
        self.bufs
            .lock()
            .unwrap_or_else(|e| e.into_inner())
            .pop()
            .unwrap_or_else(|| Vec::with_capacity(self.width))
    }

    /// A window a packet grew past the width is DROPPED rather than kept:
    /// kept, one oversized packet would make every later file's window
    /// that size for the rest of the walk.
    fn give(&self, buf: Vec<u8>) {
        if buf.capacity() <= self.width {
            self.bufs
                .lock()
                .unwrap_or_else(|e| e.into_inner())
                .push(buf);
        }
    }
}

/// One verified packet into a file's scan result - the per-packet half
/// of [`PacketCatalog::scan_one`], shared by its windowed and whole-read
/// arms so the two cannot classify a packet differently.
fn note_packet(pkt: &par2::RawPacket<'_>, occ: &mut Vec<Occ>, crits: &mut Vec<([u8; 16], Crit)>) {
    let kind = if pkt.ptype == *par2::TYPE_RECVSLIC && pkt.body.len() >= 4 {
        Kind::RecvSlic {
            exp: u32::from_le_bytes(pkt.body[0..4].try_into().unwrap()),
            off: (pkt.body_offset + 4) as u64,
            len: (pkt.body.len() - 4) as u32,
        }
    } else {
        let crit = if pkt.ptype == *par2::TYPE_MAIN {
            // The non-recovery ids are deliberately dropped here: repair lays
            // files onto the global slice index space from the
            // RECOVERY list and nothing else, so a verify-only
            // member must never reach it (see `Par2Set::nonrecovery`).
            par2::parse_main(pkt.body).map(|(bsz, ids, _)| Crit::Main(bsz, ids))
        } else if pkt.ptype == *par2::TYPE_FILEDESC {
            par2::parse_filedesc(pkt.body).map(|(fid, d)| Crit::FileDesc(fid, d))
        } else if pkt.ptype == *par2::TYPE_IFSC {
            par2::parse_ifsc(pkt.body).map(|(fid, b)| Crit::Ifsc(fid, b))
        } else {
            None
        };
        if let Some(c) = crit {
            crits.push((pkt.md5, c));
        }
        Kind::Plain
    };
    occ.push(Occ {
        md5: pkt.md5,
        set_id: pkt.set_id,
        kind,
    });
}

impl PacketCatalog {
    /// Scan every packet file in `dir` now. The everyday entry point for
    /// a directory pass that will consult the catalog more than once.
    pub fn build(dir: &Path) -> Result<Self, RepairError> {
        Self::build_scoped(dir, PacketScope::Flat)
    }

    /// [`Self::build`] with the discovery scope named. Only the late-set
    /// door asks for [`PacketScope::Nested`]; see `par2repair::nested`
    /// for why the other walks are deliberately left flat.
    pub fn build_scoped(dir: &Path, scope: PacketScope) -> Result<Self, RepairError> {
        let mut cat = Self::build_lazy_scoped(dir, scope)?;
        cat.scan_rest()?;
        Ok(cat)
    }

    /// List and stamp the packet files without reading their bytes yet.
    /// `scan_file`/`scan_rest` fill them in; `repair_dir` uses this
    /// to keep its historical critical-prefix + background-tail scan.
    pub fn build_lazy(dir: &Path) -> Result<Self, RepairError> {
        Self::build_lazy_scoped(dir, PacketScope::Flat)
    }

    /// [`Self::build_lazy`] with the discovery scope named.
    pub fn build_lazy_scoped(dir: &Path, scope: PacketScope) -> Result<Self, RepairError> {
        Self::build_lazy_bounded(dir, super::MAX_PACKET_FILE_BYTES, scope)
    }

    /// [`Self::build_lazy`] with the packet-file ceiling spelled out, so a
    /// test can exercise the bound without writing a gigabyte.
    pub(super) fn build_lazy_bounded(
        dir: &Path,
        max_bytes: u64,
        scope: PacketScope,
    ) -> Result<Self, RepairError> {
        let mut cat = PacketCatalog {
            dir: dir.to_path_buf(),
            max_bytes,
            scope,
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

    /// Every destination name this catalog's FileDesc packets declare,
    /// and the subset of those names that TWO DIFFERENT SETS claim for
    /// different content - `super::DirContext`'s two name sets, derived
    /// in ONE place so the entry points cannot disagree about what a
    /// directory declares.
    ///
    /// A descriptor is its `(file_id, length, md5)` triple, so a name
    /// two sets declare for the SAME file is not contested: sharing
    /// that destination is correct. Keyed through
    /// `super::name_identity_key`, because a case-insensitive volume
    /// folds two spellings onto one object and an exact compare would
    /// leave both undisambiguated - the very loss the claim loop exists
    /// to prevent.
    ///
    /// TWO sets is the bar, and not "two descriptors", which is what
    /// this walk asked before 31 Aug 2026. A single set declaring two
    /// names that SANITIZE alike is already handled where it happens:
    /// the claim loop sees both descriptors in the one repair, lets the
    /// first keep the declared name and disambiguates the second. Only
    /// a collision ACROSS sets is invisible there, because a repair
    /// drops every foreign packet before a target is built. Firing on
    /// the wider condition costs the first descriptor its declared name
    /// for nothing, and `e2e_norar3`'s leading-dot twin says what that
    /// is worth: "a payload kept, but under a name nobody declared and
    /// no *arr will import".
    ///
    /// Reads only what has been SCANNED: a name lives in the critical
    /// packets, so a caller that wants the whole directory's answer has
    /// to hold a complete catalog ([`PacketCatalog::build_scoped`])
    /// rather than a lazy one.
    ///
    /// F6 (1 Sep 2026): `applicable` narrows the CONTESTED half - and
    /// only that half - to the set ids the caller can actually apply.
    /// `declared` stays whole-tree whatever is passed, because
    /// over-inclusion there is the safe direction: it only ever stops
    /// the spent-donor sweep deleting a neighbour's payload. Contested
    /// is the opposite. A set that the caller will REFUSE in every
    /// round is a phantom competitor: it cannot land a file, so
    /// disambiguating a running set's target away from its declared
    /// name buys nothing and costs the payload a name anything
    /// downstream will import. The shape that reaches it is Nested
    /// discovery, where an extracted subdirectory can carry a recovery
    /// set of its own that `get::latesets`' `published_here` will never
    /// let run, while its FileDesc names still voted here.
    /// `None` is the directory-wide reading every other entry point
    /// keeps: at Flat scope each discovered set is a root set the
    /// caller would attempt if its files were on disk, so the phantom
    /// is bounded there.
    pub(super) fn declared_and_contested(
        &self,
        fold: bool,
        applicable: Option<&HashSet<[u8; 16]>>,
    ) -> (HashSet<String>, HashSet<String>) {
        type Who = (HashSet<([u8; 16], u64, [u8; 16])>, HashSet<[u8; 16]>);
        let mut claims: HashMap<String, Who> = HashMap::new();
        let mut declared: HashSet<String> = HashSet::new();
        for (_, occ) in self.walk() {
            if let Some(Crit::FileDesc(fid, d)) = self.crit(&occ.md5) {
                let key = super::name_identity_key(fold, &d.name);
                declared.insert(key.clone());
                // A non-applicable occurrence is dropped from the claim
                // tally WHOLE, descriptor as well as set id, and not
                // merely from the set tally: leaving its descriptor in
                // would let two applicable sets that agree on the same
                // file (identical descriptor, correctly not contested)
                // be pushed over the `descs.len() > 1` bar by a
                // phantom's third spelling.
                if applicable.is_none_or(|ids| ids.contains(&occ.set_id)) {
                    let e = claims.entry(key).or_default();
                    e.0.insert((*fid, d.length, d.md5));
                    e.1.insert(occ.set_id);
                }
            }
        }
        let contested = claims
            .iter()
            .filter(|(_, (descs, sets))| descs.len() > 1 && sets.len() > 1)
            .map(|(k, _)| k.clone())
            .collect();
        (declared, contested)
    }

    /// Every scanned file and every validated packet in it, in the
    /// order [`walk`] presents them - the payload of
    /// [`super::SurveyObserver::packets_scanned`]. A file the lazy walk
    /// has not reached is absent rather than empty, so a caller can
    /// tell "nothing in it" from "not read"; after [`scan_rest`] the two
    /// coincide. Identity only: a caller needs the MD5 to dedupe
    /// repeats across volumes, the set id to filter, and the exponent
    /// and slice length to count recovery blocks by the parser's own
    /// rule. Nothing here is a verdict.
    ///
    /// [`walk`]: Self::walk
    /// [`scan_rest`]: Self::scan_rest
    pub(super) fn scan_report(&self) -> super::ScanReport {
        super::ScanReport {
            files: self
                .files
                .iter()
                .filter_map(|f| {
                    let occs = f.packets.as_ref()?;
                    Some(super::PacketFileScan {
                        path: f.path.clone(),
                        packets: occs
                            .iter()
                            .map(|o| super::PacketSeen {
                                md5: o.md5,
                                set_id: o.set_id,
                                recovery: match o.kind {
                                    Kind::RecvSlic { exp, len, .. } => Some(super::RecoverySeen {
                                        exponent: exp,
                                        slice_len: len,
                                    }),
                                    Kind::Plain => None,
                                },
                            })
                            .collect(),
                    })
                })
                .collect(),
        }
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
        for cand in super::nested::walk_candidates(&self.dir, self.scope)? {
            // An unstattable entry never reaches here: the walk drops it,
            // which is the historical behavior (it read as "oversized"
            // and was skipped either way).
            let p = cand.path;
            let stamp = Stamp::of(&cand.meta);
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
                // Window rather than byte 0 - see
                // `par2::head_is_packet_file` (M4-65).
                let mut head = [0u8; par2::SNIFF_WINDOW + 8];
                let want = crate::disk::chunk_len(stamp.len, head.len());
                let ok = File::open(&p)
                    .and_then(|mut f| f.read_exact(&mut head[..want]))
                    .is_ok();
                if ok && par2::head_is_packet_file(&head[..want]) {
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

    /// Scan every remaining unscanned file, on many threads.
    ///
    /// **Why this is parallel, and why it is sound.** The whole cost of a
    /// scan is [`Self::scan_one`] - one read (or map) and an MD5 over
    /// every packet in the file - and it touches no catalog state. The
    /// only cross-file coupling is which file's copy of a repeated
    /// critical body ends up in `parsed`, and that is settled by
    /// [`Self::apply_scan`], which this calls in FILE-INDEX ORDER
    /// whatever order the reads finished in. So the catalog this leaves
    /// behind is byte-for-byte the one the sequential walk left:
    /// `parallel_scan_matches_sequential` pins that on a fixture with
    /// criticals repeated across volumes, which is the case that would
    /// break if the merge ever went in completion order.
    ///
    /// **Why it was worth doing.** `repair_dir_set_surveyed_as` - the
    /// door `parfast` and every surveying caller takes - builds the
    /// catalog COMPLETE before the repair's own clock starts, so this
    /// walk was 583 ms of a 2 GiB set that no phase line could see and
    /// the largest single component of a 13-17% CLI-versus-driver gap
    /// (`research/parfast-cli-gap-2026-09-09/REPORT.md`, 9 Sep 2026).
    /// The alternative was to stop building complete and recover the
    /// overlap with the verify pass, which `entry.rs`'s
    /// `repair_dir_set_with_donors_scoped` explains is not available
    /// here: `declared_and_contested` is one of `DirContext`'s two
    /// protections and neither survives a lazy catalog. Reading the same
    /// bytes on more threads needs no such trade.
    ///
    /// **The bound is on BYTES IN FLIGHT.** A whole file is resident
    /// while it is scanned - that is what the sequential walk charged to
    /// `memgauge` one file at a time - so N workers on a set of large
    /// volumes would hold N of them at once. The files are therefore
    /// PACKED into groups that fit the budget and one group runs at a
    /// time, so the peak is bounded by construction. See the body for
    /// the two shapes that were tried and rejected first.
    ///
    /// `NZBFAST_PAR2_CATALOG_PARALLEL=0` forces the sequential walk - the
    /// A/B knob, and the escape hatch if a host ever wants one.
    pub(super) fn scan_rest(&mut self) -> Result<(), RepairError> {
        let todo: Vec<usize> = self
            .files
            .iter()
            .enumerate()
            .filter(|(_, f)| f.packets.is_none())
            .map(|(i, _)| i)
            .collect();
        // One pool for the whole walk, groups and sequential arm alike -
        // see `WindowPool`. `None` is the whole-read A/B arm.
        let pool = windowed_scan_enabled().then(|| WindowPool::new(scan_window()));
        let pool = pool.as_ref();
        if todo.len() < 2 || !parallel_scan_enabled() {
            // `todo` is the unscanned files in index order, which is the
            // order `scan_next` would take them in.
            for i in todo {
                let out = Self::scan_one_pooled(&self.files[i].path, pool)?;
                self.apply_scan(i, out);
            }
            return Ok(());
        }
        // The bound is on BYTES IN FLIGHT, and it holds BY CONSTRUCTION:
        // the files are packed, in order, into groups whose read bytes
        // sum to at most the budget, and one group is scanned at a time.
        // Everything inside a group may therefore be in flight at once
        // with no admission control, no wait and no lock - the peak is
        // the group total, which is the budget.
        //
        // Two shapes were tried and rejected before this one. Capping the
        // WIDTH against the widest file collapses to a single worker on
        // any real set, because PAR2 volumes are sized by exponential
        // doubling and the largest holds about half the recovery set -
        // measured, it gave back the whole gain. Per-file admission on a
        // `Condvar` works, but its wait loop breaks on capacity rather
        // than on a sticky abort, which is not a shape
        // `tools/wait-recheck-gate.py` can classify, and teaching a gate
        // a new shape to admit one's own code is the wrong direction.
        // Packing needs neither.
        //
        // A file over `SLURP_MAX_BYTES` is MAPPED rather than read -
        // page-cache backed, reclaimable, charged nothing here for the
        // same reason `scan_one` does not gauge it - so it costs a group
        // nothing and never forces one open on its own.
        const IN_FLIGHT_BYTES: u64 = 256 << 20;
        let workers = crate::mem::cpu_workers().clamp(1, 8);
        let cost = |i: usize| -> u64 {
            let n = std::fs::metadata(&self.files[i].path)
                .map(|m| m.len())
                .unwrap_or(0);
            if n > Self::SLURP_MAX_BYTES { 0 } else { n }
        };
        let mut groups: Vec<Vec<usize>> = Vec::new();
        let mut cur: Vec<usize> = Vec::new();
        let mut sum = 0u64;
        for &i in &todo {
            let c = cost(i);
            // A file bigger than the whole budget opens its own group
            // rather than being refused: `cur.is_empty()` admits it.
            if !cur.is_empty() && sum + c > IN_FLIGHT_BYTES {
                groups.push(std::mem::take(&mut cur));
                sum = 0;
            }
            cur.push(i);
            sum += c;
        }
        if !cur.is_empty() {
            groups.push(cur);
        }
        // WARM THE VOLUMES AHEAD OF THE GROUPS. The groups above are
        // scanned one at a time to hold the in-flight bound, so on a cold
        // cache the big volumes - each its own group - are read one after
        // another, at one file's queue depth. Until 10 Sep 2026 that was
        // masked by an accident: `parfast`'s own duplicate load was
        // reading the same volumes on another thread at the same time,
        // and the catalog found them in the page cache. TODO 334 removed
        // the duplicate and the cold scan doubled (1.81 s against 0.88 s
        // on an M3 Ultra, 2 GiB set, APFS-cloned so its pages were cold).
        // So the warming is done on purpose: one thread reads every file
        // this walk is about to read, sequentially, through a small
        // reused buffer it never keeps, which pulls the pages into the
        // cache the groups then hit. Reclaimable cache, not RSS - the
        // in-flight bound is untouched. A mapped file (over
        // `SLURP_MAX_BYTES`) is not read here: `scan_one` prefetches the
        // mapping itself. `NZBFAST_PAR2_CATALOG_WARM=0` is the A/B arm.
        let warm: Vec<PathBuf> = if warm_scan_enabled() {
            todo.iter()
                .filter(|&&i| cost(i) > 0)
                .map(|&i| self.files[i].path.clone())
                .collect()
        } else {
            Vec::new()
        };
        // Four readers, in the groups' own order, so the queue depth the
        // accidental fan-out used to give the device is given on purpose:
        // one sequential reader measured 21% behind it on the cold
        // fixture, four is what the duplicate load's fan ran at over the
        // files that mattered.
        let warmer = std::thread::Builder::new()
            .name("par2-catalog-warm".into())
            .spawn(move || {
                let next = std::sync::atomic::AtomicUsize::new(0);
                std::thread::scope(|sc| {
                    for _ in 0..4.min(warm.len()) {
                        let (next, warm) = (&next, &warm);
                        sc.spawn(move || {
                            // ONE MiB, and not the 16 MiB it was until
                            // 15 Sep 2026: four freed 16 MiB buffers were
                            // 64 MB of the ~100 MB of `Malloc Large
                            // (empty)` a repair carried out of the scan on
                            // macOS, twice the scan's own windows. The page
                            // cache the warmer exists to fill does not care
                            // how the bytes are copied out: 256 KiB to
                            // 16 MiB read the same cold scan phase
                            // (research/PARFAST-CATALOG-SCAN-RETENTION-2026-09-14.md,
                            // section 6).
                            let mut buf = vec![0u8; 1 << 20];
                            loop {
                                let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                                let Some(p) = warm.get(k) else { return };
                                let Ok(mut f) = File::open(p) else { continue };
                                while let Ok(n) = std::io::Read::read(&mut f, &mut buf) {
                                    if n == 0 {
                                        break;
                                    }
                                }
                            }
                        });
                    }
                });
            })
            .ok();
        for group in groups {
            if group.len() < 2 || workers < 2 {
                for i in group {
                    let out = Self::scan_one_pooled(&self.files[i].path, pool)?;
                    self.apply_scan(i, out);
                }
                continue;
            }
            let paths: Vec<PathBuf> = group.iter().map(|&i| self.files[i].path.clone()).collect();
            // Dynamic within the group: the doubling above means a static
            // split would leave one worker holding most of the bytes.
            let next = std::sync::atomic::AtomicUsize::new(0);
            let (tx, rx) = std::sync::mpsc::channel::<(usize, Result<ScanOut, RepairError>)>();
            std::thread::scope(|sc| {
                for _ in 0..workers.min(group.len()) {
                    let tx = tx.clone();
                    let (next, paths) = (&next, &paths);
                    sc.spawn(move || {
                        loop {
                            let k = next.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
                            if k >= paths.len() {
                                return;
                            }
                            if tx
                                .send((k, Self::scan_one_pooled(&paths[k], pool)))
                                .is_err()
                            {
                                return;
                            }
                        }
                    });
                }
            });
            drop(tx);
            let mut done: Vec<Option<Result<ScanOut, RepairError>>> =
                (0..group.len()).map(|_| None).collect();
            for (k, out) in rx {
                done[k] = Some(out);
            }
            // IN FILE-INDEX ORDER within the group, and the groups were
            // packed in order, so the whole walk applies in file order.
            for (k, &i) in group.iter().enumerate() {
                let out = done[k]
                    .take()
                    .expect("every index is sent before the scope ends")?;
                self.apply_scan(i, out);
            }
        }
        // Whatever the warmer had not reached was read by a group already;
        // it finishes on its own shortly, but it must not outlive the
        // catalog's directory (a refresh could be re-listing it).
        if let Some(w) = warmer {
            let _ = w.join();
        }
        Ok(())
    }

    /// Read a packet file whole up to this size; MAP anything larger.
    ///
    /// The scan needs one `&[u8]` over the entire file - every packet is
    /// MD5-verified and `RawPacket::body` borrows from it - so a big volume
    /// used to mean a big private allocation, which is why
    /// [`super::MAX_PACKET_FILE_BYTES`] refused one outright. That refusal
    /// was the bug: PAR2 volumes are sized by exponential doubling, so the
    /// LARGEST holds about half the recovery set (measured: 45%), and a set
    /// with ~2 GiB of parity therefore has a volume over 1 GiB. Ours and
    /// turbo's both land it on a power-of-two block count, so it hits the
    /// ceiling exactly and passes it on the repeated critical packets alone
    /// - 8,420 bytes over, in the case that found this. The volume was
    /// skipped, 36% of the parity went with it, and the repair then failed
    /// `Unrepairable` on a set turbo completes.
    ///
    /// Mapping instead of reading keeps resident memory bounded WITHOUT
    /// refusing the file: the pages are page-cache backed and reclaimable
    /// rather than a private copy. Raising the old ceiling would have made
    /// the exposure it guards worse; this removes the reason for it.
    ///
    /// Only files ABOVE this take the mapping, so the common path is
    /// byte-for-byte what it was. That is deliberate: a member truncated
    /// under a live mapping faults the reader (SIGBUS /
    /// EXCEPTION_IN_PAGE_ERROR) rather than returning short, and confining
    /// the mapping to volumes that are refused outright today means the
    /// change cannot make any currently-working repair worse.
    const SLURP_MAX_BYTES: u64 = 1 << 30;

    fn scan_file(&mut self, i: usize) -> Result<(), RepairError> {
        let out = Self::scan_one(&self.files[i].path)?;
        self.apply_scan(i, out);
        Ok(())
    }

    /// One file's scan with NO access to the catalog: the read, the MD5
    /// verification of every packet and the body parsing, which is all of
    /// the cost. Pure by construction so [`Self::scan_rest`] can run it
    /// on many files at once - see there for why that is sound.
    ///
    /// Critical bodies come back as a LIST in first-seen order rather
    /// than a map, because the map's semantics are first-seen-wins and
    /// this function cannot see what an earlier file already claimed.
    /// [`Self::apply_scan`] does the claiming, in file order.
    fn scan_one(path: &Path) -> Result<ScanOut, RepairError> {
        Self::scan_one_in(path, windowed_scan_enabled().then(scan_window))
    }

    /// [`Self::scan_one`] with the read window named: `None` reads a
    /// volume under the slurp threshold whole, as it always was.
    fn scan_one_in(path: &Path, window: Option<usize>) -> Result<ScanOut, RepairError> {
        Self::scan_one_with(path, window, &mut Vec::new())
    }

    /// [`Self::scan_one`] reading through a window checked out of `pool`
    /// and handed back after, or the whole read when there is no pool.
    fn scan_one_pooled(path: &Path, pool: Option<&WindowPool>) -> Result<ScanOut, RepairError> {
        let Some(pool) = pool else {
            return Self::scan_one_in(path, None);
        };
        let mut buf = pool.take();
        let out = Self::scan_one_with(path, Some(pool.width), &mut buf);
        pool.give(buf);
        out
    }

    /// [`Self::scan_one_in`] with the window's buffer supplied: only its
    /// allocation is reused, never its contents.
    fn scan_one_with(
        path: &Path,
        window: Option<usize>,
        buf: &mut Vec<u8>,
    ) -> Result<ScanOut, RepairError> {
        // Stamp before read: a write racing the read leaves the stored
        // stamp older than the bytes, so the next refresh re-scans -
        // the safe direction.
        let stamp = std::fs::metadata(path).ok().map(|md| Stamp::of(&md));
        // A volume at or under the slurp threshold is READ, exactly as
        // it always was. A larger one is MAPPED instead - see
        // `SLURP_MAX_BYTES`. `scan_packets` needs one `&[u8]` over the
        // whole file either way (every packet is MD5-verified and
        // `RawPacket::body` borrows from it), so the choice is only
        // where the bytes live, and the parser is untouched.
        let flen = std::fs::metadata(path).map(|m| m.len()).unwrap_or(0);
        let mapped = if flen > Self::SLURP_MAX_BYTES {
            // RETRIED against a freshly stat'd length, because the
            // frequent failure here is not a broken mmap - it is
            // `MappedMember::open`'s own `f.metadata()?.len() != len`
            // refusal, and `refresh()` re-scans while a volume may still
            // be growing, so a member being extended fails the length
            // check on essentially every pass. Every such failure lands
            // on the whole-file `read` below, which has no size test of
            // its own and no admission gate: the packer prices a file
            // over `SLURP_MAX_BYTES` at 0 (`cost`), so any number of
            // multi-GiB members pack into one group and are read whole,
            // concurrently, outside the in-flight bound the grouping
            // exists to enforce. The retry removes that arm without
            // refusing anything - a hard refusal here would re-open the
            // skipped-volume bug the 64 GiB ceiling was raised to fix.
            crate::par2gen::MappedMember::open(path, flen)
                .ok()
                .flatten()
                .or_else(|| {
                    let fresh = std::fs::metadata(path).map(|m| m.len()).unwrap_or(flen);
                    (fresh != flen)
                        .then(|| {
                            crate::par2gen::MappedMember::open(path, fresh)
                                .ok()
                                .flatten()
                        })
                        .flatten()
                })
        } else {
            None
        };
        // A COLD mapped volume is faulted in a page at a time by the MD5
        // walk below, with nothing ahead of it: measured 10 Sep 2026 on
        // an M3 Ultra, 2 GiB set, APFS-cloned so its pages were cold, the
        // catalog's verify-overlapped scan took 1.81 s against 0.88 s
        // when a second reader happened to be pulling the same volume
        // through the page cache at the same time. That second reader
        // was `parfast`'s own duplicate load, which TODO 334 removed, so
        // the hint has to come from here: ask for the whole mapping up
        // front, exactly as `par2gen`'s own readers do.
        if let Some(m) = &mapped {
            m.prefetch();
        }
        let mut crits: Vec<([u8; 16], Crit)> = Vec::new();
        let mut occ: Vec<Occ> = Vec::new();
        // Anything not mapped - a volume at or under the slurp threshold,
        // and a larger one whose mapping failed, which used to be read
        // whole outside the in-flight bound - is READ THROUGH A WINDOW
        // first, and read whole only if the window declines. See
        // `par2::scan_file_windowed` for the retention it removes and why
        // its yes is always the whole read's answer; on its no, whatever
        // prefix it emitted is dropped and the historical path runs.
        if let Some(window) = window.filter(|_| mapped.is_none() && flen > 0) {
            let charged = window.min(flen as usize) as u64;
            crate::memgauge::add(crate::memgauge::Sub::RepairScan, charged);
            let _scan_gauge = ScanGaugeGuard(charged);
            let done = File::open(path).ok().and_then(|f| {
                par2::scan_file_windowed_in(&f, flen, window, buf, |pkt| {
                    note_packet(&pkt, &mut occ, &mut crits)
                })
            });
            if done.is_some() {
                return Ok(ScanOut {
                    occ,
                    crits,
                    scanned: flen,
                    stamp,
                });
            }
            occ.clear();
            crits.clear();
        }
        let owned;
        let bytes: &[u8] = match &mapped {
            Some(m) => m.bytes(),
            None => {
                owned = std::fs::read(path)?;
                &owned
            }
        };
        let scanned = bytes.len() as u64;
        // Memory-floor gauge (instrument-first): the whole-file READ is
        // transient but real RSS while it lives, outside every budget
        // tier - the suspected owner of the damaged-fixture floor. The
        // release below pairs with the drop at the end of this scan. A
        // MAPPING is page-cache backed and reclaimable, so it is not
        // charged as private bytes here.
        let charged = if mapped.is_some() {
            0
        } else {
            bytes.len() as u64
        };
        crate::memgauge::add(crate::memgauge::Sub::RepairScan, charged);
        let _scan_gauge = ScanGaugeGuard(charged);
        par2::scan_packets(bytes, |pkt| note_packet(&pkt, &mut occ, &mut crits));
        Ok(ScanOut {
            occ,
            crits,
            scanned,
            stamp,
        })
    }

    /// Fold one [`Self::scan_one`] result into the catalog. Called in
    /// FILE-INDEX ORDER, which is what preserves first-seen-wins for the
    /// critical bodies whatever order the reads finished in.
    fn apply_scan(&mut self, i: usize, out: ScanOut) {
        if let Some(st) = out.stamp {
            self.files[i].stamp = st;
        }
        self.bytes_scanned += out.scanned;
        for (md5, crit) in out.crits {
            if let std::collections::hash_map::Entry::Vacant(v) = self.parsed.entry(md5) {
                v.insert(crit);
            }
        }
        self.files[i].packets = Some(out.occ);
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
        super::repair_sets_catalog(self, false, super::RetentionCaller::default(), None)
    }

    /// [`super::repair_present_or_renamed_sets`] against this catalog.
    pub fn repair_present_or_renamed_sets(
        &mut self,
    ) -> Result<Vec<super::SetOutcome>, RepairError> {
        self.refresh()?;
        super::repair_sets_catalog(self, true, super::RetentionCaller::default(), None)
    }

    /// [`Self::repair_present_or_renamed_sets`] with a
    /// [`RepairControl`](super::RepairControl) - progress out of each
    /// set's repair, a cancel its loops poll - for the no-set
    /// obfuscated arm (`nzbfast-engine`'s `get::settle::noset`), which
    /// was one of the two daemon repair paths still handing the engine
    /// a default control.
    ///
    /// A SUPPLIER and not a control, for the reason
    /// [`super::repair_present_sets_controlled_as`] carries at length:
    /// this walks EVERY qualifying set in the directory in turn, and a
    /// caller whose bar is monotone would sit at 100% for every set
    /// after the first. The supplier is asked once per set, at the
    /// instant that set's repair starts, which is the set boundary and
    /// the caller's to do what it likes with.
    ///
    /// Everything else is [`Self::repair_present_or_renamed_sets`] BY
    /// CONSTRUCTION - one call to `repair_sets_catalog` differing in
    /// the observer argument alone, so the renamed-fallback gate and
    /// the caller label have no second copy to drift. A supplier
    /// returning `RepairControl::default()` is the uncontrolled call
    /// exactly, branch for branch.
    ///
    /// A cancelled set stops the walk on the set it was cancelled in -
    /// see `repair_sets_catalog`, which breaks on that edge in BOTH of
    /// its loops, the renamed fallback's included.
    pub fn repair_present_or_renamed_sets_controlled(
        &mut self,
        control: &dyn Fn() -> super::RepairControl,
    ) -> Result<Vec<super::SetOutcome>, RepairError> {
        self.refresh()?;
        let mut observe = super::entry::ControlledSets(control);
        super::repair_sets_catalog(
            self,
            true,
            super::RetentionCaller::default(),
            Some(&mut observe),
        )
    }
}

/// One line per selection pass naming recovery slices refused for
/// length, so a set that looks short of parity says why. Silent is the
/// state M4-56 was found in.
pub(super) fn warn_short_slices(refused: usize, shortest: u32, bs: usize) {
    if refused > 0 {
        warn!(
            refused,
            shortest_len = shortest,
            block_size = bs,
            "recovery slice packet(s) too short to carry a full block - refused; \
             the set has less parity available than its volumes suggest"
        );
    }
}

/// The `needed` recovery exponents to solve with: the LOWEST CONSECUTIVE
/// RUN of that length, falling back to the `needed` smallest when the
/// set has no such run.
///
/// Taking the smallest `needed` unconditionally is what this used to do,
/// and it decides which back-substitution runs. Consecutive exponents
/// make the matrix a Vandermonde times a diagonal, which is the
/// `O(m^2)` explicit inverse and, past `forney::backsub_gate`, the
/// Forney transform solve. A selection with ONE GAP in it has neither,
/// and falls through to Gauss-Jordan on an explicit `m x m`: `O(m^3)`
/// scalar ops and `~4*m^2` bytes. That arm refused outright past
/// `MAX_REPAIR_DIM` = 8,192 until 8 Sep 2026 and is bounded by MEMORY
/// now, so a gapped selection is SLOW rather than declined - which is
/// still a reason to prefer a clean run, just not the same reason.
///
/// Gaps mean recovery packets were themselves lost, which is ordinary on
/// an incomplete post - and there is usually no reason to accept one,
/// because a set holding more recovery than the damage needs will have a
/// clean run further up. Measured 6 Sep 2026 on a 46 MB corpus at 100%
/// redundancy with one middle volume removed, m = 978: taking the
/// smallest fell to gauss-jordan at 0.65 s against turbo's 0.43 s - the
/// one shape in the audit where a rival was ahead - and the arm's cost
/// is cubic, so at m = 8,192 the same selection is tens of seconds.
///
/// BOTH repair drivers select through this. The mapped driver - the
/// in-place repair the download pipeline runs - took the `needed`
/// smallest until 8 Sep 2026, two days after the disk driver stopped:
/// measured there at m = 2,048 / 64 KiB, one gap is 5.0 ms -> 956 ms of
/// setup and 123 ms -> 391 ms of solve, 6.75x over the whole
/// reconstructor (research/SPARSE-EXPONENT-BACKSUB-2026-09-08.md). A
/// third selection site written tomorrow would inherit the same defect
/// and nothing refuses one; that gate is named as open in that round.
///
/// The run is the LOWEST one so the exponents stay as small as the set
/// allows: the transform prices its work on the span it must produce,
/// and a needlessly high first exponent is what the creator's range plan
/// exists to avoid paying for.
pub(super) fn select_consecutive_run(sorted_exps: &[u32], needed: usize) -> Vec<u32> {
    if needed == 0 {
        return Vec::new();
    }
    if sorted_exps.len() >= needed {
        // `sorted_exps` is sorted and deduplicated (it comes from a map's
        // keys), so a window is consecutive exactly when its span is
        // `needed - 1`.
        let span = (needed - 1) as u32;
        for i in 0..=(sorted_exps.len() - needed) {
            if sorted_exps[i + needed - 1].saturating_sub(sorted_exps[i]) == span {
                return sorted_exps[i..i + needed].to_vec();
            }
        }
    }
    let mut out = sorted_exps.to_vec();
    out.truncate(needed);
    out
}

/// The exponents a repair over `needed` blocks selects from `by_exp`:
/// [`select_consecutive_run`] over its sorted keys. One copy, because a
/// driver PLANS with this selection before the load below re-runs it
/// (`reconstruct::selection_structured`), and two spellings of it could
/// plan one system and load another.
pub(super) fn selected_exponents<V>(by_exp: &HashMap<u32, V>, needed: usize) -> Vec<u32> {
    let mut exps: Vec<u32> = by_exp.keys().copied().collect();
    exps.sort_unstable();
    select_consecutive_run(&exps, needed)
}

/// Load the selected exponents' payloads, one `block_size` buffer each -
/// [`select_consecutive_run`] chooses which. With `revalidate`, every
/// slice is re-proven against its packet MD5 as it is read; a slice that
/// no longer proves (the file mutated below stat granularity) is dropped
/// from `by_exp` and the selection re-runs, exactly as a fresh scan
/// would never have offered the mutated packet. `None` = dropping left
/// fewer than `needed` - the caller's Unrepairable arithmetic reads the
/// shrunken map.
pub(super) fn load_selected_recovery(
    pool: &SlicePool<'_>,
    by_exp: &mut HashMap<u32, RecLoc>,
    needed: usize,
    bs: usize,
    revalidate: bool,
) -> Result<Option<Vec<(u32, Vec<u8>)>>, RepairError> {
    load_selected_recovery_span(pool, by_exp, needed, bs, 0..bs, revalidate)
}

/// [`load_selected_recovery`], keeping only bytes `span` of each slice.
///
/// A slabbed solve holds `m x span.len()` of recovery rather than
/// `m x bs`, which is the whole point of slabbing: on the 65 GiB set
/// that is the difference between 17.2 GB of resident recovery and half
/// that. The trim happens HERE, inside the reader, and not on the
/// returned vector - a caller that trimmed afterwards would already
/// have every full slice in memory at once, which is the allocation
/// being avoided.
///
/// A slice is still READ and validated in full: the packet MD5 covers
/// the whole slice, so a span cannot be proven on its own. The full
/// buffer is one per reader thread and transient; only the span is kept.
pub(super) fn load_selected_recovery_span(
    pool: &SlicePool<'_>,
    by_exp: &mut HashMap<u32, RecLoc>,
    needed: usize,
    bs: usize,
    span: std::ops::Range<usize>,
    revalidate: bool,
) -> Result<Option<Vec<(u32, Vec<u8>)>>, RepairError> {
    loop {
        if by_exp.len() < needed {
            return Ok(None);
        }
        let exps = selected_exponents(by_exp, needed);
        // One reader per packet file, the slices of that file in exponent
        // order: the selection used to pread its slices one after another
        // on the caller, and on a Windows page cache that is a ~2.9 GB/s
        // copy - 33 ms for the 101 x 1 MiB of the 101-block leg on the
        // i5-10600KF (5 Sep 2026), against ~8 ms across the eight volumes
        // it came from. A file's handle stays on its thread
        // (`read_exact_at` moves the cursor on Windows).
        let mut groups: HashMap<(SliceSrc, usize), Vec<u32>> = HashMap::new();
        for &e in &exps {
            let loc = by_exp[&e];
            groups.entry((loc.src, loc.file)).or_default().push(e);
        }
        let groups: Vec<Vec<u32>> = groups.into_values().collect();
        type Slot = Result<Option<(u32, Vec<u8>)>, RepairError>;
        let results: Vec<Vec<Slot>> = std::thread::scope(|sc| {
            let handles: Vec<_> = groups
                .iter()
                .map(|group| {
                    let by_exp = &*by_exp;
                    sc.spawn(move || -> Vec<Slot> {
                        let mut out: Vec<Slot> = Vec::with_capacity(group.len());
                        let mut file: Option<File> = None;
                        // A slab's span is read through ONE full-slice
                        // buffer per reader and copied out at its exact
                        // size. Until 14 Sep 2026 every slice took a
                        // fresh zeroed full-size allocation, a drain and
                        // a shrinking realloc - 192 of each per slab at
                        // 1 MiB blocks - and the footprint stepped up
                        // 18-38 MB per slab while live work stayed flat
                        // (research/PARFAST-CATALOG-SCAN-RETENTION-2026-09-14.md).
                        // A whole-slice load keeps reading straight into
                        // the buffer it returns: there is nothing to copy.
                        let partial = span.start > 0 || span.end < bs;
                        let mut scratch: Vec<u8> = Vec::new();
                        for &e in group {
                            let loc = by_exp[&e];
                            let f = match &file {
                                Some(f) => f,
                                None => match pool.open(&loc) {
                                    Ok(f) => file.insert(f),
                                    Err(err) => {
                                        out.push(Err(err.into()));
                                        break;
                                    }
                                },
                            };
                            let full = (loc.len as usize).max(bs);
                            let mut owned = if partial {
                                Vec::new()
                            } else {
                                vec![0u8; full]
                            };
                            let data: &mut Vec<u8> = if partial {
                                scratch.resize(full, 0);
                                &mut scratch
                            } else {
                                &mut owned
                            };
                            let read = if loc.must_revalidate(revalidate) {
                                pool.read_validated_slice(f, &loc, data)
                            } else {
                                crate::disk::read_exact_at(f, data, loc.off)
                                    .map(|()| true)
                                    .map_err(RepairError::from)
                            };
                            match read {
                                Ok(true) => {
                                    // Whole slice validated above; only
                                    // the slab's bytes are kept.
                                    let end = span.end.min(bs);
                                    let kept = if partial {
                                        data[span.start.min(end)..end].to_vec()
                                    } else {
                                        let mut whole = std::mem::take(&mut owned);
                                        whole.truncate(end);
                                        whole.shrink_to_fit();
                                        whole
                                    };
                                    out.push(Ok(Some((e, kept))));
                                }
                                Ok(false) => {
                                    warn!(
                                        file = %pool.path_of(&loc).display(),
                                        exponent = e,
                                        "recovery packet no longer matches its cataloged MD5 - dropping it"
                                    );
                                    out.push(Ok(None));
                                    break;
                                }
                                Err(err) => {
                                    out.push(Err(err));
                                    break;
                                }
                            }
                        }
                        out
                    })
                })
                .collect();
            handles
                .into_iter()
                .map(|h| h.join().expect("recovery slice reader panicked"))
                .collect()
        });
        let mut loaded: Vec<(u32, Vec<u8>)> = Vec::with_capacity(needed);
        let mut any_dropped = false;
        for slots in results {
            for slot in slots {
                match slot? {
                    Some(pair) => loaded.push(pair),
                    None => any_dropped = true,
                }
            }
        }
        if any_dropped {
            // A group loads in exponent order and stops at its failure, so
            // the failed slice is the first of its group that did not
            // load. Drop those from the pool and select again over what
            // remains - exactly the serial loop's one-at-a-time retry,
            // taken for every failing file at once.
            let got: std::collections::HashSet<u32> = loaded.iter().map(|(e, _)| *e).collect();
            for group in &groups {
                if let Some(failed) = group.iter().find(|e| !got.contains(e)) {
                    by_exp.remove(failed);
                }
            }
            continue;
        }
        loaded.sort_unstable_by_key(|(e, _)| *e);
        return Ok(Some(loaded));
    }
}

/// The recovery slices a DONOR directory already holds for THIS set,
/// folded into a selection that came up short (claim
/// `donor-parity-catalog-harvest`, 1 Sep 2026 - the parity half of
/// TODO 293's donor directory, whose adoption half deliberately
/// EXCLUDES a recovery volume because it is not a payload member).
///
/// The correctness argument is the whole feature, and it is short: a
/// PAR2 recovery set id fixes the main packet, and with it the block
/// size and the file ids, so a slice carrying `set_id` was computed
/// over the SAME global input grid as ours whatever directory it
/// landed in. Feeding one is not borrowing a neighbour's parity, it is
/// finding another copy of our own. A donor volume whose set id
/// DIFFERS was computed over a different grid, is arithmetic garbage
/// here, and is the one thing this must never admit - which is why the
/// id compare below is the only admission rule and there is no
/// name-based arm beside it.
///
/// BE HONEST ABOUT THE PRIZE. This pays exactly when a donor carries
/// volumes for the same set - a re-post with byte-identical par2, or an
/// earlier attempt at the same post that got different articles. It is
/// not free parity from any donor, and a donor holding a different
/// release's par2 contributes nothing and costs one packet scan.
///
/// `by_exp` is filled by `or_insert`, so the repair directory's own
/// slices always win an exponent and a donor only fills a gap - a
/// directory that needed no help selects byte-for-byte what it selected
/// before. The returned paths are addressed by `RecLoc.file` under
/// [`SliceSrc::Donor`]; only a file that actually contributed a locator
/// is listed.
///
/// A donor that cannot be walked is SKIPPED, never fatal, for
/// `adopt::adoption_candidates`' reason: the donor is a predecessor's
/// directory this repair does not own, and a concurrent cleanup racing
/// it must degrade to "no donation" and never to a failed repair.
pub(super) fn harvest_donor_recovery(
    donors: &[PathBuf],
    dir: &Path,
    set_id: &[u8; 16],
    bs: usize,
    by_exp: &mut HashMap<u32, RecLoc>,
) -> Vec<PathBuf> {
    let mut paths: Vec<PathBuf> = Vec::new();
    let (mut refused, mut shortest) = (0usize, u32::MAX);
    for d in donors {
        if d == dir {
            continue;
        }
        // Nested, matching the donor half of the adoption walk: a donor
        // is somebody else's output tree and its par2 files may sit in
        // a subdirectory exactly as its payload may.
        let Ok(cat) = PacketCatalog::build_scoped(d, PacketScope::Nested) else {
            continue;
        };
        // Catalog file index -> index into `paths`, so a volume holding
        // twenty admitted slices is listed once.
        let mut listed: HashMap<usize, usize> = HashMap::new();
        for (file, occ) in cat.walk() {
            let Kind::RecvSlic { exp, off, len } = occ.kind else {
                continue;
            };
            if occ.set_id != *set_id {
                continue;
            }
            // Same length rule as both in-directory selections (M4-56):
            // over-long is padding and is cut on load, short cannot be
            // extended without inventing bytes.
            if !slice_fits_block(len as usize, bs) {
                refused += 1;
                shortest = shortest.min(len);
                continue;
            }
            if let std::collections::hash_map::Entry::Vacant(v) = by_exp.entry(exp) {
                let next = paths.len();
                let pi = *listed.entry(file).or_insert(next);
                if pi == next {
                    paths.push(cat.path_of(file).to_path_buf());
                }
                v.insert(RecLoc {
                    file: pi,
                    exp,
                    off,
                    len,
                    md5: occ.md5,
                    src: SliceSrc::Donor,
                });
            }
        }
    }
    warn_short_slices(refused, shortest, bs);
    paths
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
    let (mut refused, mut shortest) = (0usize, u32::MAX);
    for (file, occ) in cat.walk() {
        if let Kind::RecvSlic { exp, off, len } = occ.kind
            && occ.set_id == *set_id
        {
            // M4-56: over-long is usable and cut on load; short is not,
            // and is counted rather than dropped in silence.
            if !slice_fits_block(len as usize, bs) {
                refused += 1;
                shortest = shortest.min(len);
                continue;
            }
            by_exp.entry(exp).or_insert(RecLoc {
                file,
                exp,
                off,
                len,
                md5: occ.md5,
                src: SliceSrc::Own,
            });
        }
    }
    warn_short_slices(refused, shortest, bs);
    match load_selected_recovery(&SlicePool::own(cat), &mut by_exp, n_missing, bs, true)? {
        Some(loaded) => Ok(loaded),
        None => Err(RepairError::RecoveryShort {
            have: by_exp.len(),
            need: n_missing,
        }),
    }
}

/// The per-set packet walk `repair_dir_set_inner` used to run inside its
/// file-read loop, replayed over catalog occurrences: packet-MD5 dedupe,
/// first-packet set binding, CONTRADICTION-AWARE Main/FileDesc/IFSC,
/// recovery locators in discovery order. Feed files strictly in catalog
/// order.
///
/// The critical packets were first-seen-wins here exactly as they were in
/// [`par2::Par2Set::parse`], and this is the DISK REPAIR side of the same
/// question that side answers for live verification. Two individually
/// valid packets that disagree about one file id, resolved by whichever
/// arrived first, let the two halves of the product select DIFFERENT
/// facts out of one malformed set - live verify taking the reading that
/// reached the wire first and repair taking the one whose packet file
/// sorts first on disk. Both now take neither (W4-10).
pub(super) struct SetReplay {
    pub(super) set_id: Option<[u8; 16]>,
    seen: HashSet<[u8; 16]>,
    pub(super) main: Option<(u64, Vec<[u8; 16]>)>,
    pub(super) descs: HashMap<[u8; 16], par2::Desc>,
    pub(super) ifscs: HashMap<[u8; 16], Vec<BlockCheck>>,
    pub(super) rec_locs: Vec<RecLoc>,
    /// Claims two valid packets CONTRADICTED. A contradicted claim is
    /// removed from the map beside it and latched here, so the field
    /// reads exactly as it does when the packet was never seen at all -
    /// which is why the three consumers in `par2repair.rs` need no
    /// change: a missing Main is already `NoMainPacket`, a missing
    /// FileDesc is already `Malformed`, and a missing IFSC already
    /// routes the file to its whole-file MD5, which covers every byte.
    /// The latch is what stops a THIRD copy of either packet re-admitting
    /// one of the two readings and putting order back in charge.
    ///
    /// For FileDescs the latch is not the last word, and `descs_bound`
    /// beside it is why: a descriptor that BINDS the id out-ranks the
    /// unbound readings that annihilated rather than joining them, so a
    /// contradicted FileDesc claim with no binder in it is still open.
    /// A contradiction BETWEEN binders is closed, like the other two.
    main_contradicted: bool,
    descs_contradicted: HashSet<[u8; 16]>,
    ifscs_contradicted: HashSet<[u8; 16]>,
    /// File ids some FileDesc packet BOUND (M4-38). The binding
    /// descriptors for an id are weighed against each other and against
    /// nothing else, so this is what separates "no binder yet, and an
    /// unbound contradiction a binder could still out-rank" from "the
    /// binders themselves annihilated, and nothing further can move
    /// it" - the distinction `descs_contradicted` alone cannot make,
    /// and the one `criticals_complete` has to make to stop scanning.
    descs_bound: HashSet<[u8; 16]>,
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
            main_contradicted: false,
            descs_contradicted: HashSet::new(),
            ifscs_contradicted: HashSet::new(),
            descs_bound: HashSet::new(),
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
                src: SliceSrc::Own,
            }),
            Kind::Plain => match cat.crit(&occ.md5) {
                Some(Crit::Main(bsz, ids)) => {
                    let claim = (*bsz, ids.clone());
                    if self.main_contradicted {
                    } else if let Some(cur) = &self.main {
                        if *cur != claim {
                            self.main = None;
                            self.main_contradicted = true;
                        }
                    } else {
                        self.main = Some(claim);
                    }
                }
                Some(Crit::FileDesc(fid, d)) => {
                    claim_desc_or_contradict(
                        &mut self.descs,
                        &mut self.descs_contradicted,
                        &mut self.descs_bound,
                        *fid,
                        d,
                    );
                }
                Some(Crit::Ifsc(fid, b)) => {
                    claim_or_contradict(&mut self.ifscs, &mut self.ifscs_contradicted, *fid, b);
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
    ///
    /// DECIDED, not present: a contradicted claim counts as complete
    /// because no further packet can settle it, and this predicate is
    /// what stops the scan reading more `.par2` files. Treating a
    /// contradiction as "still missing" would read every volume on disk
    /// looking for an answer that cannot arrive, and then fail anyway.
    ///
    /// One contradiction is NOT decided, and the exception is what
    /// keeps this half's answer equal to the live half's: an unbound
    /// FileDesc contradiction is still open to a descriptor that BINDS
    /// the id, which out-ranks it (M4-38). Counting that as decided
    /// would stop the scan at the volume the two forgeries sit in and
    /// never reach the real descriptor in the next one, so the same
    /// bytes would repair one way off disk and verify another way
    /// live - which is the whole thing `SetReplay` exists to prevent.
    /// The answer a binder cannot move is a contradiction BETWEEN
    /// binders, and `descs_bound` is how that one still stops the scan.
    /// The price is bounded and falls only on malformed sets: a set
    /// carrying an unbound contradiction reads its remaining `.par2`
    /// files before failing.
    pub(super) fn criticals_complete(&self) -> bool {
        if self.main_contradicted {
            return true;
        }
        self.main.as_ref().is_some_and(|(_, ids)| {
            ids.iter().all(|fid| {
                (self.descs.contains_key(fid) || self.descs_bound.contains(fid))
                    && (self.ifscs.contains_key(fid) || self.ifscs_contradicted.contains(fid))
            })
        })
    }
}

/// Admit one packet's reading of `fid`, or annihilate the claim if it
/// disagrees with the reading already held. See [`SetReplay`] - and
/// [`par2::Par2Set::parse`]'s `Claim`, which is this rule on the live
/// verification side; the two are deliberately the same rule so one
/// malformed set cannot be taken two ways by the two halves.
fn claim_or_contradict<T: Clone + PartialEq>(
    held: &mut HashMap<[u8; 16], T>,
    contradicted: &mut HashSet<[u8; 16]>,
    fid: [u8; 16],
    offered: &T,
) {
    if contradicted.contains(&fid) {
        return;
    }
    match held.entry(fid) {
        std::collections::hash_map::Entry::Occupied(e) => {
            if e.get() != offered {
                e.remove();
                contradicted.insert(fid);
            }
        }
        std::collections::hash_map::Entry::Vacant(e) => {
            e.insert(offered.clone());
        }
    }
}

/// [`claim_or_contradict`] with M4-38's tiebreak, for FileDesc packets
/// only: a descriptor that BINDS `fid` outranks one that merely carries
/// a copy of it, so the two are not a contradiction at all and the
/// honest member does not leave the set over a packet anyone can write.
/// [`par2::Par2Set::parse`]'s `DescClaim` is the same rule on the live
/// verification side, and carries the argument for it at length; the
/// two are deliberately the same rule so one hostile set cannot be
/// taken two ways by the two halves.
///
/// The tiebreak is over the SET of descriptors offered for `fid`, not
/// over the pair of (held, offered): the descriptors that bind the id
/// are folded by W4-10 among themselves, those that do not are folded
/// among themselves, and the binding class answers wherever it was
/// non-empty. Read pairwise against whatever is held it is
/// order-dependent as soon as three descriptors meet on one id, which
/// is what it was until 16 Sep 2026 - see the live half's `DescClaim`
/// for the shape of that race and why the set form removes it.
fn claim_desc_or_contradict(
    held: &mut HashMap<[u8; 16], par2::Desc>,
    contradicted: &mut HashSet<[u8; 16]>,
    bound: &mut HashSet<[u8; 16]>,
    fid: [u8; 16],
    offered: &par2::Desc,
) {
    if par2::filedesc_id(offered) == fid {
        if bound.insert(fid) {
            // The first binder out-ranks the whole unbound class,
            // including one that has already annihilated: those
            // readings were never evidence about THIS id.
            held.insert(fid, offered.clone());
            contradicted.remove(&fid);
            return;
        }
        // A later binder is evidence, and meets the one held under
        // W4-10 below.
    } else if bound.contains(&fid) {
        // Out-ranked, whatever the binding class settled to.
        return;
    }
    claim_or_contradict(held, contradicted, fid, offered);
}

/// RAII release for the scan's transient read gauge: the buffer's bytes
/// leave RSS when `scan_file`'s `bytes` drops, on every path out.
struct ScanGaugeGuard(u64);

impl Drop for ScanGaugeGuard {
    fn drop(&mut self) {
        crate::memgauge::sub(crate::memgauge::Sub::RepairScan, self.0);
    }
}

#[cfg(test)]
mod desc_claim_tests {
    use super::{SetReplay, claim_desc_or_contradict};
    use crate::par2;
    use std::collections::{HashMap, HashSet};

    fn desc(name: &str, len: u64, md5: u8, md5_16k: u8) -> par2::Desc {
        par2::Desc {
            name: name.to_string(),
            length: len,
            md5: [md5; 16],
            md5_16k: [md5_16k; 16],
        }
    }

    /// The disk-repair half of W4-10 over M4-38, held to the same bar as
    /// the live half's `three_descriptors_on_one_id_settle_the_same_in_every_order`:
    /// the reading a file id settles to is a function of the SET of
    /// descriptors offered, so every ordering answers the same. Read
    /// pairwise against whatever was held, two unbound forgeries
    /// annihilated the claim and the latch then refused the binding
    /// descriptor that out-ranks them (bug sweep 16 Sep 2026, item 17).
    ///
    /// A unit over the fold rather than a repair off disk: the twin the
    /// end-to-end `contradictory_filedescs_do_not_repair_differently_by_packet_order`
    /// covers is the two-descriptor case, and six orderings of a
    /// three-packet set cost six catalog builds there and six map
    /// updates here.
    #[test]
    fn three_descriptors_on_one_id_settle_the_same_in_every_order() {
        let honest = desc("real.bin", 8192, 0x11, 0x22);
        let fid = par2::filedesc_id(&honest);
        assert_eq!(par2::filedesc_id(&honest), fid, "the honest one binds");
        // Two forgeries wearing that id, disagreeing with it and with
        // each other; neither binds it.
        let forged_a = desc("evil-a.bin", 64, 0xAB, 0xAC);
        let forged_b = desc("evil-b.bin", 128, 0xCD, 0xCE);
        assert_ne!(par2::filedesc_id(&forged_a), fid);
        assert_ne!(par2::filedesc_id(&forged_b), fid);

        let settle = |order: [&par2::Desc; 3]| -> Option<par2::Desc> {
            let mut held = HashMap::new();
            let mut contradicted = HashSet::new();
            let mut bound = HashSet::new();
            for d in order {
                claim_desc_or_contradict(&mut held, &mut contradicted, &mut bound, fid, d);
            }
            held.remove(&fid)
        };

        for (i, order) in [
            [&honest, &forged_a, &forged_b],
            [&honest, &forged_b, &forged_a],
            [&forged_a, &honest, &forged_b],
            [&forged_b, &honest, &forged_a],
            [&forged_a, &forged_b, &honest],
            [&forged_b, &forged_a, &honest],
        ]
        .into_iter()
        .enumerate()
        {
            // `Desc` is deliberately not `Debug` (it carries a name), so
            // this is a bare comparison rather than `assert_eq!`.
            assert!(
                settle(order).as_ref() == Some(&honest),
                "permutation {i}: the binding descriptor answers for the id \
                 however late it arrives"
            );
        }
    }

    /// Two descriptors can BOTH bind one id with no MD5 collision -
    /// `filedesc_id` hashes the 16k hash, the length and the name, and
    /// not the whole-file MD5 - so the binding class is folded by W4-10
    /// like any other, in every order.
    #[test]
    fn two_binding_descriptors_annihilate_in_every_order() {
        let honest = desc("real.bin", 8192, 0x11, 0x22);
        let fid = par2::filedesc_id(&honest);
        let rival = desc("real.bin", 8192, 0x99, 0x22);
        assert_eq!(par2::filedesc_id(&rival), fid, "the rival binds it too");
        let forged = desc("evil.bin", 64, 0xAB, 0xAC);

        for (i, order) in [
            [&honest, &rival, &forged],
            [&forged, &honest, &rival],
            [&rival, &forged, &honest],
            [&forged, &rival, &honest],
        ]
        .into_iter()
        .enumerate()
        {
            let mut held = HashMap::new();
            let mut contradicted = HashSet::new();
            let mut bound = HashSet::new();
            for d in order {
                claim_desc_or_contradict(&mut held, &mut contradicted, &mut bound, fid, d);
            }
            assert!(
                !held.contains_key(&fid),
                "permutation {i}: two binding readings contradict, and no \
                 unbound one fills the hole"
            );
            // And the scan may stop on it: no later packet can move a
            // contradiction between binders.
            let mut replay = SetReplay::new(None);
            replay.main = Some((4096, vec![fid]));
            replay.descs_bound = bound;
            replay.ifscs.insert(fid, Vec::new());
            assert!(replay.criticals_complete(), "permutation {i}");
        }
    }

    /// The scan-termination side of the same rule: a FileDesc
    /// contradiction with no binder in it is NOT decided, because a
    /// binder in the next `.par2` file out-ranks it. Stopping there
    /// would let the disk half answer from a prefix of the packets the
    /// live half reads whole - the two-halves disagreement `SetReplay`
    /// exists to prevent.
    #[test]
    fn an_unbound_desc_contradiction_does_not_stop_the_scan() {
        let honest = desc("real.bin", 8192, 0x11, 0x22);
        let fid = par2::filedesc_id(&honest);
        let mut replay = SetReplay::new(None);
        replay.main = Some((4096, vec![fid]));
        replay.ifscs.insert(fid, Vec::new());

        let offer = |replay: &mut SetReplay, d: &par2::Desc| {
            claim_desc_or_contradict(
                &mut replay.descs,
                &mut replay.descs_contradicted,
                &mut replay.descs_bound,
                fid,
                d,
            );
        };
        // Two forgeries wearing the id, in the first volume read.
        offer(&mut replay, &desc("evil-a.bin", 64, 0xAB, 0xAC));
        offer(&mut replay, &desc("evil-b.bin", 128, 0xCD, 0xCE));
        assert!(!replay.descs.contains_key(&fid), "they annihilated");
        assert!(
            !replay.criticals_complete(),
            "a binder could still arrive, so the remaining volumes must be read"
        );

        // The real descriptor, in a volume the scan would have skipped.
        offer(&mut replay, &honest);
        assert!(replay.descs.get(&fid) == Some(&honest));
        assert!(
            replay.criticals_complete(),
            "and the scan stops once the id is genuinely decided"
        );
    }
}

#[cfg(test)]
mod recovery_selection_tests {
    use super::{Crit, Kind, PacketCatalog, PacketScope, select_consecutive_run};

    /// Which recovery exponents the solve gets, which decides which
    /// back-substitution arm runs. A gap anywhere in the selection costs
    /// the Vandermonde structure and drops the repair to Gauss-Jordan at
    /// `O(m^3)` - so a run is preferred wherever the set has one, and the
    /// LOWEST run, to keep the transform's exponent span small.
    #[test]
    fn the_selection_prefers_the_lowest_consecutive_run() {
        // The smallest three are gapped (0, 1, 5); the run is 5..8.
        assert_eq!(
            select_consecutive_run(&[0, 1, 5, 6, 7, 9], 3),
            vec![5, 6, 7]
        );
        // Already consecutive from the bottom: unchanged, and still the
        // lowest, so the span stays as small as the set allows.
        assert_eq!(select_consecutive_run(&[0, 1, 2, 3, 9], 3), vec![0, 1, 2]);
        // Two runs, and the lower one wins even though both would work.
        assert_eq!(
            select_consecutive_run(&[0, 1, 2, 7, 8, 9], 3),
            vec![0, 1, 2]
        );
        // NO run of the needed length: fall back to the smallest, which
        // is what the caller did unconditionally before. The repair still
        // happens, on the unstructured arm.
        assert_eq!(select_consecutive_run(&[0, 2, 4, 6], 3), vec![0, 2, 4]);
        // Exactly enough, and consecutive.
        assert_eq!(select_consecutive_run(&[4, 5, 6], 3), vec![4, 5, 6]);
        // Degenerate shapes must not panic or over-take.
        assert!(select_consecutive_run(&[1, 2, 3], 0).is_empty());
        assert_eq!(select_consecutive_run(&[1, 2], 5), vec![1, 2]);
        assert!(select_consecutive_run(&[], 3).is_empty());
        // A single block is trivially its own run - the 1-missing repair.
        assert_eq!(select_consecutive_run(&[9, 40, 41], 1), vec![9]);
    }

    /// The windowed read is a memory change and nothing else: on every
    /// packet file of a real set, `scan_one_in` with a window - one
    /// header wide (so every recovery packet grows it), one byte short of
    /// a packet, and wider than the file - gives the same occurrences,
    /// locators, parsed criticals and byte total as the whole read.
    #[test]
    fn windowed_scan_matches_the_whole_read() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-catalog-win-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for m in 0..3u8 {
            let bytes: Vec<u8> = (0..70_000u32)
                .map(|i| (i as u8).wrapping_mul(13).wrapping_add(m.wrapping_mul(59)))
                .collect();
            std::fs::write(dir.join(format!("w{m}.bin")), &bytes).unwrap();
        }
        let members: Vec<crate::par2gen::Member> = (0..3u8)
            .map(|m| crate::par2gen::Member {
                name: format!("w{m}.bin"),
                path: dir.join(format!("w{m}.bin")),
            })
            .collect();
        crate::par2gen::create_into(
            &dir,
            &members,
            "win",
            &crate::par2gen::Par2Spec {
                redundancy_pct: 60,
                block_size: Some(4096),
            },
        )
        .expect("fixture");
        let cat = PacketCatalog::build_lazy(&dir).unwrap();
        assert!(
            cat.files.len() > 2,
            "fixture must have several packet files"
        );
        let mut windowed_recovery = 0usize;
        for f in &cat.files {
            let whole = PacketCatalog::scan_one_in(&f.path, None).unwrap();
            for window in [64, 4096 + 67, 1 << 20] {
                let win = PacketCatalog::scan_one_in(&f.path, Some(window)).unwrap();
                let at = format!("{:?} at window {window}", f.path);
                assert_eq!(whole.scanned, win.scanned, "bytes scanned, {at}");
                assert_eq!(whole.occ.len(), win.occ.len(), "occurrences, {at}");
                for (x, y) in whole.occ.iter().zip(&win.occ) {
                    assert_eq!((x.md5, x.set_id), (y.md5, y.set_id), "occurrence, {at}");
                    match (&x.kind, &y.kind) {
                        (Kind::Plain, Kind::Plain) => {}
                        (
                            Kind::RecvSlic { exp, off, len },
                            Kind::RecvSlic {
                                exp: e2,
                                off: o2,
                                len: l2,
                            },
                        ) => {
                            assert_eq!((exp, off, len), (e2, o2, l2), "locator, {at}");
                            windowed_recovery += 1;
                        }
                        _ => panic!("packet kind differs, {at}"),
                    }
                }
                assert_eq!(whole.crits.len(), win.crits.len(), "criticals, {at}");
                for ((m1, c1), (m2, c2)) in whole.crits.iter().zip(&win.crits) {
                    assert_eq!(m1, m2, "critical order, {at}");
                    match (c1, c2) {
                        (Crit::Main(b1, i1), Crit::Main(b2, i2)) => assert_eq!((b1, i1), (b2, i2)),
                        (Crit::FileDesc(f1, d1), Crit::FileDesc(f2, d2)) => {
                            assert_eq!(f1, f2);
                            assert_eq!(
                                (&d1.name, d1.length, d1.md5),
                                (&d2.name, d2.length, d2.md5)
                            );
                        }
                        (Crit::Ifsc(f1, b1), Crit::Ifsc(f2, b2)) => {
                            assert_eq!(f1, f2);
                            assert_eq!(b1.len(), b2.len());
                        }
                        _ => panic!("critical kind differs, {at}"),
                    }
                }
            }
        }
        assert!(
            windowed_recovery > 0,
            "the fixture must carry recovery slices"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Two scans of one file agree packet for packet: occurrences,
    /// locators, parsed criticals in order, and bytes scanned.
    fn same_scan(want: &super::ScanOut, got: &super::ScanOut, at: &str) {
        assert_eq!(want.scanned, got.scanned, "bytes scanned, {at}");
        same_occ(&want.occ, &got.occ, at);
        assert_eq!(want.crits.len(), got.crits.len(), "criticals, {at}");
        for ((m1, c1), (m2, c2)) in want.crits.iter().zip(&got.crits) {
            assert_eq!(m1, m2, "critical order, {at}");
            match (c1, c2) {
                (Crit::Main(b1, i1), Crit::Main(b2, i2)) => assert_eq!((b1, i1), (b2, i2)),
                (Crit::FileDesc(f1, d1), Crit::FileDesc(f2, d2)) => {
                    assert_eq!(f1, f2);
                    assert_eq!((&d1.name, d1.length, d1.md5), (&d2.name, d2.length, d2.md5));
                }
                (Crit::Ifsc(f1, b1), Crit::Ifsc(f2, b2)) => {
                    assert_eq!(f1, f2);
                    assert_eq!(b1.len(), b2.len());
                }
                _ => panic!("critical kind differs, {at}"),
            }
        }
    }

    /// Two occurrence lists agree: MD5, set id, kind and locator, in order.
    fn same_occ(want: &[super::Occ], got: &[super::Occ], at: &str) {
        assert_eq!(want.len(), got.len(), "occurrences, {at}");
        for (x, y) in want.iter().zip(got) {
            assert_eq!((x.md5, x.set_id), (y.md5, y.set_id), "occurrence, {at}");
            match (&x.kind, &y.kind) {
                (Kind::Plain, Kind::Plain) => {}
                (
                    Kind::RecvSlic { exp, off, len },
                    Kind::RecvSlic {
                        exp: e2,
                        off: o2,
                        len: l2,
                    },
                ) => assert_eq!((exp, off, len), (e2, o2, l2), "locator, {at}"),
                _ => panic!("packet kind differs, {at}"),
            }
        }
    }

    /// A pooled window carries its ALLOCATION from file to file and
    /// nothing else. One pool is walked over every packet file of a real
    /// set twice, largest file first - so the reused buffer holds stale
    /// bytes past the end of every shorter file after it - at a width
    /// every packet grows (a grown window must not go back into the
    /// pool), one byte short of a recovery packet, and wider than every
    /// file (where the one buffer must be reused rather than replaced);
    /// every scan must equal the whole read. Then through the catalog
    /// itself: the pooled parallel walk, and a `refresh` that has ONE
    /// changed file to rescan and so takes the pooled sequential arm.
    #[test]
    fn pooled_windows_give_the_same_catalog() {
        use std::io::Write as _;
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-catalog-pool-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        for m in 0..3u8 {
            let bytes: Vec<u8> = (0..70_000u32)
                .map(|i| (i as u8).wrapping_mul(29).wrapping_add(m.wrapping_mul(71)))
                .collect();
            std::fs::write(dir.join(format!("p{m}.bin")), &bytes).unwrap();
        }
        let members: Vec<crate::par2gen::Member> = (0..3u8)
            .map(|m| crate::par2gen::Member {
                name: format!("p{m}.bin"),
                path: dir.join(format!("p{m}.bin")),
            })
            .collect();
        crate::par2gen::create_into(
            &dir,
            &members,
            "pool",
            &crate::par2gen::Par2Spec {
                redundancy_pct: 60,
                block_size: Some(4096),
            },
        )
        .expect("fixture");
        let mut cat = PacketCatalog::build_lazy(&dir).unwrap();
        assert!(
            cat.files.len() > 2,
            "fixture must have several packet files"
        );
        let truth: Vec<super::ScanOut> = cat
            .files
            .iter()
            .map(|f| PacketCatalog::scan_one_in(&f.path, None).unwrap())
            .collect();
        let mut order: Vec<usize> = (0..cat.files.len()).collect();
        order.sort_by_key(|&i| std::cmp::Reverse(cat.files[i].stamp.len));
        let widest = cat.files[order[0]].stamp.len as usize;
        for width in [64, 4096 + 67, widest + 1] {
            let pool = super::WindowPool::new(width);
            for pass in 0..2 {
                for &i in &order {
                    let path = &cat.files[i].path;
                    let at = format!("{path:?} width {width} pass {pass}");
                    let got = PacketCatalog::scan_one_pooled(path, Some(&pool)).unwrap();
                    same_scan(&truth[i], &got, &at);
                    let held = pool.bufs.lock().unwrap();
                    assert!(held.len() <= 1, "a sequential walk holds one window, {at}");
                    assert!(
                        held.iter().all(|b| b.capacity() <= width),
                        "a window grown past the width went back into the pool, {at}"
                    );
                }
            }
            if width > widest {
                assert_eq!(
                    pool.bufs.lock().unwrap().len(),
                    1,
                    "a window no packet grew is kept for the next file"
                );
            }
        }

        cat.scan_rest().unwrap();
        for (i, f) in cat.files.iter().enumerate() {
            same_occ(
                &truth[i].occ,
                f.packets.as_ref().unwrap(),
                &format!("catalog walk, {:?}", f.path),
            );
        }
        // Sixty trailing bytes are under a header, which both walks
        // ignore, and move the stamp, so the refresh rescans this file
        // and nothing else.
        let victim = cat.files[order[0]].path.clone();
        std::fs::OpenOptions::new()
            .append(true)
            .open(&victim)
            .unwrap()
            .write_all(&[0u8; 60])
            .unwrap();
        cat.refresh().unwrap();
        let want = PacketCatalog::scan_one_in(&victim, None).unwrap();
        let f = cat.files.iter().find(|f| f.path == victim).unwrap();
        same_occ(&want.occ, f.packets.as_ref().unwrap(), "refreshed file");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The parallel scan must leave EXACTLY the catalog the sequential
    /// walk leaves. The case that would break a careless merge is a
    /// critical body repeated across volumes: `parsed` is first-seen-wins
    /// keyed by packet MD5, so a merge in completion order rather than
    /// file order would store whichever thread finished first. A real
    /// PAR2 set repeats its criticals into every volume by design, so
    /// this fixture has that property without arranging it.
    ///
    /// Compared: the file list, every file's stamp-independent packet
    /// occurrences in order, the parsed critical bodies keyed by MD5, and
    /// the byte total. Anything the repair reads afterwards is derived
    /// from those.
    #[test]
    fn parallel_scan_matches_sequential() {
        let dir = std::env::temp_dir().join(format!(
            "nzbfast-catalog-par-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        // Four members, small blocks, high redundancy: many volumes, and
        // every volume carries the critical packets again.
        for m in 0..4u8 {
            let mut bytes = vec![0u8; 96 * 1024];
            for (i, b) in bytes.iter_mut().enumerate() {
                *b = (i as u8).wrapping_mul(31).wrapping_add(m.wrapping_mul(97));
            }
            std::fs::write(dir.join(format!("m{m}.bin")), &bytes).unwrap();
        }
        let members: Vec<crate::par2gen::Member> = (0..4u8)
            .map(|m| crate::par2gen::Member {
                name: format!("m{m}.bin"),
                path: dir.join(format!("m{m}.bin")),
            })
            .collect();
        crate::par2gen::create_into(
            &dir,
            &members,
            "cat",
            &crate::par2gen::Par2Spec {
                redundancy_pct: 100,
                block_size: Some(4096),
            },
        )
        .expect("fixture");

        let seq = {
            let mut c = PacketCatalog::build_lazy(&dir).unwrap();
            while c.scan_next().unwrap() {}
            c
        };
        let par = PacketCatalog::build_scoped(&dir, PacketScope::Flat).unwrap();

        assert!(
            seq.files.len() > 2,
            "fixture must have several packet files"
        );
        assert_eq!(seq.files.len(), par.files.len(), "file count");
        assert_eq!(seq.bytes_scanned, par.bytes_scanned, "bytes scanned");
        for (a, b) in seq.files.iter().zip(par.files.iter()) {
            assert_eq!(a.path, b.path, "file order");
            let (ao, bo) = (a.packets.as_ref().unwrap(), b.packets.as_ref().unwrap());
            assert_eq!(ao.len(), bo.len(), "occurrence count for {:?}", a.path);
            for (x, y) in ao.iter().zip(bo.iter()) {
                assert_eq!(x.md5, y.md5, "occurrence md5 in {:?}", a.path);
                assert_eq!(x.set_id, y.set_id, "occurrence set id in {:?}", a.path);
                match (&x.kind, &y.kind) {
                    (Kind::Plain, Kind::Plain) => {}
                    (
                        Kind::RecvSlic {
                            exp: e1,
                            off: o1,
                            len: l1,
                        },
                        Kind::RecvSlic {
                            exp: e2,
                            off: o2,
                            len: l2,
                        },
                    ) => {
                        assert_eq!((e1, o1, l1), (e2, o2, l2), "slice locator in {:?}", a.path)
                    }
                    _ => panic!("packet kind differs in {:?}", a.path),
                }
            }
        }
        // The first-seen-wins map: same keys, and the same BODY under each.
        assert_eq!(seq.parsed.len(), par.parsed.len(), "parsed critical count");
        for (md5, c) in &seq.parsed {
            let other = par.parsed.get(md5).expect("same parsed keys");
            match (c, other) {
                (Crit::Main(b1, i1), Crit::Main(b2, i2)) => {
                    assert_eq!((b1, i1), (b2, i2), "Main body")
                }
                (Crit::FileDesc(f1, d1), Crit::FileDesc(f2, d2)) => {
                    assert_eq!(f1, f2, "FileDesc id");
                    assert_eq!((&d1.name, d1.length, d1.md5), (&d2.name, d2.length, d2.md5));
                }
                (Crit::Ifsc(f1, b1), Crit::Ifsc(f2, b2)) => {
                    assert_eq!(f1, f2, "Ifsc id");
                    assert_eq!(b1.len(), b2.len(), "Ifsc blocks");
                }
                _ => panic!("parsed critical kind differs"),
            }
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
