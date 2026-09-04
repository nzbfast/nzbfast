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
    /// [`scan_file`]/[`scan_rest`] fill them in; `repair_dir` uses this
    /// to keep its historical critical-prefix + background-tail scan.
    ///
    /// [`scan_file`]: Self::scan_file
    /// [`scan_rest`]: Self::scan_rest
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

/// Load the `needed` smallest selected exponents' payloads, one
/// `block_size` buffer each. With `revalidate`, every slice is re-proven
/// against its packet MD5 as it is read; a slice that no longer proves
/// (the file mutated below stat granularity) is dropped from `by_exp`
/// and the selection re-runs with the next exponent up, exactly as a
/// fresh scan would never have offered the mutated packet. `None` =
/// dropping left fewer than `needed` - the caller's Unrepairable
/// arithmetic reads the shrunken map.
pub(super) fn load_selected_recovery(
    pool: &SlicePool<'_>,
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
        // Keyed by (list, index): a donor's file 0 and the catalog's
        // file 0 are two different files.
        let mut open: HashMap<(SliceSrc, usize), File> = HashMap::new();
        let mut dropped: Option<u32> = None;
        for e in exps {
            let loc = by_exp[&e];
            let f = match open.entry((loc.src, loc.file)) {
                std::collections::hash_map::Entry::Occupied(o) => o.into_mut(),
                std::collections::hash_map::Entry::Vacant(v) => v.insert(pool.open(&loc)?),
            };
            // The packet MD5 covers the WHOLE payload, so an over-long
            // slice ([`slice_fits_block`]) has to be read and validated
            // whole and only then cut to the block. `>= bs` is the
            // selection predicate at both callers, so the cut below is
            // exact; the `.max(bs)` is the belt for a third caller that
            // does not filter, where a short buffer would read past the
            // packet into its neighbour.
            let mut data = vec![0u8; (loc.len as usize).max(bs)];
            if loc.must_revalidate(revalidate) {
                if !pool.read_validated_slice(f, &loc, &mut data)? {
                    warn!(
                        file = %pool.path_of(&loc).display(),
                        exponent = e,
                        "recovery packet no longer matches its cataloged MD5 - dropping it"
                    );
                    dropped = Some(e);
                    break;
                }
            } else {
                crate::disk::read_exact_at(f, &mut data, loc.off)?;
            }
            // `truncate` alone keeps the padded CAPACITY, and what is
            // held here is `m` of these at once - the bound
            // `reconstruct::check_repair_dim` states as `m x
            // block_size`. Shrinking keeps that true. It costs nothing
            // in the conforming case, where capacity already equals
            // `bs` and both calls are no-ops.
            data.truncate(bs);
            data.shrink_to_fit();
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
    main_contradicted: bool,
    descs_contradicted: HashSet<[u8; 16]>,
    ifscs_contradicted: HashSet<[u8; 16]>,
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
    pub(super) fn criticals_complete(&self) -> bool {
        if self.main_contradicted {
            return true;
        }
        self.main.as_ref().is_some_and(|(_, ids)| {
            ids.iter().all(|fid| {
                (self.descs.contains_key(fid) || self.descs_contradicted.contains(fid))
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
/// [`par2::Par2Set::parse`]'s `Claim::offer_desc` is the same rule on
/// the live verification side, and carries the argument for it at
/// length; the two are deliberately the same rule so one hostile set
/// cannot be taken two ways by the two halves.
fn claim_desc_or_contradict(
    held: &mut HashMap<[u8; 16], par2::Desc>,
    contradicted: &mut HashSet<[u8; 16]>,
    fid: [u8; 16],
    offered: &par2::Desc,
) {
    if !contradicted.contains(&fid)
        && let Some(cur) = held.get(&fid)
        && cur != offered
    {
        let new_binds = par2::filedesc_id(offered) == fid;
        if new_binds != (par2::filedesc_id(cur) == fid) {
            if new_binds {
                held.insert(fid, offered.clone());
            }
            return;
        }
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
