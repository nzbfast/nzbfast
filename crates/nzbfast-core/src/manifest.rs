//! The settle manifest: checksums the download already proved, kept
//! beside the payload so the directory can verify itself later with no
//! PAR2 on disk.
//!
//! Why this exists: at settle the daemon holds the full parsed PAR2 set
//! (whole-file MD5, first-16k MD5, per-block CRC32 for every covered
//! file) and historically extracted two counters from it before the
//! Arcs dropped. Meanwhile `.par2` files are on the default cleanup
//! list, so the moment a user wants to re-check a finished folder there
//! is nothing left to check against - every verify path in the tree
//! gates on PAR2 being present. This file is that data, written once,
//! from memory, at a cost of serialization only.
//!
//! EXTRACTED OUTPUT IS COVERED TOO, since 2 Sep 2026, and it is the
//! half a library actually keeps. For an archive post the PAR2 set
//! covers the VOLUMES and the extractor retains no checksum of what it
//! produced, so the film itself used to appear here as a presence-only
//! entry - name and length, honestly marked unverifiable - which meant
//! an extracted film that rotted was invisible to `verify` and to the
//! heal behind it. `write_reconciled` now reads every file the set never
//! covered and records a CRC32 block grid for it ([`grid_from_disk`]),
//! so it is [`Role::Payload`] like anything else and a heal can act on
//! it. The measurement that chose the grid over a whole-file MD5, and
//! chose to hash at the manifest write rather than ride the finalize
//! move's read, is in that function's header: the read is 5% of the cost
//! and the hash is all of it.
//!
//! What it still is NOT: a proof the download itself produced. Every
//! other entry here is a checksum PAR2 already computed, carried at a
//! cost of serialization only; a grid read off the disk is this module
//! measuring the file it found, which is the strongest thing available
//! once the volumes are gone and is not the same claim.
//!
//! File format: one JSON object, `.nzbfast.manifest` in the job's final
//! directory, hidden on Windows the way `.nzbfast.journal` is. The
//! `.nzbfast` prefix matters: the extract diff walkers and the cleanup
//! sweeps already skip that namespace. `smart::keep_media_only` did NOT
//! until this module landed - it is the categorical sweep, deleting
//! everything that is not media, companion or archive, and it was the
//! only directory walker in the tree not honouring the prefix. It ate
//! the journal too, on any second pass.
//!
//! ONE MANIFEST PER DIRECTORY, NOT PER JOB, and that is forced rather
//! than chosen: a TV-filed job's `out_dir` is the SHARED season folder
//! claimed by every episode in it (`Job::filed`), so several jobs
//! legitimately settle into one directory. The file is therefore
//! written by MERGE - `write_reconciled` carries an existing manifest's
//! entries for files still on disk forward intact, with their own block
//! size and their own provenance - and the per-entry `bs`/`job`/`sha`
//! fields exist for that. Without it a season folder keeps only the
//! LAST episode's proof and each new one silently downgrades its
//! predecessors to "present, unverifiable", which is the feature
//! failing in precisely the directory shape a library is made of.
//!
//! WHAT STAGE 2 NEEDS FROM THIS FILE, so the shape is not accidental.
//! Healing needs no new engine work (§293 Shape A): a freshly hunted
//! post's own PAR2 set supplies the block grid, and the damaged library
//! file rides in as a donor directory - `repair_dir_with_donors` then
//! adopts every block that still matches and fetches only the rest.
//! So the manifest's job is DETECTION plus IDENTITY, never the repair:
//! which file is damaged (the grid), and which post to re-hunt for it
//! (the per-entry `job`/`sha`). Both are per ENTRY and not per file,
//! because in a season folder the answer differs per episode.
//!
//! WHAT IT DELIBERATELY DOES NOT COVER, stated rather than left to be
//! found. The post-job SCRIPT runs after this is written and may move
//! or rename anything; a file it touches reports as damage on the next
//! verify, exactly as it would to PAR2. An entry carried forward is
//! matched by (name, length) only - a previous job's file is not being
//! renamed by this job's tail, so the 16 KiB head rematch would be
//! reads spent on a case that cannot arise. And a file the user
//! deliberately deletes stays in the manifest until some later job in
//! the same directory rewrites it, so verify reports it `Missing`;
//! that is a true statement about the directory and the same thing
//! PAR2 would say.

use std::io::Read;
use std::path::{Path, PathBuf};

use crate::tools::MutexExt;
use nzbkit::md5fast::{Digest, Md5};
use serde_json::{Value, json};

pub const MANIFEST_NAME: &str = ".nzbfast.manifest";

/// What an entry claims about its file.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub(crate) enum Role {
    /// Expected to stay on disk; a missing one is damage.
    Payload,
    /// A PAR2-covered input the tail may legitimately consume (an
    /// archive volume the spent-volume sweep removes). Missing is
    /// normal; present means it can still be verified.
    Source,
    /// On disk at write time with no checksum to hold it to. Verify
    /// checks existence and length only.
    ///
    /// Extracted output USED to land here and no longer does - see
    /// [`grid_from_disk`]. What is left is the two families the grid
    /// pass deliberately skips: a file it could not read, and archive
    /// material a later sweep may legitimately take.
    Presence,
}

impl Role {
    fn tag(self) -> &'static str {
        match self {
            Role::Payload => "payload",
            Role::Source => "source",
            Role::Presence => "presence",
        }
    }
    fn parse(s: &str) -> Option<Role> {
        match s {
            "payload" => Some(Role::Payload),
            "source" => Some(Role::Source),
            "presence" => Some(Role::Presence),
            _ => None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct Entry {
    /// Path relative to the manifest's directory, `/`-separated.
    pub name: String,
    pub(crate) len: u64,
    pub(crate) role: Role,
    /// Whole-file MD5, hex. Absent on presence entries.
    pub(crate) md5: Option<String>,
    /// MD5 of the first `min(len, 16384)` bytes, hex - NOT zero-padded,
    /// same convention as PAR2's own (see `nzbkit::par2`). This is what
    /// re-identifies a renamed file without reading it whole.
    pub(crate) md5_16k: Option<String>,
    /// Per-block CRC32s in file order, empty when no grid survived.
    /// The last block is judged zero-padded to [`Entry::bs`], exactly as
    /// `nzbkit::par2::verify_file_streaming` judges it.
    pub(crate) crc32s: Vec<u32>,
    /// The block size THIS entry's grid was cut at, which is why it is
    /// per-entry rather than read off the manifest.
    ///
    /// A TV-filed job's `out_dir` is the SHARED season folder claimed by
    /// every episode in it (`Job::filed`), so one manifest legitimately
    /// carries entries proved by several different jobs - and their PAR2
    /// sets choose their own block sizes. Reading one manifest-level
    /// figure would judge a carried-forward grid at the wrong stride and
    /// call an intact file damaged in every block.
    pub(crate) bs: u64,
    /// The job whose download proved this entry, and its NZB sha.
    ///
    /// Carried per entry for the same shared-folder reason, and because
    /// this is the half a heal needs: detection says WHICH file is
    /// damaged, identity says which post to re-hunt for donors (see the
    /// stage-2 note at the head of this file).
    pub job: String,
    pub nzb_sha: String,
}

#[derive(Debug, Clone)]
pub struct Manifest {
    pub(crate) created_unix: u64,
    pub(crate) nzb_sha: String,
    pub(crate) job: String,
    pub(crate) block_size: u64,
    pub files: Vec<Entry>,
}

/// Per-file verdict from [`Manifest::verify`].
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FileStatus {
    Ok,
    /// Content mismatch. `bad` holds damaged block indexes when the
    /// grid exists (capped for the report), else empty with `md5_ok`
    /// `Some(false)` carrying the verdict.
    ///
    /// `md5_ok` is an OPTION because an entry hashed off the disk
    /// ([`grid_from_disk`]) carries a block grid and no whole-file
    /// digest, so there is no MD5 to have an opinion about. `None` is
    /// "none was recorded", which is a different statement from "it did
    /// not match" and reads differently in a damage report; a bare
    /// `false` there would have every extracted file reporting an MD5
    /// mismatch it was never asked about.
    Damaged {
        bad: Vec<usize>,
        total_blocks: usize,
        md5_ok: Option<bool>,
    },
    Missing,
    SizeMismatch {
        found: u64,
    },
    /// A presence entry that is present: nothing stronger to say.
    PresentUnverified,
    /// A source entry the tail consumed - informational, never damage.
    SourceGone,
}

#[derive(Debug, Default)]
pub struct VerifyReport {
    pub files: Vec<(String, FileStatus)>,
    /// Files under the directory the manifest never saw (skipping the
    /// `.nzbfast` namespace).
    pub(crate) extras: Vec<String>,
}

impl VerifyReport {
    /// True when nothing a user should worry about was found: every
    /// payload entry verified (or is present where unverifiable), no
    /// payload file missing or resized.
    pub(crate) fn all_ok(&self) -> bool {
        self.files.iter().all(|(_, s)| {
            matches!(
                s,
                FileStatus::Ok | FileStatus::PresentUnverified | FileStatus::SourceGone
            )
        })
    }
}

impl Manifest {
    /// Build from the settle-time PAR2 set. `archive` says whether the
    /// covered files are volumes an extract tail will consume (their
    /// role becomes [`Role::Source`] if they are gone by write time).
    /// [`Self::from_set`] over EVERY recovery set the post carried.
    ///
    /// TODO 311: a post may ship one set per file, and a manifest built
    /// from one of them describes one file of eighteen. The per-entry
    /// `bs` is what `check_entry` verifies against, so sets that
    /// disagree about block size compose without loss - the
    /// manifest-level `block_size` is only the default the writer elides
    /// against, and it takes the FIRST set's, which is the largest.
    ///
    /// A name two sets both describe is kept ONCE, first set winning:
    /// the manifest is keyed by name on disk, so a second entry for it
    /// could only ever describe the same bytes or contradict them.
    /// Empty `sets` is not reachable from the caller (the manifest is
    /// written only when a set is active) and yields an empty manifest
    /// rather than a panic.
    pub fn from_sets(
        sets: &[std::sync::Arc<nzbkit::par2::Par2Set>],
        job: &str,
        nzb_sha: &str,
        archive: bool,
    ) -> Manifest {
        let mut m = Manifest {
            created_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            nzb_sha: nzb_sha.to_string(),
            job: job.to_string(),
            block_size: sets.first().map_or(0, |s| s.block_size),
            files: Vec::new(),
        };
        let mut seen: std::collections::HashSet<String> = Default::default();
        for set in sets {
            for e in Manifest::from_set(set, job, nzb_sha, archive).files {
                if seen.insert(e.name.clone()) {
                    m.files.push(e);
                }
            }
        }
        m
    }

    pub fn from_set(
        set: &nzbkit::par2::Par2Set,
        job: &str,
        nzb_sha: &str,
        archive: bool,
    ) -> Manifest {
        let files = set
            .files
            .iter()
            .map(|f| Entry {
                name: nzbkit::disk::sanitize_out_name(&f.name),
                len: f.length,
                role: if archive { Role::Source } else { Role::Payload },
                md5: Some(hex(&f.md5)),
                md5_16k: Some(hex(&f.md5_16k)),
                crc32s: f.blocks.iter().map(|b| b.crc32).collect(),
                bs: set.block_size,
                job: job.to_string(),
                nzb_sha: nzb_sha.to_string(),
            })
            .collect();
        Manifest {
            created_unix: std::time::SystemTime::now()
                .duration_since(std::time::UNIX_EPOCH)
                .map(|d| d.as_secs())
                .unwrap_or(0),
            nzb_sha: nzb_sha.to_string(),
            job: job.to_string(),
            block_size: set.block_size,
            files,
        }
    }

    /// Reconcile against what is actually in `dir`, then write.
    ///
    /// Three things happen here, and each exists because of something
    /// the tail does after the checksums were captured.
    ///
    /// **Renames.** The finalize tail renames files after capture, so an
    /// entry whose name is gone is re-matched by (length, first-16k MD5)
    /// - a 16 KiB read per candidate, never a whole-file read, and
    /// memoized so a set of same-length volumes costs one read each
    /// rather than one per (entry, candidate) pair. A set entry found
    /// nowhere flips to [`Role::Source`]: the tail consumed it.
    ///
    /// **Carry-forward.** A TV-filed job's `out_dir` is the SHARED season
    /// folder claimed by every episode in it (`Job::filed`), so this
    /// directory may already hold a manifest another job wrote. Its
    /// entries for files still on disk are carried into the new one
    /// intact - grid, block size and provenance - instead of being
    /// demoted to presence. Without this a season folder keeps only the
    /// LAST episode's checksums and every earlier one is silently
    /// downgraded to "present, unverifiable" by its successor, which is
    /// the whole feature failing in exactly the directory shape a
    /// library is made of. Matched by (name, length): a previous job's
    /// file is not being renamed by this one's tail, so the 16 KiB
    /// rematch would be reads spent on a case that cannot arise.
    ///
    /// **Recovery files.** A `.par2` still on disk here (the user has
    /// cleanup off) is recorded [`Role::Source`], not presence, because
    /// it is precisely the file the cleanup default deletes. Recorded as
    /// presence it would report `Missing` the day the user turns cleanup
    /// on - a false damage report in the one situation this whole module
    /// exists to serve.
    ///
    /// **The archive flag is re-judged per file, here.** `from_sets`
    /// takes ONE post-wide `archive` boolean (the extractor's latched
    /// shape) and stamps [`Role::Source`] on every covered entry, which
    /// is the right INITIAL guess and the wrong final answer for a
    /// MIXED set: a PAR2 set that covers RAR volumes routinely covers a
    /// loose companion too - a `.srt`, an `.nfo`, an `.sfv`, or a loose
    /// media file the poster put beside the archive. Written `source`,
    /// that companion maps to `SourceGone` when it later disappears,
    /// and `all_ok` ACCEPTS `SourceGone` - so deleting it left the
    /// integrity feature certifying a damaged directory as clean. So
    /// every entry matched to a file that IS on disk is demoted back to
    /// [`Role::Payload`] unless the file itself is archive-or-recovery
    /// material (see [`is_consumable_source`]). The two arms that find
    /// nothing on disk are deliberately untouched: an entry the tail
    /// really did consume is gone, and `Source` is the only honest thing
    /// to say about it.
    ///
    /// **Everything else on disk the set never covered is HASHED HERE**
    /// - a CRC32 block grid read off the file, [`grid_from_disk`] - and
    /// becomes a [`Role::Payload`] entry rather than the presence stub
    /// it was until 2 Sep 2026. That is the whole of the extracted-media
    /// case: for an archive post the PAR2 set covers the volumes, so
    /// before this the film the user actually keeps was recorded as name
    /// and length only, `verify` answered `PresentUnverified`, and
    /// `heal::plan` correctly refused to call that damage - an extracted
    /// film that rotted was invisible to the entire feature.
    ///
    /// Two families are deliberately left as they were: recovery data
    /// (a source, per the paragraph above) and archive material a later
    /// sweep may legitimately take ([`is_consumable_source`]), which
    /// would report as damage the day it is swept. A file the grid pass
    /// cannot read also falls back to a presence entry, because "I could
    /// not read this" is not a checksum.
    pub fn write_reconciled(&mut self, dir: &Path) -> std::io::Result<()> {
        // Read-modify-write, so it is serialized. Carry-forward loads
        // the manifest already in the directory and writes a superset
        // of it, and two episodes of one show CAN settle into the same
        // season folder at once - there is a postproc lane per job.
        // Interleaved, the second write would be built on a snapshot
        // taken before the first one landed, and the first episode's
        // checksums would be gone: the very loss carry-forward exists
        // to prevent, just at a different seam. One lock for all
        // directories rather than one per directory, because this is
        // held for a directory walk and a small write, once per job.
        //
        // What it does NOT cover, and neither does anything else here:
        // a SECOND daemon pointed at the same completed folder. That is
        // already true of `.nzbfast.journal` and is its own hazard.
        //
        // The grid pass below reads the extracted payload INSIDE this
        // lock, so two episodes settling into one season folder at once
        // hash one after the other rather than together. Measured at
        // 0.11 s/GiB (read plus CRC32, see `hashing_extracted_output_is_
        // a_read_and_not_a_hash`), so the serialized case is ~2 s on a
        // 20 GiB folder - against a tail that already spends up to
        // twenty seconds in the identity ladder alone. Hoisting the
        // hashing out would mean walking the directory outside the lock
        // and re-walking it inside, which is a second answer to "what is
        // on disk" and exactly the read-modify-write race the lock is
        // here to prevent.
        static WRITE: std::sync::Mutex<()> = std::sync::Mutex::new(());
        let _serialized = WRITE.lock_ok();
        let mut unclaimed: Vec<(String, u64, PathBuf)> = walk_files(dir)?;
        // A manifest already here was written by an earlier job into the
        // same (shared) directory. Unreadable or of an unknown version is
        // not an error: this write replaces it either way, and the worst
        // case is the entries it held degrade to presence, which is what
        // happened before carry-forward existed.
        let prev = Manifest::load(dir).ok();
        let mut head: HeadCache = HeadCache::default();
        for e in &mut self.files {
            if let Some(i) = unclaimed
                .iter()
                .position(|(n, l, _)| *n == e.name && *l == e.len)
            {
                let (_, _, path) = unclaimed.swap_remove(i);
                // On disk under its own name, so the post-wide archive
                // guess is re-judged against the file - see the
                // archive-flag paragraph above.
                demote_if_payload_on_disk(e, &path);
                continue;
            }
            let Some(want16) = e.md5_16k.clone() else {
                e.role = Role::Source;
                continue;
            };
            let hit = unclaimed
                .iter()
                .position(|(_, l, p)| *l == e.len && head.get(p, e.len) == Some(want16.as_str()));
            match hit {
                Some(i) => {
                    let (n, _, path) = unclaimed.swap_remove(i);
                    e.name = n;
                    // Same re-judgement as the arm above, and it has to
                    // be here too: the tail renames companions as
                    // readily as volumes, so a loose `.srt` that
                    // arrived at this arm rather than the first one is
                    // exactly as wrongly marked `source`.
                    demote_if_payload_on_disk(e, &path);
                }
                // Not on disk under any name: the tail consumed it.
                None => e.role = Role::Source,
            }
        }
        for (n, l, p) in unclaimed {
            if let Some(kept) = prev
                .as_ref()
                .and_then(|m| m.files.iter().find(|o| o.name == n && o.len == l))
            {
                self.files.push(kept.clone());
                continue;
            }
            // BELOW the carry-forward, which is what keeps the cost
            // linear in a shared season folder: an episode already
            // hashed by an earlier job is cloned with its grid, so
            // episode ten's write reads episode ten and not the other
            // nine.
            //
            // Recovery data stays a source (see the paragraph above);
            // archive material a sweep may still take is left alone. In
            // between is what an extract produced, and it gets a grid.
            let consumable = is_par2_path(&p) || is_consumable_source(&p);
            let grid = (!consumable)
                .then(|| grid_from_disk(&p, l, self.block_size))
                .flatten();
            self.files.push(match grid {
                Some((bs, crc32s)) => Entry {
                    name: n,
                    len: l,
                    role: Role::Payload,
                    md5: None,
                    md5_16k: None,
                    crc32s,
                    bs,
                    job: self.job.clone(),
                    nzb_sha: self.nzb_sha.clone(),
                },
                None => Entry {
                    name: n,
                    len: l,
                    role: if is_par2_path(&p) {
                        Role::Source
                    } else {
                        Role::Presence
                    },
                    md5: None,
                    md5_16k: None,
                    crc32s: Vec::new(),
                    bs: 0,
                    job: self.job.clone(),
                    nzb_sha: self.nzb_sha.clone(),
                },
            });
        }
        self.write_to(dir)
    }

    fn write_to(&self, dir: &Path) -> std::io::Result<()> {
        let path = dir.join(MANIFEST_NAME);
        let files: Vec<Value> = self
            .files
            .iter()
            .map(|e| {
                let mut o = json!({
                    "n": e.name,
                    "l": e.len,
                    "r": e.role.tag(),
                });
                if let Some(m) = &e.md5 {
                    o["md5"] = json!(m);
                }
                if let Some(m) = &e.md5_16k {
                    o["m16"] = json!(m);
                }
                if !e.crc32s.is_empty() {
                    o["crc"] = json!(pack_crcs(&e.crc32s));
                }
                // Written only when it differs from the manifest-level
                // default, which is the single-job case - so the common
                // file gains nothing and the shared season folder stays
                // exact. Same rule for the provenance pair.
                if e.bs != self.block_size && e.bs != 0 {
                    o["bs"] = json!(e.bs);
                }
                if e.job != self.job {
                    o["job"] = json!(e.job);
                }
                if e.nzb_sha != self.nzb_sha {
                    o["sha"] = json!(e.nzb_sha);
                }
                o
            })
            .collect();
        let doc = json!({
            "v": 1,
            "created": self.created_unix,
            "nzb_sha": self.nzb_sha,
            "job": self.job,
            "block_size": self.block_size,
            "files": files,
        });
        // Temp-and-rename, not a bare write, and in a shared season
        // folder that is the difference between a stumble and data
        // loss: `fs::write` truncates first, so a failure part way
        // through destroys the manifest already there - which by then
        // holds every EARLIER episode's checksums, carried forward
        // above. A rename either replaces it whole or leaves it whole.
        let tmp = dir.join(format!("{MANIFEST_NAME}.tmp"));
        std::fs::write(&tmp, doc.to_string())?;
        if let Err(e) = std::fs::rename(&tmp, &path) {
            let _ = std::fs::remove_file(&tmp);
            return Err(e);
        }
        nzbkit::disk::hide_from_user(&path);
        Ok(())
    }

    pub fn load(dir: &Path) -> std::io::Result<Manifest> {
        let bytes = std::fs::read(dir.join(MANIFEST_NAME))?;
        let v: Value = serde_json::from_slice(&bytes)
            .map_err(|e| std::io::Error::new(std::io::ErrorKind::InvalidData, e))?;
        let bad = || std::io::Error::new(std::io::ErrorKind::InvalidData, "manifest malformed");
        if v.get("v").and_then(Value::as_u64) != Some(1) {
            return Err(std::io::Error::new(
                std::io::ErrorKind::InvalidData,
                "manifest version unsupported",
            ));
        }
        // Read before the entries: each is the default an entry falls
        // back to when it carries no override of its own.
        let block_size = v
            .get("block_size")
            .and_then(Value::as_u64)
            .ok_or_else(bad)?;
        let job = v
            .get("job")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let nzb_sha = v
            .get("nzb_sha")
            .and_then(Value::as_str)
            .unwrap_or_default()
            .to_string();
        let files = v
            .get("files")
            .and_then(Value::as_array)
            .ok_or_else(bad)?
            .iter()
            .map(|f| {
                Some(Entry {
                    name: f.get("n")?.as_str()?.to_string(),
                    len: f.get("l")?.as_u64()?,
                    role: Role::parse(f.get("r")?.as_str()?)?,
                    md5: f.get("md5").and_then(Value::as_str).map(str::to_string),
                    md5_16k: f.get("m16").and_then(Value::as_str).map(str::to_string),
                    crc32s: match f.get("crc").and_then(Value::as_str) {
                        Some(s) => unpack_crcs(s)?,
                        None => Vec::new(),
                    },
                    bs: f.get("bs").and_then(Value::as_u64).unwrap_or(block_size),
                    job: f
                        .get("job")
                        .and_then(Value::as_str)
                        .unwrap_or(job.as_str())
                        .to_string(),
                    nzb_sha: f
                        .get("sha")
                        .and_then(Value::as_str)
                        .unwrap_or(nzb_sha.as_str())
                        .to_string(),
                })
            })
            .collect::<Option<Vec<_>>>()
            .ok_or_else(bad)?;
        Ok(Manifest {
            created_unix: v.get("created").and_then(Value::as_u64).unwrap_or(0),
            nzb_sha,
            job,
            block_size,
            files,
        })
    }

    /// Verify `dir` against this manifest. Streams every checked file
    /// in 1 MiB windows - a set member is a payload file, so slurping
    /// it whole is the mistake `verify_dir`'s own comment warns about.
    pub fn verify(&self, dir: &Path) -> std::io::Result<VerifyReport> {
        let mut report = VerifyReport::default();
        let mut seen: std::collections::HashSet<&str> = std::collections::HashSet::new();
        for e in &self.files {
            seen.insert(e.name.as_str());
            let path = dir.join(&e.name);
            let status = match std::fs::metadata(&path) {
                Err(_) if e.role == Role::Source => FileStatus::SourceGone,
                Err(_) => FileStatus::Missing,
                Ok(m) if m.len() != e.len => FileStatus::SizeMismatch { found: m.len() },
                // Nothing recorded to check it against: no whole-file
                // digest AND no grid. A grid alone is enough - that is
                // the extracted-output entry `write_reconciled` hashes
                // off the disk, and `check_entry` judges it on the grid.
                Ok(_) if e.md5.is_none() && e.crc32s.is_empty() => FileStatus::PresentUnverified,
                // The entry's OWN stride, never the manifest's: a shared
                // season folder carries grids from several PAR2 sets.
                Ok(_) => check_entry(e, e.bs, &path)?,
            };
            report.files.push((e.name.clone(), status));
        }
        for (n, _, _) in walk_files(dir)? {
            if !seen.contains(n.as_str()) {
                report.extras.push(n);
            }
        }
        Ok(report)
    }
}

/// Stream one file against its entry: per-block CRC32 (last block
/// zero-padded arithmetically, via `crc32_zeros`) plus the whole-file
/// MD5. Same walk shape as `nzbkit::par2::verify_file_streaming`, minus
/// the per-block MD5 this manifest deliberately does not carry.
///
/// The MD5 half is SKIPPED when the entry carries none, which is every
/// entry [`grid_from_disk`] built: computing a digest nothing will be
/// compared against is 1.35 s/GiB spent to learn nothing (measured -
/// `hashing_extracted_output_is_a_read_and_not_a_hash`), and it is the
/// whole reason a verify of an extracted film is as cheap as one of a
/// covered file rather than fourteen times dearer.
///
/// The CALLER guarantees the entry records at least one of the two -
/// [`Manifest::verify`] sends an entry with neither straight to
/// `PresentUnverified`, because a file with nothing recorded about it
/// cannot be called clean OR damaged.
fn check_entry(e: &Entry, block_size: u64, path: &Path) -> std::io::Result<FileStatus> {
    const REPORT_BAD_CAP: usize = 64;
    let bs = block_size as usize;
    let mut f = std::fs::File::open(path)?;
    let mut buf = vec![0u8; 1 << 20];
    // `None` when the entry records no whole-file digest: an MD5 of the
    // bytes with nothing to compare it against is pure cost. See this
    // function's own header.
    let mut whole = e.md5.is_some().then(Md5::new);
    let mut bcrc = crc32fast::Hasher::new();
    let mut filled = 0usize;
    let mut bi = 0usize;
    let mut bad: Vec<usize> = Vec::new();
    let note_bad = |i: usize, bad: &mut Vec<usize>| {
        if bad.len() < REPORT_BAD_CAP {
            bad.push(i);
        }
    };
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(err) => return Err(err),
        };
        if let Some(whole) = whole.as_mut() {
            whole.update(&buf[..n]);
        }
        if bs > 0 && !e.crc32s.is_empty() {
            let mut p = 0usize;
            while p < n && bi < e.crc32s.len() {
                let seg = (bs - filled).min(n - p);
                bcrc.update(&buf[p..p + seg]);
                filled += seg;
                p += seg;
                if filled == bs {
                    let crc = std::mem::replace(&mut bcrc, crc32fast::Hasher::new()).finalize();
                    if crc != e.crc32s[bi] {
                        note_bad(bi, &mut bad);
                    }
                    bi += 1;
                    filled = 0;
                }
            }
        }
    }
    if filled > 0 && bi < e.crc32s.len() {
        let crc = nzbkit::yenc_simd::crc32_zeros(bcrc.finalize(), (bs - filled) as u64);
        if crc != e.crc32s[bi] {
            note_bad(bi, &mut bad);
        }
        bi += 1;
    }
    while bi < e.crc32s.len() {
        note_bad(bi, &mut bad);
        bi += 1;
    }
    let md5_ok = whole.map(|h| {
        let md5_hex: String = hex(&h.finalize().into());
        e.md5.as_deref() == Some(md5_hex.as_str())
    });
    if md5_ok != Some(false) && bad.is_empty() {
        Ok(FileStatus::Ok)
    } else {
        Ok(FileStatus::Damaged {
            bad,
            total_blocks: e.crc32s.len(),
            md5_ok,
        })
    }
}

/// Every regular file under `dir`, `(relative-name, len, path)`,
/// skipping the `.nzbfast` namespace at any depth.
fn walk_files(dir: &Path) -> std::io::Result<Vec<(String, u64, PathBuf)>> {
    let mut out = Vec::new();
    let mut stack = vec![dir.to_path_buf()];
    while let Some(d) = stack.pop() {
        for ent in std::fs::read_dir(&d)?.flatten() {
            let name = ent.file_name().to_string_lossy().to_string();
            if name.starts_with(".nzbfast") {
                continue;
            }
            let path = ent.path();
            // Skipped, never propagated: `metadata()` FOLLOWS the link, so
            // one broken symlink in the output directory would otherwise
            // fail the whole walk - and this walk runs on both sides, so
            // that is a manifest never written AND a verify that reports
            // nothing rather than reporting the directory. A file we
            // cannot stat is a file we can say nothing about, which is
            // exactly what leaving it out says.
            let Ok(meta) = ent.metadata() else { continue };
            if meta.is_dir() {
                stack.push(path);
            } else if meta.is_file() {
                let rel = path
                    .strip_prefix(dir)
                    .unwrap_or(&path)
                    .to_string_lossy()
                    .replace('\\', "/");
                out.push((rel, meta.len(), path));
            }
        }
    }
    Ok(out)
}

/// Memoized first-16k hashes for the rename rematch.
///
/// Without it the rematch is quadratic in the worst shape it actually
/// meets: N same-length volumes all renamed by the tail is N entries
/// each hashing the head of every remaining candidate, so N x N reads
/// of 16 KiB. A hundred volumes is 160 MB read to answer a question
/// that needs 1.6 MB. Keyed by path because that is what identifies
/// the candidate; the entries move, the files do not.
#[derive(Default)]
struct HeadCache {
    seen: std::collections::HashMap<PathBuf, Option<String>>,
}

impl HeadCache {
    fn get(&mut self, path: &Path, len: u64) -> Option<&str> {
        self.seen
            .entry(path.to_path_buf())
            .or_insert_with(|| md5_16k_hex(path, len))
            .as_deref()
    }
}

/// A PAR2 recovery file, by extension or by the `PAR2\0PKT` magic an
/// obfuscated volume keeps after losing its name.
///
/// These are what the cleanup default deletes, so one still on disk at
/// write time is recorded [`Role::Source`] - "gone later is normal" -
/// rather than as a presence entry that would report `Missing` the day
/// cleanup runs. Read the head rather than trusting the extension for
/// the same reason `unpack::dir_has_par2` does.
fn is_par2_path(path: &Path) -> bool {
    if path
        .extension()
        .is_some_and(|x| x.eq_ignore_ascii_case("par2"))
    {
        return true;
    }
    let mut head = [0u8; 8];
    std::fs::File::open(path)
        .and_then(|mut f| f.read_exact(&mut head))
        .is_ok()
        && &head == b"PAR2\0PKT"
}

/// Re-judge one entry's post-wide `archive` guess against the file the
/// reconcile just matched it to, on disk.
///
/// Only ever DEMOTES, never promotes, and that direction is the whole
/// point. `from_sets` was handed ONE boolean for the post - the
/// extractor's latched archive shape - so a mixed set (RAR volumes plus
/// a loose covered companion) stamped [`Role::Source`] on the companion
/// too. `Source` means "gone later is normal", `verify` maps a gone
/// source to `FileStatus::SourceGone`, and `VerifyReport::all_ok`
/// ACCEPTS that - so the integrity feature certified a directory whose
/// `.srt` had been deleted as clean. A companion sitting on disk is
/// payload; say so.
///
/// The inverse is deliberately NOT done. Promoting a `Payload` entry to
/// `Source` because the file happens to be a volume would change the
/// non-archive path, where `archive` was false for a reason (extraction
/// off, or a set the extractor never claimed) and a vanished volume
/// really is damage. This function is reached only from the two arms
/// that found the file, so an entry the tail genuinely consumed keeps
/// the `Source` those arms give it.
fn demote_if_payload_on_disk(e: &mut Entry, path: &Path) {
    if e.role == Role::Source && !is_consumable_source(path) {
        e.role = Role::Payload;
    }
}

/// Is this file archive-or-recovery material - something the tail's
/// spent-volume sweep or the `par_cleanup` default may legitimately
/// delete after the manifest is written, so that its absence on a later
/// verify is not damage?
///
/// Four families, and each arm is here because the one before it cannot
/// see its shape:
///
/// - [`is_par2_path`] - recovery data, by extension or by the
///   `PAR2\0PKT` magic an obfuscated volume keeps after losing its
///   name.
/// - `unpack::looks_like_named_rar` - the name grammar the RAR extract
///   paths share (`.rar`/`.rNN` outright, rollover/numeric tails only
///   with the `Rar!` magic). Name-first is what catches a volume whose
///   signature the poster destroyed, which no magic sniff can.
/// - `archname::sevenz_archive_part` - `.7z`, a `.7z.NNN` split part
///   (parts 2 and up carry NO magic, so only the name can claim them),
///   or the 7z magic. Guarded by `extract::archive_sniff_eligible`
///   because that last arm is magic-only and a NAMED file is not
///   packaging: a `.cb7` comic is the deliverable, and so - matrix row
///   M4-90, 31 Aug 2026 - is a `Movie.mkv`, a `disc.iso` or a
///   `Subs.srt`. The guard was `is_final_file` until then, which sees
///   only the first of those three.
/// - `nzbkit::zip::is_container` - `.zip`/`.zipx`, a WinZip-spanned
///   `.zNN`, a `.zip.NNN` byte split, or a bare numeric part carrying
///   `PK\x03\x04`. It carries its own `is_final_file` guard.
///
/// The 7z and zip arms are here rather than left for later on purpose:
/// without them a 7z or zip volume STILL ON DISK is demoted to
/// [`Role::Payload`] by the caller and then reports `Missing` the day
/// the sweep takes it - the mirror image of the defect this whole
/// function fixes, in the family nobody was looking at. It is a suffix
/// and magic test, not new plumbing, so there was no reason to defer it.
///
/// `scan::is_rar_member` is the wrong helper to reach for here even
/// though it looks closer: that module is behind the `indexer` feature
/// and this one is not, so the slim build would not compile.
///
/// THE 7z ARM ANSWERS THE SAME QUESTION ITS CONSUMER DOES, which is why
/// the guard is that one and not something looser. `collect_sevenz_archives`
/// - the sweep that would ever spend one of these - takes the `.7z` and
/// `.7z.NNN` NAMES unconditionally and gates its magic arm on
/// `archive_sniff_eligible_name`. This predicate reduces to exactly that:
/// neither the final-file nor the payload-content list holds a `7z` or a
/// numeric extension, and both key on the LAST extension only, so the
/// guard can bite nothing but the magic arm. Nothing on the extraction
/// path will consume a payload-named file any more, so calling one a
/// consumable source was a claim about a deletion that can no longer
/// happen - and until 31 Aug 2026 the two disagreed: a `Subs.srt` whose
/// first bytes read as 7z was stamped [`Role::Source`], so its later
/// absence mapped to `SourceGone` and `all_ok` ACCEPTED it. That is the
/// companion-certified-clean defect this whole function exists to fix,
/// live in the one family it had not reached.
///
/// TWO STATED GAPS, both in the safe direction. A covered volume whose
/// extension is numeric AND whose archive signature the poster destroyed
/// answers false to every arm - the name says nothing and the head says
/// nothing - so it is demoted to [`Role::Payload`] and would report
/// `Missing` if a later sweep took it. The second is the new guard's own
/// cost: a poster who dresses real 7z volumes as `Movie.mkv` gets the
/// same treatment, deliberately. Both are a FALSE DAMAGE report rather
/// than a false clean one, which is the direction to err in for a
/// feature whose whole job is to notice damage, and closing the first
/// needs a signal that is not on the disk. The second is not open at
/// all: no sweep takes those files either, so the report they would
/// provoke needs a deletion nothing here performs. Both are also narrow:
/// this runs after finalize, so a volume the spent-volume sweep already
/// took is not here at all and reaches the arm that correctly calls it a
/// consumed source.
fn is_consumable_source(path: &Path) -> bool {
    if is_par2_path(path) || crate::archname::looks_like_named_rar(path) {
        return true;
    }
    if nzbkit::extract::archive_sniff_eligible(path) && crate::archname::sevenz_archive_part(path) {
        return true;
    }
    nzbkit::zip::is_container(path)
}

/// The most CRC32s one hashed-from-disk entry will carry.
///
/// The grid is packed eight hex characters per block, so this is 32 KB
/// of manifest for the largest file it bites on. A 20 GiB film at a
/// poster's 384 KiB block size would be 54,613 blocks and 437 KB, in a
/// hidden sidecar written for every finished job - so the block size is
/// doubled until the count fits instead. Nothing downstream wants the
/// finer grid: an archive post's heal re-fetches the post (see
/// `heal.rs`), so the block index is a damage REPORT and not a
/// fetch plan.
const MAX_GRID_BLOCKS: u64 = 4096;

/// The stride [`grid_from_disk`] cuts at: the manifest's own block size,
/// doubled until the file fits in [`MAX_GRID_BLOCKS`].
///
/// Starting from the manifest's size rather than a constant keeps a
/// directory's grids on one stride wherever it can - the covered entries
/// are cut at the poster's block size, and an extracted file beside them
/// reads the same way in a report. Never FINER than that: a stride the
/// covered entries do not use buys precision nothing asks for.
fn grid_block_size(len: u64, manifest_bs: u64) -> u64 {
    // 0 only from a manifest built over no sets at all, which the caller
    // does not reach; 1 MiB is the fallback rather than a panic.
    let mut bs = if manifest_bs == 0 {
        1 << 20
    } else {
        manifest_bs
    };
    while len.div_ceil(bs) > MAX_GRID_BLOCKS {
        bs = bs.saturating_mul(2);
    }
    bs
}

/// Read a file the recovery set never covered and cut it into a CRC32
/// block grid - the checksums that let an extracted film be convicted.
///
/// **Why a grid and no whole-file MD5, which is the one choice here
/// worth reading twice.** Measured on an M5 Max, 1 GiB, 1 MiB windows,
/// release profile (`hashing_extracted_output_is_a_read_and_not_a_hash`
/// prints the same shape from the test profile):
///
/// | pass                    | per GiB |
/// | ----------------------- | ------- |
/// | read only               | 0.07 s  |
/// | read + CRC32            | 0.11 s  |
/// | read + SHA-256          | 0.43 s  |
/// | read + MD5              | 1.49 s  |
///
/// So the READ is 5% of the cost and the HASH is all of it, which
/// inverts the premise TODO 310's box was written on ("rides the
/// finalize move's existing read on the cross-device path; an extra read
/// pass on same-device"). Threading digests out of `smart::movetree`'s
/// cross-device copy - which does read every byte - would save 0.07 of
/// 0.11 s/GiB through four modules of plumbing, and would leave the
/// same-device path, which is most installs, still owing the whole pass.
/// Hashing HERE costs one number on both paths and needs no plumbing at
/// all. That is why there is no `hash_extracted` setting: at 0.11 s/GiB
/// (2 s on a 20 GiB season folder, against a tail that spends up to
/// twenty seconds in the identity ladder alone) there is nothing left
/// for a knob to buy back. `write_manifest` is already the switch for
/// the whole feature.
///
/// **CRC32 and not a cryptographic digest**, deliberately. This detects
/// ROT - a flipped bit, a bad sector, a truncating copy - and length is
/// checked before the grid is even read, so the residue is a
/// same-length rewrite that also collides on every block's CRC32. An
/// adversary who can rewrite the film in the user's own folder can
/// rewrite the `.nzbfast.manifest` sitting beside it, so the stronger
/// digest would be guarding a door with no wall. SHA-256 was measured
/// (0.43 s/GiB, four times the cost) and rejected on exactly that.
///
/// `None` for a file with no bytes or one that cannot be read: "I could
/// not read this" is not a checksum, and the caller records a presence
/// entry instead. The last block is judged zero-padded to the stride,
/// the same arithmetic [`check_entry`] verifies it with - the two walks
/// have to agree about the tail or every file would report its last
/// block bad.
fn grid_from_disk(path: &Path, len: u64, manifest_bs: u64) -> Option<(u64, Vec<u32>)> {
    if len == 0 {
        return None;
    }
    let bs_u64 = grid_block_size(len, manifest_bs);
    let bs = usize::try_from(bs_u64).ok()?;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; 1 << 20];
    let mut crcs: Vec<u32> = Vec::with_capacity(len.div_ceil(bs_u64) as usize);
    let mut bcrc = crc32fast::Hasher::new();
    let mut filled = 0usize;
    let mut total = 0u64;
    loop {
        let n = match f.read(&mut buf) {
            Ok(0) => break,
            Ok(n) => n,
            Err(err) if err.kind() == std::io::ErrorKind::Interrupted => continue,
            Err(_) => return None,
        };
        total += n as u64;
        let mut p = 0usize;
        while p < n {
            let seg = (bs - filled).min(n - p);
            bcrc.update(&buf[p..p + seg]);
            filled += seg;
            p += seg;
            if filled == bs {
                crcs.push(std::mem::replace(&mut bcrc, crc32fast::Hasher::new()).finalize());
                filled = 0;
            }
        }
    }
    if filled > 0 {
        crcs.push(nzbkit::yenc_simd::crc32_zeros(
            bcrc.finalize(),
            (bs - filled) as u64,
        ));
    }
    // The walk read a different file from the one `walk_files` measured:
    // something is writing here (a post-job script that started early, a
    // user copying over the top). A grid over bytes the entry's own
    // length contradicts would report damage on every later verify, so
    // record nothing and let the entry be presence-only.
    (total == len).then_some((bs_u64, crcs))
}

fn md5_16k_hex(path: &Path, len: u64) -> Option<String> {
    let take = len.min(16384) as usize;
    let mut f = std::fs::File::open(path).ok()?;
    let mut buf = vec![0u8; take];
    f.read_exact(&mut buf).ok()?;
    let mut h = Md5::new();
    h.update(&buf);
    Some(hex(&h.finalize().into()))
}

/// The CLI arm of `nzbfast verify` for a directory whose PAR2 files
/// are gone: verify against the settle manifest instead, printing a
/// per-file report in `verify_dir`'s own voice. Returns whether
/// everything a user should worry about checked out.
pub fn verify_cli(dir: &Path) -> std::io::Result<bool> {
    use tracing::{info, warn};
    let m = Manifest::load(dir)?;
    info!(
        target: "par2",
        "no PAR2 on disk - verifying against the settle manifest ({} file(s), block size {})",
        m.files.len(),
        m.block_size
    );
    let report = m.verify(dir)?;
    for (name, status) in &report.files {
        match status {
            FileStatus::Ok => info!(target: "par2", "✔ {name} - manifest checks pass"),
            FileStatus::PresentUnverified => {
                info!(
                    target: "par2",
                    "• {name} - present, size ok, no checksum recorded"
                );
            }
            FileStatus::SourceGone => {
                info!(target: "par2", "• {name} - consumed source (normal after unpack)");
            }
            FileStatus::Damaged {
                bad,
                total_blocks,
                md5_ok,
            } => {
                // An entry hashed off the disk carries a grid and no
                // whole-file digest, so there is no MD5 clause to
                // print - saying "md5 MISMATCH" about a digest that was
                // never recorded is the report lying about what it
                // checked.
                match md5_ok {
                    Some(ok) => warn!(
                        target: "par2",
                        "✘ {name} - {}/{total_blocks} block(s) bad, md5 {}",
                        bad.len(),
                        if *ok { "ok" } else { "MISMATCH" }
                    ),
                    None => warn!(
                        target: "par2",
                        "✘ {name} - {}/{total_blocks} block(s) bad",
                        bad.len()
                    ),
                }
            }
            FileStatus::Missing => warn!(target: "par2", "✘ {name} - file missing"),
            FileStatus::SizeMismatch { found } => {
                warn!(target: "par2", "✘ {name} - size changed (now {found} bytes)");
            }
        }
    }
    for extra in &report.extras {
        info!(target: "par2", "• {extra} - not in the manifest (added later)");
    }
    Ok(report.all_ok())
}

fn hex(b: &[u8; 16]) -> String {
    let mut s = String::with_capacity(32);
    for x in b {
        s.push_str(&format!("{x:02x}"));
    }
    s
}

fn pack_crcs(crcs: &[u32]) -> String {
    let mut s = String::with_capacity(crcs.len() * 8);
    for c in crcs {
        s.push_str(&format!("{c:08x}"));
    }
    s
}

fn unpack_crcs(s: &str) -> Option<Vec<u32>> {
    if !s.len().is_multiple_of(8) {
        return None;
    }
    s.as_bytes()
        .chunks(8)
        .map(|c| u32::from_str_radix(std::str::from_utf8(c).ok()?, 16).ok())
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use nzbkit::par2::{BlockCheck, Par2File, Par2Set};

    fn temp_dir(tag: &str) -> PathBuf {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-manifest-{tag}-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        dir
    }

    /// Deterministic junk that is not all-zero, so a flipped byte
    /// actually changes a checksum.
    fn body(len: usize, seed: u8) -> Vec<u8> {
        (0..len)
            .map(|i| (i as u8).wrapping_mul(31).wrapping_add(seed))
            .collect()
    }

    fn md5_of(b: &[u8]) -> [u8; 16] {
        let mut h = Md5::new();
        h.update(b);
        h.finalize().into()
    }

    /// A real `Par2Set` over generated payload, the way the parser
    /// would have built it: per-block CRC32/MD5 with the last block
    /// zero-padded, md5-16k unpadded.
    fn set_over(files: &[(&str, &[u8])], bs: usize) -> Par2Set {
        let files = files
            .iter()
            .map(|(name, data)| {
                let blocks = data
                    .chunks(bs)
                    .map(|c| {
                        let mut padded = c.to_vec();
                        padded.resize(bs, 0);
                        let mut crc = crc32fast::Hasher::new();
                        crc.update(&padded);
                        BlockCheck {
                            md5: md5_of(&padded),
                            crc32: crc.finalize(),
                        }
                    })
                    .collect();
                Par2File {
                    file_id: [0u8; 16],
                    name: (*name).to_string(),
                    length: data.len() as u64,
                    md5: md5_of(data),
                    md5_16k: md5_of(&data[..data.len().min(16384)]),
                    blocks,
                }
            })
            .collect();
        Par2Set {
            recovery_set_id: [0u8; 16],
            block_size: bs as u64,
            files,
            nonrecovery: Vec::new(),
            recovery_blocks_seen: 0,
        }
    }

    #[test]
    fn roundtrip_preserves_every_field() {
        let dir = temp_dir("roundtrip");
        let a = body(5000, 1);
        let b = body(700, 2);
        std::fs::write(dir.join("a.bin"), &a).unwrap();
        std::fs::write(dir.join("b.bin"), &b).unwrap();
        let set = set_over(&[("a.bin", &a), ("b.bin", &b)], 1024);
        let mut m = Manifest::from_set(&set, "Job.Name", "deadbeef", false);
        m.write_reconciled(&dir).unwrap();
        let back = Manifest::load(&dir).unwrap();
        assert_eq!(back.block_size, 1024);
        assert_eq!(back.nzb_sha, "deadbeef");
        assert_eq!(back.job, "Job.Name");
        let a2 = back.files.iter().find(|e| e.name == "a.bin").unwrap();
        assert_eq!(a2.len, 5000);
        assert_eq!(a2.role, Role::Payload);
        assert_eq!(a2.crc32s.len(), 5);
        assert_eq!(a2.md5.as_deref(), Some(hex(&md5_of(&a)).as_str()));
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// THE A/B THIS FEATURE OWES, printed. A: the tree as it stands -
    /// after the cleanup default has removed the .par2 files, nothing
    /// can check the directory at all (`dir_has_par2` is false, and
    /// every verify path gates on it). B: the manifest names the
    /// damaged file and the damaged block. Also prints the not-hinder
    /// number: build+write wall for a 64-file, 16k-block set, which is
    /// the whole cost the settle tail pays.
    #[test]
    fn after_par2_cleanup_only_the_manifest_can_answer() {
        let dir = temp_dir("ab");
        let a = body(64 * 1024, 3);
        std::fs::write(dir.join("payload.bin"), &a).unwrap();
        let set = set_over(&[("payload.bin", &a)], 4096);
        let mut m = Manifest::from_set(&set, "AB.Job", "cafe", false);
        m.write_reconciled(&dir).unwrap();

        // The A arm: no .par2 anywhere, so the PAR2 verify path has
        // nothing to read. This is the post-cleanup state every
        // default-settings user's library is in.
        let par2_present = std::fs::read_dir(&dir)
            .unwrap()
            .flatten()
            .any(|e| e.path().extension().is_some_and(|x| x == "par2"));
        assert!(!par2_present, "the fixture models the post-cleanup state");

        // Flip one byte mid-file: block 8 of 16.
        let mut damaged = a.clone();
        damaged[8 * 4096 + 17] ^= 0x40;
        std::fs::write(dir.join("payload.bin"), &damaged).unwrap();

        let report = Manifest::load(&dir).unwrap().verify(&dir).unwrap();
        assert!(!report.all_ok());
        let (_, status) = &report.files[0];
        match status {
            FileStatus::Damaged {
                bad,
                total_blocks,
                md5_ok,
            } => {
                assert_eq!(bad.as_slice(), &[8], "the flipped block is named exactly");
                assert_eq!(*total_blocks, 16);
                assert_eq!(*md5_ok, Some(false));
            }
            other => panic!("expected Damaged, got {other:?}"),
        }

        // The not-hinder number: what the settle tail pays to keep all
        // of this. 64 files x 256 blocks, built from memory and written
        // once - the same shape as a real job's set.
        let many: Vec<(String, Vec<u8>)> = (0..64)
            .map(|i| (format!("f{i:02}.bin"), body(1024, i as u8)))
            .collect();
        let dir2 = temp_dir("ab-cost");
        for (n, d) in &many {
            std::fs::write(dir2.join(n), d).unwrap();
        }
        let refs: Vec<(&str, &[u8])> = many
            .iter()
            .map(|(n, d)| (n.as_str(), d.as_slice()))
            .collect();
        let big = set_over(&refs, 4096);
        let t0 = std::time::Instant::now();
        let mut m2 = Manifest::from_set(&big, "Cost.Job", "beef", false);
        m2.write_reconciled(&dir2).unwrap();
        let write_us = t0.elapsed().as_micros();
        println!(
            "A/B settle manifest: post-cleanup PAR2 verify has NOTHING TO READ; \
             manifest verify named block 8/16 of the damaged file. \
             Not-hinder: 64-file manifest built+written in {write_us} us."
        );
        let _ = std::fs::remove_dir_all(&dir);
        let _ = std::fs::remove_dir_all(&dir2);
    }

    /// The finalize tail renames files after the checksums are
    /// captured. The reconcile must follow the bytes, not the name -
    /// by (length, first-16k MD5), reading 16 KiB and never the file.
    #[test]
    fn a_renamed_file_is_rematched_by_length_and_head_hash() {
        let dir = temp_dir("rename");
        let a = body(30000, 9);
        std::fs::write(dir.join("Renamed.By.The.Tail.mkv"), &a).unwrap();
        let set = set_over(&[("obfuscated0451", &a)], 4096);
        let mut m = Manifest::from_set(&set, "Rn.Job", "f00d", false);
        m.write_reconciled(&dir).unwrap();
        let back = Manifest::load(&dir).unwrap();
        assert_eq!(back.files.len(), 1);
        assert_eq!(back.files[0].name, "Renamed.By.The.Tail.mkv");
        assert_eq!(back.files[0].role, Role::Payload);
        let report = back.verify(&dir).unwrap();
        assert!(report.all_ok(), "{report:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// An archive post's PAR2 set covers the volumes, and the tail
    /// consumes them. Their entries flip to `source` (missing is
    /// normal) - and the extracted output the set never covered, which
    /// is the only thing the user actually keeps, is hashed off the disk
    /// and recorded as payload with a grid.
    ///
    /// **This is the defect TODO 310's third box named.** Until 2 Sep
    /// 2026 the `.mkv` here was a presence entry: `verify` answered
    /// `PresentUnverified`, `all_ok` accepted that, and `heal::plan`
    /// correctly refused to call it damage - so an extracted film that
    /// rotted was invisible to the whole feature, in the shape most of a
    /// library is made of. The byte flip below is the arm that would
    /// have passed.
    #[test]
    fn consumed_volumes_are_sources_and_extracted_output_is_hashed() {
        let dir = temp_dir("archive");
        let vol = body(8192, 4);
        // The volume is NOT on disk (the spent-volume sweep took it);
        // the extracted movie is.
        let mkv = body(50000, 5);
        std::fs::write(dir.join("Movie.mkv"), &mkv).unwrap();
        let set = set_over(&[("set.part1.rar", &vol)], 4096);
        let mut m = Manifest::from_set(&set, "Ar.Job", "0ddb", true);
        m.write_reconciled(&dir).unwrap();
        let back = Manifest::load(&dir).unwrap();
        let rar = back
            .files
            .iter()
            .find(|e| e.name == "set.part1.rar")
            .unwrap();
        assert_eq!(rar.role, Role::Source);
        let film = back.files.iter().find(|e| e.name == "Movie.mkv").unwrap();
        assert_eq!(
            film.role,
            Role::Payload,
            "extracted output is convictable, so it is payload"
        );
        assert!(film.md5.is_none(), "no whole-file digest: the grid is it");
        assert_eq!(film.bs, 4096, "cut at the manifest's own stride");
        assert_eq!(
            film.crc32s.len(),
            50000_usize.div_ceil(4096),
            "a block grid over every byte, last block zero-padded"
        );
        // Provenance: this post is what a heal would re-fetch for it.
        assert_eq!(
            (film.job.as_str(), film.nzb_sha.as_str()),
            ("Ar.Job", "0ddb")
        );
        let report = back.verify(&dir).unwrap();
        assert!(report.all_ok(), "{report:?}");
        assert!(
            report
                .files
                .iter()
                .any(|(n, s)| n == "set.part1.rar" && *s == FileStatus::SourceGone)
        );
        assert!(
            report
                .files
                .iter()
                .any(|(n, s)| n == "Movie.mkv" && *s == FileStatus::Ok),
            "{report:?}"
        );

        // THE ARM THAT USED TO PASS: one flipped byte in the film.
        let mut rotted = mkv.clone();
        rotted[7 * 4096 + 3] ^= 0x20;
        std::fs::write(dir.join("Movie.mkv"), &rotted).unwrap();
        let report2 = back.verify(&dir).unwrap();
        assert!(!report2.all_ok(), "a rotted film is damage");
        let (_, status) = report2
            .files
            .iter()
            .find(|(n, _)| n == "Movie.mkv")
            .unwrap();
        match status {
            FileStatus::Damaged {
                bad,
                total_blocks,
                md5_ok,
            } => {
                assert_eq!(bad.as_slice(), &[7], "the grid names the block");
                assert_eq!(*total_blocks, 50000_usize.div_ceil(4096));
                assert_eq!(
                    *md5_ok, None,
                    "no whole-file digest was recorded, so none is reported on"
                );
            }
            other => panic!("expected Damaged, got {other:?}"),
        }

        // And a payload file that goes missing is still damage.
        std::fs::remove_file(dir.join("Movie.mkv")).unwrap();
        assert!(!back.verify(&dir).unwrap().all_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The two families the grid pass deliberately does NOT hash, and
    /// the reason is the same for both: something may legitimately take
    /// them later, and an entry with a grid reports its own absence as
    /// damage.
    ///
    /// A `.par2` still on disk (cleanup off) is what the cleanup DEFAULT
    /// deletes. A leftover archive volume is what the spent-volume sweep
    /// and a later retry take. Hashing either would turn a normal
    /// deletion into a damage report - the exact false-positive the
    /// `source` role and [`is_consumable_source`] exist to prevent, and
    /// the grid pass has to honour the same rule or it reintroduces it
    /// in a new place.
    #[test]
    fn the_grid_pass_leaves_recovery_and_archive_material_alone() {
        let dir = temp_dir("grid-skips");
        let payload = body(9000, 71);
        std::fs::write(dir.join("payload.bin"), &payload).unwrap();
        // Uncovered, on disk, and both consumable.
        std::fs::write(dir.join("spare.par2"), b"PAR2\0PKTjunk-but-real-magic").unwrap();
        let mut rar = b"Rar!\x1a\x07\x01\x00".to_vec();
        rar.extend_from_slice(&body(4000, 72));
        std::fs::write(dir.join("leftover.part2.rar"), &rar).unwrap();
        let set = set_over(&[("payload.bin", &payload)], 4096);
        let mut m = Manifest::from_set(&set, "Sk.Job", "sk", false);
        m.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        let par2 = back.files.iter().find(|e| e.name == "spare.par2").unwrap();
        assert_eq!(par2.role, Role::Source, "recovery data stays a source");
        assert!(par2.crc32s.is_empty(), "and is not hashed");
        let vol = back
            .files
            .iter()
            .find(|e| e.name == "leftover.part2.rar")
            .unwrap();
        assert_eq!(vol.role, Role::Presence, "archive material stays presence");
        assert!(vol.crc32s.is_empty(), "and is not hashed");
        // Both gone is the normal end state, not damage.
        std::fs::remove_file(dir.join("spare.par2")).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(
            report
                .files
                .iter()
                .any(|(n, s)| n == "leftover.part2.rar" && *s == FileStatus::PresentUnverified),
            "{report:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A shared season folder: episode two's write must carry episode
    /// one's hashed-from-disk grid forward, exactly as it carries a
    /// covered entry's.
    ///
    /// Carry-forward matches by (name, length) and clones the entry
    /// whole, so this holds for free - but "for free" is what stops
    /// being true the day someone rebuilds the unclaimed arm, and a
    /// season folder silently downgrading last week's episode to
    /// presence is precisely the failure carry-forward exists to
    /// prevent.
    #[test]
    fn a_hashed_extracted_entry_is_carried_forward_by_the_next_episode() {
        let dir = temp_dir("carry-grid");
        let e1 = body(30000, 11);
        std::fs::write(dir.join("Show.S01E01.mkv"), &e1).unwrap();
        let vol1 = body(8192, 12);
        let mut m1 = Manifest::from_set(
            &set_over(&[("e01.part1.rar", &vol1)], 4096),
            "Show.S01E01",
            "sha-one",
            true,
        );
        m1.write_reconciled(&dir).unwrap();

        // Episode two settles into the same directory.
        let e2 = body(31000, 13);
        std::fs::write(dir.join("Show.S01E02.mkv"), &e2).unwrap();
        let vol2 = body(8192, 14);
        let mut m2 = Manifest::from_set(
            &set_over(&[("e02.part1.rar", &vol2)], 4096),
            "Show.S01E02",
            "sha-two",
            true,
        );
        m2.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        let one = back
            .files
            .iter()
            .find(|e| e.name == "Show.S01E01.mkv")
            .unwrap();
        assert_eq!(one.role, Role::Payload);
        assert!(!one.crc32s.is_empty(), "episode one keeps its grid");
        assert_eq!(
            (one.job.as_str(), one.nzb_sha.as_str()),
            ("Show.S01E01", "sha-one"),
            "and its own provenance, which is the post a heal re-fetches"
        );
        let two = back
            .files
            .iter()
            .find(|e| e.name == "Show.S01E02.mkv")
            .unwrap();
        assert_eq!(
            (two.job.as_str(), two.nzb_sha.as_str()),
            ("Show.S01E02", "sha-two")
        );
        // Rot episode ONE and the folder is damaged, on episode one's
        // grid, written a job ago.
        let mut rotted = e1.clone();
        rotted[19] ^= 0x11;
        std::fs::write(dir.join("Show.S01E01.mkv"), &rotted).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(!report.all_ok(), "{report:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A manifest written before the grid pass existed - a presence
    /// entry with neither digest nor grid - still reads as
    /// `PresentUnverified` rather than as damage.
    ///
    /// The format did not change and was not versioned up for this: the
    /// per-entry fields were already optional, so an OLD binary reading
    /// a NEW manifest sees a grid it does not consult and answers
    /// `PresentUnverified`, and this is the mirror direction. A new
    /// binary that convicted an old presence entry would report every
    /// library written before today as damaged.
    #[test]
    fn an_old_presence_entry_is_still_present_unverified() {
        let dir = temp_dir("old-presence");
        std::fs::write(dir.join("Movie.mkv"), body(5000, 21)).unwrap();
        std::fs::write(
            dir.join(MANIFEST_NAME),
            r#"{"v":1,"created":1,"nzb_sha":"old","job":"Old.Job","block_size":4096,
                "files":[{"n":"Movie.mkv","l":5000,"r":"presence"}]}"#,
        )
        .unwrap();
        let report = Manifest::load(&dir).unwrap().verify(&dir).unwrap();
        assert_eq!(
            report.files.as_slice(),
            &[("Movie.mkv".to_string(), FileStatus::PresentUnverified)]
        );
        assert!(report.all_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The measurement that chose the grid, and chose to hash at the
    /// manifest write rather than plumb digests out of the finalize
    /// move. Printed rather than asserted: it is a cost, and a timing
    /// assertion on a shared box is a flake.
    ///
    /// The decision-grade numbers are release-profile, on an M5 Max over
    /// 1 GiB in 1 MiB windows, and are recorded in [`grid_from_disk`]'s
    /// header: read 0.07 s/GiB, read+CRC32 0.11, read+SHA-256 0.43,
    /// read+MD5 1.49. The READ is 5% of the cost, which inverts the
    /// premise the TODO box was written on - riding the cross-device
    /// move's existing read would save the cheap half through four
    /// modules of plumbing and leave same-device owing the whole pass.
    /// This test prints the same two ratios from whatever profile it
    /// runs under, so a change that makes the grid pass expensive shows
    /// up as a number a reader can act on.
    #[test]
    fn hashing_extracted_output_is_a_read_and_not_a_hash() {
        let dir = temp_dir("grid-cost");
        // 16 MiB of extracted output, the shape a film has and the size
        // a test can afford.
        let film = body(16 << 20, 42);
        std::fs::write(dir.join("Movie.mkv"), &film).unwrap();
        let vol = body(8192, 43);
        let set = set_over(&[("set.part1.rar", &vol)], 1 << 18);

        let t0 = std::time::Instant::now();
        let mut m = Manifest::from_set(&set, "Cost.Job", "c0st", true);
        m.write_reconciled(&dir).unwrap();
        let grid_ms = t0.elapsed().as_secs_f64() * 1000.0;

        // The arm that was on the table: the same pass with a
        // whole-file MD5 over the same bytes.
        let t1 = std::time::Instant::now();
        let mut h = Md5::new();
        h.update(&film);
        let _ = h.finalize();
        let md5_ms = t1.elapsed().as_secs_f64() * 1000.0;

        let back = Manifest::load(&dir).unwrap();
        let film_e = back.files.iter().find(|e| e.name == "Movie.mkv").unwrap();
        assert!(!film_e.crc32s.is_empty(), "the film really was hashed");
        assert!(
            film_e.crc32s.len() as u64 <= MAX_GRID_BLOCKS,
            "the grid is capped, so the manifest cannot run away"
        );
        println!(
            "A/B extracted-output hashing, 16 MiB film: grid write {grid_ms:.1} ms              (read + CRC32, whole manifest pass) vs whole-file MD5 alone {md5_ms:.1} ms              over bytes already in memory. Release, 1 GiB, M5 Max: read 0.07 s/GiB,              read+CRC32 0.11, read+SHA-256 0.43, read+MD5 1.49 - so the read is 5%              of the cost and the hash is all of it. DEFAULT: ON for both the              same-device and cross-device finalize paths, no setting."
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A MIXED archive set: the PAR2 covers RAR volumes AND a loose
    /// companion the poster put beside them, both still on disk.
    ///
    /// `from_sets` gets ONE post-wide `archive` boolean - the
    /// extractor's latched shape - so before this was fixed the `.srt`
    /// was written `source` along with the volume. `Source` means "gone
    /// later is normal": `verify` maps a gone source to `SourceGone`
    /// and `all_ok` ACCEPTS `SourceGone`, so deleting the subtitle left
    /// the integrity feature certifying a damaged directory as clean.
    /// The reconcile now re-judges every entry it finds ON DISK against
    /// the file itself - the volume stays `source`, the companion goes
    /// back to `payload` - and the shape that would reintroduce it is
    /// trusting the flag in the two arms that matched a file.
    #[test]
    fn a_covered_companion_on_disk_is_payload_even_in_an_archive_post() {
        let dir = temp_dir("mixed");
        let vol = body(8192, 31);
        let srt = body(2000, 32);
        std::fs::write(dir.join("set.part1.rar"), &vol).unwrap();
        std::fs::write(dir.join("Movie.srt"), &srt).unwrap();
        let set = set_over(&[("set.part1.rar", &vol), ("Movie.srt", &srt)], 4096);
        let mut m = Manifest::from_set(&set, "Mx.Job", "m1", true);
        m.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        let rar = back
            .files
            .iter()
            .find(|e| e.name == "set.part1.rar")
            .unwrap();
        assert_eq!(
            rar.role,
            Role::Source,
            "a volume the tail will consume stays a source"
        );
        let sub = back.files.iter().find(|e| e.name == "Movie.srt").unwrap();
        assert_eq!(
            sub.role,
            Role::Payload,
            "a loose covered companion is payload, whatever the post's shape"
        );
        assert!(back.verify(&dir).unwrap().all_ok());

        // The whole point: losing the companion is DAMAGE, and before
        // the fix this reported clean.
        std::fs::remove_file(dir.join("Movie.srt")).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(
            !report.all_ok(),
            "deleting a covered companion must not certify as clean: {report:?}"
        );
        assert!(
            report
                .files
                .iter()
                .any(|(n, s)| n == "Movie.srt" && *s == FileStatus::Missing)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The caveat the demotion above would otherwise open, closed in the
    /// same edit. `looks_like_named_rar` is a RAR grammar, so a 7z or
    /// zip volume still on disk would be demoted to `payload` and would
    /// then report `Missing` the day the sweep took it - the mirror
    /// image of the defect, in the archive families nobody was looking
    /// at. `is_consumable_source` therefore asks the 7z and zip
    /// predicates too, which is a suffix and magic test rather than new
    /// plumbing.
    ///
    /// Part 2 of a split 7z set is the case that needs the NAME: only
    /// part 1 carries the `7z\xbc\xaf'\x1c` magic, so a magic-only
    /// arm calls every later part payload.
    #[test]
    fn seven_zip_and_zip_volumes_on_disk_stay_sources() {
        let dir = temp_dir("mixedvols");
        let sevenz_head = {
            let mut v = vec![0x37u8, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
            v.extend(body(4000, 41));
            v
        };
        let sevenz_tail = body(4000, 42);
        let zipvol = body(4000, 43);
        let srt = body(900, 44);
        std::fs::write(dir.join("pack.7z.001"), &sevenz_head).unwrap();
        std::fs::write(dir.join("pack.7z.002"), &sevenz_tail).unwrap();
        std::fs::write(dir.join("span.z01"), &zipvol).unwrap();
        std::fs::write(dir.join("Show.srt"), &srt).unwrap();
        let set = set_over(
            &[
                ("pack.7z.001", &sevenz_head),
                ("pack.7z.002", &sevenz_tail),
                ("span.z01", &zipvol),
                ("Show.srt", &srt),
            ],
            4096,
        );
        let mut m = Manifest::from_set(&set, "Vz.Job", "v9", true);
        m.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        for name in ["pack.7z.001", "pack.7z.002", "span.z01"] {
            let e = back.files.iter().find(|e| e.name == name).unwrap();
            assert_eq!(e.role, Role::Source, "{name} is archive material");
        }
        let sub = back.files.iter().find(|e| e.name == "Show.srt").unwrap();
        assert_eq!(sub.role, Role::Payload);
        assert!(back.verify(&dir).unwrap().all_ok());

        // The sweep takes the volumes. Not damage.
        for name in ["pack.7z.001", "pack.7z.002", "span.z01"] {
            std::fs::remove_file(dir.join(name)).unwrap();
        }
        let report = back.verify(&dir).unwrap();
        assert!(report.all_ok(), "{report:?}");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A TV-filed job's `out_dir` is the SHARED season folder claimed by
    /// every episode in it (`Job::filed`), so the second episode to
    /// settle finds the first one's manifest already there.
    ///
    /// Before carry-forward, episode 2's write demoted episode 1 to a
    /// presence entry - name and length, no checksum - so a season
    /// folder kept only the LAST episode's proof and every earlier one
    /// was silently downgraded by its successor. That is the whole
    /// feature failing in exactly the directory shape a library is made
    /// of. Both must still be convictable, and at their OWN block sizes:
    /// two PAR2 sets choose independently, and judging a carried grid at
    /// the wrong stride calls an intact file damaged in every block.
    #[test]
    fn a_shared_season_folder_keeps_every_episode_it_has_proved() {
        let dir = temp_dir("season");
        let ep1 = body(20000, 11);
        let ep2 = body(30000, 12);
        std::fs::write(dir.join("S01E01.mkv"), &ep1).unwrap();
        let mut m1 =
            Manifest::from_set(&set_over(&[("S01E01.mkv", &ep1)], 1024), "Ep1", "s1", false);
        m1.write_reconciled(&dir).unwrap();

        // Episode 2 settles into the same folder, from a set cut at a
        // different block size.
        std::fs::write(dir.join("S01E02.mkv"), &ep2).unwrap();
        let mut m2 =
            Manifest::from_set(&set_over(&[("S01E02.mkv", &ep2)], 4096), "Ep2", "s2", false);
        m2.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        let e1 = back.files.iter().find(|e| e.name == "S01E01.mkv").unwrap();
        assert_eq!(
            e1.role,
            Role::Payload,
            "episode 1 is not demoted to presence"
        );
        assert_eq!(e1.bs, 1024, "and keeps the stride its own set was cut at");
        assert_eq!(e1.crc32s.len(), 20, "its grid survived intact");
        assert_eq!(e1.job, "Ep1", "with the provenance a heal would re-hunt on");
        assert_eq!(e1.nzb_sha, "s1");
        let e2 = back.files.iter().find(|e| e.name == "S01E02.mkv").unwrap();
        assert_eq!(e2.bs, 4096);
        assert_eq!(e2.job, "Ep2");
        assert!(back.verify(&dir).unwrap().all_ok());

        // And episode 1 is still convictable, which is the point.
        let mut bad = ep1.clone();
        bad[3 * 1024 + 5] ^= 0x11;
        std::fs::write(dir.join("S01E01.mkv"), &bad).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(!report.all_ok());
        let (_, status) = report
            .files
            .iter()
            .find(|(n, _)| n == "S01E01.mkv")
            .unwrap();
        match status {
            FileStatus::Damaged { bad, .. } => assert_eq!(bad.as_slice(), &[3]),
            other => panic!("expected Damaged, got {other:?}"),
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A `.par2` still on disk at write time - the user has cleanup off -
    /// is a recovery file, not payload. Recorded as a presence entry it
    /// would report `Missing` the day cleanup runs, which is a false
    /// damage report in the one situation this module exists to serve.
    /// It is recorded [`Role::Source`] instead: verifiable while it is
    /// here, unremarkable once it is not. By magic as well as by
    /// extension, because an obfuscated recovery volume has no
    /// extension to read.
    #[test]
    fn recovery_files_left_on_disk_are_sources_not_future_damage() {
        let dir = temp_dir("par2left");
        let a = body(9000, 21);
        std::fs::write(dir.join("payload.bin"), &a).unwrap();
        std::fs::write(dir.join("testset.par2"), b"PAR2\0PKTnot really, but named").unwrap();
        std::fs::write(dir.join("0a1b2c3d4e"), b"PAR2\0PKTobfuscated volume").unwrap();
        let mut m = Manifest::from_set(
            &set_over(&[("payload.bin", &a)], 4096),
            "P.Job",
            "p2",
            false,
        );
        m.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        for name in ["testset.par2", "0a1b2c3d4e"] {
            let e = back.files.iter().find(|e| e.name == name).unwrap();
            assert_eq!(e.role, Role::Source, "{name} is a recovery file");
        }
        assert!(back.verify(&dir).unwrap().all_ok());

        // Cleanup runs. Nothing about that is damage.
        std::fs::remove_file(dir.join("testset.par2")).unwrap();
        std::fs::remove_file(dir.join("0a1b2c3d4e")).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(report.all_ok(), "{report:?}");
        assert!(
            report
                .files
                .iter()
                .any(|(n, s)| n == "testset.par2" && *s == FileStatus::SourceGone)
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Matrix row M4-90's residue in this module: a companion whose NAME
    /// says payload is [`Role::Payload`] however its first bytes read.
    ///
    /// `is_consumable_source`'s 7z arm was guarded by `is_final_file`,
    /// which knows only `.cbr`/`.cb7`, so a `Show.srt` carrying the 7z
    /// signature answered `sevenz_archive_part` on magic alone and was
    /// stamped `Source`. Its later absence then mapped to `SourceGone`,
    /// which `all_ok` ACCEPTS - the exact certified-clean-companion
    /// defect `demote_if_payload_on_disk` exists to fix, in the one
    /// family it had not reached. 4fabb3ff8 had already taught every
    /// consumer to decline such a file, so nothing would ever have spent
    /// it: the manifest was making a promise about a deletion that
    /// cannot happen.
    ///
    /// The real `.7z` beside it is the control and must stay `Source`,
    /// because narrowing this arm until it denies genuine packaging is
    /// the mirror-image defect - a volume the sweep really does take,
    /// reported `Missing` forever after.
    #[test]
    fn a_payload_named_companion_is_never_a_consumable_source() {
        let dir = temp_dir("m490srt");
        let sevenz = |seed: u8, len: usize| {
            let mut v = vec![0x37u8, 0x7A, 0xBC, 0xAF, 0x27, 0x1C];
            v.extend(body(len, seed));
            v
        };
        let pack = sevenz(51, 4000);
        // A subtitle whose head happens to read as 7z. The name is the
        // evidence; the magic is not.
        let srt = sevenz(52, 900);
        std::fs::write(dir.join("pack.7z"), &pack).unwrap();
        std::fs::write(dir.join("Show.srt"), &srt).unwrap();
        let set = set_over(&[("pack.7z", &pack), ("Show.srt", &srt)], 4096);
        let mut m = Manifest::from_set(&set, "M490.Job", "m490", true);
        m.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        let sub = back.files.iter().find(|e| e.name == "Show.srt").unwrap();
        assert_eq!(sub.role, Role::Payload, "a payload NAME is not packaging");
        let pk = back.files.iter().find(|e| e.name == "pack.7z").unwrap();
        assert_eq!(pk.role, Role::Source, "a named .7z is still packaging");
        assert!(back.verify(&dir).unwrap().all_ok());

        // The sweep may take the container. Not damage.
        std::fs::remove_file(dir.join("pack.7z")).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(report.all_ok(), "{report:?}");

        // Losing the subtitle is. Nothing sweeps it, so its absence is
        // damage and must be reported as such.
        std::fs::remove_file(dir.join("Show.srt")).unwrap();
        let report = back.verify(&dir).unwrap();
        assert!(!report.all_ok(), "{report:?}");
        assert!(
            report
                .files
                .iter()
                .any(|(n, s)| n == "Show.srt" && *s == FileStatus::Missing),
            "{report:?}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rename rematch over the shape that makes it expensive: a set
    /// of SAME-LENGTH volumes, every one renamed by the tail, so length
    /// alone separates nothing and only the head hash can. Each
    /// candidate's head is hashed once (see `HeadCache`) rather than
    /// once per (entry, candidate) pair, which is the difference between
    /// N and N squared reads. Correctness is what is asserted here; the
    /// memo is what keeps it affordable.
    #[test]
    fn same_length_volumes_all_renamed_still_match_one_to_one() {
        let dir = temp_dir("volset");
        let bodies: Vec<Vec<u8>> = (0..8).map(|i| body(8192, 40 + i as u8)).collect();
        for (i, b) in bodies.iter().enumerate() {
            std::fs::write(dir.join(format!("Feature.part{i}.rar")), b).unwrap();
        }
        let refs: Vec<(String, &[u8])> = bodies
            .iter()
            .enumerate()
            .map(|(i, b)| (format!("obf{i:04}"), b.as_slice()))
            .collect();
        let borrowed: Vec<(&str, &[u8])> = refs.iter().map(|(n, b)| (n.as_str(), *b)).collect();
        let mut m = Manifest::from_set(&set_over(&borrowed, 4096), "V.Job", "v1", false);
        m.write_reconciled(&dir).unwrap();

        let back = Manifest::load(&dir).unwrap();
        let mut names: Vec<&str> = back.files.iter().map(|e| e.name.as_str()).collect();
        names.sort_unstable();
        let want: Vec<String> = (0..8).map(|i| format!("Feature.part{i}.rar")).collect();
        assert_eq!(names, want.iter().map(String::as_str).collect::<Vec<_>>());
        assert!(
            back.files.iter().all(|e| e.role == Role::Payload),
            "every volume was matched, none written off as consumed"
        );
        // One-to-one: each entry must hold the CRC grid of the body it
        // was actually matched to, so a mismatched pairing convicts.
        assert!(back.verify(&dir).unwrap().all_ok());
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Truncation is caught by length before any byte is read, and a
    /// file the manifest never saw is reported as an extra rather than
    /// silently ignored.
    #[test]
    fn truncation_and_extras_are_both_reported() {
        let dir = temp_dir("trunc");
        let a = body(10000, 6);
        std::fs::write(dir.join("a.bin"), &a).unwrap();
        let set = set_over(&[("a.bin", &a)], 4096);
        let mut m = Manifest::from_set(&set, "Tr.Job", "aa55", false);
        m.write_reconciled(&dir).unwrap();
        std::fs::write(dir.join("a.bin"), &a[..9000]).unwrap();
        std::fs::write(dir.join("later-addition.srt"), b"subs").unwrap();
        let report = Manifest::load(&dir).unwrap().verify(&dir).unwrap();
        assert!(matches!(
            report.files[0].1,
            FileStatus::SizeMismatch { found: 9000 }
        ));
        assert_eq!(report.extras, vec!["later-addition.srt".to_string()]);
        let _ = std::fs::remove_dir_all(&dir);
    }
}
