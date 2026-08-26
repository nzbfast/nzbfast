//! The ZIP chase (top-level and nested): attach, the worker that
//! drives the zip reader over arriving bytes, the blocking Source
//! views it reads through, and the split-set (.z01/.zip) declarations.
//!
//! Split out of the 19,920-line `extract.rs` under the TODO 43
//! recipe: a verbatim move, not a redesign.

use super::*;
use crate::sync::MutexExt;

/// Tail window the zip attach front-loads: the EOCD scan window (22-byte
/// record + up to 64 KiB of comment = 65 557) plus the Zip64 locator (20)
/// and end record (56+), rounded up to 128 KiB so a typical central
/// directory (46 bytes + name per entry, so ~1000+ entries) arrives in
/// the same promote. A directory that starts below the window is
/// promoted separately once the EOCD says where it begins.
pub(super) const ZIP_TAIL_PREFETCH: u64 = 128 * 1024;

/// Blocking [`crate::zip::Source`] over a chased zip container - the
/// view the zip worker parses the directory through. Reads block until
/// the requested bytes arrive (the EOCD/central-directory reads block
/// only until the promoted tail lands). Each read publishes the chase's
/// drop-behind watermark, exactly like [`ChainedSeekReader`]: after the
/// directory parse the worker's reads ascend (entries stream in
/// local-offset order), so bytes behind the last read are never asked
/// for again.
pub(super) struct BlockingZipSource {
    pub(super) set: Arc<SevenZSet>,
    pub(super) low_water: Arc<AtomicU64>,
}

impl crate::zip::Source for BlockingZipSource {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), crate::zip::ZipError> {
        let mut done = 0usize;
        while done < buf.len() {
            let at = off + done as u64;
            let n = self
                .set
                .read_blocking(at, &mut buf[done..])
                .map_err(crate::zip::ZipError::Io)?;
            if n == 0 {
                return Err(crate::zip::ZipError::Malformed(
                    "read past end of container",
                ));
            }
            done += n;
            self.low_water.store(at + n as u64, Ordering::Relaxed);
        }
        Ok(())
    }

    fn total(&self) -> u64 {
        self.set.total()
    }
}

/// A read-only view of a [`BlockingZipSource`] that does NOT publish a
/// drop-behind watermark.
///
/// `entry_crypto` resolves an entry's crypto framing before its body is
/// streamed, and for WinZip-AE that means reading the authentication
/// code at `end - 10` - ABOVE the body about to be read. Through the
/// plain source that stored `low_water = end`, so between the crypto
/// resolve and the first body read (which republishes the correct, much
/// lower value) an arriving span could compute a drop-behind trim from
/// the forward-jumped mark and cut above the worker's next read offset.
/// The chase then failed "read behind the trim point" and the container
/// demoted to disk - byte-exact, never corruption, but the one-pass win
/// forfeited on exactly the large encrypted archive drop-behind exists
/// for. `SevenZCtl::arm_trim` resets low_water to 0 to avoid precisely
/// this hazard in the 7z open phase, with a named regression test.
///
/// Leaving the mark where the previous entry left it is conservative:
/// lower can only mean trimming less.
pub(super) struct QuietZipSource<'a>(&'a BlockingZipSource);

impl crate::zip::Source for QuietZipSource<'_> {
    fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), crate::zip::ZipError> {
        let mut done = 0usize;
        while done < buf.len() {
            let n = self
                .0
                .set
                .read_blocking(off + done as u64, &mut buf[done..])
                .map_err(crate::zip::ZipError::Io)?;
            if n == 0 {
                return Err(crate::zip::ZipError::Malformed(
                    "read past end of container",
                ));
            }
            done += n;
        }
        Ok(())
    }

    fn total(&self) -> u64 {
        self.0.set.total()
    }
}

/// Bounded blocking `io::Read` over a chased zip entry's data range, so
/// a decoder can never run past the entry it was given (the chase twin
/// of zip.rs's `RangeReader`).
pub(super) struct BlockingRangeReader<'a> {
    pub(super) src: &'a BlockingZipSource,
    pub(super) pos: u64,
    pub(super) end: u64,
}

impl io::Read for BlockingRangeReader<'_> {
    fn read(&mut self, buf: &mut [u8]) -> io::Result<usize> {
        let left = self.end.saturating_sub(self.pos);
        if left == 0 || buf.is_empty() {
            return Ok(0);
        }
        let take = crate::disk::chunk_len(left, buf.len());
        let n = self.src.set.read_blocking(self.pos, &mut buf[..take])?;
        if n == 0 {
            return Err(io::Error::new(
                io::ErrorKind::UnexpectedEof,
                "zip entry data runs past the end of the container",
            ));
        }
        self.pos += n as u64;
        self.src.low_water.store(self.pos, Ordering::Relaxed);
        Ok(n)
    }
}

impl Extractor {
    /// One-pass zip (phase 2): attach a POSTED single-file zip to the
    /// container chase. The central directory is the last thing in a
    /// zip (behind at most a 64 KiB comment), so the slot joins a
    /// one-part set whose tail promote front-loads the directory window,
    /// and the zip worker parses it and streams each store/deflate entry
    /// into a child slot as its bytes arrive - the same seam, budget,
    /// trim and demote ladder as the 7z chase, driven by a different
    /// parser (see [`ChaseFormat`]).
    ///
    /// Runs at depth > 0 too (the zip twin of TODO 37 step 1 and the
    /// RAR chase lift): a zip INSIDE a store RAR attaches through the
    /// child extractor's own sniff and streams its entries a level
    /// deeper. Nothing about the engine is depth-specific - the
    /// `SevenZSet`/`ChaseSink` machinery below is shared with the 7z
    /// chase, which has run nested from the start.
    ///
    /// Returns false when ineligible - the slot then classifies Plain
    /// and materializes for the disk post-pass exactly as phase 1 left
    /// it. Eligibility carries phase 0's naming rules into the stream:
    /// a `.cbz`/`.epub` never attaches, a NAMED non-zip is never
    /// magic-sniffed, and multi-part shapes wait for the disk pass
    /// (see `zip::chase_eligible_name`).
    pub(super) fn try_attach_zip(
        &self,
        inner: &mut Inner,
        slot: usize,
        data: &[u8],
    ) -> io::Result<bool> {
        // Any depth (the depth-0-only v1 guard was scope, not
        // mechanism): a zip inside a store RAR chases like nested RAR
        // and 7z already do. `top_zip_on` is the TOP-LEVEL kill switch
        // and gates depth 0 only, mirroring `top_chase_on` and
        // `top_sevenz_on`; `nested_zip_on` is the zip twin of
        // `sevenz_on`, so the two gate families stay symmetric. The
        // depth ceiling needs no check either: a child AT
        // `nested_max_depth` is created disabled and classifies
        // everything Plain before any attach runs (see `ensure_child`),
        // and a resumed run is disabled wholesale the same way.
        if (self.depth == 0 && !inner.top_zip_on)
            || !inner.nested_on
            || !inner.nested_zip_on
            || inner.protect_sources
            || inner.slots[slot].size == 0
            || inner.self_weak.upgrade().is_none()
        {
            return Ok(false);
        }
        let size = inner.slots[slot].size;
        // A byte-split part (`name.zip.001`, or bare-numeric
        // `movie.001`): the cut is arbitrary, so only part 1 has a
        // signature to sniff and the CALLER's declaration is what
        // identifies the set and its part count - see
        // `declare_zip_split`. At depth 0 that caller is `get`, reading
        // the NZB file list; at depth > 0 it is the PARENT level, which
        // opens the set as it routes the first sibling and counts it
        // once the outer archive's entry list has run past the
        // siblings (§94 D, `zip_split.rs`) - until then the count is
        // `None` and the part joins on trust. Bare-numeric names are
        // speculative by nature (RAR numeric volumes share the
        // grammar), which the part-1 magic gate below already handles:
        // a declared set whose first part is not a zip forfeits, and
        // anything carrying RAR or 7z magic classified before this arm
        // was consulted.
        if let Some((base, idx)) = crate::zip::split_part_name(&inner.slots[slot].name)
            .or_else(|| crate::zip::numeric_split_part_name(&inner.slots[slot].name))
        {
            let Some(&decl) = inner.zip_split_decl.get(&base) else {
                return Ok(false);
            };
            if let Some(n) = decl
                && idx > n
            {
                return Ok(false);
            }
            if idx == 1 && !data.starts_with(b"PK\x03\x04") {
                // The declared set's first part is not a zip after all
                // (a RAR numeric volume in a `.zip.001` costume, say).
                // Forfeit whatever joined on trust and stop later parts
                // joining; this slot classifies Plain, exactly as if
                // nothing had been declared.
                if let Some(c) = inner.sevenz_sets.get(&base).cloned() {
                    self.sevenz_fallback_set(inner, &c, "zip split part 1 is not a zip")?;
                }
                inner.zip_split_decl.remove(&base);
                return Ok(false);
            }
            let ctl = match inner.sevenz_sets.get(&base) {
                Some(c) => c.clone(),
                None => {
                    let c = Arc::new(SevenZCtl::pending(base.clone()));
                    inner.sevenz_sets.insert(base.clone(), c.clone());
                    c
                }
            };
            inner.slots[slot].container_fmt = ChaseFormat::Zip;
            let joined = self.sevenz_join_set(inner, slot, ctl.clone(), idx)?;
            if !joined {
                return Ok(false);
            }
            if let Some(n) = decl {
                self.zip_try_resolve(inner, &ctl, n)?;
            }
            if idx == 1 {
                // Part 1 spawns the worker, like the 7z split: reads
                // block until the set resolves (`wait_resolved_total`),
                // exactly as they block on bytes that have not arrived.
                self.zip_spawn_worker(inner, &ctl)?;
            }
            return Ok(true);
        }
        // Single container. 22 bytes is the smallest EOCD, i.e. the
        // smallest thing that can be a zip at all.
        if size < 22 {
            return Ok(false);
        }
        if !crate::zip::chase_eligible_name(&inner.slots[slot].name) {
            return Ok(false);
        }
        // Local-file-header magic only. The spanning markers (`PK00`,
        // `PK\x07\x08`) open the FIRST segment of a spanned set, whose
        // central directory lives in a different posted file - the disk
        // pass owns that shape.
        if !data.starts_with(b"PK\x03\x04") {
            return Ok(false);
        }
        let ctl = Arc::new(SevenZCtl {
            set: Arc::new(SevenZSet::new(size, size)),
            key: String::new(),
            archive_base: 0,
            low_water: Arc::new(AtomicU64::new(0)),
            tail: Mutex::new(None),
            trim_ok: std::sync::atomic::AtomicBool::new(false),
            worker: Mutex::new(None),
            sink_slots: Mutex::new(Vec::new()),
            outcome: Mutex::new(None),
        });
        // Front-load the directory window: EOCD scan window (22 + 64 KiB
        // comment) + Zip64 locator/record, rounded up so a typical
        // central directory rides along in the same promote. A directory
        // that starts below the window is promoted by the worker once
        // the EOCD says where it is.
        *ctl.tail.lock_ok() = Some((size.saturating_sub(ZIP_TAIL_PREFETCH), size));
        inner.slots[slot].container_fmt = ChaseFormat::Zip;
        let joined = self.sevenz_join_set(inner, slot, ctl.clone(), 1)?;
        if !joined {
            // Unreachable for a fresh one-part set (nothing to collide
            // with), kept for symmetry with the 7z attach.
            inner.slots[slot].container_fmt = ChaseFormat::SevenZ;
            return Ok(false);
        }
        self.zip_spawn_worker(inner, &ctl)?;
        Ok(true)
    }

    /// Resolve a declared zip split once every part has registered its
    /// decoded size: fix the geometry, then front-load the directory
    /// window - which could not be asked for earlier, because on a byte
    /// split nothing says where the container ENDS until the last
    /// part's size is in. Promotes are QUEUED (the caller holds the
    /// routing lock; see `pending_promote`). A set whose parts do not
    /// line up forfeits whole, like its 7z counterpart.
    pub(super) fn zip_try_resolve(
        &self,
        inner: &mut Inner,
        ctl: &Arc<SevenZCtl>,
        n: u32,
    ) -> io::Result<()> {
        if ctl.set.resolved() {
            return Ok(());
        }
        let Some((part_size, total)) = ctl.set.zip_geometry(n) else {
            return Ok(());
        };
        if part_size == 0 || !ctl.set.resolve(part_size, total) {
            return self.sevenz_fallback_set(inner, ctl, "zip split parts do not line up");
        }
        let tail = (total.saturating_sub(ZIP_TAIL_PREFETCH), total);
        *ctl.tail.lock_ok() = Some(tail);
        // Urgent, like every tail promote: the worker blocks on the
        // directory read until these land.
        for (s, ls, le) in ctl.set.map_range(tail.0, tail.1) {
            inner.pending_promote.push((s, vec![(ls, le)], true));
        }
        Ok(())
    }

    /// Spawn the zip chase worker for `ctl` (single container or split
    /// part 1) and store its handle where finish() joins it.
    pub(super) fn zip_spawn_worker(&self, inner: &Inner, ctl: &Arc<SevenZCtl>) -> io::Result<()> {
        let weak = inner.self_weak.clone();
        let ctl2 = ctl.clone();
        let handle = std::thread::Builder::new()
            .name("nzb-zip-chase".into())
            .spawn(move || Self::zip_worker(weak, ctl2))
            .map_err(io::Error::other)?;
        *ctl.worker.lock_ok() = Some(handle);
        Ok(())
    }

    /// The zip chase worker (one-pass zip, phase 2): parse the central
    /// directory through the blocking view (footer first, via the tail
    /// prefetch), then stream every entry into a fresh child slot in
    /// local-offset order - store entries as a straight copy, deflate
    /// through the same flate2 decoder the disk path trusts. The
    /// extractor is reached weakly so a cancelled job can drop; the
    /// outcome is recorded for finish() to act on. Every error wording
    /// here reaches the user through the demote reason, marked
    /// [`ZIP_DISK_FALLBACK_PREFIX`] at the demote site.
    pub(super) fn zip_worker(me: Weak<Extractor>, ctl: Arc<SevenZCtl>) {
        let result = Self::zip_run(&me, &ctl);
        let mut st = ctl.outcome.lock_ok();
        *st = Some(result);
    }

    /// The worker's engine drive. Declines - anything phase 1's disk
    /// reader would refuse (encrypted entries, methods beyond
    /// store/deflate, symlinks, spanned sets, empty archives) - error
    /// out BEFORE any entry streams, so the demote materializes a
    /// container the disk pass then fails with today's exact wording.
    /// CRC32 and declared size are enforced per entry, same as the disk
    /// reader: a mismatch demotes rather than publishing damaged bytes.
    pub(super) fn zip_run(me: &Weak<Extractor>, ctl: &SevenZCtl) -> Result<(), String> {
        use crate::zip;
        use std::io::{Read as _, Write as _};
        let src = BlockingZipSource {
            set: ctl.set.clone(),
            low_water: ctl.low_water.clone(),
        };
        // A single container resolves at attach; a declared split
        // resolves when its last part's decoded size registers - block
        // until then, exactly as reads block on unarrived bytes.
        let total = ctl.set.wait_resolved_total().map_err(|e| e.to_string())?;
        let dir = zip::find_central_directory(&src).map_err(|e| e.to_string())?;
        let cd = dir.at;
        // The resolve promoted the last ZIP_TAIL_PREFETCH bytes. A
        // directory starting below that window is front-loaded too -
        // without this the parse would wait for the natural (front-to-
        // back) arrival order to reach a tail-resident structure, i.e.
        // for nearly the whole download. Container offsets translate to
        // per-part slot ranges through the set, which is identity for a
        // single container.
        let window_start = total.saturating_sub(ZIP_TAIL_PREFETCH);
        if cd < window_start {
            let Some(ex) = me.upgrade() else {
                return Err("extractor dropped".to_string());
            };
            // Off-lock by construction: the worker holds no routing
            // lock, so the promote walk is safe to run directly (the
            // attach path, which does hold it, queues instead). Urgent:
            // this worker BLOCKS on the directory read, exactly the 7z
            // footer case. Container offsets translate to per-part slot
            // ranges through the set (identity for a single container).
            for (s, ls, le) in ctl.set.map_range(cd, window_start) {
                ex.promote_slot_spans(s, &[(ls, le)], true);
            }
        }
        let entries = zip::parse_central_directory(&src, &dir).map_err(|e| e.to_string())?;
        if entries.is_empty() {
            return Err("the zip archive contains no entries".to_string());
        }
        // Read the job's password HERE rather than at spawn: the tail
        // has just resolved, which is later, so a key that arrived
        // mid-download (daemon `set_password`) is still picked up.
        let password: Option<String> = {
            let Some(ex) = me.upgrade() else {
                return Err("extractor dropped".to_string());
            };
            let pw = ex.inner.lock_ok().password.clone();
            pw.map(|p| p.to_string())
        };
        for e in &entries {
            if e.is_symlink() {
                return Err(format!(
                    "entry {:?} is a symlink, which is not extracted",
                    e.name
                ));
            }
            if e.is_dir {
                continue;
            }
            // An encrypted entry with no key cannot be streamed OR
            // unpacked here; the demote hands the container to the disk
            // pass, which says the same thing with the same wording.
            if e.is_encrypted() && password.is_none() {
                return Err(format!(
                    "{} is password-protected and the job has no password",
                    e.name
                ));
            }
            // A WinZip AE entry stores 99 and the truth in its extra
            // field, so the method gate has to ask for the REAL one or
            // every AES zip declines as "unknown compression".
            let m = zip::real_method(e);
            if !zip::method_supported(m) {
                return Err(format!(
                    "{} uses {} compression, which is not built in",
                    e.name,
                    zip::method_name(m)
                ));
            }
            // Stored entries pack 1:1 - but an encrypted one's
            // `compressed_size` also carries its crypto framing (salt +
            // verifier + auth code, or the 12-byte ZipCrypto header),
            // so the comparison only holds for plaintext.
            if m == zip::METHOD_STORE
                && !e.is_encrypted()
                && e.compressed_size != e.uncompressed_size
            {
                // Named and quantified: the bare "stored entry sizes
                // disagree" this carried sent a reader hunting for a
                // desync in whichever entry they guessed at, and on a
                // 40-archive job it did not even say which container.
                return Err(format!(
                    "malformed zip ({} is stored, but its packed size {} and unpacked size {} disagree)",
                    e.name, e.compressed_size, e.uncompressed_size
                ));
            }
        }
        let mut files: Vec<&zip::Entry> = entries.iter().filter(|e| !e.is_dir).collect();
        if files.is_empty() {
            // Directory-only archives produce nothing; "unpacked
            // successfully" having produced nothing is the silent
            // success this codebase refuses everywhere else.
            return Err("the zip archive contains only directories".to_string());
        }
        // Ascending local offsets = the order the articles arrive in.
        files.sort_by_key(|e| e.local_offset());
        // Drop-behind is decided HERE, between the parse and the first
        // payload read (see arm_trim for why the order matters). Zip has
        // no BCJ2 analogue - a directory-driven read never revisits
        // bytes behind the frontier - so the trim is always safe to arm.
        ctl.arm_trim(false);
        let mut buf = vec![0u8; 64 * 1024];
        for e in files {
            let data_at = zip::entry_data_offset(&src, e).map_err(|err| err.to_string())?;
            let end = data_at
                .checked_add(e.compressed_size)
                .filter(|&v| v <= total)
                .ok_or_else(|| format!("{} runs past the end of the container", e.name))?;
            let Some(ex) = me.upgrade() else {
                return Err("extractor dropped".to_string());
            };
            // Same single-lock-hold discipline as the 7z sink: the
            // liveness check and the sink-slot registration must be
            // atomic against a demotion draining sink_slots, or the
            // fresh slot leaks a partial output.
            let (child, cslot) = {
                let mut g = ex.inner.lock_ok();
                let inner = &mut *g;
                let members = ctl.set.member_slots();
                if members.is_empty()
                    || !members
                        .iter()
                        .all(|&m| matches!(inner.slots[m].mode, SlotMode::SevenZ))
                {
                    return Err("zip chase demoted".to_string());
                }
                let child = ex.ensure_child(inner);
                let cslot = child.alloc_slot();
                ctl.sink_slots.lock_ok().push(cslot);
                (child, cslot)
            };
            let mut sink = ChaseSink {
                child,
                slot: cslot,
                name: e.name.clone(),
                size: e.uncompressed_size,
                pos: 0,
            };
            if e.uncompressed_size == 0 {
                // An explicit empty write is what creates the output
                // file - the copy loop below never calls the sink for
                // zero bytes, and the disk path does land empty files.
                sink.write(&[])
                    .map_err(|err| format!("writing {}: {err}", e.name))?;
            }
            // Crypto framing + password check, shared verbatim with the
            // disk reader (`zip::entry_crypto`). Plaintext entries get
            // `EntryCipher::None`, so there is one path, not two.
            // Through the quiet view: the AE authentication code lives at
            // `end - 10`, above the body we are about to stream, and
            // publishing a watermark there can strand the worker behind a
            // drop-behind trim. See `QuietZipSource`.
            let crypto =
                zip::entry_crypto(&QuietZipSource(&src), e, data_at, end, password.as_deref())
                    .map_err(|err| err.to_string())?;
            let mut rd_src = crypto.cipher.wrap(BlockingRangeReader {
                src: &src,
                pos: data_at + crypto.head,
                end: end - crypto.tail,
            });
            // One code path for both methods, like the disk reader:
            // store is the identity decoder, so the CRC/size accounting
            // cannot drift between them.
            let mut rd =
                zip::decoder(e, &mut rd_src).map_err(|err| format!("reading {}: {err}", e.name))?;
            let mut crc = crc32fast::Hasher::new();
            let mut written = 0u64;
            loop {
                let n = rd
                    .read(&mut buf)
                    .map_err(|err| format!("reading {}: {err}", e.name))?;
                if n == 0 {
                    break;
                }
                written += n as u64;
                if written > e.uncompressed_size {
                    return Err(format!("{} is longer than its declared size", e.name));
                }
                crc.update(&buf[..n]);
                sink.write_all(&buf[..n])
                    .map_err(|err| format!("writing {}: {err}", e.name))?;
            }
            // A deflate decoder stops at its own stream end, which can
            // leave an AE entry's HMAC (raised at the SOURCE's EOF)
            // unreached. Drain so authentication always runs before this
            // entry is called good - same reason, same fix, as the disk
            // reader.
            drop(rd);
            loop {
                let n = rd_src
                    .read(&mut buf)
                    .map_err(|err| format!("reading {}: {err}", e.name))?;
                if n == 0 {
                    break;
                }
            }
            if written != e.uncompressed_size {
                return Err(format!("{} is shorter than its declared size", e.name));
            }
            // AE-2 zeroes the CRC field BY SPEC - its HMAC, verified in
            // the drain above, is the integrity check. Comparing against
            // a stored zero would fail every AE-2 entry.
            let check_crc = zip::crc_is_authoritative(e);
            if check_crc && crc.finalize() != e.crc32 {
                return Err(format!(
                    "{} failed its stored CRC - the archive is damaged",
                    e.name
                ));
            }
        }
        Ok(())
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::extract::testutil::*;

    /// A posted store+deflate zip streams both entries out and the
    /// container never touches disk. Three feed orders, including the
    /// natural one where the central directory arrives dead last.
    #[test]
    fn zip_top_level_extracts_one_pass() {
        let a = payload(180_000, 130);
        let b = payload(60_000, 131);
        let arch = crate::zip::fixtures::zip_of(&[
            crate::zip::fixtures::Spec::stored("a.bin", &a),
            crate::zip::fixtures::Spec::deflated("b.bin", &b),
        ]);
        let art = 7000usize;
        let n_arts = arch.len().div_ceil(art);
        let orders: Vec<Vec<usize>> = vec![
            (0..n_arts).collect(),                               // tail last
            (0..n_arts).rev().collect(),                         // tail first
            (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(), // scrambled
        ];
        for (t, order) in orders.iter().enumerate() {
            let dir = tmpdir(&format!("zip-top-onepass{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            let mut seen = vec![false; n_arts];
            for &i in order {
                if std::mem::replace(&mut seen[i], true) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(arch.len());
                ex.write(0, "release.zip", arch.len() as u64, s as u64, &arch[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert!(
                rep.extracted
                    .iter()
                    .any(|(n, s)| n == "a.bin" && *s == a.len() as u64),
                "order {t}: {:?}",
                rep.extracted
            );
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
            assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b, "order {t}");
            // The point of the whole exercise: no materialized archive.
            assert_eq!(
                dir_files(&dir),
                vec!["a.bin".to_string(), "b.bin".to_string()],
                "order {t}"
            );
            assert_eq!(shape_of(&ex), ["zip", "one-pass"], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The root half of the zip tail-prefetch wiring: the posted `.zip`
    /// reaches the installed hook by its own name with the directory
    /// window, so the daemon front-loads the articles holding the EOCD
    /// and central directory.
    #[test]
    fn zip_top_level_tail_promote_reaches_the_root_hook() {
        let a = payload(200_000, 135);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let len = arch.len() as u64;
        let dir = tmpdir("zip-top-promote");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>)>>>;
        let calls: Calls = Default::default();
        let sink = calls.clone();
        ex.set_promote_hook(Arc::new(
            move |n: &str, s: u64, sp: &[(u64, u64)], _u: bool| {
                sink.lock().unwrap().push((n.to_string(), s, sp.to_vec()));
            },
        ));
        feed(&ex, 0, "release.zip", &arch, 6000, 55);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
        // A shuffled feed may raise the offset-0 probe first (lead span
        // (0, 1) - pinned by its own test); the subject here is the
        // directory-window promote.
        let mut got = calls.lock().unwrap().clone();
        got.retain(|(_, _, sp)| sp.first() != Some(&(0, 1)));
        assert_eq!(
            got.first(),
            Some(&(
                "release.zip".to_string(),
                len,
                vec![(len.saturating_sub(ZIP_TAIL_PREFETCH), len)]
            ))
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Entry names with directory components land FLAT (the established
    /// one-pass semantic - 7z and RAR inners do the same), directory
    /// entries produce nothing, and a zero-byte entry still lands as an
    /// empty file (the disk path lands one, so the stream must too).
    #[test]
    fn zip_entries_land_flat_and_empty_files_land() {
        let a = payload(50_000, 132);
        let arch = crate::zip::fixtures::zip_of(&[
            crate::zip::fixtures::Spec::stored("Pack/", b""),
            crate::zip::fixtures::Spec::stored("Pack/a.bin", &a),
            crate::zip::fixtures::Spec::stored("empty.txt", b""),
        ]);
        let dir = tmpdir("zip-top-flat");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 56);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("Pack_a.bin")).unwrap(), a);
        assert_eq!(std::fs::read(dir.join("empty.txt")).unwrap(), b"");
        assert_eq!(
            dir_files(&dir),
            vec!["Pack_a.bin".to_string(), "empty.txt".to_string()]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A method beyond store/deflate declines BEFORE anything streams:
    /// the container materializes byte-exact under the zip marker (with
    /// the method named in the reason), which is exactly the disk
    /// A method the tree cannot decode declines BEFORE anything streams,
    /// and the container lands byte-exact under the zip marker so the
    /// disk pass owns the outcome. zstd (93) stands in for the class now
    /// that bzip2 and lzma are decodable.
    #[test]
    fn zip_top_level_decline_materializes_under_the_zip_marker() {
        let data = payload(40_000, 135);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec {
            method: 93,
            ..crate::zip::fixtures::Spec::stored("a.bin", &data)
        }]);
        let dir = tmpdir("zip-top-decline");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 57);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(ZIP_DISK_FALLBACK_PREFIX) && w.contains("zstd")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.zip")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["release.zip".to_string()]);
        assert_eq!(shape_of(&ex), ["zip", "on-disk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// bzip2 (method 12) streams like any other. It used to FAIL the job
    /// outright - the chase declined it and the disk reader could not
    /// open one either - so this is a dead shape brought to life, not
    /// just a materialize avoided. Encrypted too, since the crypto layer
    /// and the method decoder are independent and their combination is
    /// where a wiring mistake would hide.
    #[test]
    fn zip_top_level_bzip2_extracts_one_pass() {
        use crate::zip::fixtures::{Encrypt, Spec};
        // Compressible on purpose: bzip2 on random bytes EXPANDS, and a
        // stored-size disagreement is a different failure than the one
        // under test.
        let data: Vec<u8> = (0..180_000u32).map(|i| (i / 977 % 251) as u8).collect();
        for (tag, enc) in [
            ("plain", None),
            ("zipcrypto", Some(Encrypt::ZipCrypto { password: "bz" })),
            (
                "ae",
                Some(Encrypt::Ae {
                    password: "bz",
                    strength: 3,
                    vendor_version: 2,
                }),
            ),
        ] {
            let arch = crate::zip::fixtures::zip_of(&[Spec {
                encrypt: enc,
                ..Spec::bzip2("a.bin", &data)
            }]);
            let dir = tmpdir(&format!("zip-bz-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            ex.set_password("bz");
            feed(&ex, 0, "release.zip", &arch, 7000, 62);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data, "{tag}");
            assert!(
                !dir.join("release.zip").exists(),
                "{tag}: container materialized"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// lzma (method 14) streams like bzip2 does - another dead shape
    /// brought to life, since neither the chase nor the disk reader
    /// could open one before. Encrypted too, for the same reason as the
    /// bzip2 twin: the crypto layer and the method decoder are
    /// independent and their combination is where a wiring mistake
    /// would hide.
    #[test]
    fn zip_top_level_lzma_extracts_one_pass() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data: Vec<u8> = (0..180_000u32).map(|i| (i / 977 % 251) as u8).collect();
        for (tag, enc) in [
            ("plain", None),
            ("zipcrypto", Some(Encrypt::ZipCrypto { password: "lz" })),
            (
                "ae",
                Some(Encrypt::Ae {
                    password: "lz",
                    strength: 3,
                    vendor_version: 2,
                }),
            ),
        ] {
            let arch = crate::zip::fixtures::zip_of(&[Spec {
                encrypt: enc,
                ..Spec::lzma("a.bin", &data)
            }]);
            let dir = tmpdir(&format!("zip-lzma-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            ex.set_password("lz");
            feed(&ex, 0, "release.zip", &arch, 7000, 62);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data, "{tag}");
            assert!(
                !dir.join("release.zip").exists(),
                "{tag}: container materialized"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Encrypted zip, IN STREAM. Both schemes and both AE vendor
    /// versions, store and deflate: the container must never touch disk
    /// and the payload must come out exact. AE-2 is the interesting one -
    /// it zeroes the CRC field by spec, so its HMAC (verified when the
    /// source drains, not when the decoder stops) is the only integrity
    /// check there is.
    #[test]
    fn zip_top_level_encrypted_extracts_one_pass() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data = payload(140_003, 151);
        let cases: Vec<(&str, Encrypt, bool)> = vec![
            (
                "zipcrypto-store",
                Encrypt::ZipCrypto { password: "zpw" },
                false,
            ),
            (
                "zipcrypto-deflate",
                Encrypt::ZipCrypto { password: "zpw" },
                true,
            ),
            (
                "ae1-256",
                Encrypt::Ae {
                    password: "zpw",
                    strength: 3,
                    vendor_version: 1,
                },
                false,
            ),
            (
                "ae2-256",
                Encrypt::Ae {
                    password: "zpw",
                    strength: 3,
                    vendor_version: 2,
                },
                false,
            ),
            (
                "ae2-128-deflate",
                Encrypt::Ae {
                    password: "zpw",
                    strength: 1,
                    vendor_version: 2,
                },
                true,
            ),
        ];
        for (tag, enc, deflate) in cases {
            let base = if deflate {
                Spec::deflated("a.bin", &data)
            } else {
                Spec::stored("a.bin", &data)
            };
            let arch = crate::zip::fixtures::zip_of(&[Spec {
                encrypt: Some(enc),
                ..base
            }]);
            let dir = tmpdir(&format!("zip-enc-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            ex.set_password("zpw");
            feed(&ex, 0, "release.zip", &arch, 7000, 58);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data, "{tag}");
            assert!(
                !dir.join("release.zip").exists(),
                "{tag}: container materialized"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// No password at all still declines to the disk pass, which says
    /// the same thing - streaming cannot invent a key either.
    #[test]
    fn zip_top_level_encrypted_without_a_password_declines() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data = payload(40_000, 136);
        let arch = crate::zip::fixtures::zip_of(&[Spec {
            encrypt: Some(Encrypt::ZipCrypto { password: "zpw" }),
            ..Spec::stored("a.bin", &data)
        }]);
        let dir = tmpdir("zip-top-enc-nopw");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 58);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| {
                w.starts_with(ZIP_DISK_FALLBACK_PREFIX) && w.contains("password-protected")
            }),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.zip")).unwrap(), arch);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A WRONG password must demote with the container byte-exact, not
    /// publish plausible-looking garbage. Both schemes: ZipCrypto's
    /// one-byte check catches it 255/256 of the time and the CRC catches
    /// the rest, AE's two-byte verifier then its HMAC.
    #[test]
    fn zip_top_level_encrypted_wrong_password_demotes() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data = payload(90_001, 152);
        for (tag, enc) in [
            (
                "zc",
                Encrypt::ZipCrypto {
                    password: "rightpw",
                },
            ),
            (
                "ae",
                Encrypt::Ae {
                    password: "rightpw",
                    strength: 3,
                    vendor_version: 2,
                },
            ),
        ] {
            let arch = crate::zip::fixtures::zip_of(&[Spec {
                encrypt: Some(enc),
                ..Spec::stored("a.bin", &data)
            }]);
            let dir = tmpdir(&format!("zip-enc-wrong-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            ex.set_password("wrongpw");
            feed(&ex, 0, "release.zip", &arch, 7000, 60);
            let rep = ex.finish().unwrap();
            assert!(
                rep.fallbacks
                    .iter()
                    .any(|(_, w)| w.starts_with(ZIP_DISK_FALLBACK_PREFIX)),
                "{tag}: {:?}",
                rep.fallbacks
            );
            assert_eq!(
                std::fs::read(dir.join("release.zip")).unwrap(),
                arch,
                "{tag}: container must stay byte-exact for the disk pass"
            );
            assert!(
                !dir.join("a.bin").exists(),
                "{tag}: wrong-key garbage published"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Tampered AE ciphertext with the RIGHT password: the HMAC is the
    /// only thing that can catch this on an AE-2 entry (its CRC field is
    /// zero by spec), and it must catch it before anything publishes.
    #[test]
    fn zip_top_level_ae_tampered_ciphertext_demotes() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data = payload(70_007, 153);
        let arch = crate::zip::fixtures::zip_of(&[Spec {
            encrypt: Some(Encrypt::Ae {
                password: "zpw",
                strength: 3,
                vendor_version: 2,
            }),
            tamper: true,
            ..Spec::stored("a.bin", &data)
        }]);
        let dir = tmpdir("zip-enc-tamper");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_password("zpw");
        feed(&ex, 0, "release.zip", &arch, 7000, 61);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(ZIP_DISK_FALLBACK_PREFIX)),
            "{:?}",
            rep.fallbacks
        );
        assert!(!dir.join("a.bin").exists(), "tampered bytes published");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Damaged-before-posting: a stored CRC that does not match the
    /// bytes demotes rather than publishing them - the same "never
    /// report success over damaged output" rule as everywhere else.
    #[test]
    fn zip_top_level_bad_crc_demotes() {
        let data = payload(50_000, 137);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec {
            crc_override: Some(0xDEAD_BEEF),
            ..crate::zip::fixtures::Spec::stored("a.bin", &data)
        }]);
        let dir = tmpdir("zip-top-crc");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 59);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(ZIP_DISK_FALLBACK_PREFIX)
                    && w.contains("failed its stored CRC")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.zip")).unwrap(), arch);
        assert!(!dir.join("a.bin").exists(), "partial zip output survived");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0's naming rules hold at the streaming layer: a `.cbz` (a
    /// zip container whose FILE is the deliverable) and a named non-zip
    /// that happens to start with `PK` are never attached and never
    /// badged - they land byte-exact, exactly as posted.
    #[test]
    fn zip_chase_never_takes_a_final_file_or_a_named_non_zip() {
        let data = payload(40_000, 138);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored(
            "page01.jpg",
            &data,
        )]);
        for name in ["comic.cbz", "payload.bin"] {
            let dir = tmpdir(&format!("zip-top-final-{}", name.replace('.', "_")));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            feed(&ex, 0, name, &arch, 7000, 60);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{name}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join(name)).unwrap(), arch, "{name}");
            assert_eq!(dir_files(&dir), vec![name.to_string()], "{name}");
            assert!(
                ex.archive_shape().is_none(),
                "{name} must not badge as packaging"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The top-level gate: NZBFAST_NO_TOP_ZIP=1 parses as off, and the
    /// runtime setter drives the same latch - with it off a posted .zip
    /// materializes for the disk post-pass exactly as phase 1 left it.
    /// The env PARSE is asserted on the pure helper for the same
    /// parallel-runner reason as `nested_disabled_by_env`.
    #[test]
    fn top_level_zip_disabled_by_env() {
        assert!(top_zip_env_off_value(Some("1")));
        assert!(!top_zip_env_off_value(Some("0")));
        assert!(!top_zip_env_off_value(None));

        let data = payload(50_000, 139);
        let arch =
            crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &data)]);
        let dir = tmpdir("zip-top-gate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        assert!(ex.inner.lock().unwrap().top_zip_on, "gate must default on");
        ex.set_top_level_zip(false);
        feed(&ex, 0, "release.zip", &arch, 7000, 61);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("release.zip")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["release.zip".to_string()]);
        assert_eq!(shape_of(&ex), ["zip", "on-disk"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A DECLARED `.zip.001` split set streams as one container: no
    /// part can size the set (the cut is arbitrary and only part 1 even
    /// has a signature), so the caller's NZB-derived declaration says
    /// when every part's decoded size is in and the geometry resolves.
    /// Feed orders include parts arriving backwards - nothing
    /// guarantees `.001` classifies first.
    #[test]
    fn zip_split_set_extracts_one_pass() {
        let a = payload(400_000, 150);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let parts = split_zip(&arch, 3);
        assert_eq!(parts.len(), 3, "fixture must really split");
        for (t, order) in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0]]
            .iter()
            .enumerate()
        {
            let dir = tmpdir(&format!("zip-split{t}"));
            let ex = Arc::new(Extractor::new(&dir, 3, true));
            ex.anchor();
            ex.declare_zip_split("release.zip", 3);
            for &p in order {
                feed(
                    &ex,
                    p,
                    &format!("release.zip.{:03}", p + 1),
                    &parts[p],
                    7000,
                    62 + t as u64,
                );
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
            assert_eq!(dir_files(&dir), vec!["a.bin".to_string()], "order {t}");
            assert_eq!(shape_of(&ex), ["zip", "one-pass"], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A declared part whose siblings never turn up: the set cannot
    /// resolve, so the part materializes byte-exact under the zip
    /// marker - exactly the disk post-pass's input.
    #[test]
    fn zip_split_part_without_its_siblings_materializes() {
        let a = payload(200_000, 151);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let parts = split_zip(&arch, 3);
        let dir = tmpdir("zip-split-missing");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.declare_zip_split("release.zip", 3);
        feed(&ex, 0, "release.zip.001", &parts[0], 7000, 63);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with(ZIP_DISK_FALLBACK_PREFIX)),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("release.zip.001")).unwrap(),
            parts[0]
        );
        assert_eq!(dir_files(&dir), vec!["release.zip.001".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// No declaration, no chase: parts of a set the caller did not (or
    /// could not - a hole in the NZB itself) declare classify Plain and
    /// land byte-exact, which is the phase-1 path verbatim.
    #[test]
    fn zip_split_undeclared_parts_never_chase() {
        let a = payload(150_000, 152);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let parts = split_zip(&arch, 2);
        let dir = tmpdir("zip-split-undeclared");
        let ex = Arc::new(Extractor::new(&dir, 2, true));
        ex.anchor();
        for (i, p) in parts.iter().enumerate() {
            feed(&ex, i, &format!("release.zip.{:03}", i + 1), p, 7000, 64);
        }
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(
            dir_files(&dir),
            vec!["release.zip.001".to_string(), "release.zip.002".to_string()]
        );
        assert_eq!(
            std::fs::read(dir.join("release.zip.001")).unwrap(),
            parts[0]
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Parts that do not form a uniform split (a middle part smaller
    /// than part 1) refuse the whole set rather than guess at the
    /// mapping: every part materializes byte-exact for the disk pass.
    #[test]
    fn zip_split_uneven_parts_refuse_the_set() {
        let a = payload(300_000, 153);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        // Deliberately non-uniform: 120k, 40k, rest.
        let cuts = [&arch[..120_000], &arch[120_000..160_000], &arch[160_000..]];
        let dir = tmpdir("zip-split-uneven");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        ex.declare_zip_split("release.zip", 3);
        for (i, p) in cuts.iter().enumerate() {
            feed(&ex, i, &format!("release.zip.{:03}", i + 1), p, 7000, 65);
        }
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.contains("zip split parts do not line up")),
            "{:?}",
            rep.fallbacks
        );
        for (i, p) in cuts.iter().enumerate() {
            assert_eq!(
                std::fs::read(dir.join(format!("release.zip.{:03}", i + 1))).unwrap(),
                *p,
                "part {} must land byte-exact",
                i + 1
            );
        }
        assert!(!dir.join("a.bin").exists(), "no payload from a refused set");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A declared set whose part 1 is not a zip (a RAR numeric volume
    /// in a `.zip.001` costume): the set forfeits, part 1 classifies
    /// Plain, and everything lands byte-exact as if nothing had been
    /// declared.
    #[test]
    fn zip_split_part1_without_magic_forfeits_the_set() {
        let junk1 = payload(60_000, 154); // no PK magic at offset 0
        let junk2 = payload(60_000, 155);
        let dir = tmpdir("zip-split-notzip");
        let ex = Arc::new(Extractor::new(&dir, 2, true));
        ex.anchor();
        ex.declare_zip_split("release.zip", 2);
        // Part 2 first: it joins the pending set on trust (a cut part
        // has no signature to check). Part 1 then fails the magic.
        feed(&ex, 1, "release.zip.002", &junk2, 7000, 66);
        feed(&ex, 0, "release.zip.001", &junk1, 7000, 67);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("not a zip")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("release.zip.001")).unwrap(), junk1);
        assert_eq!(std::fs::read(dir.join("release.zip.002")).unwrap(), junk2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The strict part grammar: 3-4 digits after `.zip`/`.zipx`, so
    /// `foo.zip.1` can never alias part 1 of `foo.zip.001`.
    #[test]
    fn zip_split_part_name_grammar() {
        assert_eq!(
            crate::zip::split_part_name("Release.ZIP.001"),
            Some(("release.zip".to_string(), 1))
        );
        assert_eq!(
            crate::zip::split_part_name("a.zipx.0042"),
            Some(("a.zipx".to_string(), 42))
        );
        for n in [
            "a.zip.1",
            "a.zip.01",
            "a.zip.00001",
            "a.zip.000",
            "a.7z.001",
            "a.001",
        ] {
            assert!(crate::zip::split_part_name(n).is_none(), "{n}");
        }
    }

    /// A DECLARED bare-numeric set (`movie.001`, no `.zip.` infix)
    /// streams exactly like a declared `.zip.001` set: the NZB's file
    /// list is the declaration and part 1's magic is the gate. Same
    /// three feed orders as the `.zip.NNN` twin.
    #[test]
    fn bare_numeric_zip_split_extracts_one_pass() {
        let a = payload(400_000, 156);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let parts = split_zip(&arch, 3);
        assert_eq!(parts.len(), 3, "fixture must really split");
        for (t, order) in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0]]
            .iter()
            .enumerate()
        {
            let dir = tmpdir(&format!("zip-numsplit{t}"));
            let ex = Arc::new(Extractor::new(&dir, 3, true));
            ex.anchor();
            ex.declare_zip_split("release", 3);
            for &p in order {
                feed(
                    &ex,
                    p,
                    &format!("release.{:03}", p + 1),
                    &parts[p],
                    7000,
                    68 + t as u64,
                );
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
            assert!(
                !dir.join("release.001").exists(),
                "order {t}: part materialized"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// An UNDECLARED bare-numeric part stays on the phase-1 disk path,
    /// even when it carries zip magic - `.001` is also how RAR numeric
    /// volumes and hjsplit output name themselves, and without the
    /// NZB's declaration nothing can size the set.
    #[test]
    fn bare_numeric_part_without_declaration_stays_plain() {
        let a = payload(80_000, 157);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let dir = tmpdir("zip-num-undecl");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.001", &arch, 7000, 69);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("release.001")).unwrap(), arch);
        assert!(!dir.join("a.bin").exists(), "must not extract undeclared");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A declared bare-numeric set whose part 1 is not a zip (the
    /// RAR-volume / hjsplit case the speculative declaration exists to
    /// survive): the set forfeits and every part lands byte-exact, as
    /// if nothing had been declared.
    #[test]
    fn bare_numeric_split_part1_without_magic_forfeits_the_set() {
        let junk1 = payload(60_000, 158); // no PK magic at offset 0
        let junk2 = payload(60_000, 159);
        let dir = tmpdir("zip-num-notzip");
        let ex = Arc::new(Extractor::new(&dir, 2, true));
        ex.anchor();
        ex.declare_zip_split("movie", 2);
        feed(&ex, 1, "movie.002", &junk2, 7000, 70);
        feed(&ex, 0, "movie.001", &junk1, 7000, 71);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks.iter().any(|(_, w)| w.contains("not a zip")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("movie.001")).unwrap(), junk1);
        assert_eq!(std::fs::read(dir.join("movie.002")).unwrap(), junk2);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The bare-numeric grammar: 3-4 digit tails, and heads naming
    /// another family's container are fenced off - `.7z.NNN` belongs to
    /// the 7z chase, `.zip.NNN` to `split_part_name`, and RAR/PAR2
    /// heads to their own machinery.
    #[test]
    fn numeric_split_part_name_grammar() {
        assert_eq!(
            crate::zip::numeric_split_part_name("Movie.001"),
            Some(("movie".to_string(), 1))
        );
        assert_eq!(
            crate::zip::numeric_split_part_name("a.b.0042"),
            Some(("a.b".to_string(), 42))
        );
        for n in [
            "a.1",
            "a.01",
            "a.00001",
            "a.000",
            "a.7z.001",
            "a.zip.001",
            "a.zipx.001",
            "a.rar.001",
            "a.par2.001",
        ] {
            assert!(crate::zip::numeric_split_part_name(n).is_none(), "{n}");
        }
    }

    /// The nested lift: a zip INSIDE a store RAR one-passes exactly like
    /// nested RAR and 7z - payload byte-exact, NOTHING else on disk (no
    /// inner .zip, no outer volume). Three outer feed orders, including
    /// the natural one where the zip's central directory lands dead
    /// last (the out-of-order tail-promote shape).
    #[test]
    fn zip_nested_in_store_rar_extracts_one_pass() {
        let a = payload(180_000, 160);
        let b = payload(60_000, 161);
        let arch = crate::zip::fixtures::zip_of(&[
            crate::zip::fixtures::Spec::stored("a.bin", &a),
            crate::zip::fixtures::Spec::deflated("b.bin", &b),
        ]);
        let outer = store_outer("inner.zip", &arch);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let orders: Vec<Vec<usize>> = vec![
            (0..n_arts).collect(),                               // tail last
            (0..n_arts).rev().collect(),                         // tail first
            (0..n_arts).map(|i| (i * 7 + 3) % n_arts).collect(), // scrambled
        ];
        for (t, order) in orders.iter().enumerate() {
            let dir = tmpdir(&format!("zip-nested-onepass{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            let mut seen = vec![false; n_arts];
            for &i in order {
                if std::mem::replace(&mut seen[i], true) {
                    continue;
                }
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
            assert_eq!(std::fs::read(dir.join("b.bin")).unwrap(), b, "order {t}");
            assert_eq!(
                dir_files(&dir),
                vec!["a.bin".to_string(), "b.bin".to_string()],
                "order {t}"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Encrypted entries at depth 1, with the password: the crypto path
    /// (`entry_crypto` through `QuietZipSource`) is depth-agnostic, and
    /// the child inherits the job password. Both schemes.
    #[test]
    fn zip_nested_encrypted_extracts_one_pass() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data = payload(140_003, 162);
        for (tag, enc) in [
            ("zipcrypto", Encrypt::ZipCrypto { password: "zpw" }),
            (
                "ae2",
                Encrypt::Ae {
                    password: "zpw",
                    strength: 3,
                    vendor_version: 2,
                },
            ),
        ] {
            let arch = crate::zip::fixtures::zip_of(&[Spec {
                encrypt: Some(enc),
                ..Spec::stored("a.bin", &data)
            }]);
            let outer = store_outer("inner.zip", &arch);
            let dir = tmpdir(&format!("zip-nested-enc-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            ex.set_password("zpw");
            feed(&ex, 0, "v.rar", &outer, 7000, 68);
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), data, "{tag}");
            assert_eq!(dir_files(&dir), vec!["a.bin".to_string()], "{tag}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// Encrypted at depth 1 with no password: the chase demotes and the
    /// inner zip materializes byte-exact (today's pre-lift output, the
    /// disk post-pass's input), the job itself succeeds, and the reason
    /// folds through `nested_reason` so it never pattern-matches
    /// volume-level remediation.
    #[test]
    fn zip_nested_encrypted_without_a_password_demotes() {
        use crate::zip::fixtures::{Encrypt, Spec};
        let data = payload(40_000, 163);
        let arch = crate::zip::fixtures::zip_of(&[Spec {
            encrypt: Some(Encrypt::ZipCrypto { password: "zpw" }),
            ..Spec::stored("a.bin", &data)
        }]);
        let outer = store_outer("inner.zip", &arch);
        let dir = tmpdir("zip-nested-enc-nopw");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "v.rar", &outer, 7000, 69);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w == "nested fallback: inner archive is protected"),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(std::fs::read(dir.join("inner.zip")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["inner.zip".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The laundering barrier, as a PROPERTY rather than a wording.
    ///
    /// Zip decline reasons interpolate the offending ENTRY NAME, and
    /// entry names come from a hostile downloaded archive. At depth 0
    /// `ZIP_DISK_FALLBACK_PREFIX` keeps them out of the caller's
    /// volume-remediation ladder; at depth > 0 there is no marker, and
    /// `nested_reason` replacing the WHOLE string is the only thing
    /// stopping an entry called `password.txt` from setting
    /// `enc_fallback` in nzbfast's get/tail.rs - which would leave the
    /// materialized archive packed and print a lock prompt on a job
    /// that should complete. Before this lift a nested zip never
    /// chased, so no nested-zip reason could reach that ladder at all;
    /// it can now.
    ///
    /// An exact-string assertion on the legitimate case passes whether
    /// or not the barrier protects anything, so this feeds hostile names
    /// through both reason shapes (a method decline, which names the
    /// entry BEFORE anything streams, and a CRC failure, which names it
    /// after) and asserts no trigger substring survives.
    #[test]
    fn zip_nested_hostile_entry_names_never_reach_the_remediation_ladder() {
        // Exactly what nzbfast's get/tail.rs substring-keys on (three of
        // the five directly, the other two through
        // `fallback_needs_disk_unpack`).
        const TRIGGERS: [&str; 5] = [
            "compressed",
            "encrypted",
            "password",
            "held-bytes cap",
            "incomplete mapping",
        ];
        let data = payload(60_000, 173);
        for hostile in ["password.txt", "encrypted.bin", "compressed.dat"] {
            // Both reason shapes: a method decline names the entry
            // BEFORE anything streams, a CRC failure names it after.
            for (shape, spec) in [
                (
                    "method",
                    crate::zip::fixtures::Spec {
                        method: 93,
                        ..crate::zip::fixtures::Spec::stored(hostile, &data)
                    },
                ),
                (
                    "crc",
                    crate::zip::fixtures::Spec {
                        crc_override: Some(0xDEAD_BEEF),
                        ..crate::zip::fixtures::Spec::stored(hostile, &data)
                    },
                ),
            ] {
                let arch = crate::zip::fixtures::zip_of(&[spec]);
                let outer = store_outer("inner.zip", &arch);
                let tag = format!("{shape}-{}", hostile.replace('.', "_"));
                let dir = tmpdir(&format!("zip-nested-hostile-{tag}"));
                let ex = Arc::new(Extractor::new(&dir, 1, true));
                ex.anchor();
                feed(&ex, 0, "v.rar", &outer, 7000, 78);
                let rep = ex.finish().unwrap();
                let nested: Vec<&(String, String)> = rep
                    .fallbacks
                    .iter()
                    .filter(|(_, w)| w.starts_with("nested fallback:"))
                    .collect();
                // Without this the whole test passes vacuously on a run
                // that never demoted at all.
                assert_eq!(nested.len(), 1, "{tag}: {:?}", rep.fallbacks);
                for (_, w) in &nested {
                    for t in TRIGGERS {
                        assert!(
                            !w.contains(t),
                            "{tag}: {t:?} survived into a nested reason: {w:?}"
                        );
                    }
                }
                // A nested demote must NOT wear the disk-fallback
                // marker: that marker means "a POSTED archive
                // materialized" and filters the ENTIRE volume-
                // remediation ladder, which is only ever right at
                // depth 0.
                for (_, w) in &rep.fallbacks {
                    assert!(
                        !w.starts_with(ZIP_DISK_FALLBACK_PREFIX),
                        "{tag}: nested demote wore the depth-0 marker: {w:?}"
                    );
                }
                // And the archive is still the disk pass's byte-exact
                // input.
                assert_eq!(std::fs::read(dir.join("inner.zip")).unwrap(), arch, "{tag}");
                std::fs::remove_dir_all(&dir).unwrap();
            }
        }
    }

    /// A demote AFTER an entry has already streamed (second entry fails
    /// its stored CRC): the inner zip materializes complete and the
    /// partial child outputs are deleted - the drain-the-whole-sink-list
    /// class the 7z campaign shipped bugs in.
    #[test]
    fn zip_nested_bad_crc_demotes_and_drains_partial_outputs() {
        let a = payload(150_000, 164);
        let b = payload(90_000, 165);
        let arch = crate::zip::fixtures::zip_of(&[
            crate::zip::fixtures::Spec::stored("a.bin", &a),
            crate::zip::fixtures::Spec {
                crc_override: Some(0xDEAD_BEEF),
                ..crate::zip::fixtures::Spec::stored("b.bin", &b)
            },
        ]);
        let outer = store_outer("inner.zip", &arch);
        let dir = tmpdir("zip-nested-crc");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "v.rar", &outer, 7000, 70);
        let rep = ex.finish().unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w.starts_with("nested fallback:")
                    && w.contains("failed its stored CRC")),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("inner.zip")).unwrap(),
            arch,
            "the materialized inner zip must be byte-exact for the disk pass"
        );
        assert!(
            !dir.join("a.bin").exists(),
            "partial child output survived the demote"
        );
        assert_eq!(dir_files(&dir), vec!["inner.zip".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A budget forfeit mid-chase at depth 1 (the cap wording, raised
    /// through `chase_forfeit` exactly as `chase_span` would): the inner
    /// zip materializes COMPLETE - including the article that arrives
    /// after the demote - no partial child output survives, and the
    /// reason folds to the parent's budget wording.
    #[test]
    fn zip_nested_budget_demote_materializes_byte_exact() {
        let a = payload(200_000, 166);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let outer = store_outer("inner.zip", &arch);
        let art = 7000usize;
        let n_arts = outer.len().div_ceil(art);
        let dir = tmpdir("zip-nested-budget");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        // Withhold the LAST article (the zip's directory window lives
        // there, so the worker is parked on the parse), feed the rest.
        for i in 0..n_arts - 1 {
            let s = i * art;
            let e = (s + art).min(outer.len());
            ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                .unwrap();
        }
        let child = ex
            .inner
            .lock()
            .unwrap()
            .child
            .clone()
            .expect("the outer store RAR must have routed into a child");
        {
            let mut g = child.inner.lock().unwrap();
            let inner = &mut *g;
            assert!(
                matches!(inner.slots[0].mode, SlotMode::SevenZ),
                "the inner zip must be chased before the forfeit"
            );
            child
                .chase_forfeit(inner, 0, "held-bytes cap: chase memory")
                .unwrap();
        }
        // The tail lands after the demote, as a late article would.
        let s = (n_arts - 1) * art;
        ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..])
            .unwrap();
        // Deadline belt: this finish JOINS the demoted zip chase worker,
        // which used to park forever on the withheld tail once
        // `release_gates` cleared its §94 B gate (TODO 255). The seal in
        // `sevenz_finish` is the fix; the deadline just keeps a
        // regression from wedging the whole sweep with no test name.
        let rep = finish_within(&ex, 60).unwrap();
        assert!(
            rep.fallbacks
                .iter()
                .any(|(_, w)| w == "nested fallback: inner holds budget exceeded"),
            "{:?}",
            rep.fallbacks
        );
        assert_eq!(
            std::fs::read(dir.join("inner.zip")).unwrap(),
            arch,
            "the materialized inner zip lost bytes across the demote"
        );
        assert!(
            !dir.join("a.bin").exists(),
            "no payload from a demoted chase"
        );
        assert_eq!(dir_files(&dir), vec!["inner.zip".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The nested half of the tail-prefetch wiring (twin of
    /// `sevenz_tail_promote_hook`): classifying the inner zip calls the
    /// installed promote hook with the directory window under the INNER
    /// name, and the root's output-range map resolves that same range to
    /// outer volume pieces (the composition promote_output_spans runs
    /// on) - whether the tail arrives last naturally or is promoted
    /// ahead.
    #[test]
    fn zip_nested_tail_promote_reaches_the_hook_and_maps_to_the_outer() {
        let a = payload(300_000, 167);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let zlen = arch.len() as u64;
        assert!(zlen > ZIP_TAIL_PREFETCH, "fixture must exceed the window");
        let tail = (zlen - ZIP_TAIL_PREFETCH, zlen);
        let outer = store_outer("inner.zip", &arch);
        for (t, forward) in [true, false].iter().enumerate() {
            let dir = tmpdir(&format!("zip-nested-promote{t}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            type Calls = Arc<Mutex<Vec<(String, u64, Vec<(u64, u64)>, bool)>>>;
            let calls: Calls = Default::default();
            let sink = calls.clone();
            ex.set_promote_hook(Arc::new(
                move |n: &str, s: u64, sp: &[(u64, u64)], u: bool| {
                    sink.lock()
                        .unwrap()
                        .push((n.to_string(), s, sp.to_vec(), u));
                },
            ));
            let art = 7000usize;
            let n_arts = outer.len().div_ceil(art);
            let order: Vec<usize> = if *forward {
                (0..n_arts).collect()
            } else {
                (0..n_arts).rev().collect()
            };
            for i in order {
                let s = i * art;
                let e = (s + art).min(outer.len());
                ex.write(0, "v.rar", outer.len() as u64, s as u64, &outer[s..e])
                    .unwrap();
            }
            let rep = ex.finish().unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
            // Offset-0 probes (root slot and held child slots alike) may
            // fire; they always lead with the (0, 1) span, which no tail
            // range does. The tail is URGENT (the worker blocks on the
            // directory read).
            let mut got = calls.lock().unwrap().clone();
            got.retain(|(_, _, sp, _)| sp.first() != Some(&(0, 1)));
            assert_eq!(
                got,
                vec![("inner.zip".to_string(), zlen, vec![tail], true)],
                "order {t}"
            );
            // The main.rs half of the wiring: the hook's (name, range)
            // resolves through map_output_range to outer volume pieces.
            let pieces = ex.map_output_range("inner.zip", tail.0, tail.1);
            assert!(!pieces.is_empty(), "order {t}: tail range must map");
            let span: u64 = pieces.iter().map(|(_, vs, ve, _)| ve - vs).sum();
            assert_eq!(
                span, ZIP_TAIL_PREFETCH,
                "order {t}: mapped span covers the window"
            );
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// zip-in-zip against `nested_max_depth`: within the ceiling both
    /// levels chase and only the payload lands; with the ceiling at 1
    /// the depth-1 child is created disabled, so the inner zip declines
    /// cleanly (no fallback - this is scope, not failure) and
    /// materializes as a file.
    #[test]
    fn zip_in_zip_respects_the_depth_ceiling() {
        let a = payload(120_000, 168);
        let inner_zip =
            crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let outer_zip = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored(
            "inner.zip",
            &inner_zip,
        )]);
        let dir = tmpdir("zipzip-allowed");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &outer_zip, 7000, 72);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
        assert_eq!(dir_files(&dir), vec!["a.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();

        let dir = tmpdir("zipzip-ceiling");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_nested_max_depth(1);
        feed(&ex, 0, "release.zip", &outer_zip, 7000, 73);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.zip")).unwrap(), inner_zip);
        assert_eq!(dir_files(&dir), vec!["inner.zip".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Phase 0's naming rules hold at depth: a `.cbz` inner entry (a zip
    /// container whose FILE is the deliverable) never attaches and lands
    /// byte-exact.
    #[test]
    fn zip_nested_final_file_never_attaches() {
        let data = payload(40_000, 169);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored(
            "page01.jpg",
            &data,
        )]);
        let outer = store_outer("comic.cbz", &arch);
        let dir = tmpdir("zip-nested-cbz");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "v.rar", &outer, 7000, 74);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("comic.cbz")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["comic.cbz".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A resumed run never chases at ANY depth (twin of the 7z and RAR
    /// resume rules): extraction is disabled wholesale, so the outer
    /// volume classifies Plain on its first span and lands on disk -
    /// chase bytes are never journaled as persisted, and a resumed job
    /// that re-entered a chase would re-download to fill a buffer it
    /// then throws away.
    #[test]
    fn zip_nested_never_chases_on_a_resumed_run() {
        let a = payload(160_000, 170);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let outer = store_outer("inner.zip", &arch);
        let dir = tmpdir("zip-nested-resume");
        let ex = Arc::new(Extractor::with_resume(&dir, 1, false, true));
        ex.anchor();
        feed(&ex, 0, "v.rar", &outer, 7000, 75);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("v.rar")).unwrap(), outer);
        assert_eq!(dir_files(&dir), vec!["v.rar".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `top_zip_on` gates depth 0 ONLY, mirroring `top_chase_on` and
    /// `top_sevenz_on`: with the top-level gate off a nested zip keeps
    /// streaming (nested behavior rides `nested_on`).
    #[test]
    fn zip_nested_still_chases_with_the_top_gate_off() {
        let a = payload(120_000, 171);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let outer = store_outer("inner.zip", &arch);
        let dir = tmpdir("zip-nested-topgate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_top_level_zip(false);
        feed(&ex, 0, "v.rar", &outer, 7000, 76);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a);
        assert_eq!(dir_files(&dir), vec!["a.bin".to_string()]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The nested-zip gate, the zip twin of `NZBFAST_NO_NESTED_7Z`:
    /// `NZBFAST_NO_NESTED_ZIP=1` parses as off, and the runtime setter
    /// drives the same latch - with it off an inner zip materializes
    /// exactly as it did before the depth guard came off, while the
    /// top-level chase is untouched. The env PARSE is asserted on the
    /// pure helper for the same parallel-runner reason as
    /// `nested_disabled_by_env`.
    #[test]
    fn nested_zip_disabled_by_env() {
        assert!(nested_zip_env_off_value(Some("1")));
        assert!(!nested_zip_env_off_value(Some("0")));
        assert!(!nested_zip_env_off_value(None));

        let a = payload(120_000, 174);
        let arch = crate::zip::fixtures::zip_of(&[crate::zip::fixtures::Spec::stored("a.bin", &a)]);
        let outer = store_outer("inner.zip", &arch);
        let dir = tmpdir("zip-nested-gate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        assert!(
            ex.inner.lock().unwrap().nested_zip_on,
            "gate must default on"
        );
        ex.set_nested_zip(false);
        feed(&ex, 0, "v.rar", &outer, 7000, 79);
        let rep = ex.finish().unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("inner.zip")).unwrap(), arch);
        assert_eq!(dir_files(&dir), vec!["inner.zip".to_string()]);
        // The badge reports the OUTER set and is unchanged by the gate:
        // `from_bits` renders the nested word as `inner-7z`/`inner-rar`
        // and has no zip token, so a nested zip - streamed or on disk -
        // contributes nothing to it either way. Pinned so the next
        // person to add `inner-zip` sees which test to update.
        assert_eq!(shape_of(&ex), ["rar5", "store", "one-pass"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Eligible names, in one place: single containers and extensionless
    /// (magic decides those); every multi-part, final-file and named
    /// non-zip shape says no.
    #[test]
    fn zip_chase_name_eligibility() {
        for n in ["Movie.ZIP", "movie.zipx", "a3f9c1d2e"] {
            assert!(crate::zip::chase_eligible_name(n), "{n}");
        }
        for n in [
            "comic.cbz",
            "book.epub",
            "payload.bin",
            "movie.zip.001",
            "movie.z01",
            "movie.7z",
            "movie.rar",
        ] {
            assert!(!crate::zip::chase_eligible_name(n), "{n}");
        }
    }
}
