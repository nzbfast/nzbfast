//! The one-pass ZIP DIRECT MAP: a stored zip container's entries routed
//! straight to their output files, the way a stored RAR member and a
//! Copy-coded 7z member already are, instead of through the zip worker
//! and a frontier buffer.
//!
//! Why this exists. Round 16 of the unpack audit
//! (`research/RAR-PERF-AUDIT-2026-09-02.md`) raced the zip DISK path for
//! the first time and closed by naming what it had not measured: the
//! one-pass leg. `zip_run` attaches a worker that drives the zip reader
//! over a frontier buffer of the arriving container, so every byte is
//! copied a second time, and at loopback rate the download outruns that
//! copy and the frontier holds the whole set - the same shape round 12
//! measured on 7z (1.29 GB peak for a 1 GiB container), and a
//! held-entire set is what forfeits to the disk route on a 16 GB box.
//!
//! The observation that removes both costs is the one round 16 wrote
//! down: a STORED (method 0), unencrypted zip entry is one contiguous
//! range of the container, exactly as a Copy 7z member is. There is
//! nothing to decode, only somewhere to put the bytes.
//!
//! **Sibling of [`super::sevenz_map`], not a parameter of it.** The two
//! differ in exactly one half and share the other:
//!
//!   * the PLAN is different. 7z's map is one end header at the tail
//!     whose pack-stream offsets place every member arithmetically.
//!     Zip's map is a central directory at the tail that gives every
//!     entry's LOCAL HEADER offset - and the data offset behind it can
//!     only be read from that local header, whose name and extra fields
//!     may differ in length from the directory's copy. So this module
//!     has to reach back into the container for a 30-byte read per
//!     entry, scattered across the whole byte space, which is a step
//!     `sevenz_map::plan` simply does not have (see [`resolve_offsets`]);
//!   * the PROMOTE is the same, and is shared verbatim.
//!     [`Extractor::direct_promote`] takes `DirectMember`s and slots and
//!     never asks what parsed them, so this module builds the member
//!     list and calls it. Nothing about span routing, split bases,
//!     held-span re-feed, CRC composition or read-back reconstruction is
//!     duplicated here.
//!
//! Shape of the change, end to end:
//!
//!   1. Attach is unchanged: a posted `.zip` (or a declared `.zip.001`
//!      byte split) joins a set, has its TAIL articles front-loaded, and
//!      spawns the worker.
//!   2. The worker finds and parses the central directory exactly as
//!      before, and applies every decline the disk reader would.
//!   3. Between that parse and the first payload read - the same seam
//!      `arm_trim` uses - it asks [`screen`] whether every entry is a
//!      plain stored one, resolves their data offsets, and asks [`plan`]
//!      whether the ranges close.
//!   4. If so, [`Extractor::direct_promote`] converts every registered
//!      part to `SlotMode::Rar`, re-feeds what the frontier collected,
//!      and the worker returns. Every later article routes straight to
//!      its output.
//!
//! DECIDED BEFORE `arm_trim`, and that ORDER is load-bearing - the same
//! bug the 7z lane hit after landing (commit cda702811). Arming the trim
//! first opens a window in which the routing thread can spill a part's
//! consumed prefix into that part's own file; a container promoted after
//! such a spill has bytes the re-feed will not find and a truncated
//! archive on disk that nothing deletes.
//!
//! What it deliberately does NOT take, each falling through to the
//! worker path untouched and each pinned by a test:
//!
//!   * any entry whose real method is not STORE - deflate, bzip2, LZMA
//!     and everything else still stream through their decoder;
//!   * any ENCRYPTED entry, ZipCrypto or WinZip AE alike: the container
//!     bytes are ciphertext, so they are not the output's bytes, and a
//!     zip has no per-entry framing that the stored-member crypto path
//!     models;
//!   * a symlink (the worker refuses those outright) and a zero-length
//!     entry (the worker brings that file into existence with an
//!     explicit empty write, and a map that routes bytes has none to
//!     route);
//!   * a MIXED container - one ineligible entry declines the whole
//!     archive, because a slot has ONE mode and half a container cannot
//!     be handed over. The worker then extracts it exactly as it does
//!     today, which is what makes a mixed container correct rather than
//!     merely unaccelerated;
//!   * a container whose geometry does not close: an entry's data
//!     running past the end or into the central directory, entries whose
//!     ranges overlap, two entries under one name, or a stored entry
//!     whose packed and unpacked sizes disagree;
//!   * a container with more than [`ZIP_DIRECT_MAX_MEMBERS`] entries -
//!     see that constant for the cost that bounds it.
//!
//! `NZBFAST_NO_ZIP_DIRECT=1` turns it off wholesale, leaving exactly the
//! round-16 behaviour. It is deliberately a SEPARATE switch from
//! `NZBFAST_NO_7Z_DIRECT` so one benchmark binary can A/B either map.

use super::*;

use super::sevenz_map::DirectMember;

/// Ceiling on the entry count a direct map will take.
///
/// Two costs scale with it and neither scales with payload. Each mapped
/// entry needs its local header read before the map can be built, and
/// those headers are scattered across the whole container - so each one
/// costs an URGENT promote of the article holding it, which reorders the
/// download. And every byte outside a data area (local headers, the
/// central directory, the EOCD) is header/meta to a complete synthetic
/// mapper and is RETAINED in RAM for the life of the slot by
/// `retain_header_bytes`; for a zip that is ~76 bytes plus two copies of
/// the name per entry, which is nothing at ten entries and megabytes at
/// a million.
///
/// The shape this map exists for is a handful of large stored members (a
/// posted set is one or a few files), so a ceiling costs nothing real
/// and removes both unbounded terms. A container over it keeps the
/// worker, which has neither cost because it reads front to back.
pub(super) const ZIP_DIRECT_MAX_MEMBERS: usize = 1024;

/// The cheap half of the decision, over the central directory alone: is
/// every entry a plain STORED one this map can place? Runs BEFORE any
/// local header is promoted or read, so a container that cannot qualify
/// costs nothing at all.
///
/// `files` is the worker's own non-directory entry list, already sorted
/// by local offset. Directory entries are not passed and are irrelevant:
/// neither path creates them (a tree comes from its members' names).
pub(super) fn screen(files: &[&crate::zip::Entry]) -> bool {
    use crate::zip;
    if files.is_empty() || files.len() > ZIP_DIRECT_MAX_MEMBERS {
        return false;
    }
    files.iter().all(|e| {
        // `real_method` reads the WinZip-AE extra field, so a method-99
        // entry answers with its plaintext method rather than 99. That
        // is the right question everywhere else and the wrong one here -
        // an AE-stored entry's container bytes are ciphertext - which is
        // why the encryption test below is separate and not implied.
        zip::real_method(e) == zip::METHOD_STORE
            && !e.is_encrypted()
            && !e.is_symlink()
            // The empty entry the worker creates with an explicit
            // zero-length write. A map has no byte to route for it, so
            // routing alone would silently drop the file.
            && e.uncompressed_size > 0
            // Stored and plaintext packs 1:1. The worker checks the same
            // thing and errors the container out; reaching here means it
            // held, and re-asking is what keeps the map's arithmetic
            // from depending on a check made somewhere else.
            && e.compressed_size == e.uncompressed_size
    })
}

/// Resolve every screened entry's DATA offset, front-loading the local
/// headers first so the reads do not wait for the natural arrival order.
///
/// This is the step 7z does not have. A zip entry's data begins after
/// its local header, whose name and extra-field LENGTHS may differ from
/// the central directory's copy of them - so the 30 fixed bytes at
/// `local_offset` have to be read, and they sit wherever the entry sits,
/// which at line rate is usually a byte nobody has downloaded yet.
/// Promoting is what turns "block until the download reaches the last
/// entry" into "block until one extra article lands".
///
/// `promoted_from` is the container offset above which the worker has
/// ALREADY front-loaded everything (the tail window, widened when the
/// central directory starts below it). A header up there needs no
/// promote of its own, and asking for one would put a redundant urgent
/// range in front of the downloader.
///
/// One hook call per part, not one per entry: the promote walks up the
/// nesting chain and out to the caller, so a container with many members
/// should hand it one ordered list rather than a call each.
///
/// The reads go through a source that does NOT publish a drop-behind
/// watermark: they ASCEND to near the end of the container, and a
/// watermark left up there would let an arriving span compute a trim
/// above the worker's next read if the map then declines. (`arm_trim`
/// resets the watermark, so this is belt-and-braces on the decline path
/// and load-bearing on nothing - but it costs one wrapper.)
pub(super) fn resolve_offsets<S: crate::zip::Source + ?Sized>(
    ex: &Extractor,
    ctl: &SevenZCtl,
    src: &S,
    files: &[&crate::zip::Entry],
    promoted_from: u64,
    total: u64,
) -> Result<Vec<u64>, String> {
    let mut want: Vec<(usize, Vec<(u64, u64)>)> = Vec::new();
    for e in files {
        let lo = e.local_offset();
        // 30 bytes is the whole fixed local header, and all
        // `entry_data_offset` reads.
        let hi = lo.saturating_add(30).min(total);
        if lo >= hi {
            return Err(format!("{} has no local header", e.name));
        }
        if lo >= promoted_from {
            continue;
        }
        for (s, ls, le) in ctl.set.map_range(lo, hi) {
            match want.iter_mut().find(|(slot, _)| *slot == s) {
                Some((_, spans)) => spans.push((ls, le)),
                None => want.push((s, vec![(ls, le)])),
            }
        }
    }
    for (slot, spans) in &want {
        // Off-lock by construction, exactly like the worker's
        // central-directory promote above it: this thread holds no
        // routing lock. Urgent, because the reads below BLOCK.
        ex.promote_slot_spans(*slot, spans, true);
    }
    let mut out = Vec::with_capacity(files.len());
    for e in files {
        out.push(crate::zip::entry_data_offset(src, e).map_err(|err| err.to_string())?);
    }
    Ok(out)
}

/// The members, if the resolved ranges close. `None` means "not for us"
/// and the caller keeps streaming through the worker, which is the
/// behaviour every declined shape had before this module existed.
///
/// `offsets[i]` is `files[i]`'s data offset, from [`resolve_offsets`].
/// `dir_at` is where the central directory begins - the first byte no
/// entry's data may reach.
pub(super) fn plan(
    files: &[&crate::zip::Entry],
    offsets: &[u64],
    dir_at: u64,
    total: u64,
) -> Option<Vec<DirectMember>> {
    if files.is_empty() || files.len() != offsets.len() {
        return None;
    }
    let ceiling = dir_at.min(total);
    let mut out: Vec<DirectMember> = Vec::with_capacity(files.len());
    for (e, &start) in files.iter().zip(offsets.iter()) {
        let end = start.checked_add(e.uncompressed_size)?;
        // Past the container, or over the central directory: either way
        // the range is not this entry's payload, and routing it would
        // both write the wrong bytes and stop the directory's own bytes
        // being retained as header.
        if end > ceiling {
            return None;
        }
        out.push(DirectMember {
            name: e.name.clone(),
            start,
            size: e.uncompressed_size,
            // AE-2 zeroes the CRC field by spec; every encrypted entry
            // already declined above, so this is always true here - and
            // asking anyway keeps the rule in one place
            // (`crc_is_authoritative`) rather than restating it.
            crc: crate::zip::crc_is_authoritative(e).then_some(e.crc32),
        });
    }
    // The routing map, the settle gate and `map_span_into`'s own
    // debug-assert all require ORDERED, DISJOINT data areas. The
    // worker's sort is by LOCAL OFFSET, and a well-formed zip's data
    // ranges follow it - but a header may declare otherwise, so it is
    // checked rather than assumed.
    if out
        .windows(2)
        .any(|w| w[0].start.saturating_add(w[0].size) > w[1].start)
    {
        return None;
    }
    // Two entries under ONE name would share a single output: routing
    // groups on the raw entry name, so their pieces would interleave at
    // each other's offsets. The settle gate catches it afterwards (the
    // pieces cannot tile the file) and demotes; declining here says so
    // at the point the map is built rather than after bytes have landed.
    let mut names: Vec<&str> = out.iter().map(|m| m.name.as_str()).collect();
    names.sort_unstable();
    if names.windows(2).any(|w| w[0] == w[1]) {
        return None;
    }
    Some(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    use crate::extract::testutil::*;
    use crate::zip::fixtures::{Encrypt, Spec};

    /// A whole container in memory as a [`crate::zip::Source`], so the
    /// two pure halves ([`screen`], [`plan`]) can be asked directly
    /// rather than only through a live chase. The disk path's own
    /// `Parts` is crate-private and file-backed; this is four lines.
    struct Buf<'a>(&'a [u8]);

    impl crate::zip::Source for Buf<'_> {
        fn read_exact_at(&self, off: u64, buf: &mut [u8]) -> Result<(), crate::zip::ZipError> {
            let s = off as usize;
            let e = s.saturating_add(buf.len());
            if e > self.0.len() {
                return Err(crate::zip::ZipError::Malformed(
                    "read past end of container",
                ));
            }
            buf.copy_from_slice(&self.0[s..e]);
            Ok(())
        }

        fn total(&self) -> u64 {
            self.0.len() as u64
        }
    }

    /// One stored entry: the container is direct-mapped and its payload
    /// lands with NOTHING retained - the holds cap is set to its 8 MB
    /// floor against a 24 MB container and the drop-behind trim is off,
    /// which on the worker path is the arrangement that demotes. The
    /// map has no buffer to trim because it never buffers.
    #[test]
    fn a_stored_container_maps_direct_and_retains_nothing() {
        let f = noisy(24 << 20, 190);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("F.bin", &f)]);
        let dir = tmpdir("zip-direct-one");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_sevenz_trim(false);
        ex.set_holds_cap(1); // floors at 8 MB, a third of the container
        // Head and tail first, then WAIT for the promote, then the
        // body: 24 MB arriving against an 8 MB cap with the trim off
        // would breach and demote before the map could fire, and the
        // test would be measuring that race instead of the map.
        let n = arch.len();
        let chunk = 256 << 10;
        let put = |off: usize, end: usize| {
            ex.write(0, "big.zip", n as u64, off as u64, &arch[off..end.min(n)])
                .unwrap();
        };
        put(0, chunk);
        let tail_from = n.saturating_sub(chunk * 2).max(chunk);
        put(tail_from, n);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while direct_mapped_parts(&ex) == 0 {
            assert!(std::time::Instant::now() < deadline, "the map never fired");
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        let mut off = chunk;
        while off < tail_from {
            put(off, off + chunk);
            off += chunk;
        }
        assert_eq!(direct_mapped_parts(&ex), 1);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert_eq!(dir_files(&dir), vec!["F.bin".to_string()]);
        assert_eq!(shape_of(&ex), ["zip", "one-pass"]);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Several stored entries, one of them under a directory component:
    /// each is its own contiguous range, placed by its own local
    /// header, and the tree is preserved exactly as the worker path
    /// preserves it.
    #[test]
    fn stored_members_tile_the_container() {
        let a = payload(180_000, 191);
        let b = payload(90_001, 192);
        let c = payload(40_002, 193);
        let arch = crate::zip::fixtures::zip_of(&[
            Spec::stored("A.bin", &a),
            Spec::stored("Pack/B.bin", &b),
            Spec::stored("C.bin", &c),
        ]);
        let dir = tmpdir("zip-direct-tile");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 191);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 1, "the map never fired");
        assert_eq!(std::fs::read(dir.join("A.bin")).unwrap(), a);
        assert_eq!(std::fs::read(dir.join("Pack").join("B.bin")).unwrap(), b);
        assert_eq!(std::fs::read(dir.join("C.bin")).unwrap(), c);
        assert!(!dir.join("release.zip").exists(), "the container landed");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The shipped shape: a stored container SPLIT across declared
    /// `.zip.NNN` parts, every arrival order. An entry crossing a part
    /// seam becomes two mapped pieces, one `split_after` and one
    /// `split_before`, with the base the second one needs - the shape a
    /// stored RAR member spanning two volumes already has.
    #[test]
    fn a_stored_split_set_maps_direct_in_every_order() {
        let a = payload(400_000, 194);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
        let parts = split_zip(&arch, 3);
        assert_eq!(parts.len(), 3, "fixture must really split");
        for (t, order) in [vec![0, 1, 2], vec![2, 1, 0], vec![1, 2, 0]]
            .iter()
            .enumerate()
        {
            let dir = tmpdir(&format!("zip-direct-split{t}"));
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
                    194 + t as u64,
                );
            }
            let rep = finish_within(&ex, 60).unwrap();
            assert!(rep.fallbacks.is_empty(), "order {t}: {:?}", rep.fallbacks);
            // Read AFTER finish, which is what joins the worker that
            // does the flip: before it this races a thread the test
            // never synchronised with.
            assert_eq!(direct_mapped_parts(&ex), 3, "order {t}");
            assert_eq!(std::fs::read(dir.join("a.bin")).unwrap(), a, "order {t}");
            assert_eq!(dir_files(&dir), vec!["a.bin".to_string()], "order {t}");
            assert_eq!(shape_of(&ex), ["zip", "one-pass"], "order {t}");
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// A nested stored `.zip` inside a store RAR outer maps too - the
    /// map is a property of the container, not of the depth it sits at.
    #[test]
    fn a_nested_stored_zip_maps_direct() {
        let f = payload(300_000, 195);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("F.bin", &f)]);
        let outer = store_outer("inner.zip", &arch);
        let dir = tmpdir("zip-direct-nested");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "v.rar", &outer, 7000, 195);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 1, "the child never mapped");
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        assert!(!dir.join("inner.zip").exists(), "inner materialized");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every byte arrives BEFORE the directory parses, which is the
    /// shape the map is for at line rate - and the one where nothing
    /// else is left to flush the promote's queued work. The payload is
    /// whole the moment the promote lands, with no further article and
    /// no `finish()` needed to complete it.
    #[test]
    fn a_container_whose_bytes_all_beat_the_map_still_completes() {
        let f = payload(500_000, 196);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("F.bin", &f)]);
        let dir = tmpdir("zip-direct-allfirst");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 196);
        // Polled, and deliberately BEFORE finish: waiting on the OUTPUT
        // rather than on `direct_mapped_parts` is what makes it
        // deterministic - the map is installed under the routing lock
        // but the queued child forward is delivered after that lock
        // drops, so the counter goes nonzero a moment before the file
        // is whole.
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        while std::fs::read(dir.join("F.bin")).unwrap_or_default() != f {
            assert!(
                std::time::Instant::now() < deadline,
                "the payload never completed off the promote alone \
                 (map fired: {})",
                direct_mapped_parts(&ex) > 0
            );
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        assert_eq!(direct_mapped_parts(&ex), 1, "the map never fired");
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// Every shape the map DECLINES still extracts, through the worker
    /// it always used. One test over the list so a new decline arm
    /// cannot be added without an arm here to hold it - and the MIXED
    /// case is the one that says a container the map only half fits is
    /// correct rather than merely unaccelerated.
    #[test]
    fn declined_shapes_keep_the_worker() {
        let f = payload(220_000, 197);
        let g = payload(70_000, 198);
        // Compressible on purpose where a real codec runs: bzip2 and
        // deflate over random bytes EXPAND, and a stored-size
        // disagreement is a different failure than the one under test.
        let soft: Vec<u8> = (0..180_000u32).map(|i| (i / 977 % 251) as u8).collect();
        // (tag, archive, password, the files it must produce)
        type Case<'a> = (&'a str, Vec<u8>, Option<&'a str>, Vec<(&'a str, &'a [u8])>);
        let cases: Vec<Case> = vec![
            // Deflate: a real decoder, not the identity.
            (
                "deflate",
                crate::zip::fixtures::zip_of(&[Spec::deflated("F.bin", &soft)]),
                None,
                vec![("F.bin", &soft)],
            ),
            // bzip2: a different decoder again.
            (
                "bzip2",
                crate::zip::fixtures::zip_of(&[Spec::bzip2("F.bin", &soft)]),
                None,
                vec![("F.bin", &soft)],
            ),
            // ZipCrypto over a STORED entry: the container bytes are
            // ciphertext, so they are not the output's bytes however
            // stored the plaintext is.
            (
                "zipcrypto",
                crate::zip::fixtures::zip_of(&[Spec {
                    encrypt: Some(Encrypt::ZipCrypto { password: "bz" }),
                    ..Spec::stored("F.bin", &f)
                }]),
                Some("bz"),
                vec![("F.bin", &f)],
            ),
            // WinZip AE over a STORED entry: `real_method` answers
            // STORE for it, which is exactly why the encryption test is
            // separate from the method test.
            (
                "ae",
                crate::zip::fixtures::zip_of(&[Spec {
                    encrypt: Some(Encrypt::Ae {
                        password: "bz",
                        strength: 3,
                        vendor_version: 2,
                    }),
                    ..Spec::stored("F.bin", &f)
                }]),
                Some("bz"),
                vec![("F.bin", &f)],
            ),
            // An empty entry: the worker brings it into existence with
            // an explicit zero-length write and a map has no byte to
            // route, so the whole container declines rather than
            // silently dropping the file.
            (
                "empty",
                crate::zip::fixtures::zip_of(&[
                    Spec::stored("F.bin", &f),
                    Spec::stored("empty.txt", b""),
                ]),
                None,
                vec![("F.bin", &f), ("empty.txt", b"")],
            ),
            // MIXED: one stored entry the map could take beside one it
            // cannot. A slot has ONE mode, so half a container cannot
            // be handed over - the whole thing keeps the worker.
            (
                "mixed",
                crate::zip::fixtures::zip_of(&[
                    Spec::stored("F.bin", &f),
                    Spec::deflated("G.bin", &soft),
                ]),
                None,
                vec![("F.bin", &f), ("G.bin", &soft)],
            ),
            // A directory-only prefix beside a stored entry still maps;
            // the negative control for it is this one, where the second
            // member is a SYMLINK the worker refuses outright.
            (
                "two-stored",
                crate::zip::fixtures::zip_of(&[
                    Spec::stored("F.bin", &f),
                    Spec::stored("G.bin", &g),
                ]),
                None,
                vec![("F.bin", &f), ("G.bin", &g)],
            ),
        ];
        for (tag, arch, pw, want) in cases {
            let dir = tmpdir(&format!("zip-direct-decline-{tag}"));
            let ex = Arc::new(Extractor::new(&dir, 1, true));
            ex.anchor();
            if let Some(p) = pw {
                ex.set_password(p);
            }
            feed(&ex, 0, "release.zip", &arch, 7000, 197);
            let rep = finish_within(&ex, 60).unwrap();
            assert!(rep.fallbacks.is_empty(), "{tag}: {:?}", rep.fallbacks);
            let mapped = direct_mapped_parts(&ex);
            if tag == "two-stored" {
                assert_eq!(mapped, 1, "{tag}: the control did not map");
            } else {
                assert_eq!(mapped, 0, "{tag}: the map took a shape it cannot");
            }
            for (name, bytes) in want {
                assert_eq!(
                    std::fs::read(dir.join(name)).unwrap(),
                    bytes,
                    "{tag}/{name}"
                );
            }
            std::fs::remove_dir_all(&dir).unwrap();
        }
    }

    /// The escape hatch: with the map off, a stored container takes the
    /// worker and its frontier again, which is the round-16 behaviour
    /// the audit measured. Its 7z twin is a SEPARATE switch, and this
    /// asserts they are independent.
    #[test]
    fn the_gate_turns_the_map_off() {
        let f = payload(200_000, 199);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("F.bin", &f)]);
        let dir = tmpdir("zip-direct-off");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_zip_direct(false);
        feed(&ex, 0, "release.zip", &arch, 7000, 199);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 0);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The 7z gate does NOT turn the zip map off - two switches, so a
    /// benchmark round can A/B either map out of one binary.
    #[test]
    fn the_seven_zip_gate_leaves_the_zip_map_alone() {
        let f = payload(200_000, 200);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("F.bin", &f)]);
        let dir = tmpdir("zip-direct-7zgate");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        ex.set_sevenz_direct(false);
        feed(&ex, 0, "release.zip", &arch, 7000, 200);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(rep.fallbacks.is_empty(), "{:?}", rep.fallbacks);
        assert_eq!(direct_mapped_parts(&ex), 1);
        assert_eq!(std::fs::read(dir.join("F.bin")).unwrap(), f);
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// A part that never arrives: the container has a hole in it, so
    /// the map cannot describe whole files and every part that DID
    /// arrive materializes byte-exact for the disk post-pass - through
    /// the synthetic mapper's read-back, which is the direct map's half
    /// of the demote contract.
    #[test]
    fn a_missing_part_materializes_the_rest_byte_exact() {
        let a = payload(400_000, 201);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("a.bin", &a)]);
        let parts = split_zip(&arch, 3);
        let dir = tmpdir("zip-direct-hole");
        let ex = Arc::new(Extractor::new(&dir, 3, true));
        ex.anchor();
        ex.declare_zip_split("release.zip", 3);
        for i in [0usize, 2] {
            feed(
                &ex,
                i,
                &format!("release.zip.{:03}", i + 1),
                &parts[i],
                7000,
                201 + i as u64,
            );
        }
        let rep = finish_within(&ex, 60).unwrap();
        assert!(!rep.fallbacks.is_empty(), "the hole was not noticed");
        assert_eq!(
            std::fs::read(dir.join("release.zip.001")).unwrap(),
            parts[0]
        );
        assert_eq!(
            std::fs::read(dir.join("release.zip.003")).unwrap(),
            parts[2]
        );
        assert!(!dir.join("a.bin").exists(), "a member survived the demote");
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// The entry's own stored CRC32 is carried onto the member's LAST
    /// mapped piece, so the settle-time composition gate checks the
    /// routed bytes exactly as it does a stored RAR member's. A byte
    /// flipped inside the payload must not ship.
    #[test]
    fn a_corrupt_member_fails_the_composed_crc() {
        let f = payload(400_000, 202);
        let mut arch = crate::zip::fixtures::zip_of(&[Spec::stored("F.bin", &f)]);
        // Deep inside the entry data, well past every header.
        let at = arch.len() / 2;
        arch[at] ^= 0xFF;
        let dir = tmpdir("zip-direct-crc");
        let ex = Arc::new(Extractor::new(&dir, 1, true));
        ex.anchor();
        feed(&ex, 0, "release.zip", &arch, 7000, 202);
        let rep = finish_within(&ex, 60).unwrap();
        assert!(!rep.fallbacks.is_empty(), "damaged bytes shipped clean");
        assert!(
            std::fs::read(dir.join("F.bin"))
                .map(|got| got != f)
                .unwrap_or(true),
            "the damaged member shipped as if it were good"
        );
        std::fs::remove_dir_all(&dir).unwrap();
    }

    /// `screen` is the cheap half and runs before any I/O, so it is
    /// asked directly here: the shapes it must refuse, and the one it
    /// must take.
    #[test]
    fn screen_refuses_what_the_map_cannot_place() {
        let f = payload(9_000, 203);
        let soft: Vec<u8> = (0..9_000u32).map(|i| (i / 97 % 251) as u8).collect();
        let take = |specs: &[Spec]| -> bool {
            let arch = crate::zip::fixtures::zip_of(specs);
            let parts = Buf(&arch);
            let dir = crate::zip::find_central_directory(&parts).unwrap();
            let entries = crate::zip::parse_central_directory(&parts, &dir).unwrap();
            let files: Vec<&crate::zip::Entry> = entries.iter().filter(|e| !e.is_dir).collect();
            screen(&files)
        };
        assert!(take(&[Spec::stored("F.bin", &f)]), "plain store refused");
        assert!(
            take(&[Spec::stored("F.bin", &f), Spec::stored("G.bin", &f)]),
            "two plain stores refused"
        );
        assert!(!take(&[Spec::deflated("F.bin", &soft)]), "deflate taken");
        assert!(!take(&[Spec::bzip2("F.bin", &soft)]), "bzip2 taken");
        assert!(
            !take(&[Spec {
                encrypt: Some(Encrypt::ZipCrypto { password: "p" }),
                ..Spec::stored("F.bin", &f)
            }]),
            "ZipCrypto taken"
        );
        assert!(
            !take(&[Spec {
                encrypt: Some(Encrypt::Ae {
                    password: "p",
                    strength: 3,
                    vendor_version: 2,
                }),
                ..Spec::stored("F.bin", &f)
            }]),
            "WinZip AE taken"
        );
        assert!(!take(&[Spec::stored("e.txt", b"")]), "empty entry taken");
        assert!(
            !take(&[Spec::stored("F.bin", &f), Spec::deflated("G.bin", &soft)]),
            "mixed container taken"
        );
        assert!(!take(&[]), "an empty archive was taken");
    }

    /// `plan` is fed the resolved offsets, so the geometry it refuses
    /// is asked of it directly - each of these is a header that could
    /// be crafted and none of them may reach the routing map.
    #[test]
    fn plan_declines_geometry_that_does_not_close() {
        let a = payload(1_000, 204);
        let b = payload(2_000, 205);
        let arch = crate::zip::fixtures::zip_of(&[Spec::stored("A", &a), Spec::stored("B", &b)]);
        let parts = Buf(&arch);
        let dir = crate::zip::find_central_directory(&parts).unwrap();
        let entries = crate::zip::parse_central_directory(&parts, &dir).unwrap();
        let files: Vec<&crate::zip::Entry> = entries.iter().filter(|e| !e.is_dir).collect();
        assert_eq!(files.len(), 2);
        let total = arch.len() as u64;
        let good: Vec<u64> = files
            .iter()
            .map(|e| crate::zip::entry_data_offset(&parts, e).unwrap())
            .collect();
        assert!(
            plan(&files, &good, dir.at, total).is_some(),
            "the real geometry was refused"
        );
        // Overlapping ranges: the routing map, the settle gate and
        // `map_span_into`'s debug-assert all require disjoint areas.
        assert!(plan(&files, &[good[0], good[0]], dir.at, total).is_none());
        // Descending: same requirement, the other way round.
        assert!(plan(&files, &[good[1], good[0]], dir.at, total).is_none());
        // Over the central directory: those bytes must stay header, or
        // they are routed into an output AND not retained.
        assert!(plan(&files, &[good[0], dir.at], dir.at, total).is_none());
        // Past the end of the container.
        assert!(plan(&files, &[good[0], total], dir.at, total).is_none());
        // Wildly out of range, so the addition itself would overflow.
        assert!(plan(&files, &[good[0], u64::MAX - 1], dir.at, total).is_none());
        // A count that does not match the entries it is for.
        assert!(plan(&files, &good[..1], dir.at, total).is_none());
        assert!(plan(&[], &[], dir.at, total).is_none());
        // Two entries under ONE name would share a single output.
        let dup = crate::zip::fixtures::zip_of(&[Spec::stored("A", &a), Spec::stored("A", &b)]);
        let dparts = Buf(&dup);
        let ddir = crate::zip::find_central_directory(&dparts).unwrap();
        let dents = crate::zip::parse_central_directory(&dparts, &ddir).unwrap();
        let dfiles: Vec<&crate::zip::Entry> = dents.iter().filter(|e| !e.is_dir).collect();
        let doffs: Vec<u64> = dfiles
            .iter()
            .map(|e| crate::zip::entry_data_offset(&dparts, e).unwrap())
            .collect();
        assert!(plan(&dfiles, &doffs, ddir.at, dup.len() as u64).is_none());
    }
}
