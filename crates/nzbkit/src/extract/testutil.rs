//! Shared fixtures and feed helpers for the extract test modules.
//!
//! Split out of the inline `mod tests` under the TODO 43 recipe: a
//! verbatim move of the helper fns, not a redesign.

use super::*;
use crate::rar::fixtures;

/// Run `ex.finish()` under a hard wall-clock deadline (a BELT, not the
/// fix): a demote that joins a chase worker parked on a hole used to
/// wedge forever (TODO 255), and a test with no deadline turns that into
/// a sweep that never ends and names nothing. The fix is the finish-time
/// seal in [`SevenZSet::seal_parts`]; this only makes a regression FAIL
/// fast instead of hanging. `finish()` runs on a helper thread so the
/// test thread can time it out and panic with a legible message; on the
/// happy path it returns in well under a second.
pub(super) fn finish_within(ex: &Arc<Extractor>, secs: u64) -> io::Result<ExtractReport> {
    use std::sync::mpsc::RecvTimeoutError;
    let (tx, rx) = std::sync::mpsc::channel();
    let e = Arc::clone(ex);
    std::thread::spawn(move || {
        let _ = tx.send(e.finish());
    });
    match rx.recv_timeout(std::time::Duration::from_secs(secs)) {
        Ok(v) => v,
        Err(RecvTimeoutError::Timeout) => {
            panic!(
                "ex.finish() did not return within {secs}s - a chase worker is wedged (TODO 255)"
            )
        }
        Err(RecvTimeoutError::Disconnected) => {
            panic!("the finish() helper thread panicked - its own assertion is the failure")
        }
    }
}

pub(super) fn tmpdir(tag: &str) -> PathBuf {
    let d = std::env::temp_dir().join(format!("nzbfast-extract-{tag}-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&d);
    std::fs::create_dir_all(&d).unwrap();
    d
}

pub(super) fn payload(n: usize, seed: u8) -> Vec<u8> {
    (0..n)
        .map(|i| (i as u8).wrapping_mul(17).wrapping_add(seed))
        .collect()
}

/// Feed a volume file as shuffled articles through the extractor.
/// `feed` through the verified-article-CRC entry point. `poison`
/// offsets the CRC handed over, standing in for a value that does not
/// describe the bytes - which is what a reuse bug would produce.
pub(super) fn feed_verified(
    ex: &Extractor,
    slot: usize,
    name: &str,
    vol: &[u8],
    art: usize,
    seed: u64,
    poison: u32,
) {
    let mut idx: Vec<usize> = (0..vol.len().div_ceil(art)).collect();
    let mut state = seed;
    for i in (1..idx.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        idx.swap(i, (state >> 33) as usize % (i + 1));
    }
    for i in idx {
        let s = i * art;
        let e = (s + art).min(vol.len());
        let crc = crc32fast::hash(&vol[s..e]) ^ poison;
        ex.write_verified(
            slot,
            name,
            vol.len() as u64,
            s as u64,
            &vol[s..e],
            Some(crc),
        )
        .unwrap();
    }
}

pub(super) fn feed(ex: &Extractor, slot: usize, name: &str, vol: &[u8], art: usize, seed: u64) {
    let mut idx: Vec<usize> = (0..vol.len().div_ceil(art)).collect();
    let mut state = seed;
    for i in (1..idx.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        idx.swap(i, (state >> 33) as usize % (i + 1));
    }
    for i in idx {
        let s = i * art;
        let e = (s + art).min(vol.len());
        ex.write(slot, name, vol.len() as u64, s as u64, &vol[s..e])
            .unwrap();
    }
}

/// Feed a chased RAR volume set one volume at a time, letting the decode
/// stay within `lead` volumes of the arrivals.
///
/// Without the wait the feed outruns the decode by however fast a test
/// loop runs, and a budget breach finds nothing the engine has finished
/// with - which is the honest answer for arrivals that far ahead (the
/// chase demotes, and `rar_trim_set` declining is how it says so), but it
/// is not what a drop-behind test is trying to measure. Real downloads
/// arrive at wire speed against a decoder that keeps up; this is that, in
/// a test, and it waits on the engine's own progress rather than a sleep.
/// Returns the trimmed-byte count at the end of the feed. The wait has a
/// 30 s per-volume deadline so a wedged engine cannot hang the suite,
/// and when it expires the feed proceeds anyway - and from there
/// the case measures the runaway-feed shape, not the paced one, and
/// whatever it asserts next passes or fails for a reason the failure text
/// cannot show. So an expiry is never silent: it prints one line naming
/// the volume, the consumed count and the lead, and bumps
/// [`paced_deadline_expiries`] for a case that wants to assert on it. It
/// is deliberately NOT a hard failure here: on a loaded runner that would
/// turn contention into a red gate (see `.config/nextest.toml`).
pub(super) fn feed_chase_volumes_paced(
    ex: &Extractor,
    names: &[String],
    vols: &[Vec<u8>],
    art: usize,
    lead: usize,
) -> u64 {
    for (index, vol) in vols.iter().enumerate() {
        feed(ex, index, &names[index], vol, art, 33 + index as u64);
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        // The engine can only declare volume k finished once k+1 has
        // arrived and parsed, so it is always at least one behind.
        let lagging = || {
            index >= lead
                && ex.chase_consumed_volumes() + lead <= index
                && ex.chase_retained_bytes() > 0
        };
        while lagging() && std::time::Instant::now() < deadline {
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
        if lagging() {
            PACED_EXPIRIES.fetch_add(1, std::sync::atomic::Ordering::SeqCst);
            eprintln!(
                "PACED FEED DEADLINE EXPIRED: volume {index} fed but engine consumed only {} \
                 volumes (lead {lead}, retained {} bytes) after 30 s - the rest of this case \
                 measures a runaway feed, not the paced shape it was written for",
                ex.chase_consumed_volumes(),
                ex.chase_retained_bytes()
            );
        }
    }
    ex.chase_trimmed_bytes()
}

static PACED_EXPIRIES: std::sync::atomic::AtomicUsize = std::sync::atomic::AtomicUsize::new(0);

/// Process-wide count of `feed_chase_volumes_paced` deadline expiries so
/// far. Read it before and after a feed to learn whether THAT feed ran
/// paced; a case that needs the paced shape can skip or soften its
/// assertion when the delta is non-zero, rather than failing on a loaded
/// box for a reason its output does not show.
pub(super) fn paced_deadline_expiries() -> usize {
    PACED_EXPIRIES.load(std::sync::atomic::Ordering::SeqCst)
}

/// Uniform single-file RAR5 STORE set for the arithmetic-gate tests
/// (SPEC-onepass-obfuscated-store-sets Part A): `n_full` volumes of
/// `dl` payload bytes plus a smaller final piece, dotless
/// hash-garbage volume names whose lexical order is unrelated to
/// volume order, per-piece CRCs the way real archivers write them.
pub(super) fn uniform_store_set(
    inner_name: &str,
    dl: usize,
    n_full: usize,
    tail: usize,
    seed: u8,
) -> (Vec<u8>, Vec<Vec<u8>>, Vec<String>) {
    // WinRAR-true geometry: the VOLUME size is constant, so volume 0
    // (whose main header has no volume-number field) carries one
    // byte MORE data than volumes 1..127. The gate validates exactly
    // this, so the fixture must honor it.
    let total = (dl + 1) + (n_full - 1) * dl + tail;
    let data = payload(total, seed);
    let mut vols = Vec::new();
    let mut pos = 0usize;
    for k in 0..n_full {
        let len = if k == 0 { dl + 1 } else { dl };
        let piece = &data[pos..pos + len];
        pos += len;
        vols.push(fixtures::rar5_volume_n_crc(
            &[(
                inner_name,
                total as u64,
                piece,
                k > 0,
                true,
                Some(crc32fast::hash(piece)),
            )],
            k as u64,
        ));
    }
    vols.push(fixtures::rar5_volume_n_crc(
        &[(
            inner_name,
            total as u64,
            &data[pos..],
            true,
            false,
            Some(crc32fast::hash(&data)),
        )],
        n_full as u64,
    ));
    let names = (0..vols.len())
        .map(|k| format!("{:06x}NoDotGarbage{k}", (k as u64 * 2654435761) & 0xffffff))
        .collect();
    (data, vols, names)
}

/// Deterministic volume-order shuffle with volume 0 forced LAST, so
/// the consecutive-from-0 chain can close nothing until the very end
/// of the download - the arrival shape that demoted the live 143-
/// volume remux.
pub(super) fn shuffled_zero_last(n: usize, seed: u64) -> Vec<usize> {
    let mut order: Vec<usize> = (0..n).collect();
    let mut state = seed;
    for i in (1..order.len()).rev() {
        state = state.wrapping_mul(6364136223846793005).wrapping_add(1);
        order.swap(i, (state >> 33) as usize % (i + 1));
    }
    let z = order.iter().position(|&v| v == 0).unwrap();
    let last = order.len() - 1;
    order.swap(z, last);
    order
}

pub(super) fn shape_of(ex: &Extractor) -> Vec<&'static str> {
    ex.archive_shape()
        .map(|s| s.tokens().to_vec())
        .unwrap_or_default()
}

pub(super) fn dir_files(dir: &Path) -> Vec<String> {
    let mut v: Vec<String> = std::fs::read_dir(dir)
        .unwrap()
        .flatten()
        .map(|e| e.file_name().to_string_lossy().to_string())
        .collect();
    v.sort();
    v
}

/// Minimal RAR5 volume holding ONE compressed entry - enough for the
/// child's sniff to classify RAR and its parser to hit the NotStore
/// blocker. (The shared fixtures only write store mode.)
pub(super) fn rar5_compressed_volume(name: &str, data: &[u8]) -> Vec<u8> {
    fn vint(mut v: u64, out: &mut Vec<u8>) {
        loop {
            let b = (v & 0x7f) as u8;
            v >>= 7;
            if v == 0 {
                out.push(b);
                break;
            }
            out.push(b | 0x80);
        }
    }
    fn block(btype: u64, hflags: u64, body: &[u8], data: &[u8], out: &mut Vec<u8>) {
        let mut hdr = Vec::new();
        vint(btype, &mut hdr);
        vint(hflags, &mut hdr);
        if hflags & 0x02 != 0 {
            vint(data.len() as u64, &mut hdr);
        }
        hdr.extend_from_slice(body);
        let mut sized = Vec::new();
        vint(hdr.len() as u64, &mut sized);
        let mut crc = crc32fast::Hasher::new();
        crc.update(&sized);
        crc.update(&hdr);
        out.extend_from_slice(&crc.finalize().to_le_bytes());
        out.extend_from_slice(&sized);
        out.extend_from_slice(&hdr);
        out.extend_from_slice(data);
    }
    let mut out = Vec::new();
    out.extend_from_slice(b"Rar!\x1a\x07\x01\x00");
    let mut main_body = Vec::new();
    vint(0, &mut main_body);
    block(1, 0, &main_body, &[], &mut out);
    let mut body = Vec::new();
    vint(0, &mut body); // file flags
    vint(data.len() as u64, &mut body); // unpacked size
    vint(0, &mut body); // attributes
    vint(0x80, &mut body); // compression info: method 1 = not store
    vint(0, &mut body); // host os
    vint(name.len() as u64, &mut body);
    body.extend_from_slice(name.as_bytes());
    block(2, 0x02, &body, data, &mut out);
    let mut end_body = Vec::new();
    vint(0, &mut end_body);
    block(5, 0, &end_body, &[], &mut out);
    out
}

/// Compressed RAR5 single volume built by the vendored RAR engine's
/// writer - a REAL compressed archive (LZ bitstream, valid CRCs), not
/// a hand-crafted header shell.
pub(super) fn rars_compressed_volume(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
    let entries: Vec<CompressedEntry> = entries
        .iter()
        .map(|&(name, data)| CompressedEntry {
            name: name.as_bytes(),
            data,
            mtime: None,
            attributes: 0,
            host_os: 0,
        })
        .collect();
    Rar50Writer::new(WriterOptions::default())
        .compressed_entries(&entries)
        .finish()
        .unwrap()
}

/// Compressed RAR5 multi-volume set (one member split across
/// volumes), capped payload bytes per volume.
pub(super) fn rars_compressed_volumes(name: &str, data: &[u8], per_vol: usize) -> Vec<Vec<u8>> {
    rars_compressed_volumes_at_level(name, data, per_vol, None)
}

/// The same set with the encoder's SEARCH EFFORT named, for the two
/// tests whose fixture has to clear the 8 MiB holds-cap floor and so
/// compresses tens of megabytes. Only the search changes; the ARCHIVE
/// does not.
///
/// `None` - what [`rars_compressed_volumes`] passes, and the writer's
/// own default - is the most expensive setting it has:
/// `encode_options_for_level` gives it 256 match candidates per position
/// AND a lazy-matching pass, where `Some(1)` gets 8 candidates and no
/// lazy pass. Nothing a decoder reads differs between them.
/// `compression_method_for_level` answers 1 for both, the dictionary is
/// the same 128 KiB default, and `rar50_algorithm_version` is 0 for
/// both - verified rather than reasoned, by parsing the volumes back
/// and comparing the packed `FileHeader::compression_info`, which is
/// `0x80` either way. Only the match/literal mix inside the bitstream
/// moves, and nothing in this suite asserts on that.
///
/// Measured 28 Aug 2026 on the dev Mac, debug build, over 16 MiB of
/// [`noisy`]: 7.42 s at `None` against 1.51 s at `Some(1)`, a 4.9x cut,
/// at a packed ratio of 0.770 against 0.768. `.config/nextest.toml`
/// puts a 300 s `terminate-after` on the whole `extract::` module
/// (`58b793077`), so a second saved here is headroom under it on every
/// profile - which is the other half of the remedy
/// `research/ARMV7-CHASE-TIMEOUT-2026-08-28.md` prescribes.
///
/// `Some(0)` was measured too and is NOT available: it packs to 1.000
/// of the input, so `should_store_compressed_payload` takes the STORE
/// arm and [`assert_not_store`] refuses the fixture - the test would
/// then silently exercise the phase-1 store path instead of the chase.
///
/// This is NOT the default for the whole suite, and the reason is a
/// measurement rather than caution: converting every caller reddened
/// `chase_tests::stalled_chase_pages_cold_frontier_then_demotes_byte_exact`,
/// whose `chase_retained_bytes() < 1 << 20` is tuned against the shared
/// `chase_volume_set` fixture's packed size, which the slightly worse
/// ratio moves. A fixture whose size a test asserts on is not one to
/// re-cut in passing.
pub(super) fn rars_compressed_volumes_at_level(
    name: &str,
    data: &[u8],
    per_vol: usize,
    level: Option<u8>,
) -> Vec<Vec<u8>> {
    use rars::rar50::{CompressedEntry, Rar50VolumeWriter, WriterOptions};
    let entries = [CompressedEntry {
        name: name.as_bytes(),
        data,
        mtime: None,
        attributes: 0,
        host_os: 0,
    }];
    let mut options = WriterOptions::default();
    if let Some(level) = level {
        options = options.with_compression_level(level);
    }
    Rar50VolumeWriter::new(options)
        .compressed_entries(&entries)
        .max_payload_per_volume(per_vol)
        .finish()
        .unwrap()
}

/// Compressed RAR4 (RAR 2.9/3.x format) single volume from the vendored
/// engine's writer - a real LZ bitstream with valid CRCs.
pub(super) fn rars_v4_compressed_volume(entries: &[(&str, &[u8])]) -> Vec<u8> {
    use rars::rar15_40::{FileEntry, WriterOptions, write_compressed_archive};
    use rars::{ArchiveVersion, FeatureSet};
    let entries: Vec<FileEntry> = entries
        .iter()
        .map(|&(name, data)| FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        })
        .collect();
    write_compressed_archive(
        &entries,
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
    )
    .unwrap()
}

/// Compressed RAR4 multi-volume set (one member split across volumes),
/// capped packed bytes per volume.
pub(super) fn rars_v4_compressed_volumes(name: &str, data: &[u8], per_vol: usize) -> Vec<Vec<u8>> {
    use rars::rar15_40::{FileEntry, WriterOptions, write_compressed_volumes};
    use rars::{ArchiveVersion, FeatureSet};
    write_compressed_volumes(
        FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: None,
            file_comment: None,
        },
        WriterOptions::new(ArchiveVersion::Rar29, FeatureSet::store_only()),
        per_vol,
    )
    .unwrap()
}

/// Encrypted compressed RAR4 multi-volume set. `hp` encrypts the headers
/// too (`-hp`; needs the Rar30 target - Rar29 refuses header encryption),
/// otherwise the data alone (`-p`).
pub(super) fn rars_v4_encrypted_volumes(
    name: &str,
    data: &[u8],
    per_vol: usize,
    password: &str,
    hp: bool,
) -> Vec<Vec<u8>> {
    use rars::rar15_40::{FileEntry, WriterOptions, write_compressed_volumes};
    use rars::{ArchiveVersion, FeatureSet};
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    features.header_encryption = hp;
    let target = if hp {
        ArchiveVersion::Rar30
    } else {
        ArchiveVersion::Rar29
    };
    write_compressed_volumes(
        FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(password.as_bytes()),
            file_comment: None,
        },
        WriterOptions::new(target, features),
        per_vol,
    )
    .unwrap()
}

/// Encrypted compressed RAR4 SINGLE volume (`-p` data encryption).
pub(super) fn rars_v4_encrypted_volume(name: &str, data: &[u8], password: &str) -> Vec<u8> {
    use rars::rar15_40::{FileEntry, WriterOptions, write_compressed_archive};
    use rars::{ArchiveVersion, FeatureSet};
    let mut features = FeatureSet::store_only();
    features.file_encryption = true;
    write_compressed_archive(
        &[FileEntry {
            name: name.as_bytes(),
            data,
            file_time: 0,
            file_attr: 0x20,
            host_os: 3,
            password: Some(password.as_bytes()),
            file_comment: None,
        }],
        WriterOptions::new(ArchiveVersion::Rar29, features),
    )
    .unwrap()
}

/// Half-entropy bytes (xorshift byte, zero byte, ...): compressible
/// enough that the writer keeps the compressed method, incompressible
/// enough that the packed stream stays near half the input size -
/// entropy bounds it from below, so size-driven tests are stable.
pub(super) fn noisy(n: usize, seed: u64) -> Vec<u8> {
    let mut s = seed | 1;
    (0..n)
        .map(|i| {
            if i % 2 == 0 {
                s ^= s << 13;
                s ^= s >> 7;
                s ^= s << 17;
                (s >> 24) as u8
            } else {
                0
            }
        })
        .collect()
}

/// Prove a fixture really is compressed: the store mapper must refuse
/// it with NotStore (otherwise the test would silently exercise the
/// phase-1 store path instead of the chase).
pub(super) fn assert_not_store(vol: &[u8]) {
    let mut m = VolumeMapper::new(vol.len() as u64);
    m.feed(0, vol);
    assert_eq!(
        m.blocker,
        Some(MapBlocker::NotStore),
        "fixture is not compressed"
    );
}

/// In-memory 7z container. `methods: None` keeps the writer's LZMA2
/// default; `solid` packs every entry into ONE block.
pub(super) fn sevenz_archive(
    entries: &[(&str, &[u8])],
    methods: Option<Vec<sevenz_rust2::EncoderConfiguration>>,
    solid: bool,
) -> Vec<u8> {
    let mut w = sevenz_rust2::ArchiveWriter::new(std::io::Cursor::new(Vec::new())).unwrap();
    if let Some(m) = methods {
        w.set_content_methods(m);
    }
    if solid {
        let ents: Vec<sevenz_rust2::ArchiveEntry> = entries
            .iter()
            .map(|&(n, _)| sevenz_rust2::ArchiveEntry::new_file(n))
            .collect();
        let readers: Vec<sevenz_rust2::SourceReader<&[u8]>> = entries
            .iter()
            .map(|&(_, d)| sevenz_rust2::SourceReader::new(d))
            .collect();
        w.push_archive_entries(ents, readers).unwrap();
    } else {
        for &(n, d) in entries {
            w.push_archive_entry(sevenz_rust2::ArchiveEntry::new_file(n), Some(d))
                .unwrap();
        }
    }
    w.finish().unwrap().into_inner()
}

/// A store RAR5 single volume wrapping one payload file.
pub(super) fn store_outer(name: &str, payload: &[u8]) -> Vec<u8> {
    fixtures::rar5_volume(&[(name, payload.len() as u64, payload, false, false)])
}

/// Cut a container the way a byte splitter does: every part the
/// split size, the last one the remainder.
pub(super) fn split_zip(arch: &[u8], n: usize) -> Vec<Vec<u8>> {
    let part = arch.len().div_ceil(n);
    arch.chunks(part).map(|c| c.to_vec()).collect()
}

/// Cut a container into `n` parts the way `7z -v` does: every part
/// exactly the split size, the last one the remainder.
pub(super) fn split_7z(arch: &[u8], n: usize) -> Vec<Vec<u8>> {
    let part = arch.len().div_ceil(n);
    arch.chunks(part).map(|c| c.to_vec()).collect()
}

/// How far the nested child's RAR chase has READ its first chased
/// volume, in child-volume offsets - the served line a rewrite is
/// judged against. None while the child has no chase yet.
pub(super) fn child_chase_served(ex: &Extractor) -> Option<u64> {
    let child = ex.inner.lock().unwrap().child.clone()?;
    let ci = child.inner.lock().unwrap();
    ci.slots
        .iter()
        .find_map(|s| s.chase.as_ref().map(|c| c.buf.served()))
}

/// Block until the child chase has read at least `min` bytes of its
/// volume, or `timeout` passes (then panic - the test's premise is that
/// the decode reaches that point on its own).
pub(super) fn wait_child_chase_served(ex: &Extractor, min: u64, timeout: std::time::Duration) {
    let start = std::time::Instant::now();
    loop {
        if child_chase_served(ex).is_some_and(|s| s >= min) {
            return;
        }
        assert!(
            start.elapsed() < timeout,
            "child chase never read past {min}: served {:?}",
            child_chase_served(ex)
        );
        std::thread::sleep(std::time::Duration::from_millis(5));
    }
}

/// A chased slot's live 7z control, for the trim tests.
pub(super) fn sevenz_ctl(ex: &Extractor, slot: usize) -> Option<Arc<SevenZCtl>> {
    ex.inner.lock().unwrap().slots[slot].sevenz.clone()
}

/// Feed a chased slot the way a real download behaves against a
/// decoder that is keeping up: the offset-0 article first (the sniff
/// that attaches the chase), then the TAIL (which in production the
/// promote hook front-loads, and without which the engine can never
/// open the archive), then the body in order - waiting between
/// chunks for the engine's read frontier to come within `slack` of
/// the arrival frontier.
///
/// That wait is the whole point: the trim releases bytes BELOW the
/// engine's read position, so a test that shovels the archive in
/// faster than it decodes is testing the case trimming cannot help
/// (and correctly demotes), not the case it exists for. Returns the
/// highest trim point the buffer reached.
pub(super) fn feed_paced_tail_first(
    ex: &Extractor,
    slot: usize,
    name: &str,
    vol: &[u8],
    chunk: usize,
    slack: u64,
    withhold_body_chunks: usize,
) -> u64 {
    let n = vol.len();
    let put = |off: usize, end: usize| {
        ex.write(slot, name, n as u64, off as u64, &vol[off..end.min(n)])
            .unwrap();
    };
    put(0, chunk);
    let tail_from = n.saturating_sub(chunk * 2).max(chunk);
    put(tail_from, n);
    // Wait for the container to OPEN before feeding the body. In
    // production the promote ladder front-loads the end header and
    // the parse happens in the first seconds; here the feed would
    // otherwise outrun a worker that has not been scheduled yet, and
    // the test would be measuring the race rather than the trim.
    //
    // `trim_ok` is the signal because it is set exactly between the
    // parse and the first payload read. Watching the watermark
    // instead does not work: the open seeks to the tail, which parks
    // it at EOF (the trap recorded in the scope's method notes).
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
    while std::time::Instant::now() < deadline {
        match sevenz_ctl(ex, slot) {
            Some(c) if c.trim_ok.load(Ordering::Relaxed) => break,
            Some(_) => std::thread::sleep(std::time::Duration::from_millis(1)),
            None => break,
        }
    }
    // Leaving a gap short of the tail keeps the chase LIVE and
    // trimmed at the end of the feed, which is the state the demote
    // and read-back tests need to look at.
    let body_end = tail_from.saturating_sub(withhold_body_chunks * chunk);
    let mut high_base = 0u64;
    let mut off = chunk;
    while off < body_end {
        put(off, off + chunk);
        off += chunk;
        let deadline = std::time::Instant::now() + std::time::Duration::from_secs(30);
        loop {
            let Some(ch) = ex.inner.lock().unwrap().slots[slot]
                .chase
                .as_ref()
                .map(|c| c.buf.clone())
            else {
                break; // demoted, or finish() already took it
            };
            high_base = high_base.max(ch.base());
            let (front, low) = (
                ch.frontier(),
                sevenz_ctl(ex, slot).map_or(u64::MAX, |c| c.low_water.load(Ordering::Relaxed)),
            );
            if low + slack >= front || std::time::Instant::now() > deadline {
                break;
            }
            std::thread::sleep(std::time::Duration::from_millis(1));
        }
    }
    high_base
}

/// The invariant every held-bytes-cap forfeit has to hold, whether or
/// not the decode had committed anything by the time it fired.
///
/// Here rather than in `chase_tests` (where it started) because both
/// container families now write this ledger: the RAR forfeit through
/// `chase_teardown`, the 7z and zip one through `sevenz_teardown_sinks`
/// (TODO 213 item 2). Two spellings of it could drift, and the drift
/// this exists to catch is exactly the two arms disagreeing on what a
/// trustworthy prefix is.
///
/// A cap forfeit KEEPS its in-stream output for the disk pass to resume
/// from (`ResumeOutput`), so "no partial survived" is no longer the
/// test. What replaces it is stricter, and holds either way:
///
/// - a member with no mark leaves NO file behind, exactly as before;
/// - a member with a mark leaves a file of exactly that length, whose
///   bytes are a true prefix of the payload.
///
/// Deliberately not "there must be a mark": whether the engine has
/// flushed its first megabyte before the breach depends on how fast the
/// box is decoding against how fast the test feeds, and a suite that
/// asserted the mark exists would be asserting the load on the machine.
/// The 21 Aug ladder measured the field case (~3.3 GiB committed before
/// the forfeit at 250 MB/s); what a test can pin is that the mark never
/// lies.
pub(super) fn assert_resume_ledger_honest(
    dir: &Path,
    member: &str,
    rep: &ExtractReport,
    payload: &[u8],
) {
    for r in &rep.resume_outputs {
        let kept = std::fs::read(&r.path).unwrap_or_else(|e| {
            panic!(
                "the ledger names {} and it is not readable: {e}",
                r.path.display()
            )
        });
        assert_eq!(
            kept.len() as u64,
            r.len,
            "{} must be cut to the mark, not left preallocated",
            r.path.display()
        );
        assert!(r.len > 0, "a zero-length mark must not be reported");
        assert_eq!(
            &kept[..],
            &payload[..r.len as usize],
            "the kept prefix of {} is not the payload's",
            r.path.display()
        );
        // TODO 217: the mark carries the checksum the disk pass will
        // verify the re-decode against, and it must be the checksum of
        // exactly the kept bytes - a ledger whose hash does not match
        // its own file would refuse every honest resume (or worse,
        // accept a dishonest one it happened to collide with).
        assert_eq!(
            r.crc32,
            crc32fast::hash(&kept),
            "the recorded crc32 of {} is not the crc of the kept prefix",
            r.path.display()
        );
    }
    if rep.resume_outputs.is_empty() {
        // `member` rather than a hard-coded fixture name: all three
        // callers happen to post an "F.bin" today, and a helper that
        // knows that is a helper the next caller has to read before
        // trusting.
        assert!(
            !dir.join(member).exists(),
            "a partial with no mark must not be left in the output directory"
        );
    }
}
