//! End-to-end component benchmark for a light mapped PAR2 repair.
//! Fixture construction and recovery generation are outside the clock.
//!
//! Set NZBFAST_REPAIR_TIMING=1 for the per-phase breakdown (feed reads /
//! fold+solve / patch / patch+verify, plus the self-prove's own split
//! into CRC32 and MD5 bytes), which is the split TODO M2c.2 was about.
//!
//! THE SELF-PROVE IS THE WHOLE WALL HERE and has been since M2c.2 fixed
//! the reads: 3.09 s of a 3.18 s repair on the 2 GiB arm, which is
//! 2 GiB at 0.695 GB/s - the FileDesc MD5 chain, and nothing else.
//! MD5 is serial, so the only bytes that can come off that chain are
//! the ones BELOW the first rebuilt block, and the only window big
//! enough to hash them in is the download
//! (research/DESIGN-2026-09-02-mapped-selfprove-prefix.md). The daemon
//! gets that state from `nzbkit::live::prefix`; this bench has no
//! download, so it computes the same prefix off the same disk BEFORE
//! the clock starts and hands it in, which is what the daemon's tail
//! sees.
//!
//! Knobs: NZBFAST_MAPPED_BYTES, NZBFAST_MAPPED_BLOCK,
//! NZBFAST_MAPPED_MISSING, NZBFAST_MAPPED_DAMAGE_AT (percent of the
//! file the FIRST hole sits at - the lever the whole change turns on),
//! NZBFAST_MAPPED_PREFIX=0 to measure the baseline arm.

use nzbkit::extract::Extractor;
use nzbkit::gf16;
use nzbkit::md5fast::{Digest, Md5};
use nzbkit::par2::{BlockCheck, Par2File};
use nzbkit::par2repair::{
    Md5Resume, VolumeIo, bench_fold, input_base_logs, repair_mapped_prefixed,
};
use nzbkit::rar::fixtures;
use std::io;
use std::time::Instant;

struct MappedIo<'a>(&'a Extractor);

impl VolumeIo for MappedIo<'_> {
    fn read(&self, file: usize, off: u64, buf: &mut [u8]) -> io::Result<()> {
        self.0.read_at(file, off, buf)
    }

    fn write(&self, file: usize, off: u64, data: &[u8]) -> io::Result<()> {
        self.0.patch_volume_span(file, off, data)
    }
}

fn envn(name: &str, default: usize) -> usize {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    // nzbkit emits its timing lines as tracing events; an example binary
    // has to install a sink or NZBFAST_REPAIR_TIMING prints nothing. Same
    // sink as examples/par2_repair_dir.rs, and for the same reason: the
    // `repair-timing` target is the key these lines are grepped by.
    tracing_subscriber::fmt()
        .with_ansi(false)
        .without_time()
        .with_target(true)
        .with_writer(std::io::stderr)
        .init();
    // Both calls below mirror examples/par2_repair_dir.rs, which carries the
    // long-form rationale. In short: without the throttling opt-out a
    // sustained bench gets demoted onto E-cores on Windows (16.6 s to 58 s on
    // the laptop rig, no effect elsewhere), and without fast par mode this
    // driver runs the streaming fold and reports a configuration nobody
    // ships - serve/startup.rs turns it ON via FAST_PAR_DEFAULT, and the
    // library flag defaults to OFF because it is the daemon's setting to own.
    // MUST TRACK `nzbfast::serve::FAST_PAR_DEFAULT`. `NZBFAST_NTT=0` still
    // forces the fold, which is how the fold column is measured.
    nzbkit::mem::opt_out_of_power_throttling();
    nzbkit::par2repair::set_fast_par_enabled(true);
    let payload_len = envn("NZBFAST_MAPPED_BYTES", 256 << 20);
    let block = envn("NZBFAST_MAPPED_BLOCK", 64 << 10);
    let missing_count = envn("NZBFAST_MAPPED_MISSING", 3);
    assert!(block > 0 && block.is_multiple_of(2));

    let mut payload = vec![0u8; payload_len];
    let mut state = 0x243F_6A88_85A3_08D3u64;
    for chunk in payload.chunks_mut(8) {
        state ^= state << 13;
        state ^= state >> 7;
        state ^= state << 17;
        chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
    }
    let volume = fixtures::rar5_volume(&[(
        "payload.bin",
        payload_len as u64,
        payload.as_slice(),
        false,
        false,
    )]);
    drop(payload);

    let total = volume.len().div_ceil(block);
    assert!(missing_count > 0 && missing_count < total);
    // Where the FIRST hole sits, as a percent of the file. The default
    // 25 reproduces the geometry this bench always had
    // (`(i + 1) * total / (missing_count + 1)` put three holes at
    // 25/50/75%); the knob exists because the saving IS the prefix, so
    // a fixture that fixes the first hole at a quarter of the file
    // fixes the answer at ~25% and cannot show the shape.
    let at = envn("NZBFAST_MAPPED_DAMAGE_AT", 25).min(99);
    let first = (total * at / 100).clamp(1, total - missing_count);
    let missing: Vec<usize> = (0..missing_count)
        .map(|i| first + i * (total - first) / missing_count)
        .collect();
    let mut present = vec![true; total];
    for &index in &missing {
        present[index] = false;
    }

    let mut padded = volume.clone();
    padded.resize(total * block, 0);
    let sources: Vec<&[u8]> = padded.chunks(block).collect();
    let logs = input_base_logs(total).unwrap();
    let mut recovery_words = vec![vec![0u16; block / 2]; missing_count];
    bench_fold(&mut recovery_words, &sources, &|row, input| {
        gf16::pow2(logs[input] as u64 * row as u64)
    });
    let recovery: Vec<(u32, Vec<u8>)> = recovery_words
        .into_iter()
        .enumerate()
        .map(|(e, words)| (e as u32, gf16::words_as_bytes(&words).to_vec()))
        .collect();
    drop(sources);
    drop(padded);

    let dir =
        std::env::temp_dir().join(format!("nzbfast-par2-mapped-repair-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let extractor = Extractor::new(&dir, 1, true);
    for (i, chunk) in volume.chunks(1 << 20).enumerate() {
        extractor
            .write(0, "bench.rar", volume.len() as u64, (i << 20) as u64, chunk)
            .unwrap();
    }
    assert!(
        extractor.is_mapped(0),
        "fixture must stay on the mapped path"
    );

    // REAL IFSC BLOCKS, unlike this bench before 2 Sep 2026. Every
    // production set carries them, the driver's untouched-file path
    // already depends on them, and the prefix arm REQUIRES them - the
    // self-prove closes the prefix span against these CRC32s from disk,
    // which is what keeps every byte read back after the patch.
    let blocks: Vec<BlockCheck> = volume
        .chunks(block)
        .map(|c| {
            let mut padded = c.to_vec();
            padded.resize(block, 0);
            BlockCheck {
                md5: Md5::digest(&padded).into(),
                crc32: crc32fast::hash(&padded),
            }
        })
        .collect();
    let file = Par2File {
        file_id: [7; 16],
        name: "bench.rar".into(),
        length: volume.len() as u64,
        md5: Md5::digest(&volume).into(),
        md5_16k: Md5::digest(&volume[..volume.len().min(16 << 10)]).into(),
        blocks,
    };
    // The download-time hasher, stood in for: the proven prefix runs to
    // the first hole, and it is hashed OFF THE SAME DISK the self-prove
    // rereads. Outside the clock, because in the daemon it is paid
    // while articles are still arriving.
    let want_prefix = !matches!(
        std::env::var("NZBFAST_MAPPED_PREFIX").as_deref(),
        Ok("0") | Ok("off")
    );
    let boundary = missing[0] as u64 * block as u64;
    let prefixes: Vec<Option<Md5Resume>> = if want_prefix {
        let mut h = Md5::new();
        let mut buf = vec![0u8; 1 << 20];
        let mut off = 0u64;
        while off < boundary {
            let take = (boundary - off).min(buf.len() as u64) as usize;
            extractor.read_at(0, off, &mut buf[..take]).unwrap();
            h.update(&buf[..take]);
            off += take as u64;
        }
        vec![Some(Md5Resume::bench_prefix(boundary, h))]
    } else {
        vec![None]
    };
    let started = Instant::now();
    let rebuilt = repair_mapped_prefixed(
        &[(file, present)],
        block,
        &recovery,
        &MappedIo(&extractor),
        false,
        &prefixes,
    )
    .unwrap();
    let elapsed = started.elapsed();
    println!(
        "mapped repair {:.2} MiB, block {} KiB, {rebuilt} missing, first hole at {:.0}% \
         (prefix {}): {:.3}s ({:.2} volume GiB/s)",
        volume.len() as f64 / (1 << 20) as f64,
        block >> 10,
        boundary as f64 * 100.0 / volume.len() as f64,
        if want_prefix { "on" } else { "off" },
        elapsed.as_secs_f64(),
        volume.len() as f64 / elapsed.as_secs_f64() / (1u64 << 30) as f64
    );
    std::fs::remove_dir_all(&dir).unwrap();
}
