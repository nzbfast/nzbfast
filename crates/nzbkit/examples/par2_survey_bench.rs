//! Component benchmark for the two presence surveys a repair runs BEFORE
//! it folds anything: `par2repair::verify_pass1`'s serial one-read pass,
//! and the positioned block-CRC32 pool it hands a file that is short of
//! its declared length.
//!
//! Neither is reachable from the ordinary component rig. The serial pass
//! only does skippable work when the IFSC packet is SHORT of the grid the
//! FileDesc declares - `fit_ifsc` pads those cells with
//! `BlockCheck::UNPROVEN`, whose reserved all-zero MD5 no bytes can ever
//! satisfy - and the pool only runs when the member is TRUNCATED. Both
//! shapes are ordinary in the wild (a recovery set that itself lost
//! articles; a download that stopped) and neither has a rig, which is
//! why the two Codex lane items over this code had to be measured
//! in-library (research/PAR2-TWO-LANES-COMPARED-2026-09-03.md).
//!
//! The fixture is written to disk, pre-warmed, and hashed back: the line
//! carries a digest of the presence bitmap and the verdict flags, so two
//! arms are compared on identical output or not at all.
//!
//! Knobs: NZBFAST_SURVEY_BYTES (declared length), NZBFAST_SURVEY_BLOCK,
//! NZBFAST_SURVEY_PROVED (how many leading IFSC cells the packet
//! described - the rest are UNPROVEN), NZBFAST_SURVEY_PROVED_STRIDE
//! (prove one cell in N across the whole grid instead of a prefix),
//! NZBFAST_SURVEY_ONDISK (bytes actually written; below the declared
//! length this selects the positioned pool), NZBFAST_SURVEY_THREADS,
//! NZBFAST_SURVEY_ROUNDS.

use nzbkit::md5fast::{Digest, Md5};
use nzbkit::par2::{BlockCheck, Par2File};
use nzbkit::par2repair::verify_pass1;
use std::io::Write;
use std::time::Instant;

fn envn(name: &str, default: u64) -> u64 {
    std::env::var(name)
        .ok()
        .and_then(|v| v.parse().ok())
        .unwrap_or(default)
}

fn main() {
    nzbkit::mem::opt_out_of_power_throttling();
    let declared = envn("NZBFAST_SURVEY_BYTES", 3 << 30);
    let bs = envn("NZBFAST_SURVEY_BLOCK", 64 << 10) as usize;
    let on_disk = envn("NZBFAST_SURVEY_ONDISK", declared);
    let n_slices = declared.div_ceil(bs as u64) as usize;
    let proved = envn("NZBFAST_SURVEY_PROVED", n_slices as u64) as usize;
    let stride = envn("NZBFAST_SURVEY_PROVED_STRIDE", 0) as usize;
    let threads = envn("NZBFAST_SURVEY_THREADS", nzbkit::mem::cpu_workers() as u64) as usize;
    let rounds = envn("NZBFAST_SURVEY_ROUNDS", 3) as usize;
    assert!(bs > 0 && on_disk <= declared);

    let dir = std::env::temp_dir().join(format!("nzbfast-par2-survey-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let path = dir.join("member.bin");

    // One xorshift stream, written in 8 MiB pieces so a multi-GiB fixture
    // never needs a multi-GiB buffer. The block checks are taken from the
    // same stream as it goes past, so nothing is read back to build them.
    let mut whole = Md5::new();
    let mut head = Vec::new();
    let mut blocks: Vec<BlockCheck> = Vec::with_capacity(n_slices);
    {
        let mut f = std::io::BufWriter::new(std::fs::File::create(&path).unwrap());
        let mut state = 0x243F_6A88_85A3_08D3u64;
        let mut block = vec![0u8; bs];
        let mut written = 0u64;
        while written < declared {
            let take = (declared - written).min(bs as u64) as usize;
            for chunk in block.chunks_mut(8) {
                state ^= state << 13;
                state ^= state >> 7;
                state ^= state << 17;
                chunk.copy_from_slice(&state.to_le_bytes()[..chunk.len()]);
            }
            // The spec hashes the tail block zero-padded to the block size.
            block[take..].fill(0);
            whole.update(&block[..take]);
            if head.len() < (16 << 10) {
                head.extend_from_slice(&block[..take.min((16 << 10) - head.len())]);
            }
            blocks.push(BlockCheck {
                md5: Md5::digest(&block).into(),
                crc32: crc32fast::hash(&block),
            });
            if written < on_disk {
                let keep = (on_disk - written).min(take as u64) as usize;
                f.write_all(&block[..keep]).unwrap();
            }
            written += take as u64;
        }
        f.flush().unwrap();
    }
    // UNPROVEN is what `fit_ifsc` pads with when the packet stops short.
    if stride > 1 {
        for (i, b) in blocks.iter_mut().enumerate() {
            if !i.is_multiple_of(stride) {
                *b = BlockCheck::UNPROVEN;
            }
        }
    } else {
        for b in blocks.iter_mut().skip(proved) {
            *b = BlockCheck::UNPROVEN;
        }
    }
    let live = blocks.iter().filter(|b| b.is_proven()).count();
    // A member whose whole-file MD5 MATCHES is clean and hands back no
    // bitmap, so the survey under test would never be read. Declare a
    // digest that cannot match: this is the damaged-member path, which
    // is the only path either survey exists for.
    let mut md5: [u8; 16] = whole.finalize().into();
    md5[0] ^= 0xff;
    let file = Par2File {
        file_id: [11; 16],
        name: "member.bin".into(),
        length: declared,
        md5,
        md5_16k: Md5::digest(&head).into(),
        blocks,
    };

    for r in 0..rounds {
        let started = Instant::now();
        let out = verify_pass1(&path, &file, bs, threads).unwrap();
        let elapsed = started.elapsed();
        // Verdict digest: two arms that disagree on ANY of this are not
        // comparable, whatever their wall times say.
        let mut v = Md5::new();
        v.update([
            out.exists as u8,
            out.intact as u8,
            out.clean as u8,
            out.md5_unfinished as u8,
            out.present.is_some() as u8,
            out.resume.is_some() as u8,
        ]);
        if let Some(p) = &out.present {
            for b in p {
                v.update([*b as u8]);
            }
        }
        let digest: [u8; 16] = v.finalize().into();
        println!(
            "survey r={r} declared={declared} on_disk={on_disk} block={}KiB slices={n_slices} \
             proved={live} threads={threads} path={} wall={:.4}s verdict={:02x}{:02x}{:02x}{:02x}",
            bs >> 10,
            if on_disk < declared { "pool" } else { "serial" },
            elapsed.as_secs_f64(),
            digest[0],
            digest[1],
            digest[2],
            digest[3],
        );
    }
    std::fs::remove_dir_all(&dir).unwrap();
}
