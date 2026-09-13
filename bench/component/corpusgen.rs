// Deterministic corpus payload generator for the extraction shootout.
//
//   corpusgen <outdir>
//   corpusgen rand <file> <bytes>     any length of the rand.bin stream
//
// Writes, byte-for-byte identically on every machine:
//   rand.bin   1 GiB incompressible      -> the `store` shape
//   mixed.bin  1 GiB of mixed material   -> `big`, `enc`, `r7dict`
//   rep.bin    1 GiB highly repetitive   -> `rep`
//   small/     400 files, 1 GiB total    -> `small`, `solid`
//
// `mixed` is equal thirds text, structured records and incompressible bytes,
// with periodic long-range replays so a 128 MiB dictionary can find matches a
// 32 MiB one cannot - that difference is the whole point of the r7dict shape.

use std::fs::{self, File};
use std::io::{BufWriter, Write};
use std::path::Path;

const GIB: usize = 1024 * 1024 * 1024;
const BLK: usize = 64 * 1024;

struct Rng(u64, u64, u64, u64);

impl Rng {
    fn new(seed: u64) -> Self {
        // splitmix64 to spread the seed over the state
        let mut s = seed;
        let mut next = || {
            s = s.wrapping_add(0x9E3779B97F4A7C15);
            let mut z = s;
            z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
            z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
            z ^ (z >> 31)
        };
        Rng(next(), next(), next(), next())
    }
    // xoshiro256**
    fn next_u64(&mut self) -> u64 {
        let r = self.1.wrapping_mul(5).rotate_left(7).wrapping_mul(9);
        let t = self.1 << 17;
        self.2 ^= self.0;
        self.3 ^= self.1;
        self.1 ^= self.2;
        self.0 ^= self.3;
        self.2 ^= t;
        self.3 = self.3.rotate_left(45);
        r
    }
    fn fill(&mut self, buf: &mut [u8]) {
        let mut i = 0;
        while i + 8 <= buf.len() {
            buf[i..i + 8].copy_from_slice(&self.next_u64().to_le_bytes());
            i += 8;
        }
        if i < buf.len() {
            let b = self.next_u64().to_le_bytes();
            let n = buf.len() - i;
            buf[i..].copy_from_slice(&b[..n]);
        }
    }
}

fn write_random(path: &Path, len: usize, seed: u64) -> std::io::Result<()> {
    let mut w = BufWriter::with_capacity(1 << 20, File::create(path)?);
    let mut rng = Rng::new(seed);
    let mut buf = vec![0u8; 1 << 20];
    let mut left = len;
    while left > 0 {
        let n = left.min(buf.len());
        rng.fill(&mut buf[..n]);
        w.write_all(&buf[..n])?;
        left -= n;
    }
    w.flush()
}

/// A pool of `blocks` distinct 64 KiB blocks.
fn make_pool(blocks: usize, seed: u64) -> Vec<u8> {
    let mut pool = vec![0u8; blocks * BLK];
    let mut rng = Rng::new(seed);
    rng.fill(&mut pool);
    pool
}

/// A shared vocabulary of pseudo-words. Every text payload draws from this, so
/// the 400 small files have cross-file redundancy for the solid shape to find.
fn vocabulary(seed: u64) -> Vec<Vec<u8>> {
    let mut rng = Rng::new(seed);
    (0..48_000)
        .map(|_| {
            let len = 3 + (rng.next_u64() % 10) as usize;
            (0..len)
                .map(|_| b'a' + (rng.next_u64() % 26) as u8)
                .collect()
        })
        .collect()
}

/// Text-like payload: a skewed word stream, plus long-range replays of earlier
/// spans. The word stream is what makes this decode at a realistic rate -
/// a payload built out of block copies turns every compressed shape into a
/// memcpy benchmark and hides the literal/Huffman work that dominates real
/// archives. The replays are what make a 128 MiB dictionary worth having: they
/// reach back up to 384 MiB, far past the 32 MiB default window.
fn gen_text(vocab: &[Vec<u8>], len: usize, seed: u64) -> Vec<u8> {
    let mut rng = Rng::new(seed);
    let mut out: Vec<u8> = Vec::with_capacity(len + 4096);
    let mut words_on_line = 0u32;
    let mut next_replay = 8 << 20;
    while out.len() < len {
        if out.len() >= next_replay {
            // Replay a 256 KiB span starting anywhere in the last 384 MiB.
            let horizon = out.len().min(384 << 20);
            let span = (128 << 10) + (rng.next_u64() as usize % (256 << 10));
            let back = (rng.next_u64() as usize % horizon).max(span);
            let from = out.len() - back.min(out.len());
            let span = span.min(out.len() - from).min(len - out.len());
            out.extend_from_within(from..from + span);
            next_replay = out.len() + (2 << 20) + (rng.next_u64() as usize % (6 << 20));
            continue;
        }
        // Skewed word choice: the minimum of four draws, so a small head of
        // the vocabulary carries most of the text, as in real prose.
        let mut idx = vocab.len();
        for _ in 0..4 {
            idx = idx.min(rng.next_u64() as usize % vocab.len());
        }
        out.extend_from_slice(&vocab[idx]);
        words_on_line += 1;
        if words_on_line >= 9 + (rng.next_u64() % 7) as u32 {
            out.push(b'\n');
            words_on_line = 0;
            if rng.next_u64() % 24 == 0 {
                out.push(b'\n');
            }
        } else {
            out.push(b' ');
        }
    }
    out.truncate(len);
    out
}

/// The payload the compressed shapes use: equal thirds of text, structured
/// binary records, and incompressible bytes, interleaved at 1 MiB.
///
/// This matters more than it looks. A payload built only out of block copies
/// makes every compressed shape a memcpy benchmark; a payload of only text
/// makes it a literal-and-Huffman benchmark. Real archived material is a mix,
/// and the two extremes do not even agree on who wins. The other two shapes
/// already cover the ends of that range on purpose: `store` is incompressible
/// and `rep` is almost all matches.
fn gen_mixed(vocab: &[Vec<u8>], pool: &[u8], len: usize, seed: u64) -> Vec<u8> {
    const SLICE: usize = 1 << 20;
    let mut rng = Rng::new(seed);
    let mut out: Vec<u8> = Vec::with_capacity(len + SLICE);
    let mut kind = 0usize;
    while out.len() < len {
        let n = SLICE.min(len - out.len());
        // Every so often, replay a slice from far enough back that only a big
        // dictionary can reach it. This is what makes the r7dict shape mean
        // something: -md128m finds these, the 32 MiB default does not.
        if out.len() > (48 << 20) && rng.next_u64() % 5 == 0 {
            let horizon = out.len().min(384 << 20);
            let back = ((rng.next_u64() as usize % horizon).max(40 << 20)).min(out.len());
            let from = out.len() - back;
            let span = n.min(out.len() - from);
            out.extend_from_within(from..from + span);
            continue;
        }
        match kind % 3 {
            0 => out.extend_from_slice(&gen_text(vocab, n, rng.next_u64())),
            // Structured records: a fixed-width row with a few varying fields,
            // the shape of a log or a database dump.
            1 => {
                let start = out.len();
                while out.len() - start < n {
                    let id = rng.next_u64();
                    out.extend_from_slice(b"REC ");
                    out.extend_from_slice(format!("{:012}", id % 1_000_000_000_000).as_bytes());
                    out.extend_from_slice(b" | ");
                    out.extend_from_slice(&vocab[(id as usize) % 512]);
                    out.extend_from_slice(b" | status=ok flags=0x");
                    out.extend_from_slice(format!("{:04x}\n", id as u16).as_bytes());
                }
                out.truncate(start + n);
            }
            // Already-compressed material: nothing to find.
            _ => {
                let off = (rng.next_u64() as usize % (pool.len() / BLK)) * BLK;
                let mut left = n;
                while left > 0 {
                    let take = left.min(pool.len() - off);
                    out.extend_from_slice(&pool[off..off + take]);
                    left -= take;
                }
                out.truncate(len.min(out.len()));
            }
        }
        kind += 1;
    }
    out.truncate(len);
    out
}

fn main() -> std::io::Result<()> {
    let out = std::env::args().nth(1).expect("usage: corpusgen <outdir> | corpusgen rand <file> <bytes>");

    // `corpusgen rand <file> <bytes>` writes an arbitrary length of the SAME
    // stream `rand.bin` carries (same seed, same xoshiro256** sequence), so a
    // 10 GiB scenario payload has the 1 GiB rand.bin as its own prefix and no
    // second seed enters the rig. The scenario fixtures
    // (`par2-scenarios-build.sh`) need 10 GiB and 2.4 GiB of it; without this
    // they would either re-roll a payload per machine or concatenate rand.bin
    // ten times, and a payload that repeats at 1 GiB is not incompressible -
    // periodicity in the payload moves par2cmdline-turbo's sliding scan and
    // has flattered us by ~7% before.
    if out == "rand" {
        let args: Vec<String> = std::env::args().collect();
        let path = args.get(2).expect("usage: corpusgen rand <file> <bytes>");
        let len: usize = args
            .get(3)
            .expect("usage: corpusgen rand <file> <bytes>")
            .parse()
            .expect("byte count");
        eprintln!("{path} ({len} bytes of the rand.bin stream)");
        return write_random(Path::new(path), len, 0xC0FFEE01);
    }

    let out = Path::new(&out);
    fs::create_dir_all(out)?;

    eprintln!("rand.bin  (1 GiB incompressible)");
    write_random(&out.join("rand.bin"), GIB, 0xC0FFEE01)?;

    let vocab = vocabulary(0xC0FFEE02);

    eprintln!("mixed.bin (1 GiB mixed material)");
    let noise = make_pool(512, 0xC0FFEE05); // 32 MiB of incompressible filler
    {
        let body = gen_mixed(&vocab, &noise, GIB, 0xC0FFEE03);
        let mut w = BufWriter::with_capacity(1 << 20, File::create(out.join("mixed.bin"))?);
        w.write_all(&body)?;
        w.flush()?;
    }

    eprintln!("rep.bin   (1 GiB highly repetitive)");
    {
        let small = make_pool(16, 0xC0FFEE04); // 1 MiB of distinct material
        let mut w = BufWriter::with_capacity(1 << 20, File::create(out.join("rep.bin"))?);
        let mut left = GIB;
        while left > 0 {
            let n = left.min(small.len());
            w.write_all(&small[..n])?;
            left -= n;
        }
        w.flush()?;
    }

    eprintln!("small/    (400 files, 1 GiB total)");
    let sdir = out.join("small");
    fs::create_dir_all(&sdir)?;
    let per = GIB / 400; // 2684354 bytes each, 400 files
    for i in 0..400usize {
        let body = gen_mixed(&vocab, &noise, per, 0xD00D0000 + i as u64);
        let mut w =
            BufWriter::with_capacity(1 << 20, File::create(sdir.join(format!("f{i:03}.dat")))?);
        w.write_all(&body)?;
        w.flush()?;
    }

    eprintln!("done");
    Ok(())
}
