//! Hermetic CPU rig for the built-in indexer's scan-side ingest
//! (`Index::ingest`), the per-header half of the daemon's scan loop.
//!
//! The scan loop has been tuned for coverage and correctness and never
//! profiled for cost per header. This drives the same entry point the
//! loop drives - `Index::ingest(group, &[OverEntry], now)` in chunks of
//! the size `scan_pass` actually uses - over a synthetic group in the
//! subject shapes the real header stream carries (memory topic
//! `nzbfast-index-inflated-by-its-own-key`): a named minority, the
//! 40-hex family with a poster randomised PER ARTICLE, the teevee
//! shattered family with a leading `[n/M]` session tag, par2 sidecars,
//! and a tail of subjects that parse to nothing.
//!
//! It touches no network and no provider: every header is minted here.
//!
//!   cargo run --release -p nzbkit --example indexscan_bench -- \
//!       --headers 2000000 --batch 20000 --dir /path/to/scratch
//!
//! Wall on a loaded box is noise; run the whole thing under
//! `/usr/bin/time -l` and read `instructions retired`, which is stable.
//! `--gen-only` runs the generator alone so its instructions can be
//! subtracted from the ingest arm's. `--repost-pct N` makes N% of
//! postings a SECOND GENERATION of one already emitted - off by default,
//! and the only way this corpus exercises the generation split at all
//! (see `Stream::repost_pct`).

use std::path::PathBuf;
use std::time::{Duration, Instant};

use nzbkit::index::Index;
use nzbkit::nntp::OverEntry;

/// Deterministic, so two arms of an A/B generate byte-identical headers
/// and any row-set difference is the code change, not the input.
struct Rng(u64);

impl Rng {
    fn next(&mut self) -> u64 {
        // xorshift64*
        let mut x = self.0;
        x ^= x >> 12;
        x ^= x << 25;
        x ^= x >> 27;
        self.0 = x;
        x.wrapping_mul(0x2545_F491_4F6C_DD1D)
    }
    fn below(&mut self, n: u64) -> u64 {
        self.next() % n.max(1)
    }
}

fn hex(rng: &mut Rng, chars: usize) -> String {
    let mut s = String::with_capacity(chars);
    while s.len() < chars {
        s.push_str(&format!("{:016x}", rng.next()));
    }
    s.truncate(chars);
    s
}

/// The families, in the proportions the live index carries them.
#[derive(Clone, Copy, PartialEq)]
enum Family {
    /// A readable release, stable poster, many files x many parts.
    Named,
    /// 40-hex stem, one file, poster randomised per article (63% of the
    /// dark band).
    Hex40,
    /// Leading `[037/209]` session tag, 32-hex stem, poster randomised
    /// per article (35% of the dark band).
    Teevee,
    /// par2 sidecars beside a readable release.
    Par2,
    /// Subjects with no counter, no quoted name, or an empty stem -
    /// every one of these is a drop, and the drop path is on the hot
    /// loop too.
    Unparseable,
}

const SHOWS: [&str; 8] = [
    "Deep.Harbour",
    "Iron.Marsh",
    "Night.Ferry",
    "Old.Quarry",
    "Pale.Signal",
    "Red.Lantern",
    "Silent.Ridge",
    "Wide.Meadow",
];
const GROUPS: [&str; 6] = ["WEBDL", "NTb", "FLUX", "CMRG", "EDITH", "SuccessfulCrab"];
const POSTERS: [&str; 6] = [
    "Yenc-PP-A&A",
    "Powered by AiO",
    "brotherhood",
    "TheGuild",
    "usenet-space-cowboys",
    "SSL-News",
];

/// One posting: a family, a stem, a poster policy, and its files.
///
/// `Clone` is what mints a SECOND GENERATION: re-emitting a clone
/// replays the same (poster, stem, filename, part) slots while the
/// message-ids are minted fresh per article at emit time, which is
/// exactly the shape `cluster_batch`'s generation split tests for.
#[derive(Clone)]
struct Release {
    family: Family,
    stem: String,
    poster: String,
    /// (filename, parts) - the articles this release will emit.
    files: Vec<(String, u32)>,
    posted: i64,
    session_total: u32,
    /// Mint `<clock.counter.rand@host>` message-ids (`nzbkit::pesto`),
    /// which the ngPost-family posters use and which arm the pesto
    /// counter/clock range fold on the hot loop.
    pesto: bool,
    pesto_clock: u64,
    pesto_ctr: u32,
}

fn mint_release(rng: &mut Rng, now: i64) -> Release {
    // 20% named, 50% hex40, 22% teevee, 5% par2, 3% unparseable - the
    // dark band dominates a real group by roughly this much.
    let roll = rng.below(100);
    let family = match roll {
        0..=19 => Family::Named,
        20..=69 => Family::Hex40,
        70..=91 => Family::Teevee,
        92..=96 => Family::Par2,
        _ => Family::Unparseable,
    };
    let posted = now - rng.below(400 * 86_400) as i64;
    match family {
        Family::Named | Family::Par2 => {
            let show = SHOWS[rng.below(SHOWS.len() as u64) as usize];
            let grp = GROUPS[rng.below(GROUPS.len() as u64) as usize];
            let s = 1 + rng.below(9);
            let e = 1 + rng.below(24);
            let stem = format!("{show}.S{s:02}E{e:02}.1080p.WEB.H264-{grp}");
            let poster = format!(
                "{} <{}@ngPost.invalid>",
                POSTERS[rng.below(POSTERS.len() as u64) as usize],
                hex(rng, 8)
            );
            let nfiles = (4 + rng.below(28)) as u32;
            let parts = (20 + rng.below(120)) as u32;
            let mut files: Vec<(String, u32)> = (1..=nfiles)
                .map(|i| (format!("{stem}.part{i:02}.rar"), parts))
                .collect();
            if family == Family::Par2 {
                files.push((format!("{stem}.par2"), 1));
                for v in 0..(1 + rng.below(8)) {
                    files.push((
                        format!("{stem}.vol{:03}+{:02}.par2", v * 4, 4),
                        2 + v as u32,
                    ));
                }
            }
            let session_total = files.len() as u32;
            Release {
                family,
                stem,
                poster,
                files,
                posted,
                session_total,
                pesto: false,
                pesto_clock: 0,
                pesto_ctr: 0,
            }
        }
        Family::Hex40 => {
            let stem = hex(rng, 40);
            let parts = (40 + rng.below(300)) as u32;
            Release {
                family,
                files: vec![(format!("{stem}.part01.rar"), parts)],
                stem,
                // Replaced per article; never read for this family.
                poster: String::new(),
                posted,
                session_total: 1,
                // ~40% of this family posts pesto ids (the census's
                // ngPost share); the rest are opaque hashes.
                pesto: rng.below(100) < 40,
                pesto_clock: rng.next(),
                pesto_ctr: (rng.below(0xf_ffff)) as u32,
            }
        }
        Family::Teevee => {
            let stem = hex(rng, 32);
            let parts = (30 + rng.below(80)) as u32;
            let session_total = (20 + rng.below(400)) as u32;
            Release {
                family,
                files: vec![(format!("{stem}.mkv"), parts)],
                stem,
                poster: String::new(),
                posted,
                session_total,
                pesto: false,
                pesto_clock: 0,
                pesto_ctr: 0,
            }
        }
        Family::Unparseable => {
            let stem = hex(rng, 12);
            Release {
                family,
                files: vec![(String::new(), 1 + rng.below(30) as u32)],
                stem,
                poster: format!("<{}@invalid>", hex(rng, 8)),
                posted,
                session_total: 1,
                pesto: false,
                pesto_clock: 0,
                pesto_ctr: 0,
            }
        }
    }
}

/// A generator that hands back OVER windows in article order, with a
/// few postings in flight at once the way a real group interleaves them.
struct Stream {
    rng: Rng,
    now: i64,
    number: u64,
    /// (release, file index, next part, session index)
    live: Vec<(Release, usize, u32, u32)>,
    fanout: usize,
    /// Percent of newly started postings that are a SECOND GENERATION of
    /// a release this stream already emitted, rather than a fresh one.
    ///
    /// Zero by default, which is the corpus the 3 Sep profile and its
    /// published figures were taken on. It is opt-in because the
    /// generation split is the one behaviour a batch-size change can
    /// alter, and the stock corpus cannot exercise it at all: every
    /// stock release has a unique (poster, stem), so no two articles
    /// ever contend for one (file, part) slot and the clash branch in
    /// `cluster_batch` is dead code against it. Measured on 200,000
    /// stock headers: zero `gen_depth_*` census rows and zero
    /// `ingest_drop_gen_depth`.
    repost_pct: u64,
    /// Recently started postings a repost can be drawn from. Only the
    /// stable-poster families are eligible - `Hex40` and `Teevee` mint a
    /// fresh `From` per article, so their cluster key never repeats and
    /// they cannot clash by construction however they are batched.
    pool: Vec<Release>,
}

impl Stream {
    fn new(seed: u64, now: i64, fanout: usize, repost_pct: u64) -> Self {
        Stream {
            rng: Rng(seed),
            now,
            number: 1,
            live: Vec::new(),
            fanout,
            repost_pct,
            pool: Vec::new(),
        }
    }

    fn fill(&mut self) {
        while self.live.len() < self.fanout {
            // A repost is drawn while its first generation may still be
            // LIVE, so the two interleave in the stream the way a
            // backfill leg spanning a repost delivers them - which is
            // what lets one OVER window carry both and a smaller
            // sub-batch carry only one.
            let repost = self.repost_pct > 0
                && !self.pool.is_empty()
                && self.rng.below(100) < self.repost_pct;
            let r = if repost {
                let i = self.rng.below(self.pool.len() as u64) as usize;
                self.pool[i].clone()
            } else {
                let r = mint_release(&mut self.rng, self.now);
                if self.repost_pct > 0 && matches!(r.family, Family::Named | Family::Par2) {
                    // Bounded: a pool that grows with the run would make
                    // the draw depend on how far in it is, and the point
                    // is a stable repost RATE.
                    if self.pool.len() >= 64 {
                        let i = self.rng.below(self.pool.len() as u64) as usize;
                        self.pool.swap_remove(i);
                    }
                    self.pool.push(r.clone());
                }
                r
            };
            self.live.push((r, 0, 1, 1));
        }
    }

    fn one(&mut self) -> OverEntry {
        self.fill();
        let pick = self.rng.below(self.live.len() as u64) as usize;
        let e = {
            let (r, fi, part, sess_idx) = &mut self.live[pick];
            let (fname, parts) = &r.files[*fi];
            let n = *part;
            let total = *parts;
            let subject = match r.family {
                Family::Named | Family::Par2 => format!(
                    "{} [{:02}/{:02}] - \"{}\" yEnc ({}/{})",
                    r.stem, sess_idx, r.session_total, fname, n, total
                ),
                Family::Hex40 => {
                    format!("[1/1] - \"{fname}\" yEnc ({n}/{total})")
                }
                Family::Teevee => format!(
                    "[{:03}/{:03}] - \"{}\" yEnc ({}/{})",
                    sess_idx, r.session_total, fname, n, total
                ),
                // No counter and no quoted name: parses to nothing and
                // is dropped, which is the point of carrying it.
                Family::Unparseable => {
                    format!("{} - re: your post {}", r.stem, self.number)
                }
            };
            let from = match r.family {
                // The shattered families mint a fresh From per article -
                // this is the property that inflates the index 13x and
                // it is also what makes every cluster key a fresh
                // allocation, so the rig must reproduce it.
                Family::Hex40 | Family::Teevee => {
                    format!(
                        "{}@{}.invalid",
                        hex(&mut self.rng, 10),
                        hex(&mut self.rng, 6)
                    )
                }
                _ => r.poster.clone(),
            };
            let message_id = if r.pesto {
                let ctr = r.pesto_ctr;
                r.pesto_ctr = r.pesto_ctr.wrapping_add(1) & 0xf_ffff;
                format!(
                    "<{:016x}.{:05x}.{}@ngPost.invalid>",
                    r.pesto_clock,
                    ctr,
                    hex(&mut self.rng, 16)
                )
            } else {
                format!("<{}@ngPost>", hex(&mut self.rng, 24))
            };
            let bytes = 380_000 + self.rng.below(420_000);
            let date = r.posted + i64::from(*fi as u32);
            let e = OverEntry {
                number: self.number,
                subject,
                from,
                message_id,
                bytes,
                date,
            };
            *part += 1;
            if *part > total {
                *part = 1;
                *fi += 1;
                *sess_idx += 1;
            }
            e
        };
        self.number += 1;
        if self.live[pick].1 >= self.live[pick].0.files.len() {
            self.live.swap_remove(pick);
        }
        e
    }

    fn batch(&mut self, n: usize, out: &mut Vec<OverEntry>) {
        out.clear();
        out.reserve(n);
        for _ in 0..n {
            let e = self.one();
            out.push(e);
        }
    }
}

fn pct(mut v: Vec<Duration>, p: f64) -> Duration {
    if v.is_empty() {
        return Duration::ZERO;
    }
    v.sort_unstable();
    v[(((v.len() - 1) as f64) * p) as usize]
}

type Fail = Box<dyn std::error::Error>;

fn main() -> Result<(), Fail> {
    let mut headers: usize = 2_000_000;
    let mut batch: usize = 20_000;
    let mut seed: u64 = 0x5EED_1234_ABCD_0001;
    let mut dir: Option<PathBuf> = None;
    let mut group = "alt.binaries.teevee".to_string();
    let mut gen_only = false;
    let mut append = false;
    let mut fanout: usize = 6;
    let mut repost_pct: u64 = 0;
    let mut args = std::env::args().skip(1);
    while let Some(a) = args.next() {
        let mut val = || args.next().expect("missing value");
        match a.as_str() {
            "--headers" => headers = val().replace('_', "").parse()?,
            "--batch" => batch = val().parse()?,
            "--seed" => seed = val().parse()?,
            "--dir" => dir = Some(PathBuf::from(val())),
            "--group" => group = val(),
            "--fanout" => fanout = val().parse()?,
            "--repost-pct" => {
                repost_pct = args.next().ok_or("--repost-pct needs a value")?.parse()?;
            }
            "--gen-only" => gen_only = true,
            // Grow an index this rig already built, instead of refusing
            // it. The ladder in audit Round 28 needs 1 M, 10 M and 40 M
            // header indexes; without this each rung is built from
            // nothing and the 40 M rung pays for the 11 M below it
            // twice. PASS A DIFFERENT `--seed` per append, or the second
            // pass re-ingests the first pass's headers and the row count
            // stops rising - ingest is idempotent by design.
            "--append" => append = true,
            other => return Err(format!("unknown argument {other}").into()),
        }
    }
    // A fixed clock: `now` reaches stored rows (the future-date clamp and
    // the arrival stamps), so a wall clock would make two arms differ.
    let now: i64 = 1_780_000_000;

    let mut stream = Stream::new(seed, now, fanout, repost_pct);
    let mut buf: Vec<OverEntry> = Vec::new();

    if gen_only {
        let t0 = Instant::now();
        let mut done = 0usize;
        let mut bytes = 0usize;
        while done < headers {
            let n = batch.min(headers - done);
            stream.batch(n, &mut buf);
            bytes += buf
                .iter()
                .map(|e| e.subject.len() + e.from.len())
                .sum::<usize>();
            done += n;
        }
        println!(
            "gen-only {headers} headers in {:.2?} ({bytes} subject+from bytes)",
            t0.elapsed()
        );
        return Ok(());
    }

    let dir = dir.expect("--dir is required (a scratch directory you own)");
    std::fs::create_dir_all(&dir)?;
    let db = dir.join("index.db");
    if db.exists() && !append {
        return Err(format!(
            "{} already exists - point --dir at a fresh directory, or pass \
             --append with a fresh --seed to grow it",
            db.display()
        )
        .into());
    }
    let mut ix = Index::open(&db)?;

    let mut gen_time = Duration::ZERO;
    let mut ingest_time = Duration::ZERO;
    let mut per_batch: Vec<Duration> = Vec::new();
    let mut completed_total: u64 = 0;
    let mut done = 0usize;
    let t_all = Instant::now();
    while done < headers {
        let n = batch.min(headers - done);
        let g0 = Instant::now();
        stream.batch(n, &mut buf);
        gen_time += g0.elapsed();
        let i0 = Instant::now();
        completed_total += u64::from(ix.ingest(&group, &buf, now)?);
        let dt = i0.elapsed();
        ingest_time += dt;
        per_batch.push(dt);
        done += n;
    }
    let wall = t_all.elapsed();
    drop(ix);

    let hdr_per_s = headers as f64 / ingest_time.as_secs_f64();
    println!("headers          {headers}");
    println!("batch            {batch} ({} batches)", per_batch.len());
    println!("group            {group}");
    println!("wall total       {wall:.2?}");
    println!("  generate       {gen_time:.2?}");
    println!("  ingest         {ingest_time:.2?}");
    println!("headers/s ingest {hdr_per_s:.0}");
    println!(
        "ingest per batch p50 {:.2?}  p90 {:.2?}  max {:.2?}",
        pct(per_batch.clone(), 0.5),
        pct(per_batch.clone(), 0.9),
        pct(per_batch, 1.0)
    );
    println!("completed files  {completed_total}");
    println!("db               {}", db.display());
    Ok(())
}
