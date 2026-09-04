# Architecture

How an NZB becomes extracted output. Engine code lives in `crates/nzbkit`, the CLI and
daemon in `crates/nzbfast`. Paths below are relative to `crates/` unless they start with
`vendor/`.

## 1. NZB parse (`nzbkit-base/src/nzb.rs`)

An NZB is XML: files, each with newsgroups and a list of segments (message-ID, byte
count, part number). The parser keeps the model deliberately close to the wire format;
scheduling concepts such as server tiers and block accounting live elsewhere. Each file
becomes a slot; each segment becomes one article to fetch.

## 2. Download: pool + pipelined NNTP (`nzbkit/src/pool.rs`, `nntp.rs`)

`nntp.rs` is an async NNTP client (RFC 3977) over rustls TLS or plain TCP. Its
`send_*` and `read_*` halves are split so callers can pipeline: write several `BODY`
commands, then consume responses in order, which is safe because NNTP responses arrive
strictly in command order. AUTHINFO happens once at connect and is never pipelined.

`pool.rs` manages the connection fleet (`fetch_all_multi_ctl`). Each connection is a
worker task that keeps a window of commands in flight, spawns with a ramp delay, and is
reused for the whole run. A stalled or dead connection requeues its in-flight articles
and reconnects with backoff. Retries follow the NNTP response taxonomy: transport
failures retry (bounded); a 430 "no such article" is authoritative for that server.
Every connection sends QUIT on the way out. Raw article bytes leave the pool on an mpsc
channel as `FetchOutcome`s.

## 3. Decode in place (`nzbkit-base/src/yenc.rs`, `yenc_simd.rs`)

Dedicated decode threads (capped at core count) drain that channel in batches. Each
article goes through `yenc_simd::decode_into_integrity`: rapidyenc (vendored FFI) does
yEnc unescaping and NNTP dot-unstuffing in one SIMD pass, with CRC32 from its
PMULL/CRC-instruction kernels. `yenc.rs` is the scalar correctness oracle the SIMD path
is differentially tested against. Once live verify has matched a slot to a PAR2 file,
the redundant article CRC is skipped and the PAR2 block CRC catches corruption instead.

## 4. Disk and memory (`nzbkit-base/src/disk.rs`, `mem.rs`)

One output file per NZB file, preallocated to its yEnc-declared size; every decoded
article `pwrite`s at its final offset from whichever decode thread holds it. There is no
temp file and no assembly pass. `mem.rs` runs one global memory budget over every cache
tier (extractor holds, verifier partials, the body-buffer pool); each tier has a spill
path to disk, so a 190 GB job on an 8 GB NAS degrades to more I/O rather than swapping.
Default budget: a quarter of RAM, clamped to [256 MB, 16 GB], cgroup-aware in containers.

## 5. Verify and repair (`nzbkit-base/src/live.rs`, `par2.rs`, `par2repair.rs`, `gf16.rs`, `par2ntt.rs`)

The PAR2 main packet is scheduled first. `live.rs` hashes decoded article buffers
against the PAR2 block checksums while the download runs, so verification finishes with
the last article and clean sets never pay a post-download verify pass. `par2.rs` parses
packets and drives minimum-download logic: exactly enough recovery volumes are fetched
when blocks are bad. `par2repair.rs` reconstructs missing blocks with Reed-Solomon over
GF(2^16) (`gf16.rs`, par2cmdline-compatible field) and patches damaged files in place.
`par2ntt.rs` is an output-pruned 65535-point NTT for syndrome computation. It has
been the default dispatch since 31 Jul 2026 (`FAST_PAR_DEFAULT`), with the fold as
the fallback: a repair whose whole-file verify fails is retried on the fold and
trips a process-wide breaker, and small machines are gated onto the fold up front by
a RAM- and cgroup-scaled retention budget, so the fast path can never be the reason
output is wrong.

## 6. Extraction (`nzbkit/src/extract/`, `vendor/rars`)

The extractor owns all data-file writing. A slot is sniffed at its offset-0 article
and routed by what it turns out to be: RAR, 7z or zip go to a mapper, anything else
is a plain file. No container format is disk-only. In mapping mode a `VolumeMapper`
parses volume headers as bytes arrive and stored spans `pwrite` directly into the
inner extracted file, so volumes never touch disk on the happy path. Spans ahead of
the parsed headers are held in memory under the `mem.rs` budget.

Compressed and encrypted entries decode through the vendored `rars` library while
the download is still running, reading volumes through a `BlockingRangeSource`
frontier buffer: `rars::rar50` for the RAR5/RAR7 family, `rars::rar15_40` for RAR
1.5 through 4 (so compressed RAR4 chases in-stream too, and is not a
materialize-then-unpack case). `extract/sevenz.rs` and `extract/zip.rs` do the same
job for those containers; `extract/crypto.rs` decrypts
at write time so an encrypted set yields plaintext once rather than assembling
ciphertext for a finish pass, and it walks password chains where a layer's password
is packed in the layer above it. Nested archives are unwrapped in place to a
configurable depth (`extract/shape.rs` tallies how often that fires).

What still finishes after the last article: RAR 1.3/1.4, which has no chase and is
read only by the blocking `rars::ArchiveReader` on the disk side; self-extracting
archives (the archive does not begin at offset 0), spanned zip (`.z01`) and rarer
zip variants, plain `.001` split runs with no archive header
(`nzbfast/src/splitjoin.rs`), any job
resumed after a restart, and any set that demoted mid-flight because it breached
the held-bytes budget or hit a bad CRC. Those go to the disk unpack ladder in
`crates/nzbfast`, which unpacks **every** archive family present in a directory
rather than stopping at the first one that claims it. `extract::ArchiveShape` is
the live account of which of these happened, published mid-download and rendered
by the dashboard ("RAR5 · stored · one-pass", "zip · compressed · partly on disk").

External unrar exists only behind the `prefer_external_unrar` setting; obfuscated
sets always use the native path.

## 7. Journal and resume (`nzbkit/src/journal.rs`)

An article-level journal is bound to its NZB by an md5 of the NZB bytes. Placement
lines record where each article's bytes physically went (plain slot file, extracted
file, or scratch), so on restart recorded articles are skipped instead of refetched,
including articles that were direct-extracted and have no slot file of their own.

## Concurrency

All stages overlap; the pipeline is one pass over the bytes.

```
 pool workers (N conns,        decode threads          disk / extractor
 pipelined window)             (<= cores)
 ┌────────────┐  raw articles  ┌─────────────┐  spans  ┌────────────────┐
 │ NNTP fetch │ ─── mpsc ────> │ yEnc decode │ ──────> │ pwrite at final │
 └────────────┘                │ + CRC       │         │ offset / RAR map│
       │                       └──────┬──────┘         └────────┬───────┘
       │ par2 main first              │ block hashes            │ tail only
       v                              v                         v
  download ─────────────────────────────────────────────────────────────>
  verify (live)      ─────────────────────────────────────────────>
  extract (map + chase)  ──────────────────────────────────────────────>
  repair                                                    ──────────>
```

Download, in-stream verify and extraction run concurrently on the same article flow,
for stored and compressed content alike: the chase decoder consumes volumes through
the frontier buffer as they arrive rather than waiting for the set. What extends past
the last article is repair of damaged blocks, and the disk unpack ladder for the
shapes listed in section 6.

## Daemon layer (`nzbfast/src/serve/`)

The same pipeline runs under a queue daemon with a SABnzbd-compatible API subset, so
Sonarr/Radarr/Prowlarr work unmodified. One download runs at a time at full speed; a
sidecar pipeline may prefetch the next job on idle servers, or on a capped one or two
connection slice borrowed from busy hosts when no healthy idle server exists.

- `mod.rs`: startup, settings merge, and the HTTP loop: a `tiny_http` server with a
  small worker pool over the shared listener, plus the watch-folder poller.
- `daemon.rs`: the shared `Daemon` state (queue, history, index, wall).
- `job.rs`: job lifecycle: run, post-process, finalize names, file into history.
- `api/`: the `/api` `mode=` dispatch, split by domain (queue, config, servers,
  system, index, wall).
- `sabcompat.rs`: the SAB version string and warning shapes the *arrs feature-gate on.
- `tasks.rs`: background enricher (posters/metadata) with per-provider rate limits.
- `settings.rs`: the single settings table behind `get_config` and `apply_setting`.
- `stream.rs`: `.strm` pointers and play-while-downloading media picks.
- `assets.rs`: dashboard HTML and icons embedded at compile time; one self-contained
  binary.

## Further reading

- `README.md`: what nzbfast is and how to run it.
- `docs/ENVIRONMENT.md`: every environment variable the code reads.
- `docs/MANUAL.html`: the user manual the daemon serves at /manual.
