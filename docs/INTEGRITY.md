# How nzbfast verifies data integrity

This note documents exactly what nzbfast checks, and when, so the guarantees can
be audited against the code rather than taken on trust. Every claim below cites
the source line that backs it. The interesting design choice is that nzbfast
verifies PAR2 block checksums *during* the download instead of in a separate
pass afterward, and that the in-stream fast path claims a block on its CRC32
alone. This document is about why that is sound, and about the exact boundary
where it stops being sound (lean mode).

All file/line references are against the tree this document was committed with.

## The layered model

nzbfast has five integrity layers. A given block passes through some subset of
them depending on how it was received and which verify mode is active.

1. **Article yEnc CRC32 (`pcrc32`).** Every downloaded article carries a yEnc
   trailer CRC32 over its decoded bytes. The decoder enforces it before the
   bytes are handed to the verifier as a "fresh" span. A span that reaches the
   verifier through `on_data` is asserting that this check already passed
   (`crates/nzbkit-base/src/live.rs:312` documents the `Src::Fresh` contract;
   `:103`-`:104` define `Src::Fresh` as "Decoder-fresh, article CRC passed").

2. **In-stream PAR2 block CRC32 (IFSC).** As decoded spans stream in, each PAR2
   block fully contained in a span is checked against the IFSC packet's per-block
   CRC32 (`crates/nzbkit-base/src/live.rs:767` `check_block_crc`). Blocks that straddle
   article boundaries accumulate in bounded per-file partial buffers and are
   checked once complete (`:411`-`:439`).

3. **In-stream PAR2 block MD5 (IFSC).** In full mode, the same in-stream blocks
   are checked against the IFSC MD5 as well as the CRC32
   (`crates/nzbkit-base/src/live.rs:752` `check_block`: "MD5 + CRC32 must both match").

4. **Settle-time read-back, full MD5 + CRC32.** Any block not claimed in-stream
   (a span decoded before the PAR2 set activated, a boundary block whose neighbor
   article never arrived, a partial spilled because the memory budget was full, a
   missing article) is read back from disk at slot-settle time and checked with
   the full `check_block` (MD5 + CRC32), never the CRC-only path
   (`crates/nzbkit-base/src/live.rs:621`). For a file whose PAR2 set carries no IFSC
   packet at all, settle computes a whole-file MD5 against the FileDesc MD5 as the
   only block-granularity check available (`:585`-`:595`, `src_md5` at `:799`).

5. **PAR2 repair, the final authority.** If any block is bad or any file is
   missing (`damage > 0` at `crates/nzbfast/src/main.rs:2273`), the repair path
   re-reads the whole file from disk and recomputes, independently of every
   in-stream verdict, both the per-block MD5 + CRC32 and the whole-file MD5
   (`crates/nzbkit-base/src/par2repair.rs:1591`-`:1602`). Repair output is accepted
   only when the recomputed whole-file MD5 equals the FileDesc MD5
   (`par2repair.rs:1602`, and `crates/nzbkit-base/src/par2.rs:390` for the standalone
   `verify_file` equivalent). This layer does not trust anything the live
   verifier decided.

## What each mode keeps

There are three verify modes, selected by `--verify` (default `fast`) or the
daemon setting. The dispatch is a single line: fast verify picks `check_block_crc`,
otherwise `check_block` (`crates/nzbkit-base/src/live.rs:457`); lean additionally lets
CRC-only claims stand for spans the decoder did not vouch for.

| Layer | full | fast (default) | lean |
|---|---|---|---|
| 1. Article yEnc CRC32 | yes | yes | **skipped for PAR2-covered files** |
| 2. In-stream block CRC32 | yes | yes | yes |
| 3. In-stream block MD5 | yes | no | no |
| 4. Settle read-back full MD5+CRC32 | yes | yes | yes |
| 5. Repair recompute (if damage) | yes | yes | yes |

- **full**: every in-stream block is MD5+CRC32 checked. This is the
  belt-and-suspenders mode. Choose it if you do not trust the argument below.
- **fast (default)**: an in-stream block is claimed on its IFSC CRC32 alone, but
  the span carrying it already passed its article yEnc CRC32 in the decoder. So a
  block claimed in fast mode has cleared **two independent CRC32s over
  differently-aligned spans** (the article boundary and the PAR2 block boundary
  do not coincide). MD5 is the throughput floor at roughly 0.6 to 0.8 GB/s/core
  versus 10+ GB/s/core for hardware CRC32
  (`crates/nzbkit-base/src/live.rs:29`, `:186`-`:188`), which is why skipping the
  in-stream MD5 is worth doing on fast links.
- **lean (opt-in, slow-CPU boost)**: for files a PAR2 set covers, the upstream
  decoder is told to skip the per-article yEnc CRC32 as well
  (`on_data_unverified`, `crates/nzbkit-base/src/live.rs:335`; `Src::Lean` at `:105`).
  In-stream integrity then rests on the **single** PAR2 block CRC32. Layers 4 and
  5 are unchanged: this is documented in the code as an explicit contract
  ("Settle read-back and repair remain the final authority. Only meaningful with
  fast verify on", `crates/nzbkit-base/src/live.rs:244`-`:252`).

Two facts hold in all three modes and matter for the analysis below:

- A block **claimed OK in-stream is never re-read at settle**. Settle read-back
  only touches blocks still in `Pending` state (`crates/nzbkit-base/src/live.rs:598`).
  So in fast and lean modes, a CRC32-only claim on a clean job is the last word
  for that block unless repair runs.
- Repair runs **only when there is damage** (`main.rs:2273`). On a fully clean
  job, no whole-file MD5 backstop executes for blocks that were claimed OK
  in-stream by CRC32 alone.

## After the download: the settle manifest

The five layers above all run while the job is in flight. They end when it does,
and the `.par2` files that carried the evidence are on the default cleanup list -
so a folder a user comes back to in a year has no PAR2 set to be checked against,
and every verify path in the tree gates on one being present.

nzbfast therefore writes the evidence down at the settle seam instead of
discarding it. A completed job leaves a `.nzbfast.manifest` beside its payload
(`crates/nzbfast-core/src/manifest.rs:71` for the name,
`crates/nzbfast/src/serve/postproc.rs` `settle_manifest_and_deferred_par2_sweep`
for the write). It has two sources, and they are worth telling apart:

- **For a file the PAR2 set covered**, it copies the set's own data rather than
  recomputing anything: the FileDesc whole-file MD5, the first-16k MD5 and the
  IFSC per-block CRC32, read off the parsed set that is still in memory at that
  moment and dropped a few lines later. That half costs serialization only.
- **For a file the set never covered** - the extracted film from an archive
  post, which is the only file most users keep - `grid_from_disk`
  (`crates/nzbfast-core/src/manifest.rs:998`) READS it and computes a CRC32
  block grid, so it is an ordinary payload entry rather than a name-and-length
  stub. That half costs one pass over those bytes. Recovery data and archive
  material a later sweep may legitimately take are deliberately left out of it
  (`the_grid_pass_leaves_recovery_and_archive_material_alone`).

What it is worth, stated exactly:

- **What it checks, exactly, because it is not identical to a PAR2 verify.**
  `Manifest::verify` (`crates/nzbfast-core/src/manifest.rs:540`, `check_entry` at
  `:570`) re-reads the whole file and computes the per-block CRC32 (last block
  zero-padded arithmetically, the same convention
  `nzbkit::par2::verify_file_streaming` uses) plus the **whole-file MD5**, and a
  file passes only if both agree. It does NOT carry the IFSC per-block MD5, so a
  BLOCK-level verdict here rests on CRC32 alone where full-mode PAR2 verification
  has MD5 as well. What it has that a clean fast-mode job does not is the
  whole-file MD5 running unconditionally over every byte: per the two facts above,
  on a clean job no whole-file MD5 backstop executes at all. So the manifest is
  weaker per block and stronger per file than a full-mode verify, and a re-check
  years later is a real check rather than a formality.
- **It cannot repair anything by itself.** There are no recovery slices in it,
  only checksums. It convicts, and a repair then needs the post fetched again -
  which is what the dashboard's *Checking downloads later* card and
  `mode=heal_start` do, adopting every intact byte off the disk and fetching only
  the damaged remainder.
- **Extracted output is covered, but by a grid and not a digest.** Until 2 Sep
  2026 it was presence-only, which meant the one file most users keep could not
  be convicted at all. It now carries a CRC32 grid computed off the disk, so a
  flipped byte is `Damaged` with the block named. It has NO whole-file MD5,
  which is why `FileStatus::Damaged`'s `md5_ok` is an `Option`: `None` means
  "no digest was recorded", a different statement from "it did not match", and
  a damage report must not render it as an MD5 mismatch. What is left in
  `PresentUnverified` is now narrow - a file the grid pass could not read, and
  archive material a later sweep may take.
- **A consumed archive volume is not damage either.** A `.par2` or a volume the
  unpack tail legitimately ate reports as `SourceGone` and is excluded from the
  damage set, or every extracted job would report as broken.

`nzbfast verify DIR` reads the manifest when, and only when, there is no PAR2 set
left to read (`crates/nzbfast/src/main.rs:1340`); PAR2 stays the first choice
because it can repair as well as judge. Damage exits 1 on both arms. A directory
with neither exits 0 and says on stderr that nothing was checked, because a
finished job whose recovery files the cleanup default already removed is the
normal state of a folder somebody points `verify` at, and convicting it would
fail every such folder.

The manifest is written for every completed job by default (Settings →
Downloading → **Checking downloads later**). Turning it off is supported and
loses exactly this layer: the download itself is verified identically either way.

The same card carries the SCHEDULED sweep (`crates/nzbfast/src/serve/healauto.rs`),
which verifies library folders against their manifests on a cadence and repairs
what they convict with nobody clicking. It is OFF by default and its three
ceilings are surfaced beside the switch rather than buried, because an unattended
road that can spend a metered line is only as safe as the bounds a user can read:
hours between sweeps (weekly), repairs one sweep may start (four, hard-capped at
the clicked road's own `MAX_HEAL_JOBS`), and bytes one sweep may commit to
(20 GB, and 0 means "start nothing" rather than "no limit"). The byte ceiling is
charged the WHOLE size of each post rather than the damaged remainder, so a
ceiling honoured in the worst case is honoured in every case; for an
archive-post folder that worst case IS the ordinary case, because the damaged
folder holds the extracted file while a fresh post's PAR2 set describes the
volumes, so nothing on disk can be adopted. The sweep also declines two targets
the clicked road still offers - a post no longer on record here (repairing it
would mean an indexer search for a copy nobody has compared to the disk) and a
post of unknown size (nothing for the byte ceiling to charge) - and counts both
in its log line as left for the manual road.

## Collision math and the residual

The question a hostile reviewer will ask: can a corrupt block pass and survive to
a clean, exit-0 job?

**Random corruption (wire or disk bit-flips).** A CRC32 catches all single-burst
errors up to 32 bits and all odd numbers of bit errors; a random corruption that
happens to leave the CRC32 unchanged has probability about 2^-32.

- *fast mode*: the corruption must leave **both** the article yEnc CRC32 **and**
  the PAR2 block CRC32 unchanged. These cover different, differently-aligned byte
  ranges, so to first approximation the two events are independent and the joint
  probability is about 2^-64 per block. This is stronger than a single MD5
  comparison would need to be lucky to miss, and comparable in practice to
  trusting one 64-bit hash.
- *lean mode*: only the PAR2 block CRC32 gates the block in-stream, so the
  residual for random corruption is about 2^-32 per block. Across a very large
  corpus of blocks this is a real, if small, number: at 2^32 blocks (about 4
  billion blocks, far more than any single job) you would expect one undetected
  random corruption. For a normal multi-gigabyte job of a few thousand blocks the
  per-job residual is on the order of 10^-6 or better.

**Adversarial corruption (a malicious poster).** CRC32 is not collision
resistant. An attacker who controls the posted bytes can craft a block that
matches a target CRC32 while differing from the intended content. This is the
honest weak point:

- In **fast** mode the attacker must also make the crafted block satisfy the
  article yEnc CRC32 that the poster themselves computed over the article. Since
  the poster controls both, this is not an independent obstacle against a
  malicious poster; it only stops a third-party in-path tamperer who cannot
  recompute the article CRC. Against a malicious poster, fast mode's protection
  against a crafted-CRC32 block reduces toward the block-CRC32-only case.
- In **lean** mode there is a single CRC32 and it is the poster's own, so a
  crafted block that matches CRC32 but not the IFSC MD5 would be **accepted
  in-stream on an otherwise clean job**, because layer 4 never re-reads a claimed
  block and layer 5 never runs without damage.

**What closes it.** The IFSC packet carries an MD5 per block, and the FileDesc
carries a whole-file MD5. Those are collision resistant for practical purposes.
They are always checked in two situations: (a) full mode checks the block MD5
in-stream, and (b) the repair path recomputes block MD5 and whole-file MD5 the
moment any damage exists (`par2repair.rs:1591`-`:1602`). So the residual above is
precisely: *a job where every block passed its CRC32 gate in-stream, nothing
triggered repair, and the corruption was crafted to match CRC32 but not MD5*. In
default (fast) mode that requires beating two independent CRC32s or being the
poster; in lean mode it requires only a poster-crafted CRC32 collision.

**When not to use lean.** Lean is the slow-CPU throughput option (about 7% more
single-core throughput, `crates/nzbfast/src/main.rs:127`-`:132`). Do not use it
when the source is untrusted and undetected substitution of block content that
still repairs to a clean CRC32 would matter to you. Use `full` if you want every
block MD5-checked in-stream regardless of source. Fast (the default) is the
intended balance for the normal case of trusted-enough providers plus random wire
corruption, where the two-CRC32 argument holds.

## For comparison

Conventional downloaders verify after the download completes, as a distinct
end-of-download pass that recomputes the full block checksums. nzbfast instead
folds verification into the download and finishes with the last article. Both
models end at the same place when there is damage, a full PAR2 recompute and
repair. The difference nzbfast introduces is on the *clean* path, where fast and
lean modes let a CRC32 claim stand in-stream rather than paying for a second full
read plus MD5. This document
exists so that difference is on the record as a deliberate, bounded trade rather
than a discovered corner cut.
