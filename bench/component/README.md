# Component shootout: how the published RAR and PAR2 numbers are made

Everything on the benchmarks page's "component shootouts" section comes from
the scripts in this directory. They are here so the numbers can be reproduced,
continued, or argued with. An earlier round's recipe was never written down and
those figures could not be reproduced a month later, which is a bad way to
publish a benchmark.

Nothing here is part of the product. It is a bench rig.

## What gets built

`corpusgen.rs` writes four payloads, byte-for-byte identically on every
machine, from a fixed-seed xoshiro256\*\* stream:

| payload | size | character |
|---|---|---|
| `rand.bin` | 1 GiB | incompressible |
| `mixed.bin` | 1 GiB | equal thirds text, structured records, incompressible bytes, with long-range replays |
| `rep.bin` | 1 GiB | 1 MiB of material repeated |
| `small/` | 400 files, 1 GiB | same mixed material, one seed per file |

The payload character is not a detail. A payload built out of block copies
turns every compressed shape into a `memcpy` benchmark; a payload of pure text
turns it into a literal-and-Huffman benchmark; the two do not agree on who
wins. `mixed.bin` is deliberately in the middle, and the `store` and `rep`
shapes cover the two ends on purpose.

`mixed.bin` replays 1 MiB spans from up to 384 MiB back at roughly one slice in
five. That is what makes the 128 MiB-dictionary shape mean anything: those
matches are reachable with `-md128m` and not with the 32 MiB default.

## The seven archive shapes

`shapes-build.sh` turns those payloads into archives with RAR 7.23:

| shape | input | flags |
|---|---|---|
| `store` | `rand.bin` | `-m0` |
| `small` | `small/` | `-m3` |
| `solid` | `small/` | `-m3 -s` |
| `rep` | `rep.bin` | `-m3` |
| `big` | `mixed.bin` | `-m3 -v125m` (4 volumes) |
| `enc` | `mixed.bin` | `-m3 -hpbenchpw` (encrypted headers) |
| `r7dict` | `mixed.bin` | `-m3 -md128m` |

Two flags on every archive matter more than they look:

- **`-ep`**, so archives store bare names. An earlier corpus stored absolute
  paths on some shapes only, and the extractors that recreated the directory
  chain on those legs alone looked slow for a reason that had nothing to do
  with extraction.
- **`-tsm- -tsc- -tsa- -mt4`**, so the archives are byte-identical on every
  machine. Dropping timestamps is obvious; pinning the compressor to four
  threads is not. RAR's block split follows the host core count, so a 32-core
  box and a 20-core box otherwise produce different bytes from the same input,
  and the machines stop being comparable.

The encrypted shape is the one exception to byte-identity: its AES salt is
random by construction, so the archives differ while the compressed stream
underneath does not.

## Running the extraction race

`shootout.rs` is the harness. It is one file with no dependencies because it
has to build with plain `rustc -O --edition 2021` on a box with no cargo:

```
shootout manifest <payload-dir> <manifest-file>
shootout race --shapes D --work D --manifest F --rounds N --tools a,b,c \
              [--only shape,...] [--tool-bin name=path ...] \
              [--reps N] [--layout rotate|mirror] [--settle-ms N]
```

Per run it makes a fresh output directory, reads every input byte to warm the
cache, times the child process, and then compares a content fingerprint of the
output against the manifest. A tool that drops or corrupts a member reports
`WRONG-OUTPUT` rather than a fast time; a tool that cannot do the job at all
reports the reason it gave. **A blank cell is not an acceptable result for any
competitor**, which is why the harness records failures verbatim.

Tools are interleaved inside each round rather than run in blocks, so a machine
that warms up or throttles part way through affects every tool equally.

**Interleaving is necessary and it is not sufficient, and the three protocol
flags are why.** Rotating the tool order by round balances how often each arm
runs first; it removes a position bias only if that bias is the same on every
shape it is balanced over, and on Windows/NTFS it is not - audit round 25's
A/A (one binary against a byte-identical copy of itself, six rounds, balanced
positions) read +5.0% on `storev` and -7.3% on `encstorep`, so the two halves
did not cancel and a +4 to +7% "regression" on the stored shapes was published
into round 24 as a finding before the A/A retired it. `--layout mirror` runs
each round's order and then its reverse, so both arms hold both positions
inside one shape's own visit; `--settle-ms N` idles between legs, outside every
timed region, so what a leg inherits from its predecessor is the same for every
leg rather than a function of position; `--reps N` repeats the sequence inside
a round so the round yields a median. All three default off, so a bare `race`
is byte-for-byte the old experiment.

`aa-protocol.sh` (and its Windows twin `aa-protocol.ps1`) runs that A/A under
each protocol in turn on a given box, and `aa-position.py` reads the LEG lines
back as "is this box separable at all" rather than "who won": per-arm medians
over per-round medians, the paired win count that catches a 0/N or N/N sweep,
the median by position with the arms folded away, and the between-leg
instrumentation (`gap_ms`, `tear_ms`, `fp_ms`) that lets a position effect be
attributed rather than guessed at. **Run it on any box before believing a
sub-10% two-arm delta measured there.**

## Running the PAR2 race

`par2rig-build.sh` builds the PAR2 corpus: 1 GiB of non-periodic random payload
packed store-mode into 21 RAR volumes of 50 MB, then two PAR2 sets at 10%
redundancy - 1 MiB blocks for the standard legs, 64 KiB for the heavy one -
then three fixed damage maps (3 blocks in 2 volumes, 101 in 6, 1500 across all
21). The payload must be truly random: one with 32-byte periodicity inflates
par2cmdline-turbo's sliding-scan work and flatters us by about 7% on the heavy
leg.

`round2.sh <leg> <rounds> <root> <ours-bin> [tools]` runs it, with the same
protocol as the extraction race - fresh copy, explicit pre-warm, then time -
and compares every repaired volume against the pristine set on every round.

`rev-race.sh` is the `.rev` recovery-volume leg.

`apply-damage.py` applies a recorded damage map (`map-*.txt`: block size on
line 1, then `<volume> <block index>`) to a copy of a pristine set. It is the
portable twin of the rig's `assemble.ps1`; before it existed only Windows
could reproduce a map, so the Macs re-rolled damage from a seed instead.

`par2-ifsc-surgery.py` makes the two VERIFY shapes a creator will not write,
because both need slices the set describes but carries no checksums for -
`BlockCheck::UNPROVEN` cells. `--keep N` truncates every IFSC packet to its
first N entries, and the parser pads the grid out with placeholders; `--zero
A:B` writes the reserved all-zero MD5 into a range of wire entries, which is
the only way to get an INTERIOR unproven gap rather than an unproven suffix.
Both reseal the packet MD5. Pair either with a payload whose length disagrees
with the descriptor (append or truncate a byte) to reach the POSITIONED
diagnostic path at all: a legal-size member spends its time in the whole-file
MD5 and never gets there, which is how a verify measurement can miss the code
it was aimed at. Added 3 Sep 2026 for the verify-lane race in
`research/PAR2-TWO-LANES-COMPARED-2026-09-03.md`.

## Measuring what a PAR2 pass costs the REST of the box

Every leg above times the PAR2 process. None of them time the machine
around it, and a 23 GB verify used to pull its whole payload through the
page cache and evict whatever else was resident. `par2-cache-round.sh`
measures that half, for the read-side cache policy in
`crates/nzbkit-base/src/disk/readpolicy.rs`.

`resident.c` is the metric: `mincore(2)`, one bit per page, so the answer
is a page COUNT of what survived rather than a timed re-read. It reads
only, and never touches the file it counts.

`par2-cache-round.sh --bin DIR --rig DIR [--ws FILE] --phase evict|warm`
runs the paired legs. `evict` leaves the payload cold with an unrelated
working set resident and reports how much of that working set is still
there afterwards; `warm` leaves the payload resident and reports only the
wall, which is the "must not regress" arm. Arm order alternates between
reps and the position is on every row.

**The working set has to be big enough to force the question.** Sized so
that payload + working set exceeds usable page cache, or the baseline arm
simply fits and a small eviction is indistinguishable from noise. The
script does not choose it for you.

**Both arms are one binary**: `NZBFAST_READ_HINTS=0|1` picks the policy at
run time, and the script refuses a binary that does not carry the knob.
That is the answer to this directory's most expensive trap (below): a
candidate that is secretly the baseline.

`readscan.c` is the same read loop in ~90 lines of C - open, read front
to back, optionally `POSIX_FADV_SEQUENTIAL` and `POSIX_FADV_DONTNEED`
behind the reader. It exists for a device class whose only representative
has no compiler and a libc older than any host we build on: `cc -static`
and it runs there.

## Running the recovery-record race

`rr-build.sh <root> <payload> <rar> [sizes]` then
`rr-race.sh <root> <rounds> <ours-bin> <rar> [sizes]` cover the inline `-rr`
leg. Both moved in-repo from a session scratchpad, where the race carried a
hardcoded worktree path that no longer resolves and built its corpus from
`/dev/urandom`, so no two runs shared a corpus. The payload is now a prefix
of the same fixed-seed `rand.bin` everything else uses.

**Time the right recovery path.** `bench_rr_product` drives
`ArchiveReader` -> `repair_recovery_to_file`, which is what the daemon takes
whenever the headers still parse. `bench_rr_stream` drives the raw `{RB}`
marker scan used only when headers are unreadable. Payload damage leaves
headers intact, so timing the stream driver measures a path no user reaches
on that input - an earlier round did exactly that and published it.

## The `oursntt` contestant

`round2.sh` and `round2.ps1` accept `oursntt` alongside `ours`. It is the
same binary with `NZBFAST_NTT=1`, which enables the experimental NTT syndrome
path. **That gate is OFF by default**, so `ours` is what a user gets today and
`oursntt` is what flipping the default would buy. Publishing the `oursntt`
number as our number requires the default to move first - that is a release
decision, not a benchmark one.

## Traps, each of which produced a wrong answer at least once

- **Check the box is idle before trusting anything.** `top -l 1 | grep CPU`.
  A closed session once left 64 busy-loops running and every number was
  inflated 2-12x, including a competitor's, which would have read as a crushing
  win for us and been fiction.
- **Build bench drivers with `-F rars/parallel`.** `crates/nzbkit` depends on
  `rars` without that feature - only `crates/nzbfast` enables it - so a driver
  built `-p nzbkit` alone runs serial decode and reads about 50% slow.
- **Time the binary, never `cargo run`.** The build check adds ~0.15 s to
  whichever side you run that way.
- **Pre-warm explicitly.** macOS `cp -c` is an APFS clone, so the source pages
  stay cached and the copy is warm; a Windows `Copy-Item` really copies a
  gigabyte and is cold. Without an explicit pre-warm the two platforms measure
  different things. It moved one macOS verify leg from 0.220 s to 0.118 s, so
  `cp -c` alone is not warm either.
- **`ourrars` is not the product.** `vendor/rars/examples/ourrars` attaches no
  execution policy and runs a configuration nobody ships. The extraction
  contestant is `crates/nzbkit/examples/prodrar`, which takes the same options
  object the daemon does; the `.rev` contestant is `prodrev`, likewise.
- **The three rigs do NOT all hold the same PAR2 corpus, whatever the older
  rig notes say.** Measured 31 Jul by hashing the volumes: the M3 and the
  Windows laptop are byte-identical, and the M1 holds a different random
  draw of the same shape (21 volumes, same sizes, same block sizes, damage
  verified as 3 blocks in 2 volumes / 101 in 6 / 1500 in 21). That is fine for
  every published claim, because each row compares tools *within* one machine
  on bytes all of them share. It is not fine for reading one machine's row
  against another's as if the input were the same, and payload character is
  known to move turbo's scan by ~7%. Bringing the M1 into line means shipping
  ~2.3 GB to it, and the link measured 0.47 MB/s, so it stays as it is; say
  which corpus a number came from rather than implying one corpus.
- **`cargo test` can silently re-install a serial driver.** Running
  `cargo test --release -p nzbkit` reinstates a cached
  `target/release/examples/prodrar` built *without* `rars/parallel`. It races
  ~2.5x slow and reads as a catastrophic regression. Always rebuild with
  `-F rars/parallel` immediately before copying any contestant binary.
