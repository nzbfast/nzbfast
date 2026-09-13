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

**Name the 7-Zip binary; do not take it from PATH.** A bare `7zz` tool
resolves to whatever the shell finds, and on 6 Sep 2026 that was Homebrew's
`sevenzip` 26.02 on the dev Mac and Ubuntu's `7zip` 23.01 on the VPS, both of
which refuse every RAR 7.23 `-m3` shape with `Unsupported Method` in about
30 ms (distribution builds ship without the unRAR-licensed RAR decoder) while
the 7-zip.org build of the SAME version string extracts all of them. The
harness recorded the refusals faithfully, as designed, and a whole column was
about to be published as "7-Zip cannot read these archives". Pass
`--tool-bin 7zz=~/shapes-round/bin/7zz` (the upstream binary the shapes
round installs) and check the first `7zz` leg of a new box reads `ok` before
trusting the rest.

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

## Running the CREATION race

`crace.py` (and its Windows twin `crace.ps1`) time archive CREATION over
the same payloads: `rar a` against `rar5cli`, the thin `rar a`-shaped CLI
over the RAR 5 writer in `vendor/rars/examples/rar5cli.rs` (build it with
`cargo build --release -p rars --features parallel --example rar5cli`),
with 7-Zip as a different-format context column. Shapes: store, store
in 125 MB volumes, `-m3` single and in volumes, the repeated payload, the
400 small files, and encrypted store. Two arms of ours run: `ours` at the
writer's DEFAULT dictionary - 128 KiB through 7 Sep 2026 and 2 MiB from
8 Sep 2026, so that column is not comparable across the boundary - and
`ours32` at 32 MiB, which is
rar's own `-m3` default (`rar vt` says `-md=32m`), so the ratio column is
read at equal dictionaries. Every RAR output, rar's included, is verified
with `unrar t` before its cell counts; every cell records wall, the
child's own user/sys and peak RSS (`wait4`, not the children total),
packed bytes and volume count. Rounds rotate the tool order and then run
it mirrored, as `--layout mirror` does above.

```
crace.py --payload DIR --work DIR --rounds N --tools rar,ours,ours32,sevenz \
         --bin rar=PATH --bin ours=PATH --bin sevenz=PATH --unrar PATH [--only s,...] [--label box]
```

**The writer has no product CLI.** `rar5cli` reads every input whole
before it writes, because the writer takes slices; on the stored shapes
that read-then-write is the whole difference from `rar`, which streams,
and the write-up says so. Added 5 Sep 2026 for the public-position round.

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

## The TEN SCENARIO LEGS - what the published PAR2 numbers are measured on

Added 6 Sep 2026, and this is now the sample set: ten shapes named by the
download a reader actually has, not by a block count. `par2rig-build.sh` and
the `verify / rep3 / rep101 / heavy` legs above stay as they are so the older
figures remain reproducible, but a new number belongs on a scenario row.

`par2-scenarios-build.sh <root> [rar] [par2-creator]` builds every fixture,
each payload a prefix of the ONE fixed-seed stream `corpusgen` writes
(`corpusgen rand <file> <bytes>` was added for this: it hands out any length
of the same sequence `rand.bin` carries, so 10 GiB of scenario payload has
rand.bin as its own head and no second seed enters the rig).

| row | what the reader has | fixture | recovery | damage |
|---|---|---|---|---|
| 1 | a TV episode with two articles missing | 1.5 GiB, 21 RAR volumes | 10% at 1 MiB | 2 articles in one volume |
| 2 | a movie with holes across several volumes | 10 GiB, 21 volumes | 10% at 1 MiB | 12 articles over 3 volumes |
| 3a | a provider missing a whole stretch | the same 10 GiB fixture | 10% at 1 MiB | 100 contiguous articles |
| 3b | one volume that arrived almost empty | the same | 10% at 1 MiB | 662 contiguous articles |
| 4 | a volume that fell off retention | the same | 10% at 1 MiB | one member absent |
| 5 | a pars-only post: the pars do all the work | 1 GiB single member, and the 21 volumes | 100% and 110% at 1 MiB | every data file absent |
| 6 | a download that arrived clean | the same 10 GiB fixture | 10% at 1 MiB | none, verify only |
| 7 | a poster making pars before upload | 10 x 1 GiB members | 10% at 1 MiB and 4 MiB | n/a, creating IS the leg |
| 8 | an album with a missing article | 600 MiB single RAR | 5% at 512 KiB | 1 article |
| 9 | a post with most of every volume gone | 1 GiB, 21 volumes | 10% at 64 KiB | the 1,500-block map |
| 10 | a sports broadcast: one obfuscated mp4, no RAR | 2.4 GB single member | 2% at 1.2 MB | 1 article; and a clean verify |

The sizes are the census modes measured over 189 random PAR2-bearing releases
over 1 GB: 10-15% redundancy is the largest bucket, 0.5-1.5 MiB the largest
slice bucket, and 2k-10k data blocks is where two thirds of sets sit. Rows 8
and 10 are the small-post and bare-media tails of the same survey. **Row 5 has
no measured wild population at all** - the census class that would hold it
turned out to be ordinary sets whose payload half the index had not grouped -
so it stays on the rig as the transform-bound extreme and any page carrying it
has to say so.

Rows 2, 3a, 3b, 4 and 6 share ONE 10 GiB fixture; the damaged copies are APFS
clones, so eight of them cost the blocks they damage rather than 80 GiB.

**The sets are created by the RIVAL** (par2cmdline-turbo), on purpose: a
shootout whose fixtures came out of our own creator invites an obvious
question about whose block layout the repair arm is tuned for, and answering
it later costs more than the build time does now.

### Damage is recorded in ARTICLE units

`apply-damage.py` grew a second map dialect for these legs. A block map
(`map-*.txt`, first line a block size) flips one byte mid-block, as before. An
article map (`amap-*.txt`, first line `ARTICLE <bytes>`) ZERO-FILLS whole
768000-byte yEnc article spans, and takes `DELETE <file>` for a member that
never arrived:

```
ARTICLE 768000
feature.part03.rar 61          # one article gone
feature.part09.rar 200-299     # a contiguous run gone
DELETE feature.part13.rar      # the whole member off retention
```

Two things about that are deliberate. The span is zeroed rather than flipped
because that is what the wire does - an article that never arrives leaves a
hole, and a flipped byte is a different fixture, a corrupted article that DID
arrive. And the article is the unit because the row title is the reader's
sentence: "two articles missing" is the input, and the block count is a
CONSEQUENCE of it (a 750 KiB article straddles a 1 MiB slice boundary, so two
articles are usually four damaged blocks). Pass `--block-size N` and the
script reports the block count the map implies, which is the number the
results page carries in its footnote.

### Running them

```
round2.sh <row|all> <rounds> <scenario-root> <parfast-bin> [tools]
round2.ps1 -Leg <row|all> -Rounds N -Ours <parfast.exe>     # SCENROOT env
```

Rows: `row1 row2 row3a row3b row4 row5s100 row5s110 row5m100 row5m110 row6
row7a row7b row8 row9 row10 row10v`. Arms: `parfast turboT turbo turbo140
parpar` (creates only) `rarpar classic`, plus `par2j` (MultiPar) on Windows,
plus the rival-survey arms `turbo120 gopar par2rs` (`par2rs` verify/repair
only, never creates; `gopar` needs `-g` on Apple silicon or it panics -
round2.sh passes it, see the script's own header).

The protocol is the published one, and it is stricter than the legs above:
each round runs the tool order forward and then MIRRORED, idles `SETTLE_MS`
(default 1000) between legs outside every timed region, records wall, CPU and
peak RSS rather than wall alone, and gates every repair against the pristine
`.sha` the build wrote. A tool that finishes fast without fixing anything
reports `sha=MISMATCH`, not a winning time. Mirroring is not politeness: an
A/A on this rig has read 5-7% between byte-identical binaries from position
alone, so run `aa-protocol.sh` on any box before believing a sub-10% delta
measured there.

### Slice size on the create legs: the 4 MiB leg is RETIRED

`round2.ps1 -Slice N` and `SLICE=N round2.sh` override a row's slice size in
bytes, and the create `LEG` line records it as `slice=N`.

**row7b was a 4 MiB leg until 7 Sep 2026 and is now 1,536,000 bytes**, because
4 MiB describes nobody. Of the 189 random PAR2-bearing posts over 1 GB in the
survey, the slice sizes that repeat are:

| slice | posts | note |
|---|---|---|
| 1,048,576 (1 MiB) | 29 | the mode, and the median of the whole sample |
| 768,000 | 20 | |
| 716,800 | 14 | |
| 1,536,000 | 7 | |
| 5,242,880 (5 MiB) | 5 | the largest value with a real population |
| 4,194,304 (4 MiB) | **0** | |

Banded, 512 KiB to 1.5 MiB is 54% of posts and the 3-5 MiB band that held the
old leg is 6.9%. Note that most of these are NOT round numbers: tools derive
the slice from a target block count, so only 20% of posts use any multiple of
1 MiB at all. A rig that only ever races power-of-two slices is racing a shape
the wire does not have.

Two things follow. A create sweep should walk the values above rather than
doubling from 1 MiB, and 5,242,880 is the honest "large slice" leg since the
5-20 MiB band is 11.6% of posts against the retired band's 6.9%.

### Redundancy on the create legs, and why it defaults to 10

`round2.ps1 -Redundancy N` and `REDUND=N round2.sh` set the recovery
percentage every create arm asks for, and the create `LEG` line records it as
`r=N` so two sweeps are never indistinguishable in one log.

**The default is 10 because 10 is the census MODE, not the middle of a
bucket.** The published survey reports a `10-15%` band, which reads as though
15 were a live candidate; the raw rows say otherwise. Of the 189 random
PAR2-bearing posts over 1 GB, **65 sit at exactly 10% and 2 at exactly 15%**.
The distribution is spiky at posting-tool defaults rather than smooth: 10 is
the modal value for ParPar, MultiPar's par2j and QuickPar taken separately,
par2cmdline's own 8% default supplies a second cluster at 8-9% (27 posts), and
a third sits at 18-20% (20 posts, 10.6%) from posters who raise it.

So a second column, if a page carries one, is **20%** and never 15%. And it is
a SENSITIVITY line rather than a second population row: it answers "does the
lead depend on redundancy", which is a property of the tools, not "what do
people post", which is answered above and is 10.

Redundancy is a direct multiplier on CREATE work and very nearly none on
repair: a repair consumes as many recovery blocks as there are missing blocks,
so a 20% set fixing two articles does the arithmetic a 10% set does. Sweeping
it on the repair rows measures the verify's parity hashing and little else,
which is why only the create rows take the parameter seriously.

`rarpar` is an arm on the RAR-shaped rows only. It has nothing to extract on
the pars-only rows or the bare mp4, and a blank cell there is the tool being
out of scope rather than losing.

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

- **A timed leg that discards its streams publishes refusals as wins.** On
  9 Sep 2026 a 65 GiB publication round recorded `wall=12.3` against a
  rival's 1,413.6 s and read as 115x. parfast had DECLINED the solve as over
  its memory budget, named the budget and the environment variable that
  raises it on stderr, and exited 5; the harness sent both streams to
  `/dev/null`, never read `$?`, and inferred success from a restored-file
  count. Two sessions built a 20x-scaled reproduction and ruled out three
  hypotheses before anyone re-ran the leg with the streams kept. The rule:
  **any invocation whose wall time is recorded captures its exit code and
  keeps its stderr, and a leg whose tool exited unexpectedly is a failure,
  never a time.** `bench/lib/legrc.sh` is the helper (`leg_timed`,
  `leg_flag`); the harnesses here run every timed arm through it and print
  the stderr directory at the top of the round. **The exit code does not
  replace the output gate** - a tool can exit 0 having produced the wrong
  bytes, which is what the sha/cmp check catches. Both gates, always.
- **`rc != 0` is the WRONG test for at least one tool here.** MultiPar's
  `par2j` returns **16 after a SUCCESSFUL repair** (its own docs: "16 =
  repair succeeded"). The per-tool success codes live in `bench/rc-ok.tsv`,
  which is the single definition - `bench/lib/legrc.sh`'s `rc_ok` and
  `scen-summarise.py`'s `RC_OK` both read that one file, so neither side can
  drift. A new tool with a nonzero success code gets a row there, never a
  second table in a harness. A missing table is an error and not a default:
  defaulting would quietly turn par2j's 16 into a failed leg.
- **`-T` is NOT par2cmdline-turbo's compute-thread knob.** Its own help
  reads `-t<n> : Number of threads used for main processing (12 detected)`
  and `-T<n> : Number of files hashed in parallel`. The arms named
  `turboT` / `turbo16` / `turbo150_16` / `turbo120_16` pass `-T`, so they
  are "turbo with a wide hash fan-out", not "turbo pinned to N compute
  threads". This has never HANDICAPPED turbo - lower-case `-t` defaults to
  the detected core count, so those arms always had every core - and the
  arm names are kept so the older numbers stay comparable. Found 9 Sep 2026
  reading turbo's own `--help` while checking a round's flags.
- **Two lanes on one box do not just contend - they overwrite each other's
  fixture.** `round2.sh` copies the row into ONE work dir per box
  (`$TMPDIR/parscen-work/r`), so a second round running at the same time
  replaces the bytes between the prepare and the timed region and the leg
  times another row entirely. On 7 Sep 2026 two chips claimed the M1 four
  minutes apart and the row5m100 legs ran over the other lane's row1 tree:
  0.43 s and 1.01 s, `sha=MISMATCH` on BOTH arms, which reads like a broken
  fixture rather than a second lane. The script now takes a lock on its work
  dir and refuses with exit 3, naming the holding pid; a second lane that
  really must share the box passes `W=$TMPDIR/parscen-mine`. That still leaves
  the CPU contention, so a published number wants the box to itself either
  way - which is what `COORDINATION-*.txt` is for.
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
