# The CREATE's row gate at 4 MiB on GFNI-256, on a STRUCTURED payload, 16 Sep 2026

Lane `create-rowgate-4mib-payload-control`. The payload control for the
landed round in `rounds/crg4-2026-09-16/`, whose section in
an internal note is "The CREATE at
4 MiB: it crosses BELOW the repair, and 416 is the wrong rung for it"
and whose FIRST STATED LIMIT is this round's whole subject:

> **ONE PAYLOAD.** The fixture is 16 members of `RandomNumberGenerator`
> bytes, the friendliest possible input to a fold, and the crossover is a
> property of that payload as much as of the block size.

Everything is held identical to that round except the member CONTENT.

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 16 cores, 31.4 GB,
  Windows 11 build 10.0.26200), under the per-box rig lock.
- **Binary** parfast built on the box from `06d5734b7` - the commit the
  landed create round and both 4 MiB repair rounds built. Expect
  4,173,312 bytes; the sha256 differs from the landed round's
  `fddb6aa3...` only because the build embeds its own path.
- **Harness** origin/main's `wcomb.ps1` and `plib.ps1`, NOT the copies
  `06d5734b7` carries - that tree predates `-Residency`,
  `Wait-FixtureSettle` and `-Payload`.
- **Fixture** 16 x 1,024 MiB at 4 MiB blocks, `-c640`: n = 4,096, a
  16 GiB corpus. Identical in SHAPE to the landed round.
- **PAYLOAD `text`** - the one moving part. See below.
- **Rungs** 320,352,384,416,448 - the four the chip asked for plus 320.
- **Arms** `fold force force2 fold2` at every rung, so every cell carries
  its own A/A pair, and both pools in one ladder (`-Threads 4,16`),
  exactly as the landed round ran them.

## The payload, and why this one

`-Payload text` is new in `wcomb.ps1` as of this lane. It builds a pool
of at least 32 MiB from the round's OWN SOURCE TREE - `crates`, `docs`,
`research` and `web`, sorted by full path, filtered to source and text
extensions - and tiles it across the 16 members, rotating each member
7 MiB + 1 byte against the last so no two members are byte-identical and
no two share a chunk-boundary alignment.

Three things this is NOT, deliberately:

- **not a constant or low-entropy filler.** That is as unrepresentative
  as random bytes, in the other direction, and would price a case nobody
  posts.
- **not a synthetic generator.** A Markov or zipf source would be
  reproducible only through the script that wrote it; a reader could not
  rebuild the pool independently.
- **not `target\`.** The fixture is built AFTER the cargo build, so a
  bare `-Recurse` over the source root would have pulled in ~10 GiB of
  build artifacts - minutes of enumeration, and a payload that depends on
  the toolchain rather than on a commit id.

Measured on the Mac over the same four subtrees of `06d5734b7`: the first
33,604,204 bytes are 1,018 files, 99.5% of them `.rs`, at a Shannon
entropy of **4.761 bits/byte** against random's 8.000. The log stamps the
pool's byte count, file count, sha256 and its own 8 MiB entropy figure on
a `PAYLOAD-POOL` line, and `payload=` is stamped on EVERY `LEG` line, so
no reducer can fold two payloads into one column.

A non-random payload also gets its OWN fixture directory
(`fix-<slice>-<mib>-<payload>`), because the builder only runs when
`gold.txt` is absent: a shared directory would have served random bytes
to a text round and stamped `payload=text` on every leg of it.

## Why 320 is on the ladder and the chip did not ask for it

The chip set four rungs, 352/384/416/448, bracketing the landed
crossovers of ~381 (`-t4`) and ~365 (`-t16`). That set is symmetric about
the crossovers but the EXPECTED MOVE is not. Section 32 of
an internal note measured text **1.55x dearer than
random** on this ISA for a per-code constant; a dearer fold raises F/T,
and a higher F/T moves the crossover DOWN. From 365, a move of more than
13 rows would leave the four-rung set able to say only "below 352" -
unreadable in exactly the direction the payload is most likely to push.
320 costs 8 legs, about five minutes, and turns that into a read. It is
also the rung the landed round's own eight-rung ladder started at, so the
cell is directly comparable.

## What happened, and what is in this directory

Two logs, because the round ran TWICE and the first one is evidence rather
than an embarrassment to be deleted.

- `coreultra9-gfni256-create-4m-n4096-text-build-fixture-round1-failed.log`
  Round 1, 19:16:38Z-19:40:13Z. It built the binary (`rc=0`, 118.7 s), built
  the payload pool and the 16 GiB text fixture (`CREATE rc=0`), and then ran
  **ZERO legs** and exited `rc=1` on MY OWN QUOTING BUG - `-Threads '4,16'`
  single-quoted through `cmd /c powershell -File`, which passes single quotes
  through literally, so `[int]"'4"` threw at `wcomb.ps1:821`. The 20-minute
  `FIXTURE-SETTLE` timeout above it is a consequence of that same run's
  fixture write, not the cause of the failure: SearchIndexer and MsMpEng were
  at 80-103% of a core working through the fresh extract and the 16 GiB
  write. It is kept because it carries the PAYLOAD-POOL line, the binary
  identity, and a clean measurement of what a fresh 16 GiB fixture does to
  this box's foreign CPU.
- `coreultra9-gfni256-create-4m-n4096-text-t4-t16-ladder.log`
  Round 2, 19:47:54Z-20:11:19Z, `rc=0`. **40 legs, all `rc=0`, all `match=1`,
  all `restored=16/16`.** Unquoted list parameters, `-NoBuild`, and round 1's
  fixture REUSED - so this run built nothing, never settled (wcomb settles
  only a fixture it has just built), and ran at foreign-CPU medians of 9-10%
  of a core.

Reduce either with:

    python3 harness/rowgate.py read <log>

## Result

Crossovers **~385** (`-t4`) and **~358** (`-t16`), against the landed
random-byte round's **~381** and **~365**: **+4 and -7 rows**. Both inside the
joint uncertainty of the two reads and far inside the 15 rows that would have
mattered. The 384-over-416 recommendation survives with its ranking unchanged.
Written up in an internal note, section "The
payload does NOT move the create's 4 MiB crossover".
