# What a stripe-first BAND PASS costs the create: three to five rows, and the sign is not even fixed (16 Sep 2026)

Lane `create-band-pass-cost`, the question item 4 of "The windowed CREATE
ladder" left open in
an internal note: the create is admitted on
`create_ntt_min_rows(block_size)` = `ntt_min_missing(block_size)`, the
RESIDENT row gate, whether it then makes one pass over the corpus or eight -
and nobody had measured what a pass is worth. Full write-up and the
recommendation: the section "What a band pass costs the create" at the end of
that note.

- **Box** apple-m3-ultra (Apple M3 Ultra, 32 cores, 256 GB, macOS), under the rig
  lock 18:12:19Z to 18:25:06Z. NOT a quiet box and not claimed as one - see
  the foreign-load note below.
- **Binary** release `parfast` built on the box from `c2aa24fea`, sha256
  `0fde8a1781c4971e...`, version 1.5.0-beta.3.
- **Fixture** 16 x 64 MiB of `/dev/urandom` at 64 KiB slices: n = 16,384
  slices, a 1.0 GiB corpus. The same shape as `wcomb.ps1`'s standard 64 KiB
  fixture.
- **672 ladder legs** plus ~70 probe legs, harness
  `harness/bandpass.py`. Every leg `parfast c`, rc 0, and every leg
  of a rung wrote a byte-identical recovery set across both arms.

## The result

Eight ladders - four pass counts on each of two pools - each one fold against
the forced transform at seven row counts, `fold force force2 fold2` ABBA, 3
reps. `NZBFAST_PAR2GEN_MAP=0` on every arm including the resident control.
Every crossover below is READ between two RESOLVED bracketing rungs, never
fit past the top rung.

| pool | label | passes | route | crossover (rows) | excess over resident | per pass |
|---|---|---|---:|---:|---:|---:|
| `-t32` | `res` | 1 | copied | **137** | - | - |
| `-t32` | `p2` | 2 | band | 128 | **-9** | -8.6 |
| `-t32` | `p3` | 3 | band | 129 | **-8** | -3.9 |
| `-t32` | `p4` | 4 | band | 123 | **-14** | -4.6 |
| `-t8` | `res8` | 1 | copied | **158** | - | - |
| `-t8` | `p2_8` | 2 | band | 159 | **+1** | +1.1 |
| `-t8` | `p3_8` | 3 | band | 159 | **+1** | +0.7 |
| `-t8` | `p8_8` | 8 | band | 172 | **+15** | +2.1 |

A/A floors: 0.8% to 2.9% per ladder, a MAX over reps at every rung, so adding
reps cannot lower them.

**A band pass is worth at most about five rows of crossover, and on the
32-thread pool it is worth a NEGATIVE five** - banding makes the create's
transform cheaper there, which is the stripe-first arm's own design claim
(one plan against `sweeps` of them) showing up in the crossover. The repair's
WINDOW, measured the same way against its own resident ladder, cost +17 rows
at S ~ 2,050 and ~+139 at S ~ 1,035. Two orders of magnitude apart, and the
create's term does not even have a fixed sign.

## The control that makes the eight ladders comparable

The FOLD arm is the same computation in all four ladders of a pool, and the
budget must not move it. It does not:

| pool | max spread of the fold arm against the resident ladder, over 7 rungs |
|---|---|
| `-t32` | 0.99% |
| `-t8` | 0.26% |

That is tighter than any ladder's own A/A floor, so the eight ladders are
mutually comparable and the whole effect sits on the transform arm - where
the pass count is the only thing that changed:

| pool | 1 pass | 2 | 3 | 4 | 8 |
|---|---|---|---|---|---|
| `-t32` CPU-s | 9.70 | 9.39 (-3.2%) | 9.44 (-2.6%) | 9.12 (-5.9%) | - |
| `-t8` CPU-s | 8.53 | 8.60 (+0.8%) | 8.61 (+0.9%) | - | 9.07 (+6.3%) |

## How the legs were proved to band

Not inferred from the `-m` asked for. Every leg carries `route` and `passes`,
parsed out of the binary's own success line - `W window(s)` for copied
windows, `mapped`, or `C chunk(s)` for bands - with `probe ok` part of every
match, so a leg whose probe disagreed with the fold and silently recomputed
is refused rather than counted as a transform. The probe legs printed the
binary's own timing lines verbatim beside the parsed fields and those were
read by hand before any ladder ran.

**This does NOT discharge `wcomb.ps1`'s debt.** That harness's `-Budget`
plumbing and its `-Residency` create assert have still had no leg through
them on any box: this round used `harness/bandpass.py`, on a Mac,
where there is no pwsh. An earlier cut of this paragraph cited a `.err` file,
which is `wcomb.ps1`'s spelling and not one this harness writes.

All 672 legs, grouped by (label, pool, arm): **every force leg of a ladder
took the same route at the same pass count, and every fold leg folded.** No
drift anywhere, which was not free - the band window is
`(budget - worker_arenas)/bs` and the arena term GROWS with the row count, so
a badly chosen `-m` changes its pass count along its own ladder. `-m448` and
`-m384` do exactly that on the 32-thread pool (4->5->6 and 6->7->8 across
these rungs) and were excluded at the probe stage for it. The budgets that
hold constant across all seven rungs are `-m1024`/`-m640`/`-m512` at `-t32`
and `-m1024`/`-m512`/`-m192` at `-t8`.

## Foreign load, stated rather than waved at

apple-m3-ultra carries a resident `spotlightknowledged.updater`
(an internal note) that neither
quiet gate can see. Over the 672 legs: **median 205% of one core, max 351%.**
It was NOT killed - section 4a of that note measured the replacement coming
back worse. This is why the verdict is the CPU column; the wall column is
reported by the reducer and is not read.

## Stated limits

- **THE READ SIDE IS NOT PRICED HERE, and in production it is the regime the
  band route actually serves.** 256 GB of RAM holds a 1 GiB corpus, so every
  leg here read the fixture from the page cache. `admissible()` reaches the
  bands arm only when `mapped_payload_fits_memory` is false - i.e. when the
  payload is genuinely over memory - which this round reached by knob
  (`NZBFAST_PAR2GEN_MAP=0`) rather than by size. The 16 Sep over-RAM ladder
  measured a band read at 84-89% of the transform with ~3x the corpus off the
  device (an internal note). That
  term is real and this round cannot see it. What makes the figures above
  still the right comparison is that the repair's window cost they are read
  against was measured resident too, on the same footing.
- **One class, one block size, one payload.** aarch64 NEON at 64 KiB, where
  `ntt_min_missing` is 192 at every block size. The repair figures compared
  against are GFNI-256 at 4 MiB. What carries across is the MAGNITUDE and the
  SIGN of each path's excess over its OWN resident control, which is the form
  both were reduced in; the absolute row counts do not.
- **Random members.** Whether the create's crossover moves with the payload
  is a separate open claim (`create-rowgate-4mib-payload-control`).
- **The wall column is noise on this box** and is not read anywhere above.

## Files

| file | what |
|---|---|
| `m3ultra-256gb-create-band-pass-64k-n16384.jsonl` | the 672 ladder legs: route, pass count, CPU, wall, foreign CPU, digest, per leg |
| `m3ultra-256gb-round.log` | the round's own LEG lines as it ran |
