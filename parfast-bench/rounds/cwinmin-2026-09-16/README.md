# What a create actually does over budget: it BANDS along stripes, it does not window along sources (16 Sep 2026)

Lane `create-windowed-ladder-4mib-gfni256`, run on the SESSION BOX and
not on the contended GFNI-256 part, because what it settles is a
DISPATCH MECHANISM and not a crossover: does `parfast c -m<MiB>` window a
create, and what does it print when it does? Written up in
an internal note, section "The windowed
CREATE ladder". **This round corrects a prediction that section made from
reading alone**, and it changes what the owed ladder is.

- **Box** apple-m3-ultra-512gb (Apple M3 Ultra, 512 GB, macOS 27.0, aarch64) -
  the session box. Nothing here is a crossover and nothing here should be
  read as one; the routes and their gates are target-independent code,
  and the box is somewhere to run the dispatcher.
- **Binary** release `parfast` from tree `be495f9f1`, sha256 `62e04b76...`,
  version 1.5.0-beta.3.
- **Two fixtures**, 16 members of `/dev/urandom` at 64 KiB blocks:
  n = 2,048 (128 MiB corpus) and n = 8,192 (512 MiB). Two scales, so a
  result that is an artifact of `n` sitting near `NTT_WINDOW_MIN` shows
  up as one.
- **80 legs**, each `-c384` rows with `NZBFAST_CREATE_NTT_MIN_ROWS=0` so
  the row gate is out of the way and the BUDGET is the only variable, and
  `NZBFAST_REPAIR_TIMING=1` so every route prints its line.
- **Both halves of the map decision**: `map=1` is the shipped default,
  `map=0` is `NZBFAST_PAR2GEN_MAP=0`. On a 512 GB box the mapped route
  always fits, so without the second arm the copied and band routes are
  unreachable and invisible.
- **The classifier was validated before the round**, against one known
  line of each of the four shapes. An earlier cut of it used `[^)]*` and
  matched nothing, because every one of these lines contains `stripe(s)`
  or `tail(s)`; it reported all 80 legs as folds, which is why the
  validation step is now named in the log's own header.

## The result

| budget vs corpus | map on (shipped) | map off |
|---|---|---|
| far under (64-96 MiB) | fold, `cold_builds=0` | fold, `cold_builds=0` |
| under | **mapped**, 1 pass | **stripe-first bands**, C passes |
| over (corpus + arenas) | mapped, 1 pass | copied, `1 window(s) of n` |

Transitions, read off the log: at n = 2,048 the fold gives way at 100 MiB
and the copied resident window takes over at 162 MiB against a 128 MiB
corpus; at n = 8,192 the same boundaries are 100 MiB and 550 MiB against
512 MiB.

**And the band route's chunk count is a clean monotone dial in the
budget** - at n = 8,192, `-m100` and `-m112` give 8 chunks, `-m128` 6,
`-m160`/`-m161` 5, `-m162`/`-m192` 4, `-m256` 3, and `-m384` through
`-m540` 2. That is the multi-pass shape a "windowed create ladder" needs.
It is reachable, and it is not the copied-window loop.

## Four things that follow

1. **THE TWO PATHS DECOMPOSE AN OVER-BUDGET PROBLEM ON DIFFERENT AXES.**
   The repair's window is a subset of SOURCES over all stripes, which is
   why its admission scales a row gate by a source count
   (`ntt_window_row_gate(sources, ...)`). The create's band is a subset of
   STRIPES over all sources - `384 rows in 2 chunk(s) of 33 stripes
   (n=2048, bands of 69206016 B over copies, ...)`, with every source read
   in every chunk. **So the create not calling `ntt_window_row_gate` is
   not an omission, it is a category difference**: a source-count ask has
   nothing to say about a stripe-wise decomposition. The lane's chartered
   question - does the windowed ask fit the create - has no well-formed
   answer, and the question that replaces it is what a band pass costs and
   whether the create's admission should price it at all.

2. **No leg, at either scale, under either lever, produced a copied
   window smaller than the whole corpus.** `windowed_attempt`'s
   `while w0 < n_slices` is real code that this dispatcher never handed a
   fractional window on these shapes.

3. **`cold_builds > 0` is not the same claim as "a transform ran", and
   this round does NOT reproduce the difference.** All 68 plan-building
   legs took one of the three routes; none built a plan and then fell to
   the fold. So `wcomb.ps1`'s old create path assert (`cold > 0` -> 'ntt')
   would have classified every leg here correctly, and the `probe ok`
   requirement that replaced it is justified by the CODE - both
   `windowed_attempt` and `stripe_first` verify one row against the fold
   and, on a disagreement or an unbuildable window, warn and recompute
   every row after charging their plan builds - and not by anything
   measured here. An earlier cut of this README claimed 18 such legs; that
   was the broken classifier's output being read as behaviour, and it is
   withdrawn.

4. **A `-m` on the box will probably NOT band, it will map.** The mapped
   route is tried first whenever `mapped_payload_fits_memory` holds, and
   16 GiB against 31.4 GB may well hold. A windowed create ladder
   therefore needs `NZBFAST_PAR2GEN_MAP=0` on every arm, or a corpus that
   cannot map - and `-Residency windowed` now refuses a mapped leg, so the
   round fails loudly rather than publishing single-pass legs under the
   windowed name.

## What was wrong, and is withdrawn

The section's reading that "`-m4096` should refuse the transform outright
at 4 MiB" because the window would fall under `NTT_WINDOW_MIN`. The window
floor is real and the arithmetic was right, but `None` from
`create_ntt_window` is not the end of the dispatch - the band route takes
it. The corrected statement is that a `-m` under the corpus moves the
create to BANDS.

## Stated limits

- **aarch64, 64 KiB blocks, one payload, one row count (384).** The routes
  and their gates are target-independent, but the arena term that sets the
  boundaries is not, and neither is the mapped route's fit decision on a
  31.4 GB box. Every MiB figure here is this box's.
- **Nothing here is a crossover.** Every leg forced the row gate to zero.
  No fold-versus-transform comparison was made and none should be read out
  of this log.
- **`Corpus::Mapped` bands were never observed**, only `over copies`. The
  band route has a mapped-corpus variant this fixture never reached.
- **The chunk counts are not a cost model.** This round says how many
  passes a budget buys, not what a pass costs, which is the measurement
  the owed ladder still has to make.

## Files

| file | what |
|---|---|
| `m3ultra-create-over-budget-route-64k-n2048-n8192.log` | the 80 legs, both fixtures, both map arms, route and pass count per leg |
