# Published-table reproduction census, 18 Sep 2026

Lane `published-table-reproduction-census-18sep`, gen `a81f9519`, commissioned
after the NTT / row-gate campaign's published tables had been caught
unreproducible **twice by accident** (8.20.8 and the 18 Sep filtered-fit null
lane) and never once on purpose.

**Reduction over banked data. No leg was run, no box and no rig lock was
taken, no timed leg, no constant moved and nothing under `crates/` was
touched.**

## What is here

| file | what it is |
|---|---|
| `p4recheck.py` | the one RE-IMPLEMENTED reducer in the census: 8.16.5's 4 MiB ladder, whose own reduction 8.16.11 says "was scratch and is described in 8.16.5 rather than committed". `--selftest` re-derives 8.20.8's finding independently. |
| `out/` | every re-run's banked stdout, one file per (reducer, legs) pair |
| `out/inventory-counts.txt` | the recursive leg census and the arithmetic-shape grep |
| `cellcount.py` | the cell tally, derived per published table. The first hand tally was wrong (282 of 289) and undercounted the two-pool row-gate tables; this is why the number is a script. |
| `out/interp-convention.txt` | the `rowgate.cross` / `waskred.crossover` interpolation difference, proved arithmetically |

## The commands, all of them

Every one was run from the repo root on 18 Sep 2026. Output is banked under
`out/` at the name given.

```sh
# the worked example this census generalises (green)
python3 rounds/filtered-fit-null-2026-09-18/fitnull.py --selftest

# 8.17 - the leaf-term round. leafsum.py is committed WITH its round.
python3 an internal note \
    an internal note     # out/leafsum-ship.rerun.txt
python3 an internal note \
    an internal note      # out/leafsum-g64.rerun.txt
python3 an internal note \
    an internal note    # out/leafsum-noadd.rerun.txt

# 8.21 - the fixed-width ladder. The PUBLISHED table is the width-CORRECTED
# reduction, so the bare run is NOT the table; `--cl 0.5001` is (8.21.5).
python3 harness/nttfwsum.py \
    an internal note \
    an internal note
python3 harness/nttfwsum.py --cl 0.5001 \
    an internal note \
    an internal note

# 8.18 - the guest m ladder. TWO reducers: nttmsum.py for the ladder and the
# A/A floor, jointfit.py for the joint fit that every 8.18.1 number comes from.
python3 harness/nttmsum.py \
    an internal note
NULL=0 python3 an internal note \
    an internal note

# 8.16.5 - no committed reducer; re-implemented here, selftested against 8.20.8
python3 rounds/table-reproduction-2026-09-18/p4recheck.py --selftest
python3 rounds/table-reproduction-2026-09-18/p4recheck.py

# the row-gate note's own tables. rowgate.py read over every banked ladder.
python3 harness/rowgate.py read <log-or-jsonl>     # out/rowgate-*.rerun.txt

# the `k` cells the 15 Sep note pins itself against
python3 harness/wcombsum.py measure \
    rounds/wcomb-k-nibble-2026-09-16/i5-nibble-k-64k-n16384-control.log
python3 harness/wcombsum.py measure \
    rounds/wcomb-k-nibble-2026-09-16/i5-nibble-k-1m-n8192-m2048.log

# every reducer in the census that carries its own selftest (all green)
python3 harness/kneeratio.py --selftest
python3 harness/stealsub.py selftest          # SUBCOMMAND, not a flag
python3 rounds/wask-nibble-2026-09-16/waskred.py --selftest
python3 rounds/w3win-nibble-2026-09-18/w3winred.py --selftest
python3 rounds/crossover-bias-2026-09-18/crossbias.py --selftest
```

## Three invocation traps, recorded because each one first read as a finding

1. **`rowgate.py read` cannot read its own `.log`.** The unix driver writes
   BOTH a human `.log` of `LEG ` lines and a machine `.jsonl`; the reader
   sniffs `{` and sends anything else to `_wcomb_rows`, which wants
   wcomb.ps1's field names and dies `KeyError: 'restored'`. **The `.jsonl` is
   the input for the unix rounds** (EPYC, m5max) and the `.log` for the
   Windows ones. Not a defect in any table - but a reader who takes the
   KeyError for a corrupt leg file is wrong twice.
2. **`stealsub.py selftest` is a subcommand.** `--selftest` prints usage and
   exits non-zero, which reads exactly like a failing selftest.
3. **`ts=` is the LAST field on a `LEG ` line.** Dumping the first 40 tokens
   says the format carries no per-leg timestamp, which would have made the
   256 KiB figures permanently unauditable. They are not; see the census.

## What the census found

Full per-cell table and the classification in the dated section
"Does every published table reproduce?" at the end of
an internal note. In one paragraph:

**339 published cells were re-derived across nine rounds. 332 reproduce
exactly. Seven do not, and they are four findings:**

- **3 cells** - 8.16.5's `ntt syndromes` at `w5`, `w7`, `w10`. Already known
  (8.20.8); confirmed here independently, and extended: the OTHER three
  columns of that table (wall, cpu, peak) reproduce in all 21 cells, so the
  defect is confined to one column, and the marginal column 8.16.5's
  CORRECTION 1 rests on moves by up to 5.6 s a rung.
- **1 cell** - 8.21.4's *uncorrected* first knee, 4,216.4 against the
  reducer's 4,230.4. Flagged by the 18 Sep null lane, which named the width
  correction as the likely cause and did not run it down. **Run down here and
  that cause is FALSIFIED**: the knee is monotone in the correction with a
  floor of 4,230.4, so 4,216.4 is unreachable by any non-negative correction.
  Everything else in 8.21.4 - 17 charge cells, 9 fit parameters, both
  corrected knees, both percentages - reproduces exactly under `--cl 0.5001`.
- **3 cells** - 8.18.6's steal-ladder `K` column at three of its five rungs,
  each off by exactly one 25-row scan step. Documented in `jointfit.py`'s own
  docstring; the r2 column and every leg count are exact, and the published
  headline 4,275 is one of the two exact rungs.
- **0 cells, and the only NEW finding** - `waskred.crossover` interpolates
  LINEARLY in `m` while its own docstring says it does what `rowgate.py`
  does, which is GEOMETRIC. It costs no cell in the 15 Sep note, but it
  biases the 18 Sep error-bars file's whole crossover column upward by about
  a row, always in the same direction.

**No verdict in the campaign moves, and no constant is in play.**

## The CI verdict on this round's workflow step, cited accurately

`size-gate.yml`'s step "8.16.5 4 MiB ladder reproduction, and its published
copy" runs both `p4recheck.py` copies on every push. It has passed on the
runner, twice, on two shas that contain this round:

| run | sha | job | the step itself |
|---|---|---|---|
| 35385580973 | `0402071a` | `tool-selftests` success | success |
| 35386323937 | `d8e3a1c9` | `tool-selftests` success | (job-level) |

**CORRECTION to `62f2864b0`'s commit message**, which cites the first of those
as "run 35385580973 on 4e2b119d". The run number and the sha are right
individually and wrong together: 35385580973 is on **`0402071a`**, a later
lane's merge that CONTAINS `4e2b119d`. The substantive claim is unaffected -
the tree that step ran over does carry this round's files - but a reader
reproducing the check from that message would look up the wrong sha. Recorded
here because a commit message cannot be edited once pushed.

**And run 35385580973 concluded `failure` AT RUN LEVEL, which is not this
round's doing.** The failing job is `selftest-exit-code-gate`, over
`tools/claims.py`'s own selftest exceeding `PROBE_TIMEOUT` under the 4 vCPU
runner's contention. It was already red before this round pushed anything, is
claimed by another lane (`red-selftest-exit-code-gate-c727086c`, open at the
time of writing), and no commit of this lane touches any file under `tools/`.
**A run-level `failure` on a sha containing your work is not evidence that your
work failed** - read the job, not the run, which is the same rule
`tools/ci-verdict.py` exists to enforce one level up.
