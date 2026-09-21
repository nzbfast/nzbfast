# A random-drop null over the A/A FLOOR - the 64 KiB row-gate verdict flips

Lane `rowgate-64k-verdict-flip-null-18sep`, gen `9cdb0dc6`, commissioned by
item 2 of
an internal note.
**Reduction over banked data. No leg was run, no box and no rig lock taken, no
constant moved, nothing under `crates/` touched.** The write-up is the 18 Sep
2026 section "The steal filter's 64 KiB verdict flips" in
an internal note.

## What is here

| file | what it is |
|---|---|
| `floornull.py` | the reducer, the null and the selftest; read its docstring first |
| `table-lt8.txt` | **the result** - the per-rung enumerated null at steal < 8.00% |
| `joint-lt8.txt` | the whole table under the exact d-matched null |
| `table-lt5.txt`, `table-lt4.txt` | the same two at the ladder's tighter rungs |
| `global-200-seed7.txt`, `global-1000-seed7.txt` | the whole-file uniform draw, the looser instrument, kept as the cross-check |
| `rowgate-none.txt`, `rowgate-lt8.txt` | `rowgate.py read`'s own tables, unfiltered and filtered - what the selftest pins against |
| `selftest.txt` | the banked selftest run |

## The answer in three lines

- **Seven rungs flip, not the three the handoff names**, and **no individual
  flip survives**: every one is reproduced by a random drop of the same size
  21% to 82% of the time, and three of them sit in eight-member nulls whose
  smallest attainable P is 0.125.
- **The mechanism is the floor and not the arms.** On six of the seven, the
  filtered fold/force ratio judged against the UNFILTERED floor gives the
  unfiltered verdict back; the seventh needs both halves.
- **But the SET of seven is not chance** (P = 0.0032 under the d-matched
  null), which says steal predicts WHICH leg owns the A/A worst - a new
  finding, and not one that makes any single rung readable.

## Reproducing it

    python3 rounds/rowgate-64k-floor-null-2026-09-18/floornull.py --selftest
    python3 rounds/rowgate-64k-floor-null-2026-09-18/floornull.py
    python3 rounds/rowgate-64k-floor-null-2026-09-18/floornull.py --joint

Seconds, on any platform, with no round and no box. The legs and the reducer
it pins against are `rounds/rowgate-2026-09-15/` and
`harness/`, both resolved relative to this file so the copy
`website/tools/export_parfast_evidence.py` mirrors runs unchanged.
