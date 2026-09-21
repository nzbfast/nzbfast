# Driver for `rounds/m5-full-range-2026-09-11.log`

Fetched read-only from the session box (`apple-m5-max` in `.claude/MACHINES.md`)
on 18 Sep 2026, after the round had already run. This is a RECORD of the
driver as found on the box, not a verified reproduction of the round:
nothing here was re-run.

| file | box path | sha256 | box mtime |
|---|---|---|---|
| `m5full.py` | `~/pubrun/m5full.py` | `d9c6c8d4b68e65d8e783933448babfac5aa87bbb37ff5d500406575a35b735f5` | 2026-09-10T20:04:27Z |
| `m5lad.py` | `~/pubrun/m5lad.py` | `9d98c2dd28772fef352917969400a889f9aab978863f31d55301517f0b4604c5` | 2026-09-10T13:48:19Z |

`m5full.py` is the driver that wrote `rounds/m5-full-range-2026-09-11.log`
(the log's `starting m5full.py` line). `m5lad.py` is fetched alongside it
because it is the M5's copy of the 15% ladder driver this round's docstring
says it was derived from ("Originally the Apple 15% ladder"); no published
log in this tree is attributed to it by name, so it is provenance context
rather than a driver being newly cited.

Local copies were re-hashed after transfer and match the box byte for byte.

## Cross-check against the log

`rounds/m5-full-range-2026-09-11.log` carries `BIN parfast sha256=...` and
`BIN par2turbo sha256=...` lines (the two binaries under test) but no
`HARNESS ... sha256=` line for the driver script itself, so there is nothing
in the log to check `m5full.py`'s hash against. Not verified; noted rather
than guessed.

## Arm-order classification (per the rubric in
an internal note section 1)

`m5full.py` runs `parfast` then `par2turbo` (`TOOLS = ["parfast", "par2turbo"]`,
line 55) with no rotation:

- verify legs, l.189-190: `for rep in REPS: for tool in TOOLS:`
- repair-ladder legs, l.202-204: `for rung in RUNGS: seed = ...; for tool in TOOLS:`

Order never reverses across reps or rungs. **FIXED** (parfast always first),
consistent with the census's section-1 note that both of the two
not-in-tree published drivers "run parfast before turbo in every cell."
