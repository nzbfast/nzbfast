# GFNI-256 four-window round at 1 MiB - COMPLETE, all six ladders

**The round ran to completion**, 13:14:43Z to 18:28:41Z on 18 Sep 2026: six
ladders, 704 legs, every leg `rc=0` and `restored=16/16`. Ladders A and B were
banked mid-flight at 15:25Z as insurance while the driving account migrated;
C, D, E and F were added by the takeover session once the round ended.

**The result is written up as a dated section of
an internal note** (the campaign file),
beginning "FOUR window sizes on the GFNI-256 class at 1 MiB". Headline: the
one-parameter form `gate + gate*k/(S - k)` fails as a SHAPE on this class and
fails UNLIKE the nibble class, while the shipped `NTT_WINDOW_COMBINE_X86` = 312
over-asks at every window measured here, which is the conservative direction.
No constant was moved.

The takeover brief, its three traps and the reduction recipe:
an internal note.

| file | what |
|---|---|
| `g4winres.log` | ladder A, the resident anchor, 128 legs, 13:32:24 - 14:25:06Z |
| `g4winw4k.log` | ladder B, `-m4096` (S = 4,112), 128 legs, 14:25:32 - 15:18:01Z |
| `g4winw2k.log` | ladder C, `-m2048` (S = 2,064), 128 legs, 15:18:28 - 16:11:59Z |
| `g4winw15.log` | ladder D, `-m1536` (S = 1,552), 128 legs, 16:12:29 - 17:07:01Z |
| `g4winw1k.log` | ladder E, `-m1024` (S = 1,040), 128 legs, 17:07:31 - 18:03:11Z |
| `g4winres2.log` | ladder F, the resident drift control, 64 legs, 18:03:37 - 18:28:40Z |
| `g4winrun2.ps1` | the driver, with its design and both attempt-1 defects in its header |
| `g4winrun2-driver.log` | the driver's own log, start to `G4WIN2-END` |
| `ssh-poll-timestamps.txt` | every ssh poll that landed during the sitting, including seven that returned nothing |

## THE LADDERS RAN WIDEST-WINDOW-FIRST

Window width is therefore confounded with time, and ladder F says the anchor
MOVED over the sitting: +24.7 rows (+7.4%) at `-t16` CPU and +15.0 (+4.4%) at
`-t8` CPU, against 0.3 of a row on the nibble round's equivalent control. In
WALL the control could not bracket the end-of-sitting crossover at either pool,
so the anchor movement is UNMEASURED there. Any re-reduction of these logs has
to carry that; the campaign section works it through and shows the correction
STRENGTHENS the round's finding rather than weakening it, because an upward
anchor drift costs a small excess proportionally more than a large one.

`g4winw1k.log` carries TWO `win_slices` values, 1040 and **2080**. That is not
a defect: `plan_slabs_with` holds one slab only while `m <= (S-16)/2`, which at
S = 1,040 is exactly 512, so the ladder's top rung sits on the boundary and the
window doubles there. The reducer keys shape on `(windows, win_slices, slabs)`
and excludes that rung on its own.

## Provenance

intel-core-ultra-9-386h, Core Ultra 9 386H (GFNI-256, 16C/16T, no SMT, hybrid 4P+8E+4LP-E),
Windows 11 Home, on AC, under the per-box rig lock. `parfast 1.6.0` built on the
box from origin/main `c4a9de207f7d9aacc57a6b518e319c750bcf3ebf`, sha256
`E41347B551440009F1B6DDA56A19FED47860E1B5B0C04A95A51F799B32776B31`, 4,324,864
bytes, hash-gated by the driver before the first leg. Fixture 16 x 512 MiB at
1 MiB `-c2048`, n = 8,192, built by ladder A and settled for 989 s before its
first leg. Grid `288,320,352,384,416,448,480,512` on every ladder, both pools
`-Threads 8,16`, `Reps 2`, gate 352.

**`foreign_cpu` median 9.4% of one core on both ladders** (n = 139 and 128).

## Two things about these files specifically

**They have been converted from UTF-16LE to UTF-8.** PowerShell 5's
`Tee-Object` writes UTF-16LE with a BOM, and every other banked log in this repo
is UTF-8 - `waskred.legs()` answers `no legs at threads=16` on the raw file,
which reads exactly like a round that measured nothing. The raw copies are on
the box and at `~/Claude/g4win-logs-2026-09-18/`.

**Each carries one stray `LOCK-BUSY` line at the top**, from this lane's
attempt 1, which ran zero legs. It carries no `LEG` line so every reducer
ignores it. The handoff's section 6 has the full account.
