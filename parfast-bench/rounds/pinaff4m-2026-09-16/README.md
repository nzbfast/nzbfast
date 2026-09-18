# The pinned-affinity 4 MiB row-gate round: THREE SITTINGS, FINISHED 17 Sep 2026

> **FINISHED 17 Sep 2026.** This file was written after the FIRST sitting, which
> came back with one arm of four, and everything below it is that sitting's
> record and still true of it. The item was then run twice more in one lane, on
> 16 Sep 21:04-22:43Z and 22:51-00:31Z, and **both of those sittings completed
> all four arms** (`rc=0`, 20 legs, `lock_waits=0`, eight ladders and 160 legs
> between them). Logs are filed by sitting: `logs/attempt1/` is the round this
> file describes, `logs/attempt2/` and `logs/attempt3/` are the two that
> finished it.
>
> **The answer, and where it lives:** the section "The four-arm pinned sitting,
> twice over: placement swings the crossover four times as far as the pool gap,
> and the full-box arm is not a measurement (17 Sep 2026)" at the end of
> `../../NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`. Holding the pool at four
> threads and moving only the CPU mask swings the crossover 42-52 rows, against
> the 14-row `-t4`/`-t16` gap the coincidence clause rested on.
>
> **What the two later sittings add to THIS file's lessons.** The three ways to
> lose a ladder listed below were all avoided: no hung ssh, no waiter left armed,
> and the inter-ladder gap cost nothing in either sitting (the driver now retries
> an arm on `rc=17` and only on `rc=17`, which is LOCK-BUSY; it never had to
> fire). **But a FOURTH way appeared, and it is not a mistake anybody made**: the
> `4m-t16` arm is non-monotone in all three sittings, including one run with no
> polling whatever, with wall up and CPU down together. **Scope it carefully**:
> `ladder-monotonicity-audit.py` in this directory reduces every banked ladder
> and finds 4 non-monotone of 36 full-box tables against 5 of 29 sub-box ones,
> three of those four being this round's own arm - so it is THIS ARM AT THIS
> SHAPE that fails, not full-box ladders as a class, and the no-spare-core story
> is a hypothesis the corpus does not support. Two consequences correct this file:
> lower a CPU reading** (the paragraph below that says otherwise is true of WALL
> only, and CPU is the verdict metric), and **the A/A pair is blind when the
> perturbation hits both copies of a rung** - sitting 2's m=352 reported a 0.5%
> floor on a visibly broken rung.
>
> `<rig>\crg4-16sep` and its fixture were deleted by the lane that
> finished the sitting, as this file asks below and as posted on the box.

## The first sitting (16 Sep 2026): one arm of four

Lane `parfast-4mib-pinned-affinity-pools`. **The logs in `logs/` are a real
round that answers less than it set out to.** Three of the four arms are
unusable and the reasons are recorded here rather than smoothed over, because
two of the three are new failure shapes and the third is a norm that the
instrument does not enforce.

Read `../../NTT-ROW-GATE-GFNI-AVX512-2026-09-15.md`, section "Pinned affinity
at 4 MiB: one clean arm, and three ways to lose a ladder (16 Sep 2026)", for
the numbers and the verdict. This file is the round's own record.

## What ran

Launched 17:15:22Z detached via `wlaunch.ps1`, driver pid 5732, on
intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 16C/16T as 4 P + 8 E + 4 LP-E).
**Binary and fixture INHERITED** from `parfast-create-rowgate-4mib-gfni256` at
`<rig>\crg4-16sep`, verified on the box rather than taken from its
handoff: binary 4,173,312 bytes sha256 `fddb6aa3...`, fixture 39,737,780,165
bytes across 56 files, `work\` and `pristine\` at 27 files and identical byte
counts, `shape.txt` recording slice=4194304 members=16 recovery=640. So no
build and no 16 GiB create, and arms 1 and 3 are controls against ladders
built from the same commit `06d5734b7`.

| # | arm | mask | threads | legs | crossover | state |
|---|---|---|---:|---:|---:|---|
| 1 | `4m-t16` | none | 16 | 20 | 392 | **DIRTY** - floors to 24.1% |
| 2 | `4m-p4` | `0xF` | 4 | 20 | **383** | **CLEAN** - floors 0.2-2.9% |
| 3 | `4m-t4-unpinned` | none | 4 | 20 | 351 | **DIRTY** - one leg at 160% foreign |
| 4 | `4m-e4` | `0xF0` | 4 | **0** | - | **NEVER RAN** - `rc=17`, lock lost |

`logs/pine4.log` is two lines and is kept deliberately: it is the evidence for
how arm 4 was lost.

## The class probe, which IS a result and is unaffected by any of the above

Fixed work, timed, one mask at a time, inside the sitting after the first load
gate passed. Every mask read back equal to what was asked.

| mask | class | wall |
|---|---|---:|
| `0x1` | P-core 0 | 7.844 s |
| `0x10` | E-core 4 | 13.384 s |
| `0x1000` | LP-E core 12 | 14.629 s |

**P/E is 1.71x on identical work**, against the 1.43x single-thread swing
`.claude/MACHINES.md` documents. The confound this round exists to remove is
therefore, if anything, WIDER than the landed section's stated limit assumed.
It also confirms the core-class map (0-3 P, 4-11 E, 12-15 LP-E) by measurement
rather than by firmware report, which is what the arm names rest on.

## Three ways to lose a ladder, all paid for here

**1. A HUNG SSH, which is invisible to every check we have AND to the lane
that created it.** A stdin-piped coordination append of mine hung at 16:59Z.
The ssh client did not die with the command - it stayed alive **56 minutes**,
holding a PowerShell on the box blocked on `[Console]::In.ReadToEnd()`, through
the whole of arm 1 and the first 18 minutes of arm 2. Killed by pid at 17:55Z.
It holds no rig lock, spawns no `parfast`, sits outside every round's pid tree
INCLUDING ITS OWN AUTHOR'S, and passes under `Require-QuietBox`'s 160%-of-a-core
ceiling. Unlike a poll it never ends. It was found by grepping `ps` on the Mac
for an unrelated reason. **Post a coordination line by scp-then-append from a
FILE; never pipe it into an inline `-Command` expression** - that form failed
two different ways here in four minutes and the second failure is this one.

**2. A WAITER THAT OUTLIVES WHAT IT WAITS FOR.** A probe armed at 17:03Z to
watch for the previous lane leaving kept firing after the box was mine, and
fired into arm 1 at 17:20:38Z. It is the 82%-foreign leg at m=320. Waiting for
a box and holding a box need OPPOSITE polling behaviour, and nothing disarms
the first when the second begins.

**3. THE BETWEEN-LADDERS GAP, which is a norm the instrument does not
enforce.** `wcomb` takes the rig lock PER LADDER, so a four-arm round is four
acquisitions and looks like four separate rounds to anybody reading the lock.
Arm 3 released at 18:25:40Z; `rarfast-windows-os-error-wording-16sep` took the
lock at 18:25:40.60Z; arm 4 asked at 18:25:42Z and got `LOCK-BUSY`. That lane
held ~100 s and `create-rowgate-8mib-gfni256` took it at 18:27:20Z. **Neither
lane did anything wrong** - the lock was genuinely free at the instant each
asked. `create-rowgate-8mib-gfni256`'s own QUEUED line states the protective
norm exactly ("the create rounds release the rig lock between ladders and a gap
is not an opening"), and it honoured it. The lesson is on the round, not on the
takers: **a round that must not be interrupted mid-sitting has to say so on the
coordination file, loudly, because the lock cannot say it.**

## Why the two dirty arms are NOT evidence about the landed numbers

Arm 1 reads 392 against the landed ~405 and arm 3 reads 351 against the landed
~391. **Neither miss is a finding.** Both arms carry contamination that
explains them, and publishing a miss as a result would be exactly the
rubber-stamp this round was commissioned to prevent. They are recorded as
damage.

Note the direction, because it is the trap the `rar15-pdr-candidates-x86-cells`
lane nearly fell into on this box the same day: contamination can only make a
leg SLOWER, so it cannot lower a floor, only raise one. This reducer takes a
MEDIAN of the two copies of each arm rather than a best-of-N minimum, so the
floor-raising shape that manufactures a false win does not apply here - but the
direction still decides whether an F/T moves up or down, and an F/T is a ratio
of fold to force, so WHICH arm the spoiled leg belongs to decides which way the
crossover moves.

And the A/A floor cannot be repaired by adding reps: it is a MAX over reps
(`rowgate.py` ~line 199), so it is monotonically non-decreasing in rep count.
More reps raise the acceptance threshold. The only repair is a clean re-measure.

## What a successor needs

**One clean four-arm sitting, ~100 minutes.** Not three arms bolted onto this
round's clean arm 2: the landed section "The two-binary `c_f` control: it is the
SITTING, not the commits" is the whole reason, and 383 on its own answers no
comparison. Four arms together or nothing.

The driver, `pinaff-round.ps1`, is unchanged in shape and is the thing to run.
Before launching, and these are cheap:

- `ps ax | grep <box>` ON THE MAC, and kill anything of yours that is still
  attached. This is now a precheck, not a courtesy.
- Disarm every waiter armed while you were queued, the moment you own the box.
- Post a line saying the round is FOUR LADDERS IN ONE SITTING and asking that
  the inter-ladder gaps not be taken. The lock will not say it for you.

`<rig>\crg4-16sep` and its fixture were still intact and undeleted when
this lane finished, deliberately, because the re-run needs them. Its owner left
it for this round, which inverts the usual cleanup rule: **whoever completes the
four-arm sitting deletes that root and says so on the coordination file.**
