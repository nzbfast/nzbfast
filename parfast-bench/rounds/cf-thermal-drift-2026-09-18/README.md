# Candidate 3 could not be tested on 18 Sep, and the reason is the instrument

Lane `cf-thermal-drift-candidate3-18sep`, gen `1511cd71`, on no box.
Item: the second "Owed after this lane" bullet of
`## The 17-48% gap SPLIT ...` in
an internal note - **candidate 3, thermal
and frequency drift across a sitting, now that a leg records frequency.**

**Status: this is a NULL WITH A CAUSE, not a null.** The sitting this item
asks for did not run, and it did not fail to run because no box was free.
It did not run because **the frequency half of the instrument it depends on
does not measure frequency**, which is established below from the banked
corpus alone and needed no box at all. The temperature half is sound.

Nothing in `crates/` is touched. No constant moved.

## What the item asked for, and why it stopped here

The 18 Sep census ranked three candidates for the unexplained within-sitting
residual in `c_f`. Candidates 1 (the co-tenant's footprint) and 2 (thread
placement) are confirmed. Candidate 3 was **untestable by construction** -
no banked LEG line carried a frequency or a temperature - so `e7f7cd14d`
added eight fields to every LEG line and the census said the candidate now
wanted only a long sitting on a box that heats.

That is a fair summary of what was missing and an incomplete one about what
was added. **`e7f7cd14d` made candidate 3 testable in the sense that the
columns exist. It did not make the frequency column readable**, and this
lane's whole finding is that the difference matters.

## The finding: `Get-PowerState`'s frequency half reads a number that cannot be true

`Get-PowerState` in `harness/plib.ps1` sources `perf_pct` - from
which `freq_mhz` is derived as `nominal x perf_pct / 100` - with a **single
un-refreshed CIM query** of the cooked-counter class:

    Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation -Filter "Name='_Total'"

`% Processor Performance` is a DELTA counter. It is the counter
an internal note section 2a was written about, and
its rule 1 is "never sample it single-shot". That rule was written about
`Get-Counter`; the harness reaches the same counter through WMI's cooked
provider instead, which is a different API with the same structural problem -
it needs two refreshes of its internal cache and a lone query does not give
it one.

**The six validation legs `e7f7cd14d`'s own lane ran are enough to convict
it, and the argument is internal to that one log** - no cross-date
comparison, no second box, nothing this lane measured itself.
`rounds/cf-load-term-buffer-2026-09-18/pwr.log`, intel-i5-10600kf, six
legs across 62 seconds:

| leg | wall | cpu | busy threads | perf % after | freq after | temp C | temp after |
|---|---:|---:|---:|---:|---:|---:|---:|
| m192-big-fold-t12 | 2.206 | 22.688 | 10.28 | 24 | 912 | 27.9 | 27.9 |
| m512-big-fold-t12 | 4.496 | 49.469 | 11.00 | 49 | 1862 | 27.9 | 27.9 |
| m192-big-force-t12 | 1.883 | 17.766 | 9.43 | 24 | 912 | 27.9 | 27.9 |
| m192-128-force-t12 | 2.374 | 23.625 | 9.95 | 24 | 912 | 27.9 | 27.9 |
| m512-big-force-t12 | 2.029 | 19.344 | 9.53 | 29 | 1102 | 27.9 | 27.9 |
| m512-128-force-t12 | 2.815 | 28.688 | 10.19 | 68 | 2585 | 27.9 | 27.9 |

**Every leg held between 9.4 and 11.0 threads busy for its whole duration**
(`cpu/wall`, on a 12-thread part), **every temperature sample in the sitting
read 27.9 C**, and the end-of-leg frequency nonetheless spans **912 to 2585
MHz, a 2.83x range**. There is no thermal story available for that spread -
the thermometer did not move by its own resolution - and no workload story
either: the two legs 2.83x apart are both `-t12`, both at ~10.2 busy threads,
62 seconds apart on one box.

**A quantity that moves 2.83x while everything that could move it is fixed is
not measuring the thing it is named after.**

The second half is a level check and it is worse than the spread. intel-i5-10600kf's
`Win32_Processor.MaxClockSpeed` is 3800, so these readings are 912-2585 MHz.
The same box, the same counter, read by the route
`coreultra9-THROTTLE-2026-09-04` proved (`-SampleInterval 1 -MaxSamples N`), sat
at **109.74-110.45% of nominal - 4170 to 4197 MHz - while IDLE**, flat to a
third of a percent across five calls. **The cooked-CIM route's highest
reading under a ten-thread load is 38% BELOW the proven route's idle
reading**, and its typical reading is about a quarter of it.

That comparison is across two dates and this lane says so plainly; it is
offered as the level check, and **the 2.83x spread above is the part that
stands entirely on its own**. It also disposes of the one escape a
cross-date comparison would leave open - "the box really was at 912 MHz" -
because the BEFORE samples, taken after the quiet-box guard's idle second,
read 24-30% on a box that the proven route reads at ~110% when idle. Both
routes were looking at an idle intel-i5-10600kf. They disagree by a factor of four.

## Why the AFTER position cannot be fixed by sampling it properly

The obvious repair - swap the cooked-CIM query for
`Get-Counter -SampleInterval 1 -MaxSamples 2` - is the right rule and the
wrong place. A delta counter needs an interval, the AFTER sample is taken
within ~300 ms of the child exiting, and a one-second interval starting there
**integrates the idle decay after the leg, not the leg.** It would replace a
wrong number with an honest measurement of the wrong window, at a cost of
1-2 s per sample on legs that are themselves 2-5 s.

**The fix that makes the existing bracket design correct is to read the RAW
class at both ends and do the division in the harness.** A cooked delta
counter is a ratio of two raw accumulators; bracketing the leg with
`Win32_PerfRawData_Counters_ProcessorInformation` and dividing
`delta(PercentProcessorPerformance)` by `delta(PercentProcessorPerformance_Base)`
yields the average over **exactly the leg's own window**, with one cheap
query at each end and no background thread.

That is strictly better than what the field was ever specified to give.
`wcomb.ps1`'s header states the stated limit this lane inherited - "the
samples BRACKET the leg, they do not average it", so there is end-of-leg
frequency and not a during-leg average. **A raw-delta bracket removes that
limit rather than working around it**: the bracket becomes the average, which
is the quantity a drift-across-a-sitting question wanted in the first place.

**THIS FIX IS UNVERIFIED ON A BOX AND IS NOT LANDED IN `plib.ps1`.** The
property names and the formula are from the counter's documented shape and
have been checked against no Windows machine, because every Windows timing
box in the fleet was held and saturated for the whole of this lane's window.
A harness edit that parses on a Mac and reads empty on Windows is the exact
failure `pwrcheck.ps1` was written to exclude, and `plib.ps1` was being
executed by two other lanes' live rounds while this was written. So the
candidate lands **beside** the round as `pwrcheck2.ps1`, to be run on a box
before anything is wired into the harness.

## What the validator did and did not check, which is the reusable lesson

`pwrcheck.ps1` was not negligent - it asked three questions and its header
names them: "do the fields appear, are they plausible, and does every
existing reducer still parse the line". It answered the first and the third
correctly. **The second cannot be answered by looking at the field**, because
a number that is wrong by a factor of four still looks like a frequency, and
912 MHz on an idle-looking desktop reads as entirely plausible right up until
you ask what the box was doing at the time.

Two mechanical things would have caught it, and both are cheap:

- **A reference reading in the same breath.** The validator called
  `Get-PowerState` bare and printed a `POWERSTATE` line specifically so a
  broken query would be diagnosed there. Printing it alone could not convict
  it. Printing it beside a `Get-Counter -SampleInterval 1 -MaxSamples 2` of
  the same counter, at the same moment, would have.
- **Keeping the output.** That `POWERSTATE` line went to `pwrcheck.ps1`'s
  stdout and was never banked - the round holds `pwr.log` and not the
  validator's own transcript - so the one diagnostic aimed at this failure
  is not in the corpus at all.

**A plausibility check with no reference to compare against is a presence
check wearing a plausibility check's name.**

## What this does and does not say about the fields

- **`temp_c` / `temp_after_c` are SOUND.** `Temperature` on
  `Win32_PerfFormattedData_Counters_ThermalZoneInformation` is an
  instantaneous gauge, not a delta, so a single query is the correct way to
  read it and the bracket means what it says. Nothing here impugns them.
- **`throttle_pct` is sound and its polarity is worth writing down once:**
  `PercentPassiveLimit` reads **100 when nothing is throttling**, so the
  `throttle_pct=100` on all six legs is a clean bill of health and a DROP
  below 100 is the passive-throttle signal. A reader meeting this column for
  the first time can easily take 100 for "fully throttled".
- **`perf_pct` / `freq_mhz` / `perf_after_pct` / `freq_after_mhz` must not be
  reduced or quoted** until the raw-delta fix is validated on a box.
- **`pkg_w` is unaffected.** It reads `na` for the documented reason and this
  lane found nothing to add to it.

## Consequences for candidate 3

**Candidate 3 is still NEVER TESTED, and it is now blocked on a harness fix
rather than on a hot box.** That is a different and more useful state than
the census left it in, because it names something a lane can do without
waiting for a machine.

The sequencing this implies is the part worth carrying forward:

1. **Validate the raw-delta sampler on a box** (`pwrcheck2.ps1`, minutes,
   any Windows box, no round needed).
2. **Wire it into `Get-PowerState`** and re-bank a six-leg `pwrcheck`.
3. **Then** the sitting on a box that heats.

Running step 3 first - which is exactly what this chip asked for, in good
faith, because the defect was not known - would have produced a table of
frequency drift reduced by `cfpowersum.py` out of numbers with a 2.83x
spread and no physical meaning. **On a box that DOES heat, that table would
have been readable as confirmation**, because a sitting that heats also
drifts in `c_f` for the reasons candidates 1 and 2 already establish, and a
noisy frequency column correlates with anything often enough to be quoted
once. This lane's null is worth more than that table would have been.

## The pre-registered design for the sitting, so step 3 is a run and not a design

Held in full, unrun, so that whoever reaches a hot box inherits a design
fixed before any number exists - the practice `crpool4m`, `crband`,
`crpin4m`, `cfbuf` and `cfknee` used.

**Box: intel-core-ultra-9-386h.** Its `THRM_0` read 81.05 C and 39.1 C in one session;
intel-i5-10600kf is a desktop i5 that sat at 27.9 C for a whole sitting and has no
dynamic range to offer. Read its `.claude/MACHINES.md` entry first, all of
it, and in particular: name an explicit `target\release\` path (the box
carries a debug binary that is 7.8x slower on md5), and do not re-derive the
withdrawn "throttled" verdict - an internal note is
the evidence and there is zero `Kernel-Processor-Power` event ID 37 in the
whole log.

**Harness: origin/main's, NOT the `07a24a959` pin**, because the thermal
fields did not exist there. **The load-bearing consequence, which must be
restated in the write-up: no `c_f` cell from that round is comparable with
any banked cell in the campaign** - the LEG line changed and `foreign_cpu`
changed definition at `9686ac296`. That is acceptable only because every
comparison the question needs is INTERNAL, early legsets against late ones in
one sitting on one instrument. Do not quote a level against a banked figure
and do not calibrate against one.

**Pin the pool.** Candidate 2 is confirmed: an unpinned 4-thread pool's
legset-to-legset spread is 7.0% against 0.3% pinned, and the two placements
such a pool can get differ by 43.6% in `c_f` - far larger than any plausible
thermal term, so an unpinned thermal round measures placement. Read the
topology with `GetLogicalProcessorInformation` rather than assuming it: this
part is 16C/16T in THREE classes (0-3 P, 4-11 E, 12-15 LP-E), which
`.claude/MACHINES.md` calls "the one genuine hazard". Assert the pin - every
leg carries `affinity=` and `affinity_got=` and they must read equal.

**Keep the box quiet.** Candidate 1 is confirmed and front-loaded: the first
~11 points of foreign CPU cost 0.395% of `c_f` per point. Re-confirm quiet
before each legset, not once at the start.

**Warm-up check FIRST, before committing to a long sitting.** Run a few legs
and confirm `temp_after_c` actually climbs. If it does not, stand down
cheaply. **Report "the box did not heat" and "heat did not move `c_f`" as
the different results they are** - only the second answers the question.

**What confirms:** end-of-leg frequency falls across the sitting and `c_f`
rises with it, monotonically, beyond the sitting's own measured noise floor -
and the noise floor is measured in the same sitting, never assumed.
**What refutes:** frequency moves and `c_f` does not, or frequency is flat.

**What this design does NOT license,** whatever it finds: moving any
constant. Not `NTT_WINDOW_COMBINE_X86`, not any `NTT_MIN_MISSING*`. A drift
finding is a fact about how to READ a cell, not a reason to retune one.

## Files

| file | what |
|---|---|
| `README.md` | this - the finding, and the pre-registered design for the unrun sitting |
| `pwrcheck2.ps1` | the on-box A/B of the three sampling routes; step 1 above. UNRUN |
