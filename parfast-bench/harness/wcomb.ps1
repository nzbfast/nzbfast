param(
  [string]$Root = '<rig>\wcomb-14sep',   # holds src\, fix\, logs\; the rig's own tree
  [string]$Phase = 'measure',                    # measure | validate
  [string]$Tag = 'wcomb',
  [string]$Bin = '',                             # default $Root\src\target\release\parfast.exe
  [string]$AltBin = '',                          # validate: a second binary, run as arm `autoalt`
  [int]$Reps = 2,
  [string]$Arms = '',                            # validate only: default fold,force,auto
  [string]$Rungs = '',                           # override the phase's m list, comma separated
  [string]$Threads = '',                         # override the phase's thread list, comma separated
  [string]$Gf16Force = '',                       # NZBFAST_GF16_FORCE for every leg (avx2 = nibble on a GFNI part)
  [int]$Slice = 65536,                           # fixture block size; anything but the default gets its own fix-<slice>-<mib>\
  [int]$MemberMiB = 64,                          # size of each of the 16 members, a multiple of 8
  [int]$Recovery = 4096,                         # recovery blocks the fixture is created with
  [string]$Label = '',                           # rowgate: names the shape on every LEG line (rowgate.py read groups by it)
  [string]$NttBudget = '',                       # NZBFAST_NTT_BUDGET (bytes) for every RESIDENT leg, so a corpus past RAM/4 stays one window
  [string]$Residency = '',                       # resident | windowed - ASSERT which side of the admission gate every transform leg took (create included, since 16 Sep 2026)
  [string]$Budget = '',                          # rowgate/validate/measure/create: the -m the legs run at ('big' = none); the phase's own default otherwise
  [string]$NttBudgets = '',                      # validate: m=bytes,m=bytes - the NZBFAST_NTT_BUDGET an `inb*` arm runs at that rung
  [switch]$Flip,                                 # validate: ACCEPTED AND IGNORED since 18 Sep 2026 - the arms rotate every rep unconditionally; kept so a banked launch line still parses
  [string]$Affinity = '',                        # CPU affinity mask for EVERY leg of this round, e.g. 0xF - see the note below
  [string]$Payload = 'random',                   # random | text | mixed - WHAT THE MEMBERS CONTAIN; see the payload note below
  [switch]$NoBuild
)
# wcomb.ps1 - the windowed-transform combine ratio k = c_w / c_f on a WINDOWS box.
#
# The Windows port of harness/memladder.py, written 14 Sep 2026 for
# lane parfast-x86-window-combine-measure-14sep
# (an internal note, section 6).
# memladder.py cannot run on the Windows rig boxes for two reasons that are
# facts about the boxes and not about the script: it reads child CPU with
# `os.wait4` and load with `os.getloadavg`, neither of which exists on Windows,
# and intel-i5-10600kf and intel-core-ultra-9-386h have NO python at all (`python` is the
# Microsoft Store alias and prints an install prompt). So this is PowerShell
# over plib.ps1, which already carries everything a leg needs: the per-box rig
# LOCK, the quiet-box guard sampled before AND after each leg, child CPU from
# the process handle (`TotalProcessorTime`, user + kernel - the Windows
# equivalent of wait4's ru_utime + ru_stime), peak working set, the same
# scattered damage plan and slice restore, and the parallel SHA-256 gate.
#
# Launch it DETACHED, never with Start-Process over ssh (wlaunch.ps1's header):
#
#   powershell -File <src>\research\harness\wlaunch.ps1 -Root <root> -Tag wcomb-measure \
#     -Script "<src>\research\harness\wcomb.ps1 -Root <root> -Phase measure -Tag wcomb-measure"
#
# PHASES
#
#   measure   the constants. For each thread count (4 = the NAS pool, and the
#             box's full logical count, because the old window-floor docstring
#             argued thread count separates boxes):
#               fold  NZBFAST_NTT=0, no -m, m = 192,512,1024,2048,4096
#                     -> c_f, the slope of whole-process CPU in m
#               force NZBFAST_NTT=force + NZBFAST_NTT_PROFILE=1, m = 256,1024,4096,
#                     once with the corpus resident (no -m, ONE window) and once
#                     under -m128 (windows of ~2,000 sources, slabs at 4,096)
#                     -> c_w, per window: depth0 - leaves of that window's
#                        `ntt profile` line (the counters are swapped to zero
#                        at every report, so each line is one window)
#             -Budget replaces that -m128 (the window this prices), which is
#             what a block size other than 64 KiB needs: at 1 MiB a 128 MiB
#             budget is a 128-source window, under NTT_MIN_WINDOW_PRESENT and
#             nothing the dispatcher would ever run.
#   validate  the dispatcher. -t4 -m128, fold / force / auto (nothing set) at
#             m = 192..4,096 - auto should take the transform where force
#             beats fold. Re-run with -Arms auto against a rebuilt binary.
#             `inb` (and its A/A copy `inb2`), added 15 Sep 2026 for lane
#             parfast-ntt-nibble-windowed-ask-15sep: the forced transform
#             INSIDE the budget. `force` takes the whole -m budget as its
#             corpus window with no arena subtraction, so it runs fewer,
#             larger windows than `auto` ever could; `inb` is force with
#             NZBFAST_NTT_BUDGET set per rung from -NttBudgets to the corpus
#             budget `auto`'s admission hands the worker (budget - arenas at
#             the geometry's width), so where `auto` transforms the two must
#             run the same windows - check that before reading `inb` where
#             `auto` folds.
#             THE ARM ORDER ROTATES ONE STEP PER REP, unconditionally, since
#             18 Sep 2026. It used to rotate only behind -Flip and the round
#             header never echoed the switch, so no banked validate log could
#             be classified for a position effect at all - two banked callers
#             classify either way, one having passed the switch and one not.
#             -Flip is still accepted and is now IGNORED, with a warning on
#             the round's own output stream. Never `[array]::Reverse` here:
#             reversing an odd arm count leaves the middle arm in the middle
#             forever, which is the defect jcross.ps1 shipped on 12 Sep 2026.
#             The rule, and why banking the order matters as much as rotating
#             it, is `.claude/skills/bench-suite`, "Writing an A/B driver";
#             the census is an internal note
#             section 6 and an internal note section
#             5 item 5.
# -Affinity PINS EVERY LEG OF THE ROUND TO A CPU MASK, e.g. `-Affinity 0xF`.
# Added 16 Sep 2026 for lane parfast-4mib-pinned-affinity-pools. On a HYBRID
# part a thread count is not a core mix: intel-core-ultra-9-386h is 16C/16T as 4 P-cores
# (0-3), 8 E (4-11) and 4 LP-E (12-15), and `.claude/MACHINES.md` measures a
# 1.43x single-thread swing decided purely by where Windows puts an unpinned
# thread. So a `-t4` ladder there measures "four threads as Windows places
# them", and reading it against a `-t16` ladder confounds POOL SIZE with CORE
# MIX. `-Affinity 0xF -Threads 4` is four P-cores; `-Affinity 0xF0 -Threads 4`
# is four E-cores; no -Affinity is what every round before this one ran.
#
# FOUR THINGS ABOUT IT, and each is a trap rather than a preference:
#   * PASS -Threads EXPLICITLY on a pinned round. The mask is applied just
#     after the child starts (ProcessStartInfo cannot create one suspended),
#     so a child that counted cores for itself could have sized its pool off
#     the UNPINNED mask. Every pinned arm naming -t<n> makes that unreachable.
#   * THE MASK IS READ BACK and refused on mismatch (`WCOMB-FAIL affinity`),
#     in both Run-Cell (measure/validate/rowgate) and Run-Create (create).
#     A pin that silently failed would publish an unpinned leg under a pinned
#     arm's name - the same class as a transform leg that folded, which the
#     residency arm already refuses.
#   * CPU-SECONDS ARE NOT COMPARABLE ACROSS MASKS. A P-core second and an
#     E-core second buy different amounts of work, so an E-pinned arm's raw
#     `cpu=` must never be read against a P-pinned arm's. What IS comparable
#     is the CROSSOVER, because it is a ratio of fold to force WITHIN one arm
#     on one core mix. Reduce per arm, compare crossovers.
#   * GIVE EACH MASK ITS OWN -Label. rowgate.py read groups by (label,
#     threads), so two masks at one thread count merge into one table and the
#     round becomes unreadable. The mask IS stamped on every LEG line
#     (`affinity=`), so a merged log is recoverable, but do not rely on it.
#
# EVERY LEG LINE CARRIES FREQUENCY AND THERMAL STATE since 18 Sep 2026, added
# for lane cf-load-term-buffer-and-placement-18sep: `freq_mhz` / `freq_after_mhz`,
# `perf_pct` / `perf_after_pct` (the raw counter the MHz is derived from, so a
# reader can check the derivation), `temp_c` / `temp_after_c`, `throttle_pct`
# and `pkg_w`. They exist because the within-sitting drift census of 18 Sep
# ranked THERMAL OR POWER DRIFT third among the candidates for the unexplained
# residual in `c_f` and then could not test it at all - no LEG line in the whole
# banked corpus carried either quantity, so there was nothing to reduce and the
# candidate was untestable by construction rather than merely unproven.
#
# THE FREQUENCY HALF OF THOSE FIELDS DOES NOT WORK, found 18 Sep 2026 by lane
# `cf-thermal-drift-candidate3-18sep` from the six validation legs this lane
# itself banked: `freq_after_mhz` spans 912-2585 MHz across legs that all held
# ~10 of 12 threads busy on a box whose thermometer read 27.9 C on every
# sample. `perf_pct` and both `freq_*` fields are still EMITTED - the columns
# become correct the moment the sampler is fixed, and a column that vanishes is
# how a gap stops being visible - but they MUST NOT be reduced or quoted.
# `temp_c`, `temp_after_c` and `throttle_pct` are sound: they are instantaneous
# gauges and one query reads them correctly. Diagnosis, the proposed raw-delta
# fix and its on-box validator:
# `rounds/cf-thermal-drift-2026-09-18/README.md`; the full argument
# sits at the site, in `Get-PowerState`'s header in plib.ps1. SO CANDIDATE 3 IS
# NOT YET TESTABLE AFTER ALL - it is blocked on that fix, not on a hot box.
#
# `pkg_w` READS `na` ON THIS FLEET AND THAT IS A MEASURED FACT, not a stub.
# Intel exposes package watts through RAPL MSRs, which Windows does not surface
# to user mode: intel-i5-10600kf has no hardware-monitor WMI namespace, no Intel Power
# Gadget, and no `Win32_Battery` (it is a desktop), so the ACPI `Power Meter`
# counter set laptops carry has no instance either. Every remaining route needs
# a kernel driver, which is a decision for the maintainer about a shared timing box and not
# something a lane installs. The field is EMITTED rather than omitted so a box
# that can read it needs no format change and no reducer edit, and so the
# absence is recorded in every log instead of being a column a later reader has
# to go and rediscover. Get-PowerState's own header in plib.ps1 carries the
# full measurement, including why `Win32_Processor.CurrentClockSpeed` is the
# wrong source for the frequency half and would publish a dead constant.
#
# THEY ARE ADDITIVE AND OLDER LOGS DO NOT CARRY THEM. Every reducer here parses
# a LEG line as whitespace-separated `key=value`, so an added field cannot
# displace an existing one and no reducer needed changing. They sit just BEFORE
# `ts=` rather than after it, which is additive in the sense that matters and
# keeps the timestamp as the line's last field, the way every LEG line in the
# banked corpus already ends; a reducer that found a field by POSITION would
# have been broken by either choice, and none does.
# No reducer needed changing: a reducer that comes
# to READ these must treat absent as "this log predates the field and says
# nothing about thermals", never as zero - the pattern `wcombsum.shape()` uses
# for `slice=`/`n=`, which it states in words in the log it prints.
#
#   rowgate   the single-window row gate (fastpar::ntt_min_missing), added
#             15 Sep 2026 for lane parfast-ntt-row-gate-gfni-avx512-15sep:
#             fold / force at NO -m (the corpus resident, so no window or slab
#             enters), no profile, m = 192..640 (or -Rungs) at 4 and the full
#             logical count (or -Threads), each rung ABBA as
#             `fold force force2 fold2` - the 2 arms are the SAME arm again, an
#             A/A pair seconds apart, so a cell whose effect does not clear its
#             own pair is reported unresolved (rowgate.py read, which reduces
#             this phase and harness/rowgate.py's unix legs alike).
#             Pass -Arms with fold/force/auto (and -AltBin's autoalt) to check
#             the dispatcher on the same resident ladder instead.
#             -Residency resident|windowed ASSERTS which side of the admission
#             gate every transform leg took, and stamps the DECLARED side on
#             every LEG line (`residency=`, `unset` when not declared). Without
#             it the log records where a leg LANDED (`windows=`) but never what
#             the round INTENDED, and the resident ladder (ntt_min_missing) and
#             the -Budget one (ntt_window_row_gate) are different gates whose
#             legs are otherwise indistinguishable - so a leg that crossed
#             silently published under the other gate's name with every field
#             well-formed. Use `-Residency resident` on any round whose corpus
#             approaches RAM/4, where forgetting -NttBudget is what makes the
#             forced arm cross. Added 16 Sep 2026 for lane
#             avx512-bare-metal-row-gate-16sep, whose 1 MiB n = 16,384 fixture
#             is 16 GiB against a 62 GB box; the same boundary from the
#             windowed pole is section 8.1a of
#             an internal note.
#   create    the CREATE's row gate (par2gen::ntt_range::create_ntt_min_rows),
#             added 16 Sep 2026 for lane parfast-gfni256-1mib-create-and-window-15sep:
#             `parfast c` at -Rungs recovery rows, fold against the forced
#             transform, ABBA with an A/A copy, no damage and no repair. THREE
#             things differ from the repair phases and each is forced by the
#             create path, not by taste:
#               * THE FORCED ARM IS A GATE KNOB, not NZBFAST_NTT=force. The
#                 create reads NZBFAST_NTT only for 0/off; its admission is
#                 create_ntt_min_rows / create_ntt_min_present, so the forced
#                 arm is NZBFAST_CREATE_NTT_MIN_ROWS=0 (the bench knob that
#                 constant carries for exactly this sweep) and the shape must
#                 clear the INPUT floor on its own (2,048 on x86) or the arm
#                 silently folds.
#               * THE PATH IS READ OFF `plan prep`, not `ntt syndromes`: the
#                 create prints no syndrome line. Under NZBFAST_REPAIR_TIMING
#                 (every leg has it) ntt_range's PrepSpan prints
#                 `plan prep: <t> over <n> cold build(s)`, and n > 0 IS "the
#                 transform planned". A fold leg prints n = 0 or no line at all.
#                 Same refusal as the repair phases: an arm that did not take
#                 its path measured the other arm under this arm's name.
#               * THE CORRECTNESS GATE IS CROSS-ARM, not a restore. Nothing is
#                 damaged, so `restored=16/16` has nothing to say; instead every
#                 leg's recovery files are SHA-256'd and compared against the
#                 first leg at that rung (`match=1`), which is the create's
#                 form of "byte-identical output whichever arm ran".
#             -Budget WINDOWS THIS LADDER, since 16 Sep 2026 (lane
#             create-windowed-ladder-4mib-gfni256, the first windowed create
#             ladder on any block size). `parfast c -m<MiB>` publishes a user
#             limit, ntt_budget_within_published takes it, and
#             create_ntt_window divides it by the block size - so the same -m
#             the repair phases take windows a create, at the same S, which is
#             what lets a create cell be read against a measured repair cell
#             rather than against a curve. TWO THINGS TO KNOW BEFORE USING IT:
#               * -NttBudget IS DROPPED on a windowed create leg, because
#                 NZBFAST_NTT_BUDGET is an OVERRIDE and would restore the
#                 resident budget the -m just asked to leave (the guard is at
#                 the site, in Run-Create).
#               * THE CREATE NEVER ASKS ntt_window_row_gate. The repair's
#                 windowed admission scales its row gate by the window
#                 (fastpar::ntt_window_row_ask); the create's asks
#                 create_ntt_min_rows(block_size) - the RESIDENT gate - at
#                 every window size, and nothing on the create path consults
#                 the windowed curve at all. So `-Phase create -Budget ...`
#                 is not "the other gate" the way `-Phase rowgate -Budget ...`
#                 is: it is the SAME gate, measured where its own premise may
#                 not hold. That is the question the ladder exists to answer,
#                 and it is why a windowed create ladder is worth running.
#             -Residency covers this phase too, and keys on the create's own
#             `create ntt rows ... (n=N, W window(s) of S, ... probe ok)` line
#             rather than on the repair's window and syndrome lines, which a
#             create never prints: resident is W = 1 with S = n (or the mapped
#             route, one window by construction), windowed is W > 1. Before
#             that the switch was silently inert here - a create leg under a
#             -m published under the windowed name whether it windowed or not.
#
# FIXTURE, built once under $Root\fix and identical in shape to memladder's:
# 16 x 64 MiB of RandomNumberGenerator bytes, `parfast c -q -s65536 -c4096`
# (n = 16,384 source blocks at 64 KiB, 4,096 recovery). -Slice, -MemberMiB and
# -Recovery build another shape under $Root\fix-<slice>-<mib> instead (e.g.
# -Slice 1048576 -MemberMiB 256 -Recovery 1024: n = 4,096 at 1 MiB), so the
# gate is not set off one block size. Damage is plib's
# seeded pick list (seed 1000+m, identical across arms at a rung). It is NOT
# byte-identical to pdrv.py's picks - .NET's Random is not Python's - which
# costs nothing here: the constants are per-box and no cross-box leg pairs.
#
# -Payload CHANGES WHAT THE MEMBERS CONTAIN, and it is the one fixture axis
# that did not exist before 16 Sep 2026 (lane
# `create-rowgate-4mib-payload-control`). `random` is the default and the
# historical behaviour to the byte, so every round before that date, and every
# invocation that does not name this parameter, is unchanged:
#
#   random  RandomNumberGenerator bytes, the friendliest possible input to a
#           fold, and what every figure in the row-gate note was measured on.
#   text    the round's own source tree, concatenated into a >= 32 MiB pool and
#           tiled, each member rotated 7 MiB + 1 against the last. Real text
#           with real byte-frequency skew.
#   mixed   alternating 8 MiB of that pool and 8 MiB of random - the shape of a
#           posted archive, headers and stored text beside compressed payload.
#
# A NON-RANDOM PAYLOAD LIVES IN ITS OWN FIXTURE DIRECTORY
# (`fix-<slice>-<mib>-<payload>`), because the builder runs only when gold.txt
# is absent and a shared directory would silently serve random bytes to a text
# round. The payload is stamped on EVERY LEG LINE and in the fixture's
# shape.txt, so a reducer cannot fold two payloads into one column; the pool's
# SHA-256, byte count and file count go on a PAYLOAD-POOL line at build time.
#
# Every leg is SHA-256 gated against the pristine members (`restored=16/16` IS
# "the output bytes are the pristine bytes") and undone by slice, re-gated, and
# fallen back to a full member copy if the gate still fails.
. (Join-Path $PSScriptRoot 'plib.ps1')

# $slice IS $Slice (PowerShell names are case-insensitive); the 64 KiB default
# keeps the historical fix\ so the measure and validate rounds reuse it.
$src = Join-Path $Root 'src'
if (-not $Bin) { $Bin = Join-Path $src 'target\release\parfast.exe' }
if ($MemberMiB % 8) { "WCOMB-FAIL -MemberMiB $MemberMiB is not a multiple of 8"; exit 9 }
if ($Payload -notin @('random', 'text', 'mixed')) { "WCOMB-FAIL -Payload $Payload is not random|text|mixed"; exit 9 }
# -Rungs and -Threads are [string] PARAMETERS THAT TAKE A COMMA LIST, and until
# 17 Sep 2026 that list was parsed only at dispatch time (originally around
# line 520), deep inside the try block: after Take-RigLock, after the release
# build and after the fixture (up to 8 GiB) was created. An unquoted
# `-Rungs 288,304,320,336,352` on the caller's command line is not a string at
# all - PowerShell parses a bare comma list as an ARRAY and binds it to the
# [string] parameter by STRINGIFYING IT SPACE-SEPARATED, so $Rungs became the
# single string "288 304 320 336 352" and `$Rungs.Split(',')` returned ONE
# element that `[int]` then threw on. That is exactly what happened to lane
# gfni256-resident-gate-bracket on intel-core-ultra-9-386h on 16 Sep 2026: 22 minutes and
# a rig lock spent (124.7 s build, an 8 GiB fixture) before the first leg, for
# an argument mistake every other bad argument on this page fails in under a
# second. QUOTE THE LIST: `-Rungs "288,304,320,336,352"`.
foreach ($pn in 'Rungs', 'Threads') {
  $pv = Get-Variable $pn -ValueOnly
  if ($pv -and ($pv.Split(',') | Where-Object { $_.Trim() -notmatch '^\d+$' })) {
    "WCOMB-FAIL -$pn '$pv' is not a comma list of integers with no spaces - an unquoted list on the command line (e.g. -$pn 1,2,3) is parsed as an ARRAY and rebound as a space-separated string; quote it instead (-$pn `"1,2,3`")"
    exit 9
  }
}
# -Residency IS INCOMPATIBLE WITH -Phase measure, and until 17 Sep 2026 nothing
# said so - the second half of this claim, handed over from the
# parfast-t6-1mib-nibble-smt lane on 16 Sep rather than raced. The residency
# assert (further down, in Run-Cell) fires on any `arm -like 'force*'` with no
# BUDGET distinction, but `measure` runs TWO force legs per rung: one `big`
# (resident by construction) and one `-Budget` (WINDOWED by construction, and
# the windowed one IS the c_w measurement this phase exists to take). So
# `-Phase measure -Residency resident` burns the lock, the build and the
# fixture and then dies at the SECOND force leg with a message that reads like
# a real residency violation rather than a bad invocation - and it has never
# worked: all 564 banked `residency=resident` legs under rounds/ are
# `-Phase rowgate`, not one is `measure`. Same remedy as the -Rungs/-Threads
# check above: refuse before Take-RigLock. `measure` wants the post-hoc assert
# a ladder actually needs instead - see
# rounds/t6-1mib-nibble-smt-2026-09-16/t6ctl.ps1 for a worked example.
if ($Residency -and $Phase -eq 'measure') {
  "WCOMB-FAIL -Residency $Residency is incompatible with -Phase measure - measure runs a resident AND a windowed force leg per rung by design, so a single -Residency assert on both always dies at the second one; assert residency post-hoc instead, per t6ctl.ps1"
  exit 9
}
# A NON-RANDOM PAYLOAD GETS ITS OWN FIXTURE DIRECTORY, and that is not tidiness.
# The builder below only runs when gold.txt is ABSENT, so a text round pointed at
# a directory a random round already built would silently measure RANDOM bytes
# and stamp `payload=text` on every LEG line - the exact "derived and measured
# rows in one column" failure section 32 of an internal note
# was written about. The default keeps `fix\` and `fix-<slice>-<mib>\` spelled
# EXACTLY as every round before 16 Sep 2026 spelled them, so no existing fixture
# is orphaned and no existing invocation changes meaning.
# Three plain assignments rather than one `if/elseif` expression: a newline
# before `elseif` inside an assignment is exactly the shape PowerShell 5.1
# parses differently from how it reads, and this file cannot be parse-checked
# on the dev Mac (no pwsh) - so the spelling that cannot be got wrong wins.
$fix = Join-Path $Root "fix-$slice-$MemberMiB"
if ($slice -eq 65536 -and $MemberMiB -eq 64) { $fix = Join-Path $Root 'fix' }
if ($Payload -ne 'random') { $fix = Join-Path $Root "fix-$slice-$MemberMiB-$Payload" }
$pristine = Join-Path $fix 'pristine'
$work = Join-Path $fix 'work'
$logs = Join-Path $Root "logs\$Tag"
$lock = Join-Path $env:USERPROFILE '.parfast-rig.lock'
$full = [int]$env:NUMBER_OF_PROCESSORS
$nttb = @{}
if ($NttBudgets) { foreach ($kv in $NttBudgets.Split(',')) { $p = $kv.Split('='); $nttb[[int]$p[0]] = $p[1] } }
$members = @(1..16 | ForEach-Object { 'm{0:D2}.bin' -f $_ })

# A leg's environment is this process's plus the arm's overlay, so an
# NZBFAST_* left in the launching session would silently join every arm.
Get-ChildItem env: | Where-Object { $_.Name -like 'NZBFAST_*' } | ForEach-Object { Remove-Item "env:$($_.Name)" }

function Get-LoadPct {
  $v = -1
  try { $v = [int]((Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average) } catch { }
  return $v
}

# `{:.2?}` Duration text to seconds. `$unit` is what the callers' regex caught
# BEFORE the final `s` - empty for seconds, `m`, `n`, or whatever the OEM code
# page made of `µ` (the child's stderr is decoded with it, and `µs` does not
# survive). The first cut of this compared against `s` and `ms`, so every
# whole-second phase read as microseconds and printed 0.
function Get-Secs([string]$num, [string]$unit) {
  $x = [double]::Parse($num, [Globalization.CultureInfo]::InvariantCulture)
  if ($unit -eq '') { return $x }
  if ($unit -eq 'm') { return $x / 1e3 }
  if ($unit -eq 'n') { return $x / 1e9 }
  return $x / 1e6
}

# Parse -Affinity once, refuse a mask that names no core on this box, and arm
# plib's Invoke-Leg with it. 0/'' leaves every leg placed by the box, which is
# what every round before 16 Sep 2026 did.
$AffinityMask = 0L
if ($Affinity) {
  $t = $Affinity.Trim()
  try {
    $AffinityMask = if ($t -match '^0[xX]') { [Convert]::ToInt64($t.Substring(2), 16) } else { [Convert]::ToInt64($t, 10) }
  } catch { throw "WCOMB-FAIL -Affinity '$Affinity' is not a number (want 0xF or 15)" }
  if ($AffinityMask -le 0) { throw "WCOMB-FAIL -Affinity '$Affinity' selects no core" }
  $ncpu = [int]$env:NUMBER_OF_PROCESSORS
  if ($ncpu -gt 0 -and $ncpu -lt 63) {
    $full = ([int64]1 -shl $ncpu) - 1
    if (($AffinityMask -band (-bnot $full)) -ne 0) {
      throw "WCOMB-FAIL -Affinity 0x$($AffinityMask.ToString('X')) names a core above this box's $ncpu (full mask 0x$($full.ToString('X')))"
    }
  }
  $bits = 0; $tmp = $AffinityMask
  while ($tmp) { $bits += [int]($tmp -band 1); $tmp = $tmp -shr 1 }
  "AFFINITY mask=0x$($AffinityMask.ToString('X')) cores=$bits of $ncpu label=$Label threads=$Threads"
}
Set-LegAffinity $AffinityMask

function Get-Num([string]$s) { [double]::Parse($s, [Globalization.CultureInfo]::InvariantCulture) }

New-Item -ItemType Directory -Force $logs | Out-Null
Take-RigLock $Tag   # the ROUND's name, not $lock: see plib.ps1's Take-RigLock
try {
  # `arm_order=` IS THE ONLY THING IN A BANKED LOG THAT SAYS WHICH ORDERING
  # RULE PRODUCED IT. Until 18 Sep 2026 this header carried no such token and
  # the validate phase rotated only behind an optional -Flip, so a reader of a
  # banked wcomb validate round could not tell a rotated ladder from a fixed
  # one without reconstructing the rule out of the LEG lines. Change this
  # string whenever the rule changes.
  #   validate  rotating-by-rep, one step per rep, every arm in every slot
  #   rowgate   abba-by-rep - the four legs are two A/A pairs written ABBA,
  #   create    reversed whole on even reps; unchanged 18 Sep 2026
  #   measure   fixed - fold and force run DIFFERENT rung lists here, so there
  #             is no single arm list to rotate and nothing to claim
  $armOrderTag = switch ($Phase) {
    'validate' { 'rotating-by-rep' }
    'rowgate'  { 'abba-by-rep' }
    'create'   { 'abba-by-rep' }
    default    { 'fixed' }
  }
  "ROUND tag=$Tag phase=$Phase root=$Root bin=$Bin reps=$Reps gf16force=$Gf16Force arm_order=$armOrderTag start=$((Get-Date).ToUniversalTime().ToString('o'))"
  if ($Flip) { "WCOMB-WARN -Flip is accepted and IGNORED since 18 Sep 2026 - the validate arms rotate one step every rep unconditionally, which is a superset of what the switch did; the launch line needs no edit" }
  Write-BoxFacts
  Write-HarnessFacts @($PSCommandPath)

  # SOURCE-TREE STAMP ON ENTRY, before the build - in addition to, not instead
  # of, the SRC-NOINDEX stamp below. A lane does not create $src at
  # SRC-NOINDEX's line; it creates it by scp + tar x minutes to hours earlier,
  # while queueing on a shared box, and Windows Search notices a fresh 100+ MB
  # tree within seconds - the window this closes. The stamp is idempotent and
  # costs milliseconds, so paying it twice is cheaper than missing it once.
  # an internal note.
  if (Test-Path $src) {
    cmd /c "attrib +I `"$src\*`" /S /D" | Out-Null
    "SRC-NOINDEX-ENTRY rc=$LASTEXITCODE src=$src"
  }

  if (-not $NoBuild) {
    # A round started through Win32_Process::Create (wlaunch.ps1) does not
    # always see the user's PATH, and rustup's shims live in the profile.
    if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
    $bw = [Diagnostics.Stopwatch]::StartNew()
    Push-Location $src
    # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
    # plib's $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first
    # stderr line of a native command into a terminating error.
    cmd /c "cargo build --release -p parfast --locked > `"$Root\build-$Tag.log`" 2>&1"
    $brc = $LASTEXITCODE
    Pop-Location
    "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-$Tag.log"
    if ($brc -ne 0) { "WCOMB-FAIL build"; exit 9 }
  }
  Write-BinFacts (Split-Path $Bin -Parent) @([IO.Path]::GetFileNameWithoutExtension($Bin))
  if ($AltBin) { Write-BinFacts (Split-Path $AltBin -Parent) @([IO.Path]::GetFileNameWithoutExtension($AltBin)) }

  $goldpath = Join-Path $fix 'gold.txt'
  $builtfixture = $false
  if (-not (Test-Path $goldpath)) {
    $builtfixture = $true
    New-Item -ItemType Directory -Force $pristine, $work | Out-Null
    $rng = [Security.Cryptography.RandomNumberGenerator]::Create()
    $buf = New-Object byte[] (8MB)
    # THE PAYLOAD. Until 16 Sep 2026 this loop wrote RandomNumberGenerator bytes
    # unconditionally, and every round on this harness therefore measured the
    # friendliest possible input to a fold. That was the first stated limit of
    # the section "The CREATE at 4 MiB: it crosses BELOW the repair" in
    # an internal note, and it is not idle:
    # section 32 of an internal note measured a per-code
    # constant on intel-core-ultra-9-386h that is 1.79x payload-dependent across four
    # cases, and OPPOSITE IN DIRECTION to arm64. "The GF row operations do not
    # branch on data, therefore payload-blind" is an assumption, and on this
    # box it is an assumption that has been wrong twice in one week.
    #
    # `text` and `mixed` TILE A POOL BUILT FROM THE ROUND'S OWN SOURCE TREE,
    # deliberately, over the two cheaper things that were considered:
    #   - a constant or low-entropy filler is as unrepresentative as random,
    #     in the other direction, and would price a case nothing posts;
    #   - a synthetic Markov/zipf generator would be reproducible only through
    #     this script, so a reader could not rebuild the pool without it.
    # The tree is real text with real byte-frequency skew, it is already ON the
    # box (the round builds from it), and the pool's SHA-256 and length are
    # stamped below so the cell is reproducible from a commit id alone.
    # Members are ROTATED against each other rather than byte-identical: 16
    # identical members are a degenerate corpus and nobody posts one.
    $pool = $null
    if ($Payload -ne 'random') {
      $poolmin = 32MB
      $ms = New-Object IO.MemoryStream
      # NAMED SUBTREES, NOT `-Recurse` OVER $src, and both halves of that matter.
      # The fixture is built AFTER the cargo build, so by this line $src holds a
      # `target\` of some 10 GiB and several hundred thousand files: recursing
      # the whole tree would spend minutes enumerating and sorting it (noise, in
      # a round whose whole output is timings), and - worse - it would put BUILD
      # ARTIFACTS in the pool, so the payload would depend on the toolchain and
      # the cell would not be reproducible from a commit id. These four are
      # committed source and nothing else. Sorted by full path so the pool is a
      # function of the TREE, not of the order the filesystem enumerates it in.
      $roots = @('crates', 'docs', 'research', 'web') | ForEach-Object { Join-Path $src $_ } | Where-Object { Test-Path $_ }
      $cands = @(Get-ChildItem $roots -File -Recurse -ErrorAction SilentlyContinue |
                 Where-Object { $_.Extension -in '.rs', '.md', '.toml', '.py', '.html', '.json', '.ps1', '.sh', '.txt', '.c', '.h', '.yml' } |
                 Sort-Object FullName)
      foreach ($f in $cands) {
        if ($ms.Length -ge $poolmin) { break }
        try { $b = [IO.File]::ReadAllBytes($f.FullName); $ms.Write($b, 0, $b.Length) } catch { }
      }
      if ($ms.Length -lt $poolmin) {
        # FAILING TO FIND IS FAILING. A short pool would be tiled at a much
        # tighter period than intended and would quietly measure a different
        # corpus than the one this round says it measured.
        "WCOMB-FAIL payload=$Payload pool is $($ms.Length) bytes from $($cands.Count) file(s) under $($roots -join ';'), needs $poolmin"
        exit 9
      }
      $pool = $ms.ToArray()
      $ms.Dispose()
      $psha = [BitConverter]::ToString([Security.Cryptography.SHA256]::Create().ComputeHash($pool)).Replace('-', '').ToLower()
      # SHANNON ENTROPY, stamped so the log SAYS how unlike random this payload
      # is instead of leaving a reader to take "text" on trust. Random bytes
      # read 8.000 bits/byte by construction; this repo's Rust source reads
      # about 4.76. It is the one number that makes two payload rounds
      # comparable without either fixture still existing.
      # OVER THE FIRST 8 MiB, not the whole pool, and the key says so. A
      # PowerShell 5.1 `foreach` over a 33 MB byte[] runs at order 1M/s, so the
      # whole pool would be ~30 s spent inside the rig lock for a figure that
      # moves in the third decimal; 8 MiB is ~8 s and answers the same question.
      $esz = [int][Math]::Min(8MB, $pool.Length)
      $hist = New-Object long[] 256
      for ($i = 0; $i -lt $esz; $i++) { $hist[$pool[$i]]++ }
      $ent = 0.0
      foreach ($h in $hist) { if ($h) { $pr = $h / $esz; $ent -= $pr * [Math]::Log($pr, 2) } }
      "PAYLOAD-POOL payload=$Payload bytes=$($pool.Length) files=$($cands.Count) roots=$(($roots | Split-Path -Leaf) -join ',') entropy_bits_8m=$([math]::Round($ent,3)) sha256=$psha"
    }
    $mi = 0
    foreach ($nm in $members) {
      $fs = [IO.File]::Create((Join-Path $pristine $nm))
      if ($Payload -eq 'random') {
        for ($i = 0; $i -lt ($MemberMiB / 8); $i++) { $rng.GetBytes($buf); $fs.Write($buf, 0, $buf.Length) }
      } else {
        # A per-member rotation of 7 MiB + 1 byte: coprime with the 8 MiB chunk
        # so no two members share a chunk boundary alignment either.
        $off = [int]((([long]$mi * 7340033) % $pool.Length))
        $left = [long]$MemberMiB * 1MB
        $chunk = 0
        while ($left -gt 0) {
          $take = [int][Math]::Min([long]8MB, $left)
          if ($Payload -eq 'mixed' -and ($chunk % 2) -eq 1) {
            # `mixed` models a real posted archive: compressed/encrypted payload
            # next to headers and stored text, rather than either extreme alone.
            $rng.GetBytes($buf)
            $fs.Write($buf, 0, $take)
          } else {
            $done = 0
            while ($done -lt $take) {
              $n = [int][Math]::Min($pool.Length - $off, $take - $done)
              $fs.Write($pool, $off, $n)
              $off += $n; $done += $n
              if ($off -ge $pool.Length) { $off = 0 }
            }
          }
          $left -= $take; $chunk++
        }
      }
      $fs.Close()
      $mi++
    }
    $cout = @(Invoke-Leg $Bin "c -q -s$slice -c$Recovery set.par2 $($members -join ' ')" $pristine (Join-Path $logs 'create'))
    $cr = $cout | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    "CREATE rc=$($cr.rc) wall=$($cr.wall) cpu=$($cr.cpu) peak_mb=$($cr.peakmb)"
    if ($cr.rc -ne 0) { "WCOMB-FAIL create"; exit 9 }
    # THE FIXTURE'S OWN SHAPE, written beside gold.txt so a later round can ask
    # the FIXTURE what it is instead of trusting the -Recovery it was invoked
    # with. -Recovery is honoured at CREATE ONLY: an existing fixture is reused
    # whatever a later caller passes, and `fix-<slice>-<mib>` does not encode
    # the recovery count, so two rounds wanting the same slice and members but
    # different -c values silently share one fixture.
    [IO.File]::WriteAllText((Join-Path $fix 'shape.txt'), "slice=$slice members=$($members.Count) membermib=$MemberMiB recovery=$Recovery payload=$Payload`n")
    $lines = foreach ($nm in $members) { "$(Get-Sha256Fast (Join-Path $pristine $nm)) $nm" }
    [IO.File]::WriteAllLines($goldpath, [string[]]$lines)
    foreach ($f in (Get-ChildItem $pristine -File)) { Copy-Item $f.FullName (Join-Path $work $f.Name) -Force }
  }
  # NOT CONTENT INDEXED, every round (so a fixture built before this line gets it
  # too). Windows Search indexes anything under <rig> and re-reads the
  # fixture each time a leg rewrites and restores slices: on intel-core-ultra-9-386h,
  # 15 Sep 2026, SearchIndexer burned ~1.5 cores, the quiet-box guard waited 14
  # times and ~12 legs ran beside it until this attribute stopped it within two
  # minutes (an internal note). Name the CONTENTS
  # with `\*`: a bare directory argument marks only the directory itself.
  cmd /c "attrib +I `"$fix\*`" /S /D" | Out-Null
  "FIXTURE-NOINDEX rc=$LASTEXITCODE fix=$fix"
  # And the round's SOURCE TREE, which the fixture line does not cover. On
  # intel-core-ultra-9-386h, 15 Sep 2026 evening, a fresh extract plus its release build
  # under the round root held SearchIndexer at ~108% of one core through a whole
  # 64 KiB round and into the next (foreign CPU median 86% against 11% once it
  # stopped); `attrib +I` over the tree took it to 0.5% inside two minutes
  # (an internal note, "The block-size clause").
  # This is the SECOND stamp of the tree, not the first - see SRC-NOINDEX-ENTRY
  # above, added 16 Sep 2026 for the window between a lane's scp+tar staging
  # and this line (an internal note).
  # Left here too: idempotent, and it re-covers a tree the build just touched.
  if (Test-Path $src) {
    cmd /c "attrib +I `"$src\*`" /S /D" | Out-Null
    "SRC-NOINDEX rc=$LASTEXITCODE src=$src"
  }
  $gold = @{}
  foreach ($line in [IO.File]::ReadAllLines($goldpath)) { $p = $line.Split(' '); $gold[$p[1]] = $p[0] }
  $parfiles = @(Get-ChildItem $pristine -Filter *.par2 | ForEach-Object { $_.Name })
  $start = Test-RestoredFast $work $members $gold
  if ($start.good -ne $members.Count) { "WCOMB-FAIL work copy not pristine at start: $($start.bad -join ',')"; exit 9 }
  $n = [int](($members | ForEach-Object { [math]::Ceiling((Get-Item (Join-Path $pristine $_)).Length / $slice) } | Measure-Object -Sum).Sum)
  "FIXTURE fix=$fix members=$($members.Count) slice=$slice n=$n parfiles=$($parfiles.Count)"

  # A RUNG ABOVE THE FIXTURE'S RECOVERY COUNT CANNOT BE REPAIRED, and the way
  # that surfaces is not a clear error. Added 16 Sep 2026 after the
  # parfast-k-1mib-nibble-16sep lane lost a launch to it: `-Phase measure`'s
  # default rungs top out at m = 4,096 against a fixture created `-c2048`, so
  # the fold leg returned rc=2 restored=0/16 and the FORCE leg at that rung
  # silently fell back to the fold path. The path assertion caught THAT and
  # refused - correctly, and at the first wrong leg - but by then the fixture
  # was built and a queue slot on a shared box was spent. This refuses before
  # any of that.
  #
  # ASK THE FIXTURE, NOT THE CALLER. shape.txt is authoritative because
  # -Recovery is honoured at create only; when it is absent (a fixture built
  # before this line) fall back to -Recovery and SAY the real count is
  # unverified rather than implying it was checked.
  $shapef = Join-Path $fix 'shape.txt'
  $fixrec = $null; $recsrc = ''
  if (Test-Path $shapef) {
    $mrec = [regex]::Match([IO.File]::ReadAllText($shapef), 'recovery=(\d+)')
    if ($mrec.Success) { $fixrec = [int]$mrec.Groups[1].Value; $recsrc = 'shape.txt' }
  }
  if ($null -eq $fixrec) { $fixrec = $Recovery; $recsrc = '-Recovery (UNVERIFIED - no shape.txt, fixture predates it)' }
  elseif ($fixrec -ne $Recovery) {
    "FIXTURE-RECOVERY-MISMATCH fixture has $fixrec, -Recovery says $Recovery - the EXISTING fixture wins (-Recovery is create-only)"
  }
  "FIXTURE-RECOVERY $fixrec source=$recsrc"
  # The create phase's rungs are RECOVERY ROWS, not damaged blocks, and it
  # damages nothing - so this bound does not apply to it.
  if ($Phase -ne 'create') {
    $chkrungs = if ($Rungs) { @($Rungs.Split(',') | ForEach-Object { [int]$_ }) }
      elseif ($Phase -eq 'measure')  { @(192, 512, 1024, 2048, 4096) }
      elseif ($Phase -eq 'validate') { @(192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096) }
      else                           { @(192, 256, 288, 320, 352, 384, 416, 448, 512, 640) }
    $maxr = ($chkrungs | Measure-Object -Maximum).Maximum
    # -gt, NOT -ge: m missing blocks are repairable from EXACTLY m recovery
    # blocks (the matrix is square and solvable), so m = recovery is the last
    # legal rung and not the first illegal one. The first cut of this used
    # -ge and refused a `-Phase measure` default ladder against the very
    # -c4096 fixture it is meant to run on. The acceptance suite caught it.
    if ($maxr -gt $fixrec) { "WCOMB-FAIL rungs max m=$maxr exceeds the fixture's $fixrec recovery block(s) - that rung cannot be repaired, the fold leg returns rc=2 and the force leg falls back to fold"; exit 9 }
    "RUNG-BOUND ok max_m=$maxr <= recovery=$fixrec"
  }

  # THE VALIDATE PHASE'S ARM ORDER, DECIDED AND ASSERTED HERE rather than in
  # the rep loop, and BEFORE the fixture settle below - which is the last thing
  # this round does before its first leg, and so this driver's warm-up. Two
  # reasons, both learned from jcross.ps1's port on 12 Sep 2026:
  #
  # ONE: THERE IS NO PARSE-CHECK FOR THIS FILE ON THE BOX THAT EDITS IT. The
  # dev Macs run the gates; the rigs run the rounds. So an off-by-one in the
  # modulus, or a rotate-in-place that scrambles every later rep, lands UNRUN
  # and publishes a ladder whose arms are not what the log says they are. The
  # round asserts the property it needs - every arm exactly once, every rep -
  # and dies at leg zero instead. Costing the assertion here rather than in
  # the loop means it fires BEFORE up to twenty minutes of settling.
  #
  # TWO: it prints each rep's order into the log, so a later reader tests a
  # BANKED round for a position effect instead of spending a rig to re-run it.
  # That is the whole of what an internal note
  # section 6 asks of this driver.
  #
  # A NEW ARRAY EVERY REP. Never [array]::Reverse and never a rotate-in-place
  # on @($varms): @() around an object[] hands back the SAME object, so a
  # mutation there would scramble every later rep - and reversing an ODD arm
  # count leaves the middle arm in the middle forever, which is the defect
  # that reported +42.75% for an arm that could not engage.
  $varms = if ($Arms) { @($Arms.Split(',')) } elseif ($AltBin) { @('fold', 'force', 'auto', 'autoalt') } else { @('fold', 'force', 'auto') }
  $vorders = @()
  if ($Phase -eq 'validate') {
    if ($varms.Count -lt 1) { "WCOMB-FAIL validate has no arms"; exit 9 }
    foreach ($rep in 1..$Reps) {
      $k = ($rep - 1) % $varms.Count
      $ord = @(0..($varms.Count - 1) | ForEach-Object { $varms[($k + $_) % $varms.Count] })
      if ($ord.Count -ne $varms.Count -or
          @(Compare-Object $ord $varms -SyncWindow ($varms.Count)).Count -ne 0) {
        "WCOMB-FAIL rep=$rep arm order '$($ord -join ',')' is not a permutation of '$($varms -join ',')'"
        exit 9
      }
      $vorders += ,$ord
      "ARM-ORDER rep=$rep $($ord -join ',')"
    }
    # A rep count that is a MULTIPLE of the arm count is what puts every arm in
    # every slot the same number of times; at 3 arms and 5 reps the first slot
    # goes 2/2/1. Said rather than refused, because a short confirmation round
    # is a legitimate thing to ask this phase for.
    if ($Reps % $varms.Count -ne 0) { "WCOMB-WARN reps=$Reps is not a multiple of arms=$($varms.Count), so the slots are unevenly filled - a paired per-rep statistic still holds, a per-slot mean does not" }
  }

  # A fixture built THIS round is 10.7 GB Windows Search has not seen before,
  # and the `attrib +I` above stops it growing rather than undoing the walk
  # already under way - both stamps returned rc=0 on 16 Sep 2026 and two ladders
  # were spent anyway. So settle before the first leg, and only when this round
  # actually paid for a build: a round reusing an existing fixture has nothing
  # to wait out. Design, threshold and why Require-QuietBox cannot do this job:
  # Wait-FixtureSettle in plib.ps1.
  #
  # AFTER the rung bound above and not before it, so a round that builds a
  # fixture AND was invoked with rungs the fixture cannot repair refuses in
  # milliseconds rather than after up to twenty minutes of settling. Nothing
  # between the two touches the box, so the settle's reading is not stale.
  if ($builtfixture) { Wait-FixtureSettle "fixture-$Tag" }

  # A REFUSED LEG IS NOT A NO-OP, AND THAT IS NOT OBVIOUS FROM READING IT.
  # The damage is written BEFORE the leg runs and the restore happens AFTER the
  # checks, so EVERY refusal in that window leaves work\ damaged. The next
  # round over that fixture then dies at the start gate with
  # "work copy not pristine at start" - a true message about a different
  # problem, minutes later and one confusing round trip from the cause.
  # Found 16 Sep 2026 by the parfast-k-1mib-nibble-16sep lane, which hit it as
  # the second-order consequence of a rung error: the refused leg had damaged
  # 4,096 blocks, and its relaunch could not start.
  #
  # THE RESIDENCY ASSERTION MADE THIS WORSE AND THAT IS WHY IT IS FIXED HERE:
  # before it there was one refusal in that window, now there are six, four of
  # them mine. pristine\ is never damaged, so recovery is a copy and the
  # failure is loud either way - the cheap quadrant, but only once something
  # actually does the copy.
  function Fail-Leg([string]$msg) {
    $msg
    foreach ($nm in $members) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
    foreach ($nm in $parfiles) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
    $c = Test-RestoredFast $work $members $gold
    "FAIL-RESTORE work\ returned to pristine: $($c.good)/$($members.Count) - the fixture is reusable"
    if ($c.good -ne $members.Count) { "FAIL-RESTORE INCOMPLETE - the next round over this fixture WILL refuse at its start gate" }
    exit 9
  }

  function Run-Cell([int]$m, [string]$budget, [string]$arm, [int]$threads, [int]$rep, [bool]$prof, [int]$armPos = 0) {
    $tag = "m$m-$budget-$arm-t$threads-r$rep"
    $dseed = 1000 + $m
    $picks = Get-DamagePicks $work $members $slice $m $dseed
    $wrote = Invoke-DamagePicks $work $members $slice $picks $dseed
    # `autoalt` is `auto` on a SECOND binary (-AltBin), so a dispatcher
    # change is compared rung by rung and rep by rep in the same box state
    # rather than across two rounds an hour apart.
    $exe = if ($arm -eq 'autoalt') { $AltBin } else { $Bin }
    $envx = @{ NZBFAST_REPAIR_TIMING = '1' }
    # `fold2` / `force2` are the rowgate phase's A/A copies: the same arm again.
    if ($arm -like 'fold*') { $envx['NZBFAST_NTT'] = '0' }
    elseif ($arm -like 'force*') { $envx['NZBFAST_NTT'] = 'force' }
    elseif ($arm -like 'inb*') {
      if (-not $nttb.ContainsKey($m)) { Fail-Leg "WCOMB-FAIL arm $arm has no -NttBudgets entry for m=$m" }
      $envx['NZBFAST_NTT'] = 'force'
      $envx['NZBFAST_NTT_BUDGET'] = $nttb[$m]
    }
    if ($prof) { $envx['NZBFAST_NTT_PROFILE'] = '1' }
    if ($Gf16Force) { $envx['NZBFAST_GF16_FORCE'] = $Gf16Force }
    # Every arm, so the A/B differs in the path alone - except an `inb*` arm,
    # whose per-rung -NttBudgets entry is the point of that arm and wins. Added
    # 15 Sep 2026 for lane parfast-ntt-row-gate-block-size-clause-15sep: a 1 MiB
    # fixture at n = 16,384 is 16 GiB, past RAM/4 on a 32 GB box, and without
    # this the forced arm WINDOWS and the ladder measures the windowed curve.
    #
    # RESIDENT LEGS ONLY, since 16 Sep 2026 (lane
    # parfast-window-combine-k-1mib-16sep). This exists to stop a leg windowing
    # when the round wants one window, and a leg run under a `-m` is the round
    # asking for the opposite: handing it a multi-GiB corpus budget too would
    # silently un-window the arm whose windows are the measurement. Every use
    # before this date passed -NttBudget only on resident ladders, so none of
    # them reduces differently; what it buys is ONE round carrying both arms -
    # the resident force legs (c_l) and the windowed ones (c_w) - which is what
    # the measure phase needs at a block size whose corpus does not fit RAM/4.
    if ($NttBudget -and $budget -eq 'big' -and -not $envx.ContainsKey('NZBFAST_NTT_BUDGET')) { $envx['NZBFAST_NTT_BUDGET'] = $NttBudget }
    $argstr = "r -t$threads -q"
    if ($budget -ne 'big') { $argstr += " -m$budget" }
    $argstr += ' set.par2'
    $load0 = Get-LoadPct
    $lout = @(Invoke-Leg $exe $argstr $work (Join-Path $logs $tag) $envx)
    $load1 = Get-LoadPct
    foreach ($s in ($lout | Where-Object { $_ -is [string] })) { $s }
    $r = $lout | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    $post = Test-RestoredFast $work $members $gold
    $strays = Remove-Strays $work $members $parfiles
    $err = [IO.File]::ReadAllText((Join-Path $logs "$tag.err"))

    $d0 = 0.0; $lv = 0.0; $combs = @()
    foreach ($mm in [regex]::Matches($err, 'ntt profile \(inclusive thread-seconds\): depth0 ([0-9.]+) depth1 ([0-9.]+) depth2 ([0-9.]+) leaves ([0-9.]+)')) {
      $a0 = Get-Num $mm.Groups[1].Value; $al = Get-Num $mm.Groups[4].Value
      $d0 += $a0; $lv += $al; $combs += [math]::Round($a0 - $al, 3)
    }
    $wins = @([regex]::Matches($err, 'ntt window \((\d+) bytes, (\d+) slices, (\w+)\)') | ForEach-Object { [int]$_.Groups[2].Value })
    $syn = @([regex]::Matches($err, 'ntt syndromes \(m=(\d+), needed=(\d+), n=(\d+), W=(\d+), threads=(\d+)\)'))
    $ws = @($syn | ForEach-Object { $_.Groups[4].Value } | Sort-Object -Unique)
    $ns = @($syn | ForEach-Object { $_.Groups[3].Value })
    $slabm = [regex]::Match($err, 'in (\d+) slab\(s\) of (\d+) B')
    $slabs = if ($slabm.Success) { $slabm.Groups[1].Value } else { '1' }
    $slabw = if ($slabm.Success) { $slabm.Groups[2].Value } else { "$slice" }
    $fm = [regex]::Match($err, 'forney solve: ([0-9.]+)(\S{0,3}?)s over (\d+) solve')
    $forney = if ($fm.Success) { [math]::Round((Get-Secs $fm.Groups[1].Value $fm.Groups[2].Value), 3) } else { '' }
    $ffm = [regex]::Match($err, 'feed\+fold\+solve: \+([0-9.]+)(\S{0,3}?)s')
    $ffs = if ($ffm.Success) { [math]::Round((Get-Secs $ffm.Groups[1].Value $ffm.Groups[2].Value), 3) } else { '' }
    $unbuildable = ([regex]::Matches($err, 'ntt plan unbuildable')).Count
    $path = if ($syn.Count -gt 0) { 'ntt' } else { 'fold' }
    # A forced arm that did not take its path measured the other arm under this
    # arm's name, and nothing downstream could tell.
    if (($arm -like 'fold*' -and $path -ne 'fold') -or (($arm -like 'force*' -or $arm -like 'inb*') -and $path -ne 'ntt')) { Fail-Leg "WCOMB-FAIL path arm=$arm path=$path at $tag" }
    # WHICH SIDE OF THE ADMISSION GATE THIS LEG WANTED, asserted rather than
    # left to a reader. Added 16 Sep 2026 for lane
    # avx512-bare-metal-row-gate-16sep. A resident ladder and a windowed one
    # are DIFFERENT GATES - ntt_min_missing against ntt_window_row_gate - and
    # until this switch the log recorded which side a leg LANDED on
    # (`windows=`) but never which side the round INTENDED, so a leg that
    # crossed silently published under the other gate's name and the round
    # voided with every line looking well-formed. The same gap, from the
    # opposite pole, is section 8.1a of
    # an internal note, whose round wants
    # the windowed side of this identical boundary.
    #
    # TWO CHECKS, AND THE SECOND IS THE POINT. `windows=0` is an ABSENCE, and
    # an absence is also what this harness reports when a wording change makes
    # a regex miss - so on its own it would PASS a windowed leg after a rename
    # of parfast's `ntt window (...)` line, which is the failure this assert
    # exists to catch. The syndrome line's own `n=` is the positive half, and
    # it is `present.len()` (reconstruct.rs), NOT the fixture's source count:
    # a RESIDENT call sees every present source, so it reads exactly
    # fixture_n - m, and a windowed call reads its own window's smaller
    # present count. Checked against banked legs before this was written -
    # `ntt_n=16064` at m = 320 and `16032` at m = 352 over n = 16,384
    # (rounds/rowgate-2026-09-16/coreultra9-gfni256-1m-n16384-t8.log).
    # An earlier cut of this compared against $n itself and would have failed
    # every leg it ever saw. If THAT wording moves, the path assert above has
    # already fired on $syn.Count -eq 0.
    if ($Residency -and ($arm -like 'force*' -or $arm -like 'inb*')) {
      if ($Residency -eq 'resident') {
        if ($wins.Count -ne 0) { Fail-Leg "WCOMB-FAIL residency want=resident windows=$($wins.Count) arm=$arm at $tag - the forced arm WINDOWED, so this ladder is measuring ntt_window_row_gate and not the resident gate" }
        $want = $n - $m
        $bad = @($ns | Where-Object { [int]$_ -ne $want })
        if ($bad.Count -gt 0) { Fail-Leg "WCOMB-FAIL residency want=resident ntt_n=$($bad -join '/') expected=$want (fixture_n=$n - m=$m) arm=$arm at $tag - a transform call covered fewer than all present sources" }
      } elseif ($Residency -eq 'windowed') {
        if ($wins.Count -eq 0) { Fail-Leg "WCOMB-FAIL residency want=windowed windows=0 arm=$arm at $tag - the forced arm ran RESIDENT" }
      } else { Fail-Leg "WCOMB-FAIL unknown -Residency $Residency (want resident or windowed)" }
    }
    $cmean = if ($combs.Count -gt 0) { [math]::Round((($combs | Measure-Object -Sum).Sum) / $combs.Count, 4) } else { '' }

    # A leg that did not run on the cores its arm names measured a DIFFERENT
    # core mix under this arm's name. Same refusal class as the residency arm
    # above, and it fires before the LEG line so nothing unpinned is published
    # as pinned.
    if ($AffinityMask -and [long]$r.affGot -ne [long]$AffinityMask) {
      Fail-Leg "WCOMB-FAIL affinity want=0x$($AffinityMask.ToString('X')) got=$(if ([long]$r.affGot -eq -1) { 'THREW' } else { '0x' + ([long]$r.affGot).ToString('X') }) arm=$arm at $tag - the leg did not run on the cores this arm names"
    }

    "LEG round=$Tag label=$Label slice=$slice payload=$Payload n=$n phase=$Phase rep=$rep m=$m budget=$budget arm=$arm arm_pos=$(if ($armPos) { $armPos } else { 'na' }) arm_order=$armOrderTag ntt_budget=$($envx['NZBFAST_NTT_BUDGET']) threads=$threads prof=$([int]$prof) rc=$($r.rc) restored=$($post.good)/$($members.Count) wall=$($r.wall) cpu=$($r.cpu) peak_mb=$($r.peakmb) path=$path ntt_w=$($ws -join '/') ntt_calls=$($syn.Count) ntt_n=$(($ns | Select-Object -First 3) -join '/') windows=$($wins.Count) residency=$(if ($Residency) { $Residency } else { 'unset' }) win_slices=$(($wins | Select-Object -First 3) -join '/') slabs=$slabs slab_width=$slabw prof_lines=$($combs.Count) depth0_sum=$([math]::Round($d0,3)) leaves_sum=$([math]::Round($lv,3)) combine_sum=$([math]::Round($d0-$lv,3)) combine_mean=$cmean combine_list=$(($combs | Select-Object -First 12) -join '/') forney_s=$forney ffs_s=$ffs unbuildable=$unbuildable blocks_written=$wrote strays=$strays gf16force=$Gf16Force foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) load_before=$load0 load_after=$load1 errlen=$($r.errlen) affinity=$(if ($AffinityMask) { '0x' + $AffinityMask.ToString('X') } else { 'none' }) affinity_got=$(if ($AffinityMask) { '0x' + ([long]$r.affGot).ToString('X') } else { 'none' }) rig=$(Get-RigStamp) freq_mhz=$($r.pwr0.FreqMhz) freq_after_mhz=$($r.pwr1.FreqMhz) perf_pct=$($r.pwr0.PerfPct) perf_after_pct=$($r.pwr1.PerfPct) temp_c=$($r.pwr0.TempC) temp_after_c=$($r.pwr1.TempC) throttle_pct=$($r.pwr1.ThrottlePct) pkg_w=$($r.pwr1.PkgW) ts=$((Get-Date).ToUniversalTime().ToString('o'))"

    Restore-Slices $work $pristine $members $slice $picks
    $chk = Test-RestoredFast $work $members $gold
    if ($chk.good -ne $members.Count) {
      foreach ($nm in $chk.bad) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
      foreach ($nm in $parfiles) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
      $chk2 = Test-RestoredFast $work $members $gold
      "RESTORE-FALLBACK leg=$tag copied=$($chk.bad -join ',') now=$($chk2.good)/$($members.Count)"
      if ($chk2.good -ne $members.Count) { "WCOMB-FAIL restore at $tag"; exit 9 }
    }
  }

  # The create ladder's cell. No damage, no repair: one `parfast c` per leg,
  # its recovery files hashed and compared across the arms at that rung.
  $cref = @{}
  function Run-Create([int]$m, [string]$budget, [string]$arm, [int]$threads, [int]$rep) {
    $tag = "c-m$m-$budget-$arm-t$threads-r$rep"
    $envx = @{ NZBFAST_REPAIR_TIMING = '1' }
    # `fold2` / `force2` are the A/A copies: the same arm again.
    if ($arm -like 'fold*') { $envx['NZBFAST_NTT'] = '0' }
    elseif ($arm -like 'force*') { $envx['NZBFAST_CREATE_NTT_MIN_ROWS'] = '0' }
    else { "WCOMB-FAIL unknown create arm $arm"; exit 9 }
    if ($Gf16Force) { $envx['NZBFAST_GF16_FORCE'] = $Gf16Force }
    # RESIDENT LEGS ONLY, the same rule Run-Cell carries and for the same
    # reason, which on the create path is sharper: `parfast c -m<MiB>` and
    # NZBFAST_NTT_BUDGET land on ONE function - ntt_budget_within_published -
    # and the env override WINS over the published -m outright
    # (ntt_budget_override before clamp_to_published). So setting both on a
    # windowed create leg does not merely muddle the budget, it silently
    # restores the resident one and the windows the round came for never
    # happen. Added 16 Sep 2026 with the -m plumbing below.
    if ($NttBudget -and $budget -eq 'big') { $envx['NZBFAST_NTT_BUDGET'] = $NttBudget }
    foreach ($f in (Get-ChildItem $work -Filter 'cr*.par2' -ErrorAction SilentlyContinue)) { Remove-Item $f.FullName -Force }
    # The create's WINDOW, which until 16 Sep 2026 this phase could not ask
    # for at all: `-m<MiB>` publishes a user limit (parfast's `from_user_limit`
    # funnel), ntt_budget_within_published takes it in both directions, and
    # create_ntt_window divides it by the block size to get the resident
    # window in slices. 'big' is no -m, which is the resident ladder every
    # create round before this date ran. The repair phases spell the same
    # switch the same way.
    $cargs = "c -q -t$threads -s$slice -c$m"
    if ($budget -ne 'big') { $cargs += " -m$budget" }
    $cargs += " cr.par2 $($members -join ' ')"
    $load0 = Get-LoadPct
    $lout = @(Invoke-Leg $Bin $cargs $work (Join-Path $logs $tag) $envx)
    $load1 = Get-LoadPct
    foreach ($s in ($lout | Where-Object { $_ -is [string] })) { $s }
    $r = $lout | Where-Object { $_ -isnot [string] } | Select-Object -Last 1
    $err = [IO.File]::ReadAllText((Join-Path $logs "$tag.err"))
    $cold = 0
    foreach ($mm in [regex]::Matches($err, 'plan prep: \S+ over (\d+) cold build\(s\), (\d+) stripe use\(s\)')) { $cold += [int]$mm.Groups[1].Value }
    $path = if ($cold -gt 0) { 'ntt' } else { 'fold' }
    if (($arm -like 'fold*' -and $path -ne 'fold') -or ($arm -like 'force*' -and $path -ne 'ntt')) { "WCOMB-FAIL path arm=$arm path=$path cold=$cold at $tag"; exit 9 }
    # WHICH SIDE OF THE ADMISSION GATE A CREATE LEG TOOK, asserted rather
    # than inferred from peak_mb. Added 16 Sep 2026 for lane
    # create-windowed-ladder-4mib-gfni256, the first windowed create ladder
    # on any block size, because -Residency covered the repair phases ONLY:
    # its assert lives in Run-Cell and keys on `ntt window (...)` and
    # `ntt syndromes (...)`, neither of which a create ever prints. A create
    # leg run under a -m therefore published under the windowed gate's name
    # with every field well-formed whether it windowed or not, which is
    # precisely the failure -Residency was added to the repair phases to stop.
    #
    # THE SIGNAL IS THE CREATE'S OWN LINE, and it is a positive one every
    # way. THREE ROUTES print one, which is the thing a reader of this
    # assert most needs to know and which cost this lane a local round to
    # learn - the first cut of it knew only the first two and would have
    # FALSE-REFUSED every genuinely over-budget create leg:
    #   * copied windows (par2gen::ntt::windowed_attempt)
    #     `create ntt rows f+c (n=N, W window(s) of S, ... probe ok)`
    #   * the mapped single window (par2gen::ntt::mapped_attempt)
    #     `create ntt rows f+c (n=N, mapped, T tail(s) padded, ... probe ok)`
    #   * THE STRIPE-FIRST BAND ROUTE (par2gen::stripe_first)
    #     `create stripe-first: R rows in C chunk(s) of K stripes (n=N,
    #      bands of B B over copies, ... probe ok)`
    # and the THIRD is what a create actually does when its corpus does not
    # fit its budget. Measured on an M3 Ultra at 64 KiB, n = 2,048 and 8,192,
    # both levers, mapped route on and off
    # (rounds/cwinmin-2026-09-16/): a `-m` under the corpus does NOT
    # give the copied loop a fractional window and does NOT fold - it goes to
    # bands. So the quantity this assert compares is PASSES OVER THE CORPUS,
    # which is `W` for copied windows, 1 for mapped, and `C` for bands:
    # resident is one pass, windowed is more than one.
    #
    # `probe ok` IS PART OF THE MATCH, and it closes a hole the path assert
    # above cannot see. windowed_attempt verifies one row against the fold;
    # on a disagreement, or a window whose plan will not build, it ZEROES the
    # accumulator, warns, and the fold recomputes every row - having already
    # charged its cold plan builds. `plan prep` then reads cold > 0 and the
    # path assert says 'ntt' over a leg that was entirely a fold. Requiring
    # the success line refuses that leg instead, on any -Residency round.
    $cwin = @([regex]::Matches($err, 'create ntt rows \d+\+\d+ \(n=(\d+), (\d+) window\(s\) of (\d+),.*?probe ok\)'))
    $cmap = @([regex]::Matches($err, 'create ntt rows \d+\+\d+ \(n=(\d+), mapped,.*?probe ok\)'))
    $cband = @([regex]::Matches($err, 'create stripe-first: (\d+) rows in (\d+) chunk\(s\) of (\d+) stripes \(n=(\d+),.*?probe ok\)'))
    $cslices = @($cwin | ForEach-Object { [int]$_.Groups[3].Value })
    # One pass count per success line, whichever route printed it.
    $cpass = @()
    $cpass += @($cwin | ForEach-Object { [int]$_.Groups[2].Value })
    $cpass += @($cmap | ForEach-Object { 1 })
    $cpass += @($cband | ForEach-Object { [int]$_.Groups[2].Value })
    $cwmax = if ($cpass.Count -gt 0) { ($cpass | Measure-Object -Maximum).Maximum } else { 0 }
    $cwmin = if ($cpass.Count -gt 0) { ($cpass | Measure-Object -Minimum).Minimum } else { 0 }
    $croute = if ($cband.Count -gt 0) { 'band' } elseif ($cmap.Count -gt 0) { 'mapped' } elseif ($cwin.Count -gt 0) { 'copied' } else { 'none' }
    if ($Residency -and $arm -like 'force*') {
      if ($cpass.Count -eq 0) {
        "WCOMB-FAIL residency want=$Residency no create transform success line at $tag - none of the three routes (copied windows, mapped, stripe-first bands) reported 'probe ok', so the create either never reached one or threw its transform away, and cold_builds=$cold cannot tell that from a transform that ran"; exit 9
      }
      if ($Residency -eq 'resident') {
        if ($cwmax -gt 1) { "WCOMB-FAIL residency want=resident route=$croute passes=$cwmax arm=$arm at $tag - the create took more than one pass over the corpus, so this rung is not measuring the resident gate"; exit 9 }
        # The copied route's own positive check. The mapped route covers the
        # corpus by construction and the band route is single-chunk here, so
        # neither carries a slice count to compare.
        $badw = @($cslices | Where-Object { $_ -ne $n })
        if ($badw.Count -gt 0) { "WCOMB-FAIL residency want=resident win_slices=$($badw -join '/') expected=$n arm=$arm at $tag - one window, but it did not cover every source"; exit 9 }
      } elseif ($Residency -eq 'windowed') {
        if ($cwmin -lt 2) { "WCOMB-FAIL residency want=windowed route=$croute passes=$($cpass -join '/') arm=$arm at $tag - at least one transform call made a SINGLE pass over the corpus, so this rung ran resident under a -m"; exit 9 }
      } else { "WCOMB-FAIL unknown -Residency $Residency (want resident or windowed)"; exit 9 }
    }
    # The cross-arm gate. The recovery files are the create's whole output, so
    # one hash over them in name order is "these bytes are those bytes".
    $outs = @(Get-ChildItem $work -Filter 'cr*.par2' | Sort-Object Name)
    $dig = ($outs | ForEach-Object { "$($_.Name):$(Get-Sha256Fast $_.FullName)" }) -join ','
    $obytes = ($outs | Measure-Object Length -Sum).Sum
    if (-not $cref.ContainsKey($m)) { $cref[$m] = $dig }
    $match = [int]($cref[$m] -eq $dig)
    foreach ($f in $outs) { Remove-Item $f.FullName -Force }

    # A leg that did not run on the cores its arm names measured a DIFFERENT
    # core mix under this arm's name. Same refusal class as the residency
    # arm above, and Run-Cell's own affinity check, and it fires before the
    # LEG line so nothing unpinned is published as pinned.
    if ($AffinityMask -and [long]$r.affGot -ne [long]$AffinityMask) {
      Fail-Leg "WCOMB-FAIL affinity want=0x$($AffinityMask.ToString('X')) got=$(if ([long]$r.affGot -eq -1) { 'THREW' } else { '0x' + ([long]$r.affGot).ToString('X') }) arm=$arm at $tag - the leg did not run on the cores this arm names"
    }

    "LEG round=$Tag label=$Label slice=$slice payload=$Payload n=$n phase=$Phase rep=$rep m=$m budget=$budget arm=$arm arm_pos=na arm_order=$armOrderTag ntt_budget=$($envx['NZBFAST_NTT_BUDGET']) threads=$threads prof=0 rc=$($r.rc) restored=$(if($match){$members.Count}else{0})/$($members.Count) match=$match out_files=$($outs.Count) out_bytes=$obytes wall=$($r.wall) cpu=$($r.cpu) peak_mb=$($r.peakmb) path=$path route=$croute windows=$cwmax win_slices=$(if ($cslices.Count -gt 0) { ($cslices | Select-Object -First 3) -join '/' } else { $croute }) residency=$(if ($Residency) { $Residency } else { 'unset' }) cold_builds=$cold gf16force=$Gf16Force foreign_cpu=$($r.foreign) foreign_after=$($r.foreignAfter) load_before=$load0 load_after=$load1 errlen=$($r.errlen) affinity=$(if ($AffinityMask) { '0x' + $AffinityMask.ToString('X') } else { 'none' }) affinity_got=$(if ($AffinityMask) { '0x' + ([long]$r.affGot).ToString('X') } else { 'none' }) rig=$(Get-RigStamp) freq_mhz=$($r.pwr0.FreqMhz) freq_after_mhz=$($r.pwr1.FreqMhz) perf_pct=$($r.pwr0.PerfPct) perf_after_pct=$($r.pwr1.PerfPct) temp_c=$($r.pwr0.TempC) temp_after_c=$($r.pwr1.TempC) throttle_pct=$($r.pwr1.ThrottlePct) pkg_w=$($r.pwr1.PkgW) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    if ($r.rc -ne 0) { "WCOMB-FAIL create rc=$($r.rc) at $tag"; exit 9 }
    if (-not $match) { "WCOMB-FAIL create output differs from the first arm at m=$m ($tag)"; exit 9 }
  }

  $threadlist = if ($Threads) { @($Threads.Split(',') | ForEach-Object { [int]$_ }) } else { @(4, $full) | Select-Object -Unique }
  for ($rep = 1; $rep -le $Reps; $rep++) {
    if ($Phase -eq 'measure') {
      $foldm = if ($Rungs) { @($Rungs.Split(',') | ForEach-Object { [int]$_ }) } else { @(192, 512, 1024, 2048, 4096) }
      $profm = if ($Rungs) { $foldm } else { @(256, 1024, 4096) }
      # The WINDOWED force legs' budget. 128 MiB is the shape k was first
      # measured on (a ~1,630-source window at 64 KiB); at a larger block
      # that same -m leaves a window of a few hundred sources or fewer, so
      # -Budget names the -m that gives a window worth pricing at THIS
      # block size. Added 16 Sep 2026 for lane
      # parfast-window-combine-k-1mib-16sep, the same knob the rowgate and
      # validate phases already take.
      $mb = if ($Budget) { $Budget } else { '128' }
      foreach ($t in $threadlist) {
        foreach ($m in $foldm) { Run-Cell $m 'big' 'fold' $t $rep $false }
        foreach ($m in $profm) {
          Run-Cell $m 'big' 'force' $t $rep $true
          Run-Cell $m $mb 'force' $t $rep $true
        }
      }
    } elseif ($Phase -eq 'validate') {
      $vm = if ($Rungs) { @($Rungs.Split(',') | ForEach-Object { [int]$_ }) } else { @(192, 256, 384, 512, 768, 1024, 1536, 2048, 3072, 4096) }
      $vt = if ($Threads) { $threadlist } else { @(4) }
      # No profile on these arms: the per-depth timers are the one thing that
      # could tax the transform's CPU and not the fold's, in the comparison
      # this phase exists to make.
      #
      # $vorders was built and asserted before the fixture settle above; the
      # arm list is NOT rebuilt here, so the order the log banked in its
      # ARM-ORDER lines is the order that runs, with no second copy of the
      # rotation rule to drift from the first.
      $va = $vorders[$rep - 1]
      $vb = if ($Budget) { $Budget } else { '128' }
      foreach ($t in $vt) { foreach ($m in $vm) { for ($ai = 0; $ai -lt $va.Count; $ai++) { Run-Cell $m $vb $va[$ai] $t $rep $false ($ai + 1) } } }
    } elseif ($Phase -eq 'rowgate') {
      $rm = if ($Rungs) { @($Rungs.Split(',') | ForEach-Object { [int]$_ }) } else { @(192, 256, 288, 320, 352, 384, 416, 448, 512, 640) }
      # ABBA, flipped on alternate reps, so neither copy of an arm always runs first.
      $rarms = if ($Arms) { @($Arms.Split(',')) } elseif ($rep % 2) { @('fold', 'force', 'force2', 'fold2') } else { @('force', 'fold', 'fold2', 'force2') }
      # 'big' (no -m) is the RESIDENT ladder this phase was written for - the
      # single-window gate ntt_min_missing itself. -Budget runs the same ladder
      # WINDOWED instead, which is a different gate (ntt_window_row_gate scales
      # the single-window one by the window's source count), added 15 Sep 2026
      # for lane parfast-gfni256-1mib-create-and-window-15sep to check that
      # scaling at 1 MiB. Say which in the write-up: the two are not comparable.
      $rgb = if ($Budget) { $Budget } else { 'big' }
      foreach ($m in $rm) { foreach ($t in $threadlist) { foreach ($arm in $rarms) { Run-Cell $m $rgb $arm $t $rep $false } } }
    } elseif ($Phase -eq 'create') {
      $cm = if ($Rungs) { @($Rungs.Split(',') | ForEach-Object { [int]$_ }) } else { @(256, 320, 384, 448, 512) }
      $carms = if ($Arms) { @($Arms.Split(',')) } elseif ($rep % 2) { @('fold', 'force', 'force2', 'fold2') } else { @('force', 'fold', 'fold2', 'force2') }
      # 'big' (no -m) is the RESIDENT create ladder this phase was written
      # for, and was its only shape until 16 Sep 2026. -Budget runs the same
      # ladder WINDOWED, which on the create path is the SAME gate rather
      # than a different one - create_ntt_min_rows is asked whatever the
      # window is, and ntt_window_row_gate is never consulted by a create -
      # so the two ladders together are what says whether that is right.
      # Say which in the write-up: a windowed create leg and a resident one
      # are not comparable.
      $cgb = if ($Budget) { $Budget } else { 'big' }
      foreach ($m in $cm) { foreach ($t in $threadlist) { foreach ($arm in $carms) { Run-Create $m $cgb $arm $t $rep } } }
    } else { "WCOMB-FAIL unknown phase $Phase"; exit 9 }
  }
  "ALL DONE end=$((Get-Date).ToUniversalTime().ToString('o'))"
} catch {
  # AN UNHANDLED EXCEPTION WENT TO STDERR ONLY, until 17 Sep 2026 - there was no
  # catch here, just the finally below. wlaunch.ps1 redirects stdout to the
  # round's .log and stderr to its .err, so a round that died this way left a
  # LOG that read as a clean finish: on 16 Sep 2026 the gfni256-resident-gate-bracket
  # round's log ended with FIXTURE-RECOVERY / RIG-LOCK-RELEASED and no
  # WCOMB-FAIL anywhere, and the exception (a bad -Rungs list, see above) sat
  # alone in the .err nobody was watching. Write the failure to the OUTPUT
  # stream (this line's a bare string, same as every other WCOMB-FAIL) before
  # rethrowing, so the log itself says the round died rather than reading like
  # a success.
  "WCOMB-FAIL exception: $($_.Exception.Message) at $($_.InvocationInfo.ScriptName):$($_.InvocationInfo.ScriptLineNumber)"
  throw
} finally {
  Release-RigLock $lock
}
