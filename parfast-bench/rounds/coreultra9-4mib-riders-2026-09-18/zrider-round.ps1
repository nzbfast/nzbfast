param(
  [string]$Root   = '<rig>\zr18sep',
  [string]$Bin    = '',                          # default $Root\src\target\release\parfast.exe
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$Budget = '21474836480',               # NZBFAST_NTT_BUDGET, 20 GiB - keeps every force leg resident
  [switch]$SkipProbe
)
# zrider-round.ps1 - NINE ladders in ONE sitting off ONE 4 MiB fixture, for
# lane coreultra9-4mib-riders-sitting-18sep. It carries FOUR cells that three
# different handoffs commissioned separately, each of which was written as a
# RIDER on "the next sitting that builds a 4 MiB fixture on this part":
#
#   * item 5 of an internal note
#     - the wide-pool-no-siblings cell at m=128/192/256 (ladders 5 and 6)
#   * item 1 of an internal note
#     - the e8 band is open at the top (ladder 7)
#   * item 3 of the same file
#     - 4mc-p4 is non-monotone in both sittings (ladder 8)
#   * item 2 of an internal note
#     - solo against interleaved -t16, the 22-row swing (ladders 2, 3 and 4)
#
# THE WHOLE ARGUMENT FOR ONE SITTING is that each of those items priced itself
# as a rider and NONE of them justifies taking the fleet's only GFNI-256 part on
# its own. Lane parfast-4mib-knee-below-320 released its claim on exactly that
# reasoning on 18 Sep: with no fixture on the box, its four legs would have cost
# a rebuild, a 16 GiB create and a ~745 s settle. One fixture pays that once for
# all four cells.
#
# A copy of rounds/crpin4m-2026-09-18/crpin-round.ps1 with the arm
# table replaced, a per-ladder `phase` column added (this round runs BOTH
# -Phase create and -Phase rowgate off the same fixture, which crpin did not),
# and the bandplan stage REMOVED - every rung here is a literal from the item
# that commissioned it, so there is no band to compute on the box and no python
# needed on it. Everything else - the load gate, the byte gate, the rc=17
# retry, the detached launch, the extract-inside-the-gate discipline, the
# affinity audit - is inherited and unchanged.
#
# ONE FIXTURE SERVES BOTH PHASES, and that is checked rather than assumed:
# wcomb.ps1 names the fixture `fix-<slice>-<mib>` (line 329) with no phase in
# the name, and -Recovery is honoured at CREATE ONLY (line 542), so the rowgate
# ladders reuse the create ladders' `fix-4194304-1024` whatever they pass. All
# eight ladders pass -Recovery 640, which is what both banked recipes specify.
#
# ============================== THE FOUR QUESTIONS ==============================
#
# (A) IS THE FOLD/FORCE KNEE POOL WIDTH OR SMT? (ladders 5 and 6, item 5)
# The i5 nibble part shows a sharp knee in the fold/force parallelism ratio in
# its wide arm (-t12, largest/next 16.3x) and none in its narrow one (-t4, 1.6x).
# But -t4 -> -t12 moves SMT and pool width TOGETHER, so that part cannot say
# which. THIS part is 16C/16T with no SMT anywhere, so a wide arm here is a WIDE
# POOL WITH NO SIBLINGS - the one cell neither round has. `4m3-e8` (0xFF0, t8,
# eight E-cores) against `4m3-e4` (0xF0, t4, four of the same cores) moves pool
# width with SMT held fixed at ZERO.
#   A knee in e8 and not e4  -> POOL WIDTH, and the SMT attribution is wrong.
#   No knee in either        -> SMT is implicated and survives a test it could
#                               have failed.
#   A knee in both           -> it is the fold at small m on THIS part, which
#                               the i5's own -t4 control excludes on theirs.
# THREE RUNGS, NOT ONE OR TWO, and that is item 5's own correction to itself:
# the published statistic is largest-interval-step / next-largest, so one rung
# gives a level, two give a step and no "next", and three give both. 128/192/256
# are the two intervals that ARE the largest and next-largest in both published
# i5 arms, so this grid reproduces each figure exactly rather than approximately.
# DO NOT chain the "next" step onto a 320..448 ladder: that is a second wcomb
# invocation and therefore a second lock hold, and the i5 round's own A/D control
# measured -0.8% to -1.8% of level drift across one handover on the same box,
# binary and fixture. A level shift at the junction can fabricate or mask a step,
# which is the whole quantity.
#
# (B) WHERE DOES THE e8 CREATE BAND END? (ladder 7, crpin item 1)
# crpin priced the create's proportionality band on a pinned arm for the first
# time - 0.2x at m=400, unresolved at 404 and 408, then 3.2x / 5.0x / 6.9x at
# 412/416/420 - but `4mc-e8-fine`'s WALL crossover never crossed by its top rung
# 420, so the band is OPEN AT THE TOP and the trade is steepest exactly there.
# Rungs 420..440 at 4-row spacing ask whether the ratio keeps climbing toward
# the maintainer's 10x limit or turns over.
#   THIS IS NOT A BAND AIM AND DOES NOT VIOLATE crpin's "AIM FROM YOUR OWN
#   SITTING" RULE. bandplan.py exists because a BAND's location moves between
#   sittings. 420 is not a band edge, it is the RUNG crpin actually measured and
#   published a 6.9x ratio at, and this ladder extends literally above it. What
#   this ladder inherits from another sitting is a rung number, not a band.
#   "NO RUNG ABOVE 420 IS PRICEABLE" IS AN ANSWER, and it bounds the create
#   trade at 6.9x on this arm. By the denominator argument crpin published -
#   `cost` rises slowly and monotonically while `gain` collapses toward the wall
#   crossover - rungs past the wall crossover have a NEGATIVE gain and leave the
#   band entirely. NO FLOOR IS WIDENED TO MANUFACTURE A RUNG.
#
# (C) IS `4mc-p4`'s NON-MONOTONICITY A PROPERTY OF THE ARM? (ladder 8, item 3)
# crpool4m found 4mc-p4 non-monotone (worst floor 1.2%); crpin found BOTH of its
# p4 ladders non-monotone (1.8% and 1.0%); no other arm in either sitting is. A
# defect that replicates is a property, not noise. The visible symptom is the
# m=412 cell reversing direction between 408 and 416, so this ladder re-runs
# exactly those three rungs. It is the cheapest cell in the sitting (12 legs) and
# is last on purpose - it is the one that can be cut without destroying a
# deliverable.
#   IT CANNOT CONFIRM THE CANDIDATE MECHANISM, which item 3 names as the OS
#   parking or boosting P-cores differently under a 4-thread pin. This ladder can
#   say whether the reversal reproduces a THIRD time; it cannot say why. Nothing
#   here may be written up as having tested the clock hypothesis.
#
# (D) DOES INTERLEAVING EXPLAIN THE 22-ROW SWING? (ladders 2, 3, 4, item 2)
# crpool4m's unpinned -t16 create crossover read 387 where crg4's read 365 - 22
# rows on the same configuration, binary and fixture shape. regrid-and-arm-split.py
# REFUTED the rung grid outright (on the common grid every reading is identical)
# and located the swing in the arms: the fold is 5.8% cheaper in CPU between
# sittings and the force only 3.0%, and since a crossover is where fold/force = 1
# that ~3 pp differential IS the 22 rows. Three explanations survive and that
# round could not separate them: crg4 ran its two pools INTERLEAVED in one ladder
# where crpool4m ran a SOLO ladder; a different fixture instance; and a noisier
# sitting. This round tests the first, with the other two held fixed by
# construction - one fixture, one binary, one sitting.
#   BOTH ARMS RUN ON THE SAME GRID, 288..512, WHICH IS crpool4m's AND NOT crg4's
#   (320..544). That is deliberate and is licensed by regrid-and-arm-split.py
#   having already excluded the grid: holding it fixed makes INTERLEAVING the
#   only difference between my two arms, which is the quantity. The tie-back to
#   387 and 365 is secondary to the within-sitting contrast.
#   LADDER 4 IS THE DRIFT CONTROL AND IS WHY THIS CELL IS THREE LADDERS AND NOT
#   TWO. Ladder position is itself a confound for a solo-against-interleaved
#   comparison, and crpin's own within-sitting position control bounded
#   ladder-position-plus-repeat at 1.5% of F/T on e8 (about 8 rows). The effect
#   being chased is 22 rows, so position cannot fully explain it - but that is an
#   argument, not a measurement, and this sitting can make the measurement for
#   about five minutes of legs. Ladder 4 repeats ladder 2 at ONLY the two rungs
#   the t16 crossover interpolates from, AFTER ladder 3, so the drift it reports
#   over positions 2->4 bounds the drift over 2->3 conservatively.
#   IF LADDER 4's TWO RUNGS DO NOT BRACKET, rowgate prints `?` and the honest
#   report is "the t16 crossover left [384,416] during the sitting", which is a
#   LARGER drift finding than a bracketed one and must not be reported as a
#   failed control.
#
# =============================== THE HARNESS ===============================
#
# THE CREATE PHASE NOW ASSERTS ITS PINS, and crpool4m's did not. The
# create-pool handoff's apparatus section says in as many words that Run-Create
# had no affinity readback and no `affinity=` LEG field, and that claim
# `wcomb-run-create-affinity-assert-18sep` was fixing it. It landed: wcomb.ps1's
# create LEG line carries `affinity=` and `affinity_got=` and wcomb refuses the
# leg on a mismatch, and crpin read all 124 of its pinned legs back equal. So
# ladders 7 and 8 read their masks back rather than arguing them from timings.
#
# THE ROUND STILL AUDITS THE READBACK ITSELF rather than trusting the absence of
# a failure: a pinned ladder whose legs carry no `affinity=` field AT ALL would
# be a harness older than 3bbe3d94d, which is the silent-wrong case that an
# absent exception cannot distinguish from a pass.
#
# ============================== THE NINE LADDERS ==============================
#
#   1  zwarm   create  UNPINNED  t16   288                      BUILDS THE FIXTURE
#   2  zsolo   create  UNPINNED  t16   288..512                 (D) arm A, SOLO
#   3  zint    create  UNPINNED  t4,16 288..512                 (D) arm B, INTERLEAVED
#   4  zdrift  create  UNPINNED  t16   384,416                  (D) drift control
#   5  zp3e8   rowgate 0xFF0     t8    128,192,256              (A) wide, no siblings
#   6  zp3e4   rowgate 0xF0      t4    128,192,256              (A) narrow control
#   7  ze8top  create  0xFF0     t8    420,424,428,432,436,440  (B) close the band
#   8  zp4rep  create  0xF       t4    408,412,416              (C) the third rep
#   9  zp3pe8  rowgate 0xFF      t8    128,192,256              (A) OPTIONAL mixed-class arm
#
# THE ORDERING IS FORCED AT THE TOP AND CHOSEN BELOW IT.
#
# FORCED: -Affinity arms EVERY leg INCLUDING the fixture create, so a pinned
# ladder cannot be first. Ladder 1 is unpinned.
#
# LADDER 1 IS A ONE-RUNG SPENT LADDER AND THAT IS THE ONE DESIGN CHOICE THIS
# ROUND MAKES THAT ITS ANCESTORS DID NOT. Four of four fixture-building ladders
# in this campaign show a warm-up ramp confined to the FIRST rung, with A/A
# floors of 9.6% / 15.7% / 35.5% against 0.1-2% typical, and crband established
# the ramp is a property of BUILDING THE FIXTURE rather than of being first.
# crpin answered that by spending its builder's first rung and keeping the rest
# of the ladder as a bonus reading. THAT ANSWER DOES NOT WORK HERE, because this
# round's headline cell is a comparison BETWEEN two unpinned ladders: if the
# solo arm built the fixture and the interleaved arm did not, the ramp would sit
# on one side of the comparison and not the other, and the asymmetry would be
# confounded with the very quantity being measured. So the ramp is spent on a
# ladder that is in NEITHER arm. m=288 is far below every banked unpinned -t16
# crossover (357, 359, 365, 387), so the ramp lands on a rung nothing depends on,
# and ladder 1's four legs are DISCARDED - they are not a fifth reading and are
# not reduced.
#
# CHOSEN: ladders 2, 3 and 4 are adjacent because they are one cell and their
# comparison is what ladder position would otherwise contaminate. Ladders 5 and 6
# are adjacent for the same reason - they are the two halves of one two-by-two.
# Ladders 8 and 9 are last because they are the cheapest and the only ones whose
# loss destroys no deliverable. LADDER 9 IS TAKEN ONLY BECAUSE THE FIXTURE IS
# WARM: item 5 offers it under exactly that condition ("if the fixture is already
# warm and it is cheap") and says in as many words it is not needed for the
# verdict. Its position costs it nothing analytically - the knee statistic is
# computed WITHIN a ladder, so between-ladder drift does not enter it.
#
# ====================== WHAT THIS ROUND DOES NOT LICENSE ======================
# Written BEFORE the sitting and landed on origin before the box is taken, so it
# cannot be trimmed to fit the numbers - the practice crpool4m, crband and crpin
# all used, and the reason their conclusions held when their numbers would have
# allowed stronger claims.
#
# NO CONSTANT MOVES. The rung decision - 384 against 416 against
# create_ntt_min_rows taking its own clause at ~372 - is the maintainer's, it is open, and
# six lanes have now measured inputs without moving anything. This is the
# seventh. No sentence in the write-up may be read as a decision having been
# taken.
#
# A PRICED BAND IS NOT A CHOSEN RUNG. Ladder 7 produces a trade ratio per rung.
# A ratio under 10x does not say a rung is right; it says the proportionality
# limit does not EXCLUDE it.
#
# AN UNRESOLVED RUNG IS NOT A CLEAN BILL. A narrow band means small differences,
# so rungs coming back inside their own A/A floors is the EXPECTED case. The
# honest statement is then "the trade cannot be priced at this resolution on this
# part" - NOT "the trade is small" and NOT "the metrics agree".
#
# A LEVEL IS NOT A STEP. Ladders 5 and 6 are the first rungs ever run below 320
# on this part. The banked 320..448 data shows doubling the pool with zero
# siblings RAISES the fold/force ratio here where the i5's pool-plus-SMT step
# lowers it - that is a LEVEL statement over a range that never touches the knee
# interval, and it is not the verdict. Only the three-rung step statistic is.
#
# ONE SITTING IS NOT A REPLICATE, and more reps cannot firm a rung: the A/A floor
# is a MAX over reps.
#
# ONE PART, ONE PAYLOAD, ONE BLOCK SIZE. Core Ultra 9 386H, random bytes, 4 MiB,
# n = 4,096. No other box on this fleet is GFNI-256.
#
# UNPINNED IS DELIBERATE ON LADDERS 1-4 AND IS NOT A LAPSE. Section 5 of
# an internal note says to pin to cores
# 0-3 on this part and that unpinned legs are not data - that finding is about a
# SINGLE-THREAD leg (a whole-file MD5 is one serial 64-step chain on one core)
# landing on an LP-E core, measured at a 1.43x swing. No leg in this round is
# single-threaded, and cell (D) is ABOUT an unpinned reading: its subject is why
# two unpinned sittings disagreed by 22 rows, so pinning it would delete the
# question. Ladders 5-8 are pinned.
#
# ========================= READING AND HYGIENE RULES =========================
# WALL DECIDES, CPU EXPLAINS. Both crossovers are quoted on every table and any
# divergence is named with its size.
# CPU-SECONDS DO NOT COMPARE ACROSS MASKS - P/E measured 1.731 on this part, so
# an 8 E-core arm burning more CPU than a 4 P-core arm is not doing more work.
# Only the CROSSOVER compares across arms. For ladders 5 and 6 the fold/force
# RATIO is the comparable quantity and is invariant to the thread count, because
# the same divisor sits on both sides.
# A TIGHT A/A FLOOR IS AGREEMENT, NOT CORRECTNESS. Screen every ladder with
# ladder-monotonicity-audit.py FROM THE REPO ROOT, and screen the rungs
# BRACKETING each crossing with bracket-firmness.py.
# CONTAMINATION. This driver is DETACHED and self-reporting. Poll at 600 s at the
# loosest and preferably not at all: every ssh poll spawns a PowerShell under
# sshd OUTSIDE the round's pid tree and lands in the round's own foreign_cpu.
$ErrorActionPreference = 'Stop'
if (-not $Bin) { $Bin = Join-Path $Root 'src\target\release\parfast.exe' }
$here  = $PSScriptRoot
$logs  = Join-Path $here 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
. (Join-Path $here 'plib.ps1')

function Say([string]$m) { "$(Get-Date -Format o) $m" }
# POST ONE COORDINATION LINE, AND THEN CONFIRM THE READER CAN SEE IT.
#
# This was `Add-Content -Encoding UTF8 -Path $Coord -Value $line` - inherited
# from crpin-round.ps1 - until `gfni256-four-window-shape-1mib-18sep` handed
# this lane its close-posting failure on THIS box, minutes before I took it.
# Its DONE took THREE attempts and THE FIRST TWO BOTH REPORTED SUCCESS:
#
#   1. Add-Content over ssh with a here-string: rc=1, wrote NOTHING. Caught
#      only by re-reading.
#   2. `cmd /c type f >> dest`: rc=0, and it wrote the line in UTF-16LE -
#      the ssh default shell on this box is PowerShell, so `>>` was
#      PowerShell's redirect, not cmd's, and PS5 writes UTF-16 by default.
#      The line is in the file as mojibake and matches nothing.
#   3. redirect moved INSIDE cmd: rc=0, correct ASCII, and STILL unparseable -
#      it inherited a stray NUL from the UTF-16 line above and began ONE BYTE
#      IN FROM COLUMN 0, so `findstr /B` missed it and so would any
#      line-start marker match.
#
# THE GENERALISATION, which is narrower and nastier than "re-read the box":
# rc=0 from the append is worth nothing, the line being PRESENT is worth
# nothing, and the line being correct ASCII is worth nothing. The only check
# that counts is THE ONE THE READER PERFORMS - a match on a rostered marker
# word AT COLUMN 0. Anything weaker passes on all three of those failures.
#
# That is the same shape as this round's own ZRIDER-EMPTY-LADDER guard, one
# layer down the pipe: that one refuses an EXIT that verified no LEGS, this one
# refuses a WRITE that verified no READ.
#
# So this function does three things Add-Content does not:
#   * writes through [IO.File]::Open(...Append...) + a UTF8Encoding($false)
#     StreamWriter - no BOM, no PS5 UTF-16 default, and the same path this
#     lane's own QUEUED lines went through, which parfast-rigs.sh demonstrably
#     parsed (it counted this lane in the queue);
#   * guarantees COLUMN 0 by checking the file's last byte and emitting a
#     leading CRLF when the previous writer did not terminate its line - which
#     is exactly how failure 3 happened;
#   * RE-READS the file and confirms a line-start match on the marker word it
#     just wrote, and says so loudly when it cannot find it.
#
# It never throws: a coordination post failing must not kill a measurement
# round. It reports, and the round's own log carries the verdict.
function Post([string]$line) {
  $verb = ($line -split '\s+')[0]
  $head = $line.Substring(0, [Math]::Min(60, $line.Length))
  $wrote = $false
  for ($i = 0; $i -lt 25; $i++) {
    try {
      # Does the file already end in a newline? A previous writer that did not
      # terminate its line would otherwise put ours one byte in from column 0.
      $needNl = $false
      try {
        $rs = [IO.File]::Open($Coord, 'Open', 'Read', 'ReadWrite')
        if ($rs.Length -gt 0) {
          $null = $rs.Seek(-1, 'End')
          $last = $rs.ReadByte()
          if ($last -ne 10) { $needNl = $true }
        }
        $rs.Close()
      } catch { $needNl = $true }   # cannot tell: emit the newline, a blank line is harmless
      $fs = [IO.File]::Open($Coord, 'Append', 'Write', 'Read')
      $sw = New-Object IO.StreamWriter($fs, (New-Object Text.UTF8Encoding($false)))
      if ($needNl) { $sw.Write("`r`n") }
      $sw.WriteLine($line)
      $sw.Close(); $fs.Close()
      $wrote = $true; break
    } catch { Start-Sleep -Milliseconds 400 }
  }
  if (-not $wrote) {
    Say "ZRIDER-COORD-POST-FAILED could not append to $Coord after 25 tries - line NOT posted: $head"
    return
  }
  # THE READER'S OWN CHECK, not the writer's. A line-start match on the marker
  # word, over the file as it now stands.
  $seen = $false
  try {
    foreach ($l in (Get-Content $Coord -Tail 40 -ErrorAction Stop)) {
      if ($l.StartsWith($verb) -and $l.Contains($head.Substring([Math]::Min(20, $head.Length)))) { $seen = $true }
    }
  } catch { $seen = $false }
  if ($seen) {
    Say "COORD-POST-VERIFIED $verb line is present and starts at column 0: $head"
  } else {
    Say "ZRIDER-COORD-POST-UNVERIFIED wrote a $verb line and CANNOT FIND IT BACK with a line-start match. rc from the append is worth nothing here - on this box a post has landed as UTF-16 mojibake and as a line offset one byte from column 0, both at rc=0. Other lanes may not be able to see this round's holds. Line: $head"
  }
}
function Load-Now { (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average }

# The load gate is a SECOND, cheaper instrument and NOT a repair to
# Require-QuietBox, whose 10%-of-box ceiling is 160% of a core here and lets one
# saturated core through BY DESIGN. IT RETURNS NOTHING AND SETS $script:quietOk,
# which is plib's own convention and is not a style choice: `Say` writes its line
# to the OUTPUT stream, so a function that both logs and returns a bool returns
# an ARRAY of [string, ..., bool].
function Wait-Quiet([string]$where, [int]$samples) {
  $script:quietOk = $false
  $capS = 7200; $t0 = Get-Date
  while ($true) {
    $waited = [int]((Get-Date) - $t0).TotalSeconds
    if ($waited -gt $capS) { Say "LOAD-GATE GAVE-UP at=$where waited_s=$waited"; return }
    $held = (Get-RigLockHolder).Held
    $pf   = @(Get-Process parfast -ErrorAction SilentlyContinue).Count
    $ok = $true; $reads = @()
    if ($held -or $pf -gt 0) { $ok = $false }
    else {
      for ($i = 0; $i -lt $samples; $i++) {
        $l = Load-Now; $reads += $l
        if ($l -ge 25) { $ok = $false }
        if ($i -lt ($samples - 1)) { Start-Sleep -Seconds 60 }
      }
    }
    if ($ok) { Say "LOAD-GATE ok at=$where loads=$($reads -join '/') waited_s=$waited"; $script:quietOk = $true; return }
    Say "LOAD-GATE busy at=$where riglock=$held parfast=$pf loads=$($reads -join '/') waited_s=$waited"
    Start-Sleep -Seconds 60
  }
}

# RE-READ THE COORDINATION FILE BEFORE TAKING, AND BETWEEN EVERY LADDER. This is
# the one guard crpin's driver does not carry and it is here because the lane
# that skipped it lost a whole sitting to it the same morning:
# gfni256-four-window-shape-1mib-18sep checked the lock and the process list but
# never re-read this file, could not see a CLAIM posted two minutes before its
# own, and ran ZERO legs (its 11:27Z retraction NOTE). The standing open claim
# `riglock-waiter-blind-to-late-arrivals` is the same defect from the other side.
#
# IT CLASSIFIES THE FIRST TOKEN AND NEVER SUBSTRING-MATCHES A LINE - bench-suite
# item 0a5's fourth bullet, where a waiter that grepped prose for `NOT taking`
# read every queue NOTE as a completion and cleared a five-lane ahead-list in
# 80 milliseconds. An OPEN marker from a lane that is not me is a hold; QUEUED is
# an intention and is NOT; a close-class marker ends the claim it names.
function Test-ForeignClaim([string]$me) {
  # THE ROSTERS ARE THE FLEET'S, COPIED FROM `.claude/tools/bench-accounts.sh`'s
  # MARKERS via `parfast-rigs-parse.py`'s OPEN_KW / CLOSE_KW, and NOT invented
  # here. The rig has no python and cannot import them, so they are literals -
  # but they are literals READ OFF THE SOURCE, which is the whole point.
  #
  # THE FIRST CUT OF THIS FUNCTION INVENTED THEM AND GOT `TAKEOVER` BACKWARDS.
  # It had TAKEOVER and ABANDON as CLOSE keywords. `TAKEOVER` is in the fleet's
  # OPEN_KW - a hand-over opens a claim for whoever takes it - and `ABANDON` is
  # in neither roster at all. Classifying an OPEN word as a close is the
  # DANGEROUS direction: it reads a held box as free and takes it out from under
  # somebody, which is the exact failure `nzbfast-free-box-test-fails-three-ways`
  # is about. Item 0a3 says it in as many words - "do not guess the
  # classification from the word", four pairs on this fleet contradict their own
  # spelling - and this lane proved it on itself by guessing.
  #
  # AND `WITHDRAWN` IS THE CLOSE, NOT `WITHDRAWING`: the present participle is in
  # no roster, and a lane that stood down from the intel-i5-10600kf queue with it was
  # still counted as a live queue afterwards (5383c1db1, 18 Sep 2026).
  #
  # A word in NEITHER roster is IGNORED, which is what makes `QUEUED` an
  # intention rather than a hold and `NOTE` invisible - both deliberate.
  $openKw  = @('ACTIVATING', 'CLAIM', 'CLAIM-EXTENSION', 'CONTINUATION',
               'CROSS-CLAIM', 'DIALED', 'EXTEND', 'HOLD', 'INTERIM',
               'LATE-CLAIM', 'LAUNCHED', 'LIVE', 'PROGRESS', 'RELAUNCH',
               'RELAUNCHED', 'RESULT', 'START', 'TAKEOVER')
  $closeKw = @('ABORTED', 'DONE', 'RELEASE', 'RELEASED', 'STAND-DOWN',
               'WITHDRAWN')
  $open = @{}
  if (-not (Test-Path $Coord)) { return '' }
  foreach ($line in (Get-Content $Coord -ErrorAction SilentlyContinue)) {
    $f = ($line.Trim()) -split '\s+'
    if ($f.Count -lt 3) { continue }
    $verb = $f[0]; $id = $f[2]
    if ($id -eq $me) { continue }
    if ($openKw  -contains $verb) { $open[$id] = $line }
    if ($closeKw -contains $verb) { $open.Remove($id) }
  }
  if ($open.Count -eq 0) { return '' }
  return (($open.Keys | Sort-Object) -join ',')
}

# The core-class probe. `.claude/MACHINES.md` says cores 0-3 are P and 4-11 E -
# but this round's arm NAMES rest on that, so it is checked here rather than
# trusted. Ladder 5 asserts that cores 8-11 are the SAME CLASS as cores 4-7,
# which is the premise of the only within-class pool the part can offer, so the
# probe reads core 8 as well and a core-8 time that does not match core 4's is a
# reason to throw the arm away rather than to publish it. FIXED WORK, timed.
function Probe-Classes {
  $spin = @'
param([int]$Iters)
$sw=[Diagnostics.Stopwatch]::StartNew(); $x=0.0
for($i=0;$i -lt $Iters;$i++){ $x=$x+$i*1.000001 }
$sw.Stop(); "SPIN ms=$($sw.ElapsedMilliseconds) x=$x"
'@
  $f = Join-Path $here 'spin.ps1'; [IO.File]::WriteAllText($f, $spin)
  foreach ($m in @(@(0x1,'P-core0'), @(0x10,'E-core4'), @(0x100,'E-core8'), @(0x800,'E-core11'), @(0x1000,'LPE-core12'))) {
    $mask = [long]$m[0]; $name = $m[1]
    $psi = New-Object Diagnostics.ProcessStartInfo
    $psi.FileName = 'powershell'
    $psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File `"$f`" -Iters 12000000"
    $psi.UseShellExecute = $false; $psi.RedirectStandardOutput = $true
    $psi.RedirectStandardError = $true; $psi.CreateNoWindow = $true
    $p = New-Object Diagnostics.Process; $p.StartInfo = $psi
    $w = [Diagnostics.Stopwatch]::StartNew(); $null = $p.Start()
    $got = 0
    try { $p.ProcessorAffinity = [IntPtr]$mask; $got = [long]$p.ProcessorAffinity } catch { $got = -1 }
    $o = $p.StandardOutput.ReadToEndAsync(); $null = $p.StandardError.ReadToEndAsync()
    $p.WaitForExit(); $w.Stop()
    $cpu = $p.TotalProcessorTime.TotalSeconds; $p.Dispose()
    Say ("CLASS-PROBE $name mask=0x{0:X} got=0x{1:X} wall_s={2} cpu_s={3} {4}" -f $mask, $got, [math]::Round($w.Elapsed.TotalSeconds,3), [math]::Round($cpu,3), ($o.Result -replace "`r?`n",' '))
  }
  Remove-Item $f -Force
}

# Run one ladder.
#
# IT RETURNS NOTHING AND SETS $script:ladderRc, for the same reason Wait-Quiet
# sets $script:quietOk and which is NOT a style choice: `Say` writes its line to
# the OUTPUT stream, so a function that both LOGS and RETURNS would hand the
# caller an ARRAY of [string, string, ..., rc] and `if ($arc -ne 0)` would then
# be comparing an array to 0.
function Invoke-Ladder($a) {
  $script:ladderRc = 0
  Wait-Quiet $a.tag 1
  if (-not $script:quietOk) { Say "ZRIDER-ABORT load gate gave up before $($a.tag)"; $script:ladderRc = 8; return }
  $foreign = Test-ForeignClaim 'coreultra9-4mib-riders-sitting-18sep'
  if ($foreign) {
    Say "ZRIDER-STAND-DOWN a CLAIM that is not mine is open on $Coord before $($a.tag): $foreign. Standing down at a ladder boundary rather than taking an inter-ladder gap from a lane that asked for the box."
    Post "STAND-DOWN $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) coreultra9-4mib-riders-sitting-18sep gen=09e5f607 (<user>, opus5 chip) ACCOUNTS=none - standing down at a ladder boundary before $($a.tag): an open CLAIM that is not mine appeared on this file ($foreign). Ladders completed so far are banked and my root stays until I have pulled them. Nothing of mine is running."
    $script:ladderRc = 19; return
  }
  Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) coreultra9-4mib-riders-sitting-18sep EXTENSION - still running, still ONE sitting: ladder $($a.tag) ($($a.what)), 9 ladders total"
  $log   = Join-Path $logs "$($a.tag).log"
  $wcomb = Join-Path $here 'wcomb.ps1'
  $affArg = if ($a.aff) { " -Affinity $($a.aff)" } else { '' }
  $inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
           " -Phase $($a.phase) -Tag $($a.tag) -Label $($a.label) -Slice 4194304 -MemberMiB 1024 -Recovery 640" +
           " -Rungs `"$($a.rungs)`" -Threads `"$($a.threads)`" -Reps 1 -Residency resident -NttBudget $Budget" + $affArg
  Say "LADDER $($a.tag) label=$($a.label) phase=$($a.phase) aff=$(if($a.aff){$a.aff}else{'none (UNPINNED)'}) threads=$($a.threads) rungs=$($a.rungs) log=$log"
  Say "ARGV powershell $inner"
  # cmd /c redirect, NOT Tee-Object: a Tee-Object log is UTF-16 and
  # harness/rowgate.py answers "REFUSED: no legs" on one.
  #
  # rc=17 IS THE ONE EXIT CODE WORTH WAITING OUT, and the narrowness is the
  # point. rc=17 is plib's LOCK-BUSY: it means "somebody else has the box",
  # never "this measurement is wrong", because the ladder stopped before its
  # first leg, so nothing was measured and nothing is contaminated by asking
  # again later. EVERY OTHER NON-ZERO rc STILL ENDS THE ROUND ON THE SPOT,
  # because those are the instrument REFUSING - a residency violation, a path
  # assert, an AFFINITY READBACK MISMATCH, a cross-arm hash that does not match
  # - and retrying one of those would launder a refusal into a number.
  $arc = 0; $legs = 0; $lockWaits = 0
  while ($true) {
    & cmd /c "powershell $inner > `"$log`" 2>&1"
    $arc = $LASTEXITCODE
    $legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
    if ($arc -ne 17) { break }
    $lockWaits++
    if ($lockWaits -gt 20) { Say "ZRIDER-LADDER-LOCKOUT $($a.tag) gave up after $lockWaits waits of 120 s"; break }
    Say "ARM-LOCK-BUSY $($a.tag) attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s. This is an INTER-LADDER GAP being taken, not a measurement failure: no leg ran."
    Start-Sleep -Seconds 120
  }
  if ($a.aff) {
    $legLines = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue | ForEach-Object { $_.Line })
    $withAff  = @($legLines | Where-Object { $_ -match 'affinity=0x' })
    $equal    = @($legLines | Where-Object { $_ -match 'affinity=(0x[0-9A-Fa-f]+) .*affinity_got=\1( |$)' })
    Say "AFFINITY-AUDIT $($a.tag) want=$($a.aff) legs=$($legLines.Count) with_affinity_field=$($withAff.Count) readback_equal=$($equal.Count)"
    if ($legLines.Count -gt 0 -and $equal.Count -ne $legLines.Count) {
      Say "ZRIDER-AFFINITY-AUDIT-MISMATCH $($a.tag) - $($equal.Count) of $($legLines.Count) legs read their mask back equal. wcomb should have refused; read the log before believing ANY number from this ladder."
    }
  }
  Say "ARM-DONE $($a.tag) rc=$arc legs=$legs lock_waits=$lockWaits"
  # rc=0 WITH ZERO LEGS IS A REFUSAL, NOT A PASS, and this guard exists because
  # the lane holding this box before me lost a whole sitting to exactly it on
  # the morning of 18 Sep 2026. Its six ladders each hit wcomb's rc=17 LOCK-BUSY,
  # a non-zero exit from a called .ps1 does not throw in PowerShell, so its
  # try/catch read a busy rig as a finished ladder; all six "completed" in 0.4
  # seconds and its driver posted a completion NOTE over a round that had
  # measured nothing. I inherited the rc=17 retry that stops that particular
  # cause - but NOT a check on the OUTCOME, and the outcome is the thing that
  # generalises: any path that returns 0 having run no leg reads as a pass.
  #
  # This is CLAUDE.md's standing trap in a new place: `0 passed` is never a
  # verdict, and a green line over zero tests has the same shape as a green line
  # over a passing suite. READ THE COUNT, NOT THE EXIT CODE.
  #
  # It is a HARD STOP and deliberately not an rc=17-style retry: rc=17 means
  # "somebody else has the box", which is a reason to ask again later, where
  # rc=0-with-no-legs means the instrument returned success having done nothing,
  # and there is nothing about waiting that would fix it.
  if ($arc -eq 0 -and $legs -eq 0) {
    Say "ZRIDER-EMPTY-LADDER $($a.tag) returned rc=0 with ZERO legs - the instrument reported success having measured nothing. Refusing to treat that as a completed ladder and ending the round here. Read $log before believing anything about this sitting."
    $script:ladderRc = 21; return
  }
  $script:ladderLegs = $legs
  $script:ladderRc = $arc
}

# THE EIGHT LADDERS. Ladder 1 is unpinned and MUST be first (-Affinity arms the
# fixture create too). Its four legs are SPENT and are not reduced.
$ladders = @(
  @{ tag='zwarm';  label='4mr-warm';      phase='create';  aff='';      threads='16';   rungs='288';
     what='UNPINNED t16, ONE rung - BUILDS THE 16 GiB FIXTURE and SPENDS the warm-up ramp. Its four legs are DISCARDED, not reduced: the headline cell is a comparison between two unpinned ladders and the ramp must sit in NEITHER arm' },
  @{ tag='zsolo';  label='4mr-t16-solo';  phase='create';  aff='';      threads='16';   rungs='288,320,352,384,416,448,480,512';
     what='item 2 arm A - UNPINNED t16 SOLO on crpool4m grid, the arm that read 387' },
  @{ tag='zint';   label='4mr-int';       phase='create';  aff='';      threads='4,16'; rungs='288,320,352,384,416,448,480,512';
     what='item 2 arm B - UNPINNED -Threads 4,16 INTERLEAVED in ONE ladder the way crg4 ran it, same grid and same fixture as arm A so interleaving is the only difference' },
  @{ tag='zdrift'; label='4mr-t16-drift'; phase='create';  aff='';      threads='16';   rungs='384,416';
     what='item 2 DRIFT CONTROL - ladder 2 repeated at only the two rungs its crossover interpolates from, after ladder 3, so drift over positions 2 to 4 bounds drift over 2 to 3' },
  @{ tag='zp3e8';  label='4m3-e8';        phase='rowgate'; aff='0xFF0'; threads='8';    rungs='128,192,256';
     what='item 5 THE DECISIVE ARM - mask 0xFF0, cores 4-11, EIGHT E-cores: a WIDE POOL WITH NO SIBLINGS, the cell neither the i5 nor any GFNI-256 round has' },
  @{ tag='zp3e4';  label='4m3-e4';        phase='rowgate'; aff='0xF0';  threads='4';    rungs='128,192,256';
     what='item 5 THE CONTROL - mask 0xF0, cores 4-7, FOUR of the same E-cores: with the arm above this moves pool width with SMT held fixed at ZERO, which the i5 t4-to-t12 step cannot do' },
  @{ tag='ze8top'; label='4mr-e8-top';    phase='create';  aff='0xFF0'; threads='8';    rungs='420,424,428,432,436,440';
     what='crpin item 1 - the e8 create band is OPEN AT THE TOP; 4-row rungs literally above crpins top rung 420, where no-rung-priceable is a legitimate answer that bounds the trade at 6.9x' },
  @{ tag='zp4rep'; label='4mr-p4-rep';    phase='create';  aff='0xF';   threads='4';    rungs='408,412,416';
     what='crpin item 3 - a THIRD rep of the three rungs where 4mc-p4 reverses direction; cheapest ladder in the sitting' },
  @{ tag='zp3pe8'; label='4m3-pe8';       phase='rowgate'; aff='0xFF';  threads='8';    rungs='128,192,256';
     what='item 5 OPTIONAL THIRD ARM, taken only because the fixture is warm - mask 0xFF, cores 0-7, FOUR P PLUS FOUR E, MIXED and to be stated as mixed. Not needed for the e8-vs-e4 verdict; it says whether a MIXED-class wide pool knees like a single-class one. LAST on purpose: it is the one ladder whose loss destroys no deliverable' }
)

Say "ZRIDER-ROUND start root=$Root bin=$Bin budget=$Budget ladders=$($ladders.Count) plan=$(($ladders | ForEach-Object { "$($_.tag):$($_.phase):$($_.rungs)" }) -join ' ')"

# THE BUILD AND THE EXTRACT ARE GATED LIKE A MEASUREMENT ARM. A `cargo build`
# plus a 16 GiB create is foreign load to whoever is measuring, every bit as much
# as a ladder is, so the gate comes FIRST and the TAKING-THE-BOX line comes after
# it passes: until then this lane is queued and says so.
Wait-Quiet 'prebuild' 2
if (-not $script:quietOk) { Say "ZRIDER-ABORT load gate gave up before the build"; exit 8 }
$foreign0 = Test-ForeignClaim 'coreultra9-4mib-riders-sitting-18sep'
if ($foreign0) {
  Say "ZRIDER-ABORT an open CLAIM that is not mine is on $Coord at launch: $foreign0. NOT taking the box, NOT building, exiting 19. This is the guard gfni256-four-window-shape-1mib-18sep did not have on 18 Sep and lost a whole sitting to."
  Post "STAND-DOWN $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) coreultra9-4mib-riders-sitting-18sep gen=09e5f607 (<user>, opus5 chip) ACCOUNTS=none - NOT taking the box. An open CLAIM that is not mine is on this file at my launch ($foreign0), so I never started: no build, no fixture, no leg, no lock. I remain QUEUED."
  exit 19
}
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) coreultra9-4mib-riders-sitting-18sep gen=09e5f607 (<user>, opus5 chip, apple-m3-ultra-512gb; an internal note, lease to 2026-09-20T16:00:41Z) ACCOUNTS=none - TAKING THE BOX, now, for NINE ladders in ONE sitting off ONE 4 MiB / n=4096 fixture, carrying FOUR cells that three handoffs each commissioned AS A RIDER on the next sitting that builds this fixture. zwarm UNPINNED t16 m=288 builds the 16 GiB fixture and its four legs are SPENT and discarded; zsolo UNPINNED t16 and zint UNPINNED -Threads 4,16 on grid 288..512 with zdrift repeating zsolo at 384,416 afterwards (item 2 of an internal note - is the 22-row unpinned swing INTERLEAVING?); zp3e8 mask 0xFF0 t8 and zp3e4 mask 0xF0 t4 at rungs 128,192,256 on -Phase rowgate (item 5 of an internal note - a WIDE POOL WITH NO SIBLINGS, the cell that separates pool width from SMT, and the first rungs ever run below 320 on this part); ze8top mask 0xFF0 t8 at 420..440 (item 1 of an internal note - the e8 create band is open at the top); zp4rep mask 0xF t4 at 408,412,416 (item 3 of the same file - a third rep of the arm that is non-monotone in both sittings); and LAST, zp3pe8 mask 0xFF t8 at 128,192,256, item 5's OPTIONAL mixed-class arm taken only because the fixture is warm, which destroys no deliverable if it is cut. NO BUILD IF A BINARY IS INHERITED; otherwise ~2 min cargo build from 06d5734b7, byte-gated at 4,173,312. NINE LADDERS, ONE SITTING: wcomb takes the rig lock PER LADDER, so anybody inspecting the lock will see nine separate holds and THE GAPS BETWEEN THEM ARE NOT OPENINGS. Each ladder gates on lock-free AND no-parfast AND load under 25, RE-READS THIS FILE and stands down at a ladder boundary on any open CLAIM that is not mine, and waits out an rc=17 LOCK-BUSY rather than dying. Estimate ~3h including the build, the 16 GiB create and its ~745 s settle. NO CONSTANT MOVES - this round produces evidence only, and what it does not license is written into zrider-round.ps1 and landed on origin BEFORE the box was taken. My root is <rig>\zr18sep and I delete it when the numbers are banked. Kill by pid, never by pattern."

if (-not $SkipProbe) { Probe-Classes }

$WantBytes = 4173312
if (-not (Test-Path $Bin)) {
  # Win32_Process::Create (wlaunch.ps1) does not always see the user's PATH, and
  # rustup's shims live in the profile. Same fix wcomb.ps1 carries.
  if (-not (Get-Command cargo -ErrorAction SilentlyContinue)) { $env:PATH = "$env:USERPROFILE\.cargo\bin;$env:PATH" }
  $src = Join-Path $Root 'src'
  # EXTRACT INSIDE THE GATED REGION, not at staging time. The tarball is scp'd up
  # before launch - that is network work and costs the box little - but unpacking
  # ~25,000 files is disk and CPU that lands on whoever is measuring, so it waits
  # behind the same gate the build does.
  if (-not (Test-Path $src)) {
    $tgz = Join-Path $Root 'src-06d5734b7.tar.gz'
    if (-not (Test-Path $tgz)) { Say "ZRIDER-FAIL no source tree at $src and no tarball at $tgz"; exit 9 }
    New-Item -ItemType Directory -Force $src | Out-Null
    $xw = [Diagnostics.Stopwatch]::StartNew()
    cmd /c "tar -xzf `"$tgz`" -C `"$src`""
    $xrc = $LASTEXITCODE
    Say "EXTRACT rc=$xrc secs=$([math]::Round($xw.Elapsed.TotalSeconds,1)) into=$src"
    if ($xrc -ne 0) { Say "ZRIDER-FAIL extract rc=$xrc"; exit 9 }
  }
  if (-not (Test-Path (Join-Path $src 'Cargo.toml'))) { Say "ZRIDER-FAIL no Cargo.toml under $src"; exit 9 }
  $bw = [Diagnostics.Stopwatch]::StartNew()
  Push-Location $src
  # cmd /c, not `& cargo ... 2>&1`: cargo writes progress to stderr, and under
  # $ErrorActionPreference = 'Stop' PowerShell 5.1 turns the first stderr line of
  # a native command into a terminating error.
  cmd /c "cargo build --release -p parfast --locked > `"$Root\build-zrider.log`" 2>&1"
  $brc = $LASTEXITCODE
  Pop-Location
  Say "BUILD rc=$brc secs=$([math]::Round($bw.Elapsed.TotalSeconds,1)) log=$Root\build-zrider.log"
  if ($brc -ne 0) { Say "ZRIDER-FAIL build rc=$brc"; exit 9 }
} else {
  Say "BIN-INHERITED $Bin already present - no extract and no cargo build. The byte gate below runs on it UNCHANGED, which is what makes inheriting safe."
}
if (-not (Test-Path $Bin)) { Say "ZRIDER-FAIL bin not found after build: $Bin"; exit 9 }
$gotSha = (Get-FileHash $Bin -Algorithm SHA256).Hash
$gotLen = (Get-Item $Bin).Length
Say "BIN bytes=$gotLen want_bytes=$WantBytes sha256=$gotSha (a sha that matches no other round is EXPECTED and not a fault - the build embeds its own path; the byte count is the invariant across every build of 06d5734b7 on this fleet)"
if ($gotLen -ne $WantBytes) {
  Say "ZRIDER-FAIL binary byte count want=$WantBytes got=$gotLen - this is NOT the 06d5734b7 artefact the banked create and rowgate ladders used, so none of this round's four cells would tie to the figures they are commissioned against. Refusing rather than measuring it."
  exit 9
}
$fix = Join-Path $Root 'fix-4194304-1024'
Say "FIXTURE $(if (Test-Path $fix) { 'PRESENT (reused - no 16 GiB create and no settle wait)' } else { 'ABSENT - ladder zwarm builds it, then waits out the settle' }) $fix"
# Keep Windows Search out of the round root, not just the fixture dir.
cmd /c "attrib +I `"$Root`" /S /D" | Out-Null

$rc = 0
foreach ($a in $ladders) {
  Invoke-Ladder $a
  if ($script:ladderRc -ne 0) { Say "ZRIDER-LADDER-FAILED $($a.tag) rc=$($script:ladderRc) - see $logs\$($a.tag).log"; $rc = $script:ladderRc; break }
}

Say "ZRIDER-ROUND end rc=$rc"
# THE DONE LINE CARRIES THE PER-LADDER LEG COUNTS, and that is not decoration.
# The lane before me on this box posted a completion NOTE, in wording its driver
# generates automatically, over a sitting that ran ZERO legs - and the IDENTICAL
# wording had been posted by its own attempt 1 four hours earlier, so no reader
# of that file could tell the two apart. Its own correction is that the text is
# evidence the ladder LOOP EXITED and never that anything was measured; the
# check that settles it is the per-ladder LEG count.
#
# So this line states the counts rather than asserting completion, and a reader
# who sees `legs=0` anywhere in it knows the round is empty WITHOUT pulling a
# log off the box. An automatically-posted line cannot be a verdict, but it can
# at least carry the number that is one.
$tally = (@($ladders | ForEach-Object {
  $lg = @(Select-String -Path (Join-Path $logs "$($_.tag).log") -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
  "$($_.tag)=$lg"
}) -join ' ')
Say "ZRIDER-TALLY $tally"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) coreultra9-4mib-riders-sitting-18sep gen=09e5f607 (<user>, opus5 chip) ACCOUNTS=none - round ended rc=$rc; LEGS PER LADDER: $tally. This line is posted automatically by the driver when its ladder loop exits, so read the counts and not the word DONE - a loop can exit having measured nothing, which is what happened to the lane before me on this box. Logs under $logs. See the follow-up line for the result and the box-as-left statement."
exit $rc
