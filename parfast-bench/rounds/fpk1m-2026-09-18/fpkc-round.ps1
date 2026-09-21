param(
  [string]$Root   = '<rig>\fpk18sep',
  [string]$Bin    = '<rig>\fpk18sep\src\target\release\parfast.exe',
  [string]$Coord  = '<rig>\COORDINATION-coreultra9.txt',
  [string]$BinSha = '7DBF785D6AD48735EE3073C72A7314D5B74068B17147FA64E6955CFDACF52E78',
  [string]$Budget = '12884901888'
)
# fpkc-round.ps1 - LADDER C of lane fold-parallelism-knee-18sep: the same
# unpinned 1 MiB pool ladder as ladder A, with the NIBBLE kernel forced on the
# GFNI part (`NZBFAST_GF16_FORCE=avx2`).
#
# WHY THIS LADDER EXISTS, AND WHY IT WAS NOT IN THE ORIGINAL TWO. Ladders A and
# B refuted the banked shape: at 1 MiB on this part the fold's cpu/wall HOLDS as
# the pool widens (0.908 -> 0.957 unpinned -t12 across m, 0.924 -> 0.964 pinned
# -t8) where on the i5 it is 0.598 -> 0.542, and the fold BEATS the transform at
# every wide cell here (fold/force 1.09-1.18) where on the i5 it loses (0.63-
# 0.72). That settles the chip's question - the shape is not a property of the
# fold - and immediately raises the next one, which the chip's own framing
# cannot answer: **the two boxes differ in TWO ways at once.**
#
#   candidate 1  SMT. The i5's -t12 is 6 physical cores plus 6 SIBLINGS; this
#                part has no SMT at all and its -t12 is twelve distinct cores.
#                The i5's own decomposition puts the whole cost in the -t6 ->
#                -t12 step, which adds no cores (the two-binary control,
#                +61.3%/+56.2% for nothing).
#   candidate 2  KERNEL CLASS. The i5 is nibble (AVX2, no GFNI); this part is
#                GFNI-256. A denser fold kernel moves the compute-per-byte
#                ratio, so a bandwidth wall twelve NIBBLE threads reach need not
#                be reached by twelve GFNI ones.
#
# Ladders A and B cannot separate those, because the box choice confounds them.
# THIS LADDER CAN, in one direction: it runs the NIBBLE kernel on a NON-SMT
# part. Forcing avx2 holds the kernel class fixed at the i5's and leaves SMT as
# the only remaining difference.
#
#   If the fold STILL scales at -t12 under the nibble kernel -> candidate 2 is
#     refuted in this cell and SMT is what is left standing.
#   If the fold COLLAPSES at -t12 under the nibble kernel -> candidate 2 carries
#     it, the i5 reading is about the KERNEL and not about siblings, and the
#     refutation above needs re-reading as a GFNI-only result.
#
# EITHER WAY THIS IS ONE CELL ON ONE PART AND RANKS CANDIDATES RATHER THAN
# EXCLUDING ANY (memory topic nzbfast-rank-hypotheses-never-exclude-one). It
# cannot refute candidate 1, because nothing here has siblings to test; the
# clean test of SMT is `-Gf16Force` in the OTHER direction, which needs a GFNI
# part WITH SMT and this fleet has none.
#
# Reps 1, not 2: ladder A carries the replicate for this cell's shape and its
# rep spread was 0.03-3.1%, well under the effect being read (a fold eff of
# 0.95 against 0.54 is a 76% difference). NO CONSTANT MOVES.
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$logs = Join-Path $here 'logs'
New-Item -ItemType Directory -Force $logs | Out-Null
. (Join-Path $here 'plib.ps1')
function Say([string]$m) { "$(Get-Date -Format o) $m" }
function Post([string]$line) { try { Add-Content -Encoding UTF8 -Path $Coord -Value $line } catch { Say "COORD-WRITE-FAILED $_" } }
function Load-Now { (Get-CimInstance Win32_Processor | Measure-Object LoadPercentage -Average).Average }
function Wait-Quiet([string]$where, [int]$samples) {
  $script:quietOk = $false
  $capS = 5400; $t0 = Get-Date
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

Say "FPKC-ROUND start root=$Root bin=$Bin"
if (-not (Test-Path $Bin)) { Say "FPKC-FAIL binary absent $Bin"; exit 9 }
# THE SAME EXECUTABLE AS LADDERS A AND B, gated on the sha THEY ran under. This
# ladder is read directly against ladder A leg for leg, so a rebuilt binary
# would make that comparison a comparison of two executables with every field
# of every LEG line still well-formed - the t6ctl hazard.
$h = (Get-FileHash $Bin -Algorithm SHA256).Hash
if ($h -ne $BinSha) { Say "FPKC-FAIL binary sha256=$h wanted=$BinSha - not the executable ladders A and B ran"; exit 9 }
Say "BIN sha256=$h $Bin"
$fix = Join-Path $Root 'fix-1048576-512'
if (-not (Test-Path (Join-Path $fix 'gold.txt'))) { Say "FPKC-FAIL fixture absent $fix - this ladder reuses ladder A's and never builds one"; exit 9 }
Say "FIXTURE reused $fix"

Wait-Quiet 'fpkc' 2
if (-not $script:quietOk) { Say "FPKC-ABORT load gate gave up"; exit 8 }
Post "CLAIM $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) fold-parallelism-knee-18sep gen=585c33c3 (<user>, opus5 chip; an internal note, lease to 2026-09-18T12:25:50Z) ACCOUNTS=none - TAKING THE BOX AGAIN for ONE more ladder, fpkc, off the fixture and binary my earlier sitting already built (no build, no create). Ladders A and B answered the chip and raised a follow-on the chip could not: the i5 and this part differ in TWO ways at once, SMT and kernel class, and ladders A and B cannot separate them. fpkc forces the NIBBLE kernel (NZBFAST_GF16_FORCE=avx2) on this GFNI part at the same unpinned -t4,6,12 and the same rungs, which holds kernel class fixed at the i5's and leaves SMT as the only remaining difference. ~35 min, Reps 1, 36 legs. Root <rig>\fpk18sep, unchanged. NO CONSTANT MOVES. Will post DONE with the box-as-left statement and DELETE my root. Kill by pid, never by pattern."

$log = Join-Path $logs 'fpkc.log'
$wcomb = Join-Path $here 'wcomb.ps1'
$inner = "-NoProfile -ExecutionPolicy Bypass -File `"$wcomb`" -Root `"$Root`" -Bin `"$Bin`" -NoBuild" +
         " -Phase measure -Tag fpkc -Label g1m-nibble -Slice 1048576 -MemberMiB 512 -Recovery 2048" +
         " -Rungs `"192,512,1024,2048`" -Threads `"4,6,12`" -Reps 1 -Budget 2048 -NttBudget $Budget" +
         " -Gf16Force avx2"
Say "LADDER fpkc label=g1m-nibble UNPINNED threads=4,6,12 reps=1 gf16force=avx2 log=$log"
Say "ARGV powershell $inner"
$arc = 0; $lockWaits = 0
while ($true) {
  & cmd /c "powershell $inner > `"$log`" 2>&1"
  $arc = $LASTEXITCODE
  if ($arc -ne 17) { break }
  $lockWaits++
  if ($lockWaits -gt 20) { Say "FPKC-LOCKOUT gave up after $lockWaits waits"; break }
  Say "ARM-LOCK-BUSY attempt=$lockWaits holder=[$((Get-RigLockHolder).Text)] - waiting 120 s; no leg ran."
  Start-Sleep -Seconds 120
}
$legs = @(Select-String -Path $log -Pattern '^LEG ' -ErrorAction SilentlyContinue).Count
Say "ARM-DONE fpkc rc=$arc legs=$legs lock_waits=$lockWaits"
# THE KERNEL FORCE IS ASSERTED, NOT ASSUMED. `gf16force=` is stamped on every
# LEG line; a leg that did not carry it would be a GFNI leg published under the
# nibble ladder's name, which is the whole comparison inverted.
$bad = @(Select-String -Path $log -Pattern '^LEG ' | Where-Object { $_.Line -notmatch 'gf16force=avx2' }).Count
Say "GF16FORCE-ASSERT legs=$legs without_avx2=$bad"
if ($legs -gt 0 -and $bad -gt 0) { Say "FPKC-FAIL $bad leg(s) did not carry gf16force=avx2"; $arc = 9 }
Say "FPKC-ROUND end rc=$arc"
Post "DONE $((Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')) fold-parallelism-knee-18sep gen=585c33c3 (<user>, opus5 chip) ACCOUNTS=none - ladder fpkc ended rc=$arc, legs=$legs. See the follow-up line for the result and the box-as-left statement."
exit $arc
