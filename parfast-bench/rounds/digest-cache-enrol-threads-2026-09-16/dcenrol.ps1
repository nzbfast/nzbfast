# dcenrol.ps1 - the ENROL_THREADS ladder. Claim
# digest-cache-enrol-threads-gate-16sep.
#
# The question: the +2% enrol gate FAILS on the Core Ultra 9 at +2.8-3.3%
# (an internal note section 5), and the
# comment on `ENROL_THREADS` says that cannot happen. So walk the constant
# 1..4 and see whether any rung clears the gate on the part that fails it
# WITHOUT regressing a part that currently passes.
#
# THE PROTOCOL IS COPIED FROM dcsmall.ps1 (which copied it from design note
# 9b-3): same 8.86 GB AES-CTR fixture, same `c -q -s4429188 -c100`, the member
# warm, per-leg rig lock never held while waiting for quiet, quiet read as
# plib's foreign_cpu, `attrib +I` over the round root, and the combined
# SHA-256 of set*.par2 in name order identical on every leg or the leg is void.
#
# Arms: `fresh` (no flag - ENROL_THREADS is not on its path at all, so ONE
# fresh arm is the denominator for every rung) and `e<N>` (flag, an EMPTY
# store each leg, ENROL_THREADS forced to N through the measurement probe).
#
# THE PROBE: the binary this drives carries a throwaway
# PARFAST_ENROL_THREADS_PROBE knob in digest_cache.rs so one release build
# serves the whole ladder. IT MUST NOT LAND, and the ladder is only comparable
# because every rung is the same binary.
param(
  [string]$tree,
  [string]$work,
  [string]$tag = 'dcenrol',
  [string]$rungs = '1,2,3,4',
  [int]$reps = 3
)
$ErrorActionPreference = 'Stop'
. (Join-Path $tree 'research\harness\plib.ps1')

$exe    = Join-Path $tree 'target\release\parfast.exe'
$out    = Join-Path $work 'out'
$logd   = Join-Path $work 'logs'
$member = Join-Path $work 'single.bin'
foreach ($d in @($work, $out, $logd)) { New-Item -ItemType Directory -Force $d | Out-Null }
function Log([string]$s) { $s; Add-Content -Path (Join-Path $logd "$tag.log") -Value $s }

$rungList = @($rungs -split ',' | ForEach-Object { [int]$_.Trim() })
Log "ROUND $tag start=$((Get-Date).ToUniversalTime().ToString('o')) host=$env:COMPUTERNAME cores=$env:NUMBER_OF_PROCESSORS rungs=$rungs reps=$reps"

# THE HARNESS'S OWN PROVENANCE, at round start: one `HARNESS` line per file
# this round sources, then the `HARNESS-RIG` token that
# `tools/jcross-position-audit.py`'s `driver_label()` reads. Without it a
# banked log cannot be traced to the harness revision that wrote it months
# later, from the log alone (an internal note).
# plib adds ITSELF to the set, so this passes only its own path.
#
# GUARDED, because this driver dot-sources a BOX-LOCAL copy of plib.ps1 and
# `$ErrorActionPreference = 'Stop'` at the top of that file makes an unknown
# command a TERMINATING error - so a box whose deployed plib predates the
# function would have this stamp END THE ROUND. A stamp is a nicety and must
# never be able to do that; the absence is reported instead.
#
# THROUGH THIS DRIVER'S OWN `Log`, NOT `Write-HarnessFacts`: the round tees
# its log through a helper that writes the banked FILE and stdout, and never
# calls `Set-PlibLog`, so plib's own writer would put the stamp on the terminal
# and leave the BANKED log unstamped - looking fixed. `Get-HarnessLines`
# returns the lines and writes nothing, for exactly this case.
if (Get-Command Get-HarnessLines -ErrorAction SilentlyContinue) {
  foreach ($_hl in (Get-HarnessLines @($PSCommandPath))) { Log $_hl }
} else { Log 'HARNESS-UNAVAILABLE this plib.ps1 predates Get-HarnessLines' }
$cpuinfo = Get-CimInstance Win32_Processor
Log ("BOX cpu=" + $cpuinfo.Name + " cores=" + $cpuinfo.NumberOfCores + " logical=" + $cpuinfo.NumberOfLogicalProcessors + " ram_gb=" + [math]::Round((Get-CimInstance Win32_ComputerSystem).TotalPhysicalMemory/1GB,1))
& cmd /c "attrib +I `"$tree\*`" /S /D" 2>&1 | Out-Null
& cmd /c "attrib +I `"$work`" /D" 2>&1 | Out-Null
Log ("BIN parfast sha256=" + (Get-FileHash $exe -Algorithm SHA256).Hash.Substring(0,16) + " mtime=" + (Get-Item $exe).LastWriteTimeUtc.ToString('o'))

if (-not (Test-Path $member) -or (Get-Item $member).Length -ne 8858370048) {
  Log "NO FIXTURE at $member (need 8858370048 bytes) - run dcsmall.ps1 there first"; exit 3
}
Log ("FIXTURE sha256=" + (Get-FileHash $member -Algorithm SHA256).Hash)
Wait-FixtureSettle 'fixture'

$storeNull = Join-Path $work 'store-null'
New-Item -ItemType Directory -Force $storeNull | Out-Null

function Clear-Out { Get-ChildItem $out -File -ErrorAction SilentlyContinue | Remove-Item -Force }
function SetSha {
  $files = Get-ChildItem $out -Filter 'set*.par2' | Sort-Object Name
  $sha = [Security.Cryptography.SHA256]::Create()
  foreach ($f in $files) {
    $fs = [IO.File]::OpenRead($f.FullName); $buf = New-Object byte[] (4MB)
    while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $sha.TransformBlock($buf, 0, $n, $null, 0) | Out-Null }
    $fs.Close()
  }
  $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0) | Out-Null
  $h = ($sha.Hash | ForEach-Object { $_.ToString('x2') }) -join ''
  $sha.Dispose(); return ($h.Substring(0,16) + " files=" + $files.Count)
}
function Wait-BoxFree([string]$where, [int]$capS = 10800) {
  $real = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  $cores = [int]$env:NUMBER_OF_PROCESSORS; if ($cores -lt 1) { $cores = 1 }
  $ceiling = [math]::Max(100.0, $cores * 100.0 * 0.10)
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  while ($t0.Elapsed.TotalSeconds -lt $capS) {
    $pct = Get-ForeignCpu
    $locked = Test-Path $real
    if (-not $locked -and ($pct -lt 0 -or $pct -lt $ceiling / 3.0)) {
      Log ("BOX-FREE foreign_cpu=$pct ceiling=$ceiling waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " at=$where"); return
    }
    Log ("BOX-QUEUE foreign_cpu=$pct ceiling=$ceiling locked=$locked waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " at=$where")
    Start-Sleep -Seconds 45
  }
  Log "BOX-QUEUE-TIMEOUT at=$where capS=$capS - continuing anyway, read foreign_cpu on every leg below"
}
function Take-RigLockWaiting([string]$lockpath, [int]$capS = 3600) {
  $real = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  while ($t0.Elapsed.TotalSeconds -lt $capS) {
    if (-not (Test-Path $real)) { try { Take-RigLock $lockpath; return $true } catch { } }
    $who = ''; try { $who = [IO.File]::ReadAllText($real) } catch { $who = '(unreadable)' }
    Log ("LOCK-WAIT waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " held_by=" + ($who -replace '\s+',' '))
    Start-Sleep -Seconds 30
  }
  Log "LOCK-TIMEOUT never free in $capS s"; exit 17
}

$argsFresh = "c -q -s4429188 -c100 -B `"$work`" `"$out\set.par2`" `"$member`""
$argsFlag  = "c -q -s4429188 -c100 --digest-cache -B `"$work`" `"$out\set.par2`" `"$member`""

function Run-Arm([string]$arm, [int]$rep) {
  Clear-Out
  Read-Warm $work @('single.bin')
  $env2 = @{ NZBFAST_REPAIR_TIMING = '1' }
  if ($arm -eq 'fresh') {
    $env2['LOCALAPPDATA'] = $storeNull
    $a = $argsFresh
  } else {
    $n = [int]($arm -replace '^e','')
    $store = Join-Path $work ("store-$arm-$rep")
    if (Test-Path $store) { Remove-Item -Recurse -Force $store }
    New-Item -ItemType Directory -Force $store | Out-Null
    $env2['LOCALAPPDATA'] = $store
    $env2['PARFAST_ENROL_THREADS_PROBE'] = "$n"
    $a = $argsFlag
  }
  $base = Join-Path $logd "$tag-$arm-$rep"
  $r = Invoke-Leg $exe $a $work $base $env2
  $txt = (Get-Content "$base.out" -Raw) + (Get-Content "$base.err" -Raw)
  $fused = if ($txt -match 'fused=(\w+)') { $matches[1] } else { '?' }
  $dc    = if ($txt -match 'digest-cache [^\r\n]*') { ($matches[0] -replace '\s+', ' ') } else { '-' }
  $fold  = if ($txt -match 'fold alone ([0-9.]+\w*)') { $matches[1] } else { '-' }
  $chain = if ($txt -match 'chain alone ([0-9.]+\w*)') { $matches[1] } else { '-' }
  Log ("LEG arm=$arm rep=$rep rc=" + $r.rc + " wall=" + $r.wall + " cpu=" + $r.cpu + " peakmb=" + $r.peakmb +
       " foreign_cpu=" + $r.foreign + " foreign_after=" + $r.foreignAfter +
       " fused=$fused fold_alone=$fold chain_alone=$chain dc=[$dc] sha=" + (SetSha) +
       " ts=" + (Get-Date).ToUniversalTime().ToString('o'))
}

# Mirrored: forward, reverse, forward - the 9b-3 shape generalised past three
# arms, so no rung sits at a fixed position in the rep and the fresh
# denominator moves with them.
$forward = @('fresh') + ($rungList | ForEach-Object { "e$_" })
$reverse = @()
for ($i = $forward.Count - 1; $i -ge 0; $i--) { $reverse += $forward[$i] }
for ($rep = 1; $rep -le $reps; $rep++) {
  $order = if ($rep % 2 -eq 0) { $reverse } else { $forward }
  foreach ($arm in $order) {
    Wait-BoxFree "pre-$arm-$rep"
    Require-QuietBox "pre-$arm-$rep"
    Take-RigLockWaiting (Join-Path $env:USERPROFILE "$tag.lock")
    try { Run-Arm $arm $rep } finally { Release-RigLock (Join-Path $env:USERPROFILE "$tag.lock") }
  }
}
Log "ROUND $tag done=$((Get-Date).ToUniversalTime().ToString('o'))"
