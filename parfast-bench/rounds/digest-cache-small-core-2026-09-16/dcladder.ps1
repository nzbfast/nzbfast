# dcladder.ps1 - the SYNTHETIC half of claim
# parfast-digest-cache-small-core-gate-16sep: walk `parfast -t<n>` down from
# the whole box and find the width at which a --digest-cache HIT stops
# clearing the 0.55x gate.
#
# `-t` publishes nzbkit::mem::set_cpu_workers, and digest_cache.rs takes
# VALIDATE_THREADS.min(cpu_workers()), so ONE switch narrows the validation
# and the split scan's fold together - which is what a smaller part does.
#
# WHAT IT IS NOT: a smaller part also has less cache, less memory bandwidth
# and different turbo behaviour, none of which `-t` touches. A narrowed wide
# part keeps the whole box's bandwidth for its few threads, so this ladder is
# a LOWER BOUND on the harm, and the real boxes' rows are what the verdict
# rests on.
param(
  [string]$tree,
  [string]$work,
  [string]$tag = 'dcladder',
  [string]$widths = '18,12,8,6,4,3,2',
  [int]$reps = 2
)
$ErrorActionPreference = 'Stop'
. (Join-Path $tree 'research\harness\plib.ps1')

$exe    = Join-Path $tree 'target\release\parfast.exe'
$out    = Join-Path $work 'out'
$logd   = Join-Path $work 'logs'
$member = Join-Path $work 'single.bin'
foreach ($d in @($out, $logd)) { New-Item -ItemType Directory -Force $d | Out-Null }
function Log([string]$s) { $s; Add-Content -Path (Join-Path $logd "$tag.log") -Value $s }

Log "LADDER $tag start=$((Get-Date).ToUniversalTime().ToString('o')) host=$env:COMPUTERNAME cores=$env:NUMBER_OF_PROCESSORS widths=$widths"

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
Log ("BIN parfast sha256=" + (Get-FileHash $exe -Algorithm SHA256).Hash.Substring(0,16))
if (-not (Test-Path $member)) { Log "NO FIXTURE at $member - run dcsmall.ps1 first"; exit 3 }

$storeHit  = Join-Path $work 'store-hit'
$storeNull = Join-Path $work 'store-null'
if (-not (Test-Path $storeHit)) { Log "NO ENROLLED STORE at $storeHit - run dcsmall.ps1 first"; exit 3 }
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
  $sha.Dispose(); return $h.Substring(0,16)
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
      Log ("BOX-FREE foreign_cpu=$pct waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " at=$where"); return
    }
    Log ("BOX-QUEUE foreign_cpu=$pct locked=$locked waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " at=$where")
    Start-Sleep -Seconds 45
  }
  Log "BOX-QUEUE-TIMEOUT at=$where"
}
function Take-RigLockWaiting([string]$lockpath, [int]$capS = 3600) {
  $real = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  while ($t0.Elapsed.TotalSeconds -lt $capS) {
    if (-not (Test-Path $real)) { try { Take-RigLock $lockpath | Out-Null; return } catch { } }
    Log ("LOCK-WAIT waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0))
    Start-Sleep -Seconds 30
  }
  Log "LOCK-TIMEOUT"; exit 17
}

function Run-Leg([string]$arm, [int]$t, [int]$rep) {
  Clear-Out
  Read-Warm $work @('single.bin')
  $store = if ($arm -eq 'hit') { $storeHit } else { $storeNull }
  $flag = if ($arm -eq 'hit') { '--digest-cache ' } else { '' }
  $a = "c -q -s4429188 -c100 -t$t $flag-B `"$work`" `"$out\set.par2`" `"$member`""
  $base = Join-Path $logd "$tag-$arm-t$t-$rep"
  Wait-BoxFree "pre-$arm-t$t-$rep"
  Take-RigLockWaiting (Join-Path $env:USERPROFILE "$tag.lock")
  try {
    $r = Invoke-Leg $exe $a $work $base @{ LOCALAPPDATA = $store; NZBFAST_REPAIR_TIMING = '1' }
  } finally { Release-RigLock (Join-Path $env:USERPROFILE "$tag.lock") | Out-Null }
  $txt = (Get-Content "$base.out" -Raw) + (Get-Content "$base.err" -Raw)
  $fused = if ($txt -match 'fused=(\w+)') { $matches[1] } else { '?' }
  $dc = if ($txt -match 'digest-cache [^\r\n]*') { ($matches[0] -replace '\s+', ' ') } else { '-' }
  $fold = if ($txt -match 'fold alone ([0-9.]+\w*)') { $matches[1] } else { '-' }
  $chain = if ($txt -match 'chain alone ([0-9.]+\w*)') { $matches[1] } else { '-' }
  Log ("LEG arm=$arm t=$t rep=$rep rc=" + $r.rc + " wall=" + $r.wall + " cpu=" + $r.cpu +
       " foreign_cpu=" + $r.foreign + " foreign_after=" + $r.foreignAfter +
       " fused=$fused fold_alone=$fold chain_alone=$chain dc=[$dc] sha=" + (SetSha) +
       " ts=" + (Get-Date).ToUniversalTime().ToString('o'))
}

foreach ($w in ($widths -split ',')) {
  $t = [int]$w
  for ($rep = 1; $rep -le $reps; $rep++) {
    $order = if ($rep % 2 -eq 1) { @('fresh','hit') } else { @('hit','fresh') }
    foreach ($arm in $order) { Run-Leg $arm $t $rep }
  }
}
Log "LADDER $tag done=$((Get-Date).ToUniversalTime().ToString('o'))"
