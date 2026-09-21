# dcsmall.ps1 - does a --digest-cache HIT still clear the 0.55x gate on a
# small-core part? Claim parfast-digest-cache-small-core-gate-16sep.
#
# The protocol is COPIED from design note 9b-3 (an internal note-
# 2026-09-15.md): same 8.86 GB AES-CTR fixture, same `c -q -s4429188 -c100`,
# arms fresh / enrol / hit, three reps mirrored F-E-H / H-E-F / F-E-H, the
# member warm, the combined SHA-256 of set*.par2 identical across every leg of
# a box or the leg is void.
#
# Two deliberate differences from the mac driver, both forced by the platform:
#  - the store home is %LOCALAPPDATA%, not $HOME (digest_cache.rs store_dir).
#  - "quiet" is plib.ps1's foreign_cpu (CPU outside our own process tree), not
#    a one-minute load average. That is the STRONGER reading here: it cannot be
#    polluted by the leg's own burst, so the after-sample needs no settle wait.
param(
  [string]$tree,
  [string]$work,
  [string]$tag = 'dcsmall',
  [int64]$size = 8858370048,
  [int]$reps = 3
)
$ErrorActionPreference = 'Stop'
. (Join-Path $tree 'research\harness\plib.ps1')

$exe   = Join-Path $tree 'target\release\parfast.exe'
$out   = Join-Path $work 'out'
$logd  = Join-Path $work 'logs'
$member= Join-Path $work 'single.bin'
$SIZE  = $size
foreach ($d in @($work, $out, $logd)) { New-Item -ItemType Directory -Force $d | Out-Null }

function Log([string]$s) { $s; Add-Content -Path (Join-Path $logd "$tag.log") -Value $s }

Log "ROUND $tag start=$((Get-Date).ToUniversalTime().ToString('o')) host=$env:COMPUTERNAME cores=$env:NUMBER_OF_PROCESSORS"

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
# NOT CONTENT INDEXED, our own round root only. Windows Search walks a freshly
# extracted source tree and a freshly written fixture under the user profile,
# and SearchIndexer at ~1 core is invisible to a 10%-of-a-16-core-box ceiling:
# it cost the 15 Sep NTT round twelve legs and two of five ladders
# (an internal note). `attrib +I` is that
# round's own remedy, applied here BEFORE the fixture exists rather than
# mid-round.
& cmd /c "attrib +I `"$tree\*`" /S /D" 2>&1 | Out-Null
& cmd /c "attrib +I `"$work`" /D" 2>&1 | Out-Null
Log ("BIN parfast sha256=" + (Get-FileHash $exe -Algorithm SHA256).Hash.Substring(0,16) + " mtime=" + (Get-Item $exe).LastWriteTimeUtc.ToString('o'))

# --- fixture: the openssl -aes-128-ctr keystream, byte for byte -------------
# openssl enc -aes-128-ctr -nosalt -K 000102..0f -iv 00..00 -in /dev/zero is
# exactly AES-ECB over a big-endian 128-bit counter starting at zero, because
# the plaintext is all zeros. No openssl on any Windows box in the fleet, so it
# is regenerated here rather than copied; the SHA-256 below is the cross-check.
Add-Type @"
using System;
using System.IO;
using System.Security.Cryptography;
public static class CtrGen {
  // openssl enc -aes-128-ctr -nosalt -K 000102..0f -iv 00..00 -in /dev/zero
  // is exactly AES-ECB over a big-endian 128-bit counter from zero, because
  // the plaintext is all zeros. Same bytes on every box, no openssl needed.
  public static void Write(string path, long size) {
    Aes aes = Aes.Create();
    aes.Mode = CipherMode.ECB; aes.Padding = PaddingMode.None; aes.KeySize = 128;
    byte[] key = new byte[16];
    for (int i = 0; i < 16; i++) key[i] = (byte)i;
    aes.Key = key;
    ICryptoTransform enc = aes.CreateEncryptor();
    const int blocks = 262144;
    byte[] plain = new byte[blocks * 16];
    byte[] cipher = new byte[blocks * 16];
    ulong ctr = 0;
    long written = 0;
    using (FileStream fs = new FileStream(path, FileMode.Create, FileAccess.Write, FileShare.None, 1 << 20)) {
      while (written < size) {
        for (int b = 0; b < blocks; b++) {
          int o = b * 16;
          for (int i = 0; i < 8; i++) plain[o + i] = 0;
          for (int i = 0; i < 8; i++) plain[o + 15 - i] = (byte)((ctr >> (8 * i)) & 0xFF);
          ctr++;
        }
        int n = enc.TransformBlock(plain, 0, plain.Length, cipher, 0);
        long take = Math.Min((long)n, size - written);
        fs.Write(cipher, 0, (int)take);
        written += take;
      }
    }
    enc.Dispose(); aes.Dispose();
  }
}
"@

if (-not (Test-Path $member) -or (Get-Item $member).Length -ne $SIZE) {
  Log "FIXTURE building $SIZE bytes"
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  [CtrGen]::Write($member, $SIZE)
  $t0.Stop()
  Log ("FIXTURE built_s=" + [math]::Round($t0.Elapsed.TotalSeconds,1) + " size=" + (Get-Item $member).Length)
}
Log ("FIXTURE sha256=" + (Get-FileHash $member -Algorithm SHA256).Hash)
Wait-FixtureSettle 'fixture'

# --- store homes -------------------------------------------------------------
$storeHit  = Join-Path $work 'store-hit'
$storeNull = Join-Path $work 'store-null'
New-Item -ItemType Directory -Force $storeNull | Out-Null

function Wait-BoxFree([string]$where, [int]$capS = 10800) {
  # The queue half of the lock discipline. plib's Require-QuietBox aborts the
  # round (exit 18) after five minutes over the ceiling, which is right for a
  # box that has quietly acquired a neighbour and wrong for a box that is
  # simply BUSY WITH SOMEBODY ELSE'S ROUND when ours wants to start a leg.
  # amd-epyc-vm ate a whole cold pass that way on 15 Sep (design note 9b-3).
  # So wait for the box to be free FIRST - no lock held while waiting, per
  # memory topic nzbfast-quiet-leg-gate-and-rig-lock-queues - and only then
  # let Require-QuietBox do its own (now cheap) check inside Invoke-Leg.
  $real = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  $cores = [int]$env:NUMBER_OF_PROCESSORS; if ($cores -lt 1) { $cores = 1 }
  $ceiling = [math]::Max(100.0, $cores * 100.0 * 0.10)
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  while ($t0.Elapsed.TotalSeconds -lt $capS) {
    $pct = Get-ForeignCpu
    $locked = Test-Path $real
    if (-not $locked -and ($pct -lt 0 -or $pct -lt $ceiling / 3.0)) {
      Log ("BOX-FREE foreign_cpu=$pct ceiling=$ceiling waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " at=$where")
      return
    }
    Log ("BOX-QUEUE foreign_cpu=$pct ceiling=$ceiling locked=$locked waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " at=$where")
    Start-Sleep -Seconds 45
  }
  Log "BOX-QUEUE-TIMEOUT at=$where capS=$capS - continuing anyway, read foreign_cpu on every leg below"
}

function Take-RigLockWaiting([string]$lockpath, [int]$capS = 3600) {
  # plib's Take-RigLock exits 17 on a busy lock, which is right for a round
  # that has not started and wrong for leg 7 of 9. A lane that queues behind
  # another lane's lock must WAIT, and must not be holding the lock while it
  # does (memory topic nzbfast-quiet-leg-gate-and-rig-lock-queues).
  $real = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  while ($t0.Elapsed.TotalSeconds -lt $capS) {
    if (-not (Test-Path $real)) {
      try { Take-RigLock $lockpath; return $true } catch { }
    }
    $who = ''
    try { $who = [IO.File]::ReadAllText($real) } catch { $who = '(unreadable)' }
    Log ("LOCK-WAIT waited_s=" + [math]::Round($t0.Elapsed.TotalSeconds,0) + " held_by=" + ($who -replace '\s+',' '))
    Start-Sleep -Seconds 30
  }
  Log "LOCK-TIMEOUT never free in $capS s"
  exit 17
}

function Clear-Out { Get-ChildItem $out -File -ErrorAction SilentlyContinue | Remove-Item -Force }
function SetSha {
  $files = Get-ChildItem $out -Filter 'set*.par2' | Sort-Object Name
  $sha = [Security.Cryptography.SHA256]::Create()
  foreach ($f in $files) {
    $fs = [IO.File]::OpenRead($f.FullName)
    $buf = New-Object byte[] (4MB)
    while (($n = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $sha.TransformBlock($buf, 0, $n, $null, 0) | Out-Null }
    $fs.Close()
  }
  $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0) | Out-Null
  $h = ($sha.Hash | ForEach-Object { $_.ToString('x2') }) -join ''
  $sha.Dispose()
  return ($h.Substring(0,16) + " files=" + $files.Count)
}

$argsBase = "c -q -s4429188 -c100 -B `"$work`" `"$out\set.par2`" `"$member`""

# Enrolment setup leg, untimed: one create with the flag into storeHit.
if (Test-Path $storeHit) { Remove-Item -Recurse -Force $storeHit }
New-Item -ItemType Directory -Force $storeHit | Out-Null
Clear-Out
Wait-BoxFree "setup"
Log "SETUP enrolling into $storeHit"
$r = Invoke-Leg $exe ("c -q -s4429188 -c100 --digest-cache -B `"$work`" `"$out\set.par2`" `"$member`"") $work (Join-Path $logd "$tag-setup") @{ LOCALAPPDATA = $storeHit; NZBFAST_REPAIR_TIMING = '1' }
Log ("SETUP rc=" + $r.rc + " wall=" + $r.wall + " sha=" + (SetSha))

function Run-Arm([string]$arm, [int]$rep) {
  Clear-Out
  Read-Warm $work @('single.bin')
  $store = switch ($arm) { 'fresh' { $storeNull } 'hit' { $storeHit } 'enrol' { Join-Path $work ("store-enrol-$rep") } }
  if ($arm -eq 'enrol') {
    if (Test-Path $store) { Remove-Item -Recurse -Force $store }
    New-Item -ItemType Directory -Force $store | Out-Null
  }
  $a = if ($arm -eq 'fresh') { $argsBase } else { "c -q -s4429188 -c100 --digest-cache -B `"$work`" `"$out\set.par2`" `"$member`"" }
  $base = Join-Path $logd "$tag-$arm-$rep"
  $r = Invoke-Leg $exe $a $work $base @{ LOCALAPPDATA = $store; NZBFAST_REPAIR_TIMING = '1' }
  $txt = (Get-Content "$base.out" -Raw) + (Get-Content "$base.err" -Raw)
  $fused = if ($txt -match 'fused=(\w+)') { $matches[1] } else { '?' }
  $dc = if ($txt -match 'digest-cache [^\r\n]*') { ($matches[0] -replace '\s+', ' ') } else { '-' }
  $fold = if ($txt -match 'fold alone ([0-9.]+\w*)') { $matches[1] } else { '-' }
  $chain = if ($txt -match 'chain alone ([0-9.]+\w*)') { $matches[1] } else { '-' }
  Log ("LEG arm=$arm rep=$rep rc=" + $r.rc + " wall=" + $r.wall + " cpu=" + $r.cpu + " peakmb=" + $r.peakmb +
       " foreign_cpu=" + $r.foreign + " foreign_after=" + $r.foreignAfter +
       " fused=$fused fold_alone=$fold chain_alone=$chain dc=[$dc] sha=" + (SetSha) +
       " ts=" + (Get-Date).ToUniversalTime().ToString('o'))
}

$orders = @(@('fresh','enrol','hit'), @('hit','enrol','fresh'), @('fresh','enrol','hit'))
for ($rep = 1; $rep -le $reps; $rep++) {
  foreach ($arm in $orders[$rep - 1]) {
    # Quiet FIRST, without the lock: the rig lock is per leg and a waiter must
    # never hold it while it waits (memory topic
    # nzbfast-quiet-leg-gate-and-rig-lock-queues).
    Wait-BoxFree "pre-$arm-$rep"
    Require-QuietBox "pre-$arm-$rep"
    Take-RigLockWaiting (Join-Path $env:USERPROFILE "$tag.lock")
    try { Run-Arm $arm $rep } finally { Release-RigLock (Join-Path $env:USERPROFILE "$tag.lock") }
  }
}
Log "ROUND $tag done=$((Get-Date).ToUniversalTime().ToString('o'))"
