# zswp3drv.ps1 - detached waiter for claim zswp2-rotated-rerun-18sep on intel-core-ultra-9-386h.
# Holds NO lock and runs NO build while waiting. Takes the box only when the rig
# lock reads free (Get-RigLockHolder) AND the live coordination file carries no
# open CLAIM (Get-OpenClaimants) AND foreign CPU is under the quiet ceiling, for
# GRACE consecutive one-minute polls - so a lane queued ahead of me who wants the
# box next only has to post CLAIM inside that window and I hold. Then it posts
# CLAIM and runs zswp3run.ps1 as a child process; swpcore takes the rig lock
# itself (exit 17 = LOCK-BUSY, 18 = ABORT-LOAD, both re-queue rather than end).
param([switch]$Restart)
$ErrorActionPreference = 'Continue'
$R      = '<rig>\zswp3-18sep'
$COORD  = '<rig>\COORDINATION-coreultra9.txt'
$ID     = 'zswp2-rotated-rerun-18sep'
$GEN    = 'a5802b1b'
$WHO    = "(fable chip, <user>, apple-m3-ultra-512gb; an internal note, lease to 2026-09-20T16:38Z) ACCOUNTS=none"
$TAKEBY = [datetime]::Parse('2026-09-20T12:30:00Z').ToUniversalTime()
$GRACE  = 10
$POLL   = 60
$CEIL   = 160.0
. "$R\plib.ps1"
Set-PlibLog "$R\zswp3-driver.log"
# Get-OpenClaimants returns `,$open` - a one-element wrapper - so @() around it
# counts ONE even when $open is empty. Pipe to unroll, then keep non-empty names.
function Claimants { @(@(Get-OpenClaimants $COORD $ID) | ForEach-Object { $_ } | Where-Object { "$_" -ne '' }) }
function Stamp { (Get-Date).ToUniversalTime().ToString('o') }
function Post([string]$kw, [string]$body) { try { Write-CoordMarker $COORD $kw $ID $body | Out-Null } catch { "POST-FAILED $kw $($_.Exception.Message)" } }

"DRV-START $(Stamp) pid=$PID root=$R restart=$Restart"
if ($Restart) { Post 'NOTE' "gen=$GEN $WHO - waiter RESTARTED as pid $PID after a fix to my own polling script (it read an empty open-claim list as one open claim, so it would never have taken the box). My QUEUED line of 17:06:02Z stands unchanged: same place in the queue, same 10-minute grace rule, nothing taken, nothing run." }
else { Post 'QUEUED' "gen=$GEN $WHO - NOT taking the box: I am QUEUED behind gfni256-four-window-shape-1mib-18sep, who holds it (driver pid 2868, ends about 18:20-18:30Z by its own handover NOTE), and behind rar15-pdr-candidates-x86-cells, rarfast-header-vint-width-on-rewrite, coreultra9-4mib-riders-sitting-18sep and codex-parfast-create-readers-18sep, all named QUEUED on this file ahead of me. My waiter is pid $PID; it holds NO lock and runs NO build. WHAT I WANT: the published zswp2 create sweep re-run under the ROTATED swpcore.ps1 (an internal note row R1) - parfast vs parfast-mcap vs par2turbo, sizes 10/15/20/23/30/40 GiB x redundancy 10/15/20, 16 threads, mem arm 2048 MB, 54 legs, the SAME parfast.exe sha (cae5a6f3) the published round used. PRICE, read off the published log rather than the census: that round ran 04:50-07:33Z, so about 2h45m of box, plus a 40 GiB payload build under the lock at the start (the census said 90 min; the 30 and 40 GiB cells are minutes each, not seconds). HOW I TAKE IT: only after the rig lock reads free AND this file carries no open CLAIM AND foreign CPU is under 160 pct for $GRACE consecutive one-minute polls - so if you are ahead of me and want the box next, post CLAIM inside that window and I hold; I re-read this file on every poll. If it has not freed by $($TAKEBY.ToString('o')) I post WITHDRAWN and release my ledger claim. Everything of mine lives under $R (scripts, two sha-gated binary copies, payload, rig dir, logs); payload and rig dir are removed by name when the round ends, logs kept. Kill by pid, never by pattern; I kill nothing." }

$streak = 0
$attempt = 0
while ($true) {
  $now = (Get-Date).ToUniversalTime()
  if ($now -gt $TAKEBY) {
    "DRV-DEADLINE $(Stamp)"
    Post 'WITHDRAWN' "gen=$GEN $WHO - WITHDRAWING my QUEUED line: the box did not free by $($TAKEBY.ToString('o')). Nothing of mine ran, no lock taken, no build, no leg. My ledger claim is released by the session that owns it. Files under $R are removed by hand."
    exit 3
  }
  $h = Get-RigLockHolder
  $claim = Claimants
  $fc = Get-ForeignCpu
  $free = (-not $h.Held) -and ($claim.Count -eq 0) -and ($fc -ge 0) -and ($fc -lt $CEIL)
  if ($free) { $streak++ } else { $streak = 0 }
  "DRV-POLL $(Stamp) lock_held=$($h.Held) lock_why=$($h.Why) open_claims=[$($claim -join ' ')] foreign_cpu=$fc streak=$streak/$GRACE"
  if ($streak -ge $GRACE) {
    $attempt++
    $h2 = Get-RigLockHolder; $c2 = Claimants
    if ($h2.Held -or $c2.Count -gt 0) { "DRV-RECHECK-BUSY lock_held=$($h2.Held) open_claims=[$($c2 -join ' ')]"; $streak = 0; Start-Sleep -Seconds $POLL; continue }
    Post 'CLAIM' "gen=$GEN $WHO - TAKING THE BOX (attempt $attempt): the rig lock read free, this file carried no open CLAIM and foreign CPU was under 160 pct for $GRACE consecutive minutes ending $(Stamp), and nobody ahead of me posted CLAIM in that window. Launching swpcore.ps1 now (child of my waiter pid $PID; its lock token reads round=swp, its own pid); it quiet-gates every leg. About 2h45m of box: 40 GiB payload build first, then 54 create legs, parfast/parfast-mcap/turbo rotated one step per cell. Log <rig>\zswp3-18sep\zswp3.log. I will post DONE. Kill by pid, never by pattern."
    $log = "$R\zswp3.log"; $err = "$R\zswp3.err"
    if (Test-Path $log) { Move-Item $log "$R\zswp3-attempt$($attempt - 1).log" -Force }
    "DRV-LAUNCH $(Stamp) attempt=$attempt"
    & powershell -NoProfile -ExecutionPolicy Bypass -File "$R\zswp3run.ps1" 2> $err | Out-File -Encoding utf8 $log
    $rc = $LASTEXITCODE
    "DRV-CHILD-EXIT $(Stamp) rc=$rc"
    if ($rc -eq 17 -or $rc -eq 18) {
      $why = if ($rc -eq 17) { 'LOCK-BUSY (rc 17): another round took the rig lock between my re-check and swpcore''s take' } else { 'ABORT-LOAD (rc 18): the quiet gate refused a leg after ten 30 s waits' }
      Post 'RELEASE' "gen=$GEN $WHO - NOT running: $why. No leg of mine is data (the partial log is banked as zswp3-attempt$attempt.log and will not be published). Re-queuing behind whoever has the box; my waiter pid $PID keeps polling with the same $GRACE-minute grace rule."
      Move-Item $log "$R\zswp3-attempt$attempt.log" -Force -EA SilentlyContinue
      $streak = 0; Start-Sleep -Seconds $POLL; continue
    }
    $legs = @(Select-String -Path $log -Pattern '^CC ' -EA SilentlyContinue).Count
    $ended = [bool](Select-String -Path $log -Pattern '^SWP-END' -EA SilentlyContinue)
    Remove-Item "$R\paysweep" -Recurse -Force -EA SilentlyContinue
    Remove-Item "$R\swp" -Recurse -Force -EA SilentlyContinue
    Post 'DONE' "gen=$GEN $WHO - BOX RELEASED, rig lock released by swpcore''s finally. Round rc=$rc, CC legs=$legs of 54, SWP-END=$ended, log $R\zswp3.log. Payload (40 GiB) and rig dir removed by name; logs and the two binary copies stay under $R until the write-up lands, then the directory goes. I killed nothing. Thank you to the queue."
    "DRV-END $(Stamp) rc=$rc legs=$legs ended=$ended"
    exit 0
  }
  Start-Sleep -Seconds $POLL
}
