# nttwork-i5.ps1 - the Windows half of nttwork.py (lane
# parfast-ntt-min-work-small-sets-14sep): where the single-window transform
# stops losing to the fold on (n_present, n_missing), on the x86 box the
# NTT_MIN_WORK floor was set from. Same fixture, arms and gates as the mac
# half - read that file's header; only the mechanics differ here.
#
# KEEP THIS FILE PURE ASCII. PowerShell 5.1 reads a BOM-less script as ANSI,
# so a literal micro sign in a regex silently matches nothing; the unit parser
# below takes any non-(ms|s|ns) unit as micro for that reason.
#
# DRIVEN BY A PLAN FILE, because wlaunch.ps1 passes no arguments: plan.txt in
# the ROUND DIRECTORY, which is the directory this script sits in (<rig>\ntw
# for the 14 Sep round). One series per line,
#     <label> <block_bytes> <reps> <m>:<P>,<P>,...;<m>:<P>,... [<variant> ...]
# and a SOURCE TARBALL src.tgz beside it (git archive of the tree under
# test: Cargo.toml Cargo.lock rust-toolchain.toml .cargo crates vendor). The
# round builds parfast from it under the rig lock and refuses a binary older
# than the build start (the stale-tree trap, 7 Sep round NP).
#
# ONE ROUND DIRECTORY PER LANE (added 15 Sep 2026, lane
# parfast-x86-transform-cpu-1mib-15sep). Two lanes wanted this box on the same
# day and this script hard-coded <rig>\ntw, so the second lane's plan.txt and
# src.tgz would have overwritten the first's while its round was queued. The
# rig lock still keeps the ROUNDS apart; the directory keeps their INPUTS
# apart. claim.txt beside the plan names the lane: line 1 the claim id, the
# rest the COORDINATION text. Absent, the 14 Sep id is used, so the 14 Sep
# launch line below still works unchanged.
#
# VARIANTS, fields 5 and on, each `<name>:<KEY>=<VAL>[,<KEY>=<VAL>...]`: an
# extra FORCE arm with that environment on top, run on the SAME corpus and
# mirrored within each rep with force and fold (arm tag `force-<name>`), so a
# geometry A/B pays for one fold arm and not one per pin. Keys must be
# NZBFAST_* and may not be NZBFAST_NTT itself (a variant is a forced
# transform by definition). A pinned NZBFAST_NTT_THREADS or NZBFAST_NTT_W is
# ASSERTED against the leg's `ntt syndromes (...)` line, so a pin the binary
# ignored cannot bank as a measurement of that pin.
#
# LAUNCH (detached; a Start-Process dies with the ssh session):
#     powershell -File <rig>\wlaunch.ps1 -Script <rig>\ntw\nttwork-i5.ps1 -Tag ntw -Root <rig>\ntw
# $Root IS DERIVED FROM THIS SCRIPT'S OWN LOCATION, not hard-coded (16 Sep
# 2026, lane neon-thin-rows-second-part-16sep). It was '<rig>', which is the
# rig root on intel-i5-10600kf and on no other box - snapdragon-x2-elite-extreme has no D: at all, and
# the 14 Sep note above already records a round dying on its own preflight for
# exactly that reason. The round directory is the script's parent and its
# parent is the rig root, which is the layout every Windows box here already
# uses, so this resolves to <rig> on intel-i5-10600kf unchanged and needs no
# configuration on a new box.
$Ntw = Split-Path -Parent $PSCommandPath
$Root = if ($Ntw) { Split-Path -Parent $Ntw } else { '<rig>' }
if (-not $Ntw) { $Ntw = Join-Path $Root 'ntw' }
$Fix = Join-Path $env:USERPROFILE ((Split-Path $Ntw -Leaf) + 'fix')   # C: (TLC); D: is QLC
# The coordination file is the BOX's, so it cannot be a constant either. A
# coord.txt beside the plan names it, the same idiom claim.txt already uses;
# absent, the intel-i5-10600kf default stands and that box's rounds are unchanged.
$coordFile = Join-Path $Ntw 'coord.txt'
$coordName = if (Test-Path $coordFile) { (Get-Content $coordFile -Raw).Trim() } else { 'COORDINATION-intel-i5-10600kf.txt' }
$Coord = Join-Path $Root $coordName
$Id = 'parfast-ntt-min-work-small-sets-14sep'
$ClaimText = '(opus lane, <user>) - NTT_MIN_WORK small-set sweep: build parfast from <rig>\ntw\src.tgz, then force vs fold on (n_present, m) at 1 MiB and 128 KiB, SHA-gated, path asserted per leg. Holds ~\.parfast-rig.lock. Will post DONE.'
$claimFile = Join-Path $Ntw 'claim.txt'
if (Test-Path $claimFile) {
  $claimLines = @(Get-Content $claimFile)
  $Id = $claimLines[0].Trim()
  if ($claimLines.Count -gt 1) { $ClaimText = ($claimLines[1..($claimLines.Count - 1)] -join ' ').Trim() }
}
. (Join-Path $Root 'plib.ps1')
$ErrorActionPreference = 'Stop'
# Every knob an arm may pin, cleared from the DRIVER's environment: a child
# inherits it, and an inherited pin would turn the default arms into pinned ones.
foreach ($knob in @('NZBFAST_NTT', 'NZBFAST_NTT_THREADS', 'NZBFAST_NTT_W')) {
  Remove-Item "Env:$knob" -ErrorAction SilentlyContinue
}

function Stamp { (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ') }
function Coord([string]$verb, [string]$text) { Add-Content $Coord ("$verb " + (Stamp) + " $Id $text") }
function AsSec([string]$v, [string]$u) {
  $x = [double]::Parse($v, [Globalization.CultureInfo]::InvariantCulture)
  switch ($u) { 'ms' { return $x / 1e3 } 's' { return $x } 'ns' { return $x / 1e9 } default { return $x / 1e6 } }
}

# WAITING FOR A FREE BOX, when wait.txt sits beside the plan: line 1 a UTC
# deadline, every further line the pid of a process queued AHEAD of this round.
# Added 15 Sep 2026, when this box carried a lock holder (fsi5) with a second
# lane's waiter (narrowx86.ps1) queued behind it. The lock alone is not "busy"
# enough: that waiter runs ~20 minutes of cargo BEFORE its round takes the lock,
# so a round that only waited for the lock could take it inside that window and
# measure somebody's build. So busy is: the lock, OR any parfast / cargo / rustc,
# OR a listed pid still alive and older than this wait (a reused pid is younger,
# so it cannot hold the queue forever) - and free must read free twice, a minute
# apart. wlaunch.ps1 refuses outright while the lock is held, so a queued round
# is launched the way wlaunch launches, by hand. Past the deadline: exit 5,
# no lock taken.
$waitFile = Join-Path $Ntw 'wait.txt'
if (Test-Path $waitFile) {
  $waitLines = @(Get-Content $waitFile | Where-Object { $_.Trim() })
  $waitUntil = [datetime]::Parse($waitLines[0].Trim()).ToUniversalTime()
  $ahead = @()
  if ($waitLines.Count -gt 1) { $ahead = @($waitLines[1..($waitLines.Count - 1)] | ForEach-Object { [int]$_.Trim() }) }
  $waitStart = Get-Date
  # BUSY IS A HOLDER, NOT A FILE. This was `Test-Path $lockProbe` until 16 Sep
  # 2026, so an ORPHAN - a lock whose holder died without releasing - read as
  # 'lock' on every poll and parked this round here until its deadline, exit 5,
  # on a box that was free (an internal note).
  # plib's Test-RigLockHeld puts the question to the holder's own pid, and plib
  # is already dot-sourced above. THE OTHER TWO ARMS STAY: a round that never
  # took the lock is still load, which is what the parfast/cargo/rustc test
  # catches, and the queued-ahead pids are this round's own turn-taking.
  function Test-BoxBusy {
    if (Test-RigLockHeld) { return 'lock' }
    if (Get-Process parfast, cargo, rustc -ErrorAction SilentlyContinue) { return 'parfast/cargo/rustc running' }
    foreach ($aheadPid in $ahead) {
      $q = Get-Process -Id $aheadPid -ErrorAction SilentlyContinue
      if ($q -and $q.StartTime -lt $waitStart) { return "queued-ahead pid=$aheadPid alive" }
    }
    return ''
  }
  "WAIT until=$($waitLines[0].Trim()) ahead=$($ahead -join ',') ts=$(Stamp)"
  $lastWhy = ''
  while ($true) {
    $why = Test-BoxBusy
    if (-not $why) {
      Start-Sleep -Seconds 60
      $why = Test-BoxBusy
      if (-not $why) { break }
    }
    if ($why -ne $lastWhy) { "WAIT-BUSY $why ts=$(Stamp)"; $lastWhy = $why }
    if ((Get-Date).ToUniversalTime() -gt $waitUntil) { "WAIT-DEADLINE the box never came free ts=$(Stamp)"; exit 5 }
    Start-Sleep -Seconds 60
  }
  "WAIT-FREE ts=$(Stamp)"
}

Take-RigLock (Join-Path $Ntw 'nttwork.lock')
$done = 'ABORTED'
try {
  Coord 'CLAIM' $ClaimText
  "BOX host=$env:COMPUTERNAME cpu=$((Get-CimInstance Win32_Processor).Name) cores=$env:NUMBER_OF_PROCESSORS"
  "ROUND dir=$Ntw fixture=$Fix id=$Id"
  # Registers both files, so every LEG line's rig= re-reads what ran.
  Write-HarnessFacts @($PSCommandPath)

  # --- build ----------------------------------------------------------------
  $src = Join-Path $Ntw 'src'
  $exe = Join-Path $src 'target\release\parfast.exe'
  $tgz = Join-Path $Ntw 'src.tgz'
  $stampFile = Join-Path $Ntw 'src.tgz.built'
  $tgzHash = (Get-FileHash $tgz -Algorithm SHA256).Hash
  $prev = if (Test-Path $stampFile) { (Get-Content $stampFile -Raw).Trim() } else { '' }
  if ($prev -ne $tgzHash -or -not (Test-Path $exe)) {
    if (Test-Path $src) {
      # keep target/ so a rebuild reuses the dependency artifacts; replace the source
      Get-ChildItem $src -Exclude target | Remove-Item -Recurse -Force
    } else { New-Item -ItemType Directory -Force $src | Out-Null }
    Push-Location $src; & tar -xzf $tgz; Pop-Location
    $buildStart = Get-Date
    Push-Location $src
    $env:CARGO_INCREMENTAL = '0'
    # crates/parfast/build.rs stamps `-VV` from NZBFAST_BUILD_COMMIT when the
    # tree is an export with no .git; without it the binary reads `built from
    # unknown` (the 14 Sep round's did). Write the commit beside the tarball:
    #     git rev-parse HEAD > src.commit
    $commitFile = Join-Path $Ntw 'src.commit'
    if (Test-Path $commitFile) { $env:NZBFAST_BUILD_COMMIT = (Get-Content $commitFile -Raw).Trim() }
    $ErrorActionPreference = 'Continue'
    & cargo build --release -p parfast --locked 2>&1 | Select-Object -Last 4 | ForEach-Object { "BUILD $_" }
    $ErrorActionPreference = 'Stop'
    Pop-Location
    if (-not (Test-Path $exe)) { throw "parfast.exe was not produced" }
    if ((Get-Item $exe).LastWriteTime -lt $buildStart) { throw "parfast.exe predates the build start - a stale build is a failed round" }
    Set-Content $stampFile $tgzHash
    "BUILD-SECS $([math]::Round(((Get-Date) - $buildStart).TotalSeconds))"
  }
  $ver = (& $exe -VV 2>&1 | Select-Object -First 2) -join ' / '
  "BIN parfast.exe sha256=$((Get-FileHash $exe -Algorithm SHA256).Hash.Substring(0,16)) $ver"

  $members = @('f0.bin') + (1..8 | ForEach-Object { "p$_.bin" })
  $synRe = 'ntt syndromes \(m=(\d+), needed=(\d+), n=(\d+), W=(\d+), threads=(\d+)\): ([0-9.]+)([^0-9.\s]+)'
  $ffsRe = 'feed\+fold\+solve: \+([0-9.]+)([^0-9.\s]+)'

  foreach ($planLine in (Get-Content (Join-Path $Ntw 'plan.txt'))) {
    if ($planLine -match '^\s*(#|$)') { continue }
    $f = $planLine.Trim() -split '\s+'
    $label = $f[0]; $B = [int]$f[1]; $reps = [int]$f[2]
    $out = Join-Path $Ntw "legs-$label.jsonl"
    $legdir = Join-Path $Ntw "legs-$label"
    New-Item -ItemType Directory -Force $legdir | Out-Null
    # Arms in plan order: force, fold, then each variant. Mirrored per rep below.
    $armspecs = [ordered]@{}
    $armspecs['force'] = @{ NZBFAST_NTT = 'force' }
    $armspecs['fold'] = @{ NZBFAST_NTT = '0' }
    if ($f.Count -gt 4) {
      foreach ($spec in $f[4..($f.Count - 1)]) {
        if ($spec -notmatch '^[A-Za-z0-9]+:NZBFAST_[A-Z0-9_]+=[^,=]+(,NZBFAST_[A-Z0-9_]+=[^,=]+)*$') { throw "PLAN-FAIL bad variant '$spec' in series $label" }
        $vname = ($spec -split ':', 2)[0]
        $venv = @{ NZBFAST_NTT = 'force' }
        foreach ($kv in (($spec -split ':', 2)[1] -split ',')) {
          $pair = $kv -split '=', 2
          if ($pair[0] -eq 'NZBFAST_NTT') { throw "PLAN-FAIL variant '$spec' sets NZBFAST_NTT; a variant is always forced" }
          $venv[$pair[0]] = $pair[1]
        }
        if ($armspecs.Contains("force-$vname")) { throw "PLAN-FAIL duplicate variant name $vname in series $label" }
        $armspecs["force-$vname"] = $venv
      }
    }
    $armnames = @($armspecs.Keys)
    $armnamesRev = @($armspecs.Keys)
    [array]::Reverse($armnamesRev)
    "ARMS label=$label " + (($armnames | ForEach-Object { $a = $_; $a + '{' + ((@($armspecs[$a].Keys) | Sort-Object | ForEach-Object { $_ + '=' + $armspecs[$a][$_] }) -join ',') + '}' }) -join ' ')
    foreach ($series in ($f[3] -split ';')) {
      $mm = [int]($series -split ':')[0]
      foreach ($npres in (($series -split ':')[1] -split ',' | ForEach-Object { [int]$_ })) {
        # --- corpus ---------------------------------------------------------
        $rootc = Join-Path $Fix "c-$label-m$mm-P$npres"
        if (Test-Path $rootc) { Remove-Item -Recurse -Force $rootc }
        New-Item -ItemType Directory -Force $rootc | Out-Null
        $rnd = [System.Random]::new($mm * 100003 + $npres)
        $buf = New-Object byte[] $B
        $counts = @{ 'f0.bin' = $mm }
        foreach ($i in 1..8) { $counts["p$i.bin"] = [int]($npres / 8) }
        foreach ($nm in $members) {
          $fs = [IO.File]::Create((Join-Path $rootc $nm))
          for ($k = 0; $k -lt $counts[$nm]; $k++) { $rnd.NextBytes($buf); $fs.Write($buf, 0, $B) }
          $fs.Close()
        }
        $rec = $mm + [int][math]::Floor($mm / 10)
        $t0 = Get-Date
        Push-Location $rootc
        $ErrorActionPreference = 'Continue'
        & $exe c -q -q "-s$B" "-c$rec" set.par2 @members 2>&1 | Out-Null
        $crc = $LASTEXITCODE
        $ErrorActionPreference = 'Stop'
        Pop-Location
        if ($crc -ne 0) { throw "create failed rc=$crc at m=$mm P=$npres" }
        $gold = @{}
        foreach ($nm in $members) { $gold[$nm] = (Get-FileHash (Join-Path $rootc $nm) -Algorithm SHA256).Hash }
        $keep = @{}
        foreach ($x in Get-ChildItem $rootc) { $keep[$x.Name] = 1 }
        "CORPUS label=$label m=$mm present=$npres block=$B recovery=$rec create_s=$([math]::Round(((Get-Date)-$t0).TotalSeconds,2)) files=$($keep.Count)"

        for ($rep = 1; $rep -le $reps; $rep++) {
          $order = if ($rep % 2) { @($armnames) } else { @($armnamesRev) }
          if ($rep -eq 1) { $order += 'auto' }
          foreach ($arm in $order) {
            foreach ($x in Get-ChildItem $rootc) { if (-not $keep.ContainsKey($x.Name)) { Remove-Item -Force $x.FullName } }
            $z = New-Object byte[] $B
            $fs = [IO.File]::Open((Join-Path $rootc 'f0.bin'), 'Open', 'Write')
            for ($k = 0; $k -lt $mm; $k++) { $fs.Write($z, 0, $B) }
            $fs.Close()
            if ((Get-FileHash (Join-Path $rootc 'f0.bin') -Algorithm SHA256).Hash -eq $gold['f0.bin']) { throw "damage did not take at m=$mm P=$npres" }
            $envx = @{ NZBFAST_REPAIR_TIMING = '1'; NZBFAST_NO_ENRICH = '1' }
            $armenv = @{}
            if ($armspecs.Contains($arm)) { $armenv = $armspecs[$arm] }
            foreach ($k in $armenv.Keys) { $envx[$k] = $armenv[$k] }
            $isforce = ($armenv['NZBFAST_NTT'] -eq 'force')
            $pinT = $armenv['NZBFAST_NTT_THREADS']
            $pinW = $armenv['NZBFAST_NTT_W']
            $tag = "$label-m$mm-P$npres-r$rep-$arm"
            $lb = Join-Path $legdir $tag
            $l0 = (Get-CimInstance Win32_Processor).LoadPercentage
            $r = Invoke-Leg $exe 'r -q set.par2' $rootc $lb $envx
            $l1 = (Get-CimInstance Win32_Processor).LoadPercentage
            $e = [IO.File]::ReadAllText("$lb.err")
            $ok = ($r.rc -eq 0)
            foreach ($nm in $members) { if ((Get-FileHash (Join-Path $rootc $nm) -Algorithm SHA256).Hash -ne $gold[$nm]) { $ok = $false } }
            if (-not $ok) { throw "GATE-FAIL $tag rc=$($r.rc)" }
            $sm = [regex]::Match($e, $synRe)
            $path = if ($sm.Success) { 'ntt' } else { 'fold' }
            if ($isforce -and (-not $sm.Success -or [int]$sm.Groups[1].Value -ne $mm)) { throw "PATH-FAIL $tag force leg did not transform m=$mm" }
            if ($arm -eq 'fold' -and $sm.Success) { throw "PATH-FAIL $tag fold leg printed ntt syndromes" }
            if ($pinT -and [int]$sm.Groups[5].Value -ne [int]$pinT) { throw "PIN-FAIL $tag NZBFAST_NTT_THREADS=$pinT but the transform ran threads=$($sm.Groups[5].Value)" }
            if ($pinW -and [int]$sm.Groups[4].Value -ne [int]$pinW) { throw "PIN-FAIL $tag NZBFAST_NTT_W=$pinW but the transform ran W=$($sm.Groups[4].Value)" }
            $fm = [regex]::Match($e, $ffsRe)
            $rig = Get-RigStamp
            $o = [ordered]@{
              label = $label; block = $B; m = $mm; present = $npres; rep = $rep; arm = $arm
              threads = if ($pinT) { [int]$pinT } else { 'default' }
              stripe_w = if ($pinW) { [int]$pinW } else { 'default' }
              env = ((@($armenv.Keys) | Sort-Object | ForEach-Object { $_ + '=' + $armenv[$_] }) -join ',')
              rig = $rig
              rc = $r.rc; ok = $ok; path = $path; wall = $r.wall; cpu = $r.cpu; peak_mb = $r.peakmb
              load_before = $l0; load_after = $l1; foreign_before = $r.foreign; foreign_after = $r.foreignAfter
              ffs_s = if ($fm.Success) { [math]::Round((AsSec $fm.Groups[1].Value $fm.Groups[2].Value), 4) } else { $null }
              syn_s = if ($sm.Success) { [math]::Round((AsSec $sm.Groups[6].Value $sm.Groups[7].Value), 4) } else { $null }
              ntt_n = if ($sm.Success) { [int]$sm.Groups[3].Value } else { $null }
              ntt_W = if ($sm.Success) { [int]$sm.Groups[4].Value } else { $null }
              ntt_threads = if ($sm.Success) { [int]$sm.Groups[5].Value } else { $null }
            }
            Add-Content -Encoding ASCII $out ((New-Object psobject -Property $o) | ConvertTo-Json -Compress)
            "LEG $tag rc=$($r.rc) sha=OK path=$path wall=$($r.wall) cpu=$($r.cpu) ffs=$($o.ffs_s) syn=$($o.syn_s) W=$($o.ntt_W) T=$($o.ntt_threads) load=$l0/$l1 foreign=$($r.foreign)/$($r.foreignAfter) rig=$rig"
          }
        }
        Remove-Item -Recurse -Force $rootc
      }
      Coord 'CLAIM' "EXTENSION - still running: finished $label m=$mm"
    }
  }
  $done = 'finished'
  "ALL DONE $(Stamp)"
} catch {
  "ROUND-ERROR $($_.Exception.Message)"
} finally {
  Coord 'DONE' "$done; rig lock released"
  Release-RigLock (Join-Path $Ntw 'nttwork.lock')
}
