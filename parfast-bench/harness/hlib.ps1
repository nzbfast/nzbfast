# hlib.ps1 - the round-start harness stamp for PowerShell round drivers that
# do NOT dot-source plib.ps1. Dot-source it (`. "$harness\hlib.ps1"`).
#
# WHY IT IS NOT JUST `plib.ps1`. plib is 2,800 lines and is not side-effect
# free to load: it sets `$ErrorActionPreference = 'Stop'` for the whole script
# and `Add-Type`s a psapi.dll P/Invoke at load time. Dot-sourcing it into a
# driver that never expected either would change how that driver handles every
# error it already survives - which is a behaviour change, where the whole
# second census is one round-start banner line per driver and nothing else
# (an internal note). Seven PowerShell round
# drivers outside `harness/` are in that position, so they get this
# file: same two line formats, no preferences touched, nothing typed, nothing
# else defined.
#
# A DRIVER THAT ALREADY DOT-SOURCES plib MUST NOT USE THIS. Use plib's own
# `Write-HarnessFacts` (or `Get-HarnessLines` if the driver tees its log
# through its own helper): only those REGISTER the set, so that plib's
# `Get-RigStamp` re-reads exactly the files the HARNESS lines named when it
# stamps each LEG line. This file has no registry to offer and the two would
# disagree.
#
# IT RETURNS LINES AND EMITS NOTHING ELSE, and NEVER throws. PowerShell does
# not distinguish logging from returning, so a stray unassigned statement here
# would be returned as an extra "line" and written into the round log as one;
# and a stamp must never be able to end a round - plib's `Get-RigStamp` header
# names the seven-tool field round that rule was learned on. An unreadable or
# missing file is stamped `unreadable` rather than left off, for
# `pdrv.rig_stamp`'s reason: an absent token is indistinguishable from a
# harness older than this block, which never had one.
#
# USE. Pass every file the round sources, starting with the driver itself,
# and put the lines through whatever already reaches the banked log:
#
#     foreach ($l in (Get-HarnessLinesStandalone @($PSCommandPath))) { Say $l }

function Get-HarnessLinesStandalone([string[]]$paths) {
  # NAMED DIFFERENTLY FROM plib's `Get-HarnessLines` ON PURPOSE. If a driver
  # ever dot-sources both, one name would silently win and the registering
  # copy is the one that must - a same-named override would take `Get-RigStamp`
  # off the set the HARNESS lines named without anything saying so.
  $uniq = @()
  $seen = @{}
  foreach ($p in $paths) {
    if (-not $p) { continue }
    $full = $p
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $full = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { $full = $p }
    $ErrorActionPreference = $prevEap
    if (-not $seen.ContainsKey($full)) { $seen[$full] = $true; $uniq += $full }
  }
  # ONE sort key, built as a string, so the order cannot depend on how this
  # PowerShell version handles a multi-scriptblock Sort-Object. Same key as
  # plib.ps1 and pdrv.py, so the same round composes the same token whichever
  # of the three wrote it.
  $files = @($uniq | Sort-Object { [IO.Path]::GetFileName($_) + '|' + $_ })
  $out = @()
  $parts = @()
  foreach ($p in $files) {
    $nm = [IO.Path]::GetFileName($p)
    $sha = $null
    $len = $null
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      $sha = (Get-FileHash -LiteralPath $p -Algorithm SHA256 -ErrorAction Stop).Hash.ToLower()
      $len = (Get-Item -LiteralPath $p -ErrorAction Stop).Length
    } catch { $sha = $null }
    $ErrorActionPreference = $prevEap
    if ($sha) {
      $out += "HARNESS $nm sha256=$sha bytes=$len"
      $parts += "${nm}:$($sha.Substring(0, 16))"
    } else {
      $out += "HARNESS $nm sha256=unreadable bytes=0"
      $parts += "${nm}:unreadable"
    }
  }
  if ($parts.Count -gt 0) { $out += "HARNESS-RIG $($parts -join '+')" }
  else { $out += 'HARNESS-RIG unknown' }
  return $out
}
