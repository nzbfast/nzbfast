# foreign-claim-selftest.ps1 - prove zrider-round.ps1's Test-ForeignClaim guard
# classifies the fleet's marker vocabulary correctly, on a synthetic coordination
# file, with no box and no network.
#
# WHY IT EXISTS AS A FILE rather than as a claim in a write-up. The guard is a
# SAFETY device: it decides whether this lane takes a contended box. Its first
# cut INVENTED its keyword rosters and got `TAKEOVER` BACKWARDS - it had that
# word as a CLOSE, where the fleet has it in OPEN_KW, because a hand-over OPENS
# a claim for whoever takes it. Classifying an open word as a close reads a HELD
# box as free and takes it out from under somebody, which is the failure memory
# topic `nzbfast-free-box-test-fails-three-ways` is entirely about. It was caught
# by reading `.claude/tools/parfast-rigs-parse.py`'s OPEN_KW / CLOSE_KW instead
# of trusting a commit message, and this file is what stops the next edit
# reintroducing it.
#
# It EXTRACTS the function from zrider-round.ps1 rather than carrying a copy, so
# a second copy cannot drift from the one that actually runs.
#
#   pwsh -NoProfile -File foreign-claim-selftest.ps1
$ErrorActionPreference = 'Stop'
$here = $PSScriptRoot
$src  = Get-Content (Join-Path $here 'zrider-round.ps1') -Raw
$i    = $src.IndexOf('function Test-ForeignClaim')
if ($i -lt 0) { throw 'SELFTEST-REFUSED: Test-ForeignClaim not found in zrider-round.ps1 - failing to find is failing' }
$j    = $src.IndexOf("`n}`n", $i)
if ($j -lt 0) { throw 'SELFTEST-REFUSED: could not find the end of Test-ForeignClaim' }
$body = $src.Substring($i, $j - $i + 3)

$ME = 'coreultra9-4mib-riders-sitting-18sep'
$base = @(
  "CLAIM 2026-09-18T10:00:00Z holder-lane gen=aaaa - TAKING THE BOX",
  "QUEUED 2026-09-18T10:05:00Z $ME gen=09e5f607 - queued behind them"
)

# name, extra lines, expected result
$cases = @(
  @{ n = 'a live CLAIM by another lane is a HOLD';            add = @();                                                                    want = 'holder-lane' },
  @{ n = 'DONE closes it';                                    add = @('DONE 2026-09-18T11:00:00Z holder-lane - finished');                  want = '' },
  @{ n = 'RELEASED closes it';                                add = @('RELEASED 2026-09-18T11:00:00Z holder-lane - released');              want = '' },
  @{ n = 'ABORTED closes it';                                 add = @('ABORTED 2026-09-18T11:00:00Z holder-lane - died');                   want = '' },
  @{ n = 'STAND-DOWN closes it';                              add = @('STAND-DOWN 2026-09-18T11:00:00Z holder-lane - standing down');       want = '' },
  @{ n = 'WITHDRAWN closes it';                               add = @('WITHDRAWN 2026-09-18T11:00:00Z holder-lane - withdrawn');            want = '' },
  # THE FOUR THAT MUST NOT CLOSE. Each is a word that reads like a close and is
  # not one; every one of them, misclassified, takes a held box.
  @{ n = 'TAKEOVER must NOT close (it is in OPEN_KW)';        add = @('TAKEOVER 2026-09-18T11:00:00Z holder-lane - handed over');           want = 'holder-lane' },
  @{ n = 'WITHDRAWING must NOT close (5383c1db1)';            add = @('WITHDRAWING 2026-09-18T11:00:00Z holder-lane - going');              want = 'holder-lane' },
  @{ n = 'a bare NOTE must NOT close';                        add = @('NOTE 2026-09-18T11:00:00Z holder-lane - just saying');               want = 'holder-lane' },
  @{ n = 'ABANDON is in NEITHER roster, so it must NOT close';add = @('ABANDON 2026-09-18T11:00:00Z holder-lane - abandoned');              want = 'holder-lane' },
  # QUEUED is an intention, never a hold - bench-suite item 0a5.
  @{ n = 'another lane QUEUED is NOT a hold';                 add = @('DONE 2026-09-18T11:00:00Z holder-lane - done',
                                                                      'QUEUED 2026-09-18T11:01:00Z other-lane - waiting');                  want = '' },
  # The late arrival this guard exists for.
  @{ n = 'a CLAIM arriving after the DONE IS a hold';         add = @('DONE 2026-09-18T11:00:00Z holder-lane - done',
                                                                      'CLAIM 2026-09-18T11:01:00Z late-lane - TAKING THE BOX');             want = 'late-lane' },
  @{ n = 'my own CLAIM is never foreign';                     add = @('DONE 2026-09-18T11:00:00Z holder-lane - done',
                                                                      "CLAIM 2026-09-18T11:01:00Z $ME - TAKING THE BOX");                   want = '' },
  @{ n = 'leading whitespace does not hide a hold';           add = @('DONE 2026-09-18T11:00:00Z holder-lane - done',
                                                                      '   CLAIM 2026-09-18T11:01:00Z late-lane - TAKING THE BOX');          want = 'late-lane' },
  @{ n = 'two holders are both reported';                     add = @('CLAIM 2026-09-18T11:01:00Z late-lane - TAKING THE BOX');             want = 'holder-lane,late-lane' }
)

$tmp  = Join-Path ([IO.Path]::GetTempPath()) ("zrider-selftest-" + [guid]::NewGuid().ToString('N') + ".txt")
$fail = 0
foreach ($c in $cases) {
  [IO.File]::WriteAllLines($tmp, [string[]]($base + $c.add))
  $Coord = $tmp
  $got = & ([scriptblock]::Create($body + "`nTest-ForeignClaim '$ME'"))
  $got = [string]$got
  if ($got -ne $c.want) {
    "FAIL  $($c.n): want [$($c.want)] got [$got]"
    $fail++
  } else {
    "ok    $($c.n)"
  }
}
Remove-Item $tmp -Force -ErrorAction SilentlyContinue
if ($fail -gt 0) { "SELFTEST FAILED: $fail of $($cases.Count)"; exit 1 }
"selftest OK - $($cases.Count) cases, extracted from zrider-round.ps1 itself"
