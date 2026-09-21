# plib.ps1 - shared harness for the parfast publication rounds, intel-i5-10600kf.
#
# Every defect this library exists to prevent is recorded in
# an internal note:
#  - a refused tool must never read as a fast success  -> rc AND stderr kept per leg
#  - Start-Process -PassThru returned wall=0           -> ProcessStartInfo, streams
#                                                         drained before WaitForExit
#  - PowerShell variables are CASE-INSENSITIVE         -> every name here is distinct
#                                                         in lowercase
#  - PowerShell does not glob for native commands      -> member names are passed
#                                                         explicitly, never *.bin
#  - concurrency corrupted three rounds in one day     -> an exclusive rig LOCK,
#                                                         counted as a lock and not
#                                                         as a process
#  - numbered backups reached 157 GB                   -> stray files are removed
#                                                         after every leg
$ErrorActionPreference = 'Stop'

# DOT-SOURCING THIS FILE TWICE IN ONE PROCESS MUST BE HARMLESS, and until
# 16 Sep 2026 it was not. `Add-Type` throws "the type name 'PMem' already
# exists" on the second pass, and `$script:lockfs = $null` below silently
# DROPPED a rig lock this process was still holding - so a script that took
# the lock and then dot-sourced plib (catwin.ps1 does exactly that, because
# plib comes out of the tarball it extracts under the lock) had to hand-roll
# its own take and its own handle to stay correct. That hand-rolled copy is
# how `catwin.ps1` came to test the lock file's mere EXISTENCE, which is the
# defect an internal note is about.
# Both hazards are guarded here rather than worked around at each call site.
if (-not ('PMem' -as [type])) {
Add-Type @"
using System;
using System.Runtime.InteropServices;
public static class PMem {
  [StructLayout(LayoutKind.Sequential)]
  public struct PMC {
    public uint cb; public uint PageFaultCount;
    public IntPtr PeakWorkingSetSize; public IntPtr WorkingSetSize;
    public IntPtr QuotaPeakPagedPoolUsage; public IntPtr QuotaPagedPoolUsage;
    public IntPtr QuotaPeakNonPagedPoolUsage; public IntPtr QuotaNonPagedPoolUsage;
    public IntPtr PagefileUsage; public IntPtr PeakPagefileUsage;
  }
  [DllImport("psapi.dll", SetLastError=true)]
  static extern bool GetProcessMemoryInfo(IntPtr h, out PMC c, uint sz);
  public static long PeakWS(IntPtr h) {
    PMC c = new PMC();
    c.cb = (uint)Marshal.SizeOf(typeof(PMC));
    if (GetProcessMemoryInfo(h, out c, c.cb)) return (long)c.PeakWorkingSetSize;
    return -1;
  }
}
"@
}

# GUARDED, not assigned: see the note above. A second dot-source must not
# forget a handle the first one is still holding.
if (-not (Test-Path 'variable:script:lockfs')) { $script:lockfs = $null }

# ---------------------------------------------------------------------------
# THE ROUND LOG SINK
# ---------------------------------------------------------------------------
# EVERY STATUS LINE IN THIS LIBRARY WENT TO STDOUT AND NOWHERE ELSE until
# 16 Sep 2026, and for one whole family of drivers that is the same as not
# logging it at all. A bare PowerShell string statement is implicit
# `Write-Output`: it reaches the output stream and no file. Two families of
# driver consume that, and only one of them is safe:
#
#  - harness/wcomb.ps1 and its siblings write EVERY line of the round
#    to stdout and are redirected to a file by their launcher, so plib's lines
#    are in the banked log already (rounds/settle-e2e-2026-09-16/ is
#    one - the FIXTURE-SETTLE lines are right there in it).
#  - the round drivers that define their own `Log` - dcsmall.ps1, dcladder.ps1,
#    dcenrol.ps1 - append to `work\logs\<tag>.log` and it is THAT file which
#    is banked into rounds/ and read afterwards. plib's lines never
#    entered it.
#
# So the guard's verdict was in neither the banked artefact nor anything a
# later reader saw, and it is not hypothetical: the round for claim
# digest-cache-enrol-threads-gate-16sep hit Wait-FixtureSettle's cap TWICE on
# 16 Sep 2026 (`ok=0 GAVE-UP foreign_cpu=10.9 ... waited_s=1206`), on BOTH
# boxes, and both verdicts were recovered only because that round happened to
# be driven over ssh with stdout redirected to a scratch file. A round started
# as a scheduled task loses them and its numbers read as clean
# (an internal note section 5, last bullet).
# Wait-FixtureSettle's own header already CLAIMED it logged whether it waited -
# the same silent-guard class it was written to prevent, one step further out:
# the guard was not silent, the place a reader looks was.
#
# OPT-IN, AND INERT UNTIL SOMETHING OPTS IN. This library is dot-sourced by
# drivers this repo holds no copy of - intel-i5-10600kf carries TWO rig roots with
# their own plib.ps1 (`tools/bench-deploy-check.py intel-i5-10600kf` probes both) - so
# a driver that never calls `Set-PlibLog` and a box with no `PLIB_LOG` set must
# behave exactly as before, which is what `Get-PlibLog` returning $null buys.
#
# TWO WAYS IN, deliberately. `Set-PlibLog <path>` is for a driver that has its
# own log (one line, next to its own `Log` definition). `$env:PLIB_LOG` is for
# the case that lost the two verdicts above - a round somebody else starts,
# from a scheduled task or a launcher, where no driver edit is available at
# all. Set-PlibLog wins when both are set, and the variable is re-read on every
# line rather than cached, so a launcher can set it around one round.
#
# STDOUT IS UNCHANGED, BYTE FOR BYTE, and that is the constraint the whole
# shape is built around: rounds and reducers parse these lines, and several of
# these functions are documented as MUST-NOT-RETURN-ANYTHING-EXTRA because
# PowerShell makes no distinction between logging and returning (see
# Require-QuietBox's note, and Get-RigStamp's). `Write-PlibLine` emits the
# string exactly as the bare statement did - a nested function's output flows
# into the caller's stream unchanged - and everything else it does is an
# assignment or a swallowed append, so nothing is reordered, reformatted,
# duplicated or dropped.
#
# AND AN APPEND MUST NEVER THROW INTO A ROUND. `$ErrorActionPreference = 'Stop'`
# at the top of this file makes a locked file or a missing directory a
# TERMINATING error, and a guard that kills a round because it could not log is
# strictly worse than the defect. Same rule, same shape and the same reason as
# Write-BinFacts' `-VV` probe, which learned it by killing the seven-tool field
# round two seconds in.
if (-not (Test-Path 'variable:script:pliblog')) { $script:pliblog = $null }

# SILENT, and that is load-bearing rather than tidy: a confirmation line here
# would be a line in the caller's output stream at a point no existing log
# format expects one. Pass '' or $null to turn the sink back off.
function Set-PlibLog([string]$path) {
  if ($path) { $script:pliblog = $path } else { $script:pliblog = $null }
}

# The effective sink, or $null. EMITS NOTHING - every statement is an
# assignment or a return, for the reason Get-RigStamp's header gives.
function Get-PlibLog {
  if ($script:pliblog) { return $script:pliblog }
  if ($env:PLIB_LOG) { return $env:PLIB_LOG }
  return $null
}

# The one place a plib status line goes. stdout exactly as before, plus the
# sink when there is one.
function Write-PlibLine([string]$line) {
  $line
  $sink = Get-PlibLog
  if (-not $sink) { return }
  $prevEap = $ErrorActionPreference
  $ErrorActionPreference = 'Continue'
  try { Add-Content -LiteralPath $sink -Value $line -ErrorAction Stop } catch { }
  $ErrorActionPreference = $prevEap
}

# THE LOCK IS PER BOX, NOT PER ROUND, and that is the whole point. Until
# 10 Sep 2026 each script locked its OWN file - lad.lock, vfy.lock,
# full.lock - so the lock excluded a second copy of the SAME round and did
# nothing at all about a DIFFERENT one. Measured that day on intel-i5-10600kf:
# lad.ps1, vfy.ps1 and full.ps1 all live at once with two rival tools
# running, which silently contaminated an entire ladder (parfast read 36.5 s
# at m=64 and 29.7 s at m=1,280 - not a curve, a disturbed box).
#
# So every round on a box now contends for ONE file in the rig root, and the
# round's own name is written inside it, which is also what makes the holder
# identifiable to a human.
#
# ABSOLUTE, in the user profile. The first fix derived the lock from the
# LOG's directory, which is per-DIRECTORY and not per-box: on 10 Sep 2026 a
# lane running out of one directory and a publication round running out of
# another took two different "per-box" locks and measured each other for ten
# minutes at load 161. Only a fixed path outside the round's own tree is
# actually one per machine.
function Get-RigLockPath { Join-Path $env:USERPROFILE '.parfast-rig.lock' }

# THE ONE PLACE THE HOLD RULE LIVES. Every question any script asks about this
# lock - may I take it, is it busy, may I remove it - is answered from here, so
# the takers cannot disagree with the waiters about what a hold IS. They did
# disagree, and on 16 Sep 2026 it cost apple-m3-ultra eight hours in the unix
# spelling and very nearly cost a live round its box in this one
# (an internal note). The unix half of
# this same rule is harness/riglock_state.py; read its module
# docstring, which is the design for both.
#
# LIVENESS COMES FROM THE HOLDER, NEVER FROM THE CLOCK, and there is no age
# bound here for the same reason there is none in riglock_state.py: a
# legitimate round holds this box for hours, so any age short enough to clear
# an orphan is short enough to steal a live round's box - the failure
# bench-suite item 0e exists to prevent, and strictly worse than the one being
# fixed. A lock naming a pid that is alive on this box is HELD at any age; a
# lock that parses to no pid is an orphan at any age. DO NOT ADD AN AGE BOUND
# AND DO NOT ADD A -Force.
#
# Returns: Path, Exists, Text, Pid, Alive, Held, Why.
function Get-RigLockHolder {
  $lockpath = Get-RigLockPath
  $r = [ordered]@{ Path = $lockpath; Exists = $false; Text = ''; Pid = 0; Alive = $false; Held = $false; Why = 'absent' }
  if (-not (Test-Path $lockpath)) { return [pscustomobject]$r }
  $r.Exists = $true
  # AN UNREADABLE LOCK IS A HELD LOCK. This is now a BACKSTOP rather than the
  # common case, and the change is the point: Take-RigLock opened the file
  # [IO.FileShare]::None until 16 Sep 2026, so while a round was running nobody
  # could even READ the lock - a human asking who holds this box got
  # "the process cannot access the file" and an ORPHAN, having no open handle,
  # was the only kind of lock that would answer. Backwards from what a human
  # needs, and exactly backwards at the moment it matters, which is somebody
  # deciding whether to clear somebody else's lock. wlaunch.ps1 met the same
  # wall on 11 Sep 2026 from the other side: it read the file under
  # $ErrorActionPreference = 'Stop' with no catch and died with a raw .NET
  # "cannot access the file" on every box that had a round in flight.
  #
  # FileShare::Read fixes that and costs neither load-bearing property.
  # Measured cross-process on intel-i5-10600kf, 16 Sep 2026 (PowerShell 5.1.26100.9444,
  # scratch dir, holder and reader in separate processes): under ::None,
  # Get-Content REFUSED, Remove-Item refused, a rival CreateNew refused; under
  # ::Read, Get-Content returned the identity line while Remove-Item and the
  # rival CreateNew were STILL refused. FILE_SHARE_DELETE stays excluded, which
  # is the half Release-RigLock's NTFS argument below actually rests on - it
  # needs nobody to be able to DELETE our file, not nobody to be able to read
  # it. Record: an internal note, section
  # "On Windows a HELD lock cannot be read at all".
  #
  # The arm stays because it is still TRUE and still free: an exclusive handle
  # dies with the process that holds it, so a lock we cannot read for any
  # reason is held by something alive, and a lock left by a hard-killed round
  # is always readable. It is the safety net under the pid parse, not the
  # primary path any more.
  # FileShare::ReadWrite ON THE READ, and it is not optional. `File.ReadAllText`
  # opens the file sharing READ only, and the holder's handle carries WRITE
  # access - so the reader's share mode does not permit what the holder already
  # has and the open is REFUSED, even though the holder shares Read. Measured
  # on amd-ryzen-9800x3d, 16 Sep 2026: `Get-Content` (which shares ReadWrite by default)
  # returned the identity line from a bystander process while `ReadAllText` on
  # the same file threw, so this function reported `held-exclusively
  # (unreadable)` and named no pid for a lock that was perfectly legible. That
  # is the "identifiable to a human" property failing in the one place a human
  # would be reading it from - and it would have made the FileShare::Read change
  # above a no-op for every caller inside the harness.
  try { $fs = [IO.File]::Open($lockpath, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::ReadWrite)
        try { $r.Text = (New-Object IO.StreamReader($fs)).ReadToEnd() } finally { $fs.Close() } }
  catch { $r.Held = $true; $r.Why = 'held-exclusively (unreadable, so its owner is alive)'; return [pscustomobject]$r }
  if ($r.Text -match 'pid=(\d+)') { $r.Pid = [int]$Matches[1] }
  if ($r.Pid -le 0) { $r.Why = 'orphan (names no pid)'; return [pscustomobject]$r }
  # [Diagnostics.Process]::GetProcessById rather than Get-Process, and
  # [ArgumentException] rather than the cmdlet's own exception type: a
  # `catch [T]` whose T cannot be resolved is itself an error at runtime, and
  # ArgumentException lives in the base library where it can always be
  # resolved. GetProcessById throws exactly that when no such process is
  # running, which is the one answer we act on. Any OTHER failure reads as
  # ALIVE, because being wrong that way costs a wait and being wrong the other
  # way costs somebody's round.
  #
  # Never `os.kill(pid, 0)` or its PowerShell equivalents for this: the POSIX
  # existence idiom has no Windows case in CPython and TERMINATES the process
  # it asks about, and asking a handle you opened for query rather than
  # SYNCHRONIZE to WaitForSingleObject returns WAIT_FAILED for every pid, which
  # read every live holder as dead until d048a0ca6 fixed it in
  # riglock_state.py. This primitive has neither defect.
  try { $null = [Diagnostics.Process]::GetProcessById($r.Pid); $r.Alive = $true }
  catch [ArgumentException] { $r.Alive = $false }
  catch { $r.Alive = $true }
  if ($r.Alive) { $r.Held = $true; $r.Why = "held by live pid=$($r.Pid)" }
  else { $r.Why = "orphan (pid=$($r.Pid) is gone)" }
  return [pscustomobject]$r
}

# THE READ-ONLY QUESTION, for a script that OBSERVES the box rather than
# taking it - wquiet.ps1, oramafter.ps1, and any waiter written after them.
# Calling Take-RigLock to find out whether the box is busy would TAKE it, and
# testing Test-Path would block the waiter on an orphan forever, which is
# exactly what both of those did before 16 Sep 2026.
function Test-RigLockHeld { (Get-RigLockHolder).Held }

# SAYING SO OUT LOUD, factored out because there are now TWO callers and a
# second copy of it would be a second convention. Item 3 of the handoff: two
# lanes cleared an orphan by hand on 16 Sep 2026 and neither left a trace, so
# the next lane re-derived the same judgement from scratch. A NOTE costs one
# line and makes the pattern visible.
#
# wlaunch.ps1 is the second caller. It clears orphans too - it is a launcher,
# so it clears and then starts a round that takes the lock properly - and until
# 16 Sep 2026 it announced NOTHING when it did, which is the silence this
# exists to end. Best effort in both directions: a round must never die because
# a coordination file was unwritable.
#
# AND UNTIL 17 Sep 2026 THE NOTE REACHED NOBODY ON ANY BOX IN THE FLEET. The
# file it posted into was resolved by `Get-ChildItem $env:USERPROFILE\bench-out
# -Filter 'COORDINATION-*.txt'`, taken when exactly one matched. `bench-out` is
# the UNIX fleet's convention (`~/bench-out/COORDINATION-<box>.txt`) and it is
# not where a Windows box here keeps the file. Measured 17 Sep 2026 on all four
# Windows boxes, with `$env:BOXGATE_COORD` unset on every one of them:
#
#   - intel-i5-10600kf: it found `bench-out\COORDINATION-intel-i5-10600kf.txt`, 86 KB, last
#     written 8 Sep - while the live file was `<rig>\COORDINATION-intel-i5-10600kf.txt`,
#     257 KB, written that morning, on another volume entirely.
#   - windows-gaming-pc-b, amd-ryzen-9800x3d and intel-core-ultra-9-386h: NOTHING AT ALL. None of the three has a
#     `bench-out` directory; each keeps its live file directly in
#     `%USERPROFILE%` (`COORDINATION-windows-gaming-pc-b.txt`, `COORDINATION-amd-ryzen-9800x3d.txt`,
#     and `COORDINATION-coreultra9.txt` - the last not even named after the box).
#
# So on three of the four it found ZERO candidates and posted nothing AND SAID
# NOTHING, and on the fourth it found exactly one and took it on the strength
# of being single - a file nine days dead, while the live one sat on another
# volume. A single match is not a current match, and a `-eq 1` with no `else`
# is a guard that reports its own blindness as success.
#
# TWO CHANGES, AND NEITHER IS A GUESS:
#
#   1. LOOK WHERE THE FILES ARE. The candidate directories are
#      `$env:USERPROFILE\bench-out` AND `$env:USERPROFILE`, which turns three
#      of those zeroes into three exact hits. The bench-out arm is KEPT rather
#      than replaced: it is the fleet convention, some boxes will grow one, and
#      nothing is bought by removing it.
#   2. RANK, DO NOT DEMAND UNIQUENESS. Newest `LastWriteTimeUtc` wins, ties
#      broken by path so two runs of the same round agree. On intel-i5-10600kf that
#      picks the 16 Sep profile copy over the 8 Sep bench-out one - still not
#      the live `<rig>` file, because NO derivation from a home directory can
#      reach another volume. That is what `$BOXGATE_COORD` is for, it still
#      wins outright, and that box now sets it (.claude/MACHINES.md).
#
# NO AGE BOUND - THE AGE IS REPORTED INSTEAD. An mtime is the only
# discriminator available here, so it RANKS; making it REFUSE past a threshold
# would be the clock deciding liveness, which is the mistake Get-RigLockHolder's
# header forbids for the lock itself. The chosen file's age goes in the status
# line, so a lane reading the round log sees `age_d=9` and knows to go looking,
# rather than having the library decide on its behalf and say nothing.
#
# AND IT IS NEVER SILENT NOW. Zero candidates, and an append that fails, each
# produce a line through `Write-PlibLine` naming what was searched. The ROUND
# LOG SINK essay at the head of this file is this same failure one level out:
# a guard whose ENTIRE PURPOSE is to leave a trace must not fail to leave one
# quietly. Best effort still survives in both directions - nothing below
# throws, and a missing, ambiguous or unwritable coordination file never ends
# a round.
#
# THE UNIX HALF HAS THE SAME SHAPE AND IS NOT FIXED HERE:
# `coordination_file()` in harness/riglock_state.py returns a single
# `~/bench-out` match or None, silently. It is correct for the Macs, whose
# files really are there, so it is a latent copy of this rather than a live
# defect - but the two are one rule and the next box that moves its file will
# find it.

# THE CANDIDATE LIST. RETURNS, AND EMITS NOTHING ELSE, for the reason
# Get-BoxHandover's header gives: PowerShell makes no distinction between
# logging and returning, so a status line added here would be handed to the
# caller as part of the answer. Newest first. An empty array when there is
# nothing, never $null, so a caller can index `.Count` without a null test.
#
# DELIBERATELY NOT A GENERAL COORDINATION-FILE FINDER, and it must not become
# one. `Get-BoxHandover` takes its path FROM THE CALLER on purpose: a WAITER
# that guesses wrong reads a stale file as a free box, which is what cost two
# lanes their box on 16 Sep 2026. Guessing is acceptable here and only here,
# because the worst case of a wrong guess is a NOTE in a quiet file while the
# alternative is no note at all. Do not repoint a reader at this.
function Get-OrphanNoteCoordDirs {
  $dirs = @()
  if ($env:USERPROFILE) {
    $dirs += (Join-Path $env:USERPROFILE 'bench-out')
    $dirs += $env:USERPROFILE
  }
  return $dirs
}

function Get-OrphanNoteCoordCandidates {
  $hits = @()
  foreach ($d in (Get-OrphanNoteCoordDirs)) {
    # -File so a DIRECTORY called COORDINATION-something.txt cannot be chosen;
    # SilentlyContinue because a missing bench-out is the NORMAL case on three
    # of the four boxes and $ErrorActionPreference is 'Stop' in this file.
    $hits += @(Get-ChildItem -LiteralPath $d -Filter 'COORDINATION-*.txt' -File -ErrorAction SilentlyContinue)
  }
  if ($hits.Count -eq 0) { return @() }
  return @($hits | Sort-Object -Property @{ Expression = 'LastWriteTimeUtc'; Descending = $true }, @{ Expression = 'FullName'; Descending = $false })
}

function Write-RigLockOrphanNote([string]$lockpath, [string]$what, [string]$action) {
  Write-PlibLine "RIG-LOCK-ORPHAN $lockpath $action, was: $($what.Trim())"
  $coord = $null
  $src = ''
  if ($env:BOXGATE_COORD) {
    $coord = $env:BOXGATE_COORD
    $src = 'src=BOXGATE_COORD'
  } else {
    $cands = @(Get-OrphanNoteCoordCandidates)
    if ($cands.Count -ge 1) {
      $coord = $cands[0].FullName
      $aged = [int](((Get-Date).ToUniversalTime() - $cands[0].LastWriteTimeUtc).TotalDays)
      $src = "src=newest-of-$($cands.Count) age_d=$aged"
    }
  }
  if (-not $coord) {
    Write-PlibLine "RIG-LOCK-ORPHAN-NOTE coord=NONE searched=[$((Get-OrphanNoteCoordDirs) -join '; ')] - this clearing is in the round log only. Set BOXGATE_COORD on this box."
    return
  }
  $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  $note = "NOTE $ts (rig lock, $env:COMPUTERNAME) ORPHAN cleared at $lockpath - was: $($what.Trim()). Liveness came from the holder (dead or unnamed pid), never from the file's age."
  $wrote = 1
  try { Add-Content -LiteralPath $coord -Value $note -ErrorAction Stop } catch { $wrote = 0 }
  Write-PlibLine "RIG-LOCK-ORPHAN-NOTE coord=$coord $src wrote=$wrote"
}

# ---------------------------------------------------------------------------
# THE HANDOVER MATCHER
# ---------------------------------------------------------------------------
# A LANE WAITING FOR THIS BOX MUST KEY ON THE CLAIM-ID FIELD, NOT ON A
# SUBSTRING, and every lane that hand-rolled the test got it wrong the same
# way. The house line format in a coordination file is
#
#     <VERB> <timestamp> <claim-id> <prose>
#
# so the natural-looking predicate is two independent conditions - the line
# starts with a closing keyword, AND the line mentions my blocker's id - which
# is `^(DONE|RELEASE).*<id>`. That is WRONG, and it is wrong in the direction that
# costs a shared box hours: a courteous lane names every id on its AHEAD-LIST
# inside its own closing prose, which is the habit these files run on, so any
# other lane's DONE that merely MENTIONS the id you are waiting on satisfies
# it. Measured on <rig>\COORDINATION-intel-i5-10600kf.txt on 16 Sep 2026, three lanes
# in one day:
#
#  - a waiter for nibble-crossover-quiet-box-confirm-16sep fired on its FIRST
#    poll while that lane was three hours into a live round, matching five
#    unrelated closing lines, the earliest of which had made it satisfiable
#    since 12:57:24Z;
#  - parfast-nibble-windowed-ask-1mib-16sep hit it TWICE and wrote it up on
#    that file at 14:38:52Z - parfast-cf-two-binary-control-16sep's DONE at
#    14:01:15Z listed the lanes it was handing the box to, so one lane's
#    courtesy cleared three lanes off that waiter's ahead-list;
#  - digest-cache-i5-width-ladder-16sep hit it at 15:35Z, on a RELEASE from a
#    different lane that merely mentioned the blocker.
#
# So the test is POSITIONAL: split on whitespace, field 0 must BE one of the
# CLOSING KEYWORDS, and field 2 must EQUAL the id. Not -match, not -like, not
# .Contains(). Equality on the third token is the whole fix, and it is the only
# spelling that also refuses the id that is a PREFIX of another lane's id -
# `-16sep` suffixes make near-misses the normal case here, not a corner.
#
# AND THE CLOSING VOCABULARY IS SIX WORDS, NOT TWO. `DONE` and `RELEASE` are
# the two this box's file happens to use (33 and 13 of its lines on 16 Sep
# 2026, against no instance of the other four), and a matcher built from the
# evidence in front of it inherits exactly the failure that left two waiters
# sitting through a free box for nine minutes: a close it does not recognise
# reads as no close at all. The fleet's roster is
# `.claude/tools/bench-accounts-parse.py`'s `CLOSE_KW` - 95 first tokens
# classified open / close / neither BY READING THEIR OWN LINES, baselined over
# 7,036 lines of the canonical files - and it carries `ABORTED` ("the round
# died; the line is free"), `RELEASED`, `STAND-DOWN` and `WITHDRAWN` as well.
# `tools/bench-box-gate.py` IMPORTS that roster rather than re-spelling it,
# which is the rule here too - but a round on a Windows box cannot run Python
# mid-leg, so this is the one place a SECOND copy is unavoidable. It is
# therefore a DECLARED copy, not a quiet one: `tools/rig-selftest-gate.py`
# holds the list below equal to `CLOSE_KW` on every push, so a
# reclassification there reddens rather than silently splitting the two
# readers. Never edit the list below to match a file you are looking at; edit
# the roster, and let the gate move this.
#
# The comparisons are PowerShell's default CASE-INSENSITIVE equality, and that
# is a choice rather than an oversight: a lane that posts `Done` still means
# done, and claim ids are lowercase kebab by convention, so case-insensitivity
# cannot manufacture a match that case-sensitivity would refuse - only an
# equality-vs-substring mistake can, which is the thing being fixed.
#
# AND THE SECOND HALF OF THE DEFECT IS THE REPORT, not the predicate. A matcher
# that prints only "HANDOVER" gives the operator no way to tell a true match
# from a misfire: the i5 lane's watcher fired CORRECTLY at 18:47Z on a real
# DONE and the lane still had to re-read the file by hand to find out whether
# to believe it. `Write-BoxHandoverNote` exists so the line that fired is in
# the round log next to the decision it caused.
#
# TWO FUNCTIONS, AND THE SPLIT IS THE POINT rather than a style choice. Read
# Require-QuietBox's note: PowerShell makes no distinction between logging and
# returning, so a function that calls `Write-PlibLine` AND returns a value
# hands its caller BOTH, as an array - which is how a guard's own wait line
# ended up inside a LEG line on 11 Sep 2026, displacing every field after it.
# This helper has exactly that shape, so it is split at the seam instead:
# `Get-BoxHandover` RETURNS and emits nothing else, `Write-BoxHandoverNote`
# LOGS and returns nothing. A waiter uses both, in two lines:
#
#     $hit = Get-BoxHandover $coord $blocker
#     if ($hit) { Write-BoxHandoverNote $blocker $hit; break }
#
# WHAT THIS DELIBERATELY DOES NOT DO, AND WHERE THE REST OF IT ALREADY LIVES.
# A lane that posts DONE and then re-CLAIMs is holding the box again, so the
# STRICT reading is "finished only when its own close comes after its own most
# recent open" - published on that file at 14:38:52Z, and BUILT: it is
# `fold()` in `tools/bench-box-gate.py`, the fleet's tested "may I take this
# box?" gate, which folds per lane to the latest open with no later close and
# adds the stale and phantom tiers on top. That file is the HOME of this rule
# and its header is the design for both halves, the way
# `harness/riglock_state.py` is for the rig lock. Read it before
# extending this.
#
# So this helper is the narrow Windows-side question - has this lane posted a
# close at all - for a round that cannot shell out to Python between legs. It
# returns the LAST such line, so a caller needing the strict reading has the
# timestamp in hand to compare against its own CLAIM. A driver that CAN run
# Python should call bench-box-gate.py instead of this. It is also not a file FINDER: the path comes from the
# caller, deliberately, because on intel-i5-10600kf the file under
# `$env:USERPROFILE` is the STALE copy and the live one is `<rig>\` - a
# documented fleet hazard (.claude/MACHINES.md, intel-i5-10600kf) that a helper must
# not paper over by guessing.
#
# A MISSING OR UNREADABLE FILE IS $null, NEVER A THROW, and the direction is
# chosen: $null reads as "no handover", so a waiter keeps waiting rather than
# taking a box it cannot see the state of. Empty is not absent, in this as in
# every other Windows read.
# THE CLOSING KEYWORDS, held equal to `CLOSE_KW` in
# `.claude/tools/bench-accounts-parse.py` by tools/rig-selftest-gate.py. Edit
# the roster, never this line: this copy exists only because a Windows round
# cannot import it mid-leg.
$script:handover_close = [string[]]@('ABORTED', 'DONE', 'RELEASE', 'RELEASED', 'STAND-DOWN', 'WITHDRAWN')

function Get-BoxHandover([string]$coordpath, [string]$id) {
  # EMITS NOTHING BUT ITS VERDICT. Every statement here is an assignment, a
  # control-flow keyword or the single return, for the reason above - a status
  # line added to this function would be returned to the caller as part of the
  # answer. If you want to say something, say it in Write-BoxHandoverNote.
  if (-not $coordpath) { return $null }
  if (-not $id) { return $null }
  $lines = $null
  try { $lines = @(Get-Content -LiteralPath $coordpath -ErrorAction Stop) } catch { return $null }
  $hit = $null
  foreach ($line in $lines) {
    # ONE GRAMMAR, TWO READERS. This used to test field 0 for a close keyword
    # and field 2 for the id by hand; it asks `Get-CoordMarkerEvent` now, which
    # is the same parse `Get-CoordFoldedState` uses and is where the shapes and
    # the 19 Sep 2026 measurement are written down. A continuation line of a
    # multi-line entry still falls out - its third token is prose - and so now
    # does a whole PROSE SENTENCE that opens with a close keyword, which is the
    # `DONE CONDITION: REL24_ALL_DONE` family this file's corpus carries.
    #
    # IT ALSO READS THE SECOND FIELD ORDER NOW, which is a widening and a fix:
    # a lane that posted `<ts> DONE <id>` - 49 such lines on the fleet, the
    # intel-i5-10600kf shape - was invisible here, so a waiter sat through a box that
    # had been handed back. The fold one function down has read both orders
    # since 18 Sep 2026 and this did not; they cannot disagree any more.
    $ev = Get-CoordMarkerEvent $line $script:handover_open
    if (-not $ev) { continue }
    if (-not $script:handover_close.Contains($ev.Keyword)) { continue }
    if ($ev.Subject -ne $id) { continue }
    $hit = $line
  }
  return $hit
}

# THE REPORT HALF, and the logging side of the seam. Its ONLY output is the
# status line itself, exactly as Write-RigLockOrphanNote's is - which is what
# makes it safe to call: there is no verdict mixed into that stream for a
# caller to lose. Never give this one a return value, and never move the note
# into Get-BoxHandover; the two together are the shape Require-QuietBox's note
# is about.
function Write-BoxHandoverNote([string]$id, [string]$line) {
  Write-PlibLine "BOX-HANDOVER waiting_on=$id at=$((Get-Date).ToUniversalTime().ToString('o')) matched: $($line.Trim())"
}

# ---------------------------------------------------------------------------
# THE LATE ARRIVAL: ANY OPEN CLAIM, NOT AN AHEAD-LIST FIXED AT ARM TIME
# ---------------------------------------------------------------------------
# A WAITER CANNOT QUEUE BEHIND A LANE THAT ARRIVES AFTER IT ARMED, and until
# 18 Sep 2026 every waiter on this fleet was built so that it could not even
# try. `Get-BoxHandover` above answers "has THIS id handed the box back", which
# is the right question for a list of ids you already have - and the list is
# taken once, at arm time, and never revisited. Two dated instances, both in
# an internal note section 1:
#
#   - intel-i5-10600kf, 18 Sep. A waiter armed at 19:06:50Z on 17 Sep with two ids.
#     A third lane took the box for ~90 s of ISCC at 00:57Z, posting a CLAIM
#     and a DONE around it exactly as the convention asks. The waiter read
#     FREE-1 at 00:56:57, FREE-2 at 00:57:57, and its driver took the rig lock
#     at 00:57:57.76 - INSIDE that claimed window. The CLAIM was posted three
#     seconds after FREE-1 and could not have been on an ahead-list decided
#     fourteen hours earlier.
#   - intel-core-ultra-9-386h, 18 Sep. `g4winrun2.ps1` attempt 1 read the coordination
#     file once during recon at 10:53Z, built for two minutes, and posted its
#     own CLAIM at 11:02Z - by which time another lane had claimed at 11:00:07Z
#     and took the lock seven seconds before ladder A asked for it. That round
#     ran zero legs and posted a completion NOTE over its own failure.
#
# Attempt 2 of that round fixed it BY HAND, in its own driver: re-read the file
# immediately before taking and again between every ladder, and stand down on a
# CLAIM that is not its own. It was right, and it was the fourth hand-rolled
# copy of a coordination-file matcher on this fleet - the class the open claim
# `plib-handover-matcher-helper-16sep` is about, where three lanes wrote the
# handover test and all three got it wrong the same way. So it is lifted here.
#
# THE OPEN VOCABULARY IS EIGHTEEN WORDS AND EVERY HAND-ROLLED COPY KNEW ONE.
# `g4winrun2.ps1` matched `^(DONE|CLAIM)\s`, cfwait.ps1 matched `CLAIM` alone.
# A lane that posts TAKEOVER, LATE-CLAIM, RELAUNCHED or HOLD is holding the box
# just as hard, and an open keyword this list does not carry reads as NOBODY
# THERE - the same polarity of blindness `$script:handover_close` exists to
# stop one keyword class over, and the worse one: a missed CLOSE costs a wait,
# a missed OPEN costs somebody's round. Held equal to `OPEN_KW` in
# `.claude/tools/bench-accounts-parse.py` by tools/rig-selftest-gate.py, on the
# same terms as the close list below it: edit the ROSTER, and let the gate move
# this line.
$script:handover_open = [string[]]@('ACTIVATING', 'CLAIM', 'CLAIM-EXTENSION', 'CONTINUATION', 'CROSS-CLAIM', 'DIALED', 'EXTEND', 'HOLD', 'INTERIM', 'LATE-CLAIM', 'LAUNCHED', 'LIVE', 'PAUSED', 'PROGRESS', 'RELAUNCH', 'RELAUNCHED', 'RESULT', 'START', 'TAKEOVER')

# Every id on this file whose most recent marker is an OPEN one, except our
# own. File order is time order, so "most recent" is simply the last line that
# named the id, which is the fold `tools/bench-box-gate.py` does in Python and
# the strict reading `Get-BoxHandover`'s header points at.
#
# RETURNS, AND EMITS NOTHING ELSE, for the reason Get-BoxHandover's header
# gives at length: PowerShell hands the caller every line a function emits, so
# a status line here would arrive as part of the answer. `Write-LateArrivalNote`
# is the logging half.
#
# AN UNREADABLE FILE IS NOT AN EMPTY ONE, and this is the one place in this
# library where that distinction changes the returned VALUE rather than only
# the log line. Everywhere else a failed read answers "no handover", which
# reads as KEEP WAITING and is safe. Here "no open claim" reads as TAKE THE
# BOX, so the same convention would turn an unreadable file into a green light.
# A path that was GIVEN and could not be read therefore comes back as the
# single pseudo-id `(unreadable:<path>)`: it can never equal a lane id, so it
# can never equal $selfid, every caller blocks on it, and the reason is in the
# text a stand-down NOTE quotes. An EMPTY $coordpath is the caller opting out
# and returns nothing - a box with no coordination file is not a box with a
# hidden claimant.
#
# EVERY RETURN IS COMMA-WRAPPED AND NO CALLER MAY WRAP IT IN `@()`. `,$open`
# hands back the ARRAY as one object, so `.Count` is right at zero, one and
# many and `$x[0]` is an id; an `@(...)` around the call re-wraps that one
# object and gives an array whose single element is the array, where `.Count`
# reads 1 for a file with four claimants on it. Assign it plainly:
# `$c = Get-OpenClaimants $coord $me`. Same arrangement, same reason, as
# `Get-OwnPidTree`'s `return ,$mine`.
#
# THE FOLD ITSELF IS `Get-CoordFoldedState`, BELOW, AND THIS DOES NOT CARRY A
# SECOND COPY OF IT. That function landed for the box queue on the same day as
# this one and the two were written as two loops over the same lines; the
# vocabulary is a parameter there now, so the box queue keeps its "only CLAIM
# is a hold" rule and this passes the roster's eighteen. Both field orders and
# the third-token subject rule live there too - read its header.
function Get-OpenClaimants([string]$coordpath, [string]$selfid) {
  if (-not $coordpath) { return ,@() }
  # THE READABILITY TEST IS HERE AND NOT IN THE FOLD, deliberately. The fold
  # answers "not a holder" for a file it cannot read, which is right for its
  # box-queue callers - their own preflight has already checked the file is
  # there, and a waiter must not read a transient read failure as a permanent
  # hold. It is exactly wrong here, where the same answer means TAKE THE BOX.
  try { $null = Get-Content -LiteralPath $coordpath -TotalCount 1 -ErrorAction Stop }
  catch { return ,@("(unreadable:$coordpath)") }
  $f = Get-CoordFoldedState $coordpath $script:handover_open
  $open = @()
  foreach ($subject in $f.Order) {
    if ($selfid -and $subject -eq $selfid) { continue }
    if ($f.State[$subject]) { $open += $subject }
  }
  return ,$open
}

# THE REPORT HALF, the same seam as Write-BoxHandoverNote's and for the same
# reason. A stand-down that prints only "STANDING DOWN" leaves the next reader
# re-deriving whose box it was from the file by hand; this names them.
function Write-LateArrivalNote([string]$where, [string[]]$claimants) {
  Write-PlibLine "BOX-LATE-ARRIVAL at=$where ts=$((Get-Date).ToUniversalTime().ToString('o')) open_claims=[$($claimants -join ' ')]"
}

# THE TAKE THAT DOES NOT EXIT. Take-RigLock below is this plus `exit 17`, and the
# split exists because exit 17 ends the PROCESS: a round that means to QUEUE
# for the box rather than give up (oram.ps1) cannot call the exiting form at
# all, and before this it hand-rolled its own CreateNew - correctly, but
# without the orphan arm, so an orphan livelocked it to its own deadline.
#
# A FAILED CreateNew IS NOT A HOLD, IT IS A FILE. The two are the same fact
# only while the holder's handle is open; a holder that dies without releasing
# leaves the directory entry behind and CreateNew then refuses every round on
# this box forever, naming nobody. So ask WHO, not HOW OLD.
function Try-TakeRigLock([string]$roundname) {
  # SUCCESS IS REPORTED IN $script:riglock_taken, NOT AS A RETURN VALUE, and
  # that is forced rather than stylistic: PowerShell returns EVERY line a
  # function emits, so a `return $true` sitting next to the RIG-LOCK-TAKEN line
  # this must print into the round's log would hand the caller a two-element
  # ARRAY - which is truthy either way, so a refusal would read as a take. That
  # is the same "PowerShell returns every emitted line" trap plib's other
  # counter helpers avoid by writing into $script: variables.
  $script:riglock_taken = $false
  $lockpath = Get-RigLockPath
  try { $script:lockfs = [IO.File]::Open($lockpath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read) }
  catch {
    $h = Get-RigLockHolder
    if ($h.Held) { Write-PlibLine "LOCK-BUSY $lockpath $($h.Why): $($h.Text)"; return }
    if (-not $h.Exists) {
      # It went away between our CreateNew and the read - a release, not an
      # orphan. Retry once; a second failure is a live taker racing us.
      try { $script:lockfs = [IO.File]::Open($lockpath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read) }
      catch { Write-PlibLine "LOCK-BUSY $lockpath - another round took it as it was released"; return }
      Write-RigLockIdentity $roundname $lockpath
      $script:riglock_taken = $true
      return
    }
    # Provably nobody's. Clear it, SAY SO on stdout and on the box's
    # coordination file, and retry exactly ONCE - a second collision is a live
    # taker racing us, which is a refusal and not an orphan.
    Write-RigLockOrphanNote $lockpath $h.Text "cleared by round=$roundname pid=$PID - $($h.Why)"
    Remove-Item $lockpath -Force -ErrorAction SilentlyContinue
    try { $script:lockfs = [IO.File]::Open($lockpath, [IO.FileMode]::CreateNew, [IO.FileAccess]::Write, [IO.FileShare]::Read) }
    catch {
      Write-PlibLine "LOCK-BUSY $lockpath - another round took it as we cleared an orphan"
      return
    }
  }
  Write-RigLockIdentity $roundname $lockpath
  $script:riglock_taken = $true
}

function Write-RigLockIdentity([string]$roundname, [string]$lockpath) {
  $txt = "round=$roundname pid=$PID started=$((Get-Date).ToUniversalTime().ToString('o'))"
  $bytes = [Text.Encoding]::ASCII.GetBytes($txt)
  $script:lockfs.Write($bytes, 0, $bytes.Length); $script:lockfs.Flush()
  Write-PlibLine "RIG-LOCK-TAKEN $lockpath $txt"
}

# THE ROUND LOG IS THE ONE PLACE A ROUND NAMES ITS OWN pid, and since 17 Sep
# 2026 it is read back. Write-RigLockIdentity above puts
# `RIG-LOCK-TAKEN <lock> round=<tag> pid=<n> started=<iso>` into the round's
# own stdout as its first line; this pair reads it out again, so a watcher
# armed on a pid that came from somewhere else (a process tree walk, an
# operator's memory) can CHECK it against what the round says about itself.
#
# WHY THIS IS HERE RATHER THAN IN ITS TWO CALLERS. wlaunch.ps1 resolves the
# round's pid before arming the deadline, and deadline.ps1 confirms that pid
# again for itself - two copies of one parse, of the line this file writes. It
# belongs beside the writer: a change to the RIG-LOCK-TAKEN format that misses
# a reader is the same silent blindness as a gate that stopped matching.
#
# THE SHARE MODE IS LOAD-BEARING. A round's log is held open by the cmd.exe
# redirect that launched it, so it is being WRITTEN while these read it.
# [IO.FileShare]::ReadWrite -bor ::Delete is what lets the read succeed against
# a live writer; a plain Get-Content can lose to a sharing violation, and under
# $ErrorActionPreference = 'Stop' - which every caller of this file inherits -
# that is a TERMINATING error in the caller rather than an empty answer. Same
# wall wlaunch.ps1 hit reading the rig lock on 11 Sep 2026, and the reason
# every path in here answers with an empty string instead of throwing.
function Read-SharedText([string]$path) {
  if (-not $path) { return '' }
  if (-not (Test-Path $path)) { return '' }
  $fs = $null
  try {
    $fs = [IO.File]::Open($path, [IO.FileMode]::Open, [IO.FileAccess]::Read,
                          ([IO.FileShare]::ReadWrite -bor [IO.FileShare]::Delete))
    $sr = New-Object IO.StreamReader($fs)
    try { return $sr.ReadToEnd() } finally { $sr.Dispose() }
  } catch {
    return ''
  } finally {
    if ($fs) { $fs.Dispose() }
  }
}

# What a round log says about itself. Returns: Pid (0 when the round has not
# taken the lock yet - which is NOT evidence of anything, only of "not yet"),
# Round (the tag the round named itself), Finished (the round printed a line
# that means it is over), Why.
#
# FINISHED IS EVIDENCE AND AN ABSENT PROCESS IS NOT. That distinction is the
# whole point of this function's second half: a watcher polling a pid it cannot
# vouch for sees "no such process" and knows nothing, where `ALL DONE` or
# `RIG-LOCK-RELEASED` in the round's own log is the round saying it finished.
function Get-RoundLogFacts([string]$path) {
  $r = [ordered]@{ Pid = 0; Round = ''; Finished = $false; Why = 'no round log path given' }
  if (-not $path) { return [pscustomobject]$r }
  $text = Read-SharedText $path
  if (-not $text) {
    $r.Why = "round log $path is empty or not readable yet"
    return [pscustomobject]$r
  }
  $r.Why = "round log $path has no RIG-LOCK-TAKEN line yet"
  $m = [regex]::Match($text, 'RIG-LOCK-TAKEN\b.*?\bround=(\S+)\s+pid=(\d+)')
  if ($m.Success) {
    $r.Round = $m.Groups[1].Value
    $r.Pid = [int]$m.Groups[2].Value
    $r.Why = "RIG-LOCK-TAKEN round=$($r.Round) pid=$($r.Pid)"
  }
  if ($text -match '(?m)^RIG-LOCK-RELEASED\b' -or $text -match '(?m)^ALL DONE\b') {
    $r.Finished = $true
  }
  return [pscustomobject]$r
}

# The caller names ITSELF; only the path is collapsed. Exits 17 when the box is
# held - so a caller that must SURVIVE a refusal wants Try-TakeRigLock above,
# not this.
#
# $round is the round's NAME. The nine callers that predate 16 Sep 2026 pass a
# per-round PATH instead (`<rig>\full.lock`, `$root\jcross.lock`) and keep
# working, because the basename of one is the other; both spellings are fine
# and neither is a lock file any more.
function Take-RigLock([string]$round) {
  $roundname = [IO.Path]::GetFileNameWithoutExtension($round)
  # THE ROUND NAME IS THE CALLER'S, AND A CALLER THAT PASSES THE BOX LOCK PATH
  # NAMES NOTHING. `[IO.Path]::GetFileNameWithoutExtension('.parfast-rig.lock')`
  # is `.parfast-rig`, so three callers (oramx.ps1, wcomb.ps1, lad2.ps1, all
  # fixed 16 Sep 2026) wrote `round=.parfast-rig pid=NNNN` into live locks on
  # windows-gaming-pc-b. Exclusion was never affected - that comes from the pid, which was
  # always right - but the lock then fails the OTHER job this header claims for
  # it, being identifiable to a human, exactly when somebody is staring at it
  # deciding whether to clear it. Caller fourteen will do it again, so it is
  # closed here as well: fall back to the calling SCRIPT's name, which is a
  # real answer. `$MyInvocation.ScriptName` inside a function is the caller's
  # script, not this file.
  if ($roundname -eq '.parfast-rig' -or -not $roundname) {
    $caller = $MyInvocation.ScriptName
    $roundname = if ($caller) { [IO.Path]::GetFileNameWithoutExtension($caller) } else { "pid$PID" }
  }
  Try-TakeRigLock $roundname
  if (-not $script:riglock_taken) { exit 17 }
}

# THE SCOPE OF THIS LOCK IS ONE PROCESS, AND THAT IS DELIBERATE - DECIDED
# 16 Sep 2026, lane riglock-sitting-scope. A measurement SITTING is several
# wcomb.ps1 invocations (several ladders), so the lock is free in the gaps and
# neither a waiter nor a load check can tell "between ladders" from "between
# sittings". That is a real cost - it cost one lane a three-hour watch and a
# queued round a stand-down on 16 Sep - and it was considered and NOT fixed
# here, for a reason worth reading before you widen it:
#
# The hold's liveness comes from a live pid holding an exclusive handle, which
# is the whole reason it self-heals. A hold that outlives every process has no
# holder left to ask, so it must be either presence-as-hold (banned fleet-wide,
# it cost apple-m3-ultra eight hours on 16 Sep and took three lanes to remove) or an
# age bound (refused in capitals by Get-RigLockHolder's header above). The one
# safe shape is a DRIVER process holding it across its children, and that needs
# NO change here: rounds/cf-two-binary-control-2026-09-16/cfctl-driver.ps1
# is one, taking the lock for its own cargo builds and then invoking wcomb.ps1
# behind a retry-on-exit-17 loop.
#
# SO DO NOT ADD A -NoLock SWITCH TO wcomb.ps1, which is the only thing a
# "sitting lock" would actually add over that driver. The retry loop keeps every
# ladder's identity in the lock file, and a -NoLock spelling is a round that
# takes no lock at all - which is the ONLY contamination shape measured on
# 16 Sep (a rars round and two 16-thread cargo builds, all outside the lock's
# vocabulary, and none of which a wider lock would have seen). The waiter-side
# answer that DOES span a sitting already exists and is the ahead-list: name the
# driver's pid, cstripe-i5.ps1's wait.txt block is the pattern. Full reasoning:
# an internal note, "DECIDED, 16 Sep 2026: no
# sitting-level lock is built".
function Release-RigLock([string]$lockpath) {
  # Close-then-Remove with no inode check looks like the same unconditional
  # unlink that let a POSIX round delete another round's live lock file on
  # amd-epyc-vm on 15 Sep 2026
  # (an internal note), but it is
  # NOT the same hazard here, deliberately left unguarded rather than
  # unguarded by omission. That race needs "locked" and "exists" to be
  # separable facts: on POSIX, flock() locks an fd's INODE while unlink()
  # frees the PATH to be recreated under a NEW holder while the old fd is
  # still flocked - so a late unlink can delete a file that has since become
  # someone else's. Take-RigLock above opens with [IO.FileShare]::Read
  # (::None until 16 Sep 2026 - see Get-RigLockHolder, and note that this
  # argument never rested on excluding READ, only DELETE, which ::Read still
  # excludes), which on NTFS makes "the path is taken" and "the file is open"
  # the SAME fact: nobody else's CreateNew can succeed while our handle is open
  # (CreateNew requires the path NOT exist, and it still does), and nobody
  # can have replaced our file before we get here, because replacing it
  # requires deleting it first, which requires OUR handle to already be
  # closed - which is exactly the line above this comment. So by the time
  # Remove-Item runs, the file at $lockpath is still provably ours.
  $lockpath = Join-Path $env:USERPROFILE '.parfast-rig.lock'
  if ($script:lockfs) { $script:lockfs.Close(); $script:lockfs = $null }
  Remove-Item $lockpath -Force -ErrorAction SilentlyContinue
  Write-PlibLine "RIG-LOCK-RELEASED $lockpath"
}

# ---------------------------------------------------------------------------
# THE BOX QUEUE: Enter-BoxQueue / Exit-BoxQueue
# ---------------------------------------------------------------------------
# an internal note item 2: nothing in
# `harness/` reads or writes a box's QUEUED/CLAIM/close-marker
# queue, so every round driver hand-rolls its own gate, and on 16 Sep 2026
# all five hand-rolled gates on apple-m3-ultra were wrong in a DIFFERENT way -
# a QUEUED line read as a hold, a waiter that armed and never polled, a
# `pgrep` on the round NAME that matched two idle watchers, a lane that
# held the box for two rounds without ever posting a line, and two
# collisions from read-then-append with no re-check. This pair is the
# fix for the Windows/parfast-rig side of that item; `.claude/tools/
# bench-box-gate.py` is the equivalent for the THROUGHPUT boxes (item
# 0a5) and this pair deliberately mirrors its decisions rather than
# reinventing them, because both read the SAME marker vocabulary.
#
# THE VOCABULARY IS DELIBERATELY NARROW: this pair only ever POSTS
# `QUEUED`, `CLAIM` and one of the five close-class markers `DONE`,
# `RELEASED`, `WITHDRAWN`, `ABORTED`, `STAND-DOWN` (RIG-QUEUE-VOCABULARY-
# 2026-09-16.md and item 0a5's fifth bullet - "waiting rather than
# running? Post QUEUED. Not CLAIM, not NOTE." / "leaving a queue? Post a
# close-class marker, not a NOTE"). `NOTE` settles nothing: a lane that
# posts a NOTE instead of a close-class marker is invisible to
# `parfast-rigs-parse.py` rule 16 and to `$script:handover_close` here,
# which is the exact defect this pair exists to stop introducing.
#
# ONLY `CLAIM` IS EVER TREATED AS A HOLD, per item 2's first rule ("A
# QUEUED line is an INTENTION; only a CLAIM is a hold"). `Get-CoordOpenIds`
# and `Test-CoordStillHolds` below fold the file exactly the way
# `Get-BoxHandover` above already does for a single id - CLAIM opens,
# a close-class keyword (the SAME `$script:handover_close` list, held
# equal to `CLOSE_KW` by `tools/rig-selftest-gate.py`) closes, and LINE
# ORDER decides, never the timestamp (parfast-rigs-parse.py rule 1). One
# fold, three call sites, so a change to the rule cannot land in one and
# not the other.
#
# THE RIG LOCK IS A SEPARATE MECHANISM FROM THE COORDINATION FILE, and
# this pair does not blur them: the coordination file decides WHOSE TURN
# IT IS (prose, hand-appended, read by every lane), the rig lock is the
# OS-level mutex that actually excludes a second process on this box.
# Taking the rig lock is deliberately NOT reimplemented here - see the
# note on `Enter-BoxQueue`'s last step. an internal note-
# RELEASE-NIGHT-FINDINGS.md` records a live gap in the CURRENT lock
# waiters (`Wait-LockFree`, hand-rolled per round script in
# `rounds/cf-load-term-*/`): their ahead-list is fixed at arm
# time and their load census cannot see a non-cargo/parfast tool, so a
# lane that arrives after the waiter armed is invisible to it. Claim
# `riglock-waiter-blind-to-late-arrivals` (paths `plib.ps1`,
# `cfwait.ps1`) is the fix for THAT gap, open on the ledger as this pair
# was written. `Enter-BoxQueue` calls `Wait-LockFree` if that claim has
# already landed one in this scope (`Get-Command`), because the box
# queue's own ahead-list wait (which DOES re-read on every poll, so it
# does not share the late-arrival blindness) has already established
# whose turn it is by the time the lock is asked for - this function
# must not grow a second copy of that waiter's retry/census logic while
# it is still being fixed elsewhere.

# `CLAIM` and the CLOSE vocabulary are folded over the file exactly once,
# in line order (parfast-rigs-parse.py rule 1: never the timestamp). An
# unreadable or missing file returns "not a holder" for every id, which
# is the same direction `Get-BoxHandover` takes for the same reason: a
# waiter that cannot read the file must not treat that as a permanent
# hold either, and the caller's own preflight has already checked the
# file is there.
# ONE FOLD, TWO POLICIES, AND THE SECOND ONE ARRIVED THE SAME DAY. This
# function landed for the BOX QUEUE with `CLAIM` hard-coded as the only opening
# keyword, which is item 2's own decision and is preserved exactly - it is the
# DEFAULT below and no box-queue caller passes anything else. The late-arrival
# waiter (`Get-OpenClaimants`, beside `$script:handover_open` above) needs the
# same fold over the roster's EIGHTEEN opening words instead, and it was written
# as a second copy of this loop before the two met in a merge. A second copy of
# a fold is the thing several gates in this repo exist to refuse, so the
# vocabulary became a parameter rather than the loop becoming two loops.
#
# BOTH FIELD ORDERS, which is a widening of what landed and is a FIX rather
# than a convenience: most lanes post `CLAIM <ts> <id>` and several post
# `<ts> RELEASE <id>`, both observed on the live intel-i5-10600kf file, and the
# SUBJECT is the third token under both - so only the keyword moves and it is
# looked for in fields 1 and 2. cfwait.ps1 arrived at that rule by reading the
# file; a fold that reads field 1 only misses every line of the second shape,
# which for a CLOSE means a finished lane still reads as a holder.
#
# ---------------------------------------------------------------------------
# AND A KEYWORD IN THOSE FIELDS IS NOT ENOUGH, MEASURED 19 Sep 2026
# ---------------------------------------------------------------------------
# The two field orders above were read off the files correctly and then applied
# to EVERY line, with no test that the line was a marker at all. So any PROSE
# sentence whose first or second word happened to be one of the twenty-four
# roster keywords minted or closed a subject named by its THIRD word. That is
# not a hypothetical: on windows-gaming-pc-b, line 8 of `%USERPROFILE%\COORDINATION-windows-gaming-pc-b.txt`
# is a sentence beginning `ROUTE CLAIM CHECKED MECHANICALLY, ...`, which under
# the rule above held a permanent open claim named `CHECKED` that nothing could
# ever close - append-only file, and no lane would ever post a close for a
# subject no lane had ever claimed. A correct round on 19 Sep took the rig
# lock, saw that stranger, released the lock and sat in its wait loop for three
# minutes; every later caller on that box would have done the same. Section 8
# of an internal note is the write-up.
#
# THE OTHER DIRECTION IS THE DANGEROUS ONE AND IT IS REACHABLE. A prose
# sentence can just as easily CLOSE a live lane: `NOTE DONE <their-id> ...`
# and `the RELEASE m1-scout ...` both fold to a close of a real subject under
# the old rule, which frees a held box and puts two rounds on it. Six live
# instances of the shape (a keyword-bearing prose line closing a subject an
# earlier line had opened) are on the fleet's own files today - on apple-m1-ultra-64gb
# and the M5's `COORDINATION-m5-local-par.txt` - and it is only luck that the
# subjects they closed were themselves phantoms rather than lane ids. The
# account reader hit the same class one keyword class over and its
# `_marker_shaped` docstring records a prose line that DID close a live claim.
#
# SO A LINE MUST BE MARKER-SHAPED, AND THE SHAPES ARE THESE THREE. Measured
# over 5,171 coordination lines collected read-only on 19 Sep 2026 from nine
# boxes (apple-m1-ultra-64gb, apple-m3-ultra, amd-epyc-vm, intel-i5-10600kf, intel-core-ultra-9-386h,
# spinning-disk-nas-a, spinning-disk-nas-b, apple-m1-ultra-128gb and the M5's two files):
#
#   S1  `<KEYWORD> <stamp> <subject> ...`     1,511 instances - Write-CoordMarker
#   S2  `<stamp> <KEYWORD> <subject> ...`        49 instances - the intel-i5-10600kf shape
#   S3  `<KEYWORD> <tag> claim=<id> ...`          8 instances - the rarkit fleet
#                                                               gate-tip driver
#
# and 99 keyword-bearing lines are refused, of which every one read by hand is
# either prose or a line whose third token was never a subject (`CLAIM 23:16Z
# 6 Aug mock-ceiling-AB` minted `6`; `CLAIM 09/09/2026 3:22:07.91 <id>` minted
# the time). THE OPEN SET WAS COMPARED PER BOX BEFORE AND AFTER: 39 phantom
# open subjects go away (34 -> 19 on apple-m1-ultra-64gb, 18 -> 1 on the M5's file,
# 10 -> 5 on amd-epyc-vm, 2 -> 1 on intel-i5-10600kf) and NOT ONE box gains an open
# subject it did not already have. That last half is the one that had to be
# checked - a tightening that drops a real CLOSE reads a finished lane as a
# holder, and a tightening that drops a real OPEN takes somebody's box.
#
# S3 IS IN THE GRAMMAR BECAUSE A LIVE WRITER EMITS IT, not to be generous. The
# rarkit gate-tip driver posts `CLAIM gate-tip-19sep claim=<id> box=<box>
# round=<round> pid=<n> started=<ts>` and the matching `DONE gate-tip-19sep
# claim=<id> rc=0 at=<ts>`, with no stamp in field 1 at all, and it was posting
# to apple-m3-ultra while this was written. Dropping it would make a live lane
# invisible, which is the polarity that costs somebody's round. The SUBJECT for
# that shape is the VALUE of `claim=`, so it is the real claim id rather than
# the token - which is what `Test-CoordStillHolds` and `Get-OpenClaimants`
# compare their callers' ids against. Only `claim=`, `round=` and `id=` name a
# subject; `ACCOUNTS=none` sits in field 2 on ten lines of the M5's file and
# naming it a subject is how that file grew a phantom called `ACCOUNTS=none`.
#
# WHAT IS DELIBERATELY NOT HERE. There is no fourth shape for `<KEYWORD> <id>
# <stamp>` (six instances on the M5's file, one codex writer): it was built and
# measured and it OPENS `par-incremental-full-7sep` without ever closing it,
# because that lane's own close is `DONE par-incremental-full-7sep: results...`
# with no stamp anywhere. A shape that adds an open and cannot add its close is
# the defect above with a different first token. And there is no arm for
# `<ts> DONE <ts> <id>`, one line on apple-m3-ultra where the stamp is written
# twice; that line is why `digest-cache-enrol-threads-close-the-question-16sep`
# reads as open on that box under the old rule AND the new one. It is a live
# phantom, reported rather than parsed around: the file is append-only and the
# fix is a corrective line from a lane that holds the box.

# THE STAMP TEST, IN TWO HALVES, AND ONLY THE FIRST IS A COPY OF THE ROSTER'S.
# `$script:coord_stamp_core` is `MARKER_TS_RE.pattern` in
# `.claude/tools/bench-accounts-parse.py`, character for character, and
# `tools/rig-selftest-gate.py` holds it equal on every push exactly as it
# already holds the two keyword lists - same reason, same terms: a Windows
# round has no Python between legs, so plib keeps the one unavoidable copy and
# a gate stops the two readers splitting. Edit the roster, then move this line.
$script:coord_stamp_core = '^(?:\d{4}-\d{2}-\d{2}T\d{2}:\d{2}(?::\d{2})?|\d{8}T\d{4,6})(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?$'

# THE SECOND HALF IS A DELIBERATE SUPERSET OF THE ROSTER'S, AND THE DIFFERENCE
# IS ARGUED RATHER THAN ACCIDENTAL. `MARKER_TS_RE` refuses the fleet's
# degenerate stamp spellings on purpose, and its own comment gives the reason:
# there the stamp is the ONLY guard, so a pattern loose enough to swallow `$TS`
# or a bare date is loose enough to swallow prose. Here it is one of three
# anchors and the subject is checked too, so the trade is different - and it
# has to be, because refusing them costs REAL CLOSES. Measured on the same
# corpus: without this half, `codex-par2-create-race` on apple-m1-ultra-64gb reads as
# OPEN FOREVER, because its close is `DONE $TS codex-par2-create-race` with the
# shell variable unexpanded; four more August lanes lose their close the same
# way. Every spelling below was read off the files:
#
#   `10:35Z` `03:0*Z` `3:22:07.91`   a time with no date
#   `2026-08-02` `09/09/2026`        a date with no time
#   `2026-09-03T~18:25Z`             an APPROXIMATE stamp
#   `$TS` `"$T"` `%Y-%m-%dT%H:%M:%SZ`  a stamp that never rendered
#
# NONE OF THEM MATCHES ANY PROSE TOKEN IN THE CORPUS, which is the check that
# makes this safe rather than merely convenient: over all 5,171 lines the
# accepted set is 1,568 marker instances and zero prose, and the refused set is
# 99 lines of which zero are markers with a usable subject. If you widen this,
# re-run that separation; a shape that admits one English word admits the lot.
$script:coord_stamp_degenerate = '^(?:\d{1,2}:[\d*]{2}[\d:*.]*Z?|\d{4}-\d{2}-\d{2}|\d{1,2}/\d{1,2}/\d{4}|\d{4}-\d{2}-\d{2}T~[\d:]+Z?|"?\$\w+"?|%[-%\w:]*Z?)$'

# `claim=`, `round=` and `id=` ONLY - see the S3 note above for why
# `ACCOUNTS=` is not on this list.
$script:coord_subject_kv = '^(?:claim|round|id)=(\S+)$'

# Is this token a timestamp as some lane on this fleet has actually written
# one? A `[...]`-wrapped stamp counts: two `[2026-08-14T02:01:10Z] CLAIM
# <id>` lines are on apple-m1-ultra-64gb and the brackets are the only thing between
# them and shape S2. No prose token in the corpus is bracketed.
#
# RETURNS AND EMITS NOTHING ELSE, for the reason Get-BoxHandover's header gives
# at length - every statement in here is an assignment, a control-flow keyword
# or the single return.
function Test-CoordStampToken([string]$tok) {
  if (-not $tok) { return $false }
  $t = $tok
  if ($t.Length -gt 2 -and $t[0] -eq '[' -and $t[$t.Length - 1] -eq ']') { $t = $t.Substring(1, $t.Length - 2) }
  if ($t -match $script:coord_stamp_core) { return $true }
  return ($t -match $script:coord_stamp_degenerate)
}

# A subject has at least one letter in it and is not itself a stamp. That
# second clause is not decoration: a `CLAIM <date> <time> - <id> session:` line
# on apple-m1-ultra-64gb and three `<date> <time> <id>` lines on intel-i5-10600kf all put a
# STAMP in field 2, and taking it as the subject is how those files grew open
# claims named after clock readings. The first clause drops `6` and `-`,
# which is what `CLAIM 23:16Z 6 Aug <id>` and `THE RESULT - THE CONTROLLER`
# offer in that position.
function Test-CoordSubjectToken([string]$tok) {
  if (-not $tok) { return $false }
  if ($tok -notmatch '[A-Za-z]') { return $false }
  return (-not (Test-CoordStampToken $tok))
}

# ONE line -> one event, or $null for prose. This is the only place the
# grammar above is spelled, and `Get-CoordFoldedState` and `Get-BoxHandover`
# both go through it: a second copy of a coordination matcher is the thing
# tools/coord-matcher-gate.py exists to refuse, and two copies of it inside the
# library it points at would be the same defect wearing the right coat.
#
# The caller supplies the OPEN vocabulary, exactly as the fold does, so the box
# queue keeps its "only CLAIM is a hold" rule. Returns a hashtable with
# Keyword (upper-cased) and Subject, or $null.
#
# RETURNS AND EMITS NOTHING ELSE. Same rule as its two neighbours.
function Get-CoordMarkerEvent([string]$line, [string[]]$openkw) {
  if (-not $line) { return $null }
  if (-not $openkw) { $openkw = [string[]]@('CLAIM') }
  $f = $line.Split((" `t").ToCharArray(), [StringSplitOptions]::RemoveEmptyEntries)
  if ($f.Count -lt 3) { return $null }
  $k0 = $f[0].ToUpperInvariant()
  $k1 = $f[1].ToUpperInvariant()
  $isk0 = ($openkw.Contains($k0) -or $script:handover_close.Contains($k0))
  $isk1 = ($openkw.Contains($k1) -or $script:handover_close.Contains($k1))
  # S1, then S2, then S3. The order matters only for a line that could be
  # read two ways, and no line in the corpus is.
  if ($isk0 -and (Test-CoordStampToken $f[1]) -and (Test-CoordSubjectToken $f[2])) {
    return @{ Keyword = $k0; Subject = $f[2] }
  }
  if ($isk1 -and (Test-CoordStampToken $f[0]) -and (Test-CoordSubjectToken $f[2])) {
    return @{ Keyword = $k1; Subject = $f[2] }
  }
  if ($isk0 -and $f[2] -match $script:coord_subject_kv) {
    return @{ Keyword = $k0; Subject = $Matches[1] }
  }
  return $null
}

function Get-CoordFoldedState([string]$coordpath, [string[]]$openkw) {
  if (-not $openkw) { $openkw = [string[]]@('CLAIM') }
  $state = @{}
  $order = @()
  $lines = $null
  try { $lines = @(Get-Content -LiteralPath $coordpath -ErrorAction Stop) } catch { return @{ Order = @(); State = $state } }
  foreach ($line in $lines) {
    $ev = Get-CoordMarkerEvent $line $openkw
    if (-not $ev) { continue }
    $lid = $ev.Subject
    if (-not $state.ContainsKey($lid)) { $order += $lid }
    $state[$lid] = $openkw.Contains($ev.Keyword)
  }
  return @{ Order = $order; State = $state }
}

# Every id whose most recent CLAIM has no later close-class line, in the
# order each first appeared, minus $excludeId. This is `Enter-BoxQueue`'s
# ahead-list, snapshotted ONCE at QUEUE time - the list a lane polls
# against, never recomputed wholesale (a late arrival joins the SAME
# poll loop the next time it posts a CLAIM, which is re-checked at
# claim-settle time below, not by widening this snapshot).
function Get-CoordOpenIds([string]$coordpath, [string]$excludeId) {
  $f = Get-CoordFoldedState $coordpath
  return @($f.Order | Where-Object { $f.State[$_] -and $_ -ne $excludeId })
}

# Would `parfast-rigs-parse.py` (or a human folding the file by eye) still
# call $id a holder of $coordpath right now? Used both to poll an
# ahead-list id closed and, in Exit-BoxQueue, to FAIL LOUDLY when a
# posted close did not land.
function Test-CoordStillHolds([string]$coordpath, [string]$id) {
  $f = Get-CoordFoldedState $coordpath
  if (-not $f.State.ContainsKey($id)) { return $false }
  return [bool]$f.State[$id]
}

# Post one marker-shaped line: `<KEYWORD> <iso-stamp> <id> - <body>`. The
# stamp is `yyyy-MM-ddTHH:mm:ssZ`, one of the forms `parfast-rigs-parse.
# py`'s `MARKER_TS_RE` accepts without the fractional-second or basic-form
# arms (those exist because OTHER tools write those shapes, not because
# this one should start). Throws on an unwritable file rather than
# swallowing the failure the way `Write-RigLockOrphanNote` does for its
# best-effort note: a QUEUED/CLAIM/close line that silently failed to
# post is the exact invisible-lane hazard item 0a5's fifth bullet is
# about, and $ErrorActionPreference = 'Stop' at the top of this file is
# what a caller of this helper is already relying on everywhere else.
function Write-CoordMarker([string]$coordpath, [string]$keyword, [string]$id, [string]$body) {
  $ts = (Get-Date).ToUniversalTime().ToString('yyyy-MM-ddTHH:mm:ssZ')
  $line = "$keyword $ts $id - $body"
  Add-Content -LiteralPath $coordpath -Value $line -ErrorAction Stop
  Write-PlibLine "BOXQUEUE-POST $coordpath $line"
  return $line
}

# THE QUEUE ENTER. `$coordpath` and `$id` follow `Get-BoxHandover`'s own
# rule: never guessed, always the caller's - a wrong guess reads a stale
# file as a free box, which is the class of incident item 2 exists to
# close. `$gen` is the claim's generation out of an internal note
# (`tools/claims.py claim` prints it); it goes in the posted prose only,
# never parsed back. `$round` is passed straight to Take-RigLock.
#
# Returns nothing; success/failure is `$script:boxqueue_taken`, for the
# same reason `Try-TakeRigLock` reports through `$script:riglock_taken`
# and not a return value - PowerShell returns every line a function
# EMITS, so a `return $true` next to the BOXQUEUE-* lines this prints
# would hand the caller a two-element array.
function Enter-BoxQueue([string]$coordpath, [string]$id, [string]$gen, [string]$round,
                         [string]$expectBy = '', [int]$pollSecs = 20, [int]$maxPolls = 180) {
  $script:boxqueue_taken = $false
  if (-not (Test-Path -LiteralPath $coordpath)) {
    Write-PlibLine "BOXQUEUE-REFUSE $coordpath does not exist - Enter-BoxQueue never creates the coordination file, the caller must (item 2: failing to find is failing)."
    return
  }

  # --- snapshot the ahead-list and declare the intention -------------------
  $ahead = @(Get-CoordOpenIds $coordpath $id)
  $expectTxt = if ($expectBy) { "Expect CLAIM and DONE by $expectBy." } else { 'No ETA given.' }
  if ($ahead.Count -eq 0) {
    Write-CoordMarker $coordpath 'QUEUED' $id "gen=$gen round=$round - box appears free of any open CLAIM. Posting CLAIM next. $expectTxt" | Out-Null
  } else {
    Write-CoordMarker $coordpath 'QUEUED' $id "gen=$gen round=$round - queuing behind: $($ahead -join ', '). Will post CLAIM once every one of those has posted a close-class marker (DONE/RELEASED/WITHDRAWN/ABORTED/STAND-DOWN). $expectTxt" | Out-Null
  }

  # --- poll the ahead-list closed, an id at a time, never a keyword anywhere
  # in a line (parfast-rigs-parse.py rule 16 / the intel-i5-10600kf sixth rule) -----
  foreach ($aheadId in $ahead) {
    $tries = 0
    while (Test-CoordStillHolds $coordpath $aheadId) {
      $tries++
      if ($tries -gt $maxPolls) {
        Write-CoordMarker $coordpath 'WITHDRAWN' $id "gen=$gen round=$round - STANDING DOWN. $aheadId never posted a close-class marker after $($tries * $pollSecs) s of polling. This is an intention timing out, never a hold; nothing of mine was taken." | Out-Null
        return
      }
      Start-Sleep -Seconds $pollSecs
    }
  }

  # --- claim it, then re-read the tail and stand down if beaten ------------
  # (bench-box-gate.py decision D, item 0a5: append, settle, re-read, stand
  # down inside the window if a second CLAIM landed under mine - the
  # earlier timestamp keeps the box). This loops rather than recursing so a
  # lane that loses several ties in a row still terminates on $maxPolls.
  for (;;) {
    Write-CoordMarker $coordpath 'CLAIM' $id "gen=$gen round=$round - taking the box. $expectTxt" | Out-Null
    Start-Sleep -Seconds 20   # settle: bench-box-gate.py decision D's window -
    $rivals = @(Get-CoordOpenIds $coordpath $id)
    if ($rivals.Count -eq 0) { break }
    # A rival CLAIM is under mine. Stand down, wait for IT to close (folding
    # it into the same poll loop above, not a fresh snapshot of the whole
    # file), and try again - this is the box queue's own re-check, and it is
    # deliberately not "whoever posted first wins without a stand-down": the
    # loser must SAY so, or it reads as a phantom holder the next lane has
    # to wait out unnecessarily.
    Write-CoordMarker $coordpath 'STAND-DOWN' $id "gen=$gen round=$round - a rival CLAIM landed under mine ($($rivals -join ', ')). Standing down and waiting for it to close before re-claiming." | Out-Null
    foreach ($rivalId in $rivals) {
      $tries = 0
      while (Test-CoordStillHolds $coordpath $rivalId) {
        $tries++
        if ($tries -gt $maxPolls) {
          Write-CoordMarker $coordpath 'WITHDRAWN' $id "gen=$gen round=$round - STANDING DOWN. $rivalId (which beat my CLAIM) never posted a close-class marker after $($tries * $pollSecs) s of polling." | Out-Null
          return
        }
        Start-Sleep -Seconds $pollSecs
      }
    }
  }

  # --- the coordination file says it is my turn; now take the REAL lock ----
  # THIS WAS A `Get-Command` PROBE FOR A FUNCTION THAT NEVER EXISTED, and the
  # shape is worth naming because it looks like careful forward compatibility
  # and is the "failing to find is failing" class wearing a hat. It asked
  # whether claim `riglock-waiter-blind-to-late-arrivals` had landed a
  # `Wait-LockFree` into this scope and fell through to a bare retry loop if
  # not. That claim landed on 18 Sep 2026 and the function it landed is called
  # `Take-RigLockWhenFree`, so the probe answered NO FOREVER, silently, on the
  # one path it was written for - a hook whose absent arm is indistinguishable
  # from its waiting arm.
  #
  # AND WHERE IT DID RESOLVE, IT RESOLVED THE WRONG THING. `Wait-LockFree` is
  # not a plib name at all: it is hand-rolled inside cfload.ps1, cfknee.ps1 and
  # cfbuf.ps1, each of which DOT-SOURCES this library, so in those scopes
  # `Get-Command` finds the ROUND'S OWN copy and calls it with plib's
  # `($round, $maxPolls)` arguments, then reads a `$script:lockfree` that
  # nothing here sets. A cross-scope call by NAME to a function no file in this
  # repo defines is not a hook, it is a hope. Do not put one back.
  #
  # SO IT CALLS THE REAL FUNCTION, BY NAME, AND GETS THE LATE-ARRIVAL RE-READ
  # WITH IT. The old fall-through loop was `Try-TakeRigLock` on a timer with no
  # look at the coordination file between polls - the probe-then-act shape, in
  # the one place the box queue is most exposed to it: the ahead-list was
  # SNAPSHOTTED before the wait, so a lane that claims while we are polling is
  # invisible to this function by construction (`Get-CoordOpenIds`' own header
  # says so). `Take-RigLockWhenFree` re-reads on every attempt, with the lock
  # already in hand, and gives it back if the file says the box is not ours.
  #
  # `-StandDownOnClaim` rather than waiting it out, because the box queue has
  # ALREADY posted a CLAIM of its own: sitting in a retry loop under somebody
  # else's open claim would leave two lanes claiming one box on the file, which
  # is the state this whole pair exists to prevent. Standing down posts the
  # WITHDRAWN below, which closes ours.
  Take-RigLockWhenFree -round $round -coordpath $coordpath -selfid $id `
                       -maxwaits ($pollSecs * $maxPolls) -polls $pollSecs -standdownonclaim
  if ($script:riglock_taken) {
    $script:boxqueue_taken = $true
    Write-PlibLine "BOXQUEUE-TAKEN $coordpath $id round=$round"
    return
  }
  # ONE WITHDRAWN, AND IT SAYS WHICH REASON. The loop this replaced had exactly
  # one way to fail - the lock never came free - and its message said so. There
  # are two now, an open claim and a busy box, and `$script:boxtake_why` is the
  # one that distinguishes them: a lane reading this file afterwards needs to
  # know whether it was beaten to the box or whether the box was simply loaded.
  Write-CoordMarker $coordpath 'WITHDRAWN' $id "gen=$gen round=$round - the coordination file gave me the box but I did not take it: $($script:boxtake_why). Standing down after $($maxPolls * $pollSecs) s. Nothing of mine holds the rig lock and nothing of mine is running." | Out-Null
}

# THE QUEUE EXIT. Releases the rig lock, posts a close-class marker
# (default DONE), then RE-READS THE FILE AND FAILS LOUDLY if $id would
# still read as a holder - an append that silently failed (permissions,
# a race, a truncated write) must not be mistaken for a released box by
# the next lane in the queue, which is exactly the "posted no line to
# the file at any point while holding the box" failure mode item 2's
# table records for `nttwork-rig-stamp-16sep`.
function Exit-BoxQueue([string]$coordpath, [string]$id, [string]$gen, [string]$closeKeyword = 'DONE', [string]$note = '') {
  if ($closeKeyword -notin $script:handover_close) {
    throw "Exit-BoxQueue: '$closeKeyword' is not one of the five close-class markers ($($script:handover_close -join ', ')) - posting it would leave $id reading as a holder to every other reader of $coordpath."
  }
  Release-RigLock (Get-RigLockPath)
  $body = if ($note) { "gen=$gen box released. $note" } else { "gen=$gen box released." }
  Write-CoordMarker $coordpath $closeKeyword $id $body | Out-Null
  if (Test-CoordStillHolds $coordpath $id) {
    throw "Exit-BoxQueue: FAIL LOUDLY - after posting $closeKeyword, $id STILL reads as a holder of $coordpath (a later CLAIM landed for this id, or the close did not really land). The rig lock has already been released; fix the coordination file before anything else queues behind a phantom."
  }
  Write-PlibLine "BOXQUEUE-RELEASED $coordpath $id"
}

# ---------------------------------------------------------------------------
# THE CENSUS, AND THE GAP NO CENSUS CAN CLOSE
# ---------------------------------------------------------------------------
# `Test-BoxFree` was hand-rolled in four waiters (cfwait.ps1, t6wait.ps1 and
# two more) and every copy asked the same two questions the same wrong way:
#
#   1. `Test-Path` on the lock file. EXISTENCE IS NOT A HOLD - a round that
#      dies between the create and the identity write leaves a file that blocks
#      every waiter forever and names nobody. That is the whole subject of
#      an internal note and of
#      `Get-RigLockHolder` above, which is the one place the hold rule lives.
#      A waiter must ask THAT, and `Test-RigLockHeld` is the read-only door to
#      it.
#   2. `Get-Process -Name parfast,cargo,rustc`. A NAME LIST CANNOT BE COMPLETE
#      and this one is three words long. On 18 Sep 2026 a lane compiled the
#      Windows installer with ISCC for ninety seconds and the box read
#      genuinely free on two samples sixty seconds apart, because an Inno Setup
#      compile is none of those three names and takes no rig lock. rars, 7-Zip,
#      msbuild, a Defender pass and a Windows Update scan are all in the same
#      position.
#
# SO THE PRIMARY ARM IS CPU ATTRIBUTION, NOT NAMES. `Get-ForeignCpu` already
# measures the CPU burnt OUTSIDE our own process tree over a one second window
# and is the quantity `Require-QuietBox` aborts a leg on; asking it here costs
# one second and sees every tool on the box whatever it is called. The name
# list is KEPT as corroboration, widened, and demoted: it catches a tool that
# is between bursts at the instant we sample, which is the one thing the CPU
# arm can miss.
#
# AND THE READING IS REPORTED WHETHER IT IS OVER THE CEILING OR NOT, which is
# the half that makes this reviewable after the fact. The 18 Sep 13:26Z probe
# that read the box free was CORRECT about the lock and had `foreign_cpu 21.7`
# in its own hand; the number only became interesting two minutes later. A
# census that logs "free" and drops the figure cannot be re-read.
#
# WHAT THIS DOES NOT FIX, STATED HERE BECAUSE THE FIRST DRAFT OF THE HANDOFF
# THOUGHT IT DID. "Ask the rig lock rather than a name list" does NOT cover the
# second dated instance. That lane asked the lock DIRECTLY, with a fifteen
# second per-process attribution census wider than this one, and got
# `lock_exists=False lock_held=False` at 13:26 - and another lane took the lock
# at 13:28:19, thirteen seconds before the round asked for it. The lock was
# free when asked. The exposure is the GAP between any probe and the driver's
# own acquire, which is about two minutes of staging scripts and launching, and
# A CENSUS CANNOT CLOSE A GAP THAT OPENS AFTER IT RETURNS. Only an acquire that
# is itself the probe can, which is `Take-RigLockWhenFree` below.
#
# A WIDER LIST THAN THREE WORDS, and still not a complete one - it cannot be,
# which is why it is second. These are the tools measured contending for a box
# on this fleet: the PAR2 family, the Rust build, the RAR engines, the
# archivers, the installer compiler and the MSVC build.
$script:boxcensus_names = [string[]]@(
  'parfast', 'par2', 'par2j', 'par2j64', 'par2turbo', 'phpar2',
  'cargo', 'rustc', 'cc1', 'link', 'cl', 'msbuild', 'ninja', 'cmake',
  'rars', 'rarfast', 'rar', 'unrar', 'WinRAR', '7z', '7za', '7zg', '7zz',
  'ISCC', 'Compil32', 'makensis')

# The whole census as one object. RETURNS AND EMITS NOTHING, same seam, same
# reason. `Free` is the verdict; every input that produced it is a field beside
# it so the log line and the caller read the same numbers.
#
# AN UNMEASURABLE COUNTER IS NOT BUSY, and the direction is chosen rather than
# defaulted. `Get-ForeignCpu` answers -1 when it cannot sample, and on a box
# where that is permanent - not a blip - treating it as busy makes every waiter
# wait forever, which loses the round exactly as surely as taking an occupied
# box does and is harder to see. The lock arm is unaffected and stays
# authoritative, `Take-RigLockWhenFree` still holds the lock before it believes
# anything, and the field says `cpu=-1` so a reader knows the arm was blind
# rather than quiet.
function Get-BoxCensus([double]$cpuceiling) {
  if ($cpuceiling -le 0) { $cpuceiling = 50.0 }
  $r = [ordered]@{ Free = $true; LockHeld = $false; LockWhy = ''; ForeignCpu = -1.0
                   CpuCeiling = $cpuceiling; Names = ''; Why = 'free' }
  $h = Get-RigLockHolder
  # A LOCK HELD BY OUR OWN PID IS NOT SOMEBODY ELSE'S BOX. Without this the
  # census is unusable from inside `Take-RigLockWhenFree`, which asks it with
  # our own handle deliberately open - it would report `lock held by live
  # pid=<us>` and refuse every take forever. It is the right answer for a
  # standalone caller too: a driver asking "is this box free" while holding the
  # lock is asking about everyone else.
  $r.LockHeld = ($h.Held -and $h.Pid -ne $PID)
  $r.LockWhy = $h.Why
  $r.ForeignCpu = Get-ForeignCpu
  $mine = Get-OwnPidTree
  $hits = @()
  foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
    if ($mine.Contains($p.Id)) { continue }
    if (-not $script:boxcensus_names.Contains($p.ProcessName)) { continue }
    $hits += ($p.ProcessName + '(' + $p.Id + ')')
  }
  $r.Names = ($hits -join ' ')
  $why = @()
  if ($r.LockHeld) { $why += "lock $($r.LockWhy)" }
  if ($r.ForeignCpu -ge $cpuceiling) { $why += "foreign_cpu=$($r.ForeignCpu) over ceiling=$cpuceiling" }
  if ($hits.Count -gt 0) { $why += "tools=[$($r.Names)]" }
  if ($why.Count -gt 0) { $r.Free = $false; $r.Why = ($why -join '; ') }
  return [pscustomobject]$r
}

# The one-line question, for a caller that wants a boolean and nothing else.
# Every hand-rolled waiter spelled this; none of them spelled it right.
function Test-BoxFree([double]$cpuceiling) { (Get-BoxCensus $cpuceiling).Free }

# The logging half. It prints on a FREE box too, deliberately: the figure that
# made the 18 Sep probe re-readable was the one taken on the sample that said
# free.
function Write-BoxCensusNote([string]$where, $census) {
  Write-PlibLine "BOX-CENSUS at=$where free=$(if ($census.Free) { 1 } else { 0 }) lock_held=$(if ($census.LockHeld) { 1 } else { 0 }) foreign_cpu=$($census.ForeignCpu) ceiling=$($census.CpuCeiling) tools=[$($census.Names)] why=$($census.Why) ts=$((Get-Date).ToUniversalTime().ToString('o'))"
}

# ---------------------------------------------------------------------------
# THE ACQUIRE IS THE PROBE
# ---------------------------------------------------------------------------
# THE ROUND-START PATH IS THE ONE PLACE ON THIS FLEET THAT STILL PROBES AND
# THEN ACTS. Inside a round the shape is already right: cfload.ps1's
# `Wait-LockFree` probes the lock free with no load generator running and then
# acquires, and a legset that never gets the lock is SKIPPED rather than run on
# a borrowed box. At round START every driver did the opposite - read the file,
# sample the box, stage the scripts, build, then acquire, with minutes between
# the belief and the act. Both 18 Sep instances live in that gap.
#
# SO TAKE THE LOCK FIRST AND ASK AFTERWARDS. `Try-TakeRigLock` is an exclusive
# CreateNew on NTFS: while our handle is open no other round's CreateNew can
# succeed (see Release-RigLock's note on why "the path is taken" and "the file
# is open" are the same fact here). Every question this function asks is asked
# with that handle HELD, so an answer cannot go stale between the asking and
# the running. If any answer says the box is not ours we RELEASE and wait -
# holding a lock we are not entitled to would be the same defect pointed the
# other way.
#
# THE ORDER IS ACQUIRE, CLAIM, CPU, and it is not arbitrary. The acquire is
# cheapest and excludes every lane that respects the lock. The coordination
# re-read is a file read and catches the lane that claimed the box in prose
# without having taken the lock yet - which is precisely the late arrival, and
# precisely what an ahead-list cannot see. The CPU sample costs a second and
# catches the tool that is in neither, which is the ISCC case.
#
# WE NEVER CLEAR ANOTHER LANE'S ANYTHING and we never kill: an orphaned lock is
# handled by Try-TakeRigLock's own arm, which proves it is nobody's before
# touching it, and everything else here is a wait.
#
# STAND DOWN OR KEEP WAITING IS THE CALLER'S POLICY, not this function's. A
# waiter whose whole job is to catch a gap wants to keep waiting;
# `g4winrun2.ps1`'s round wanted to exit 7 and be re-queued by a human, because
# a six-hour sitting that starts under somebody else's claim is worse than one
# that does not start. `-StandDownOnClaim` picks the second.
#
# SUCCESS IS $script:riglock_taken, NOT A RETURN VALUE, for the reason
# Try-TakeRigLock's header gives - this function logs, so anything it returned
# would reach the caller as an array with its log lines in it. The reason is
# $script:boxtake_why.
function Take-RigLockWhenFree {
  param([string]$round,
        [string]$coordpath = '',
        [string]$selfid = '',
        [int]$maxwaits = 3600,
        [int]$polls = 60,
        [double]$cpuceiling = 50.0,
        [switch]$standdownonclaim)
  $script:riglock_taken = $false
  $script:boxtake_why = ''
  if ($polls -lt 1) { $polls = 1 }
  $sw = [Diagnostics.Stopwatch]::StartNew()
  while ($true) {
    Try-TakeRigLock $round
    if ($script:riglock_taken) {
      # HELD FROM HERE. Nothing below can be invalidated by a lane that
      # respects the lock, which is what the probe-then-act shape could not say.
      $claimants = (Get-OpenClaimants $coordpath $selfid)
      if ($claimants.Count -gt 0) {
        Release-RigLock ''
        $script:riglock_taken = $false
        Write-LateArrivalNote "take:$round" $claimants
        $script:boxtake_why = "open claim(s) not mine: $($claimants -join ' ')"
        if ($standdownonclaim) {
          Write-PlibLine "BOX-TAKE-STANDDOWN round=$round why=$($script:boxtake_why)"
          return
        }
      } else {
        $census = Get-BoxCensus $cpuceiling
        Write-BoxCensusNote "take:$round" $census
        if ($census.Free) {
          Write-PlibLine "BOX-TAKE-CONFIRMED round=$round waited_s=$([math]::Round($sw.Elapsed.TotalSeconds)) foreign_cpu=$($census.ForeignCpu) open_claims=none"
          $script:riglock_taken = $true
          $script:boxtake_why = 'free'
          return
        }
        # The lock was ours and the box is not. Give it back rather than sit on
        # it: a lane that DOES respect the lock must not be blocked by our wait.
        Release-RigLock ''
        $script:riglock_taken = $false
        $script:boxtake_why = $census.Why
      }
    } else {
      $script:boxtake_why = 'rig lock held by another round'
    }
    if ($sw.Elapsed.TotalSeconds -ge $maxwaits) {
      Write-PlibLine "BOX-TAKE-GAVE-UP round=$round waited_s=$([math]::Round($sw.Elapsed.TotalSeconds)) cap_s=$maxwaits why=$($script:boxtake_why)"
      return
    }
    Write-PlibLine "BOX-TAKE-WAIT round=$round waited_s=$([math]::Round($sw.Elapsed.TotalSeconds)) why=$($script:boxtake_why)"
    Start-Sleep -Seconds $polls
  }
}

# Run one tool invocation and measure it. Returns rc, wall, child CPU seconds and
# peak working set; stdout and stderr are written to $logbase.out / $logbase.err
# and NEVER discarded, so a refusal cannot be recorded as a fast success.
function Resolve-OwnPidSet {
  # THE PID-SET WALK, SPLIT OUT OF Get-OwnPidTree SO IT CAN BE TESTED, and the
  # arrangement is deliberately the same as Measure-ForeignDelta's below and for
  # the same reason: the gate for this file is a macOS runner, so anything that
  # needs `Get-CimInstance` cannot be tested at all. This half is a pure graph
  # walk over two hashtables - pid -> parent pid, pid -> process name - and a
  # seed pid, so plib_selftest.ps1 drives it with a synthetic process table,
  # starts nothing, and runs anywhere.
  #
  # ---------------------------------------------------------------------------
  # IT WALKS DOWN AND IT WALKS UP, AND THEY ARE NOT THE SAME WALK (16 Sep 2026)
  # ---------------------------------------------------------------------------
  # DOWN is the original behaviour and the reason this function exists: our own
  # driver plus everything under it, so the guard does not measure the round's
  # OWN work. Run-Rung hashes all 23 members immediately before calling a leg,
  # so a plain "total processor time" sample catches the tail of our own SHA
  # gate and would abort a clean round.
  #
  # UP is new, and it closes a defect the downward walk had by construction:
  # the ANCESTORS of $PID were foreign. A round driven over ssh is a PowerShell
  # under a login shell under a per-connection `sshd-session`, none of which is
  # under $PID, so a lane's own observer landed in the lane's own `foreign_cpu`
  # field and could trip the lane's own guards. Measured: on windows-gaming-pc-b the
  # measuring script's own ssh login shell was charged 0.16 core-seconds in a
  # single 1 s sample (banked on that box's COORDINATION file, 18:05Z), and on
  # intel-i5-10600kf the two samples of ten with a `powershell` born inside the window
  # read 68.8 and 76.6 percent of a core against a 40 s per-process truth of
  # 15.7 - a PowerShell start is about 0.3 core-seconds of module autoload, and
  # 0.3 core-seconds inside a 1 s window is 30% of a core, correctly measured.
  # Record: an internal note section 5, item 1.
  #
  # ---------------------------------------------------------------------------
  # THE TRAP, WHICH IS WHY THE TWO WALKS ARE SEPARATE AND ORDERED
  # ---------------------------------------------------------------------------
  # The downward walk excludes a pid AND EVERYTHING UNDER IT. Seeding the
  # ancestors into the same set before that closure runs - the one-line
  # spelling of "add ancestors" - does not exclude your login shell. It
  # excludes `sshd`, then `services.exe`, then every process `services.exe`
  # ever started, which is most of the box: the guard would read ~0 forever and
  # would be reporting its own blindness rather than a quiet box. So the
  # ancestor chain is added ONE PID AT A TIME, AFTER the downward closure has
  # finished growing, and nothing in it is ever used as a seed. A sibling
  # under a shared ancestor - another lane's `sshd-session`, its shell, and
  # everything that lane runs - stays FOREIGN, which is correct: it is somebody
  # else's work on this box and seeing it is what these guards are for.
  #
  # ---------------------------------------------------------------------------
  # WHERE THE CHAIN STOPS, AND WHY THERE
  # ---------------------------------------------------------------------------
  # Walking to the top of the tree would excuse `System` (pid 4) and whichever
  # `svchost` hosts the service that started us, and both are genuine foreign
  # consumers: `System` was 3.6% of the 15.7% truth on intel-i5-10600kf and is where a
  # neighbouring round's kernel time lands, and a `svchost` ancestor is the
  # Schedule service, which hosts many other services besides the one that
  # launched this round. So the walk stops, WITHOUT excluding, at the first of:
  #
  #   - a parent pid <= 4 (0 is "no parent" and Idle, 4 is System);
  #   - a parent that is not in the snapshot at all, which means it has been
  #     reaped and its pid is free to be somebody else's;
  #   - a pid already seen on this chain, so a recycled pid cannot loop;
  #   - EIGHT hops, which is about twice the longest real chain here
  #     (driver <- launcher <- cmd <- sshd-session <- sshd is four);
  #   - a SHARED ROOT by name: a process that serves the whole box rather than
  #     this session. That is the boundary this rule is really about, and the
  #     one it is named for: `sshd-session` is OUR connection and is excluded,
  #     while the `sshd` LISTENER above it serves every other lane's connection
  #     too and is not.
  #
  # THE NAME LIST IS A STATED LIMIT, NOT A CLASSIFIER. It cannot be complete,
  # and it does not have to be, because every way it can be wrong fails in the
  # same direction: an unlisted root stops the walk one hop late and excuses ONE
  # extra long-lived pid (never its other children, per the ordering above),
  # while a listed name that is really ours stops the walk early and excludes
  # LESS than it could. Both are under-exclusion of foreign CPU or a single pid
  # of over-exclusion; neither can blind the guard to a round. An OpenSSH old
  # enough to fork `sshd.exe` per connection rather than `sshd-session.exe`
  # lands in the second case on purpose: we stop at it and charge ourselves our
  # own connection process, which is the conservative direction and is what
  # this whole function is for.
  #
  # WHAT IT DOES NOT FIX, stated here because the failure it does not fix looks
  # identical in a log to the one it does: the DOMINANT contaminant on a
  # contended box is somebody ELSE's ssh poll landing in YOUR window - four
  # queued lanes polling intel-i5-10600kf put five distinct `sshd-session` births into
  # one 70 second run - and that CPU is real, foreign, and correctly charged.
  # This removes a lane's own observer from its own reading and nothing else.
  param([hashtable]$parentOf, [hashtable]$nameOf, [int]$self)
  $mine = New-Object 'System.Collections.Generic.HashSet[int]'
  $null = $mine.Add($self)
  if ($null -eq $parentOf) { return ,$mine }

  # 1. DOWN: the closure under $self, seeded with $self ALONE.
  $grew = $true
  while ($grew) {
    $grew = $false
    foreach ($k in @($parentOf.Keys)) {
      $kid = [int]$k
      if (-not $mine.Contains($kid) -and $mine.Contains([int]$parentOf[$k])) { $null = $mine.Add($kid); $grew = $true }
    }
  }

  # 2. UP: the chain, one pid at a time, and only after the closure above has
  #    stopped growing. Never a seed - see the trap in the header.
  $roots = @('idle', 'system', 'registry', 'memory compression', 'smss', 'csrss',
             'wininit', 'winlogon', 'services', 'lsass', 'lsaiso', 'svchost',
             'taskeng', 'taskhostw', 'explorer', 'sshd')
  $seen = New-Object 'System.Collections.Generic.HashSet[int]'
  $null = $seen.Add($self)
  $cur = $self
  for ($hop = 0; $hop -lt 8; $hop++) {
    if (-not $parentOf.ContainsKey($cur)) { break }
    $p = [int]$parentOf[$cur]
    if ($p -le 4) { break }
    if (-not $parentOf.ContainsKey($p)) { break }
    if (-not $seen.Add($p)) { break }
    $n = ''
    if ($null -ne $nameOf -and $nameOf.ContainsKey($p)) {
      $n = ([string]$nameOf[$p]).Trim().ToLowerInvariant() -replace '\.exe$', ''
    }
    if ($roots -contains $n) { break }
    $null = $mine.Add($p)
    $cur = $p
  }
  # `,` on purpose. PowerShell ENUMERATES a collection on return, so a bare
  # `return $mine` hands the caller an object[] whose .Contains() does not
  # resolve - the call then throws, the catch turns it into -1, and the guard
  # silently measures nothing for the rest of the round.
  return ,$mine
}

function Get-OwnPidTree {
  # The snapshot half: one CIM enumeration, handed to the walk above. `Name` is
  # read alongside the two pid columns because the chain's stopping rule needs
  # it; it is one more property on a query that was already enumerating every
  # process, and the walk treats a missing name as "not a root", which stops
  # nothing and excludes one more pid at most.
  $parentOf = @{}
  $nameOf = @{}
  try {
    Get-CimInstance Win32_Process -Property ProcessId,ParentProcessId,Name -ErrorAction Stop |
      ForEach-Object {
        $parentOf[[int]$_.ProcessId] = [int]$_.ParentProcessId
        $nameOf[[int]$_.ProcessId] = [string]$_.Name
      }
  } catch { $parentOf = @{}; $nameOf = @{} }
  # An enumeration that failed leaves both tables empty, and the walk then
  # returns our own pid alone - the same answer this function gave before the
  # ancestor chain existed, and the conservative one.
  $mine = Resolve-OwnPidSet $parentOf $nameOf $PID
  return ,$mine
}

function Measure-ForeignDelta {
  # THE ARITHMETIC OF Get-ForeignCpu, SPLIT OUT SO IT CAN BE TESTED, and that
  # is the whole reason it is a function of its own rather than a loop inside
  # the sampler. plib_selftest.ps1 STUBS `Get-ForeignCpu` with a scripted
  # sequence in order to drive the callers - Wait-FixtureSettle, Require-QuietBox,
  # Require-QuietCore - in seconds on a box that is busy for its own reasons, so
  # the primitive's own arithmetic was, by construction, the one thing in this
  # library that nothing could test. It is exercised here over SYNTHETIC
  # snapshots, which needs no Windows box at all and so runs on the macOS
  # runner that gates this file.
  #
  # ---------------------------------------------------------------------------
  # THE DEFECT THIS REPLACES (16 Sep 2026)
  # ---------------------------------------------------------------------------
  # The original summed `$b[$k] - $a[$k]` with `$was = 0.0` for any pid absent
  # from the BEFORE snapshot, and divided by a window it ASSUMED was 1.000 s.
  # Both halves were wrong, and they compound:
  #
  #  1. A pid absent from the before snapshot had its ENTIRE LIFETIME CPU
  #     charged to that one second. For a process genuinely BORN inside the
  #     window that is correct - all of its CPU really was spent in there - but
  #     for one that merely failed to be read in the first snapshot (a
  #     protected process whose TotalProcessorTime threw, a process the first
  #     Get-Process did not enumerate) it charges hours of accumulated CPU to
  #     one second. That is the spike source.
  #  2. The window is NOT one second. Two `Get-Process` enumerations over ~300
  #     processes bracket the sleep, and each costs real wall time, so the
  #     actual per-process spacing is the sleep PLUS one enumeration. Dividing
  #     a ~1.4 s measurement by 1.0 s overstates everything by ~1.4x, on every
  #     reading, forever.
  #
  # Measured on intel-i5-10600kf (i5-10600KF, 6c/12t) idle, with the one known heavy
  # background process already stopped: twelve 1 s samples read 25-544% of a
  # core, median 267; a calmer stretch of six read 31-81; and a per-process
  # delta over a 40 s window read 14.6%, with that 40 s attribution naming the
  # whole of it (System 5.2, MsMpEng 2.9, SRAgent 2.7, nothing else over 1).
  # There was no hidden load. Record:
  # an internal note.
  #
  # IT IS NOT COSMETIC. Require-QuietBox's ceiling is max(100, cores*100*0.10),
  # so a 12-logical box floors at 100 and a 16-core one sits at 160; waitquiet's
  # queue opens at a third of that. A box genuinely at 14.6% that READS 50-70
  # never opens its queue and is indistinguishable from a busy one - not fixed
  # by waiting, because waiting does not make Windows stop spawning svchost
  # children. That is half of why the 16 Sep digest-cache small-core round's
  # first attempt on intel-i5-10600kf never ran a single leg
  # (an internal note section 1).
  #
  # ---------------------------------------------------------------------------
  # THE FIX, AND THE TRADE IT MAKES
  # ---------------------------------------------------------------------------
  # A pid absent from the before snapshot is decided by its START TIME, not by
  # its absence:
  #
  #   - born INSIDE the window  -> charged in full. Its whole lifetime CPU
  #     genuinely was spent inside this window, so this is the correct number,
  #     not a concession.
  #   - born BEFORE the window  -> charged ZERO. We have no before reading for
  #     it and cannot invent one; its real in-window delta is bounded by the
  #     window and will be measured exactly on the NEXT sample, one second
  #     later, when it is in both snapshots.
  #   - start time unreadable   -> charged zero, same reasoning.
  #
  # THE THREE CANDIDATES, AND WHY THIS ONE. "Ignore every pid absent from the
  # before snapshot" is one line shorter and is the WRONG FIX FOR THIS USE
  # CASE: the thing these guards exist to catch is somebody else's ROUND
  # arriving on the box, and a neighbouring round's freshly spawned `parfast`
  # is precisely a newly born heavy process. Ignoring by absence blinds the
  # guard to exactly its subject. Deciding by start time keeps it - a new
  # parfast is charged in full on the first sample that sees it - while still
  # refusing the unreadable-in-snapshot-a case, which is the one that spikes.
  # "Widen the sample" fixes the spikes by averaging them down and is NOT free:
  # Require-QuietBox runs before EVERY timed leg, so a 5 s window costs 4 extra
  # seconds a leg - about 45 minutes on a 672-leg round - and Require-QuietCore
  # takes up to three samples on top. The window stays at one second and the
  # per-leg cost of this change is one extra property read per process.
  #
  # WHAT IT COSTS. A heavy process that was alive before the window but missing
  # from snapshot a is under-reported for exactly one sample. Every caller
  # samples repeatedly (Require-QuietBox retries ten times at 30 s,
  # Require-QuietCore takes a minimum of three, Wait-FixtureSettle needs three
  # consecutive clean ones), so a RESIDENT consumer cannot hide behind this for
  # longer than one sample - which is the same discriminator Require-QuietCore's
  # minimum-of-three already relies on, applied one level down.
  #
  # AND THE WINDOW IS MEASURED, not assumed: the caller passes the real
  # start-of-snapshot-a to start-of-snapshot-b span and the sum is divided by
  # it. Start-to-start and not start-to-end, because each process's two
  # readings are one enumeration apart, not one enumeration plus a sleep.
  #
  # ---------------------------------------------------------------------------
  # HOW TO READ A `foreign_cpu` BANKED BEFORE 16 Sep 2026
  # ---------------------------------------------------------------------------
  # NOTHING ALREADY PUBLISHED IS RETRACTED, and no old log is being relabelled.
  # Every `foreign_cpu=` and `foreign_after=` field in every LEG line this repo
  # holds was produced by the code above and is sound in the two ways those
  # fields are actually used:
  #
  #   - as an UPPER BOUND on foreign load. Both defects push the number UP and
  #     neither can push it down, so a leg whose field reads low really did run
  #     on a quiet box. `foreign_cpu=5.8` still means 5.8 or less.
  #   - for COMPARING LEGS WITHIN ONE ROUND. The inflation is a property of the
  #     sampler, not of the leg, so it applies about equally to every leg on one
  #     box in one round; the per-ladder medians the reducers print, and the
  #     clean-versus-contaminated contrasts they are read for (9% and 13% against
  #     36%, 77% and 88%), survive it intact.
  #
  # What it is NOT is a measure of SUSTAINED load, and a pre-16-Sep reading must
  # not be quoted as one - on the box measured above the honest figure was
  # 2-5x below what the field said in the calm case, and ~20x below it at the
  # spikes. Readings from before and after this change are also not directly
  # comparable as absolute numbers, which matters only if somebody puts an old
  # round's foreign_cpu column beside a new one's.
  #
  # $windowStart is the wall clock at the start of the before snapshot; $cores
  # only feeds a sanity clamp - a process born inside the window cannot have
  # burned more than window x cores, so anything past that is a clock or
  # pid-reuse anomaly rather than load.
  param([hashtable]$before, [hashtable]$after, [double]$windowS,
        [datetime]$windowStart, [int]$cores)
  if ($windowS -le 0) { return -1.0 }
  if ($cores -lt 1) { $cores = 1 }
  $cap = $windowS * $cores
  $delta = 0.0
  foreach ($k in $after.Keys) {
    $now = [double]$after[$k].Cpu
    $startedAt = $after[$k].Start
    $fresh = $true
    if ($before.ContainsKey($k)) {
      # PID REUSE IS A THIRD CASE, and Windows recycles pids briskly enough for
      # it to matter. Same pid, different start time, is a DIFFERENT process:
      # its predecessor's total is not a before reading for it. The old code
      # subtracted anyway and got a negative it then discarded, which happens to
      # be harmless; treating it as a birth is correct rather than harmless.
      $wasStart = $before[$k].Start
      if ($null -eq $wasStart -or $null -eq $startedAt -or $wasStart -eq $startedAt) {
        $fresh = $false
        $d = $now - [double]$before[$k].Cpu
        if ($d -gt 0) { $delta += $d }
      }
    }
    if ($fresh) {
      if ($null -eq $startedAt) { continue }
      if ($startedAt -lt $windowStart) { continue }
      $d = $now
      if ($d -gt $cap) { $d = $cap }
      if ($d -gt 0) { $delta += $d }
    }
  }
  return [math]::Round(($delta / $windowS) * 100.0, 1)
}

function Get-ForeignCpu {
  # CPU seconds consumed OUTSIDE our own process tree over a roughly one second
  # window, expressed as a percentage of one core (so 100 = one core fully busy
  # by somebody else). Returns -1 when it cannot be measured, and the caller then
  # continues rather than blocking a round on a missing counter.
  #
  # The window is roughly a second and the arithmetic divides by the span it
  # actually measured; the rest of the reasoning - and what this does to
  # readings banked before 16 Sep 2026 - is in Measure-ForeignDelta above.
  try {
    $mine = Get-OwnPidTree
    $snap = {
      $h = @{}
      foreach ($p in (Get-Process -ErrorAction SilentlyContinue)) {
        if ($mine.Contains($p.Id)) { continue }
        # A process whose CPU counter cannot be read is SKIPPED ENTIRELY rather
        # than recorded as zero: recorded as zero in the before snapshot it
        # would read as a birth in the after one, which is the defect.
        # `continue` out of a catch is left alone on purpose - the branch is
        # taken outside it.
        $cpu = $null
        try { $cpu = $p.TotalProcessorTime.TotalSeconds } catch { $cpu = $null }
        if ($null -eq $cpu) { continue }
        # Throws for protected processes (System, Registry, csrss and friends).
        # $null then means "unknown", which Measure-ForeignDelta treats as
        # pre-existing - the conservative direction.
        $st = $null
        try { $st = $p.StartTime } catch { $st = $null }
        $h[$p.Id] = [pscustomobject]@{ Cpu = [double]$cpu; Start = $st }
      }
      return ,$h
    }
    $cores = [int]$env:NUMBER_OF_PROCESSORS
    if ($cores -lt 1) { $cores = [Environment]::ProcessorCount }
    $t0 = Get-Date
    $sw = [Diagnostics.Stopwatch]::StartNew()
    $a = & $snap
    Start-Sleep -Milliseconds 1000
    # BEFORE the second enumeration, not after it: each process's two readings
    # are one enumeration apart.
    $windowS = $sw.Elapsed.TotalSeconds
    $b = & $snap
    $sw.Stop()
    return Measure-ForeignDelta $a $b $windowS $t0 $cores
  } catch { return -1.0 }
}

function Require-QuietBox([string]$where) {
  # A leg measured on a box carrying somebody else's work is not slow, it is
  # WRONG, and nothing downstream can tell the difference: the exit code is 0
  # and the SHA gate still passes. The rig lock cannot catch it, because a lock
  # only excludes lanes that agreed to take it. Load can be seen whoever caused
  # it. The ceiling is 10% of the whole box, floored at one core.
  # It WAITS before it gives up. A Defender pass or a Windows Update scan is
  # transient, and killing a twelve hour overnight round over thirty seconds of
  # someone else's CPU trades one kind of lost night for another. Ten retries
  # at thirty seconds, then abort.
  #
  # IT RETURNS NOTHING, AND THE READING COMES BACK IN $script:lastforeign.
  # This function LOGS through `Write-PlibLine` (BOX-BUSY-WAIT has to reach the
  # round log, and since 16 Sep 2026 that means the FILE as well as stdout -
  # see the ROUND LOG SINK block at the head of this file; the ABORT-LOAD line
  # is the one this matters most for, because it is the round's cause of death)
  # and PowerShell makes no distinction between logging and
  # returning: a `return $pct` here hands the caller EVERY line the function
  # emitted as well, as an array. On 11 Sep 2026 that put the guard's own wait
  # line inside a LEG line -
  #   foreign_cpu=BOX-BUSY-WAIT try=1 foreign_cpu=343.8 ceiling=160 at=... 59.4
  # - so that leg's `foreign_cpu` field read as the PRE-WAIT spike the guard had
  # just waited out rather than the quiet 59.4 the leg actually ran under, and
  # every field after it on the line was displaced by one. The leg itself was
  # sound; only its record was wrong, which is the worse of the two failures
  # because nothing downstream can see it. jcross.ps1 met the same PowerShell
  # rule twice (its notes on $script:lastwall and Get-StageLabels) and answers
  # it the same way, which is why this is a $script: variable and not a
  # cleverer return.
  $cores = [int]$env:NUMBER_OF_PROCESSORS
  if ($cores -lt 1) { $cores = 1 }
  $ceiling = [math]::Max(100.0, $cores * 100.0 * 0.10)
  $pct = Get-ForeignCpu
  $script:lastforeign = $pct
  if ($pct -lt 0) { return }
  $tries = 0
  while ($pct -ge $ceiling -and $tries -lt 10) {
    $tries++
    Write-PlibLine "BOX-BUSY-WAIT try=$tries foreign_cpu=$pct ceiling=$ceiling at=$where ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    Start-Sleep -Seconds 30
    $pct = Get-ForeignCpu
    $script:lastforeign = $pct
    if ($pct -lt 0) { return }
  }
  if ($pct -ge $ceiling) {
    $mine = Get-OwnPidTree
    $top = (Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $mine.Contains($_.Id) -and $_.CPU -gt 1 } |
            Sort-Object CPU -Descending | Select-Object -First 4 |
            ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join ' '
    Write-PlibLine "BOX-BUSY foreign_cpu=$pct ceiling=$ceiling cores=$cores top=[$top]"
    Write-PlibLine "ABORT-LOAD at=$where ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    exit 18
  }
  $script:lastforeign = $pct
  Require-QuietCore $where
}

function Require-QuietCore([string]$where) {
  # THE SECOND ARM, and the reason the ceiling above cannot be the only one.
  #
  # That ceiling is 10% of the whole box FLOORED AT ONE CORE, so one saturated
  # core passes it on a box of any size - by construction, independent of core
  # count. By 16 Sep 2026 that arithmetic had hidden five distinct things: a
  # foreign lane's pinned single-core round on intel-core-ultra-9-386h, Windows Search at
  # 87% of one core, SignalRgb resident on amd-ryzen-9800x3d at 31.7%, any rars / cargo
  # / nextest run in principle, and - measured on the unix half the same day -
  # spotlightknowledged.updater at 99.6% of ONE core on apple-m3-ultra, whose
  # 134.9% total sat comfortably under its 320% ceiling while the guard said
  # quiet. Record:
  # an internal note.
  #
  # DO NOT LOWER THE BOX-WIDE CEILING TO CATCH THESE. It is aimed at somebody
  # else's whole ROUND, and one low enough to catch a single core aborts
  # (exit 18) on boxes that are merely normally busy. Two failures, two
  # mechanisms, two thresholds - which is what Wait-FixtureSettle below has
  # said at length since 16 Sep, and this is that reasoning applied to the
  # guard every timed leg already goes through.
  #
  # THE THRESHOLD IS 25% OF ONE CORE, Wait-FixtureSettle's, shared on purpose
  # so the two platforms do not diverge on a quantity that has been identical
  # by construction until now (pdrv.py's PER_CORE_CEILING_PCT is the same 25
  # and carries the unix half of this note). Its calibration is that
  # function's: clean ladders at 9% and 13% of a core, after-leg medians
  # 16-17%, contaminated ones at 36%, 77% and 88%. Two later points bracket it
  # from outside - a genuinely quiet box measured over ten samples on 16 Sep
  # read a median of 2.0% and a max of 4.0% of one core, and SignalRgb sits at
  # 31.7% - so 25 has about 6x headroom over idle jitter and still sits under
  # every contaminant anyone has caught.
  #
  # IT NEVER ABORTS, AND THAT IS MEASURED RATHER THAN TIMID. mred.py records a
  # 135-leg round on a real bench box at a foreign_cpu median of 25.8% and a
  # p90 of 133.5%, and apple-m1-ultra-64gb was measured on 16 Sep with WindowServer
  # resident at 43-46% of a core across ten consecutive samples. An arm at 25
  # that called `exit 18` would kill about half of one of those rounds and all
  # of the other, which is how a gate gets commented out. So it WAITS on the
  # ceiling's budget, then says so, names the busiest foreign processes, and
  # lets the leg run - the same bargain Wait-FixtureSettle strikes, for the
  # same reason.
  #
  # ONE SAMPLER HERE, TWO ON UNIX, and that asymmetry is not an oversight.
  # Get-ForeignCpu is already a one second DELTA window, so it means "right
  # now" and both arms can read it. pdrv.py's deployed foreign_cpu() reads
  # `ps -o pcpu`, which on Linux is a LIFETIME average - measured 16 Sep:
  # 99.8 -> 50.0 -> 22.2 -> 12.1 -> 6.3 over four minutes idle after an eight
  # second burn, i.e. cpu_time/elapsed exactly - so the unix half had to grow
  # a delta sampler of its own before it could express a tight threshold at
  # all. This file needed no such thing; it had the right sampler first.
  #
  # CONFIRM BY MINIMUM, AND ONLY WHEN THE FIRST SAMPLE IS SUSPICIOUS. A one
  # second window cannot tell a core pinned for ninety seconds from a process
  # that lived for one and a half, and at a 25% threshold that difference is
  # most of the traffic. Reported by the create-width-additive-kernel-gfni-16sep
  # lane from intel-core-ultra-9-386h and REPRODUCED here on amd-ryzen-9800x3d 16 Sep 2026: a
  # WATCHING session polling the box over ssh spawns a PowerShell under SSHD,
  # which is outside the round's pid tree by construction, and PowerShell 5.1
  # startup is about a core-second of module autoload. Measured on this box,
  # same script, ten samples each:
  #
  #     undisturbed          min 26.6  median 43.8  max  84.4
  #     under an ssh poll    min 92.2  median 253.1 max 339.1
  #
  # The observer is the contaminant, and the top row is this box's RESIDENT
  # load (SignalRgb) rather than noise. Note the second row also clears the
  # 160% BOX-WIDE ceiling on this 16-core part, so a watched round can already
  # be aborted at exit 18 by its own watcher - that is a pre-existing hazard in
  # the arm above, not something this one introduces, and it is why this arm
  # must not add a second way to lose a round.
  #
  # So: take the MINIMUM of three samples. A transient spike is in at most one
  # of them; a resident consumer is in all three. SignalRgb survives the
  # minimum here (26.6 at its lowest, still over 25), which is the discriminator
  # working in both directions at once on one box.
  #
  # THE EXTRA SAMPLES ARE ONLY PAID WHEN THE FIRST ONE IS OVER, and that is the
  # difference between this costing nothing and costing a round. Get-ForeignCpu
  # is a one second window and this guard runs before EVERY timed leg, so three
  # unconditional samples would add two seconds a leg - about 22 minutes on a
  # 672-leg round like the one that produced this finding. A quiet box trips the
  # early return on its first sample and pays nothing extra.
  #
  # NO RETRY LOOP, unlike the arm above. Waiting is what the box-wide ceiling
  # does about somebody else's ROUND, which ends; the consumers THIS arm is for
  # are resident and relaunch at logon (SignalRgb) or run for the length of an
  # indexing pass, so thirty second sleeps would buy nothing and cost the round
  # ten of them per leg.
  #
  # The reading comes back in $script:lastforeign1core, NOT as a return value -
  # see Require-QuietBox above on why a PowerShell function must not log AND
  # return. Its two lines go through `Write-PlibLine`, so they reach the
  # round's LOG as well as stdout when a driver or launcher has opted in - read
  # the ROUND LOG SINK block at the head of this file. This arm needs that more
  # than most of them: it never aborts, so its BOX-ONE-CORE-BUSY line is the
  # ONLY record that a leg ran on a box carrying a saturated foreign core, and
  # a `foreign_1core` field on a leg line is a number rather than a verdict.
  $thresh = 25.0
  $pct = Get-ForeignCpu
  $script:lastforeign1core = $pct
  if ($pct -lt 0 -or $pct -lt $thresh) { return }
  $lo = $pct
  for ($i = 0; $i -lt 2; $i++) {
    Start-Sleep -Milliseconds 700
    $v = Get-ForeignCpu
    if ($v -lt 0) { return }
    if ($v -lt $lo) { $lo = $v }
  }
  $script:lastforeign1core = $lo
  if ($lo -ge $thresh) {
    $mine = Get-OwnPidTree
    $top = (Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $mine.Contains($_.Id) -and $_.CPU -gt 1 } |
            Sort-Object CPU -Descending | Select-Object -First 4 |
            ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join ' '
    Write-PlibLine "BOX-ONE-CORE-BUSY at=$where foreign_1core=$lo thresh=$thresh cores=$env:NUMBER_OF_PROCESSORS top=[$top]"
    Write-PlibLine "BOX-ONE-CORE-NOTE the leg RUNS; read its foreign_1core and the reducers' per-ladder median before trusting a number from it"
  }
}

function Wait-FixtureSettle {
  # A FRESHLY BUILT fixture is work the box does to ITSELF, and Require-QuietBox
  # above cannot see it. On 16 Sep 2026 lane parfast-windowed-ask-form-16sep
  # built a 10.7 GB fixture (16 x 512 MiB) in a source tree it had extracted
  # minutes earlier, and Windows Search walked both through the first half of
  # the round: SearchIndexer + SearchProtocolHost + SearchFilterHost at about
  # 87% of ONE core, measured by process while the round ran, with Defender at
  # 5% and not the cause. Two of five ladders are unusable - foreign CPU medians
  # of 77% and 88% of a core against the 9% the clean one ran at, A/A floors of
  # 2.4-17.3% against 2.1-2.9% - and the tell was a PHYSICAL IMPOSSIBILITY in
  # the reduced result rather than anything the harness said
  # (an internal note, "The windowed ask's
  # FORM"). The guard never fired because 87% of one core is ~5.4% of a 16-core
  # box, far under its 10%-of-the-box ceiling. That ceiling is NOT the thing to
  # lower: it is aimed at somebody else's ROUND on the box, and a ceiling low
  # enough to catch an indexer aborts (exit 18) on boxes that are merely
  # normally busy. Two failures, two mechanisms.
  #
  # THE THRESHOLD IS 25% OF ONE CORE, and it is picked off that round rather
  # than guessed. The clean ladders sat at 9% and 13% of a core with their
  # after-leg medians at 16-17%, so 25 clears the idle jitter of a quiet box;
  # the contaminated ones sat at 36%, 77% and 88%, so 25 is well below anything
  # this failure has ever presented at. Expressed per CORE and not per box on
  # purpose - the quantity that ruins a ladder is one saturated service thread,
  # and scaling it by the core count is exactly the arithmetic that hid this.
  #
  # IT NEVER ABORTS. A round that has already paid for a fixture is not
  # improved by being killed, and these are research logs a human reads: past
  # the cap it says so on a line, names the four busiest foreign processes, and
  # runs anyway. The per-leg `foreign_cpu` field and the reducers' per-ladder
  # medians are what let that round be judged afterwards.
  #
  # AND IT LOGS WHETHER IT WAITED OR NOT. A silent guard is how the 16 Sep
  # round got past one, so FIXTURE-SETTLE is on the line every time, with the
  # seconds waited and the reading it settled at.
  #
  # AND SINCE 16 Sep 2026 THAT LINE GOES TO THE ROUND'S LOG AS WELL AS STDOUT,
  # because until then this header's claim was true of the library and false of
  # the artefact. Every emit here was a bare string - stdout and nothing else -
  # while the drivers with their own `Log` bank a FILE, so the verdict was in
  # neither the banked round nor anything a later reader saw. The enrol-threads
  # round hit this cap TWICE that day on both boxes and its two GAVE-UP lines
  # survived only because stdout happened to be redirected to a scratch file.
  # Read the ROUND LOG SINK block at the head of this file; every line below
  # goes through `Write-PlibLine`, and a driver or launcher opts in with
  # `Set-PlibLog` or `$env:PLIB_LOG`.
  #
  # $thresh and $capS are parameters ONLY so the selftest can drive both arms
  # in seconds on a box that is busy for its own reasons - every round takes the
  # defaults, and a round that passes its own is not doing what this is for.
  param([string]$where, [double]$thresh = 25.0, [int]$capS = 1200)
  $need = 3          # consecutive clean samples; Get-ForeignCpu is a 1 s window
  $gap = 10          # seconds between samples
  $every = 6         # log a WAIT line on the first busy sample, then ~per minute
  $t0 = [Diagnostics.Stopwatch]::StartNew()
  $clean = 0
  $busy = 0
  $pct = Get-ForeignCpu
  if ($pct -lt 0) {
    Write-PlibLine "FIXTURE-SETTLE skipped=no-counter at=$where ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    return
  }
  while ($clean -lt $need -and $t0.Elapsed.TotalSeconds -lt $capS) {
    if ($pct -lt $thresh) {
      $clean++
      if ($clean -ge $need) { break }
    } else {
      if ($busy % $every -eq 0) {
        Write-PlibLine "FIXTURE-SETTLE-WAIT foreign_cpu=$pct thresh=$thresh waited_s=$([math]::Round($t0.Elapsed.TotalSeconds,0)) cap_s=$capS at=$where"
      }
      $busy++
      $clean = 0
    }
    Start-Sleep -Seconds $gap
    $pct = Get-ForeignCpu
    if ($pct -lt 0) {
      Write-PlibLine "FIXTURE-SETTLE skipped=counter-lost at=$where waited_s=$([math]::Round($t0.Elapsed.TotalSeconds,0))"
      return
    }
  }
  $t0.Stop()
  $waited = [math]::Round($t0.Elapsed.TotalSeconds, 0)
  if ($clean -ge $need) {
    Write-PlibLine "FIXTURE-SETTLE ok=1 foreign_cpu=$pct thresh=$thresh waited_s=$waited busy_samples=$busy at=$where ts=$((Get-Date).ToUniversalTime().ToString('o'))"
  } else {
    $mine = Get-OwnPidTree
    $top = (Get-Process -ErrorAction SilentlyContinue | Where-Object { -not $mine.Contains($_.Id) -and $_.CPU -gt 1 } |
            Sort-Object CPU -Descending | Select-Object -First 4 |
            ForEach-Object { $_.ProcessName + '(' + $_.Id + ')' }) -join ' '
    Write-PlibLine "FIXTURE-SETTLE ok=0 GAVE-UP foreign_cpu=$pct thresh=$thresh waited_s=$waited cap_s=$capS at=$where top=[$top] ts=$((Get-Date).ToUniversalTime().ToString('o'))"
    Write-PlibLine "FIXTURE-SETTLE-NOTE the round CONTINUES; read every leg's foreign_cpu and the reducers' per-ladder median before trusting a number from it"
  }
}

# --- leg CPU affinity -------------------------------------------------------
#
# Added 16 Sep 2026 for lane parfast-4mib-pinned-affinity-pools, which needs to
# separate POOL SIZE from CORE MIX on a hybrid part. intel-core-ultra-9-386h is 16C/16T in
# THREE classes (cores 0-3 P at ~5.0 GHz, 4-11 E at 3.89, 12-15 LP-E at 3.49),
# and `.claude/MACHINES.md` measures a 1.43x single-thread swing decided purely
# by where Windows puts an unpinned thread. So a `-t4` ladder measures "four
# threads as Windows places them", NOT four P-cores, and a `-t4` result read
# against a `-t16` one has the pool size confounded with the core mix.
#
# THE MASK IS APPLIED AFTER Start(), AND THAT IS A STATED LIMIT, not an
# oversight: ProcessStartInfo cannot create a process suspended, so the child's
# first instants run under the inherited mask. It is microseconds against a
# ~45 s leg, and it cannot reach the thread pool this measures because every
# pinned arm passes -t<n> EXPLICITLY rather than letting the child count cores.
# A round that let the child auto-detect its pool WOULD be exposed to it.
#
# THE MASK IS READ BACK, and that half is the point. A pin that silently failed
# would publish an UNPINNED leg under a pinned arm's name, which is the exact
# failure the rowgate phases already refuse for a transform leg that folded.
# So the readback travels on the leg line as `affinity_got`, and the caller
# refuses the cell rather than this function throwing mid-leg and orphaning a
# 16 GiB repair.
#
# PriorityClass is deliberately NOT touched here, though the pattern this
# copies (an internal note) sets High. A round
# whose unpinned arm is a CONTROL against an already-banked unpinned ladder
# must differ from it in affinity and in nothing else; raising priority on the
# pinned arms only would make placement and priority move together and neither
# readable.
$script:legAffinity = 0

function Set-LegAffinity([long]$mask) {
  # 0 clears it: every subsequent leg runs as the box places it.
  $script:legAffinity = $mask
}

function Get-LegAffinity { $script:legAffinity }

# ---------------------------------------------------------------- POWER STATE
# Package power and core frequency per leg, added 18 Sep 2026 for lane
# cf-load-term-buffer-and-placement-18sep. Candidate 3 for the unexplained
# residual in the `c_f` drift census is THERMAL OR POWER DRIFT ACROSS A
# SITTING, and that census could not test it at all - not because the evidence
# was ambiguous but because no LEG line in the whole banked corpus carries
# either quantity, so there was nothing to reduce. This is the field that makes
# it testable from banked logs from now on; it settles nothing by itself.
#
# WHAT IS AVAILABLE ON THIS FLEET, MEASURED ON intel-i5-10600kf 18 Sep 2026 RATHER
# THAN ASSUMED, because the honest answer is "one of the two":
#
#   FREQUENCY - YES, and NOT from where you would first reach for it.
#   `Win32_Processor.CurrentClockSpeed` read 3801 MHz in the same second that
#   the perf counter read 113% of nominal, i.e. ~4295 MHz: that property is the
#   NOMINAL speed restated, it equals MaxClockSpeed on this part, and a round
#   that logged it would publish a dead constant under a live-sounding name -
#   which is worse than logging nothing, because it reads as evidence that
#   frequency did not drift. The live figure is the `Processor Information`
#   counter's `PercentProcessorPerformance` against nominal. Both the percent
#   and the derived MHz travel, so a reader can check the derivation.
#
#   PACKAGE POWER - NO, and it cannot be had here without installing software
#   on somebody's box. Intel exposes package watts through RAPL MSRs, which
#   Windows does not surface to user mode at all: there is no `root\OpenHardwareMonitor`
#   or `root\LibreHardwareMonitor` namespace on this box, no Intel Power Gadget,
#   and `Win32_Battery` is absent because it is a desktop, so the `Power Meter`
#   ACPI counter set that laptops and some servers carry has no instance either.
#   Every remaining route needs a KERNEL DRIVER. So `pkg_w` is emitted as `na`
#   rather than omitted: the field exists so a box that CAN read it needs no
#   format change and no reducer edit, and so its absence is a recorded fact in
#   every log rather than a column a later reader wonders about. Getting real
#   watts is a decision for the maintainer about installing a driver on a shared timing
#   box, not something a lane may do on its own.
#
#   TEMPERATURE AND PASSIVE THROTTLE - YES, and they are the useful proxy while
#   watts are missing. Thermal drift's whole signature is the part getting
#   hotter and clocking down, and `temp_c` falling with `freq_mhz` across a
#   sitting is that signature without needing watts at all. RE-TENSED 18 Sep
#   2026: half of that signature is unavailable - see the banner below, which
#   finds the frequency half of this function unreadable. TEMPERATURE alone
#   still answers "did this box heat at all", which is the cheap stand-down the
#   candidate-3 design puts before any long sitting.
#
# COST, AND WHY IT CONTAMINATES NOTHING. The sample costs a few hundred
# milliseconds of CPU. That is large next to a 3.6 s leg and would be a real
# problem if it landed INSIDE one - it does not. Invoke-Leg's `$watch` starts at
# `$proc.Start()` and stops at `WaitForExit`, and both samples are taken
# outside that span, so they cost the SITTING wall-clock time and cost no CELL
# anything. The same is already true of `Get-ForeignCpu`, which samples for a
# full second twice per leg.
#
# IT NEVER THROWS. A counter class that is missing, renamed or momentarily
# unavailable returns the `na` shape, exactly as Get-ForeignCpu returns -1: a
# round must not die mid-leg, orphaning a child, over an instrument that is only
# ever additional evidence.
#
# ==========================================================================
# THE FREQUENCY HALF OF THIS FUNCTION IS BROKEN. `FreqMhz` AND `PerfPct` MUST
# NOT BE REDUCED OR QUOTED. Found 18 Sep 2026 by lane
# `cf-thermal-drift-candidate3-18sep`; full argument and the proposed fix in
# `rounds/cf-thermal-drift-2026-09-18/README.md`.
#
# `PercentProcessorPerformance` is a DELTA counter and the query below is a
# SINGLE un-refreshed one. That is the same mistake, through a different API,
# that an internal note section 2a was written about
# and whose rule 1 is "never sample this counter single-shot"; that rule names
# `Get-Counter`, this reaches the counter through WMI's cooked provider
# instead, and the structural problem - it needs two refreshes of its cache and
# a lone query gives it one - is identical.
#
# THE EVIDENCE IS THE SIX VALIDATION LEGS THIS FUNCTION'S OWN LANE BANKED, and
# the argument is internal to that single log (`rounds/
# cf-load-term-buffer-2026-09-18/pwr.log`, intel-i5-10600kf): every leg held 9.4-11.0
# of 12 threads busy for its whole duration, every temperature sample in the
# sitting read 27.9 C, and `freq_after_mhz` nonetheless spans 912-2585 MHz - a
# 2.83x range with everything that could move it held fixed. The level is wrong
# as well as the spread: on the same idle box, the route section 2a PROVED
# reads 109.74-110.45% of nominal where this one reads 24-30%.
#
# WHY SWAPPING IN `-SampleInterval 1 -MaxSamples 2` IS NOT THE FIX. It is the
# right rule in the wrong place: a delta counter needs an interval, `$pwr1` is
# taken within ~300 ms of the child exiting, and an interval starting there
# integrates the idle decay rather than the leg. The fix is to bracket the leg
# with the RAW class and divide the deltas here, which returns the average over
# exactly the leg's own window and retires wcomb.ps1's stated "brackets, does
# not average" limit rather than working around it. It is NOT applied here
# because it is UNVERIFIED ON A BOX - every Windows timing box in the fleet was
# held and saturated - and an untested edit to this file is executed by other
# lanes' live rounds. Validate with
# `rounds/cf-thermal-drift-2026-09-18/pwrcheck2.ps1` FIRST.
#
# TEMPERATURE AND `ThrottlePct` ARE SOUND and nothing here impugns them: both
# are instantaneous gauges, so one query is the correct way to read them and
# the bracket means what it says. `ThrottlePct` is `PercentPassiveLimit` and
# reads 100 when NOTHING is throttling - a drop below 100 is the signal.
# ==========================================================================
$script:nominalMhz = 0
function Get-PowerState {
  $r = [ordered]@{ FreqMhz = ''; PerfPct = ''; TempC = ''; ThrottlePct = ''; PkgW = 'na' }
  try {
    if (-not $script:nominalMhz) {
      $script:nominalMhz = [int](Get-CimInstance Win32_Processor -ErrorAction Stop |
                                 Select-Object -First 1 -ExpandProperty MaxClockSpeed)
    }
    $p = Get-CimInstance Win32_PerfFormattedData_Counters_ProcessorInformation `
           -Filter "Name='_Total'" -ErrorAction Stop | Select-Object -First 1
    if ($p -and $p.PercentProcessorPerformance -ne $null) {
      $r.PerfPct = [int]$p.PercentProcessorPerformance
      if ($script:nominalMhz) {
        $r.FreqMhz = [int][math]::Round($script:nominalMhz * $r.PerfPct / 100.0)
      }
    }
  } catch { }
  try {
    $tz = Get-CimInstance Win32_PerfFormattedData_Counters_ThermalZoneInformation `
            -ErrorAction Stop | Select-Object -First 1
    # The counter is in KELVIN despite the name, so 301 is 27.9 C and not a
    # broken reading. Converted here so no reducer has to know that.
    if ($tz -and $tz.Temperature) { $r.TempC = [math]::Round([double]$tz.Temperature - 273.15, 1) }
    if ($tz -and $tz.PercentPassiveLimit -ne $null) { $r.ThrottlePct = [int]$tz.PercentPassiveLimit }
  } catch { }
  return [pscustomobject]$r
}

function Invoke-Leg {
  # $envExtra overlays the child's environment, for the joint Forney solver
  # ("fast mode"): it ships as a CLI switch AND as NZBFAST_FORNEY_JOINT, default
  # off either way, so an A/B is two arms of the SAME binary and the arms cannot
  # differ by anything but the switch. Optional and last, so every existing
  # caller is unaffected.
  param([string]$exepath, [string]$argstr, [string]$cwd, [string]$logbase,
        [hashtable]$envExtra)
  # Sampled BEFORE the leg. That is necessary and not sufficient: a neighbour
  # that starts mid-leg is invisible to it, and on 11 Sep 2026 a round polled a
  # quiet box during another round's I/O-bound restore phase, read 89% foreign,
  # and then ran its leg alongside that round's next tool. A 19-minute leg is a
  # long window to be blind in, so the reading is taken again AFTER the leg and
  # BOTH travel on the leg line.
  # NOT `$foreign = Require-QuietBox ...`. That captures the guard's log lines
  # along with its reading - see the note in Require-QuietBox.
  Require-QuietBox ([IO.Path]::GetFileName($logbase))
  $foreign = $script:lastforeign
  # OUTSIDE the timed window on purpose - see Get-PowerState's cost note.
  $pwr0 = Get-PowerState
  $psi = New-Object Diagnostics.ProcessStartInfo
  $psi.FileName = $exepath
  $psi.Arguments = $argstr
  $psi.WorkingDirectory = $cwd
  $psi.UseShellExecute = $false
  $psi.RedirectStandardOutput = $true
  $psi.RedirectStandardError = $true
  # AND BOTH STREAMS ARE DECODED AS UTF-8, EXPLICITLY. Without these two lines
  # a redirected stream is decoded in the CONSOLE CODEPAGE (437 on
  # intel-core-ultra-9-386h, 850 on the NUC), and the damage lands in two stages, only the
  # first of which is reversible. Stage 1: parfast separates the fields of its
  # `mem-floor:` lines with U+00B7 MIDDLE DOT, `C2 B7` in UTF-8, so a CP437
  # decode turns one character into two and `[IO.File]::WriteAllText` below
  # banks `E2 94 AC E2 95 96` - a VALID-UTF-8 `<U+252C><U+2556>` where a middle
  # dot belongs. Stage 2: a driver echoes those `.err` lines to stdout as
  # TIMING lines, `cmd /c ... >` applies the console encoding AGAIN to
  # characters the codepage cannot represent, and it emits the
  # unmappable-character `?`. That one is NOT reversible, and it has already
  # cost a post-hoc rewrite of two banked round logs (256 copies in
  # `oramnuc1.log`, 128 in `oramnuc2.log`), because
  # `website/tools/export_parfast_evidence.py` correctly REFUSES a file it
  # cannot decode as UTF-8.
  # Measured on intel-core-ultra-9-386h (PowerShell 5.1.26100.9444, console cp 437,
  # 20 Sep 2026) with a child writing the two raw bytes to its stderr handle:
  # without these lines the `.err` file holds `E2 94 AC E2 95 96`, with them it
  # holds `C2 B7`.
  # `[Console]::OutputEncoding` is the SEPARATE, per-DRIVER half of this - it is
  # what keeps a driver's OWN round log clean - and it is deliberately not set
  # here: this function decodes other people's output and must not reach into
  # the console of whoever dot-sourced it.
  # The one behaviour this trades away, stated rather than discovered later: a
  # child that emits bytes which are NOT valid UTF-8 now decodes to U+FFFD
  # where CP437 would have given some readable character. Every tool a leg runs
  # here writes UTF-8 or pure ASCII, and a replacement character that survives
  # into a banked log is a visible defect, where the two-stage mangling above
  # is not.
  $psi.StandardOutputEncoding = [Text.Encoding]::UTF8
  $psi.StandardErrorEncoding = [Text.Encoding]::UTF8
  $psi.CreateNoWindow = $true
  if ($envExtra) { foreach ($k in $envExtra.Keys) { $psi.EnvironmentVariables[$k] = [string]$envExtra[$k] } }
  $proc = New-Object Diagnostics.Process
  $proc.StartInfo = $psi
  $watch = [Diagnostics.Stopwatch]::StartNew()
  $null = $proc.Start()
  # Pinned before the first I/O completes; see the affinity note above Invoke-Leg.
  $affWant = $script:legAffinity
  $affGot  = 0
  if ($affWant) {
    try {
      $proc.ProcessorAffinity = [IntPtr]$affWant
      $affGot = [long]$proc.ProcessorAffinity
    } catch {
      $affGot = -1
    }
  }
  $taskout = $proc.StandardOutput.ReadToEndAsync()
  $taskerr = $proc.StandardError.ReadToEndAsync()
  $proc.WaitForExit()
  $watch.Stop()
  $sout = $taskout.Result
  $serr = $taskerr.Result
  $foreignAfter = Get-ForeignCpu
  # The AFTER sample is the one that carries the signal: a leg that ran long
  # enough to heat the part reports its end state here, and the pair brackets
  # the leg the way foreign/foreignAfter already do.
  $pwr1 = Get-PowerState
  $peakbytes = [PMem]::PeakWS($proc.Handle)
  $cpusecs = $proc.TotalProcessorTime.TotalSeconds
  $rcode = $proc.ExitCode
  [IO.File]::WriteAllText("$logbase.out", $sout)
  [IO.File]::WriteAllText("$logbase.err", $serr)
  $proc.Dispose()
  New-Object psobject -Property @{
    rc      = $rcode
    wall    = [math]::Round($watch.Elapsed.TotalSeconds, 3)
    cpu     = [math]::Round($cpusecs, 3)
    peakmb  = [math]::Round($peakbytes / 1MB, 1)
    errlen  = $serr.Length
    outlen  = $sout.Length
    # Published on the leg line, not just used for the refusal: a clean leg and
    # a leg that shared the box are identical in wall, rc and the hash gate, so
    # the evidence has to travel WITH the number or a reader cannot check it.
    foreign = $foreign
    foreignAfter = $foreignAfter
    # Both travel, and the CALLER compares them: want != got is a leg that did
    # not run where its arm says it ran, and is refused rather than reported.
    affWant = $affWant
    affGot  = $affGot
    # Candidate 3's evidence. ADDITIVE and last, so every existing reducer that
    # reads this object by name is untouched.
    pwr0    = $pwr0
    pwr1    = $pwr1
  }
}

# Deterministic scattered damage. Picks $mblocks of the set's slices with a
# seeded Fisher-Yates over the GLOBAL slice index and overwrites each with
# seeded pseudo-random bytes, clamped at end of file so a partial final slice is
# not extended. Damage depends only on (dir shape, slice, mblocks, seed), so
# every tool at a rung repairs byte-identical damage.
function Invoke-Damage {
  param([string]$dir, [string[]]$members, [int]$slicesize, [int]$mblocks, [int]$dseed)
  $counts = @(); $lens = @(); $total = 0
  foreach ($nm in $members) {
    $flen = (Get-Item (Join-Path $dir $nm)).Length
    $cnt = [int][math]::Ceiling($flen / $slicesize)
    $counts += $cnt; $lens += $flen; $total += $cnt
  }
  if ($mblocks -gt $total) { throw "damage $mblocks exceeds $total slices" }
  $order = New-Object int[] $total
  for ($i = 0; $i -lt $total; $i++) { $order[$i] = $i }
  $rng = New-Object Random($dseed)
  for ($i = $total - 1; $i -gt 0; $i--) {
    $j = $rng.Next($i + 1)
    $tmp = $order[$i]; $order[$i] = $order[$j]; $order[$j] = $tmp
  }
  # group the picks by member, ascending offset, so each file opens once
  $bymember = @{}
  for ($k = 0; $k -lt $mblocks; $k++) {
    $g = $order[$k]
    $mi = 0
    while ($g -ge $counts[$mi]) { $g -= $counts[$mi]; $mi++ }
    if (-not $bymember.ContainsKey($mi)) { $bymember[$mi] = New-Object Collections.ArrayList }
    $null = $bymember[$mi].Add($g)
  }
  $fill = New-Object byte[] $slicesize
  $frng = New-Object Random($dseed + 1)
  $written = 0
  foreach ($mi in ($bymember.Keys | Sort-Object)) {
    $path = Join-Path $dir $members[$mi]
    $fs = [IO.File]::Open($path, 'Open', 'Write', 'None')
    foreach ($si in ($bymember[$mi] | Sort-Object)) {
      $off = [int64]$si * $slicesize
      $n = [int][math]::Min([int64]$slicesize, $lens[$mi] - $off)
      $frng.NextBytes($fill)
      $null = $fs.Seek($off, 'Begin')
      $fs.Write($fill, 0, $n)
      $written++
    }
    $fs.Close()
  }
  if ($written -ne $mblocks) { throw "damage wrote $written of $mblocks" }
  $written
}

# SHA-256 restoration gate. Never gate on an exit code: MultiPar returns 16 on a
# SUCCESSFUL repair.
function Test-Restored {
  param([string]$dir, [string[]]$members, [hashtable]$gold)
  $good = 0; $bad = New-Object Collections.ArrayList
  foreach ($nm in $members) {
    $h = (Get-FileHash (Join-Path $dir $nm) -Algorithm SHA256).Hash
    if ($h -eq $gold[$nm]) { $good++ } else { $null = $bad.Add($nm) }
  }
  New-Object psobject -Property @{ good = $good; bad = @($bad) }
}

# Put the work directory back to pristine: restore any member that is not
# byte-identical, and delete every file the tools left behind (numbered backups
# are what reached 157 GB in an earlier round).
function Reset-Work {
  param([string]$work, [string]$pristine, [string[]]$members, [string[]]$parfiles, [string[]]$badlist)
  foreach ($nm in $badlist) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
  $wanted = @{}
  foreach ($nm in $members)  { $wanted[$nm] = $true }
  foreach ($nm in $parfiles) { $wanted[$nm] = $true }
  foreach ($f in (Get-ChildItem $work -File)) {
    if (-not $wanted.ContainsKey($f.Name)) { Remove-Item $f.FullName -Force }
  }
  # a tool may also have altered a par2 file; restore the set unconditionally,
  # it is small next to the payload
  foreach ($nm in $parfiles) { Copy-Item (Join-Path $pristine $nm) (Join-Path $work $nm) -Force }
}

function Read-Warm {
  # $names limits the warm to those files. The gate reads every member right
  # before the tool runs, so only the recovery set actually needs warming, and
  # warming the whole work dir instead costs 11.5 GB of reads per leg.
  param([string]$dir, [string[]]$names)
  $buf = New-Object byte[] (8MB)
  $list = if ($names) { $names | ForEach-Object { Join-Path $dir $_ } }
          else { (Get-ChildItem $dir -File) | ForEach-Object { $_.FullName } }
  foreach ($f in $list) {
    if (-not (Test-Path $f)) { continue }
    $fs = New-Object IO.FileStream($f, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 1048576, [IO.FileOptions]::SequentialScan)
    while ($fs.Read($buf, 0, $buf.Length) -gt 0) { }
    $fs.Close()
  }
}

function Write-BoxFacts {
  $cpu = Get-CimInstance Win32_Processor
  $os  = Get-CimInstance Win32_OperatingSystem
  $cs  = Get-CimInstance Win32_ComputerSystem
  # Name the drive rather than assume D:. The first Windows box added after
  # intel-i5-10600kf had no D: at all and the round died on its own preflight line,
  # which is a silly way to lose a box.
  $drv = @('D','C') | ForEach-Object { Get-PSDrive -Name $_ -ErrorAction SilentlyContinue } | Select-Object -First 1
  $ram = [math]::Round($cs.TotalPhysicalMemory/1GB,1)
  $free = if ($drv) { "$($drv.Name)free_gb=$([math]::Round($drv.Free/1GB,1))" } else { "free_gb=?" }
  Write-PlibLine "BOX host=$env:COMPUTERNAME cpu=$($cpu.Name) caption=$($cpu.Caption) cores=$($cpu.NumberOfCores) threads=$($cpu.NumberOfLogicalProcessors) ram_gb=$ram os=$($os.Caption) build=$($os.Version) $free"
}

function Write-BinFacts([string]$bindir, [string[]]$tools) {
  foreach ($nm in $tools) {
    $p = Join-Path $bindir "$nm.exe"
    if (-not (Test-Path $p)) { Write-PlibLine "PREFLIGHT-FAIL missing $p"; exit 9 }
    # -VV carries parfast's build stamp on the second line. A log that cannot
    # name the source of its own binary is the defect that voided 10 Sep.
    #
    # WRAPPED, and this is not defensive padding: `-VV` is parfast's and turbo's
    # spelling, NOT a universal one. phpar2 answers "Not enough command line
    # arguments" on stderr, which under this file's $ErrorActionPreference =
    # 'Stop' is a TERMINATING error - so adding this stamp line silently killed
    # the seven-tool field round and the verify ladder at the phpar2 entry, two
    # seconds in, while the three-tool ladders were unaffected. A probe for a
    # nicety must not be able to end a round.
    $vv = @()
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $vv = @(& $p -VV 2>&1) } catch { $vv = @() }
    $ErrorActionPreference = $prevEap
    if (-not $vv -or $vv.Count -eq 0) { $vv = @('(no -VV)') }
    $stamp = ($vv | Where-Object { $_ -like 'built from *' } | Select-Object -First 1)
    if (-not $stamp) { $stamp = 'built from ?' }
    Write-PlibLine "BIN $nm sha256=$((Get-FileHash $p -Algorithm SHA256).Hash.ToLower()) bytes=$((Get-Item $p).Length) version=$($vv[0]) $stamp"
  }
}

# ---------------------------------------------------------------------------
# WHICH CUT OF THE HARNESS PRODUCED THIS ROUND, AND THIS LEG?
# ---------------------------------------------------------------------------
# Until 11 Sep 2026 this file stamped `BIN` and nothing whatsoever about
# ITSELF, so every Windows parfast round - intel-i5-10600kf, intel-core-ultra-9-386h, windows-gaming-pc-b,
# amd-ryzen-9800x3d, which is the largest share of the fleet's parfast rounds - banked
# a log with zero harness provenance in it. `Write-BinFacts` answers "which
# build did this round measure"; nothing answered "which harness measured it".
#
# Two questions, two mechanisms, and neither answers the other.
# `Write-HarnessFacts` is the ROUND-START half: every file the round sources,
# hashed once, in the log the round writes. `Get-RigStamp` is the PER-LEG half,
# ported from the bench rig library's `rig_gen` (TODO 236 item 1, 23 Aug
# 2026), and it exists because a hash taken once at round start CANNOT SEE A
# FILE THAT CHANGES AT LEG 40. That is not hypothetical and it is why this
# landed: on 11 Sep 2026 the deployed harness on intel-i5-10600kf diverged from
# origin/main for about twenty minutes and came back, because a queue owner
# added a refusal gate to the box before it landed in the repo
# (an internal note). **A DRIFT THAT REVERTS
# IS INVISIBLE TO EVERY CHECK THAT RUNS AT A POINT IN TIME** -
# `tools/bench-deploy-check.py` covers every rig box on both platforms since
# 11 Sep, and it still cannot see that, because it runs BEFORE the round. So
# the identity has to travel on the LINE, which is what the throughput farm
# has done since 23 Aug and what cost `funny-lalande-5ab050` four columns
# before it did.
#
# ONE SHA PER FILE, NOT A DIRECTORY DIGEST. The point is to name what RAN, and
# a round sources two files - this library and its driver. A digest over
# `<rig>` would move whenever any of the twenty unrelated scripts beside them
# moved, which is a token nobody would keep reading.
#
# SORTED BY BASENAME, so the value is stable across legs and identical in shape
# to `pdrv.py`'s `rig_stamp` on the unix half: a reader comparing two legs is
# comparing ONE string, which is what lets `jsum.py` and `s2sum.py` refuse a
# fold whose legs came from two different harnesses. Resolve a token with one
# command and no box access:
#
#     git show origin/main:harness/plib.ps1 | shasum -a 256 | cut -c1-16
#
# NO CACHE, DELIBERATELY, and this is the one place the port differs from
# rig-lib.sh (which memoises into `_RIG_GEN`). There a leg is a fresh
# `bench2.sh` process, so a per-process cache is still per-leg; here the driver
# is ONE PowerShell process for the whole round, and a cache would silently
# turn this back into the round-start stamp it exists to complement. Two ~20 KB
# hashes against a leg measured in minutes.

# CAPTURED HERE, AT DOT-SOURCE TIME, and not inside the function: this is the
# one instant at which the automatic variables certainly describe THIS file,
# and a driver is free to change directory afterwards.
$script:harnessfiles = @()
# PLAIN STATEMENTS, not `$x = if (...) {...} elseif (...)`. The expression form
# is legal PowerShell and it is also the form whose parse this Mac cannot check
# - there is no pwsh on the dev box - and a PARSE error here does not degrade a
# round, it kills every Windows round at dot-source time. Nothing clever above
# the level of an assignment belongs at this file's top level.
$script:pliblibpath = $PSCommandPath
if (-not $script:pliblibpath) {
  try { $script:pliblibpath = $MyInvocation.MyCommand.Path } catch { }
}
if ($script:pliblibpath -and
    ([IO.Path]::GetFileName($script:pliblibpath) -ne 'plib.ps1')) {
  # A dot-sourced file shares the caller's scope, and if either automatic
  # variable resolved to the CALLING script rather than to this one the token
  # would still be TRUE - it names whatever it hashed, under that file's own
  # basename, which is rig-lib.sh's honesty rule - but this library itself
  # would go unhashed. Prefer a sibling plib.ps1 when one is actually on disk.
  # That is a Test-Path and not a guess; when it is absent, keep what we have
  # rather than inventing a path, because a confidently wrong generation is
  # worse than a differently-labelled true one.
  $sibling = Join-Path (Split-Path $script:pliblibpath -Parent) 'plib.ps1'
  if (Test-Path -LiteralPath $sibling) { $script:pliblibpath = $sibling }
}

function Get-RigStamp {
  # `<basename>:<sha16>` per harness file, `+`-joined. RE-READ ON EVERY CALL.
  #
  # IT RETURNS ONE STRING AND EMITS NOTHING ELSE, and that is load-bearing
  # rather than style. PowerShell makes no distinction between logging and
  # returning, so a single stray unassigned statement in here would be
  # CONCATENATED INTO THE LEG LINE at the call site and displace every field
  # after `rig=` - which is precisely the defect `Require-QuietBox` above
  # carries a sixteen-line note about, and the one `jcross.ps1` met twice.
  # Every statement below is an assignment, a loop, or consumed by `if`.
  # Nothing here writes to the output stream. Keep it that way.
  #
  # AND IT NEVER THROWS. `$ErrorActionPreference = 'Stop'` at the top of this
  # file makes an unreadable file a TERMINATING error, and a probe for a
  # nicety must not be able to end a round - `Write-BinFacts` learned that the
  # expensive way, by killing the seven-tool field round two seconds in. An
  # unreadable file is STAMPED `unreadable` rather than left off: "this leg
  # could not establish its harness" is a fact a reader wants, and an absent
  # token is indistinguishable from a harness older than this block, which
  # never had one.
  $files = $script:harnessfiles
  if (-not $files -or @($files).Count -eq 0) {
    if ($script:pliblibpath) { $files = @($script:pliblibpath) } else { $files = @() }
  }
  if (-not $files -or @($files).Count -eq 0) { return 'unknown' }
  $parts = @()
  foreach ($f in $files) {
    $nm = 'unknown'
    $sha = 'unreadable'
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
      $nm = [IO.Path]::GetFileName($f)
      $h = Get-FileHash -LiteralPath $f -Algorithm SHA256 -ErrorAction Stop
      if ($h -and $h.Hash -and $h.Hash.Length -ge 16) {
        $sha = $h.Hash.ToLower().Substring(0, 16)
      }
    } catch {
      $sha = 'unreadable'
    }
    $ErrorActionPreference = $prevEap
    if (-not $nm) { $nm = 'unknown' }
    # THE FORMAT OPERATOR, NOT "$nm`:$sha". `$name:` is PowerShell's
    # scope-qualified variable syntax ($env:, $script:), so a colon directly
    # after a variable reference inside a double-quoted string does not mean
    # what it reads like.
    $parts += ('{0}:{1}' -f $nm, $sha)
  }
  return ($parts -join '+')
}

function Write-HarnessFacts([string[]]$paths) {
  # Round start. REGISTERS the set as well as printing it, so every LEG line's
  # `Get-RigStamp` re-reads exactly the files these HARNESS lines named. This
  # library adds ITSELF; the caller passes its own `$PSCommandPath` (and
  # anything else it sources).
  #
  # THE COMPOSITION MOVED INTO `Get-HarnessLines` (20 Sep 2026) and this is now
  # the printing half alone. A driver that tees its own log through a local
  # `Log` / `Say` and never calls `Set-PlibLog` cannot use THIS function: it
  # writes through `Write-PlibLine`, whose sink is plib's, so the stamp would
  # land on stdout and the BANKED log would stay unstamped - looking fixed.
  # Five drivers in the second census are in exactly that state and call
  # `Get-HarnessLines` instead (an internal note).
  foreach ($l in (Get-HarnessLines $paths)) { Write-PlibLine $l }
}

function Get-HarnessLines([string[]]$paths) {
  # `Write-HarnessFacts` without the writing: REGISTERS the set and RETURNS the
  # lines, for a driver whose own helper is the one that reaches the banked log.
  #
  # IT RETURNS LINES AND EMITS NOTHING ELSE, for `Get-RigStamp`'s reason one
  # function down: PowerShell does not distinguish logging from returning, so a
  # single stray unassigned statement in here would be returned to the caller
  # as an extra "line" and written into the round log as one. Every statement
  # below is an assignment, a loop, or consumed by `if`.
  $all = @()
  if ($script:pliblibpath) { $all += $script:pliblibpath }
  foreach ($p in $paths) { if ($p) { $all += $p } }
  $seen = @{}
  $uniq = @()
  foreach ($p in $all) {
    $full = $p
    $prevEap = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { $full = (Resolve-Path -LiteralPath $p -ErrorAction Stop).Path } catch { $full = $p }
    $ErrorActionPreference = $prevEap
    if (-not $seen.ContainsKey($full)) { $seen[$full] = $true; $uniq += $full }
  }
  # ONE sort key, built as a string, so the order cannot depend on how this
  # PowerShell version handles a multi-scriptblock Sort-Object.
  $script:harnessfiles = @($uniq | Sort-Object { [IO.Path]::GetFileName($_) + '|' + $_ })
  $out = @()
  foreach ($p in $script:harnessfiles) {
    # A MISSING file still ends the round here, and it is the one thing this
    # function is allowed to do besides return lines. A round that cannot find
    # what it sources has established nothing, and the caller's own log helper
    # has not necessarily been wired yet - so the refusal goes through plib's
    # sink, the same one `Write-HarnessFacts` used before the split.
    if (-not (Test-Path -LiteralPath $p)) { Write-PlibLine "PREFLIGHT-FAIL missing $p"; exit 9 }
    $h = (Get-FileHash -LiteralPath $p -Algorithm SHA256).Hash.ToLower()
    $len = (Get-Item -LiteralPath $p).Length
    $out += "HARNESS $([IO.Path]::GetFileName($p)) sha256=$h bytes=$len"
  }
  # The token the legs will carry, emitted once at round start as well, so a
  # reader who greps the head of a log sees the same string the legs carry
  # instead of composing it from the HARNESS lines by hand.
  $out += "HARNESS-RIG $(Get-RigStamp)"
  return $out
}

# ---------------------------------------------------------------------------
# Parallel SHA-256 over the members. The serial gate costs ~25 s per leg on this
# box (Comet Lake has no SHA-NI), which is most of a short leg's own wall; six
# runspaces bring it under 6 s. The gate is NOT optional - MultiPar returns exit
# 16 on a successful repair, so an exit code can never stand in for it.
function Test-RestoredFast {
  param([string]$dir, [string[]]$members, [hashtable]$gold, [int]$lanes = 6)
  $pool = [RunspaceFactory]::CreateRunspacePool(1, $lanes)
  $pool.Open()
  $jobs = @()
  foreach ($nm in $members) {
    $ps = [PowerShell]::Create()
    $ps.RunspacePool = $pool
    $null = $ps.AddScript({
      param($p, $n)
      # An 8 MB TransformBlock loop, NOT ComputeHash($stream). ComputeHash reads
      # a stream in 4 KB chunks, so a 10 GiB gate becomes ~2.6 million tiny
      # reads: measured at ~300 s of overhead PER LEG on this box, against
      # ~5 s here. It does not touch a published timing, but it was going to
      # cost this round about seven hours of wall.
      $sha = [Security.Cryptography.SHA256]::Create()
      $fs = New-Object IO.FileStream($p, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 1048576, [IO.FileOptions]::SequentialScan)
      $buf = New-Object byte[] (8MB)
      while (($cnt = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $null = $sha.TransformBlock($buf, 0, $cnt, $null, 0) }
      $fs.Close()
      $null = $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
      New-Object psobject -Property @{ name = $n; hash = ([BitConverter]::ToString($sha.Hash).Replace('-','')) }
    }).AddArgument((Join-Path $dir $nm)).AddArgument($nm)
    $jobs += New-Object psobject -Property @{ ps = $ps; handle = $ps.BeginInvoke() }
  }
  $good = 0; $bad = New-Object Collections.ArrayList
  foreach ($j in $jobs) {
    $res = $j.ps.EndInvoke($j.handle)
    $j.ps.Dispose()
    foreach ($r in $res) {
      if ($gold[$r.name] -eq $r.hash) { $good++ } else { $null = $bad.Add($r.name) }
    }
  }
  $pool.Close(); $pool.Dispose()
  New-Object psobject -Property @{ good = $good; bad = @($bad) }
}

# Same loop, single file, for the one-off gold hashes.
function Get-Sha256Fast([string]$path) {
  $sha = [Security.Cryptography.SHA256]::Create()
  $fs = New-Object IO.FileStream($path, [IO.FileMode]::Open, [IO.FileAccess]::Read, [IO.FileShare]::Read, 1048576, [IO.FileOptions]::SequentialScan)
  $buf = New-Object byte[] (8MB)
  while (($cnt = $fs.Read($buf, 0, $buf.Length)) -gt 0) { $null = $sha.TransformBlock($buf, 0, $cnt, $null, 0) }
  $fs.Close()
  $null = $sha.TransformFinalBlock((New-Object byte[] 0), 0, 0)
  [BitConverter]::ToString($sha.Hash).Replace('-','')
}

# The damage pick list, as data, so a leg can be undone by writing back exactly
# the slices it changed instead of re-copying 10 GiB.
function Get-DamagePicks {
  param([string]$dir, [string[]]$members, [int]$slicesize, [int]$mblocks, [int]$dseed)
  $counts = @(); $lens = @(); $total = 0
  foreach ($nm in $members) {
    $flen = (Get-Item (Join-Path $dir $nm)).Length
    $cnt = [int][math]::Ceiling($flen / $slicesize)
    $counts += $cnt; $lens += $flen; $total += $cnt
  }
  if ($mblocks -gt $total) { throw "damage $mblocks exceeds $total slices" }
  $order = New-Object int[] $total
  for ($i = 0; $i -lt $total; $i++) { $order[$i] = $i }
  $rng = New-Object Random($dseed)
  for ($i = $total - 1; $i -gt 0; $i--) {
    $j = $rng.Next($i + 1)
    $tmp = $order[$i]; $order[$i] = $order[$j]; $order[$j] = $tmp
  }
  $bymember = @{}
  for ($k = 0; $k -lt $mblocks; $k++) {
    $g = $order[$k]; $mi = 0
    while ($g -ge $counts[$mi]) { $g -= $counts[$mi]; $mi++ }
    if (-not $bymember.ContainsKey($mi)) { $bymember[$mi] = New-Object Collections.ArrayList }
    $null = $bymember[$mi].Add($g)
  }
  New-Object psobject -Property @{ bymember = $bymember; lens = $lens; total = $total }
}

function Invoke-DamagePicks {
  param([string]$dir, [string[]]$members, [int]$slicesize, $picks, [int]$dseed)
  $fill = New-Object byte[] $slicesize
  $frng = New-Object Random($dseed + 1)
  $written = 0
  foreach ($mi in ($picks.bymember.Keys | Sort-Object)) {
    $fs = [IO.File]::Open((Join-Path $dir $members[$mi]), 'Open', 'Write', 'None')
    foreach ($si in ($picks.bymember[$mi] | Sort-Object)) {
      $off = [int64]$si * $slicesize
      $n = [int][math]::Min([int64]$slicesize, $picks.lens[$mi] - $off)
      $frng.NextBytes($fill)
      $null = $fs.Seek($off, 'Begin')
      $fs.Write($fill, 0, $n)
      $written++
    }
    $fs.Close()
  }
  $fs = $null
  $written
}

# Write the damaged slices back from pristine. Cheap where a full member copy is
# not: at m=1 this moves 750 KiB where a copy moves 1 GiB. The caller MUST
# re-gate afterwards and fall back to a full copy for anything still wrong -
# a tool is free to have touched something the pick list does not name.
function Restore-Slices {
  param([string]$work, [string]$pristine, [string[]]$members, [int]$slicesize, $picks)
  $buf = New-Object byte[] $slicesize
  foreach ($mi in ($picks.bymember.Keys | Sort-Object)) {
    $nm = $members[$mi]
    $src = [IO.File]::OpenRead((Join-Path $pristine $nm))
    $dst = [IO.File]::Open((Join-Path $work $nm), 'Open', 'Write', 'None')
    foreach ($si in ($picks.bymember[$mi] | Sort-Object)) {
      $off = [int64]$si * $slicesize
      $n = [int][math]::Min([int64]$slicesize, $picks.lens[$mi] - $off)
      $null = $src.Seek($off, 'Begin')
      $got = 0; while ($got -lt $n) { $r = $src.Read($buf, $got, $n - $got); if ($r -le 0) { break }; $got += $r }
      $null = $dst.Seek($off, 'Begin')
      $dst.Write($buf, 0, $got)
    }
    $src.Close(); $dst.Close()
  }
}

function Remove-Strays {
  param([string]$work, [string[]]$members, [string[]]$parfiles)
  $wanted = @{}
  foreach ($nm in $members)  { $wanted[$nm] = $true }
  foreach ($nm in $parfiles) { $wanted[$nm] = $true }
  $n = 0
  foreach ($f in (Get-ChildItem $work -File)) {
    if (-not $wanted.ContainsKey($f.Name)) { Remove-Item $f.FullName -Force; $n++ }
  }
  $n
}
