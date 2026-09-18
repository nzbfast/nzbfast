# Launch sequence - run ONLY after the d8 lane posts DONE (not on a poll)

PRECHECKS, all four, before any leg:
1. d8's DONE line present, with its delete-time and post-time three minutes apart.
2. crg4's DONE line present AND containing the sentence that `work\` is pristine.
   If absent: re-copy members + parfiles from `pristine\` to `work\` FIRST.
3. Binary byte count == 4173312. If it differs, STOP and tell crg4 -
   that would mean the tree is not 06d5734b7.
4. Rig lock absent, no parfast process, load < 25.

THEN, in order:
  scp harness/wlaunch.ps1  -> intel-core-ultra-9-386h:pinaff-16sep/harness/
  scp scratchpad/pinaff-round.ps1   -> intel-core-ultra-9-386h:pinaff-16sep/harness/
  ssh parsecheck.ps1                (wcomb, plib, pinaff-round, wlaunch)

LAUNCH (detached - Start-Process over ssh dies SILENTLY, wlaunch uses
Win32_Process::Create). Do NOT pass -DeadlineUtc: it resolves deadline.ps1
under $Root instead of beside the script and arms nothing while printing rc=0
(open claim wlaunch-deadline-not-armed-16sep).

  powershell -NoProfile -ExecutionPolicy Bypass -File <rig>\pinaff-16sep\harness\wlaunch.ps1 `
    -Root <rig>\pinaff-16sep -Tag pinaff `
    -Script "<rig>\pinaff-16sep\harness\pinaff-round.ps1 -Root <rig>\crg4-16sep"

  -Root on wlaunch  = where pinaff.log / pinaff.err go (MY root).
  -Root on the driver = where the fixture and binary are (CRG4's root).
  These are deliberately different. **The driver does NOT delete crg4's root** -
  that sentence stood here unchecked until the round actually ran, and there is
  no Remove-Item in the driver. Deleting it is a HAND step after the reduce,
  and it is deliberately after rather than inside: a soft low rung is re-measured
  at the end of the sitting on a settled box (the A/A floor is a MAX over reps
  and cannot be firmed by adding reps), and that re-measure needs the fixture.

POLL AT 10 MIN, NEVER TIGHTER. Every ssh poll spawns a PowerShell under sshd,
outside the round's pid tree, ~1 core-second - a lane contaminated its OWN
round this way today.

WATCH FOR, in pinaff.log:
  PROVENANCE ...          which of inherit/build actually happened
  BIN sha256=... bytes=   must be 4173312
  CLASS-PROBE             0xF should be materially faster than 0xF0
  LOAD-GATE ok            two samples before ladder 1
  ARM-DONE <tag> rc=0 legs=20   x4

REDUCE (on the Mac, no python on the rigs):
  python3 harness/rowgate.py read <the four logs>
  -> groups by (label, threads); the four -Label values are distinct so the
     four arms come out as four tables. Cross-arm F/T differences are
     subtraction from those tables, as the landed section did.
