# field.ps1 - the seven-tool comparison, in two phases.
#
# the maintainer's requirement is that this chart reach past 2,000 blocks, because that is
# where parfast's transform has barely started and the comparison is not yet in
# its stride. Its predecessor tried to do that by asking a 15% set to rebuild
# 32,177 blocks, which it does not have the parity for - see fieldcore.ps1's
# header. This does it by changing the FIXTURE instead of the wish.
#
# PHASE 1, 15% parity. Every one of the seven tools can afford it, and it is the
# realistic setting a poster actually uses. One depth, 1,399 blocks, which is a
# single deleted member - the common real failure. This phase is also the
# CALIBRATION: every tool's create time here is what phase 2 projects from.
#
# PHASE 2, 100% parity, and every tool carried as deep as it can afford.
#
# It runs overnight, so the five quick tools go all the way to 13,990 blocks -
# the set's ceiling, and four times deeper than any chart on the page today.
# Projected from their own measured legs that is about 2.6 hours a repetition
# for the four rivals plus parfast, and two repetitions of it.
#
# THE TWO SLOW TOOLS STOP AT 5,500, AND GET ONE REPETITION. par2cmdline and
# phpar2 are roughly fifty times parfast at this job. Carrying them to the
# ceiling projects at over four hours FOR A SINGLE LEG, and the bars would say
# nothing the shallow rungs have not already said. At 5,500 with one repetition
# they cost about 3.6 hours between them, which the night can absorb.
#
# The budget is 1,500 s, not a round 1,200: rarpar's 15% create is 159-195 s
# on this box, which projects to 1,060-1,300 s at 100%, so 1,200 sat inside
# rarpar's own noise and skipped it on one repetition's figure and not the
# other's. The two slow tools project to 12,000 s and clear either by a mile.
#
# Their creates are skipped too - 3.5 hours each at 100% parity - and that costs
# nothing, because every reader repairs the set parfast builds. A tool needs its
# own create only to appear in the CREATE chart, where the 15% phase already has
# all seven.
#
# Every skip carries its reason: a depth ceiling says "ceiling=", a repetition
# limit says "reps_allowed=", a projection says "projected_s=". A missing bar is
# never unexplained.
$root = if ($PSScriptRoot) { $PSScriptRoot } else { '<rig>' }

"FIELD-PHASE-1 15% parity, all seven tools, one depth - and the calibration for phase 2"
& (Join-Path $root 'fieldcore.ps1') -root $root -pct 15 -rungs '1399' -round 'field15'

# Every tool's own 15% create, read back from the log phase 1 just wrote, so the
# projection comes from THIS machine on THIS night rather than from a constant
# somebody typed in once.
#
# WHY IT READS TWO FILES. On 12 Sep the first night of this round ran phase 1
# to completion and then phase 2 with NO calibration: fieldcore's Say() tee
# that writes field15.log was deployed after phase 1 had started, so the file
# did not exist, $ref was empty, and par2classic began a 3.5-hour create the
# projection existed to skip. The queue runner's own capture (field.log) had
# every CREATE line the whole time. So: the phase log first, and when it has
# nothing, the capture, filtered to this phase's round tag. The round name is
# in every line, so the fallback cannot read phase 2's own creates as its
# calibration.
$ref = @{}
foreach ($src in @('field15.log', 'field.log')) {
  foreach ($ln in (Get-Content (Join-Path $root $src) -EA SilentlyContinue)) {
    if ($ln -match '^CREATE round=field15 .* tool=(\S+) .* wall=([\d.]+)') {
      if (-not $ref.ContainsKey($Matches[1])) { $ref[$Matches[1]] = [double]$Matches[2] }
    }
  }
  if ($ref.Count) { break }
}
if ($ref.Count) { "FIELD-CALIBRATION " + (($ref.Keys | Sort-Object | ForEach-Object { "$_=$($ref[$_])s" }) -join ' ') }
else { "FIELD-CALIBRATION none found - phase 2 will attempt every create unbudgeted" }

"FIELD-PHASE-2 100% parity, depths to 13,990; the two slow tools stop at 5,500 with one repetition"
# THE KEYS ARE fieldcore's TOOL NAMES, NOT THE PRODUCT NAMES. The first night
# keyed this table 'par2cmdline' while every log line says tool=par2classic,
# so the ceiling and the repetition limit matched nothing and par2cmdline was
# headed for 13,990 blocks twice over. Read $creators in fieldcore.ps1 before
# adding a row here.
$slowCeiling = @{ 'par2classic' = 5500; 'phpar2' = 5500 }
$slowReps    = @{ 'par2classic' = 1;    'phpar2' = 1 }
& (Join-Path $root 'fieldcore.ps1') -root $root -pct 100 -rungs '1399,2098,4096,5500,8192,13990' `
    -round 'field100' -createBudget 1500 -createRef $ref `
    -toolMaxRung $slowCeiling -toolReps $slowReps
