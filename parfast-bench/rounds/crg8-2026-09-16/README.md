# The CREATE's row gate at 8 MiB on GFNI-256, both pools, 16 Sep 2026

Lane `create-rowgate-8mib-gfni256`. The third block size on the CREATE
path, after its two predecessors: the 1 MiB create ladder in
`rounds/rowgate-2026-09-16/coreultra9-gfni256-create-1m-n4096.log`
and the 4 MiB round in `rounds/crg4-2026-09-16/`.
Written up as the section "The CREATE at 8 MiB: it is FLAT in block size,
and the n term's SIGN was backwards" in
an internal note.

**Result:** the create is FLAT in block size across 1, 4 and 8 MiB. It
crosses 403 (`-t4`) and 380 (`-t16`) at n = 2,048; with the n term
removed, ~377 and ~355 against the 4 MiB round's 381 and 365. The
repair's `-t16` rose +63 rows over 1 to 4 MiB and the create does not
reproduce that under any treatment of the n term, including zero. No
constant moved.

- **Box** intel-core-ultra-9-386h (Core Ultra 9 386H, GFNI-256, 16 cores, 31.4 GB,
  Windows 11 build 10.0.26200), under the per-box rig lock, one sitting
  18:27:20Z-19:11:22Z, 44 minutes.
- **Binary** the SAME `parfast.exe` both landed 4 MiB rounds ran, not
  merely the same commit: sha256 `fddb6aa34283001a...`, 4,173,312 bytes,
  copied out of the 4 MiB round's `crg4-16sep` tree before the lane
  inheriting that root deleted it, and byte-verified on arrival. Nothing
  was built on the box, so there is no build-variation term between this
  round and the ones it is compared against.
- **Harness** origin/main's `wcomb.ps1` (`60ded61d...`) and `plib.ps1`
  (`05860fd5...`) as origin/main stood at 16:56Z, NOT what it carries now
  (`d85f29f08` moved `wcomb.ps1` twelve minutes later, giving the create
  phase the `-Residency` assertion this round ran without), and NEWER
  than the copies the 4 MiB round ran (`1ad3f260` / `3b0e254e`). None of the changes between touches what is
  measured; one of them changes a reported diagnostic, so the
  foreign-CPU figures are not strictly comparable across the two rounds.
- **Fixture** 16 x 1,024 MiB at 8 MiB blocks, `-c640`: n = 2,048, a
  16 GiB corpus. n = 2,048 is EXACTLY the x86 create input floor and the
  comparison is `>=`, so it clears by equality; all 32 forced legs report
  `path=ntt cold_builds=1` and would have silently folded otherwise.
  n = 3,072 was rejected before launch: a 24 GiB corpus on a 31.4 GB box
  takes the over-RAM band route and stops being a resident ladder.
- **Rungs** 320,352,384,416,448,480,512,544 - the SAME eight the 4 MiB
  round ran, so every shared-rung comparison is measured against
  measured, and both crossovers are READS between bracketing rungs rather
  than fits past a top rung.
- **Arms** `fold force force2 fold2` at every rung, so every cell carries
  its own A/A pair. 64 legs, all `rc=0`, all `match=1`, all path-asserted.

## Files

- `coreultra9-gfni256-create-8m-n2048-t4-t16-ladder.log` - the round.
  Header carries BOX, HARNESS, BIN, the fixture build and the settle;
  then 64 LEG lines. Reduce with
  `harness/rowgate.py read <log>`.
- `coreultra9-gfni256-create-8m-gate.log` - the on-box gate's trail: what
  it waited for, the three lock-and-load samples it required before
  taking the box, and the ARGV it launched.

## Two things a reader should not re-derive

- **`-Residency resident` is in the ARGV and is INERT on this phase.**
  wcomb.ps1's residency assertion lived in `Run-Cell` only when this
  round ran, and `Run-Create` did not consult it; `d85f29f08` fixed that
  twelve minutes after this round's harness was staged, so the defect is
  a fact about this round and not about the harness today. Residency here is established by measurement, not
  assertion: a 20 GiB budget over 8 MiB blocks is a 2,560 source window
  against n = 2,048, and every forced leg peaks at 18,980-20,347 MB,
  which is the whole corpus resident.
- **An orphan rig lock was cleared on entry** and it was neither this
  lane's nor the lane ahead of it: `rarfast-windows-os-error-wording-16sep`
  pid 11560, whose pid was gone by 18:26:36Z. It was read as HELD BY A
  LIVE PID on two samples first and waited on. See the `RIG-LOCK-ORPHAN`
  line at the head of the ladder log.
