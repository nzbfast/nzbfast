# oramnuc1 / oramnuc2 - the over-RAM create round on intel-i5-10600kf, 18 Sep 2026

Claim `parfast-over-ram-create-nuc-18sep-r2`. The findings are in
an internal note; this file records
what is in the directory and the one edit made to a log after the fact.

- `oramnuc.ps1` - the round driver (four arms: three parfast builds plus
  ParPar). Written for this round because `oramx.ps1` runs arms of ONE binary.
- `oramnucrun.ps1` - the plan, baked in, because `wlaunch.ps1` launches a
  script with `-File` and passes no arguments.
- `oramnuc1.log` - the main round. 28 legs, 16:17:26Z to 20:57:39Z, zero
  failures.
- `oramnuc2*` - the within-binary `main` against `nobands` supplement, run
  with `harness/oramx.ps1` UNMODIFIED from the tip tree.

## The logs, the one post-hoc edit, and the encoding trap behind it

- `legs/` - the per-leg stderr of all 54 legs, exactly as captured. These
  carry the full timing block each leg printed, including the
  `create stripe-first: ... read Ns` split that section 4 of the write-up
  rests on.

**`oramnuc1.log` and `oramnuc2.log` were each rewritten once after banking**,
to replace the five-byte sequence `83 22 AA C7 3F` with a single ASCII `|` -
256 copies in `oramnuc1.log` and 128 in `oramnuc2.log`. Nothing else was
touched and both files are now pure ASCII. Before each rewrite it was asserted
that EVERY non-ASCII byte in the file was inside one of those runs.

### What the character was, and where it was lost

parfast separates the fields of its `mem-floor:` lines with `.` U+00B7 MIDDLE
DOT, which is `C2 B7` in UTF-8. It is destroyed in two stages, and the two
stages matter because only the first is reversible:

1. **At capture.** `plib.ps1`'s `Invoke-Leg` reads the child's stderr through
   `StandardError.ReadToEndAsync()` with **no encoding set**, so the bytes are
   decoded in the console's codepage - CP850 on this box, where `C2` is the
   box-drawing character and `B7` is a capital A-grave - and then written back
   out as UTF-8 by `WriteAllText`. So the `.err` files in `legs/` are VALID
   UTF-8 containing two mojibake characters where one middle dot belongs. The
   original is recoverable from them: the pair is a deterministic CP850
   round-trip of `C2 B7`.
2. **At the round log.** The driver echoes those `.err` lines to stdout as
   `TIMING` lines, and stdout is redirected to the round log by `cmd /c ... >`,
   which applies the console encoding AGAIN - this time to characters the
   target codepage cannot represent, so it emits the unmappable-character `?`.
   That is the `83 22 AA C7 3F` above and it is NOT reversible.

So nothing was lost by the substitution that had not already been lost in the
round log, and the `.err` files keep the recoverable form. **An earlier
revision of this file claimed the character was unrecoverable from the `.err`
files too. That was wrong** - it was written before those files were banked
and inspected, and it is corrected here rather than quietly dropped.

### Why the round logs had to be fixed rather than left

`website/tools/export_parfast_evidence.py` REFUSES a file it cannot decode as
UTF-8 ("so it cannot be inspected or rewritten. Re-save it as UTF-8, or re-bank
the round"), which correctly stops an unreadable file reaching the published
tree. The fix belongs at the site - these logs - and not in
`tools/scrub-bench-logs.py` or `tools/site-leak-scan.py`, and the substitution
is recorded here rather than made silently.

### The general fix, which is NOT made here

**One line in `plib.ps1`'s `Invoke-Leg`**: set `$psi.StandardErrorEncoding`
(and `StandardOutputEncoding`) to `[Text.Encoding]::UTF8`, so stage 1 above
decodes correctly and stage 2 has nothing left to mangle. `plib.ps1` sets
neither today. A driver that also wants its own round log clean should set
`[Console]::OutputEncoding` as well.

Checked 18 Sep 2026: of 283 `.log` and `.txt` files under `rounds/`,
`oramnuc1.log` was the ONLY one that was not valid UTF-8, so the trap is
latent rather than active - it needs a tool that prints non-ASCII on a leg
whose stderr a driver echoes into a redirected round log. It is written up as
a recommendation rather than taken, because this chip lands no code and a
change to `plib.ps1` is a change to the harness every round on this fleet
uses.
