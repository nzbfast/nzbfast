# Capability-test corpus (no-RAR deobfuscation tier)

A reproducible corpus of bare-file Usenet posts - no archive anywhere,
random-looking names on the wire, real names only in the PAR2 FileDesc
packets - plus the loopback rig to run any client against it. One leg
per capability-matrix row: placeholders, directory trees, hostile
names, hash-key collisions, damaged heads. Built so the whole set can
be posted to a public test group and the results reproduced by anyone
against any client.

Everything is generated: payload bytes come from the OS entropy pool,
PAR2 sets are built locally by par2cmdline, and the three shapes
par2cmdline cannot emit (0-byte members, traversal names, duplicate
FileDesc names) are patched by `par2patch.py` into what MultiPar/parpar
produce natively. No third-party or copyrighted material is included or
required, so the corpus, its NZBs and its results can be published
freely.

The sibling `bench/nested-corpus/` holds the archive-shaped tiers
(nested RAR/7z, damage ladders, password chains); this directory adds
the bare-file tier in the SAME leg-dir layout, so nzbserve,
run-legs.sh and classify.py consume both. Note classify.py grades by
payload CONTENT only - for these legs the landed NAME is the
measurement, so grade against `deobf.json` too (roundtrip.py shows
how).

## Layout

    generate.py          builds the tier (this is the reproduction step)
    par2patch.py         PAR2 packet surgery (rename / splice a 0-byte member)
    roundtrip.py         serves each leg over loopback NNTP and proves the
                         real nzbfast lands the exact expected end state
    corpus/norar/<leg>/  generated output:
        post/            the files a client downloads / a poster uploads
        manifest.json    nested-corpus schema (payload sha256 pins)
        deobf.json       exact expected END STATE: relative path + sha256
                         per file, forbidden leftover names, documented
                         race/gap outcomes
        <leg>.nzb        loopback-rig NZB (nzbserve build)
        yenclies.txt     n37 only: per-file LYING yEnc headers the rig
                         posts (`<postname> <size_lie> <total_lie>`)

## Reproducing

    ./generate.py                          # all 37 legs (par2 + cargo required)
    ./roundtrip.py                         # round-trip every leg
    ./roundtrip.py corpus/norar/n06-tree                 # one leg
    ./roundtrip.py --selftest                            # the grader's own arms
    ./roundtrip.py --arrival late-par2 corpus/norar/n01-announced-par2
    ./roundtrip.py --report-dir /tmp/rpt                 # keep per-leg evidence

(All five scripts here carry a shebang and are committed 100755 as of
30 Aug 2026 - they were 100644 until then, which is why an earlier
revision of this section spelled every line `python3 <script>`. That
spelling still works and is the portable one if your checkout predates
the mode fix.)

## What "graded" means

`roundtrip.py` proves the END STATE, and since 30 Aug 2026 it proves
rather more than the expected files. The arms below were commissioned as
a prerequisite for the wave-4 adversarial rows, because a grader that
checks only what it was told to expect cannot see a cleanup or collision
defect - a leftover hash name, a duplicate silently disambiguated into a
second copy, a partial file never reaped, a symlink standing in for a
payload.

* **Closed-world output.** Anything in the output tree that no
  expectation claimed and no `allowed_extra` pattern names fails the
  leg. `generate.py` seeds that list with the posted files that are
  neither an expected output nor a forbidden leftover - the recovery
  blobs and sidecars a client legitimately keeps - and a row that keeps
  junk on purpose opts out with a REASON.
* **Path multiplicity.** The tree is a list of raw directory entries.
  Two entries never collapse into one before grading, and one file
  never satisfies two expectations.
* **The destination filesystem is probed**, not assumed: case folding
  and unicode normalization. `path_by_volume` lets a collision row name
  different acceptable spellings per volume while keeping one
  no-data-loss invariant.
* **Special files are refused.** Grading is by `lstat`, and a realpath
  check joins the lexical containment check, so a symlink cannot make
  an inside path point out.
* **Spend is graded** where spend is the bug: `budget` bounds repair
  blocks, bytes on disk, output amplification and wall time.
* **Arrival order is controllable.** `--arrival <plan>` puts a stall
  proxy in front of the loopback server that holds chosen article
  requests, so a row whose bug needs a particular order gets that order
  instead of whatever the scheduler picked.
* **Honest failure is expressible.** `honest_failure` accepts a nonzero
  exit that kept the right bytes and said why - and never accepts rc=0
  with wrong or missing output.

A `deobf.json` with no `schema` key is a schema-1 manifest and grades
exactly as the first 50 posted legs did (closed world OFF); `schema: 2`
turns the closed world on. `./roundtrip.py --selftest` drives
every arm against fixtures built to bite.

Every leg but n03 carries a `TEST PASSED - <leg>.txt` marker file,
named only through the leg's own name source (FileDesc, SFV), posted
through the leg's own hazard where the leg has one (n37 posts its
marker under the same lying header as its payload), or buried
at the deepest archive layer in the nested tier - seeing it on disk is
the human pass signal, while deobf.json stays the grading truth. n03
has none on purpose: its point is that no name source exists.

Structure and names are deterministic; payload bytes are drawn fresh
each generation and pinned by sha256 in the manifests, so any two
copies of a generated corpus are verifiable even though their bytes
differ (the bench/nested-corpus convention).

## The legs

| leg | shape | correct outcome |
| --- | ----- | --------------- |
| n01-announced-par2 | obfuscated payload, PAR2 under real names | payload lands under its FileDesc name |
| n02-sniffed-par2 | PAR2 posted under hash names too | same end state - recovery set found by content |
| n03-extensionless | extensionless payload, no name source at all | bytes intact; real container extension resolved, never junk appended |
| n04-zerobyte | 0-byte member named only in a FileDesc, not posted | empty file created under its real name, nothing reported missing |
| n05-zerobyte-posted | 0-byte placeholder posted as one empty article | placeholder paired + renamed, no hash names remain |
| n06-tree | FileDesc names carry a VIDEO_TS tree | the TREE lands intact |
| n07-dup-basenames | a/readme.txt vs b/readme.txt | both land, distinct |
| n08-lookalike | sub/movie.mkv beside sub_movie.mkv | both land, neither lost |
| n09-traversal | ../evil.bin in a FileDesc (security row) | containment - nothing outside the job dir |
| n10-dup-filedesc | two descriptors, one name, different files | both files survive, disambiguated |
| n11-subset | PAR2 covers only part of the post | covered renamed; stray keeps its posted name |
| n12-exact16k | file of exactly 16384 bytes | lands under its FileDesc name |
| n13-short | file under 16 KiB | lands under its FileDesc name |
| n14-damaged-head | first 16 KiB damaged after PAR2 create | repaired byte-exact under its FileDesc name |
| n15-twins-r100 | identical 16 KiB heads, same length, 100% recovery | both twins exact under their own names |
| n16-twins-r10 | the same pair at realistic 10% recovery | both twins exact under their own names, every run |
| n17-manifest-only-par2 | PAR2 index only, zero recovery volumes | renamed and verified with no recovery data |
| n18-raw-splits | .001/.002 parts, FileDesc names the parts | renamed, joined, byte-exact |
| n19-split-join | halves posted, FileDesc names the join | joined file lands byte-exact |
| n20-decoy-junk | uncovered junk incl. a same-length decoy | covered renames; decoy never claims; junk kept |
| n21-sfv-sidecar | .sfv is the only name source | names resolved via CRC32; intact bytes are the floor |
| n22-two-par2-sets | two independent sets, half the files each | each claims only its own |
| n23-windows-hostile | CON.mkv, NUL, trailing dot-space | sanitized identically on every host |
| n24-dedupe-descriptors | two identical FileDescs, one posted copy | both names land byte-exact |
| n25-near-twin-decoy | damaged payload + same-length same-head decoy | payload repairs; decoy survives byte-exact |
| n26-triplet-one-damaged | three zero-head same-length files, one damaged | all three land under their own names |
| n27-par2-of-par2 | obfuscated inner PAR2 named by an outer set | payload lands via the chain |
| n28-foreign-set-decoy | junk PAR2 set covering a never-posted file | payload lands; job unharmed |
| n29-zero-head-dvd-drill | zero-head VOB pair + tree + placeholder, r=10 | full tree, byte-exact, placeholder created |
| n30-damaged-index | poisoned PAR2 index, intact volumes | named and verified from the volume packets |
| n31-index-only-tree | manifest-only PAR2 + tree + placeholder | full structure, zero recovery spend |
| n32-sniffed-index-only | manifest-only index under a hash name | full naming from one sniffed kilobyte file |
| n33-join-quarters | four raw quarters, PAR2 names the join | joined byte-exact, no part files linger |
| n34-sfv-tree | SFV entries spelling relative paths | files land at their tree paths |
| n35-unicode-names | accents, CJK, mixed scripts | faithful names on every host |
| n36-many-small | 120 small files, one set | all 120 under their real names |
| n37-lying-size | `=ybegin size=` +77,777 and `total=` +9, ranges true | file lands byte-exact at its FileDesc length, no zero-padded tail |

Measured nzbfast results per leg live in
`research/NORAR-DEOBF-MATRIX-2026-08-29.md` (private repo); the
public-facing list document maps legs to NZBs once the corpus is
posted.

## Posting

Each leg is one post and one NZB: `nzbfast post <leg>/post/` (see
`bench/nested-corpus/POSTING.md` for the runbook; the n05 leg's 0-byte
placeholder needs `--allow-empty`). **n37-lying-size is not publishable
as-is**: its whole point is a yEnc header that overstates the file, and
`nzbfast post` writes honest headers, so a real upload of its post/ dir
would carry none of the lie and the leg would grade like n01. Posting
it needs a lying knob on the poster, or a hand-built post; until then
the leg measures over the loopback rig only, and its row in the
published list should say so. The `.nzb` files here point at the
loopback rig and exist for verification and competitor rounds; the
published NZBs are the ones `nzbfast post` mints at upload time.
