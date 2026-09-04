# nzbkit fuzz targets

Coverage-guided (libFuzzer / cargo-fuzz) fuzzers for the untrusted-input
parsers. Everything here takes attacker-controlled bytes: article bodies,
`.nzb` files, `.par2` recovery volumes, and downloaded RAR archives.

Needs nightly + `cargo install cargo-fuzz`.

## Targets

- `yenc_decode`  - the SIMD yEnc decoder (`yenc_simd::decode`) plus the
  scalar reference (`yenc::decode`) on RAW bytes. Complements the in-repo
  round-trip lite fuzzer, which never feeds the decoder malformed input.
- `nzb_parse`    - `Nzb::parse` (XML) on RAW bytes. Its corpus is
  COMMITTED (`seeds/nzb_parse/`, 19 files / 33 KB, added 30 Aug 2026):
  an NZB is XML, and every interesting arm sits behind a well-formed
  element tree that random bytes reach about as often as they reach a
  CRC. Measured that day, INITED: 110 edges cold, 1,322 seeded; after a
  60 s burst, 861 cold against 2,102 seeded.
- `nzb_semantic` - the SEMANTIC oracle over the same parser, and the
  only NZB target that can see a manifest REWRITE (addendum row N6-14).
  `nzb_parse` asks whether the parser crashed; this one asks whether it
  told the truth. It reads the fuzzer's bytes as a stream of CHOICES
  that build a manifest, renders that manifest to XML three times under
  independently chosen but semantically equivalent styles (attribute
  order, named versus numeric character references, CDATA versus text, a
  comment splitting a text node, formatting whitespace, prefixed versus
  default namespace, apostrophe delimiters, section order), and asserts
  that all three parse to the SAME `Nzb` and that every declared file
  and segment is accounted for. All three `EMIT_*` flags it shipped with
  are retired (31 Aug 2026) - two of those shapes are ordinary legal
  input now and the third became a refusal; the head of the target says
  which and why the third did not simply flip.
  Since 31 Aug 2026 it also carries the HOSTILE arm, which is the only
  thing in either NZB target that reaches a REFUSAL on purpose: the
  `Schema` breaks (a wrong root, a second root, a core element where the
  grammar has no slot for it), asserted to be refused identically under
  all three styles, and the N6-09 ceilings. Its corpus is COMMITTED
  (`seeds/nzb_semantic/`, 18 files / 613 bytes) and those seeds are
  CHOICE STREAMS rather than XML - see `seeds/README.md`.
- `nzblnk_parse` - `nzblnk::parse` + `looks_like` on pasted text. Also
  asserts the two agree about whether a string IS a link: the dashboard
  gates on `looks_like` and the daemon then runs `parse`, so a
  disagreement is a link the UI accepts and the API refuses.
- `par2_parse`   - `Par2Set::parse`, single- and split-input framing.
- `par2_verify_diff` - the only target that fuzzes a VERDICT rather than
  a parser (TODO 133.3). It generates FileDesc / IFSC / on-disk-bytes
  triples from independent sources - so an internally INCONSISTENT set is
  an ordinary case, not a rare one - and asserts
  `verify_pass1(threads=1) == verify_pass1(threads=8) == md5_matches(..)`
  plus an oracle computed in the target from the bytes it wrote, so all
  three agreeing wrongly still fails. This is the generalisation of H7,
  which `par2_parse` could never have found: that input was not
  malformed, both packets parsed fine, and the bug was in which of the
  two claims answered the verdict. It relies on `--cfg fuzzing`, which
  cargo-fuzz sets for every crate in its build and which lowers
  `par2repair`'s pool gate from 8 MiB to 8 KiB - without it the parallel
  branch is unreachable at these file sizes.
- `rar_extract`  - `ArchiveReader::read_with_options` + `extract_to`
  (the RAR13/15-40/50 decompressor). Window and output are bounded so a
  decompression bomb can't OOM/hang the run.
- `rar_map`      - `VolumeMapper`, the first thing every downloaded RAR
  volume touches. It is fed article spans in ARBITRARY ORDER while the
  download is still in flight, and every offset it produces - a piece's
  `data_off`, its `data_len`, the parse cursor's next stop - is
  arithmetic over attacker-declared header fields that the extractor
  turns straight into `pwrite` destinations, so this is the parser where
  a bad bound becomes a write, not just a bad read. Hunts panics,
  non-termination and unbounded growth (the cursor must strictly
  advance; a declared data area must not run past the volume; the RAR4
  name decoder must not amplify a 38-byte field into kilobytes of
  `String`) across three entry points at very different speeds: the
  mapper itself at full speed (no key schedule runs on this path), and
  the RAR4 `-hp` encrypted and plaintext header framing through
  dedicated entry points, since going through the mapper would run the
  KDF's 0x40000 SHA-1 rounds on every input.
- `rar_name_probe` - `nameprobe::rar_head` + `pick_rar_media_name` (RAR
  volume-head naming, TODO 131 rung 5). The layer ABOVE `rar_map`: that
  one covers the mapper's offset arithmetic, this one the blocker
  mapping and the name/key sanitising. Worth its own target because an
  `EncryptedHeader` verdict writes the TERMINAL `header_encrypted`
  classification - a volume that talks the parser into that answer
  retires a release from byte probing. Seeds: real `.rar` files
  verbatim (no selector byte, unlike `rar_map`).
- `mediaprobe`   - the container probe behind the preview-and-verify
  panel (`mediaprobe::probe` over MKV/WebM, MP4 and AVI). It reads a file
  that is still ARRIVING, before PAR2 has verified anything, so every
  length it follows is attacker-declared. Asserts determinism (the same
  bytes must probe to the same answer - which is why the parser's budgets
  contain no wall clock) and that the track/chapter/warning lists stay
  bounded, since a list that grows with a declared length is an
  allocation attack.
- `rar_recovery_scan` - the streaming recovery scanners:
  `scan_inline_recovery_chunks` (`{RB}` inline records) and
  `read_rev5_meta` / `verify_rev5_payload` (`.rev` headers). These size
  their own allocations from attacker-controlled header fields - the
  route the 64 GiB-from-1.8 MiB REV bomb took - and they run
  AUTOMATICALLY once extraction fails, so a panic or hang here is
  reachable by downloading a file. Asserts the ranges the scan reports
  stay inside the input, since callers read parity straight from them.
- `sevenz_name_probe` - `nameprobe::sevenz_tail_names` (7z end-header
  naming, TODO 131 B3). Run with `-rss_limit_mb=4096
  -malloc_limit_mb=128`: a legit probe peaks at a few MiB, and the low
  ceiling on the single allocation (not process RSS) is what makes a
  header decompression bomb (kEncodedHeader declaring a huge decoded
  size) trip instead of hiding under 4 GiB. 128 MiB is set just above
  the largest allocation the gates permit
  (`SEVENZ_PPMD_MEM_MAX` = 64 MiB). Seeds:
  `cp ../tests/fixtures/sevenz/* corpus/sevenz_name_probe/`.
- `sevenz_disk_gate` - `nameprobe::sevenz_disk_declared_bomb` (the
  whole-container declared-size gate: start geometry incl. the
  zeroed-start recovery-scan refusal, packed-header caps, an in-process
  LZMA/LZMA2 packed-header decode, and content-block dictionary/PPMd
  accounting - bug-sweep H1+H2, 14 Aug 2026). Run with the same
  `-rss_limit_mb=4096 -malloc_limit_mb=128` reasoning as
  `sevenz_name_probe`: the gate's own legal allocations top out around
  2 MiB (header window + bounded packed-header decode), so a big single
  allocation is a finding. Seeds: same fixtures dir.
- `remux`        - the fMP4 remuxer behind the in-page preview player. A
  harder target than `mediaprobe`: the probe reads a header and stops,
  this walks sample tables and block lacing, exactly the structures
  where one number describes another - a lace count that says how many
  sizes follow, a chunk table that says where payload begins, a declared
  size that says how far a frame extends - and every one of them arrives
  off Usenet before PAR2 has verified a byte. Asserts four properties
  beyond "does not crash": determinism, that every walk terminates,
  bounded allocation (nothing is sized by a declared length alone), and
  arrival-order independence - the same bytes served whole and served
  with a hole produce identical output up to the hole, which is the
  property the live-preview feature rests on. Run with
  `-rss_limit_mb=512`; seeds share `mediaprobe`'s generated fixtures.
- `audio_tags`   - the audio tag reader (issue #55). Every byte it
  parses is a filename an anonymous poster chose, and the value it
  returns is put on a file, so both the walk and the strings it yields
  are attacker controlled. Drives two surfaces: the input as a whole
  file (almost everything rejects at the magic gate, which is kept
  because that gate IS the first piece of armor), and the input wearing
  each supported magic, so the fuzzer reaches the metadata walks - block
  lengths, frame sizes, box sizes and the comment grammar - instead of
  being turned away at the door.
- `mkv_parse`    - the Matroska header probe on arbitrary bytes.
  Untrusted, completed downloads are opened to read duration and
  dimensions before renaming and sample-sweep decisions.
- `pesto_msgid`  - the pesto uploader-family adapter (TODO 131, red-team
  5a). Message-ids come straight off OVER headers from anonymous posters
  and are parsed for every scanned article, so the grammar parser is the
  hot untrusted surface; the FileDesc gate consumes lengths and hashes
  read out of attacker-authored PAR2 bodies. The PAR2 packet walk itself
  is already covered by `par2_parse`.
- `tar_parse`    - the tar container parser on arbitrary bytes.
  `nzbkit::tar::Reader` is the ONLY entry point that walks a posted
  `.tar` - the in-stream chase and the disk post-pass arm both drive it
  directly with no second copy of the grammar, so this target's coverage
  is theirs too. Exercises both the classification sniff
  (`looks_like_tar`, which a `.tar`-or-extensionless posted file is
  routed through first) and the header/data walk: checksums in both
  signed and unsigned form, octal and GNU base-256 sizes, the typeflag
  table, the `prefix` join, GNU long-name members and pax extended
  headers.
- `zip_parse`    - the zip container parser on arbitrary bytes. A posted
  zip is untrusted input that drives file creation, so both halves are
  exercised: reading the central directory, and decoding every entry it
  claims (sizes, offsets and the deflate stream itself all come from the
  attacker). The reader works over a real file because it preads by
  offset, so the target writes the input to a temp path per run.
- `zip_stream`   - the zip parser as the in-stream CHASE drives it, over
  an in-memory source. `zip_parse` already covers the disk reader, and
  the two share one `Source`-generic parser - but not one call order:
  the chase resolves an entry's crypto framing by reading ABOVE the body
  it is about to stream, wraps a bounded range reader rather than a
  file, and drains the source explicitly so a WinZip-AE HMAC is reached
  even when the deflate decoder stopped at its own stream end. Covers
  the encrypted path deliberately - encrypted entries stream in-stream
  now, and since the depth guard came off a zip chases at every nesting
  level, so these bytes can arrive from inside another attacker-supplied
  archive with nothing upstream having vetted them.
- `url_authority_diff` - `nzbkit::urlauth` (`url_host`/`url_netloc`, the
  M12 origin-bound fetch comparison) differentially against the `url`
  crate - the parser ureq dials with. Seed the corpus with real URLs
  first: "http://" is a 7-byte magic that coverage feedback alone is
  slow to discover.

## Run

    cd crates/nzbkit/fuzz
    cargo +nightly fuzz run rar_extract -- -max_total_time=120 -rss_limit_mb=4096 -timeout=10

`yenc_decode` also ships a dictionary - always pass it, or the fuzzer
essentially never guesses a yEnc header:

    cargo +nightly fuzz run yenc_decode -- -dict=yenc.dict -max_total_time=180

## Seed corpora (recommended, esp. for rar_extract)

The corpus is gitignored. Seed it from the in-tree fixtures so the fuzzer
starts from valid inputs and reaches the decode paths fast:

    mkdir -p corpus/rar_extract corpus/par2_parse corpus/rar_recovery_scan \
             corpus/nzb_parse corpus/yenc_decode
    # EVERY .rar in the fixture tree, at any depth, under a
    # path-qualified name. Both halves of that matter and the recipe
    # here got both wrong until 23 Aug 2026: a `rar*/*.rar` glob is ONE
    # level deep and reaches 54 of the tree's 141 archives, and a flat
    # corpus dir silently loses the three basenames that exist in more
    # than one fixture subdir. rar_extract INITED: 2,685 -> 5,722 edges.
    find ../../../vendor/rars/tests/fixtures -name '*.rar' -type f \
    | while read -r f; do
        cp "$f" "corpus/rar_extract/$(printf '%s' "${f##*fixtures/}" | tr / _)"
      done
    cp ../tests/fixtures/par2/*.par2                  corpus/par2_parse/
    # nzb_parse's corpus is COMMITTED since 30 Aug 2026 (seeds/nzb_parse/
    # is replayed by fuzz-smoke.yml's generic seeds/ loop, so CI gets it
    # too), and a recipe pointing at ../testdata/nzb is NOT the same
    # thing. Measured that day over 60 s bursts: committed seeds alone
    # (33 KB, largest unit 14 KB) reach 2,102 edges; adding the two
    # smaller testdata fixtures on top reaches 2,072 - WORSE - because
    # libFuzzer takes `max_len` from the largest corpus unit, so an
    # 84,880-byte fixture drops the burst from 120k execs to 54k. The
    # 1.18 MiB undefined-entity fixture is far past that; its shape is
    # carried by a 448-byte seed instead. Copy testdata for a long
    # CAMPAIGN with an explicit `-max_len`, not for a burst.
    cp seeds/nzb_parse/*                              corpus/nzb_parse/
    # yenc_decode's corpus is COMMITTED (seeds/yenc_decode/, 11 files /
    # 44 KB, added 27 Aug 2026) for the reason the 25 Jul entry below
    # describes: corpus/ is gitignored, so "seed it before you fuzz"
    # was machine-local advice that a fresh clone or a 60s CI burst
    # never sees - see seeds/README.md.
    cp seeds/yenc_decode/*                             corpus/yenc_decode/
    # mediaprobe's fixtures are generated, not committed - the test
    # suite writes them out on request:
    NZBFAST_WRITE_FUZZ_SEEDS=$PWD/corpus/mediaprobe \
      cargo test -p nzbkit --test mediaprobe write_fuzz_seeds
    # `remux` walks the same containers a layer deeper (sample tables,
    # block lacing), so it wants the same seeds. The two fixtures that
    # actually carry payload - mkv_remux, mp4_remux - are the ones that
    # reach the sample walk at all; the header-only ones stop at track
    # selection, which is worth fuzzing but is not where the arithmetic
    # is.
    NZBFAST_WRITE_FUZZ_SEEDS=$PWD/corpus/remux \
      cargo test -p nzbkit --test mediaprobe write_fuzz_seeds
    # rar_recovery_scan's corpus is COMMITTED (seeds/rar_recovery_scan/,
    # 242 files / 240 KB) rather than recreated by a cp, because every
    # entry point it has is behind a checksum or a signature and the
    # recipe that used to sit here was both skippable and wrong - see
    # seeds/README.md.
    cp seeds/rar_recovery_scan/* corpus/rar_recovery_scan/

## Status

23 Jul 2026 smoke pass (cold-start, ~60-120s each): ~5.8M+ total
executions across the four targets that existed then (`yenc_decode`,
`nzb_parse`, `par2_parse`, `rar_extract`), ZERO crashes. Longer campaigns
with the seed corpora are the next step for deeper coverage. The targets
added since have their own entries below; a green smoke run is evidence
about that run, not a standing property of the target.

25 Jul 2026 - `yenc_decode`'s corpus was found to contain ZERO inputs with
`=y` in them: it had only ever exercised the header-absent early return,
which is how three silent-truncation bugs in the `=y` control-line handling
survived it. Seeded with encoder output (CRLF, bare-LF, dot-stuffed,
multi-part, all-256-byte-values) plus the known bug shapes, and given
`yenc.dict`. The first seeded run found six real decoder divergences in
under ten minutes (dot unstuffing, duplicate/junk header keys, `name=`
swallowing later fields, whitespace-glued keys, multi-trailer gates); all
are fixed, and the target now runs clean at ~1.1M execs / 180s.

25 Jul 2026 - `rar_recovery_scan` added with the streaming recovery
rewrite. Cold-start smoke: 3.1M executions in 121s, ZERO crashes, RSS
flat at 112 MB throughout, which is the property the target exists to
pin. Coverage was only 95 edges cold: the chunk parser is behind a CRC64
gate the fuzzer will not guess, so this one genuinely needs its seed
corpus to reach the plan arithmetic.

23 Aug 2026 - `rar_recovery_scan` seeded for good (TODO 16k). The seed
corpus is now COMMITTED at `seeds/rar_recovery_scan/`, 242 files / 240 KB,
so a cold start is not a thing that happens here any more: **INITED 1,686
edges** against **226** reached by a 60s cold run. First seeded campaign:
**1,952,069 executions in 3,600s, cov 3,229, ZERO crashes, OOMs or
timeouts**, peak RSS 354 MB (the 112 MB above was a 6-input corpus; the
flatness, not the number, is the property - libFuzzer holds the corpus
resident, and this one is 19 MB by the end).

Two things the old recipe got wrong, both found by measuring it rather
than reading it:

- It copied SIX `.rev` fixtures and only TWO of them reach anything. The
  RAR 2/3 `rev_oldstyle` / `rev_newstyle` volumes are headerless parity
  blobs - no signature at all - so `read_rev5_meta`,
  `scan_inline_recovery_chunks` and `ArchiveReader::read` each refuse
  them on their first check. All six together are 296 edges at INITED,
  of which the four inert ones contribute 14, all on the refusal path.
- It copied no ARCHIVES, and the archives are where the coverage is: the
  `{RB}`-bearing RAR5 volumes and the RAR 2/3 protect-record fixtures
  take it from 296 to 1,434. `fuzz-smoke.yml` did copy `.rar` fixtures,
  but through a one-level `rar*/*.rar` glob that cannot see
  `rar15_40/rar300/`, which is where all three legacy RR fixtures live -
  so CI reached the leg added in `507eef5ed` only by mutation.

27 Aug 2026 - post-v1.2.4 overnight campaign (`fuzz-campaign-post-v124`),
triggered by the release's parser churn: §296 changed settle ordering on
the extract path, §297 added nzbindex as a new NZB ingestion source, and
the 22-23 Aug disk-unpack round touched the RAR/7z container readers.
`vendor/rars` had also been re-synced since the last campaign (23 Jul),
which alone would have called for a re-fuzz of every RAR target.

Ten targets, 4h each (`-max_total_time=14400`), all ten run in PARALLEL
(one core apiece, on a 32-core box already carrying other lanes - kept
to 10 concurrent jobs deliberately, per the "leave room" instruction):
`yenc_decode`, `nzb_parse`, `par2_parse`, `par2_verify_diff`,
`rar_extract`, `rar_map`, `rar_name_probe`, `rar_recovery_scan`,
`sevenz_name_probe`, `sevenz_disk_gate` (the last two with
`-malloc_limit_mb=128` per this file's own guidance above). Corpora
seeded from every in-tree fixture and committed `seeds/` corpus this
file and `seeds/README.md` name; `yenc_decode` additionally seeded from
a hand-built 11-file corpus committed this same night (see
`seeds/README.md`), closing the cold-start gap the 25 Jul entry above
left open (the fix that day was to a gitignored `corpus/`, so it never
survived past that one machine).

**352,444,582 executions total, ZERO crashes, OOMs, timeouts or leaks,
across all ten targets:**

| target | executions | exec/s (avg) | final corpus |
|---|---|---|---|
| `yenc_decode` | 44,520,321 | 3,091 | 1,779 files / 6.9 MB |
| `nzb_parse` | 3,794,579 | 263 | 1,983 files / 136 MB |
| `par2_parse` | 64,107,746 | 4,452 | 180 files / 996 KB |
| `par2_verify_diff` | 8,559,854 | 594 | 329 files / 1.3 MB |
| `rar_extract` | 520,560 | 36 | 2,158 files / 295 MB |
| `rar_map` | 45,473,993 | 3,158 | 1,029 files / 9.2 MB |
| `rar_name_probe` | 73,992,172 | 5,138 | 197 files / 788 KB |
| `rar_recovery_scan` | 16,091,634 | 1,117 | 2,970 files / 27 MB |
| `sevenz_name_probe` | 24,480,219 | 1,700 | 2,829 files / 11 MB |
| `sevenz_disk_gate` | 70,903,504 | 4,924 | 807 files / 3.2 MB |

`rar_extract`'s low exec/s is corpus-driven, not a stall: it holds the
largest average input of any target here (its corpus is dominated by
real multi-hundred-KB archives) and the decompressor genuinely does
that much work per input. `nzb_parse` similarly - a 1 MiB `-max_len`
XML body is expensive to parse and its corpus grew to 136 MB of
fuzzer-discovered structure. `-print_final_stats=1` output (peak RSS,
new-units-added) landed for only 2 of the 10 logs; the other 8 lost it
to a buffering/flush race between the `-max_total_time` watchdog firing
and process exit - a harness artifact, not a target property. No
process approached the 4096 MB `-rss_limit_mb` ceiling on the two
observed (peak 1046 MB and 1106 MB).

Corroborated by the two 7z targets' own final-stats block:
`sevenz_name_probe` added 15,513 new corpus units over the run (cov
still climbing at the 4h mark), `sevenz_disk_gate` added 4,887.

2-3 Sep 2026 - `par2_verify_diff` and `par2_parse`, against
**`46bd58e51`**, and the first campaign here to run libFuzzer's FORK
mode (`-fork=5` / `-fork=2`). That is what makes a campaign possible on
`par2_verify_diff` at all: it writes its payload to disk every case, so
one process does 417-720 exec/s whatever the wall clock, and five give
~3,100/s. **165,678,477 executions, ONE crash**, and the crash was the
target's own oracle rather than the verify path - the write-up, the
audit behind that verdict and two measurements that revise how this
target should be scheduled are in
`research/PAR2-VERIFY-DIFF-CAMPAIGN-2026-09-02.md`.

| target | executions | wall | exec/s | final cov / ft | corpus |
|---|---|---|---|---|---|
| `par2_verify_diff` (as shipped) | 30,658,465 | 9,774 s | 3,137 | 728 / 2,867 | 311 -> 363 files |
| `par2_verify_diff` (oracle fixed) | 37,415,437 | 10,851 s | 3,448 | 732 / 2,889 | 363 -> 375 files / 1.5 MB |
| `par2_parse` | 97,604,575 | 14,425 s | 6,766 | 571 / 2,104 | 2 -> 170 files |

The crash came 2h43m and 30.6M executions in, and libFuzzer got there
by SOLVING a CRC32 comparison with its CMP instrumentation - the kind
of input no 60 s burst builds. Both repros are committed under
`seeds/par2_verify_diff/`. Fork mode's supervisor prints no
`-print_final_stats=1` block of its own, which is a second reason the
peak-RSS column is missing here as well as in the 27 Aug entry above;
the one job that did report (the crashing one) peaked at 226 MB against
a 4,096 MB ceiling.

Two things worth carrying forward. This target's `md5_unfinished`
branch is taken on 25.5% of executions, so length converts into it
directly rather than needing a generator change. And its edge space
saturates from COLD in under a minute - cov 699 of the ~730 that exist,
from an EMPTY corpus, in 60 s - so corpus FILE COUNT says nothing about
how saturated it is, and there is deliberately no derived seed corpus
committed for it (`seeds/README.md` has the numbers). `par2_parse` has
now had two 4 h campaigns a week apart, 64.1M on 27 Aug and 97.6M here,
with nothing to show either time.
