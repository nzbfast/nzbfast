# Committed fuzz seeds

`corpus/` is gitignored (it is machine-local and grows), so a repro that
CI found would be lost the moment its artifact expired. Anything in
`seeds/<target>/` is copied into `corpus/<target>/` by the seed step in
`.github/workflows/fuzz-smoke.yml`, so every future smoke run replays it.

Two kinds of thing live here, and they are replayed by the same step:

- a crash/OOM/timeout **repro**, kept under the name libFuzzer gave it so
  it maps back to the CI artifact it came from; and
- a **seed corpus** for a target whose interesting code sits behind a
  checksum or a magic no mutator will guess, where a recipe in
  `../README.md` was the only thing standing between a run and cold
  start. A recipe that is not optional is a recipe somebody skips, and
  the skip is silent - the run still prints execs and still says zero
  crashes, it just never reached the arithmetic.

Note either below.

- `nzb_parse/` (19 files / 33 KB, 30 Aug 2026) - a SEED CORPUS, not a
  repro, and the second kind of entry above: an NZB is XML, so every arm
  worth reaching sits behind a well-formed element tree that libFuzzer's
  mutations find about as often as they find a CRC. Measured that day,
  INITED: 110 edges cold, 1,318 seeded; after a 60 s burst, 861 cold
  against 2,102 seeded. Four of the files are realistic posting shapes (a
  multi-file release, a PAR2-bearing set with an index and three
  recovery-volume spellings, an unquoted split archive, an obfuscated
  hash-named post); the rest are one per confirmed row of the 30 Aug 2026
  parser/front-door addendum, named `n6-NN-*` after the row. The
  `../README.md` recipe used to point at `../testdata/nzb/*.nzb` instead,
  and that is NOT the same thing and measurably worse: libFuzzer takes
  `max_len` from the largest corpus unit, so the 84,880-byte garbled
  fixture halves the burst's exec count and the 1.18 MiB
  undefined-entity fixture is far past that. Both of those shapes are
  carried here by seeds under 600 bytes.
  The ordinary-test twins are in
  `crates/nzbkit/tests/integration/fuzz_seed_corpus.rs`, and they are
  split deliberately: SETTLED outcomes (an undefined entity refused, the
  HTML latin-1 set resolved, CDATA and comment-split text re-joined) are
  asserted by result, while the N6-01..N6-08 seeds are asserted only to
  still CARRY their shape. That was written while those rows were open;
  both lanes have since landed (`dd479f9b4`, `97e4dea88`, 30 Aug 2026)
  and each row is pinned by its own deterministic regression in
  `crates/nzbkit-base/src/nzb_tests.rs`. The split STAYS anyway, and for a
  better reason than the original one: this file checks that a SEED
  still carries the shape it was committed for, and putting a second
  copy of each row's outcome assertion here would be two places to keep
  in step for no coverage.

- `nzb_semantic/` (18 files / 613 bytes, 31 Aug 2026) - a SEED CORPUS,
  and the only one here whose files are not inputs to a parser at all.
  That target reads its bytes as a stream of CHOICES, so a seed is a
  choice stream: the first byte picks the arm, the next few pick the
  shape, and the rest are style flags. They are named for what they
  select and every one was VERIFIED to select it (a temporary probe
  build printing the resolved family, 31 Aug 2026) rather than computed
  and assumed.
  Eight `break-N-*` files are one per `Schema` violation the hostile arm
  can spell, six `long-*` are one per capped field at a length that
  crosses its own ceiling, and four `nzbc-*` are the two N6-09 COUNT
  ceilings in both element spellings. The SEGMENT pair keeps the cheap
  default-namespace style in both spellings and the prefixed style rides
  the FILES pair instead, which is a tenth of the cost and exercises the
  identical counter - the ceiling is one check on a match arm that takes
  `Event::Start` and `Event::Empty` together, so the spellings part
  company downstream of it rather than at it.
  The `nzbc-*` four are the ones that need explaining. Those documents
  run to NINETEEN MEGABYTES - 1,000,001 segments, or 100,001 files -
  so the target puts them behind a four-byte magic AND a per-process
  BUDGET, and the budget is not caution: with the magic alone, measured
  that day, the four seeds took a 60 s burst from 1,557 exec/s to 287,
  because libFuzzer keeps them and then mutates around them and a mutant
  that leaves four bytes alone rebuilds the whole document. With the
  budget it is 1,594 exec/s and the ceilings are still reached at
  INITED, which for a state space of one is the stronger guarantee
  anyway: a ceiling that regressed fails in the first seconds of every
  run rather than at some point in a campaign.
  The ordinary-test twin is
  `fuzz_seed_corpus.rs::the_nzb_semantic_seeds_still_select_a_hostile_arm`.
  It is weaker than the other twins on this page and says so: a choice
  stream means nothing outside the target, so what it can hold is the
  selector arithmetic, mirrored. What it catches is the failure that
  actually happens - a seed that silently starts selecting the legal
  arm after the arm order moves, leaving every hostile family
  unreachable at INITED while the run still prints a hundred thousand
  execs.

- `rar_name_probe/crash-f064a660a000d079ef552779894d5aa9ba76d15c` - a
  RAR4 main header declaring `head_size` 7 while carrying `MHD_COMMENT`,
  whose CRC range is a fixed 13 bytes: the probe's truncated-half feed
  left 12 bytes and `v4_header_crc` sliced `h[2..13]` out of them. Fixed
  by the `head_size < 13` guard in `rar.rs`; the unit-test twin is
  `a_comment_block_shorter_than_its_fixed_crc_range_is_refused`.
- `zip_parse/oom-437816e14944e2fc4658651e31e35851fe966516` - 139 bytes:
  an LZMA (method 14) entry declaring a 128 MiB dictionary over an
  84-byte body and a 2.9 GiB uncompressed size, so `LzDecoder::
  ensure_capacity` allocates the whole window up front. NOT a bug and
  NOT fixed by a code change: 256 MiB (`LZMA_DICT_MAX`) is exactly
  7-Zip's `-mx=9` output, so the cap cannot come down without refusing
  real archives - see the constant's comment in `zip.rs` for the
  measured `-mx` ladder and why a ratio guard buys nothing. Kept
  because it is a good corpus entry for the method-14 framing. The
  ordinary-test twins are
  `the_lzma_dictionary_cap_admits_7zips_top_preset_and_nothing_above_it`
  and `the_lzma_oom_seed_leaves_by_the_ordinary_error_path`. It was
  reported as an OOM only because that lane ran the zip targets under
  `-malloc_limit_mb=128`, which fuzz-smoke.yml applies to the 7z
  targets alone.
- `sevenz_name_probe/oom-b7ac49cace9854623f5eedf2f72f38047546621e` - 33
  bytes: a raw `kEncodedHeader` window (the target seals it into a 7z
  container itself) declaring one 16-byte pack stream and one block
  whose single coder is LZMA2 (method id `0x21`), with a props byte of
  0x21 = 33. LZMA2 encodes the dictionary in that ONE byte as
  `(2 | p & 1) << (p / 2 + 11)`, so 33 names `3 << 27` = 384 MiB, while
  the block's `kCodersUnpackSize` declares NINE bytes of output. The
  last nine bytes are mutation residue past the point the scan stops.
  A REAL bug, and fixed by a code change: `LzDecoder::ensure_capacity`
  allocates the match window whole, and lzma-rust2 does not clamp it to
  the unpack size on the LZMA2 path, so the 2 MiB `SEVENZ_END_MAX`
  output cap never saw the allocation - same shape as the PPMd memSize
  hole of 10 Aug 2026, a cost declared in the coder PROPS and paid
  before any output exists to bound it. Fixed by `SEVENZ_DICT_MAX`
  (64 MiB) over both LZMA1's 32-bit dictSize and LZMA2's exponential
  byte (`p > 40` refused outright) in `nameprobe.rs`, in the gate both
  7z entry points share. Unlike the zip entry above, the OOM label here
  is NOT a harness threshold artifact: `malloc(402653184)` is one
  allocation, and it trips any single-allocation ceiling below 384 MiB.
  The `-malloc_limit_mb=128` that fuzz-smoke.yml applies to the two 7z
  targets alone is only what made it VISIBLE - the `-rss_limit_mb`
  ceiling it replaced never surfaced it, and neither did a 60s burst;
  it took a 420s soak. The ordinary-test twin is
  `checked_in_fuzz_seeds_keep_their_meaning`, which reaches it through
  `tests/fixtures/sevenz/lzma2-dict-window.bin` - a byte-identical copy
  of this seed.

- `rar_recovery_scan/` - a SEED CORPUS, not a repro: 242 files, 240 KB.
  Every entry point this target has is behind a checksum or a signature
  (a CRC64 over each `{RB}` chunk, a RAR5 REV header, a RAR volume
  signature), so cold it reaches 226 edges and seeded it reaches 1,686,
  and TODO 16k stood open for a month on a `cp` recipe nobody was
  obliged to run. Eight of the files are copies of in-tree fixtures,
  kept under their own names: `multivol_rev.part{1,2}.rev` (RAR5 REV
  headers - the route the 64 GiB-from-1.8 MiB bomb took),
  `with_recovery.rar` / `with_all_services.rar` (inline `{RB}` records),
  and `rar250_protect_head_rr1.rar` plus the three
  `*recovery*_rar300.rar` (the legacy RAR 2/3 protect-record repair
  added in `507eef5ed`). The other 234 are fuzzer-derived, distilled out
  of a 3,600s campaign with `cargo +nightly fuzz cmin` after dropping
  everything over 4 KB - uncapped the same distillation is 943 files and
  13.9 MB, which is not a thing to commit.

  The eight named fixtures add no edge the derived 234 do not already
  reach, and they are here anyway: a derived blob is a byte string that
  happened to fit today's parser, while a fixture is real WinRAR output
  that stays meaningful across a change to `rars`. They are also the
  half that can be ASSERTED, and they are:
  `crates/nzbkit/tests/fuzz_seed_corpus.rs` holds each one to the entry
  point it was committed to reach, in an ordinary `cargo test` needing
  neither nightly nor cargo-fuzz. That test is the point of the pairing -
  a corpus that quietly stops reaching the gated code still prints
  millions of execs and still says zero crashes, which is exactly how
  `yenc_decode`'s `=y`-less corpus survived three silent-truncation bugs.

  NOT here, deliberately: the other four in-tree `.rev` fixtures. The
  RAR 2/3 `rev_oldstyle` / `rev_newstyle` volumes are headerless parity
  with no signature at all, and all three entry points refuse them on
  their first check - 14 edges between the four, all on the refusal
  path. The recipe in `../README.md` used to copy all six, which is how
  a seeding step can look done and be two-thirds inert.

- `yenc_decode/crash-d94c80b4149bae0e461b8c0d86d2f5757efdf9cf` (127 B,
  3 Sep 2026) - a REPRO, and the x86 TWIN of the entry below: same class
  (a width-aligned SIMD over-read that cannot fault and cannot change an
  answer, which ASan aborts on), different kernel family. This one is
  the CRC side, not the decode side. The body is a `=ybegin` header, 101
  bytes of `0xff` and a `=yend crc32=` trailer, which is what makes the
  target compute a CRC at all; its length is what matters, not its
  bytes, because a CRC kernel branches on neither.
  `AddressSanitizer: unknown-crash` inside the `vpclmul` CRC kernel,
  which finished the buffer with an aligned 32-byte load while 1..31
  bytes remained. The `generic` and `pclmul` kernels each ran their full
  46 s clean in the same job, and `fuzz-arm` was green, because that
  kernel is x86-only - run 33719528482, the FIRST scheduled run to reach
  it, the CRC pin having landed the day before (`db85dff50`). The
  128-bit sibling carried the identical defect at four tail sites and is
  fixed in the same commit. Fixed in
  `vendor/rapidyenc/src/crc_folding_256.cc` and `crc_folding.cc`; the
  reasoning, the five sites and the honest limit (no box on this fleet
  can execute either kernel) are in `vendor/rapidyenc/VENDOR.txt` under
  Local patches. The value oracle is
  `yenc_simd::tests::every_reachable_crc_kernel_matches_the_oracle`,
  which already sweeps every tail residue at four alignments with each
  case at the end of its own heap block.

- `yenc_decode/crash-8937f3763d1ff20d1926829b1448067ae62341c2` (261 B,
  2 Sep 2026) - a REPRO, and the first entry here that is a repro for a
  memory-safety fault rather than a wrong answer. It is a one-byte
  mutation of `seed_small.bin` below, and the mutation is not what
  matters: `seed_small.bin` ITSELF trips the same fault, so the target
  aborted inside `ReadAndExecuteSeedCorpora` before libFuzzer had
  mutated anything. Under `NZBFAST_FUZZ_YENC_KERNEL=neon` (which is
  also what an UNPINNED run selects on any Apple silicon box) both
  files hit `AddressSanitizer: heap-buffer-overflow, READ of size 16`,
  10 bytes past the end of the article body, inside
  `RapidYenc::do_decode_neon<true, true>`. rapidyenc's two ARM decode
  kernels loaded a whole 16-byte vector for a 4-byte lookahead that
  `_do_decode_simd`'s `lenBuffer` reserves exactly 4 bytes for; the x86
  kernels load exactly 4, which is why the ubuntu smoke run was green
  over these same seeds. Fixed in `vendor/rapidyenc/src/decoder_neon64.cc`
  and `decoder_neon.cc` the same day (see `../../../../vendor/rapidyenc/VENDOR.txt`
  and `research/YENC-NEON-OVERREAD-2026-09-02.md`).

  Read the pairing rule above with care here: a plain `cargo test` over
  these bytes CANNOT catch this class. The fault is an aligned read
  inside the same 64-byte block, so it can never fault on real hardware
  and never changes an answer - AddressSanitizer is the only detector,
  and ASan reaches this C++ only in a `cargo fuzz` build (2 Sep 2026,
  `e0dedc105`). So the gate for this regression is an ARM box running
  this target, not a unit test, and today no CI runner is one.

- `yenc_decode/` - a SEED CORPUS, 11 files / 44 KB, added 27 Aug 2026
  (post-v1.2.4 overnight campaign) to close the exact gap the 25 Jul
  entry above describes in passing: `corpus/` is gitignored, so the
  discovery that the target's corpus held ZERO `=y` inputs was a
  finding about that one machine's accumulated state, not a property
  the repo remembered - a fresh clone or a short CI smoke burst starts
  from the same blind cold start every time, with only `yenc.dict`
  (a flat string list, not a seed) standing between it and the control
  line. Hand-built, one file per shape the 25 Jul note names as having
  taken the corpus that long to reach on its own: `seed_all256_{crlf,lf}.bin`
  (a full 0-255 payload, once each line ending), `seed_dotstuff.bin`
  (an encoded line starting with `.`, the leading-dot unstuffing path),
  `seed_multipart_p{1,2}.bin` (`=ypart`/`total=2` framing),
  `seed_junkheader.bin` (a duplicate `name=` plus an unknown key),
  `seed_namefield.bin` (a filename containing a space, unquoted),
  `seed_glued.bin` (header keys separated by runs of spaces rather than
  one), `seed_noend.bin` (body with no `=yend` at all) and
  `seed_orphanpart.bin` (a bare `=ypart` with no preceding `=ybegin`).
  Not a repro for any specific bug - the six silent-truncation shapes
  the 25 Jul first seeding found are long since fixed - but the same
  category of thing: `=ybegin`/`=yend`/`=ypart` is a magic no mutator
  finds cold in a 60s CI burst, and every one of these shapes is a
  distinct control-line edge the target's own doc comment says it
  differentially checks (SIMD path vs scalar path). Verified rather
  than assumed: all 11 were part of the corpus that ran 44.5M
  executions over 4h in the campaign that added them, mutated
  continuously, zero crashes or decoder divergences.

- `tar_parse/` - a SEED CORPUS, and there was no in-tree tar fixture of
  any kind to copy (`nzbkit::tar` is a new parser, TODO 163 item 6). 15
  files, 112 KB: `plain_ustar.tar`, `gnu_longname.tar`, `pax_longname.tar`
  and `default_fmt.tar` are real `bsdtar 3.5.3` output (macOS's system
  `tar`) over a small tree with a subdirectory, a symlink and a
  path deep enough to force long-name framing - `--format=ustar`,
  `--format=gnutar`, `--format=pax` and bsdtar's own default
  respectively, so the corpus starts from all three magic/checksum
  shapes a real writer produces rather than one. The rest are
  `synth_*.tar`, built with the crate's own `tar::fixtures::tar_of` (the
  hand-rolled writer the unit tests use) for shapes no unprivileged
  `tar` invocation on this box reaches: `synth_gnu_longname.tar` /
  `synth_pax_longname.tar` force the two long-name spellings the same
  way `reads_long_names_both_ways` does, `synth_reference_*.tar` covers
  all four reference typeflags (symlink, hard link, device node, FIFO -
  a device node needs root to create for real), and
  `synth_sparse_typeflag.tar` / `synth_sparse_pax.tar` are the sparse
  refusal in both spellings (the GNU `S` typeflag, and the pax
  `GNU.sparse.*` keyword hidden behind an ordinary file header) -
  `parse_pax`'s byte-vs-char slicing the reader's own doc comment flags
  as found by inspection rather than by a test, which is the argument
  for fuzzing it at all. Every seed here was parsed with
  `nzbkit::tar::Reader` before being committed (the four real ones read
  clean end to end; the two sparse ones correctly return the
  `Unsupported` refusal) so none of them is dead weight in the corpus.

- `par2_verify_diff/` - two REPROS, 183 bytes between them, and the
  first entries this target has had. Its seeds are CHOICE STREAMS, not
  PAR2 files: the target reads the bytes as a series of small picks
  (block size, declared length, which payload lands on disk, which claim
  the FileDesc MD5 states, how long the IFSC list is and what it
  describes), so handing one to a parser proves nothing. Both are also
  small enough not to move `max_len`, which is the measured trap the
  `nzb_parse` entry above records.

  - `crash-3bf05aa41303eb270ccae2a12c280f1f1c70c9fc` (172 bytes) - found
    2 Sep 2026 by the first long campaign on this target, 2h43m and
    30.7M executions in (`46bd58e51`;
    `research/PAR2-VERIFY-DIFF-CAMPAIGN-2026-09-02.md`). An IFSC entry
    with an ALL-ZERO MD5 beside the tail slice's exact CRC32 - the
    `BlockCheck::UNPROVEN` placeholder shape, which vouches for no bytes
    whatever its CRC32 field says. NOT a production bug: every CRC-only
    site in the tree goes through `crc_matches`, and the audit is in the
    campaign record. The defect was the target's own oracle, which
    modelled one half of the rule. libFuzzer got here by SOLVING the
    CRC32 comparison with its CMP instrumentation (the mutation line
    carries the four CRC bytes as a dictionary entry), which is exactly
    the kind of input a 60 s burst does not build. The ordinary-test
    twin is
    `par2repair::unit_tests::a_zero_md5_ifsc_entry_never_reads_as_present_even_with_the_right_crc`,
    which pins the rule at both places `verify_pass1` decides a slice -
    a whole block and the zero-padded tail.
  - `crash-b046c9bc493b4d08dafdf9083153a38466cccad1` (11 bytes) - the
    `md5_stopped` contract regression fuzz-smoke found in run
    33678333481, nine hours after `7f195ff27` caused it, resolved by
    `ad597c06d` (the contract is "not proven", the target was reading a
    withheld verdict as a decided one). Committed here on 3 Sep because
    it had been sitting in a gitignored `artifacts/` directory on one
    box ever since - the CI artifact expires in 90 days and nothing else
    in the repo held those eleven bytes. The ordinary-test twin is
    `par2repair::unit_tests::filedesc_md5_over_bytes_the_ifsc_denies_is_unproven_not_damaged`.

  There is deliberately NO seed CORPUS here beside them, and the reason
  is measured rather than assumed: unlike `rar_recovery_scan` this
  target has no checksum or magic in front of it, so a cold 60 s run
  reaches cov 699 of the ~730 edges that exist (INITED 182), where the
  30.7M-execution campaign's warm corpus ended at 728. A committed
  corpus would buy a few dozen edges and carry ~360 derived blobs to do
  it. What length buys on this target is the feature space, and no
  corpus shortens that.
