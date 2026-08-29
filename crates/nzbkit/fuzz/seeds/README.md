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
