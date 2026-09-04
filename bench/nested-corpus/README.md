# Nested-archive benchmark corpus

A reproducible corpus of nested-archive Usenet posts - from the everyday
RAR-in-RAR shape up to deliberately hostile multi-level damage - plus a
loopback NNTP rig to run any client against it. Built for measuring how
much of a nested post a downloader completes automatically versus how
much is left for the operator to finish by hand.

Everything here is generated: payloads are random bytes from
/dev/urandom, archives are built locally by the listed tools, and the
NZBs point at a local mock server. No third-party or copyrighted
material is included or required, so the corpus and its results can be
published freely.

## Layout

    generate.sh          builds the corpus (this is the reproduction step)
    lib.sh               shared shell helpers
    validate.py          corpus self-test: proves every leg is recoverable
                         with stock tools (par2, unrar, rar r, 7z)
    run-legs.sh          drives clients against each leg over the rig
    classify.py          grades one client run of one leg
    nzbserve/            the rig: builds each leg's NZB and serves the
                         leg's files as real yEnc articles over plain-TCP
                         NNTP (reuses the repo's mock NNTP server)
    corpus/<tier>/<leg>/ generated output: post/, ghost/, manifest.json,
                         <leg>.nzb

## Required tools

Versions the corpus was authored and verified against:

| tool | version | used for |
| ---- | ------- | -------- |
| rar (rarlab CLI) | 7.23 | RAR5 archives, store + compressed, volumes, recovery records, passwords |
| 7-Zip (7zz, or 7z/7za) | 26.02 | 7z layers (LZMA2) |
| par2 (par2cmdline) | 1.2.0 | PAR2 sets, including the 100% recovery leg |
| | | (1.3.0 also validates all 14 legs, measured 3 Sep 2026; never the 0.8.1 package - see memory `nzbfast-ci-par2-version-skew`) |
| cargo (Rust) | repo toolchain | builds nzbserve |
| unrar 7.23 | validation only | validate.py extraction chain |

`generate.sh` checks for these and stops with a clear message if one is
missing. The rar CLI is the only non-free tool (trial versions work);
every other tool is freely available.

## Reproducing the corpus

    ./generate.sh                # full sizes (payloads 256 MB - 1.5 GB)
    ./generate.sh --quick        # small payloads (6 - 24 MB) for CI/self-test
    ./generate.sh --tier extreme # one tier only
    ./generate.sh --leg r2-depth2-store-store
    ./validate.py corpus         # self-test: every leg must recover

Structure is deterministic: the same legs, shapes, nesting depths,
volume splits, and damage offsets every run. The payload bytes are drawn
fresh from /dev/urandom each generation and pinned by sha256 in each
leg's `manifest.json`, so any two copies of a generated corpus are
verifiable even though their bytes differ.

## The legs

### realistic - shapes seen in everyday posts (1.5 GB payloads)

| leg | shape | depth |
| --- | ----- | ----- |
| r1-depth1-store | store RAR volumes + PAR2 | 1 |
| r2-depth2-store-store | store RAR inside store RAR | 2 |
| r2c-depth2-store-compressed | compressed RAR inside store RAR | 2 |
| r3-rar-wrap-7z | 7z (LZMA2) inside store RAR | 2 |
| r4-inner-damaged | intact post, damaged inner RAR, its PAR2 packed alongside | 2 |
| r5-zip | zip (store) + PAR2 | 1 |
| r6-7z-split | 7z copy split volumes + PAR2 | 1 |

### extreme - depth stress (256 - 512 MB payloads)

| leg | shape | depth |
| --- | ----- | ----- |
| x1-depth5-ladder | store RAR ladder, sibling file at every level | 5 |
| x2-depth10-ladder | store RAR ladder, sibling file at every level | 10 |
| x3-mixed-7z-rar-store | RAR > 7z > RAR > payload | 3 |

Note on x2: nzbfast caps nested extraction at depth 5 today (the
in-stream extractor and the disk pass share the cap), so this leg
currently measures graceful behavior at the cap - the deepest reached
layer is left as a healthy archive rather than a failed job. It becomes
a full-automation leg once the depth setting lands.

### apocalypse - damage, loss, and passwords (384 MB payloads)

| leg | shape | depth |
| --- | ----- | ----- |
| a1-damage-every-level | 64 bytes poisoned at every level; PAR2 posted for the outer, a PAR2 for level 2 packed inside the outer, a recovery record inside level 3 | 3 |
| a2-par-only | every archive article missing (430); the posted PAR2 set carries 100% recovery data | 1 |
| a3-password-chain | each level AES-encrypted; each level ships the next level's password as a sibling text file; outer password posted in the clear | 3 |
| a4-meta-password | AES volumes whose password rides only in the NZB's `<meta type="password">` | 1 |

Passwords for a3 are fixed and documented: `corpus-a3-l1`,
`corpus-a3-l2`, `corpus-a3-l3` (also in the leg's manifest).

## Manifests and the completion classes

Each leg's `manifest.json` records the shape, depth, tool versions, the
sha256 of every final payload file, the posted and ghosted file lists,
and an expected completion class per client. Classes:

- **auto-complete** - the client finished with every final payload
  present and byte-identical, no operator action needed.
- **manual-intervention** - the client finished without an error, but
  archives or repair steps were left for the operator (an inner archive
  sitting in the output directory is the classic sign).
- **fail** - the client errored out or timed out without producing the
  payloads.

The framing is deliberately factual: a manual-intervention result means
"this shape needs operator work with this client today", nothing more.
Expected classes for clients that were not run are hypotheses and are
marked as such in the manifest notes; `run-legs.sh` records measured
classes.

## Running clients against the corpus

    # one leg, nzbfast only
    NZBFAST=../../target/release/nzbfast \
      ./run-legs.sh corpus/realistic/r2-depth2-store-store nzbfast

    # a whole tier, nzbfast + nzbget
    ./run-legs.sh corpus/realistic nzbfast nzbget

`run-legs.sh` starts nzbserve for the leg, runs each client with the
same connection count, and appends one result line per run to
`corpus-run/suite.log`:

    LEG <leg> <client> wall_s=<s> hiwater_mb=<MB> rc=<rc> class=<class> ...

- `wall_s` - wall time for the whole job including post-processing.
- `hiwater_mb` - disk high-water of the client's working tree (du
  polled at 1 s), the cost nested one-pass extraction removes.
- `class` - measured completion class from classify.py.

The rig serves every article from RAM as real yEnc over plain TCP on
127.0.0.1, so results measure the client, not a provider - no Usenet
account or network access is involved. The SABnzbd and rustnzb drivers
need their binaries pointed at via `SAB_CMD` / `RUSTNZB` and are
best-effort.

## License

All corpus content is machine-generated for this benchmark (random
payloads, locally built archives and NZBs) and carries no third-party
material. The scripts and the generated corpus are covered by the
repository license.
