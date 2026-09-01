# Posting the benchmark corpus

`nzbfast post` uploads local files as yEnc articles to a test newsgroup and
writes the matching NZB, so published benchmarks can reference real,
downloadable posts. It is an internal ops tool - it is not documented in the
user manual and its defaults are tuned for corpus uploads, not general
posting.

## The one rule: pick the server yourself

`--post-server` is mandatory and must name exactly ONE server from the
config. There is no default, and there is deliberately no "post through all
servers" mode. The tool refuses to run without the flag, refuses an
ambiguous name (two entries sharing a host - disambiguate with `host:port`),
and refuses a server that is disabled in the config. It prints the chosen
server and a summary line before any byte moves - read that line.

## Typical corpus upload

```bash
nzbfast post bench/nested-corpus/generated --post-server news.example.com \
  --nzb bench/nested-corpus/corpus.nzb --title "nzbfast bench corpus v1" --verify
```

- Directories are walked recursively; files post under their file name only
  (local directory layout never reaches the wire, except through a `--par2`
  set's FileDesc packets - see No-RAR mode). Duplicate names and empty
  files are errors.
- Subjects follow the standard yEnc convention every downloader parses:
  `title [i/n] - "file.bin" yEnc (part/parts)`, or just
  `"file.bin" yEnc (part/parts)` without `--title`.
- The NZB is written even without `--verify`; segments carry the encoded
  article sizes and the generated message-ids.

## No-RAR mode

`--obfuscate` posts BARE FILES under names that say nothing: a random
subject per file and a random (or empty) yEnc `name=`. The real names ride
out of band - in the NZB, and in the PAR2 FileDesc packets that `--par2`
posts beside the payload.

```bash
nzbfast post ./release --post-server news.example.com \
  --nzb release.nzb --obfuscate --par2 10 --verify
```

This is the near-term shape of the Reddit thread's proposal
(`research/REDDIT-NORAR-FOLLOWUP-2026-08-31.md`): drop the store-RAR
container, which encrypts nothing and only costs a download-write-unpack-delete
pass, and break header LINKAGE instead so a scraper that never saw the NZB
cannot tie an article to a release.

**What it does not do.** It hides no bytes. yEnc is a fixed +42, so the
payload is exactly as readable as it ever was, and anyone holding the
article can still fingerprint it by magic, first-16k hash or known-block
hash. A passworded RAR with `<meta type="password">` remains the only thing
in the format that hides content. Say so plainly to anyone who asks what
the mode buys.

- **`--obfuscate` requires a name carrier and is refused without one.** An
  obfuscated post puts no real name anywhere on the wire, so without
  `--par2` the names are simply gone - and the run would look perfectly
  healthy while landing a directory of random tokens. `--par2 0` is the
  cheapest way to satisfy it: every name and every block checksum, no
  parity bytes.
- A directory argument keeps its own name at the head of every member's
  relative path, so `post ./release` describes `release/VIDEO_TS/VTS_01_1.VOB`.
  That path lives in the FileDesc packets and nowhere on the wire, which is
  what lets an obfuscated post rebuild a tree.
- `--title` and `--obfuscate` are refused together: a title spells the
  release name into every subject, which is the linkage the mode removes.
- Duplicate basenames across directories are fine under `--obfuscate`
  (wire names are random tokens), and still an error without it.
- The recovery set is ANNOUNCED under its own name even when the payload is
  obfuscated. A set nobody can find carries its names to nobody. Its base
  name is a random token under `--obfuscate` (so it leaks no title) and the
  NZB's own stem otherwise; `--par2-base` overrides.

### The PAR2 set is built natively

`--par2 <percent>` builds the set in process (`nzbkit::par2gen`) with NO
external `par2` binary. That is not a convenience: **par2cmdline prints
"Skipping 0 byte file" and omits the member outright**, so the VIDEO_TS
placeholder shape - a 0-byte file whose only name lives in the FileDesc -
cannot be produced by it at all (matrix finding F3,
`research/NORAR-DEOBF-MATRIX-2026-08-29.md`). `--allow-empty` admits that
shape deliberately, so the creator that names it has to describe it too.

- `--par2 0` is a verify-only set: Main, FileDesc, IFSC and Creator, no
  recovery slices. It names every member and carries the block checksums,
  which is the manifest-only shape the matrix already sweeps.
- Above 0 the value is a percentage of the input slice count, and real
  Reed-Solomon recovery slices are computed over GF(2^16) using the same
  constant sequence `par2repair` reads back.
- Every emitted file repeats the critical packets, so a set whose index
  article is lost is still nameable from its volumes.
- `--par2-block-size` overrides the derived slice size (must be a multiple
  of 4). The default targets a few thousand input slices.
- Output is deterministic: identical members under identical names produce
  identical bytes, so a re-run after a failed post rebuilds the same set.

Interop is pinned rather than assumed:
`crates/nzbkit/tests/integration/par2gen_interop.rs` has par2cmdline verify
a set we wrote and REPAIR real damage from the recovery slices we computed.
A set only our own client could read would be a private format wearing
PAR2's name.

## Options that matter

| Flag | Default | Notes |
| --- | --- | --- |
| `--post-server` | none, required | host or host:port of ONE config entry |
| `--group` | alt.binaries.test | target newsgroup |
| `--from` | corpus@nzbfast.invalid | From header |
| `--msgid-domain` | nzbfast.invalid | right-hand side of message-ids |
| `--article-size` | 700K | decoded payload bytes per article |
| `--connections` | 4 | concurrent posting sessions |
| `--nzb` | posted.nzb | output NZB path |
| `--verify` | off | re-download + hash check, see below |
| `--allow-empty` | off | admit 0-byte files (one empty yEnc article each) |
| `--obfuscate` | off | random subject + yEnc name; see No-RAR mode |
| `--obfuscate-empty-name` | off | with `--obfuscate`, empty yEnc `name=` |
| `--par2` | off | build + post a recovery set; value is percent redundancy |
| `--par2-block-size` | derived | PAR2 slice size, multiple of 4 |
| `--par2-base` | see above | base name of the emitted `.par2` files |

## Header hygiene

Articles carry exactly five headers: From, Newsgroups, Subject, Message-ID,
Date. No User-Agent, no X-Newsreader, no Organization. Message-ID local
parts are random hex with a caller-chosen domain and Date is always +0000,
so neither the posting host nor its timezone leaks into the group. Keep it
that way when touching `crates/nzbkit/src/post.rs` - the test
`wire_article_has_only_the_five_headers` pins this.

## Verify

`--verify` parses the NZB it just wrote, downloads every segment back
through the normal engine connection pool from the SAME server, reassembles
into `<nzb>.verify.tmp/`, and compares SHA-256 per file against the
sources. On success the temp directory is removed; on failure it is kept
for inspection and the command exits non-zero.

Freshly posted articles can take a moment to become retrievable; the tool
waits 2 seconds before verifying. If verify still reports missing articles
on a real provider, wait a minute and re-run the download by hand:

```bash
nzbfast get bench/nested-corpus/corpus.nzb --out /tmp/corpus-check
```

## Protocol notes

- POST first; a server answering 440 (posting not permitted) flips the run
  to IHAVE automatically. A rejection after the article body is a hard
  error - a partially posted corpus is worse than a loud failure.
- Any article that fails three attempts (with reconnects between) aborts
  the whole run.

## Testing

- Unit + e2e tests live in `crates/nzbkit/src/post.rs` (encoder round-trip
  against the production decoder, split boundaries, NZB emission, POST and
  IHAVE e2e against the in-memory mock NNTP server) and
  `crates/nzbfast/src/post_cmd.rs` (server selection rules, full CLI run
  with verify). The no-RAR producer's round trip - post obfuscated to the
  mock, download through the real `get` path, land every byte under the
  real names - is `crates/nzbfast/tests/e2e_norar/postmode.rs`, and the
  PAR2 creator's own tests are beside it in `crates/nzbkit/src/par2gen.rs`
  plus the par2cmdline interop suite named above.
- The test mock (`nzbkit::mock::MockServer`) accepts POST and IHAVE. The
  standalone `nzbfast mockserve` loopback bench server does NOT - it serves
  a synthetic set for download benchmarks only; do not point `post` at it.
