# Contributing to nzbfast

Thanks for wanting to help - contributions of every size are welcome,
from a one-character typo fix to a new feature. Small first PRs are a
great way in; issues labeled **`good first issue`** are picked to be
approachable.

## The short version

1. Fork the repo, create a branch, make your change.
2. `cargo test` passes locally (see *Building* below).
3. Open a pull request with a clear description of what and why.
4. Add a `Signed-off-by:` line to your commits (see *DCO* below).

A CI check builds and tests every PR. A maintainer reviews it from
there - response may take a few days; pinging after a week is fine.

## What's especially welcome

- **Typos, wording, UI polish** - dashboard text lives in
  `web/dashboard.html` (and `web/wall.html`), the user manual in
  `docs/MANUAL.html`. Both are compiled into the binary with
  `include_str!`, so a rebuild is what makes an edit visible.
- **Docs** - anything that confused you is a bug in the docs.
- **Translations** - the dashboard, poster wall and user manual all have
  a locale layer now: 27 UI catalogues in `web/i18n/<lang>.json` beside
  the inline English, and 15 translated manuals in
  `docs/i18n/MANUAL.<lang>.html`.
  Corrections to an existing language are the easiest PR here; a new
  language is very welcome too - `web/i18n/README.md` has the checklist,
  and `python3 web/i18n/check.py` tells you whether a catalogue is
  complete before you open the PR.
- **Bug reports with an .nzb-shaped repro** - even without a fix.
- **Code** - fixes and features. For anything larger than a small fix,
  open an issue first so we can agree direction before you invest time.

## Building

```sh
cargo build --release        # single static-ish binary

# The two test commands CI runs, in the same shape. The nzbfast suites
# bind real ports and share spool state, so they run single-threaded;
# everything else runs in parallel.
cargo test --workspace --exclude nzbfast --features nzbkit/heavy-tests --no-fail-fast
cargo test -p nzbfast --features heavy-tests --no-fail-fast -- --test-threads=1
```

Rust stable, no nightly features (the exact version is pinned by
`rust-toolchain.toml`, so rustup picks it up for you). The `heavy-tests`
feature is what links the seven slower end-to-end suites; without it
cargo builds a shorter suite than CI does, and it does so quietly. The
e2e tests spin up a local mock NNTP server; some repair tests skip
unless `par2` is installed (`brew install par2` / `apt install par2`).
Set `NZBFAST_NO_ENRICH=1` to keep tests off the network.

The PR check is more than the tests, and each of these fails a PR on its
own, so they are worth running before you push:

```sh
cargo fmt -p nzbkit -p nzbfast -p nzbtray --check
cargo clippy -p nzbkit -p nzbfast -p nzbtray --all-targets --no-deps -- -D warnings
tools/size-gate.py           # per-file and per-function size ceilings
```

`--no-deps` on the clippy line matters: without it you lint the vendored
crates under `vendor/` and get a page of errors that are not yours.

Match the style around you. Comments explain *why*, not *what*.

## Developer Certificate of Origin (DCO)

By adding a `Signed-off-by: Your Name <you@example.com>` line to each
commit (`git commit -s`), you certify the [DCO](https://developercertificate.org/):
that you wrote the change or otherwise have the right to submit it
under the project licence (GPL-3.0-or-later, see COPYRIGHT.md). There
is no CLA and no copyright assignment - you keep your copyright.

## How merging works here

Maintainers develop against a private integration tree (benchmark
rigs, release tooling and other infrastructure live there). Your PR is
merged **on this repo** - your commit and attribution stay in `main`'s
history permanently - and the same change is ported into the
integration tree so it ships in the next release. You may notice
occasional `nzbfast public snapshot` commits syncing the two; that's
normal and never removes merged work.

The maintainers decide what gets merged; a polite "no" to a PR is
always an option and never personal.

## A note on the maintainers

nzbfast is maintained pseudonymously - the maintainer account is
`nzbfast` and all project communication happens through GitHub issues
and PRs. Please don't take the lack of a personal name as a lack of
care; reviews are real, and your name (unlike ours) is preserved in
history.

The project is built with heavy use of AI coding assistants (mostly
Claude), and that includes drafting replies on issues and PRs. The
maintainer is accountable for everything posted under the `nzbfast`
account. If a reply reads as if nobody checked it, say so: it will be
corrected in the open rather than defended.

## Security issues

Please don't open a public issue for exploitable bugs - use GitHub's
**"Report a vulnerability"** (Security tab), which reaches the
maintainers privately.
