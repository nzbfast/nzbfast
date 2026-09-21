# nzbkit-base

The base layer of the nzbfast engine: the 46 modules that everything
else in the engine stands on, and that reach none of it back.

It parses an NZB, talks NNTP over TLS, decodes yEnc in place, lands
bytes on disk, verifies and repairs with PAR2, reads RAR / ZIP / 7z /
tar / SFX containers, and names releases. `nzbkit` is a facade over
this crate, re-exporting every module here under its old name; the
downloader that drives both is [nzbfast](https://github.com/nzbfast/nzbfast).

The PAR2 half is the interesting one: verify and repair are
differential-tested byte for byte against par2cmdline, and the repair
solver has an NTT fast path that, as far as we know, no other PAR2
implementation carries.

## Status

Cut out of `nzbkit` on 3 September 2026. The public surface was
deliberately narrowed on 1 August 2026 and several modules are
`#[doc(hidden)]`: they are public only so the workspace's own benches,
examples and test rigs can build against them, and they carry no
stability promise.

**This crate is not on crates.io yet.** It depends on a vendored fork
of `rars` by path, and its build script compiles vendored rapidyenc C++
sources that live outside the package directory; both have to be
resolved before a publish can work. See TODO paragraph 84 in the
nzbfast repository for the current state.

## Licence

GPL-3.0-or-later.
