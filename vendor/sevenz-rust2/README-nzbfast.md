# sevenz-rust2, vendored

sevenz-rust2 0.22.2 from crates.io, Apache-2.0, vendored under
`[patch.crates-io]` in the root `Cargo.toml`. Tests and examples were not
copied.

**This file is the whole list of what differs from upstream.** Re-apply
each item on the next bump, or drop it if upstream took it. To see the
diff for yourself:

```sh
diff -ru ~/.cargo/registry/src/*/sevenz-rust2-0.22.2/src vendor/sevenz-rust2/src
```

## 1. `src/encryption/aes.rs` - the decoder's input buffer

The AES decoder's `get_more_data` read its input through a 512-byte stack
array, so an encrypted 1 GiB Copy-method member cost two million read
syscalls and as many cipher calls. It now reads into a persistent 1 MiB
buffer. Measured in `research/RAR-PERF-AUDIT-2026-09-02.md`, round 10.

## 2. `src/write_entropy.rs` (new) - a caller-supplied entropy source

`AesEncoderOptions::new` drew its initialisation vector and its key
derivation salt from `getrandom::fill`, so one generator profile plus one
seed emitted a DIFFERENT archive on every run. `crates/postfast` builds
posting-layout fixtures that a catalog walk compares byte for byte, so
that made an encrypted 7z row impossible to write at all: the archives
would have differed in bytes carrying no meaning.

The new module adds a public `Entropy` (`Os` by default, `Seeded([u8;
32])` for a fixture) and a public `EntropyScope` a caller installs around
the whole archive build. The two draw sites in
`src/encoder_options.rs` go through it. **`Os` is still the default and
must stay that way** - a seeded salt hands the key derivation to anyone
holding the seed, and the seed travels in a public catalog. The module
header carries the full argument, including why it is a thread scope
rather than a parameter.

The design is copied from `vendor/rars/src/write_entropy.rs`, which
answered the identical problem for the RAR writers on the same day
(4 Sep 2026). `postfast` draws ONE seed per nesting level and hands it to
whichever writer that level selected, so a stack mixing the two formats
is reproducible the same way at every level.

**Its tests live in `crates/postfast/src/sevenz.rs`, module
`tests::entropy`, and NOT in this crate.** This crate is a
`[patch.crates-io]` path dependency of the nzbfast workspace rather than
a member of it, so `cargo test -p sevenz-rust2` runs nowhere in that repo
and a `#[cfg(test)]` module here would be a test set with no runner -
which is the trap `vendor/lzma-rust2/README-nzbfast.md` item 2 records
finding the hard way. Four properties are pinned there by name:
successive draws differ (a source handing back one constant would still
be reproducible, and would repeat an IV under one key), one seed gives
one sequence, a scope puts back what it replaced, and the DEFAULT still
varies per run. If this crate ever becomes a workspace member, move them
here.
