# Copyright, licensing and third-party components

nzbfast - Copyright (C) 2026 The nzbfast Authors.

nzbfast is free software: you may redistribute it and/or modify it under
the terms of the **GNU General Public License, version 3 or (at your
option) any later version**, as published by the Free Software
Foundation. The full text is in [LICENSE](LICENSE).

This program is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU General
Public License for more details.

---

## No embedded third-party tools

nzbfast is a single self-contained executable with **no embedded external
programs**. Everything is native Rust: yEnc decoding, PAR2 verification
and Reed-Solomon repair, and RAR extraction (all RAR families, including
compressed, encrypted and filtered archives, plus recovery-record repair)
via the vendored `rars` crate - a clean-room implementation containing no
RARLab code.

Historical note: releases up to and including v1.0.2 embedded RARLab's
`unrar` utility (executed as a separate process) under a GPLv3 §7
additional permission that appeared in this file. That binary - and the
permission, which is no longer needed - was removed when native RAR
extraction landed. If a separately installed `unrar` or `par2` exists on
the system, nzbfast can still invoke it as an ordinary external program
(a fallback escape hatch) - mere aggregation, needing no special
permission and shipping nothing.

---

## Third-party components

| Component | Where | Licence |
|---|---|---|
| **rapidyenc** 1.1.1 (SIMD yEnc codec) | `vendor/rapidyenc/`, compiled into nzbfast | Public domain / CC0 - no attribution obligation |
| **crcutil** | `vendor/rapidyenc/crcutil-1.0/` | Apache Licence 2.0. **Not compiled into nzbfast** (the build sets `YENC_DISABLE_CRCUTIL=1`); present only because it is part of the upstream snapshot |
| **rars** 0.4.6 (pure-Rust RAR extractor, perf fork of [bitplane/rars](https://github.com/bitplane/rars)) | `vendor/rars/`, statically linked; THE RAR extraction path (decode and recovery-record repair APIs only) | MIT OR Apache-2.0 (texts at `vendor/rars/LICENSE-MIT` and `vendor/rars/LICENSE-APACHE`; `vendor/rars/COPYING` records that this fork is stated MIT OR Apache-2.0, matching upstream's own Cargo.toml and crates.io metadata, and relicensed from upstream's WTFPL COPYING which WTFPL permits). Clean-room implementation - no unRAR-derived code |
| **MD5 x86-64 block function** (Project Nayuki, `md5-fast-x8664.S`, 2016) | `crates/nzbkit-base/src/md5fast.rs`, Windows x86-64 builds only; ported to Rust inline assembly, with the round tail's three-operand LEA split into two adds | MIT (notice reproduced in that file's module header). The same routine the `md5-asm` crate carries; nzbfast uses `md5-asm` itself on non-Windows x86-64, where it compiles |
| Rust crate dependencies | resolved via `Cargo.lock`, statically linked | Permissive (MIT / Apache-2.0 / BSD / ISC / zlib / Unicode-3.0). A few are **Apache-2.0 only** - notably `ring` (via `rustls`), `rpassword` and `rtoolbox`. Reproduce the exact set with `cargo tree` or `cargo license` |

## Why version 3

The project was initially released as GPL-2.0-or-later and moved to
GPL-3.0-or-later deliberately. Three reasons, in order of weight:

1. **Apache-2.0 compatibility - the decisive one.** nzbfast statically
   links Rust crates that are Apache-2.0 *only*, with no MIT alternative:
   `ring` (pulled in by `rustls`, so it is in every TLS connection the
   client makes), plus `rpassword` and `rtoolbox` in the setup wizard.
   The Apache 2.0 licence is **incompatible with GPL v2** - its patent
   termination and indemnification provisions count as "further
   restrictions" that GPLv2 forbids - but it **is** compatible with
   GPL v3, which was drafted with section 7 to accommodate exactly such
   terms. Under the old "v2 or later" grant, a recipient choosing the v2
   option would have been left holding a combination that could not
   actually be distributed under that option. Requiring v3 removes that
   defect.
2. **It raises the floor.** "v2 or later" means the *weakest* available
   terms govern in practice: anyone wanting to avoid v3's patent grant or
   its anti-tivoisation requirement could simply elect v2. Since the
   protections only bind if they cannot be opted out of, "v3 or later"
   is what actually delivers them.
3. **Additional permissions get a proper home.** While nzbfast embedded
   RARLab's unRAR (through v1.0.2), its licence structure relied on a
   GPLv3 section 7 additional permission. GPLv2 has no formal framework
   for such permissions (they are conventional but extra-textual);
   GPLv3 section 7 defines them explicitly. The permission is retired,
   but section 7 remains the right foundation should a similar need
   arise.

Known trade-off, accepted: GPLv3 code cannot be combined with
GPLv2-**only** code. This costs nzbfast nothing today - it links no
GPLv2-only code.

---

## Contributing

By submitting a contribution you agree that it is licensed under the same
terms as this project (GPL-3.0-or-later), and that you have the right to
submit it.
