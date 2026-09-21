//! The binary fixtures this crate owns, as constants a crate ABOVE it can
//! reach.
//!
//! WHY THIS MODULE EXISTS, and it is a publication constraint rather than
//! tidiness. `cargo package` includes only files BELOW the package root, so
//! an `include_bytes!("../../nzbkit-base/testdata/...")` written in the
//! `nzbkit` facade resolves here in this workspace and resolves to NOTHING
//! in the published `.crate`. Forty such sites were live on main on 21 Sep
//! 2026 and no gate in the repo could see them; `tools/package-escape-gate.py`
//! is the gate that now does, and this module is the fix it names.
//!
//! WHY RE-EXPORT RATHER THAN COPY. Fifteen of the twenty fixtures below are
//! read by THIS crate's own tests as well as the facade's, so copying them
//! up would put 89 KiB of binary in the tree twice with nothing holding the
//! copies equal - and a regenerated fixture here would silently stop being
//! the one the facade tests against. One copy, owned by the crate whose
//! `testdata/` and `tests/fixtures/` they live in.
//!
//! The gating is `renameclaim`'s, for `renameclaim`'s reason: a `cfg(test)`
//! item is invisible from another crate whatever its visibility, so the
//! module is compiled under `test-support` too and the facade reaches it
//! through a DEV dependency. `cargo build -p nzbkit` never sees it, and no
//! shipping binary carries a byte of it.

/// The plaintext packed inside the RAR4 encrypted sets below.
pub const RAR4_SECRET: &[u8] = include_bytes!("../testdata/rar4/secret.bin");

/// RAR4, encrypted payload, plaintext headers, stored.
pub const RAR4_ENC_STORE: &[u8] = include_bytes!("../testdata/rar4/enc-store.rar");

/// RAR4 with ENCRYPTED headers (`-hp`).
pub const RAR4_ENC_HDRS: &[u8] = include_bytes!("../testdata/rar4/enc-hdrs.rar");

/// RAR4 encrypted multi-volume set, volume 1 of 3.
pub const RAR4_ENC_VOLS_P1: &[u8] = include_bytes!("../testdata/rar4/enc-vols.part1.rar");

/// RAR4 encrypted multi-volume set, volume 2 of 3.
pub const RAR4_ENC_VOLS_P2: &[u8] = include_bytes!("../testdata/rar4/enc-vols.part2.rar");

/// RAR4 encrypted multi-volume set, volume 3 of 3.
pub const RAR4_ENC_VOLS_P3: &[u8] = include_bytes!("../testdata/rar4/enc-vols.part3.rar");

/// RAR4 encrypted-HEADER multi-volume set, volume 1 of 3.
pub const RAR4_ENC_HDR_VOLS_P1: &[u8] = include_bytes!("../testdata/rar4/enc-hdr-vols.part1.rar");

/// RAR4 encrypted-HEADER multi-volume set, volume 2 of 3.
pub const RAR4_ENC_HDR_VOLS_P2: &[u8] = include_bytes!("../testdata/rar4/enc-hdr-vols.part2.rar");

/// RAR4 encrypted-HEADER multi-volume set, volume 3 of 3.
pub const RAR4_ENC_HDR_VOLS_P3: &[u8] = include_bytes!("../testdata/rar4/enc-hdr-vols.part3.rar");

/// The plaintext packed inside the RAR5 encrypted sets below.
pub const RAR5_SECRET: &[u8] = include_bytes!("../testdata/rar5/secret.bin");

/// RAR5, encrypted payload, plaintext headers, stored.
pub const RAR5_ENC_STORE: &[u8] = include_bytes!("../testdata/rar5/enc-store.rar");

/// RAR5 with ENCRYPTED headers (`-hp`).
pub const RAR5_ENC_HDRS: &[u8] = include_bytes!("../testdata/rar5/enc-hdrs.rar");

/// RAR5 encrypted multi-volume set, volume 1 of 3.
pub const RAR5_ENC_VOLS_P1: &[u8] = include_bytes!("../testdata/rar5/enc-vols.part1.rar");

/// RAR5 encrypted multi-volume set, volume 2 of 3.
pub const RAR5_ENC_VOLS_P2: &[u8] = include_bytes!("../testdata/rar5/enc-vols.part2.rar");

/// RAR5 encrypted multi-volume set, volume 3 of 3.
pub const RAR5_ENC_VOLS_P3: &[u8] = include_bytes!("../testdata/rar5/enc-vols.part3.rar");

/// The free.pt Spotnet over-list, as a TSV.
pub const SPOT_FREE_PT_OVER: &[u8] = include_bytes!("../testdata/spot/free.pt.over.tsv");

/// The PAR2 index packet for the alpha/beta set.
pub const PAR2_TESTSET: &[u8] = include_bytes!("../tests/fixtures/par2/testset.par2");

/// Four recovery slices for the alpha/beta set.
pub const PAR2_TESTSET_VOL0_4: &[u8] = include_bytes!("../tests/fixtures/par2/testset.vol0+4.par2");

/// `alpha.bin`, the first file the PAR2 set above covers.
pub const PAR2_ALPHA: &[u8] = include_bytes!("../tests/fixtures/par2/alpha.bin");

/// `beta.bin`, the second file the PAR2 set above covers.
pub const PAR2_BETA: &[u8] = include_bytes!("../tests/fixtures/par2/beta.bin");
