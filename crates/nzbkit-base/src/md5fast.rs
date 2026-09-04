//! MD5 for nzbfast, with a Rust-native x86-64 assembly block function on
//! Windows.
//!
//! # Why this module exists
//!
//! Every downloaded byte is hashed with MD5 twice over by PAR2 (per block
//! and per file), every self-prove after a repair rehashes what it wrote,
//! and the creator hashes the whole payload - so the MD5 block function is
//! on the per-byte budget next to yEnc decode and crc32.
//!
//! `crates/nzbkit/Cargo.toml` turns on the `md-5` crate's `asm` feature,
//! but only for `cfg(all(target_arch = "x86_64", not(target_os =
//! "windows")))`. That gate is not a preference: the `md5-asm` crate the
//! feature pulls in is C plus GNU-syntax assembly built through `cc`, and
//! it has a `compile_error!` on both MSVC and mingw. So on Windows x86-64
//! - and only there - MD5 ran through the portable Rust path, which the
//! 2 Sep 2026 PAR2 audit measured as the reason both Windows rigs' verify
//! legs sit well above the Macs' (research/PAR2-PERF-AUDIT-2026-09-02.md
//! section 6 item 0c).
//!
//! This module closes that gap without reintroducing a C toolchain: the
//! block function is written with `core::arch::asm!`, which LLVM
//! assembles itself, so it builds under MSVC exactly as it does under
//! mingw. Nothing about the other targets changes - off Windows x86-64
//! [`Md5`] is `md5::Md5` verbatim, asm feature and all.
//!
//! # What the assembly is
//!
//! A port of the classic x86-64 MD5 block routine - Project Nayuki's
//! `md5-fast-x8664.S`, which is the routine the `md5-asm` crate itself
//! carries (`src/x64.S`) - rewritten as Rust inline assembly with named
//! operands, so the register allocator picks registers rather than the
//! author pinning them, and so LLVM assembles it on every Windows
//! toolchain.
//!
//! ```text
//! MD5 hash in x86-64 assembly
//! Copyright (c) 2016 Project Nayuki. (MIT License)
//! https://www.nayuki.io/page/fast-md5-hash-implementation-in-x86-assembly
//!
//! Permission is hereby granted, free of charge, to any person obtaining a
//! copy of this software and associated documentation files (the "Software"),
//! to deal in the Software without restriction, including without limitation
//! the rights to use, copy, modify, merge, publish, distribute, sublicense,
//! and/or sell copies of the Software, and to permit persons to whom the
//! Software is furnished to do so, subject to the following conditions:
//! - The above copyright notice and this permission notice shall be included
//!   in all copies or substantial portions of the Software.
//! - The Software is provided "as is", without warranty of any kind, express
//!   or implied, including but not limited to the warranties of
//!   merchantability, fitness for a particular purpose and noninfringement.
//!   In no event shall the authors or copyright holders be liable for any
//!   claim, damages or other liability, whether in an action of contract,
//!   tort or otherwise, arising from, out of or in connection with the
//!   Software or the use or other dealings in the Software.
//! ```
//!
//! # The shape, and the one place this differs from Nayuki
//!
//! MD5 is a 64-step serial chain and its floor is the latency around
//! `b`: two operations to form the round function from the previous
//! step's output, then `add`, `rol`, `add` - five cycles a step, ~320 a
//! block, which is the ~1 GB/s per core every MD5 implementation lands
//! near. Each round's function is written in the form that keeps
//! everything not depending on `b` off that chain, exactly as Nayuki
//! writes them:
//!
//! - steps 0-15   `F = d ^ (b & (c ^ d))`      - `c ^ d` is two steps old
//! - steps 16-31  `G = (b & d) | (c & !d)`     - `c & !d` does not touch b
//! - steps 32-47  `H = b ^ c ^ d`              - `c ^ d` first
//! - steps 48-63  `I = c ^ (b | !d)`           - `!d` first
//!
//! The deviation is the round tail. Nayuki folds the round constant and
//! the round-function term into the destination with one three-operand
//! `leal t(%esi,%a), %a`; that is one instruction instead of two, but a
//! base+index+displacement LEA has three-cycle latency on every Intel
//! core since Sandy Bridge and it sits ON the critical path, so it
//! trades two issue slots for two cycles a step. Here the constant is
//! added early, beside the message word - both addends depend only on a
//! value four steps old, so they are free - and only `add`, `rol`, `add`
//! remain after the round function. Nine instructions a step against
//! eight, and the chain stays at five cycles.
//!
//! The 592 step instructions are mechanical: for step `i`, the message
//! word is `X[g(i)]` with `g` the RFC 1321 schedule, the constant is
//! `floor(2^32 * abs(sin(i + 1)))`, the rotate is the standard table,
//! and the four working registers rotate `(a,b,c,d) -> (d,a,b,c)` after
//! every step. Do not hand-edit one: derive the whole list again and let
//! the tests below judge it.
//!
//! # Who routes through it
//!
//! Every nzbkit site that hashed payload bytes (`par2`, `par2repair`,
//! `par2gen`, `par2/verify`, `live`, `sysbench` and the rest) now says
//! `use crate::md5fast::{Digest, Md5};`, and the four production sites
//! above nzbkit that hash whole files do the same through
//! `nzbkit::md5fast`: `nettools`'s `bench-cpu` stages, `manifest`'s
//! custody hashes, the dedupe pass's `whole_file_md5` and the `.sfv` /
//! `.md5` sidecar prover. Test modules deliberately keep naming `md-5`
//! directly - they are the reference side of the differential.
//!
//! # Trusting it
//!
//! The `md5_differential_*` tests beside this file hash the same bytes
//! through this path and through the `md-5` crate at every length that
//! exercises a padding edge (0, 55, 56, 63, 64, 65, 119, 120), at every
//! length to 200, at several megabytes, at 500 random lengths and
//! through uneven `update` chunks; `md5_clone_resume_at_every_block_boundary`
//! clones a hasher at every cut point of a multi-block message and
//! finishes both halves, which is the shape
//! [`crate::par2repair::Md5Resume`] depends on; and
//! `md5_rfc1321_vectors` is absolute, so a mistake shared by both sides
//! could not pass. They compile and run on every target; off Windows
//! x86-64 the differential arms compare `md-5` against itself, which is
//! cheap and keeps the harness in place for whoever widens the `cfg`.
//!
//! For a speed A/B (the arms are a compile-time `cfg`, so "before and
//! after" is otherwise two builds), `cargo run --release -p nzbkit
//! --example md5_ab_bench` runs both in one process.

/// Re-exported so a call site needs one `use` line: `use
/// crate::md5fast::{Digest, Md5};`.
pub use md5::Digest;

/// The MD5 hasher this crate uses.
///
/// On Windows x86-64 this is the inline-assembly implementation in this
/// module; everywhere else it is `md5::Md5` unchanged, which already has
/// the `md5-asm` backend on x86-64 and the portable one elsewhere. Both
/// are `digest::CoreWrapper`s, so they are the same type shape: `new`,
/// `update`, `finalize`, `digest`, `Clone`, `Default`, `Reset`.
#[cfg(all(windows, target_arch = "x86_64"))]
pub type Md5 = md5::digest::core_api::CoreWrapper<winasm::Md5AsmCore>;

/// The MD5 hasher this crate uses - the ARM64 arm; see the module header.
#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")))]
pub type Md5 = awslc::Md5;

/// The MD5 hasher this crate uses - see the accelerated arms above.
#[cfg(not(any(
    all(windows, target_arch = "x86_64"),
    all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux"))
)))]
pub type Md5 = md5::Md5;

#[cfg(all(target_arch = "aarch64", any(target_os = "macos", target_os = "linux")))]
pub mod awslc {
    //! A `digest`-shaped wrapper over the AWS-LC that is already linked
    //! into this binary as rustls' crypto provider.
    //!
    //! Public only because [`super::Md5`] names the type; nothing here is
    //! API. `MD5_CTX` is a plain 92-byte POD value with no pointers and no
    //! ownership, so `#[derive(Clone)]` reproduces the exact prefix state
    //! [`crate::par2repair::Md5Resume`] clones - the property the tests in
    //! `md5fast/tests.rs` check at all 2,598 cut points of a message.

    use core::fmt;
    use md5::digest::{
        FixedOutput, FixedOutputReset, HashMarker, Output, OutputSizeUser, Reset, Update,
        typenum::U16,
    };

    /// Streaming AWS-LC MD5 state.
    #[derive(Clone)]
    pub struct Md5 {
        context: aws_lc_sys::MD5_CTX,
    }

    impl Default for Md5 {
        #[inline]
        fn default() -> Self {
            let mut context = aws_lc_sys::MD5_CTX::default();
            // SAFETY: `context` is valid, writable, correctly aligned
            // storage for `MD5_Init`, which only writes the chaining
            // value and counters. This AWS-LC's MD5_Init is infallible
            // and always returns 1.
            let ok = unsafe { aws_lc_sys::MD5_Init(&mut context) };
            debug_assert_eq!(ok, 1);
            Self { context }
        }
    }

    impl OutputSizeUser for Md5 {
        type OutputSize = U16;
    }

    impl Update for Md5 {
        #[inline]
        fn update(&mut self, data: &[u8]) {
            // SAFETY: `context` was initialised by `Default`/`Reset`, and
            // `data` is live and readable for exactly `data.len()` bytes.
            let ok = unsafe {
                aws_lc_sys::MD5_Update(
                    &mut self.context,
                    data.as_ptr().cast::<core::ffi::c_void>(),
                    data.len(),
                )
            };
            debug_assert_eq!(ok, 1);
        }
    }

    impl FixedOutput for Md5 {
        #[inline]
        fn finalize_into(mut self, out: &mut Output<Self>) {
            // SAFETY: `out` is 16 bytes (`OutputSize = U16`, MD5's digest
            // length) and `context` is initialised.
            let ok = unsafe { aws_lc_sys::MD5_Final(out.as_mut_ptr(), &mut self.context) };
            debug_assert_eq!(ok, 1);
        }
    }

    impl Reset for Md5 {
        #[inline]
        fn reset(&mut self) {
            // SAFETY: as `Default`, over storage that is already live.
            let ok = unsafe { aws_lc_sys::MD5_Init(&mut self.context) };
            debug_assert_eq!(ok, 1);
        }
    }

    impl FixedOutputReset for Md5 {
        #[inline]
        fn finalize_into_reset(&mut self, out: &mut Output<Self>) {
            // SAFETY: as `finalize_into`, over a borrow rather than a move.
            let ok = unsafe { aws_lc_sys::MD5_Final(out.as_mut_ptr(), &mut self.context) };
            debug_assert_eq!(ok, 1);
            Reset::reset(self);
        }
    }

    impl HashMarker for Md5 {}

    impl fmt::Debug for Md5 {
        fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
            formatter.write_str("Md5 { ... }")
        }
    }
}

#[cfg(all(windows, target_arch = "x86_64"))]
pub mod winasm {
    //! The inline-assembly block function and the `digest` core that
    //! wraps it. Public only because [`super::Md5`] names the core type;
    //! nothing here is API.

    use core::arch::asm;
    use core::fmt;
    use core::slice::from_ref;
    use md5::digest::{
        HashMarker, Output,
        block_buffer::Eager,
        core_api::{
            AlgorithmName, Block, BlockSizeUser, Buffer, BufferKindUser, FixedOutputCore,
            OutputSizeUser, Reset, UpdateCore,
        },
        typenum::{U16, U64, Unsigned},
    };

    /// RFC 1321 initial chaining value.
    const STATE_INIT: [u32; 4] = [0x6745_2301, 0xefcd_ab89, 0x98ba_dcfe, 0x1032_5476];

    const BLOCK_SIZE: usize = 64;

    /// The MD5 block function: absorb `blocks` into `state`.
    ///
    /// Sixty-four steps in the ordering described in the module header.
    /// The four working words, two temporaries and three pointers are
    /// named operands, so LLVM allocates them and saves whatever it has
    /// to; the routine itself touches no stack and no flags-carrying
    /// state beyond the loop's own compare.
    #[inline(never)]
    fn compress(state: &mut [u32; 4], blocks: &[[u8; BLOCK_SIZE]]) {
        if blocks.is_empty() {
            return;
        }
        let msg = blocks.as_ptr().cast::<u8>();
        // SAFETY: `blocks` is a live slice of `blocks.len()` 64-byte
        // arrays, so one past its last byte is the slice's one-past-the-
        // end address - in bounds for pointer arithmetic and never
        // dereferenced (it is only the loop's stop value).
        let end = unsafe { msg.add(blocks.len() * BLOCK_SIZE) };
        let st = state.as_mut_ptr();
        // SAFETY: the block below reads exactly `blocks.len() * 64` bytes
        // from `msg` forward, which is `blocks` in full and nothing past
        // `end`, and reads/writes exactly the sixteen bytes at `st`,
        // which is `state`. `msg` walks forward in 64-byte steps and the
        // loop exits when it reaches `end`, so the first iteration is
        // guaranteed a full block by the emptiness check above. Every
        // other register is a named operand LLVM allocated for us; the
        // asm neither touches the stack (`nostack`) nor leaves flags
        // live across its end.
        unsafe {
            asm!(
                "2:",
                "mov {a:e}, dword ptr [{st}]",
                "mov {b:e}, dword ptr [{st} + 4]",
                "mov {c:e}, dword ptr [{st} + 8]",
                "mov {d:e}, dword ptr [{st} + 12]",
                // round 1: F = d ^ (b & (c ^ d))
                // step 0
                "add {a:e}, dword ptr [{msg} + 0]",
                "add {a:e}, 0xd76aa478",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "and {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 7",
                "add {a:e}, {b:e}",
                // step 1
                "add {d:e}, dword ptr [{msg} + 4]",
                "add {d:e}, 0xe8c7b756",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "and {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 12",
                "add {d:e}, {a:e}",
                // step 2
                "add {c:e}, dword ptr [{msg} + 8]",
                "add {c:e}, 0x242070db",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "and {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 17",
                "add {c:e}, {d:e}",
                // step 3
                "add {b:e}, dword ptr [{msg} + 12]",
                "add {b:e}, 0xc1bdceee",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "and {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 22",
                "add {b:e}, {c:e}",
                // step 4
                "add {a:e}, dword ptr [{msg} + 16]",
                "add {a:e}, 0xf57c0faf",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "and {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 7",
                "add {a:e}, {b:e}",
                // step 5
                "add {d:e}, dword ptr [{msg} + 20]",
                "add {d:e}, 0x4787c62a",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "and {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 12",
                "add {d:e}, {a:e}",
                // step 6
                "add {c:e}, dword ptr [{msg} + 24]",
                "add {c:e}, 0xa8304613",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "and {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 17",
                "add {c:e}, {d:e}",
                // step 7
                "add {b:e}, dword ptr [{msg} + 28]",
                "add {b:e}, 0xfd469501",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "and {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 22",
                "add {b:e}, {c:e}",
                // step 8
                "add {a:e}, dword ptr [{msg} + 32]",
                "add {a:e}, 0x698098d8",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "and {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 7",
                "add {a:e}, {b:e}",
                // step 9
                "add {d:e}, dword ptr [{msg} + 36]",
                "add {d:e}, 0x8b44f7af",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "and {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 12",
                "add {d:e}, {a:e}",
                // step 10
                "add {c:e}, dword ptr [{msg} + 40]",
                "add {c:e}, 0xffff5bb1",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "and {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 17",
                "add {c:e}, {d:e}",
                // step 11
                "add {b:e}, dword ptr [{msg} + 44]",
                "add {b:e}, 0x895cd7be",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "and {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 22",
                "add {b:e}, {c:e}",
                // step 12
                "add {a:e}, dword ptr [{msg} + 48]",
                "add {a:e}, 0x6b901122",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "and {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 7",
                "add {a:e}, {b:e}",
                // step 13
                "add {d:e}, dword ptr [{msg} + 52]",
                "add {d:e}, 0xfd987193",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "and {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 12",
                "add {d:e}, {a:e}",
                // step 14
                "add {c:e}, dword ptr [{msg} + 56]",
                "add {c:e}, 0xa679438e",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "and {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 17",
                "add {c:e}, {d:e}",
                // step 15
                "add {b:e}, dword ptr [{msg} + 60]",
                "add {b:e}, 0x49b40821",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "and {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 22",
                "add {b:e}, {c:e}",
                // round 2: G = (b & d) | (c & !d)
                // step 16
                "add {a:e}, dword ptr [{msg} + 4]",
                "add {a:e}, 0xf61e2562",
                "mov {t1:e}, {d:e}",
                "mov {t2:e}, {d:e}",
                "not {t1:e}",
                "and {t1:e}, {c:e}",
                "and {t2:e}, {b:e}",
                "or {t1:e}, {t2:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 5",
                "add {a:e}, {b:e}",
                // step 17
                "add {d:e}, dword ptr [{msg} + 24]",
                "add {d:e}, 0xc040b340",
                "mov {t1:e}, {c:e}",
                "mov {t2:e}, {c:e}",
                "not {t1:e}",
                "and {t1:e}, {b:e}",
                "and {t2:e}, {a:e}",
                "or {t1:e}, {t2:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 9",
                "add {d:e}, {a:e}",
                // step 18
                "add {c:e}, dword ptr [{msg} + 44]",
                "add {c:e}, 0x265e5a51",
                "mov {t1:e}, {b:e}",
                "mov {t2:e}, {b:e}",
                "not {t1:e}",
                "and {t1:e}, {a:e}",
                "and {t2:e}, {d:e}",
                "or {t1:e}, {t2:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 14",
                "add {c:e}, {d:e}",
                // step 19
                "add {b:e}, dword ptr [{msg} + 0]",
                "add {b:e}, 0xe9b6c7aa",
                "mov {t1:e}, {a:e}",
                "mov {t2:e}, {a:e}",
                "not {t1:e}",
                "and {t1:e}, {d:e}",
                "and {t2:e}, {c:e}",
                "or {t1:e}, {t2:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 20",
                "add {b:e}, {c:e}",
                // step 20
                "add {a:e}, dword ptr [{msg} + 20]",
                "add {a:e}, 0xd62f105d",
                "mov {t1:e}, {d:e}",
                "mov {t2:e}, {d:e}",
                "not {t1:e}",
                "and {t1:e}, {c:e}",
                "and {t2:e}, {b:e}",
                "or {t1:e}, {t2:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 5",
                "add {a:e}, {b:e}",
                // step 21
                "add {d:e}, dword ptr [{msg} + 40]",
                "add {d:e}, 0x02441453",
                "mov {t1:e}, {c:e}",
                "mov {t2:e}, {c:e}",
                "not {t1:e}",
                "and {t1:e}, {b:e}",
                "and {t2:e}, {a:e}",
                "or {t1:e}, {t2:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 9",
                "add {d:e}, {a:e}",
                // step 22
                "add {c:e}, dword ptr [{msg} + 60]",
                "add {c:e}, 0xd8a1e681",
                "mov {t1:e}, {b:e}",
                "mov {t2:e}, {b:e}",
                "not {t1:e}",
                "and {t1:e}, {a:e}",
                "and {t2:e}, {d:e}",
                "or {t1:e}, {t2:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 14",
                "add {c:e}, {d:e}",
                // step 23
                "add {b:e}, dword ptr [{msg} + 16]",
                "add {b:e}, 0xe7d3fbc8",
                "mov {t1:e}, {a:e}",
                "mov {t2:e}, {a:e}",
                "not {t1:e}",
                "and {t1:e}, {d:e}",
                "and {t2:e}, {c:e}",
                "or {t1:e}, {t2:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 20",
                "add {b:e}, {c:e}",
                // step 24
                "add {a:e}, dword ptr [{msg} + 36]",
                "add {a:e}, 0x21e1cde6",
                "mov {t1:e}, {d:e}",
                "mov {t2:e}, {d:e}",
                "not {t1:e}",
                "and {t1:e}, {c:e}",
                "and {t2:e}, {b:e}",
                "or {t1:e}, {t2:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 5",
                "add {a:e}, {b:e}",
                // step 25
                "add {d:e}, dword ptr [{msg} + 56]",
                "add {d:e}, 0xc33707d6",
                "mov {t1:e}, {c:e}",
                "mov {t2:e}, {c:e}",
                "not {t1:e}",
                "and {t1:e}, {b:e}",
                "and {t2:e}, {a:e}",
                "or {t1:e}, {t2:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 9",
                "add {d:e}, {a:e}",
                // step 26
                "add {c:e}, dword ptr [{msg} + 12]",
                "add {c:e}, 0xf4d50d87",
                "mov {t1:e}, {b:e}",
                "mov {t2:e}, {b:e}",
                "not {t1:e}",
                "and {t1:e}, {a:e}",
                "and {t2:e}, {d:e}",
                "or {t1:e}, {t2:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 14",
                "add {c:e}, {d:e}",
                // step 27
                "add {b:e}, dword ptr [{msg} + 32]",
                "add {b:e}, 0x455a14ed",
                "mov {t1:e}, {a:e}",
                "mov {t2:e}, {a:e}",
                "not {t1:e}",
                "and {t1:e}, {d:e}",
                "and {t2:e}, {c:e}",
                "or {t1:e}, {t2:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 20",
                "add {b:e}, {c:e}",
                // step 28
                "add {a:e}, dword ptr [{msg} + 52]",
                "add {a:e}, 0xa9e3e905",
                "mov {t1:e}, {d:e}",
                "mov {t2:e}, {d:e}",
                "not {t1:e}",
                "and {t1:e}, {c:e}",
                "and {t2:e}, {b:e}",
                "or {t1:e}, {t2:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 5",
                "add {a:e}, {b:e}",
                // step 29
                "add {d:e}, dword ptr [{msg} + 8]",
                "add {d:e}, 0xfcefa3f8",
                "mov {t1:e}, {c:e}",
                "mov {t2:e}, {c:e}",
                "not {t1:e}",
                "and {t1:e}, {b:e}",
                "and {t2:e}, {a:e}",
                "or {t1:e}, {t2:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 9",
                "add {d:e}, {a:e}",
                // step 30
                "add {c:e}, dword ptr [{msg} + 28]",
                "add {c:e}, 0x676f02d9",
                "mov {t1:e}, {b:e}",
                "mov {t2:e}, {b:e}",
                "not {t1:e}",
                "and {t1:e}, {a:e}",
                "and {t2:e}, {d:e}",
                "or {t1:e}, {t2:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 14",
                "add {c:e}, {d:e}",
                // step 31
                "add {b:e}, dword ptr [{msg} + 48]",
                "add {b:e}, 0x8d2a4c8a",
                "mov {t1:e}, {a:e}",
                "mov {t2:e}, {a:e}",
                "not {t1:e}",
                "and {t1:e}, {d:e}",
                "and {t2:e}, {c:e}",
                "or {t1:e}, {t2:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 20",
                "add {b:e}, {c:e}",
                // round 3: H = b ^ c ^ d
                // step 32
                "add {a:e}, dword ptr [{msg} + 20]",
                "add {a:e}, 0xfffa3942",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 4",
                "add {a:e}, {b:e}",
                // step 33
                "add {d:e}, dword ptr [{msg} + 32]",
                "add {d:e}, 0x8771f681",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 11",
                "add {d:e}, {a:e}",
                // step 34
                "add {c:e}, dword ptr [{msg} + 44]",
                "add {c:e}, 0x6d9d6122",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 16",
                "add {c:e}, {d:e}",
                // step 35
                "add {b:e}, dword ptr [{msg} + 56]",
                "add {b:e}, 0xfde5380c",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 23",
                "add {b:e}, {c:e}",
                // step 36
                "add {a:e}, dword ptr [{msg} + 4]",
                "add {a:e}, 0xa4beea44",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 4",
                "add {a:e}, {b:e}",
                // step 37
                "add {d:e}, dword ptr [{msg} + 16]",
                "add {d:e}, 0x4bdecfa9",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 11",
                "add {d:e}, {a:e}",
                // step 38
                "add {c:e}, dword ptr [{msg} + 28]",
                "add {c:e}, 0xf6bb4b60",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 16",
                "add {c:e}, {d:e}",
                // step 39
                "add {b:e}, dword ptr [{msg} + 40]",
                "add {b:e}, 0xbebfbc70",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 23",
                "add {b:e}, {c:e}",
                // step 40
                "add {a:e}, dword ptr [{msg} + 52]",
                "add {a:e}, 0x289b7ec6",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 4",
                "add {a:e}, {b:e}",
                // step 41
                "add {d:e}, dword ptr [{msg} + 0]",
                "add {d:e}, 0xeaa127fa",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 11",
                "add {d:e}, {a:e}",
                // step 42
                "add {c:e}, dword ptr [{msg} + 12]",
                "add {c:e}, 0xd4ef3085",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 16",
                "add {c:e}, {d:e}",
                // step 43
                "add {b:e}, dword ptr [{msg} + 24]",
                "add {b:e}, 0x04881d05",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 23",
                "add {b:e}, {c:e}",
                // step 44
                "add {a:e}, dword ptr [{msg} + 36]",
                "add {a:e}, 0xd9d4d039",
                "mov {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "xor {t1:e}, {b:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 4",
                "add {a:e}, {b:e}",
                // step 45
                "add {d:e}, dword ptr [{msg} + 48]",
                "add {d:e}, 0xe6db99e5",
                "mov {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "xor {t1:e}, {a:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 11",
                "add {d:e}, {a:e}",
                // step 46
                "add {c:e}, dword ptr [{msg} + 60]",
                "add {c:e}, 0x1fa27cf8",
                "mov {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "xor {t1:e}, {d:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 16",
                "add {c:e}, {d:e}",
                // step 47
                "add {b:e}, dword ptr [{msg} + 8]",
                "add {b:e}, 0xc4ac5665",
                "mov {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "xor {t1:e}, {c:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 23",
                "add {b:e}, {c:e}",
                // round 4: I = c ^ (b | !d)
                // step 48
                "add {a:e}, dword ptr [{msg} + 0]",
                "add {a:e}, 0xf4292244",
                "mov {t1:e}, {d:e}",
                "not {t1:e}",
                "or {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 6",
                "add {a:e}, {b:e}",
                // step 49
                "add {d:e}, dword ptr [{msg} + 28]",
                "add {d:e}, 0x432aff97",
                "mov {t1:e}, {c:e}",
                "not {t1:e}",
                "or {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 10",
                "add {d:e}, {a:e}",
                // step 50
                "add {c:e}, dword ptr [{msg} + 56]",
                "add {c:e}, 0xab9423a7",
                "mov {t1:e}, {b:e}",
                "not {t1:e}",
                "or {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 15",
                "add {c:e}, {d:e}",
                // step 51
                "add {b:e}, dword ptr [{msg} + 20]",
                "add {b:e}, 0xfc93a039",
                "mov {t1:e}, {a:e}",
                "not {t1:e}",
                "or {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 21",
                "add {b:e}, {c:e}",
                // step 52
                "add {a:e}, dword ptr [{msg} + 48]",
                "add {a:e}, 0x655b59c3",
                "mov {t1:e}, {d:e}",
                "not {t1:e}",
                "or {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 6",
                "add {a:e}, {b:e}",
                // step 53
                "add {d:e}, dword ptr [{msg} + 12]",
                "add {d:e}, 0x8f0ccc92",
                "mov {t1:e}, {c:e}",
                "not {t1:e}",
                "or {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 10",
                "add {d:e}, {a:e}",
                // step 54
                "add {c:e}, dword ptr [{msg} + 40]",
                "add {c:e}, 0xffeff47d",
                "mov {t1:e}, {b:e}",
                "not {t1:e}",
                "or {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 15",
                "add {c:e}, {d:e}",
                // step 55
                "add {b:e}, dword ptr [{msg} + 4]",
                "add {b:e}, 0x85845dd1",
                "mov {t1:e}, {a:e}",
                "not {t1:e}",
                "or {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 21",
                "add {b:e}, {c:e}",
                // step 56
                "add {a:e}, dword ptr [{msg} + 32]",
                "add {a:e}, 0x6fa87e4f",
                "mov {t1:e}, {d:e}",
                "not {t1:e}",
                "or {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 6",
                "add {a:e}, {b:e}",
                // step 57
                "add {d:e}, dword ptr [{msg} + 60]",
                "add {d:e}, 0xfe2ce6e0",
                "mov {t1:e}, {c:e}",
                "not {t1:e}",
                "or {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 10",
                "add {d:e}, {a:e}",
                // step 58
                "add {c:e}, dword ptr [{msg} + 24]",
                "add {c:e}, 0xa3014314",
                "mov {t1:e}, {b:e}",
                "not {t1:e}",
                "or {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 15",
                "add {c:e}, {d:e}",
                // step 59
                "add {b:e}, dword ptr [{msg} + 52]",
                "add {b:e}, 0x4e0811a1",
                "mov {t1:e}, {a:e}",
                "not {t1:e}",
                "or {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 21",
                "add {b:e}, {c:e}",
                // step 60
                "add {a:e}, dword ptr [{msg} + 16]",
                "add {a:e}, 0xf7537e82",
                "mov {t1:e}, {d:e}",
                "not {t1:e}",
                "or {t1:e}, {b:e}",
                "xor {t1:e}, {c:e}",
                "add {a:e}, {t1:e}",
                "rol {a:e}, 6",
                "add {a:e}, {b:e}",
                // step 61
                "add {d:e}, dword ptr [{msg} + 44]",
                "add {d:e}, 0xbd3af235",
                "mov {t1:e}, {c:e}",
                "not {t1:e}",
                "or {t1:e}, {a:e}",
                "xor {t1:e}, {b:e}",
                "add {d:e}, {t1:e}",
                "rol {d:e}, 10",
                "add {d:e}, {a:e}",
                // step 62
                "add {c:e}, dword ptr [{msg} + 8]",
                "add {c:e}, 0x2ad7d2bb",
                "mov {t1:e}, {b:e}",
                "not {t1:e}",
                "or {t1:e}, {d:e}",
                "xor {t1:e}, {a:e}",
                "add {c:e}, {t1:e}",
                "rol {c:e}, 15",
                "add {c:e}, {d:e}",
                // step 63
                "add {b:e}, dword ptr [{msg} + 36]",
                "add {b:e}, 0xeb86d391",
                "mov {t1:e}, {a:e}",
                "not {t1:e}",
                "or {t1:e}, {c:e}",
                "xor {t1:e}, {d:e}",
                "add {b:e}, {t1:e}",
                "rol {b:e}, 21",
                "add {b:e}, {c:e}",
                "add dword ptr [{st}], {a:e}",
                "add dword ptr [{st} + 4], {b:e}",
                "add dword ptr [{st} + 8], {c:e}",
                "add dword ptr [{st} + 12], {d:e}",
                "add {msg}, 64",
                "cmp {msg}, {end}",
                "jb 2b",
                msg = inout(reg) msg => _,
                end = in(reg) end,
                st = in(reg) st,
                a = out(reg) _,
                b = out(reg) _,
                c = out(reg) _,
                d = out(reg) _,
                t1 = out(reg) _,
                t2 = out(reg) _,
                options(nostack),
            );
        }
    }

    /// Core MD5 hasher state - the same shape as `md5::Md5Core`, with the
    /// assembly block function above in place of its portable one.
    #[derive(Clone)]
    pub struct Md5AsmCore {
        block_len: u64,
        state: [u32; 4],
    }

    impl HashMarker for Md5AsmCore {}

    impl BlockSizeUser for Md5AsmCore {
        type BlockSize = U64;
    }

    impl BufferKindUser for Md5AsmCore {
        type BufferKind = Eager;
    }

    impl OutputSizeUser for Md5AsmCore {
        type OutputSize = U16;
    }

    /// `GenericArray<u8, U64>` and `[u8; 64]` have the same layout, which
    /// is what lets the block function take a plain array slice.
    #[inline(always)]
    fn as_arrays(blocks: &[Block<Md5AsmCore>]) -> &[[u8; BLOCK_SIZE]] {
        let p = blocks.as_ptr().cast::<[u8; BLOCK_SIZE]>();
        // SAFETY: `GenericArray<u8, U64>` is a `#[repr(transparent)]`
        // wrapper over `[u8; 64]` - same size, same alignment, same
        // validity - so the two slices describe the identical bytes, and
        // the borrow keeps `blocks` alive for the result's lifetime.
        unsafe { core::slice::from_raw_parts(p, blocks.len()) }
    }

    impl UpdateCore for Md5AsmCore {
        #[inline]
        fn update_blocks(&mut self, blocks: &[Block<Self>]) {
            self.block_len = self.block_len.wrapping_add(blocks.len() as u64);
            compress(&mut self.state, as_arrays(blocks));
        }
    }

    impl FixedOutputCore for Md5AsmCore {
        #[inline]
        fn finalize_fixed_core(&mut self, buffer: &mut Buffer<Self>, out: &mut Output<Self>) {
            let bit_len = self
                .block_len
                .wrapping_mul(<Self as BlockSizeUser>::BlockSize::U64)
                .wrapping_add(buffer.get_pos() as u64)
                .wrapping_mul(8);
            let mut s = self.state;
            buffer.len64_padding_le(bit_len, |b| compress(&mut s, as_arrays(from_ref(b))));
            for (chunk, v) in out.as_chunks_mut::<4>().0.iter_mut().zip(s.iter()) {
                *chunk = v.to_le_bytes();
            }
        }
    }

    impl Default for Md5AsmCore {
        #[inline]
        fn default() -> Self {
            Self {
                block_len: 0,
                state: STATE_INIT,
            }
        }
    }

    impl Reset for Md5AsmCore {
        #[inline]
        fn reset(&mut self) {
            *self = Self::default();
        }
    }

    impl AlgorithmName for Md5AsmCore {
        fn write_alg_name(f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Md5")
        }
    }

    impl fmt::Debug for Md5AsmCore {
        fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
            f.write_str("Md5AsmCore { ... }")
        }
    }
}

#[cfg(test)]
mod tests;
