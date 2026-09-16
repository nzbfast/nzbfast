//! Fast `memset` / `memcpy` / `memmove` / `memcmp` / `bcmp` for the static
//! musl downloads, replacing the byte-at-a-time routines that build links
//! today. x86_64 and AArch64 have bodies here; armv7 deliberately does not
//! (see WHY NOT armv7 below).
//!
//! WHY THIS EXISTS. The Linux tarballs and the ghcr.io images are static
//! musl, cross-built with `cargo zigbuild` (`packaging/build-linux-tarballs.sh`,
//! `packaging/build-parfast-bundles.sh`). Zig's bundled musl ships NO
//! `src/string` mem routines at all - the whole family is served from zig's
//! `compiler_rt`, whose `memset`, `memcmp`, `bcmp` and `strlen` are literal
//! one-byte-per-iteration loops and whose `memcpy` copies a
//! 16-byte SSE2 vector at a time. A glibc build calls libc's AVX2 ones
//! instead. Measured over nine parfast cells on a rig-locked Zen 4 box, that
//! shows up as 1.27-1.65x glibc's retired INSTRUCTIONS in the two cells an
//! allocator swap could not reach, with `compiler_rt.memset` alone 6.4-13.1%
//! of the musl profiles against ~1-3% for glibc's mem ops. With the routines
//! below, all nine of those cells retire 0.93-1.04x of a glibc build's
//! instructions and four of them burn 4.4-25.7% fewer cycles, at no cost in
//! memory (48 legs inside a 512 MiB limit, 0 kills, peak anonymous use
//! moving less than the run-to-run spread).
//!
//! WHY THE SYMBOLS ARE NOT DEFINED HERE. `compiler_rt` defines them WEAK, so
//! a strong definition anywhere in the link wins - but only if the object
//! carrying it is actually pulled in, and an rlib is an ARCHIVE. By the time
//! the linker reaches this crate there is no undefined `memset` left to
//! resolve, so `#[no_mangle]` fns living here would be silently dropped and
//! `compiler_rt`'s byte loop would keep serving. A binary crate's own object
//! is always linked whole, which is the only placement that reliably wins -
//! the same reasoning as the `#[global_allocator]` in
//! `crates/nzbfast/src/main.rs` and `fix_mmap_threshold_when_bounded` in
//! `crates/parfast/src/main.rs`: a whole-program choice belongs in the
//! program. So the algorithms live here, once, with their tests, and
//! [`crate::fast_mem_ops`] stamps the five exported symbols into the bin.
//!
//! WHY NOT musl's own routines. They are not available to link: zig's
//! `lib/zig/libc/musl/src/string/` carries only `strdup`, `strerror_r`,
//! `strndup`, `strverscmp` and the `wcs*` pair. rustc's own self-contained
//! musl `libc.a` does carry the real x86_64 `memset.s` / `memcpy.s`, but
//! cargo-zigbuild does not put it on the link line - zig provides libc.
//!
//! TWO ARCHITECTURES, ONE CONTRACT. `fill`, `copy_disjoint`,
//! `copy_bytes_forward`, `compare` and `differs` keep the same names and
//! signatures on both, so [`crate::fast_mem_ops`] and the unit tests are
//! shared and only the bodies are gated.
//!
//! - **x86_64**: an overlapping-store ladder for short lengths, then
//!   `rep stosq` / `rep movsq`, which every x86_64 part executes as a fast
//!   string operation. Nothing beyond the baseline is used or detected
//!   (`rep` string ops and the SSE2 unaligned 16-byte pair).
//! - **AArch64**: the same ladder idea, but there is no string operation to
//!   amortise, so the crossover sits at the width of the ladder itself
//!   (`BULK_MIN` = 128) and the body above it is a 64-byte-per-iteration
//!   `stp`/`ldp` loop over NEON `q` registers. NEON is assumed and not
//!   detected: it is mandatory in ARMv8-A and
//!   `aarch64-unknown-linux-musl` carries `target_feature = "neon"`, so the
//!   shipped binary already requires it. Every bulk loop is written as
//!   inline assembly, because LLVM's loop-idiom pass turns a Rust store or
//!   copy loop back into a `memset`/`memcpy` CALL - which, from inside
//!   `memset`, is unbounded recursion. x86_64 sidesteps the same hazard
//!   through its `rep` string ops.
//!
//! WHY NOT armv7. `armv7-unknown-linux-musleabihf` is the third static musl
//! download and it links the same `compiler_rt` byte loops, but it is
//! deliberately left on them. Its target spec has NO `neon` feature, so the
//! 16-byte shapes above are not available to it and it would need its own
//! 32-bit integer variant; and nothing on this fleet can MEASURE one. Apple
//! Silicon cannot execute AArch32 at all, so the aarch64 rig that priced the
//! routines below is no help, and the only remaining option is qemu-user,
//! whose JIT distorts exactly the instruction-mix ratios the question turns
//! on. An unmeasured port is not worth its risk here, so armv7 keeps the byte
//! loops until a real 32-bit ARM box exists. RE-OPENED AND DECLINED
//! 16 Sep 2026: acquiring such a board was weighed against what the port
//! would buy a BETA asset, and declined, so this paragraph stands. The
//! note `research/MEMOPS-ARMV7-NO-RIG-2026-09-16.md` carries the probe
//! that establishes the gap across the whole fleet rather than the
//! aarch64 rig alone, and the method to follow if a board is ever
//! obtained, so neither need be redone.
//!
//! WHERE IT COMPILES, AND WHERE THE TESTS RUN. The module is gated on
//! `target_arch = "x86_64"` or `"aarch64"` and the macro's exports on musl,
//! so the algorithms are built and unit-tested well away from the musl link
//! while only the static downloads take the symbols. Gated on musl alone,
//! nothing in CI would compile a line of this file: no job builds an x86_64
//! musl target, and the two clippy gates are the host (aarch64 macOS) and
//! `x86_64-pc-windows-gnu`. As it stands the x86_64 bodies ride CI's ubuntu
//! `linux-tests` shards, and the AArch64 bodies are compiled by the host
//! clippy gate and run by nightly's `aarch64-cross` job under qemu on a
//! Cortex-A72 model - which is the ONLY place in CI they execute, so its
//! `-E` filter names `memops::` and has to keep doing so.

use core::arch::asm;

#[cfg(target_arch = "x86_64")]
/// `rep stosq`: store `qwords` copies of `v` at `dest`.
///
/// # Safety
/// `dest` must be writable for `qwords * 8` bytes.
#[inline]
pub unsafe fn store_qwords(dest: *mut u8, v: u64, qwords: usize) {
    // SAFETY: the caller guarantees the range is writable. The SysV ABI
    // guarantees DF is clear at a function boundary, so the copy runs
    // upward. `rep stosq` leaves the flags alone.
    unsafe {
        asm!(
            "rep stosq",
            inout("rdi") dest => _,
            inout("rcx") qwords => _,
            in("rax") v,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
/// `rep movsq`: copy `qwords` quadwords from `src` to `dest`.
///
/// # Safety
/// The two ranges must be valid for `qwords * 8` bytes and must not overlap
/// with `src` below `dest`.
#[inline]
pub unsafe fn copy_qwords(dest: *mut u8, src: *const u8, qwords: usize) {
    // SAFETY: as above; the caller owns both ranges.
    unsafe {
        asm!(
            "rep movsq",
            inout("rdi") dest => _,
            inout("rsi") src => _,
            inout("rcx") qwords => _,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
/// Fill `n` bytes at `dest` with `c`.
///
/// Short lengths use the overlapping-store ladder (two stores per width,
/// one from each end), which covers every length up to 126 with no branch
/// per byte; past that a single tail store covers the ragged end and
/// `rep stosq` does the body.
///
/// # Safety
/// `dest` must be writable for `n` bytes.
#[inline]
pub unsafe fn fill(dest: *mut u8, c: u8, n: usize) {
    let v = (c as u64).wrapping_mul(0x0101_0101_0101_0101);
    // SAFETY: every offset below is inside `0..n`, which the caller owns.
    // The ladder's invariant is that after the rung guarded by `n <= k` the
    // head covers `0..=k` and the tail `n-1-k..n-1`, so the two meet for
    // every `n <= 2*k`; the last rung is k = 62, hence the 126 bound.
    unsafe {
        if n == 0 {
            return;
        }
        if n <= 126 {
            dest.write(c);
            dest.add(n - 1).write(c);
            if n <= 2 {
                return;
            }
            dest.add(1).cast::<u16>().write_unaligned(v as u16);
            dest.add(n - 3).cast::<u16>().write_unaligned(v as u16);
            if n <= 6 {
                return;
            }
            dest.add(3).cast::<u32>().write_unaligned(v as u32);
            dest.add(n - 7).cast::<u32>().write_unaligned(v as u32);
            if n <= 14 {
                return;
            }
            dest.add(7).cast::<u64>().write_unaligned(v);
            dest.add(n - 15).cast::<u64>().write_unaligned(v);
            if n <= 30 {
                return;
            }
            dest.add(15).cast::<u64>().write_unaligned(v);
            dest.add(23).cast::<u64>().write_unaligned(v);
            dest.add(n - 31).cast::<u64>().write_unaligned(v);
            dest.add(n - 23).cast::<u64>().write_unaligned(v);
            if n <= 62 {
                return;
            }
            dest.add(31).cast::<u64>().write_unaligned(v);
            dest.add(39).cast::<u64>().write_unaligned(v);
            dest.add(47).cast::<u64>().write_unaligned(v);
            dest.add(55).cast::<u64>().write_unaligned(v);
            dest.add(n - 63).cast::<u64>().write_unaligned(v);
            dest.add(n - 55).cast::<u64>().write_unaligned(v);
            dest.add(n - 47).cast::<u64>().write_unaligned(v);
            dest.add(n - 39).cast::<u64>().write_unaligned(v);
            return;
        }
        // n >= 127: the last up-to-7 bytes the quadword loop cannot reach.
        dest.add(n - 8).cast::<u64>().write_unaligned(v);
        let misalign = (dest as usize) & 15;
        let (body, rem) = if misalign == 0 {
            (dest, n)
        } else {
            // Writing 16 bytes at the head is in range because n >= 127.
            dest.cast::<u64>().write_unaligned(v);
            dest.add(8).cast::<u64>().write_unaligned(v);
            let adj = 16 - misalign;
            (dest.add(adj), n - adj)
        };
        store_qwords(body, v, rem >> 3);
    }
}

#[cfg(target_arch = "x86_64")]
/// `rep movsb`: copy `n` bytes strictly in ascending address order.
///
/// # Safety
/// Both ranges must be valid for `n` bytes; ascending order makes this
/// correct even when they overlap with `dest` below `src`.
#[inline]
pub unsafe fn copy_bytes_forward(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges. DF is clear at a function
    // boundary per the SysV ABI, so the copy runs upward.
    unsafe {
        asm!(
            "rep movsb",
            inout("rdi") dest => _,
            inout("rsi") src => _,
            inout("rcx") n => _,
            options(nostack, preserves_flags),
        );
    }
}

#[cfg(target_arch = "x86_64")]
/// Above this length the string op beats a 32-byte load/store loop, and
/// below it the string op's start-up cost dominates. Measured on the Zen 4
/// box: a `rep movsq` copy ran 0.50-0.57x of the 16-byte loop at 64-256
/// bytes and 1.3-1.4x of it at 4-16 KiB, crossing over between 1 and 2 KiB.
/// 2 KiB is the safe side of that crossover - the loop is within a few
/// percent of the string op just below it, where the string op is 2x slower
/// just below ITS side.
const STRING_OP_MIN: usize = 2048;

/// The length at which `fill` and `copy_disjoint` leave their
/// straight-line ladder for a loop. Named once per architecture so the
/// shared tests can pin both sides of the crossover without knowing which
/// shape serves it.
#[cfg(target_arch = "x86_64")]
pub const BULK_MIN: usize = STRING_OP_MIN;

#[cfg(target_arch = "x86_64")]
/// Copy `n` bytes that do not overlap.
///
/// # Safety
/// The ranges must be valid for `n` bytes and must not overlap.
#[inline]
pub unsafe fn copy_disjoint(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges and guarantees they are disjoint,
    // which is what lets the tail be a second overlapping chunk rather than
    // a byte loop. Every offset below is inside `0..n`.
    unsafe {
        if n < 16 {
            // The same overlapping ladder `fill` uses, read side and write
            // side both, narrowing by half each rung.
            if n == 0 {
                return;
            }
            if n >= 8 {
                let a = src.cast::<u64>().read_unaligned();
                let b = src.add(n - 8).cast::<u64>().read_unaligned();
                dest.cast::<u64>().write_unaligned(a);
                dest.add(n - 8).cast::<u64>().write_unaligned(b);
            } else if n >= 4 {
                let a = src.cast::<u32>().read_unaligned();
                let b = src.add(n - 4).cast::<u32>().read_unaligned();
                dest.cast::<u32>().write_unaligned(a);
                dest.add(n - 4).cast::<u32>().write_unaligned(b);
            } else if n >= 2 {
                let a = src.cast::<u16>().read_unaligned();
                let b = src.add(n - 2).cast::<u16>().read_unaligned();
                dest.cast::<u16>().write_unaligned(a);
                dest.add(n - 2).cast::<u16>().write_unaligned(b);
            } else {
                dest.write(src.read());
            }
            return;
        }
        if n < STRING_OP_MIN {
            // 16-byte units: `u128` compiles to the SSE2 unaligned pair,
            // which is x86_64 baseline, so no CPU feature is assumed.
            if n <= 32 {
                let a = src.cast::<u128>().read_unaligned();
                let b = src.add(n - 16).cast::<u128>().read_unaligned();
                dest.cast::<u128>().write_unaligned(a);
                dest.add(n - 16).cast::<u128>().write_unaligned(b);
                return;
            }
            let mut i = 0;
            while i + 32 <= n {
                let a = src.add(i).cast::<u128>().read_unaligned();
                let b = src.add(i + 16).cast::<u128>().read_unaligned();
                dest.add(i).cast::<u128>().write_unaligned(a);
                dest.add(i + 16).cast::<u128>().write_unaligned(b);
                i += 32;
            }
            if i < n {
                let a = src.add(n - 32).cast::<u128>().read_unaligned();
                let b = src.add(n - 16).cast::<u128>().read_unaligned();
                dest.add(n - 32).cast::<u128>().write_unaligned(a);
                dest.add(n - 16).cast::<u128>().write_unaligned(b);
            }
            return;
        }
        // Align the destination to 8 so the string op runs at full width,
        // then let it take everything but the ragged tail.
        let head = (8 - ((dest as usize) & 7)) & 7;
        if head != 0 {
            let a = src.cast::<u64>().read_unaligned();
            dest.cast::<u64>().write_unaligned(a);
        }
        let body = n - head;
        copy_qwords(dest.add(head), src.add(head), body >> 3);
        let done = head + (body & !7);
        if done < n {
            let b = src.add(n - 8).cast::<u64>().read_unaligned();
            dest.add(n - 8).cast::<u64>().write_unaligned(b);
        }
    }
}

// ---------------------------------------------------------------------------
// AArch64
// ---------------------------------------------------------------------------

/// Fill `bytes` bytes at `dest` with the broadcast byte in `v`, 64 at a time.
///
/// The loop is inline assembly rather than Rust because LLVM's loop-idiom
/// pass turns a store loop back into a `memset` CALL, which from inside
/// `memset` is unbounded recursion. That hazard is why every bulk loop in
/// this section is written out; on x86_64 the `rep` string ops sidestep it
/// for the same reason.
///
/// # Safety
/// `dest` must be writable for `bytes` bytes and 16-byte aligned, and
/// `bytes` must be a non-zero multiple of 64.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn store_blocks(dest: *mut u8, v: u64, bytes: usize) {
    // SAFETY: the caller guarantees alignment, the length and that the range
    // is writable. `subs` writes the flags, so this block does NOT claim
    // `preserves_flags`.
    unsafe {
        asm!(
            "dup v0.2d, {v}",
            "2:",
            "stp q0, q0, [{d}]",
            "stp q0, q0, [{d}, #32]",
            "add {d}, {d}, #64",
            "subs {n}, {n}, #64",
            "b.ne 2b",
            d = inout(reg) dest => _,
            n = inout(reg) bytes => _,
            v = in(reg) v,
            out("v0") _,
            options(nostack),
        );
    }
}

/// Copy `bytes` bytes from `src` to `dest`, 32 at a time, ascending.
///
/// # Safety
/// Both ranges must be valid for `bytes` bytes, `bytes` must be a multiple
/// of 32, and the ranges must not overlap with `src` less than 32 bytes
/// above `dest`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn copy_blocks32(dest: *mut u8, src: *const u8, bytes: usize) {
    if bytes == 0 {
        return;
    }
    // SAFETY: the caller owns both ranges and guarantees the length.
    unsafe {
        asm!(
            "2:",
            "ldp q0, q1, [{s}]",
            "add {s}, {s}, #32",
            "stp q0, q1, [{d}]",
            "add {d}, {d}, #32",
            "subs {n}, {n}, #32",
            "b.ne 2b",
            d = inout(reg) dest => _,
            s = inout(reg) src => _,
            n = inout(reg) bytes => _,
            out("v0") _,
            out("v1") _,
            options(nostack),
        );
    }
}

/// Copy `bytes` bytes from `src` to `dest`, 64 at a time, ascending.
///
/// # Safety
/// Both ranges must be valid for `bytes` bytes, `bytes` must be a non-zero
/// multiple of 64, and the ranges must not overlap with `src` less than 64
/// bytes above `dest`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn copy_blocks(dest: *mut u8, src: *const u8, bytes: usize) {
    // SAFETY: as above - the caller owns both ranges and guarantees the
    // length is a non-zero multiple of the 64-byte step.
    unsafe {
        asm!(
            "2:",
            "ldp q0, q1, [{s}]",
            "ldp q2, q3, [{s}, #32]",
            "add {s}, {s}, #64",
            "stp q0, q1, [{d}]",
            "stp q2, q3, [{d}, #32]",
            "add {d}, {d}, #64",
            "subs {n}, {n}, #64",
            "b.ne 2b",
            d = inout(reg) dest => _,
            s = inout(reg) src => _,
            n = inout(reg) bytes => _,
            out("v0") _,
            out("v1") _,
            out("v2") _,
            out("v3") _,
            options(nostack),
        );
    }
}

/// Above this length `copy_disjoint` leaves its 32-byte loop for the aligned
/// 64-byte block loop. It is a MEASURED crossover and the measurement
/// overturned the first design, so the reasoning is worth keeping.
///
/// The obvious port of the x86_64 shape - a wide overlapping ladder below
/// the bound - was built first and REGRESSED against `compiler_rt` at every
/// length from 64 to 256 bytes, bottoming out at 0.75-0.79x around 96-192.
/// The cause is that `compiler_rt`'s 16-byte loop is traffic-optimal (it
/// moves exactly `n` bytes), while an eight-store ladder moves a flat 128
/// whatever `n` is - 1.33x the traffic at `n` = 96 - and in that range these
/// cores are limited by BYTES MOVED, not by branches. So the mid-range shape
/// here matches `compiler_rt`'s traffic to within 31 bytes and beats it on
/// ITERATION COUNT instead, at 32 bytes a step rather than 16.
///
/// That also makes 1,024 the conservative value, not just the fastest one
/// measured: below it the routine can hardly lose on an unfamiliar core,
/// since it does the same work in half the steps, whereas the block loop
/// above it overshoots and squares up the destination first. The measured
/// difference between a 512 and a 1,024 bound on the rig was 1.37x vs 1.42x
/// at 1 KiB - real but small, and the rig is one virtualised Apple core
/// while the download ships to Graviton, Ampere and Cortex parts nobody
/// here can measure. See `research/MUSL-STATIC-MEMOPS-ARM64-2026-09-16.md`.
#[cfg(target_arch = "aarch64")]
pub const BULK_MIN: usize = 1024;

/// The widest length `fill`'s straight-line ladder covers: eight 16-byte
/// stores, two from each end at four rungs. It is NOT [`BULK_MIN`] - the
/// two crossovers answer different questions, and conflating them made the
/// ladder claim lengths it could not fill. `fill` has no traffic problem to
/// trade against (a byte loop cannot compete at any length), so its bound is
/// simply how far the ladder reaches.
#[cfg(target_arch = "aarch64")]
pub const FILL_LADDER_MAX: usize = 128;

/// Fill `n` bytes at `dest` with `c`.
///
/// Every length up to [`BULK_MIN`] is covered branch-free-per-byte by an
/// overlapping-store ladder (two stores per width, one from each end),
/// exactly as the x86_64 `fill` does; past it the head is squared up to 16
/// and [`store_blocks`] takes the body, with the last up-to-64 ragged bytes
/// covered by four overlapping stores off the end.
///
/// NEON is assumed and not detected: it is mandatory in ARMv8-A and
/// `aarch64-unknown-linux-musl` carries `target_feature = "neon"` in its
/// target spec, so the binary the download ships to unknown hardware already
/// requires it. That is NOT true of `armv7-unknown-linux-musleabihf`, whose
/// spec has no `neon`, which is why this section is `aarch64` and not `arm`.
///
/// # Safety
/// `dest` must be writable for `n` bytes.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn fill(dest: *mut u8, c: u8, n: usize) {
    let v = (c as u64).wrapping_mul(0x0101_0101_0101_0101);
    let w = (v as u128) | ((v as u128) << 64);
    // SAFETY: every offset below is inside `0..n`, which the caller owns.
    // The ladder's invariant is that the head covers `0..k` and the tail
    // `n-k..n`, so the two meet for every `n <= 2*k`; the widest rung before
    // the block loop is k = 64, hence the 128-byte bound.
    unsafe {
        if n == 0 {
            return;
        }
        if n < 16 {
            if n >= 8 {
                dest.cast::<u64>().write_unaligned(v);
                dest.add(n - 8).cast::<u64>().write_unaligned(v);
            } else if n >= 4 {
                dest.cast::<u32>().write_unaligned(v as u32);
                dest.add(n - 4).cast::<u32>().write_unaligned(v as u32);
            } else if n >= 2 {
                dest.cast::<u16>().write_unaligned(v as u16);
                dest.add(n - 2).cast::<u16>().write_unaligned(v as u16);
            } else {
                dest.write(c);
            }
            return;
        }
        if n <= 32 {
            dest.cast::<u128>().write_unaligned(w);
            dest.add(n - 16).cast::<u128>().write_unaligned(w);
            return;
        }
        if n <= 64 {
            dest.cast::<u128>().write_unaligned(w);
            dest.add(16).cast::<u128>().write_unaligned(w);
            dest.add(n - 32).cast::<u128>().write_unaligned(w);
            dest.add(n - 16).cast::<u128>().write_unaligned(w);
            return;
        }
        if n <= FILL_LADDER_MAX {
            dest.cast::<u128>().write_unaligned(w);
            dest.add(16).cast::<u128>().write_unaligned(w);
            dest.add(32).cast::<u128>().write_unaligned(w);
            dest.add(48).cast::<u128>().write_unaligned(w);
            dest.add(n - 64).cast::<u128>().write_unaligned(w);
            dest.add(n - 48).cast::<u128>().write_unaligned(w);
            dest.add(n - 32).cast::<u128>().write_unaligned(w);
            dest.add(n - 16).cast::<u128>().write_unaligned(w);
            return;
        }
        // n > 128. Square the head up to 16 so every block store is aligned,
        // then cover the ragged end with four overlapping stores. `n > 128`
        // is what makes `n - 64` land past the 16-byte head.
        dest.cast::<u128>().write_unaligned(w);
        let adj = (16 - ((dest as usize) & 15)) & 15;
        let blocks = (n - adj) & !63;
        if blocks != 0 {
            store_blocks(dest.add(adj), v, blocks);
        }
        dest.add(n - 64).cast::<u128>().write_unaligned(w);
        dest.add(n - 48).cast::<u128>().write_unaligned(w);
        dest.add(n - 32).cast::<u128>().write_unaligned(w);
        dest.add(n - 16).cast::<u128>().write_unaligned(w);
    }
}

/// Copy `n` bytes that do not overlap.
///
/// The same ladder-then-blocks shape as [`fill`]; see [`BULK_MIN`] for why
/// the crossover sits where it does.
///
/// # Safety
/// The ranges must be valid for `n` bytes and must not overlap.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn copy_disjoint(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges and guarantees they are disjoint,
    // which is what lets each tail be a second overlapping chunk rather than
    // a byte loop. Every offset below is inside `0..n`.
    unsafe {
        if n == 0 {
            return;
        }
        if n < 16 {
            if n >= 8 {
                let a = src.cast::<u64>().read_unaligned();
                let b = src.add(n - 8).cast::<u64>().read_unaligned();
                dest.cast::<u64>().write_unaligned(a);
                dest.add(n - 8).cast::<u64>().write_unaligned(b);
            } else if n >= 4 {
                let a = src.cast::<u32>().read_unaligned();
                let b = src.add(n - 4).cast::<u32>().read_unaligned();
                dest.cast::<u32>().write_unaligned(a);
                dest.add(n - 4).cast::<u32>().write_unaligned(b);
            } else if n >= 2 {
                let a = src.cast::<u16>().read_unaligned();
                let b = src.add(n - 2).cast::<u16>().read_unaligned();
                dest.cast::<u16>().write_unaligned(a);
                dest.add(n - 2).cast::<u16>().write_unaligned(b);
            } else {
                dest.write(src.read());
            }
            return;
        }
        if n <= 32 {
            let a = src.cast::<u128>().read_unaligned();
            let b = src.add(n - 16).cast::<u128>().read_unaligned();
            dest.cast::<u128>().write_unaligned(a);
            dest.add(n - 16).cast::<u128>().write_unaligned(b);
            return;
        }
        if n <= BULK_MIN {
            // 32 bytes an iteration over `n & !31`, then at most two
            // overlapping 16-byte stores for the ragged end. TRAFFIC, not
            // branches, is what this range is limited by on the cores
            // measured, so the shape deliberately copies at most `n + 31`
            // bytes instead of taking a wide overlapping ladder.
            let blocks = n & !31;
            copy_blocks32(dest, src, blocks);
            let rem = n & 31;
            if rem != 0 {
                if rem > 16 {
                    let a = src.add(n - 32).cast::<u128>().read_unaligned();
                    dest.add(n - 32).cast::<u128>().write_unaligned(a);
                }
                let b = src.add(n - 16).cast::<u128>().read_unaligned();
                dest.add(n - 16).cast::<u128>().write_unaligned(b);
            }
            return;
        }
        // Past the crossover the 64-byte block loop pays. The head and the
        // last 64 bytes are written BEFORE it so no register has to live
        // across the loop; the loop may re-write some of those bytes with
        // the same source data, which is harmless for a disjoint copy.
        let head = src.cast::<u128>().read_unaligned();
        let e = src.add(n - 64).cast::<u128>().read_unaligned();
        let f = src.add(n - 48).cast::<u128>().read_unaligned();
        let g = src.add(n - 32).cast::<u128>().read_unaligned();
        let h = src.add(n - 16).cast::<u128>().read_unaligned();
        dest.cast::<u128>().write_unaligned(head);
        dest.add(n - 64).cast::<u128>().write_unaligned(e);
        dest.add(n - 48).cast::<u128>().write_unaligned(f);
        dest.add(n - 32).cast::<u128>().write_unaligned(g);
        dest.add(n - 16).cast::<u128>().write_unaligned(h);
        let adj = (16 - ((dest as usize) & 15)) & 15;
        let blocks = (n - adj) & !63;
        if blocks != 0 {
            copy_blocks(dest.add(adj), src.add(adj), blocks);
        }
    }
}

/// Copy `n` bytes strictly in ascending address order.
///
/// The arm `memmove` takes when the ranges overlap with the destination
/// BELOW the source. There is no `rep movsb` here, so the ascending copy is
/// written out: 32 bytes an iteration, then a byte loop for the ragged tail.
/// A plain Rust byte loop would be turned back into a `memmove` call by
/// LLVM, so both are assembly.
///
/// The chunk loop is safe at EVERY overlap, not only a wide one, because
/// its chunk is exactly its step: the read at iteration `k` starts at
/// `src + 32k` while the writes done so far have reached only
/// `src - gap + 32k`, which is below it for any `gap > 0`. An earlier draft
/// guarded the loop with `gap >= 32` and fell back to a byte loop below
/// that; the guard was dropped because it was not buying correctness and
/// cost 32x on exactly the close overlaps this arm exists to serve. The
/// `gap = 1` rows of `copy_bytes_forward_is_correct_when_the_ranges_overlap`
/// are what hold that.
///
/// # Safety
/// Both ranges must be valid for `n` bytes; ascending order makes this
/// correct even when they overlap with `dest` below `src`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn copy_bytes_forward(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges. Each loop reads a chunk strictly
    // before writing it and advances upward, so an overlap with `dest` below
    // `src` reads bytes the copy has not yet reached.
    unsafe {
        if n == 0 {
            return;
        }
        let mut d = dest;
        let mut s = src;
        let mut rem = n;
        {
            let blocks = rem & !31;
            if blocks != 0 {
                asm!(
                    "2:",
                    "ldp q0, q1, [{s}]",
                    "add {s}, {s}, #32",
                    "stp q0, q1, [{d}]",
                    "add {d}, {d}, #32",
                    "subs {n}, {n}, #32",
                    "b.ne 2b",
                    d = inout(reg) d,
                    s = inout(reg) s,
                    n = inout(reg) blocks => _,
                    out("v0") _,
                    out("v1") _,
                    options(nostack),
                );
                rem -= blocks;
            }
        }
        if rem != 0 {
            asm!(
                "2:",
                "ldrb {t:w}, [{s}], #1",
                "strb {t:w}, [{d}], #1",
                "subs {n}, {n}, #1",
                "b.ne 2b",
                d = inout(reg) d => _,
                s = inout(reg) s => _,
                n = inout(reg) rem => _,
                t = out(reg) _,
                options(nostack),
            );
        }
    }
}

/// Compare `n` bytes, eight at a time, returning the C `memcmp` ordering.
///
/// # Safety
/// Both ranges must be valid for `n` bytes.
#[inline]
pub unsafe fn compare(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: the caller owns both ranges. The quadword scan compares
    // big-endian, so the first DIFFERING byte decides the sign - which is
    // the order C specifies, and is not the order a native-endian compare of
    // the same two words gives.
    unsafe {
        let mut i = 0;
        while i + 8 <= n {
            let x = a.add(i).cast::<u64>().read_unaligned();
            let y = b.add(i).cast::<u64>().read_unaligned();
            if x != y {
                return if x.to_be() < y.to_be() { -1 } else { 1 };
            }
            i += 8;
        }
        while i < n {
            let (x, y) = (a.add(i).read(), b.add(i).read());
            if x != y {
                return x as i32 - y as i32;
            }
            i += 1;
        }
        0
    }
}

/// Equality only, so it may stop at the first differing quadword without
/// working out which way round they are.
///
/// # Safety
/// Both ranges must be valid for `n` bytes.
#[inline]
pub unsafe fn differs(a: *const u8, b: *const u8, n: usize) -> i32 {
    // SAFETY: the caller owns both ranges.
    unsafe {
        let mut i = 0;
        while i + 8 <= n {
            if a.add(i).cast::<u64>().read_unaligned() != b.add(i).cast::<u64>().read_unaligned() {
                return 1;
            }
            i += 8;
        }
        while i < n {
            if a.add(i).read() != b.add(i).read() {
                return 1;
            }
            i += 1;
        }
        0
    }
}

/// Stamp strong `memset` / `memcpy` / `memmove` / `memcmp` / `bcmp` into the
/// CALLING crate, overriding zig `compiler_rt`'s weak byte loops.
///
/// Invoke it once at the root of a BINARY crate that ships a static musl
/// x86_64 artifact - `crates/parfast/src/main.rs` and
/// `crates/nzbfast/src/main.rs` - and nowhere else. It is a macro rather
/// than five `#[no_mangle]` fns in this module because the symbols only win
/// the link from an object that is linked whole (see the module docs), which
/// an rlib's members are not; the macro keeps the bodies single-source while
/// putting the definitions where they take effect.
///
/// The caller does the target gating, so the expansion assumes it is already
/// on x86_64 musl.
#[macro_export]
macro_rules! fast_mem_ops {
    () => {
        /// `memset` - strong, so it wins the link over `compiler_rt`'s weak
        /// byte loop.
        ///
        /// # Safety
        /// The C `memset` contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn memset(
            dest: *mut ::core::ffi::c_void,
            c: i32,
            n: usize,
        ) -> *mut ::core::ffi::c_void {
            // SAFETY: the C contract is the caller's to keep.
            unsafe { $crate::memops::fill(dest.cast(), c as u8, n) };
            dest
        }

        /// `memcpy`.
        ///
        /// # Safety
        /// The C `memcpy` contract: the ranges do not overlap.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn memcpy(
            dest: *mut ::core::ffi::c_void,
            src: *const ::core::ffi::c_void,
            n: usize,
        ) -> *mut ::core::ffi::c_void {
            // SAFETY: the C contract is the caller's to keep.
            unsafe { $crate::memops::copy_disjoint(dest.cast(), src.cast(), n) };
            dest
        }

        /// `memmove`.
        ///
        /// # Safety
        /// The C `memmove` contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn memmove(
            dest: *mut ::core::ffi::c_void,
            src: *const ::core::ffi::c_void,
            n: usize,
        ) -> *mut ::core::ffi::c_void {
            // SAFETY: the C contract is the caller's to keep. Which of the
            // three arms is correct depends only on how the ranges lie.
            unsafe {
                let (d, s): (*mut u8, *const u8) = (dest.cast(), src.cast());
                if (d as usize).abs_diff(s as usize) >= n {
                    // Disjoint: the fast path may work from both ends.
                    $crate::memops::copy_disjoint(d, s, n);
                } else if (d as usize) < (s as usize) {
                    // Overlapping with the destination below the source.
                    // Only a strictly ascending copy is correct here - the
                    // disjoint path reads its tail after writing its head,
                    // which can read bytes the head already overwrote when
                    // the two ranges are within 32 bytes of each other.
                    $crate::memops::copy_bytes_forward(d, s, n);
                } else {
                    // Overlapping the other way: descending, a byte at a
                    // time. Rare enough that a second string-op path is not
                    // worth the surface.
                    let mut i = n;
                    while i > 0 {
                        i -= 1;
                        d.add(i).write(s.add(i).read());
                    }
                }
            }
            dest
        }

        /// `memcmp`.
        ///
        /// # Safety
        /// The C `memcmp` contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn memcmp(
            a: *const ::core::ffi::c_void,
            b: *const ::core::ffi::c_void,
            n: usize,
        ) -> i32 {
            // SAFETY: the C contract is the caller's to keep.
            unsafe { $crate::memops::compare(a.cast(), b.cast(), n) }
        }

        /// `bcmp` - the equality-only form the standard library's slice
        /// compare lowers to.
        ///
        /// # Safety
        /// The C `bcmp` contract.
        #[unsafe(no_mangle)]
        pub unsafe extern "C" fn bcmp(
            a: *const ::core::ffi::c_void,
            b: *const ::core::ffi::c_void,
            n: usize,
        ) -> i32 {
            // SAFETY: the C contract is the caller's to keep.
            unsafe { $crate::memops::differs(a.cast(), b.cast(), n) }
        }
    };
}

#[cfg(test)]
mod tests {
    use super::*;

    /// A reference fill/copy the implementation is checked against, written
    /// so no `memset`/`memcpy` call can serve it.
    fn ref_fill(v: &mut [u8], c: u8) {
        for b in v.iter_mut() {
            *b = c;
        }
    }

    #[test]
    fn fill_matches_a_byte_loop_at_every_length_and_alignment() {
        // Lengths across all four rungs of the ladder and both sides of the
        // 126-byte string-op bound, at every alignment inside a cache line.
        for n in 0..300usize {
            for off in 0..64usize {
                let mut got = vec![0xAAu8; n + off + 64];
                let mut want = got.clone();
                let c = (n as u8) ^ (off as u8) ^ 0x5a;
                // SAFETY: the window `off..off + n` is inside the vec.
                unsafe { fill(got.as_mut_ptr().add(off), c, n) };
                ref_fill(&mut want[off..off + n], c);
                assert_eq!(got, want, "fill n={n} off={off}");
            }
        }
        // `mut` FOR THE aarch64 `extend` BELOW, and the attribute is what
        // keeps both arches green: on every other target the ladder is
        // complete as written, so the `mut` is dead and `-D warnings` reds
        // `check` and `windows-clippy` on it - while DROPPING the `mut`
        // reds aarch64 instead, where the extend needs it. Every dev box
        // on this fleet is aarch64, which is why this shipped green
        // locally and red on main (run 35078365972, 16 Sep 2026).
        #[cfg_attr(not(target_arch = "aarch64"), allow(unused_mut))]
        let mut big: Vec<usize> = vec![1023, 1024, 1025, 4096, 65537];
        // The ladder's own bound, by NAME. It was the same constant as
        // `BULK_MIN` until raising that for `copy_disjoint` silently handed
        // `fill` lengths its eight stores could not reach - caught only
        // because the `0..300` sweep above happens to cover 128, which is
        // luck rather than coverage.
        #[cfg(target_arch = "aarch64")]
        big.extend([FILL_LADDER_MAX - 1, FILL_LADDER_MAX, FILL_LADDER_MAX + 1]);
        for n in big {
            let mut got = vec![0xAAu8; n + 8];
            let mut want = got.clone();
            // SAFETY: `0..n` is inside the vec.
            unsafe { fill(got.as_mut_ptr(), 0x31, n) };
            ref_fill(&mut want[..n], 0x31);
            assert_eq!(got, want, "fill n={n}");
        }
    }

    #[test]
    fn copy_disjoint_matches_the_source_across_the_bulk_bound() {
        let src: Vec<u8> = (0..70_000u32).map(|i| (i % 251) as u8).collect();
        let mut lens: Vec<usize> = (0..300).collect();
        lens.extend([
            BULK_MIN - 1,
            BULK_MIN,
            BULK_MIN + 1,
            // Remainders in the 49..63 band: the block loop stops more than
            // 48 bytes short of the end, so every one of the four tail
            // stores is doing work. Without these the suite passes with one
            // of them deleted.
            BULK_MIN + 49,
            BULK_MIN + 63,
            4096,
            4096 + 63,
            65537,
            65536 + 63,
        ]);
        for &n in &lens {
            // EVERY length gets every destination offset. This loop used to
            // `break` after `off == 0` for `n > 300`, which pinned the block
            // path to one destination alignment and so to one ragged
            // remainder - and a dropped tail store survived the suite
            // because of it. The lengths above deliberately include
            // remainders in the 49..63 band, where the loop stops more than
            // 48 bytes short and all four tail stores are load-bearing.
            for off in 0..24usize {
                for soff in 0..8usize {
                    let mut got = vec![0x55u8; n + off + 64];
                    let mut want = got.clone();
                    // SAFETY: both windows are inside their allocations.
                    unsafe { copy_disjoint(got.as_mut_ptr().add(off), src.as_ptr().add(soff), n) };
                    want[off..off + n].copy_from_slice(&src[soff..soff + n]);
                    assert_eq!(got, want, "copy n={n} off={off} soff={soff}");
                }
            }
        }
    }

    #[test]
    fn copy_bytes_forward_is_correct_when_the_ranges_overlap() {
        // The arm `memmove` takes when the destination is below the source
        // and within `n` of it - the case the disjoint path cannot serve.
        for n in [1usize, 7, 8, 31, 32, 33, 63, 64, 65, 127, 200, 1024, 4096] {
            for gap in [1usize, 2, 3, 8, 12, 16, 24, 31, 32, 33, 64] {
                let base: Vec<u8> = (0..n + 128).map(|i| (i % 251) as u8).collect();
                let mut got = base.clone();
                let mut want = base.clone();
                // SAFETY: src at 64, dest at 64 - gap, both inside the vec.
                unsafe {
                    let p = got.as_mut_ptr();
                    copy_bytes_forward(p.add(64 - gap), p.add(64), n);
                }
                let tmp: Vec<u8> = want[64..64 + n].to_vec();
                want[64 - gap..64 - gap + n].copy_from_slice(&tmp);
                assert_eq!(got, want, "overlap n={n} gap={gap}");
            }
        }
    }

    #[test]
    fn compare_orders_by_the_first_differing_byte() {
        for n in 1..200usize {
            let a: Vec<u8> = (0..n).map(|i| (i % 251) as u8).collect();
            for i in 0..n {
                let mut b = a.clone();
                b[i] = a[i].wrapping_add(1);
                // SAFETY: both slices are `n` bytes.
                let got = unsafe { compare(a.as_ptr(), b.as_ptr(), n) };
                let want = a[i] as i32 - b[i] as i32;
                assert_eq!(got.signum(), want.signum(), "memcmp n={n} i={i}");
                // SAFETY: as above.
                assert_ne!(unsafe { differs(a.as_ptr(), b.as_ptr(), n) }, 0);
            }
            // SAFETY: as above.
            assert_eq!(unsafe { compare(a.as_ptr(), a.as_ptr(), n) }, 0);
            // SAFETY: as above.
            assert_eq!(unsafe { differs(a.as_ptr(), a.as_ptr(), n) }, 0);
        }
    }
}
