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
/// The arm `memmove` takes when the ranges overlap with the destination
/// BELOW the source.
///
/// THIS LOSES TO `compiler_rt.memmove.memmoveFast` ACROSS A MEASURED BAND
/// AND IS LEFT ALONE ON PURPOSE, 16 Sep 2026. `compiler_rt` moves a 16-byte
/// vector whose chunk equals its step, which is correct at ANY gap, so the
/// routine we are beaten by is not slow here at all: measured against it on
/// a Zen 4 part, `rep movsb` reads **0.45-0.72x at gaps of 16 and 24 for
/// lengths from 48 to 512**, the string op's start-up cost against a vector
/// loop. Two replacements were built and measured and NEITHER cleared the
/// bar - a 16/8-byte chunk loop regressed to 0.80x at gap 1 for lengths
/// 128-192, and routing these moves into [`copy_disjoint`] regressed to
/// 0.42x wherever `src - dest` was not a multiple of 8. Both are recorded
/// in `research/MEMOPS-MEMMOVE-OVERLAP-2026-09-16.md` so the next attempt
/// starts after them rather than at them, and the measured population this
/// arm actually serves is 299 calls and 64 KB in a 2.05 GB TLS download,
/// which is why an unproven replacement is the worse trade.
///
/// THREE MORE FAILED ON 17 Sep 2026 AND THE ARM IS STILL THIS, for a reason
/// that is no longer about shape at all - see
/// `research/MEMOPS-MEMMOVE-OVERLAP-PARITY-2026-09-17.md`. An aligned
/// 64-byte block loop read 0.50-0.63x across 64-512 bytes; `compiler_rt`'s
/// own `copyForwards` TRANSLITERATED read 0.51-0.65x over the same band;
/// and the transliteration with the string op kept above 768 bytes read the
/// same. The cause is CODEGEN, not algorithm: LLVM unrolls zig's element
/// loop four ways and gives its aligned side a `movaps`, and gives the same
/// algorithm written here one unaligned `movups` pair a turn. Whoever takes
/// this next should make the aligned side an ALIGNED ACCESS and let the
/// loop be one LLVM will unroll, rather than trying a fifth shape.
///
/// AND THIS ARM HAS A HOLE OF ITS OWN THAT NOTHING HERE FIXES, found the
/// same day by benching main as an arm in its own right: at
/// `gap == n - 1` from 4 KiB to 1 MiB `rep movsb` runs **0.067-0.095x** of
/// `compiler_rt` - 3.4 GB/s against 37-55 - because the store for byte `i`
/// and the load for byte `i + 1` then share their low 12 address bits and
/// every iteration takes a false 4 KiB dependency. It is left standing
/// deliberately: the population above says an ascending overlap here
/// averages ~212 bytes and never reaches 4 KiB, and the guard that removes
/// it (`(gap + 1) % 4096 != 0`) is a constant fitted to one part.
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
        //
        // THE RELATIVE ALIGNMENT COSTS NOTHING, AND THIS IS THE END TO
        // ALIGN. MEASURED 17 Sep 2026 - DO NOT "FIX" IT.
        // `rep movsq` is documented as wanting both ends aligned, and
        // `src - dest` is invariant under any head, so when it is not a
        // multiple of 8 no head can align both. That reads as a defect and
        // was reported as one: section 5 of
        // `research/MEMOPS-MEMMOVE-OVERLAP-2026-09-16.md` has this routine
        // at 0.42-0.65x of `compiler_rt` for every copy of 2 KiB or more
        // whose ends differ by a non-multiple of 8. It is not. Over 512
        // cells on the same Zen 4 rig, with the ranges DISJOINT - the only
        // way a `memcpy` is called - the code below reads **1.395-1.436x of
        // `compiler_rt` at every one of the eight `(src - dest) % 8`
        // residues**, against a byte-identical A/A of 0.997-1.009, with
        // not one of grid A's 160 cells below 0.99. Ragged destination
        // (1, 8, 16, 32, 63): median 1.518. Five separations from touching
        // to 1 MiB apart: 1.016-1.155.
        // WHAT THAT REPORT MEASURED IS 4 KiB STORE-TO-LOAD ALIASING, which
        // its grid could not tell apart from alignment because it placed
        // the source at `dest + gap` and so had one variable doing both
        // jobs. This loop's loads run `gap` bytes ahead of its stores, and
        // a load matching a pending store in bits 11:0 cannot be
        // disambiguated: at `gap = 4088` the aliased store is the
        // immediately preceding one and throughput falls to 0.41-0.45x, at
        // every residue including 0. At `gap = 4096` and `gap = 2048` it
        // is 1.63-1.69x, again at every residue. `compiler_rt`'s 16-byte
        // loop loses ~8% on the same input rather than 2.4x, which is what
        // made the contrast look like a routine defect.
        // AND THE FIX THAT LOOKS OBVIOUS WAS BUILT AND PRICED: gating the
        // string op on relative alignment keeps 1.32x at residue 0 and
        // hands back 1.4x -> 1.01-1.04x at the other seven, which are
        // seven eighths of the population. That is the same trade, on the
        // primitive, as the 1.019x it cost the daemon's TLS cell in that
        // round. Aligning the SOURCE instead reads 1.171-1.235, i.e. worse
        // than this, so the end chosen here is the right one.
        // THE ALIASING WINDOW IS REACHABLE BY A LEGAL `memcpy`, AND WAS
        // PRICED AND LEFT ALONE. With the ranges DISJOINT throughout, a
        // copy whose `src - dest` sits 8 or 24 bytes BELOW a multiple of
        // 4096 runs 0.375-0.609x at every length from 2 KiB to 64 KiB; at
        // 64 bytes below it is fast again (1.436, 1.648, 1.845), so the
        // window is 24-64 bytes of the 4,096 - **at most 1.6% of gaps and
        // probably ~0.8%**. A gate on `((src - dest) & 4095) >= 4096 - W`
        // repairs every one of those cells (0.375 -> 0.982, 0.609 -> 1.161)
        // and is NOT taken, for two reasons: W's upper edge is bracketed
        // rather than measured (residues 32/40/48/56 were not in the grid,
        // and both widths tried - 64 and 512 - are too wide and cost the
        // fast residue at their own boundary), and the arithmetic is
        // against it. The population this routine serves in a TLS leg is
        // rustls's deframer compaction at `conn.rs:937`
        // (`research/MEMMOVE-SELFMOVE-SITE-2026-09-17.md`), where `gap` is
        // the bytes consumed that pass, so under 1% of 277 MB would be
        // repaired while every copy above 2 KiB pays a load, an `and` and a
        // compare. What would flip that is evidence the real `gap`
        // distribution is CONCENTRATED near multiples of 4096 rather than
        // uniform, and that commit's own probe patch answers it in one
        // counting leg.
        // THAT LEG HAS NOW RUN, AND THE WINDOW IS UNREACHABLE FROM THE
        // CALLER, SO THE GATE IS CLOSED RATHER THAN DEFERRED. Over 129,966
        // disjoint calls and 277.4 MB, 127,236 of them (97.9%) sit at
        // `(src - dest) & 4095 == 22`, and NOT ONE lands within 256 bytes
        // of a multiple of 4096 from below. That is 4,074 bytes from the
        // window, on the mirror side the same grid measured at 1.353-1.927x.
        // It is arithmetic and not luck: `gap` is one TLS record's wire
        // size, `16384 + 22`, and **16,384 is exactly four times 4,096**, so
        // the residue IS the per-record AEAD overhead - 22 on TLS 1.3, 29 on
        // TLS 1.2 AES-GCM - and reaching the window would need an overhead
        // of 4,064-4,095 bytes. Independently, only 2,682 of those calls
        // (2.06%) are longer than `STRING_OP_MIN` and execute `rep movsq` at
        // all; 125,678 are in the 1-2 KiB bucket, just under the crossover.
        // So do not re-derive the gate from the 0.375x above: the hole is
        // real and this caller is on the other side of the period from it.
        // `research/MEMCPY-ALIAS-RESIDUE-REACHABILITY-2026-09-17.md` carries
        // the histogram, the record arithmetic and the two limits (one
        // caller; counted on aarch64, where the population reproduces the
        // x86_64 musl figures to 0.02%).
        // `research/MEMCPY-RELATIVE-ALIGNMENT-2026-09-17.md` carries the
        // four grids, the nine shapes that were tried and that arithmetic.
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

#[cfg(target_arch = "x86_64")]
/// Copy `n` bytes strictly in DESCENDING address order.
///
/// The arm `memmove` takes when the ranges overlap with the destination
/// ABOVE the source, which is the one direction no ascending path can
/// serve. It was a byte-at-a-time loop until 16 Sep 2026; see
/// [`move_bytes`] for what that cost and how it was found.
///
/// There is no descending string op worth having - `std; rep movsb; cld`
/// runs the slow microcoded path on every part in this family - so this is
/// the ascending 32-byte SSE2 loop written backwards.
///
/// MEASURED AT PARITY 17 Sep 2026 AND LEFT ALONE. The 16 Sep round reported
/// this arm "short of `compiler_rt` in 54 of 215 cells", and that figure was
/// against a 0.99 bar rather than against the noise floor: re-benched with
/// an A/A arm of 0.825-1.158, it is **median 1.032, one cell below the
/// floor**. Two replacements were built and measured and both were far
/// worse - an aligned 64-byte version, and `compiler_rt`'s own
/// `copyBackwards` transliterated, which reads a flat **0.42-0.51x** above
/// 512 bytes because LLVM unrolls zig's loop four ways and does not unroll
/// the same algorithm written here.
/// `research/MEMOPS-MEMMOVE-OVERLAP-PARITY-2026-09-17.md` has both.
///
/// Safe at EVERY overlap, not only a wide one, because its chunk is exactly
/// its step and both halves are READ before either is written: at iteration
/// `k` it reads `[src + n - 32(k+1), src + n - 32k)` while the writes so far
/// have reached down only to `dest + n - 32k = src + gap + n - 32k`, which is
/// at or above the read's end for any `gap >= 0`. The ragged head goes to
/// [`copy_disjoint`], whose sub-32-byte paths read both ends before writing
/// either and so are correct at any overlap in either direction.
///
/// # Safety
/// Both ranges must be valid for `n` bytes; descending order makes this
/// correct even when they overlap with `dest` above `src`.
#[inline]
pub unsafe fn copy_bytes_backward(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges. Every offset below is inside
    // `0..n`, and the order is strictly descending.
    unsafe {
        let mut rem = n;
        // 64 bytes - a whole cache line - and not 32. A descending walk
        // gets no help from the hardware prefetcher, so the step is what
        // has to carry it: measured against `compiler_rt`, the 32-byte
        // version read 0.76-0.92x from 64 KiB to 1 MiB where this one
        // clears parity. Widening costs nothing at the short end because
        // the 32-byte arm below still catches it.
        while rem >= 64 {
            // Every load before every store: see the note above.
            let a = src.add(rem - 64).cast::<u128>().read_unaligned();
            let b = src.add(rem - 48).cast::<u128>().read_unaligned();
            let c = src.add(rem - 32).cast::<u128>().read_unaligned();
            let d = src.add(rem - 16).cast::<u128>().read_unaligned();
            dest.add(rem - 64).cast::<u128>().write_unaligned(a);
            dest.add(rem - 48).cast::<u128>().write_unaligned(b);
            dest.add(rem - 32).cast::<u128>().write_unaligned(c);
            dest.add(rem - 16).cast::<u128>().write_unaligned(d);
            rem -= 64;
        }
        if rem >= 32 {
            let a = src.add(rem - 32).cast::<u128>().read_unaligned();
            let b = src.add(rem - 16).cast::<u128>().read_unaligned();
            dest.add(rem - 32).cast::<u128>().write_unaligned(a);
            dest.add(rem - 16).cast::<u128>().write_unaligned(b);
            rem -= 32;
        }
        if rem != 0 {
            copy_disjoint(dest, src, rem);
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

/// Copy `n` bytes strictly in DESCENDING address order.
///
/// The AArch64 twin of the x86_64 arm above, and the same 32-byte chunk
/// written backwards; assembly for the same reason [`copy_bytes_forward`]
/// is, because LLVM's loop-idiom pass turns a Rust copy loop back into a
/// `memmove` CALL, which from inside `memmove` is unbounded recursion.
///
/// Safe at EVERY overlap: chunk equals step and the pair is loaded before
/// it is stored, so the write at iteration `k` lands at or above the end of
/// the read that follows it.
///
/// # Safety
/// Both ranges must be valid for `n` bytes; descending order makes this
/// correct even when they overlap with `dest` above `src`.
#[cfg(target_arch = "aarch64")]
#[inline]
pub unsafe fn copy_bytes_backward(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges. The loop walks down from the top
    // of the copy, so an overlap with `dest` above `src` writes only bytes
    // the copy has already read.
    unsafe {
        // 64 bytes a step, the same width the ascending block loop uses and
        // for the same reason as the x86_64 twin: a descending walk gets no
        // help from the hardware prefetcher, so the step has to carry it.
        // The 32-byte arm below catches what the 64-byte loop leaves, so
        // nothing short pays for the width.
        let mut rem = n;
        let blocks = n & !63;
        let mut d = dest.add(n);
        let mut s = src.add(n);
        if blocks != 0 {
            asm!(
                "2:",
                "sub {s}, {s}, #64",
                "sub {d}, {d}, #64",
                "ldp q0, q1, [{s}]",
                "ldp q2, q3, [{s}, #32]",
                "stp q0, q1, [{d}]",
                "stp q2, q3, [{d}, #32]",
                "subs {n}, {n}, #64",
                "b.ne 2b",
                d = inout(reg) d,
                s = inout(reg) s,
                n = inout(reg) blocks => _,
                out("v0") _,
                out("v1") _,
                out("v2") _,
                out("v3") _,
                options(nostack),
            );
            rem -= blocks;
        }
        if rem >= 32 {
            let a = src.add(rem - 32).cast::<u128>().read_unaligned();
            let b = src.add(rem - 16).cast::<u128>().read_unaligned();
            dest.add(rem - 32).cast::<u128>().write_unaligned(a);
            dest.add(rem - 16).cast::<u128>().write_unaligned(b);
            rem -= 32;
        }
        if rem != 0 {
            copy_disjoint(dest, src, rem);
        }
        let _ = (d, s);
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

// ---------------------------------------------------------------------------
// The `memmove` dispatcher, shared
// ---------------------------------------------------------------------------

/// The longest move [`copy_disjoint`] serves by reading BOTH ends before it
/// writes either, which makes it correct at ANY overlap in EITHER direction.
/// Both architectures' short paths have that shape (the sub-16 ladder and the
/// 16..=32 pair), and [`move_bytes`] leans on it.
pub const OVERLAP_SAFE_ANY_MAX: usize = 32;

/// The full C `memmove`: copy `n` bytes correctly however the ranges lie.
///
/// WHY THIS IS A FUNCTION AND NOT FOUR LINES IN [`crate::fast_mem_ops`].
/// It was four lines in the macro until 16 Sep 2026, which put the one part
/// of these routines with a real decision in it in the one place no unit
/// test can reach - the macro only expands inside a bin. The dispatch is
/// here so the tests below drive it directly, over every shape, on both
/// architectures.
///
/// THE ARMS, and each one's bound is a correctness bound first:
///
/// - **`dest == src`** returns at once. musl's own `memmove.c` opens with
///   exactly this line and the first port of it here did not, which is the
///   whole of the regression this function was written to fix: measured on
///   the 16 Sep daemon round's TLS cell, **161,095 of the 291,000 memmove
///   calls in a 2.05 GB download are self-moves carrying 586 MB**, and every
///   one of them was being served a byte at a time by the descending arm
///   below, because `abs_diff == 0` is not `>= n` and `dest < src` is false
///   when they are equal. That is the `compiler_rt.memmove.memmoveFast`
///   0.66% -> our 5.14% of a TLS leg reported in section 5 of
///   `research/MUSL-MEMOPS-DAEMON-2026-09-16.md`. Genuine overlaps in that
///   same population are 414 calls and 64 KB, i.e. nothing.
/// - **disjoint, or `n <= OVERLAP_SAFE_ANY_MAX`** goes to
///   [`copy_disjoint`]: either the ranges do not overlap at all, or the move
///   is short enough that it reads both ends before writing either.
/// - **ascending overlap** (`dest` below `src`) goes to
///   [`copy_bytes_forward`], unchanged. Two faster shapes were built and
///   measured for it and neither cleared parity with `compiler_rt` at every
///   length and gap, so this arm keeps the shape it had; that routine's
///   docs carry both results.
/// - **descending overlap** (`dest` above `src`) goes to
///   [`copy_bytes_backward`]. [`copy_disjoint`] can NEVER serve this
///   direction at any gap: it writes above where it reads, so a write always
///   lands on source bytes a later step still needs.
///
/// # Safety
/// Both ranges must be valid for `n` bytes. Any overlap is allowed; that is
/// the whole point of `memmove`.
#[inline]
pub unsafe fn move_bytes(dest: *mut u8, src: *const u8, n: usize) {
    // SAFETY: the caller owns both ranges for `n` bytes. Which arm is
    // correct depends only on how the two ranges lie, which is what the
    // gap and the sign below decide.
    unsafe {
        let (d, s) = (dest as usize, src as usize);
        let gap = d.abs_diff(s);
        if gap == 0 {
            return;
        }
        if gap >= n || n <= OVERLAP_SAFE_ANY_MAX {
            copy_disjoint(dest, src, n);
        } else if d < s {
            copy_bytes_forward(dest, src, n);
        } else {
            copy_bytes_backward(dest, src, n);
        }
    }
}

/// Stamp strong `memset` / `memcpy` / `memmove` / `memcmp` / `bcmp` into the
/// CALLING crate, overriding zig `compiler_rt`'s weak byte loops.
///
/// Invoke it once at the root of a BINARY crate that ships a static musl
/// x86_64 or aarch64 artifact - `crates/parfast/src/main.rs` and
/// `crates/nzbfast/src/main.rs` - and nowhere else. It is a macro rather
/// than five `#[no_mangle]` fns in this module because the symbols only win
/// the link from an object that is linked whole (see the module docs), which
/// an rlib's members are not; the macro keeps the bodies single-source while
/// putting the definitions where they take effect.
///
/// The caller does the target gating, so the expansion assumes it is already
/// on musl, on one of the two architectures the bodies above are written
/// for. Both call sites say `any(target_arch = "x86_64", target_arch =
/// "aarch64")`; the aarch64 half joined on 16 Sep 2026 and this line still
/// said x86_64 alone until 17 Sep. Which jobs compile each expansion, and
/// which do not, is in CLAUDE.md's `target_env` axis section.
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
            // SAFETY: the C contract is the caller's to keep. The whole
            // decision lives in `move_bytes`, where the unit tests can
            // reach it - this macro only expands inside a bin.
            unsafe { $crate::memops::move_bytes(dest.cast(), src.cast(), n) };
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
        // `pad` walks the whole 16-byte residue class of the DESTINATION,
        // which is what the arm squares up before its block loop, so every
        // value of the ragged head is exercised at every length. Without it
        // the only thing moving the destination's alignment is `gap`, and a
        // head bound could be wrong at a residue no gap in the list reaches.
        for n in [
            1usize, 7, 8, 31, 32, 33, 47, 63, 64, 65, 79, 95, 96, 127, 128, 129, 200, 1024, 4096,
        ] {
            for gap in [1usize, 2, 3, 8, 12, 16, 24, 31, 32, 33, 64] {
                for pad in 0..16usize {
                    let base: Vec<u8> = (0..n + 160).map(|i| (i % 251) as u8).collect();
                    let mut got = base.clone();
                    let mut want = base.clone();
                    let d = 64 + pad - gap;
                    // SAFETY: src at 64 + pad, dest at 64 + pad - gap, both
                    // inside the vec for `n` bytes.
                    unsafe {
                        let p = got.as_mut_ptr();
                        copy_bytes_forward(p.add(d), p.add(64 + pad), n);
                    }
                    let tmp: Vec<u8> = want[64 + pad..64 + pad + n].to_vec();
                    want[d..d + n].copy_from_slice(&tmp);
                    assert_eq!(got, want, "overlap n={n} gap={gap} pad={pad}");
                }
            }
        }
    }

    /// The reference: a `memmove` that cannot get an overlap wrong, because
    /// it copies the source out before it writes anything.
    fn ref_move(buf: &mut [u8], dofs: usize, sofs: usize, n: usize) {
        let tmp: Vec<u8> = buf[sofs..sofs + n].to_vec();
        buf[dofs..dofs + n].copy_from_slice(&tmp);
    }

    #[test]
    fn copy_bytes_backward_is_correct_when_the_ranges_overlap() {
        // The arm `memmove` takes when the destination is ABOVE the source
        // and within `n` of it - the one direction no ascending path and no
        // disjoint path can serve, at any gap. The mirror of
        // `copy_bytes_forward_is_correct_when_the_ranges_overlap`, and the
        // lengths straddle the 32-byte chunk and its ragged head.
        // `pad` walks the destination's 16-byte residue class for the same
        // reason the ascending test does: this arm squares the TOP of the
        // destination down, so the ragged tail is a function of
        // `(dest + n) % 16` and nothing else in the grid moves it.
        for n in [
            1usize, 7, 8, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 79, 95, 96, 127, 128, 129, 200,
            1024, 4096,
        ] {
            for gap in [1usize, 2, 3, 8, 12, 15, 16, 17, 24, 31, 32, 33, 47, 64, 129] {
                for pad in 0..16usize {
                    let base: Vec<u8> = (0..n + 288).map(|i| (i % 251) as u8).collect();
                    let mut got = base.clone();
                    let mut want = base.clone();
                    let s0 = 64 + pad;
                    // SAFETY: src at 64 + pad, dest at 64 + pad + gap, both
                    // inside the vec for `n` bytes.
                    unsafe {
                        let p = got.as_mut_ptr();
                        copy_bytes_backward(p.add(s0 + gap), p.add(s0), n);
                    }
                    ref_move(&mut want, s0 + gap, s0, n);
                    assert_eq!(got, want, "backward overlap n={n} gap={gap} pad={pad}");
                }
            }
        }
    }

    #[test]
    fn move_bytes_matches_a_reference_memmove_at_every_overlap() {
        // The dispatcher itself, which is where this module's only real
        // DECISION lives and where the 16 Sep regression was. Four arms, and
        // the grid has to cross every bound that selects between them: the
        // gap `0` self-move, `OVERLAP_SAFE_ANY_MAX` and `BULK_MIN`, in both
        // directions. The gap list keeps 31/32/33 even though no arm turns
        // on 32 any more: an ascending chunk loop is correct at EVERY gap
        // (its write lands below where it read), which is exactly the
        // property a future replacement for `copy_bytes_forward` will lean
        // on, and these rows are what would catch it being got wrong.
        let mut lens: Vec<usize> = (0..=300).collect();
        for extra in [
            OVERLAP_SAFE_ANY_MAX - 1,
            OVERLAP_SAFE_ANY_MAX,
            OVERLAP_SAFE_ANY_MAX + 1,
            BULK_MIN - 1,
            BULK_MIN,
            BULK_MIN + 1,
            BULK_MIN + 31,
            BULK_MIN + 49,
            BULK_MIN + 63,
            2 * BULK_MIN,
            4096,
            4096 + 63,
            8191,
            65537,
        ] {
            lens.push(extra);
        }
        lens.sort_unstable();
        lens.dedup();
        let pad = 4 * BULK_MIN + 512;
        for &n in &lens {
            let mut gaps: Vec<usize> = vec![
                0, 1, 2, 3, 7, 8, 15, 16, 17, 31, 32, 33, 47, 63, 64, 65, 127, 128, 129,
            ];
            for rel in [n / 2, n.saturating_sub(1), n, n + 1, n + 31, 2 * n] {
                gaps.push(rel);
            }
            gaps.sort_unstable();
            gaps.dedup();
            // A length that reaches the block paths does not need every
            // alignment as well - `copy_disjoint`'s own test sweeps those -
            // so the offsets narrow once the case count would otherwise
            // multiply out into minutes.
            let offs: &[usize] = if n <= 300 {
                &[0, 1, 7, 8, 15, 16, 31]
            } else {
                &[0, 1, 15]
            };
            for &gap in &gaps {
                for &off in offs {
                    for dir in 0..2u8 {
                        let span = n + gap + pad;
                        let base: Vec<u8> = (0..span).map(|i| ((i * 7 + 13) % 251) as u8).collect();
                        let mut got = base.clone();
                        let mut want = base.clone();
                        let (dofs, sofs) = if dir == 0 {
                            (off, off + gap)
                        } else {
                            (off + gap, off)
                        };
                        // SAFETY: both windows are inside the vec - the span
                        // carries `n + gap` plus the padding.
                        unsafe {
                            let p = got.as_mut_ptr();
                            move_bytes(p.add(dofs), p.add(sofs), n);
                        }
                        ref_move(&mut want, dofs, sofs, n);
                        assert_eq!(got, want, "move n={n} gap={gap} off={off} dir={dir}");
                    }
                }
            }
        }
    }

    #[test]
    fn move_bytes_leaves_a_self_move_alone() {
        // `dest == src` is a no-op by the C contract, and this is the line
        // musl's own `memmove.c` opens with. It is pinned on its own because
        // the regression it fixes was invisible to every other test here:
        // the byte loop the self-move used to take produced the RIGHT bytes,
        // so only a measurement could see it (0.66% -> 5.14% of a TLS leg,
        // 586 MB of a 2.05 GB download moved a byte at a time).
        for n in [0usize, 1, 31, 32, 33, 1024, BULK_MIN + 1, 65536] {
            let base: Vec<u8> = (0..n + 64).map(|i| (i % 251) as u8).collect();
            let mut got = base.clone();
            // SAFETY: the window is inside the vec.
            unsafe {
                let p = got.as_mut_ptr();
                move_bytes(p.add(16), p.add(16), n);
            }
            assert_eq!(got, base, "self-move n={n}");
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
