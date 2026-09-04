# lzma-rust2, vendored

lzma-rust2 0.20.0 from crates.io, Apache-2.0, vendored under
`[patch.crates-io]` in the root `Cargo.toml`. sevenz-rust2 hands every
LZMA and LZMA2 folder to this crate, and nzbkit's zip reader uses it for
zip method 14, so it is on the hot path of every compressed 7z member we
unpack.

**This file is the whole list of what differs from upstream.** Re-apply
each item on the next bump, or drop it if upstream took it. To see the
diff for yourself:

```sh
diff -ru ~/.cargo/registry/src/*/lzma-rust2-0.20.0/src vendor/lzma-rust2/src
```

## 1. `src/lzma2_reader_mt.rs` - the worker-spawn condition

`send_work_unit` spawned another worker only when every already-spawned
worker had marked itself ACTIVE. A worker marks itself active *after* it
pops a unit, and the dispatcher outruns a decode by two orders of
magnitude, so units queued behind workers that had not popped yet and a
16-block stream decoded on one or two threads. The condition is now
"work is queued and the cap is not reached".

Measured on a driver over the raw pack stream, 1 GiB of LZMA2
(`research/RAR-PERF-AUDIT-2026-09-02.md`, round 11): 9.93 s
single-threaded, 8.13 s "multi-threaded" before, 2.70 s after. End to
end, byte-compared: an M1 Ultra 9.5 -> 2.7-2.8 s, an 8-vCPU EPYC
9.9 -> 2.4-2.9, a six-core i5 8.1-9.1 -> 1.93-2.82.

## 2. `Cargo.toml` - the target sections whose files were not vendored

Upstream's manifest declares `[[test]]`, `[[bench]]` and `[[example]]`
targets and the dev-dependencies they need (criterion, liblzma). None of
those source files are in the published crate we vendored, so `cargo
test -p lzma-rust2` refused the package outright ("requires
dev-dependencies"). Those sections are dropped here. The crate is a
member of the workspace, so its `--lib` tests run in the ordinary sweep:

```sh
cargo test -p lzma-rust2 --lib
```

## 3. `src/filter/bcj.rs` - eight upstream tests marked `#[ignore]`

The eight `test_bcj_*_roundtrip` tests read `tests/data/wget-<arch>`.
Upstream's manifest carries `exclude = ["/tests/data"]`, so those files
are not in the published crate and never were in our copy - the tests
could only ever fail here. They are marked `#[ignore]` with the reason at
the site rather than deleted, so the next bump still shows what upstream
covers. The BCJ path is covered from our side by the `mx9_code_bcj`
fixture in `decoder::differential`, which decodes a real 7-Zip
BCJ+LZMA2 stream.

## 4. `src/decoder.rs` + `src/range_dec.rs` - the bit-tree fastpath

`decode_bit_tree_fixed` / `decode_reverse_bit_tree_fixed` take a
compile-time-sized `[u16; N]`, so `N.trailing_zeros()` is a constant and
the 3-, 6- and 8-bit trees unroll to a straight line with the bounds
check and the loop-carried length compare lifted out of the per-bit
path; the run-time-sized reverse tree over the distance-special slices
keeps its loop and loses only the check. With it, the coder state is
read once per symbol rather than once per `is_*` table, and the four
per-symbol helpers are `#[inline(always)]`.

Measured on an 8-vCPU EPYC over a 1 GiB LZMA2 stream, 8 interleaved
reps, median of the per-rep paired difference: **10.51 -> 10.22 s/GiB
(-2.41%)**, 70.90 G -> 70.00 G retired instructions. No effect on either
aarch64 box. Dropping the `inline(always)` hints alone costs 3.2%.

**Do not "finish the port" by unrolling the literal chains** the way
7-Zip's `LzmaDec.c` does. That was measured: it removes 6.1% of the
retired instructions and is no faster on x86 and 2.4% slower on aarch64,
because the range coder's per-bit dependency chain binds rather than
instruction count. The comment on `LiteralSubDecoder::decode` carries
the numbers, and `research/RAR-PERF-AUDIT-2026-09-02.md`, round 20, has
every arm.

## 5. `src/decoder.rs` - the differential test harness

`LzmaDecoder`'s pre-fastpath decode path is kept beside the shipping one
as `decode_reference` (and `decode_bit_tree_reference` /
`decode_reverse_bit_tree_reference` in `range_dec.rs`), selected by a
`#[cfg(test)]` thread-local switch, the way `vendor/rars` keeps its old
kernels. `decoder::differential` decodes each fixture both ways and
compares byte for byte.

The fixtures in `testdata/` are raw LZMA2 pack streams lifted out of
one-folder `.7z` archives built by 7-Zip itself (`7zz a -t7z -mx1/-mx5/
-mx9 -m0=LZMA2`, plus one `-m0=BCJ -m1=LZMA2`), so they carry the real
encoder's symbol mix rather than this crate's encoder's. The packed
streams run from byte 32 of the archive to byte 32 + NextHeaderOffset
(bytes 12..20 of the signature header). Expected lengths and CRC-32s
come from liblzma via Python, not from this crate, so they are an
independent anchor. Both plaintexts are synthesised by the generator
(log-like text, and synthetic x86-64 code with real E8/E9 rel32 targets
so the BCJ arm has something to filter), so nothing third-party is
embedded here - `vendor/` ships publicly. Two more arms feed truncated
and bit-flipped streams through both decoders, which is where a lifted
bounds check would show as a wrong answer rather than a panic. The
generator is recorded in `research/RAR-PERF-AUDIT-2026-09-02.md`,
round 20.

## 6. `src/lzma2_reader_mt.rs` - the dispatcher's read-ahead

Item 1 above got the reader off one thread; it did not make it scale.
This is the rest of that item, and it is the larger half.

**What was wrong.** `get_next_uncompressed_chunk` read more input only
while `self.work_queue.is_empty()`, and the blocking wait underneath it
was an inner `loop` whose `Timeout` arm went straight back into
`recv_timeout` without ever re-reading the queue. So the dispatcher
pushed ONE work unit, found the queue non-empty on the very next turn,
dropped into that wait, and stayed there until that unit came back
decoded. No second unit could be read in the meantime, whatever the
worker count. Whether the reader ran one decode at a time or two came
down to a race: if a worker had already popped the unit by the time
`is_empty()` ran microseconds later, the dispatcher read on; if not, it
parked. That race is why the same binary on the same idle box measured
2.6 s and 8.2 s for the same GiB.

**What it is now.** The dispatcher budgets on units IN FLIGHT -
dispatched minus received, a quantity a worker cannot empty out from
under it - and reads ahead until `max_workers + 1` are outstanding. Every
arm of the wait returns to the outer loop, so the read-ahead gets another
look. Worker spawning moved onto the same quantity for the same reason.
The result channel's bound went from 1 to `max_workers`, so a worker that
finishes while the caller is consuming an earlier unit takes the next one
instead of parking in `send` (the memory is the same either way: a
blocked sender holds its output buffer just as a queued one does, and the
in-flight budget is what bounds how many can be live). `active_workers`
is gone - nothing reads it any more. Work units now also carry the
decoded length the chunk headers declare, so a 64 MiB unit is one
allocation rather than a chain of doublings.

**Measured**, 1 GiB of LZMA2 in 8 independent blocks (the 7zl shape),
through a driver on the raw pack stream, arms interleaved, output digests
identical at every worker count. Single-threaded is untouched and reads
the same in both arms. A 20-core M1 Ultra at load 3.0-3.4, 5 reps:
at 8 workers **4.80-8.07 s/GiB before (median 6.97), 2.53-2.56 after
(median 2.55)**, and with the driver's own hashing pass off, 3.50-4.77
before against **1.23-1.28** after - 6.9x over the same binary's
single-threaded 8.79. The before-arm's spread is 68% of its median and
the after-arm's is 1.1%: the thing that was being measured before was the
race, not a rate. An instrumented build agrees on the mechanism directly:
over 8 units with 8 threads spawned, the peak number of workers decoding
at once is **2 before and 8 after**.

Full arms, the x86 column and the end-to-end leg:
`research/RAR-PERF-AUDIT-2026-09-02.md`, round 32.

**The tests it is carried by** are in the file, beside the code:
`lzma2_reader_mt::tests` decodes the same 7-Zip fixtures
`decoder::differential` uses, plus streams synthesised with 1, 2, 5, 9
and 17 independent blocks, through `Lzma2ReaderMt` at 1, 2, 3, 4, 8, 16
and 64 workers and at consumer read sizes from 1 byte to 1 MiB, and
byte-compares every one against `Lzma2Reader` over the identical stream -
never against a stored digest, because the failure a scheduling change
invites is reassembly in the wrong order. Corrupt and truncated streams
are asked of both readers and must reach the same outcome. All 32 pass
under AddressSanitizer.
