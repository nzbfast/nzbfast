#![no_main]
//! Fuzz the RAR reader + decompressor on arbitrary bytes (untrusted
//! archives from a completed download). The window and output are bounded
//! so a decompression bomb can't OOM/hang the fuzzer - we are hunting
//! panics / OOB in the parse + decode paths, not memory pressure.
use libfuzzer_sys::fuzz_target;
use std::cell::Cell;
use std::io::Write;
use std::rc::Rc;

use rars::{ArchiveReadOptions, ArchiveReader};

/// Discards output but caps the total so a bomb terminates the run.
///
/// 8 MiB, not the 64 MiB this started with. The original figure was chosen
/// against OOM, and it does prevent that - but libFuzzer also enforces a
/// per-input WALL CLOCK limit (`-timeout=10`), and 64 MiB of decode does not
/// fit inside it once the target is built with coverage instrumentation.
///
/// Measured on the input that caught this (a 1,112-byte RAR15 that expands
/// 60,409x, found by the first CI run on 4 Aug): 67,174,400 bytes out, 528ms
/// uninstrumented at ~127 MB/s - a perfectly ordinary decode rate, no
/// pathology - but **14,466ms** under `__sanitizer_cov_trace_*`, a 27x
/// multiplier, which blew the 10s limit and failed the job.
///
/// Lowering the cap is the right lever rather than raising `-timeout`: this
/// target hunts panics and OOB in the parse and decode paths, and 8 MiB of
/// output exercises those just as well as 64 MiB, while keeping `-timeout=10`
/// meaningful as a genuine hang detector instead of a bomb detector.
/// The budget is PER ARCHIVE, not per entry. It used to live inside the
/// sink, and `open` builds a fresh sink for every member - so an archive
/// of 400 members each decoding 8 MiB passed the cap 400 times over and
/// produced 3.2 GiB of output, which is exactly the libFuzzer timeout the
/// cap was lowered to 8 MiB to prevent. One counter, shared by every
/// sink the run opens.
struct CapSink(Rc<Cell<usize>>);
impl Write for CapSink {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.set(self.0.get().saturating_add(buf.len()));
        if self.0.get() > 8 * 1024 * 1024 {
            return Err(std::io::Error::other("output cap"));
        }
        Ok(buf.len())
    }
    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

fuzz_target!(|data: &[u8]| {
    let opts = || {
        ArchiveReadOptions::new()
            .with_rar50_max_window(1 << 20)
            .with_rar50_buffered_decode_limit(1 << 20)
    };
    if let Ok(archive) = ArchiveReader::read_with_options(data, opts()) {
        let spent = Rc::new(Cell::new(0usize));
        let _ = archive.extract_to_with_options(opts(), |_meta| {
            Ok(Box::new(CapSink(spent.clone())) as Box<dyn Write>)
        });
    }
});
