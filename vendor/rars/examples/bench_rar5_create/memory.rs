//! Requested live heap bytes during one writer invocation, excluding inputs.
//! This is allocation accounting, not RSS: allocator metadata, stacks and
//! resident code are outside it. Do not use this instrumented mode for CPU.
#![allow(unsafe_code)]
use rars::rar50::{CompressedEntry, Rar50Writer, WriterOptions};
use rars::{ArchiveVersion, FeatureSet};
use std::alloc::{GlobalAlloc, Layout, System};
use std::sync::atomic::{AtomicUsize, Ordering::Relaxed};

pub struct Meter;
static LIVE: AtomicUsize = AtomicUsize::new(0);
static PEAK: AtomicUsize = AtomicUsize::new(0);
fn add(bytes: usize) {
    let live = LIVE.fetch_add(bytes, Relaxed) + bytes;
    PEAK.fetch_max(live, Relaxed);
}
// SAFETY: Every request is forwarded unchanged to System, and dealloc/realloc
// retain the caller's allocation and layout contract. Counters neither inspect
// the allocated memory nor allocate themselves. Failed requests do not count.
unsafe impl GlobalAlloc for Meter {
    unsafe fn alloc(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc(layout) };
        if !ptr.is_null() {
            add(layout.size());
        }
        ptr
    }
    unsafe fn alloc_zeroed(&self, layout: Layout) -> *mut u8 {
        let ptr = unsafe { System.alloc_zeroed(layout) };
        if !ptr.is_null() {
            add(layout.size());
        }
        ptr
    }
    unsafe fn dealloc(&self, ptr: *mut u8, layout: Layout) {
        unsafe { System.dealloc(ptr, layout) };
        LIVE.fetch_sub(layout.size(), Relaxed);
    }
    unsafe fn realloc(&self, ptr: *mut u8, layout: Layout, size: usize) -> *mut u8 {
        let next = unsafe { System.realloc(ptr, layout, size) };
        if !next.is_null() {
            if size >= layout.size() {
                add(size - layout.size());
            } else {
                LIVE.fetch_sub(layout.size() - size, Relaxed);
            }
        }
        next
    }
}

/// Alternate invocation: --writer-memory DICTIONARY OUTPUT INPUT... [--optimal] [--horizon]
/// Input buffers and entry metadata remain alive throughout the measured call.
/// Each invocation measures one cold writer in a fresh process. Pool startup
/// belongs to the writer measurement, as do its returned archive allocations.
pub fn run(args: &[String]) {
    let dictionary: u64 = args[2].parse().expect("dictionary in bytes");
    let output = &args[3];
    let optimal = args.iter().any(|s| s == "--optimal");
    let horizon = args.iter().any(|s| s == "--horizon");
    let paths: Vec<_> = args[4..]
        .iter()
        .filter(|s| *s != "--optimal" && *s != "--horizon")
        .collect();
    assert!(!paths.is_empty(), "at least one input is required");
    let names: Vec<_> = paths
        .iter()
        .map(|p| {
            std::path::Path::new(p)
                .file_name()
                .unwrap()
                .to_string_lossy()
                .into_owned()
        })
        .collect();
    let data: Vec<_> = paths
        .iter()
        .map(|p| std::fs::read(p).expect("read input"))
        .collect();
    let entries: Vec<_> = names
        .iter()
        .zip(&data)
        .map(|(name, data)| CompressedEntry {
            name: name.as_bytes(),
            data,
            mtime: None,
            attributes: 0,
            host_os: 3,
        })
        .collect();
    let input_bytes: usize = data.iter().map(Vec::len).sum();
    let input_capacity: usize = data.iter().map(Vec::capacity).sum();
    let options = WriterOptions::new(ArchiveVersion::Rar50, FeatureSet::default())
        .with_dictionary_size(dictionary)
        .with_optimal_parse(optimal)
        .with_tokenizer_horizon_choice(horizon);
    let baseline = LIVE.load(Relaxed);
    PEAK.store(baseline, Relaxed);
    let encoded = Rar50Writer::new(options)
        .compressed_entries(&entries)
        .finish()
        .expect("writer");
    let peak = PEAK.load(Relaxed);
    let retained = LIVE.load(Relaxed);
    // The measurement ends before file output, formatting or verification.
    std::fs::write(output, &encoded).expect("write archive for external unrar t");
    println!("WRITER_MEMORY dictionary={dictionary} optimal={optimal} horizon={horizon} members={} input_bytes={input_bytes} input_capacity={input_capacity} baseline_live={baseline} peak_live={peak} writer_peak_delta={} writer_retained_delta={} output_bytes={} output_capacity={}",
        entries.len(), peak.saturating_sub(baseline), retained.saturating_sub(baseline), encoded.len(), encoded.capacity());
}
