//! What the read-side cache policy decides for a path, printed.
//!
//! `cargo run --release -p nzbkit --example readpolicy_probe -- PATH...`
//!
//! Built for the round behind `crates/nzbkit-base/src/disk/readpolicy.rs`
//! (claim par2-pagecache-policy), which has to answer two questions a
//! timed leg cannot:
//!
//! * does the device probe classify a real SMB/NFS mount as `Network`,
//!   on the box where that mount actually exists - the policy's whole
//!   network arm is a STAND-DOWN, and a stand-down that never fires
//!   because the probe reads `Unknown` is indistinguishable from one
//!   that works;
//! * which arm a given member size selects on THIS machine's RAM, which
//!   is what the floor is expressed in.
//!
//! Prints the class, the length, and the two hints, one line per path,
//! plus `direct=` since TODO 325 (4 Sep 2026) - whether the class came
//! off the filesystem's own device or had to be resolved through the
//! mount table, which is the difference the decode-worker clamp and the
//! spill governor read. On an anonymous-device filesystem (btrfs, ZFS)
//! that column is what says the fallback fired at all.
//!
//! `NZBFAST_READ_HINTS` and `NZBFAST_READ_HINT_MIN_MB` are honoured, so
//! the same binary shows both arms of the A/B.
fn main() {
    let mut args = std::env::args().skip(1).peekable();
    if args.peek().is_none() {
        eprintln!("usage: readpolicy_probe PATH...");
        std::process::exit(2);
    }
    for a in args {
        let p = std::path::Path::new(&a);
        let len = std::fs::metadata(p).map(|m| m.len()).unwrap_or(0);
        let class = nzbkit::disk::device_class(p);
        // Unmemoised on purpose, unlike `device_class` above: this line
        // is the instrument for the probe itself, and the memo would
        // hand back a neighbouring path's answer.
        let probe = nzbkit::disk::probe_storage(p);
        let h = nzbkit::disk::hints_for_path(p, len);
        println!(
            "{a}\tclass={class:?}\tdirect={}\tlen={len}\tsequential={}\tdrop_behind={}",
            u8::from(probe.direct_dev),
            u8::from(h.sequential),
            u8::from(h.drop_behind)
        );
    }
}
