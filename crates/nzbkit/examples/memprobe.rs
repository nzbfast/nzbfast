//! Prints the detected cgroup memory limit and the resolved budget
//! ladder. Used to verify container-limit clamping: run inside
//! `docker run --memory 1g` and expect limit ≈ 1 GiB, budget = half.
//!
//! Pass a size to inspect an explicit `--mem-limit` instead of the auto
//! budget - `cargo run --example memprobe -- 8G`. That arm exists for
//! 32-bit hosts (armv7 Raspberry Pi OS): every cap below is `usize`, so
//! a budget the pointer width cannot hold used to truncate on the way
//! out and the ladder printed here is the only place that is visible.
//! Sizes accept a K/M/G suffix; a bare number is bytes.

fn parse_size(s: &str) -> Option<u64> {
    let s = s.trim();
    let (num, mul) = match s.chars().last()?.to_ascii_uppercase() {
        'K' => (&s[..s.len() - 1], 1u64 << 10),
        'M' => (&s[..s.len() - 1], 1u64 << 20),
        'G' => (&s[..s.len() - 1], 1u64 << 30),
        _ => (s, 1),
    };
    num.trim().parse::<u64>().ok()?.checked_mul(mul)
}

fn main() {
    let gb = |b: u64| b as f64 / (1u64 << 30) as f64;
    let mb = |b: usize| b as f64 / (1usize << 20) as f64;
    println!("target_pointer_width: {}", usize::BITS);
    println!("physical_ram: {:?} GB", nzbkit::mem::physical_ram().map(gb));
    println!(
        "available_ram: {:?} GB ({:?} bytes)",
        nzbkit::mem::available_ram().map(gb),
        nzbkit::mem::available_ram()
    );
    // The same reading `available_ram` returns on a Mac since 16 Sep 2026,
    // printed separately because it is macOS-only (TODO 345 D).
    #[cfg(target_os = "macos")]
    println!(
        "vm_available_ram: {:?} GB ({:?} bytes)",
        nzbkit::mem::vm_available_ram().map(gb),
        nzbkit::mem::vm_available_ram()
    );
    println!(
        "cgroup_mem_limit: {:?} GB",
        nzbkit::mem::cgroup_mem_limit().map(gb)
    );

    let arg = std::env::args().nth(1);
    let budget = match arg.as_deref() {
        Some(a) => {
            let want = parse_size(a).unwrap_or_else(|| {
                eprintln!("could not parse size {a:?} - try 8G, 512M, or a byte count");
                std::process::exit(2);
            });
            println!("requested --mem-limit: {:.2} GB", gb(want));
            nzbkit::mem::MemBudget::with_total(want)
        }
        None => nzbkit::mem::MemBudget::auto(),
    };

    println!(
        "resolved budget: {:.2} GB ({} bytes)",
        gb(budget.total),
        budget.total
    );
    // Every line below is a `usize` on the way out. On a 32-bit target a
    // resolved budget above the address-space ceiling would make these
    // disagree with the budget above - which is the failure this probe
    // exists to make visible rather than infer.
    println!(
        "  holds_cap     (extractor spill): {:8.1} MB",
        mb(budget.holds_cap())
    );
    println!(
        "  partials_cap  (verifier spill):  {:8.1} MB",
        mb(budget.partials_cap())
    );
    println!(
        "  bufpool_bufs  (~800 KB each):    {:8}",
        budget.bufpool_bufs()
    );
    println!(
        "  channel_depth (~800 KB each):    {:8}",
        budget.channel_depth()
    );
    println!(
        "  inflight_cap  (wire bodies):     {:8.1} MB",
        mb(budget.inflight_cap() as usize)
    );
    println!(
        "  repair_cap    (RAR recovery):    {:8.1} MB",
        mb(budget.repair_cap() as usize)
    );
    println!("concurrency_caps: {:?}", nzbkit::mem::concurrency_caps());
}
