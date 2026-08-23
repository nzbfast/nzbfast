//! Extraction shootout contestant that is provably the PRODUCT path.
//!
//! `vendor/rars/examples/ourrars` calls `rars::extract_volumes_to`, which
//! attaches no execution policy: no worker cap, and `member_flat_limit`
//! falls back to rars' built-in buffered cap, so a gigabyte-sized member
//! is refused the flat plan and runs the bounded ring instead. Every real
//! entry point (crates/nzbkit/src/extract/chase.rs, which took the RAR
//! chase when the extract module was split, and
//! crates/nzbfast/src/main.rs) goes through
//! `nzbkit::mem::rar_read_options`, which attaches the
//! process budget's policy - on a large host that is a 6 GiB working-memory
//! allowance and 8+ workers. Benchmarking `ourrars` therefore measures a
//! configuration nobody ships.
//!
//! This driver takes the same options object the daemon does, so its times
//! describe what a user actually gets.
//!
//!   prodrar <voldir> <outdir> [password]

use std::io::Write;
use std::path::PathBuf;

fn main() {
    let mut args = std::env::args().skip(1);
    let dir = PathBuf::from(
        args.next()
            .expect("usage: prodrar <voldir> <outdir> [password]"),
    );
    let out = PathBuf::from(args.next().expect("need an output directory"));
    let password = args.next();

    // Publish a budget exactly as the daemon does at startup, so
    // rar_read_options resolves the same policy it would in production.
    // PRODRAR_BUDGET (bytes) overrides the resolved budget so a run can be
    // pinned to a specific execution policy; unset means auto, i.e. exactly
    // what the daemon resolves on this host.
    let budget = std::env::var("PRODRAR_BUDGET")
        .ok()
        .and_then(|v| v.parse::<u64>().ok())
        .map(nzbkit::mem::MemBudget::with_total)
        .unwrap_or_else(nzbkit::mem::MemBudget::auto);
    eprintln!("budget {} MiB", budget.total >> 20);
    nzbkit::mem::set_process_budget(budget);

    let mut vols: Vec<PathBuf> = std::fs::read_dir(&dir)
        .expect("read volume dir")
        .filter_map(|e| e.ok().map(|e| e.path()))
        .filter(|p| p.extension().is_some_and(|x| x == "rar"))
        .collect();
    vols.sort();
    // One options value for both the parse and the extract, so the policy
    // is attached on every step the daemon attaches it on.
    let options = nzbkit::mem::rar_read_options(password.as_deref().map(str::as_bytes));
    let archives: Vec<_> = vols
        .iter()
        .map(|p| rars::ArchiveReader::read_path_with_options(p, options).expect("open volume"))
        .collect();

    std::fs::create_dir_all(&out).expect("create output dir");
    rars::extract_volumes_to_with_options(&archives, options, |meta| {
        let raw = meta.name_lossy();
        let name = std::path::Path::new(&raw)
            .file_name()
            .map(|n| n.to_owned())
            .unwrap_or_else(|| raw.clone().into());
        let path = out.join(name);
        // Plain File, exactly as vendor/rars/examples/ourrars does: an
        // extra BufWriter here would copy every byte a second time and
        // make this driver measure the harness, not the extractor.
        Ok(Box::new(std::fs::File::create(&path)?) as Box<dyn Write>)
    })
    .expect("extract");
}
