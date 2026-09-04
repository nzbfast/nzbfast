//! The `parfast` binary: argv in, exit code out.
//!
//! Everything is in the library so the unit tests can drive a run
//! without building and shelling out to a binary - the exact text of
//! these lines is what this crate is for, and a test that can only see
//! it through a process boundary is a slower test that proves less.

use std::process::ExitCode;

fn main() -> ExitCode {
    let mut argv = std::env::args();
    // argv[0] selects the command for the `par2create` / `par2verify` /
    // `par2repair` spellings, which scripts invoke by name.
    let argv0 = argv.next().unwrap_or_else(|| "parfast".to_string());
    let args: Vec<String> = argv.collect();
    ExitCode::from(parfast::run(&argv0, &args))
}
