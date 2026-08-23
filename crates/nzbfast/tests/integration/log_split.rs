//! The CLI's log writer is level-split: WARN and ERROR go to stderr,
//! INFO to stdout. That is what lets `nzbfast probe > out.txt` capture
//! the report without its complaints, exactly as the `println!` /
//! `eprintln!` pair it replaced did.
//!
//! From the day §80 shipped (2 Aug 2026) until 22 Aug 2026 the split was
//! dead: `stdout.with_max_level(Level::INFO)` is in tracing's VERBOSITY
//! order, where ERROR is the smallest level, so the stdout arm took
//! INFO, WARN and ERROR and the stderr arm chained behind it never saw a
//! line. No test noticed, because the e2e suite concatenates stdout and
//! stderr before it looks. This one captures the two streams separately
//! and pins each line to its side.
//!
//! The command is `nzbfast extract` on a directory holding a real RAR
//! under a hash name (the obfuscated sniff claims it and announces the
//! set at INFO) beside a truncated `Rar!`-magic file (which the sniff
//! also claims and then cannot parse, so it is skipped at WARN). One
//! process, one line of each level, deterministic.

use std::path::Path;
use std::process::Command;

#[test]
fn warn_goes_to_stderr_and_info_to_stdout() {
    let dir = std::env::temp_dir().join(format!("nzbfast-logsplit-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();

    let arch = std::fs::read(
        Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../../vendor/rars/tests/fixtures/rar50/m3_default.rar"),
    )
    .unwrap();
    std::fs::write(dir.join("a91f3c0d77b2e4"), &arch).unwrap();
    // RAR5 signature and nothing after it: magic-sniffed as a volume,
    // unparseable as one.
    std::fs::write(dir.join("b72e0c19d4a6f3"), &arch[..8]).unwrap();

    let out = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .arg("extract")
        .arg(&dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .env_remove("RUST_LOG")
        .env_remove("NZBFAST_LOG")
        .output()
        .unwrap();
    let stdout = String::from_utf8_lossy(&out.stdout);
    let stderr = String::from_utf8_lossy(&out.stderr);
    let _ = std::fs::remove_dir_all(&dir);

    let skipping = "[extract] skipping ";
    let unpacking = "[extract] unpacking 1 obfuscated RAR set";
    assert!(
        stderr.contains(skipping),
        "the skip warning must reach stderr\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stdout.contains(skipping),
        "the skip warning must not ALSO land on stdout\nstdout:\n{stdout}"
    );
    assert!(
        stdout.contains(unpacking),
        "the set announcement must reach stdout\nstdout:\n{stdout}\nstderr:\n{stderr}"
    );
    assert!(
        !stderr.contains(unpacking),
        "the set announcement must not land on stderr\nstderr:\n{stderr}"
    );
}
