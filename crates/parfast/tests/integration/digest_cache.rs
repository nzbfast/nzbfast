//! `--digest-cache` through the real binary, in child processes so the
//! per-user store can be pointed at a scratch home without touching this
//! process's environment: no store without the flag, one record on first
//! use, a validated hit on the repeat create and on a `--slow` verify, the
//! same set bytes on every run, and a damaged member that never answers
//! from its record. The engine half (every scan arm, stale and torn
//! records, cancel) is pinned in `nzbkit-base`'s unit tests.

use std::path::{Path, PathBuf};
use std::process::Command;

use crate::scratch::scratch;

/// Run parfast with `home` as the account's home and cache folder, the
/// cache floor at zero and the create forced onto the fused single pass
/// (the 8.86 GB single-file shape the cache exists for).
fn parfast(home: &Path, args: &[&Path]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(args)
        .env("HOME", home)
        .env("LOCALAPPDATA", home)
        .env_remove("XDG_CACHE_HOME")
        .env("NZBFAST_DIGEST_CACHE_FLOOR", "0")
        .env("NZBFAST_PAR2GEN_FUSE", "1")
        .env("NZBFAST_REPAIR_TIMING", "1")
        .output()
        .expect("run parfast");
    let text = format!(
        "{}{}",
        String::from_utf8_lossy(&out.stdout),
        String::from_utf8_lossy(&out.stderr)
    );
    (out.status.code().unwrap_or(-1), text)
}

fn store(home: &Path) -> PathBuf {
    if cfg!(target_os = "macos") {
        home.join("Library")
            .join("Caches")
            .join("parfast")
            .join("digests")
    } else if cfg!(windows) {
        home.join("parfast").join("digests")
    } else {
        home.join(".cache").join("parfast").join("digests")
    }
}

fn records(home: &Path) -> usize {
    std::fs::read_dir(store(home)).map_or(0, |rd| {
        rd.flatten()
            .filter(|e| e.file_name().to_string_lossy().ends_with(".pfd"))
            .count()
    })
}

/// Every file of the set named `base`, keyed by its name with the base
/// taken off.
fn set_files(dir: &Path, base: &str) -> Vec<(String, Vec<u8>)> {
    let mut files: Vec<(String, Vec<u8>)> = std::fs::read_dir(dir)
        .expect("dir")
        .flatten()
        .filter_map(|e| {
            let name = e.file_name().to_string_lossy().into_owned();
            let rest = name.strip_prefix(base)?;
            (rest.starts_with('.') && rest.ends_with(".par2"))
                .then(|| (rest.to_string(), std::fs::read(e.path()).expect("read")))
        })
        .collect();
    files.sort();
    files
}

#[test]
fn the_digest_cache_enrols_then_answers_and_never_changes_a_set() {
    let dir = scratch("digest-cache");
    let home = dir.join("home");
    std::fs::create_dir_all(&home).expect("home");
    let data_path = dir.join("payload.bin");
    let mut data: Vec<u8> = (0..(12u32 << 20))
        .map(|i| (i.wrapping_mul(2654435761) >> 13) as u8)
        .collect();
    std::fs::write(&data_path, &data).expect("payload");
    let c = |base: &str, cache: bool| -> Vec<PathBuf> {
        let mut a: Vec<PathBuf> = vec!["c".into(), "-q".into(), "-s1048576".into(), "-c3".into()];
        if cache {
            a.push("--digest-cache".into());
        }
        a.push(dir.join(format!("{base}.par2")));
        a.push(data_path.clone());
        a
    };
    let run = |args: Vec<PathBuf>| {
        let refs: Vec<&Path> = args.iter().map(PathBuf::as_path).collect();
        parfast(&home, &refs)
    };

    let (code, out) = run(c("plain", false));
    assert_eq!(code, 0, "{out}");
    assert!(!store(&home).exists(), "no flag, no store");

    let (code, out) = run(c("enrol", true));
    assert_eq!(code, 0, "{out}");
    assert_eq!(records(&home), 1, "{out}");

    let (code, out) = run(c("hit", true));
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("digest-cache payload.bin: hit"), "{out}");
    let plain = set_files(&dir, "plain");
    assert!(!plain.is_empty());
    assert!(
        plain == set_files(&dir, "enrol"),
        "enrolling changed the set"
    );
    assert!(
        plain == set_files(&dir, "hit"),
        "a validated digest changed the set"
    );

    let verify = |cache: bool| {
        let mut a: Vec<PathBuf> = vec!["v".into(), "--slow".into()];
        if cache {
            a.push("--digest-cache".into());
        }
        a.push(dir.join("hit.par2"));
        run(a)
    };
    let (code, out) = verify(true);
    assert_eq!(code, 0, "{out}");
    assert!(out.contains("digest-cache payload.bin: hit"), "{out}");

    data[6_000_000] ^= 0x42;
    {
        use std::io::{Seek, SeekFrom, Write};
        let mut w = std::fs::File::options()
            .write(true)
            .open(&data_path)
            .expect("reopen");
        w.seek(SeekFrom::Start(6_000_000)).expect("seek");
        w.write_all(&data[6_000_000..6_000_001]).expect("poke");
    }
    let (code, out) = verify(true);
    assert_ne!(code, 0, "a damaged member verified: {out}");
    assert!(
        !out.contains(": hit"),
        "a damaged member answered from its record: {out}"
    );
    let (plain_code, _) = verify(false);
    assert_eq!(code, plain_code, "the cache changed the damaged verdict");
}
