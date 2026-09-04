//! Directory entries must come out of extraction as directories, never as
//! zero-byte files.
//!
//! `tests/fixtures/rar50/dir_entry.rar` is real `rar a -m3` output for a
//! directory `small/` holding three compressed members, so the set carries a
//! directory entry alongside its members (the directory header trails the
//! members, as rar emits it). The three members are pool-eligible, so with
//! `--features parallel` the same fixture drives the member-pool plan;
//! without it, the serial path. Usenet payloads are almost always flat,
//! which is how a driver that ignored `is_directory` survived: it
//! materialised the entry as a 0-byte file named `small` (colliding with the
//! real directory name), where unrar creates `small/`.

use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};
use std::sync::{Arc, Mutex};

fn fixture() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("tests/fixtures/rar50/dir_entry.rar")
}

/// Every entry the extractor surfaces: (is_directory, bytes written to it).
fn extract_collect() -> BTreeMap<String, (bool, Vec<u8>)> {
    let archive = rars::ArchiveReader::read_path(fixture()).expect("parse fixture");
    let entries: Arc<Mutex<BTreeMap<String, (bool, Arc<Mutex<Vec<u8>>>)>>> =
        Arc::default();

    struct Sink(Arc<Mutex<Vec<u8>>>);
    impl Write for Sink {
        fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
            self.0.lock().unwrap().extend_from_slice(buf);
            Ok(buf.len())
        }
        fn flush(&mut self) -> std::io::Result<()> {
            Ok(())
        }
    }

    let volumes = [archive];
    rars::extract_volumes_to(&volumes, None, |meta| {
        let data = Arc::new(Mutex::new(Vec::new()));
        let prior = entries
            .lock()
            .unwrap()
            .insert(meta.name_lossy(), (meta.is_directory, Arc::clone(&data)));
        assert!(prior.is_none(), "entry surfaced twice: {}", meta.name_lossy());
        Ok(Box::new(Sink(data)) as Box<dyn Write>)
    })
    .expect("extract fixture");

    Arc::try_unwrap(entries)
        .expect("no writer outlives extraction")
        .into_inner()
        .unwrap()
        .into_iter()
        .map(|(name, (is_dir, data))| (name, (is_dir, data.lock().unwrap().clone())))
        .collect()
}

#[test]
fn directory_entry_is_flagged_and_carries_no_data() {
    let entries = extract_collect();
    let names: Vec<&str> = entries.keys().map(String::as_str).collect();
    assert_eq!(
        names,
        ["small", "small/member0.txt", "small/member1.txt", "small/member2.txt"]
    );

    let (is_dir, data) = &entries["small"];
    assert!(is_dir, "directory entry must surface with is_directory=true");
    assert!(data.is_empty(), "directory entry must receive no payload bytes");

    for member in ["small/member0.txt", "small/member1.txt", "small/member2.txt"] {
        let (is_dir, data) = &entries[member];
        assert!(!is_dir, "{member} is a file");
        assert_eq!(data.len(), 32000, "{member} decodes fully");
    }
}

/// A driver that honours `is_directory` (create the directory, sink the
/// writer) produces the unrar layout on disk: members under `small/`, no
/// stray file named `small`.
#[test]
fn directory_aware_driver_matches_unrar_layout() {
    let outdir = std::env::temp_dir().join(format!(
        "rars-dir-entry-{}-{}",
        std::process::id(),
        if cfg!(feature = "parallel") { "par" } else { "ser" }
    ));
    let _ = std::fs::remove_dir_all(&outdir);
    std::fs::create_dir_all(&outdir).unwrap();

    let archive = rars::ArchiveReader::read_path(fixture()).expect("parse fixture");
    let volumes = [archive];
    rars::extract_volumes_to(&volumes, None, |meta| {
        let mut path = outdir.clone();
        path.extend(
            meta.name_lossy()
                .split(['/', '\\'])
                .filter(|part| !part.is_empty() && *part != "." && *part != ".."),
        );
        if meta.is_directory {
            std::fs::create_dir_all(&path)?;
            return Ok(Box::new(std::io::sink()) as Box<dyn Write>);
        }
        if let Some(parent) = path.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Box::new(std::fs::File::create(path)?) as Box<dyn Write>)
    })
    .expect("extract fixture");

    let small = outdir.join("small");
    assert!(small.is_dir(), "`small` must be a directory, not a 0-byte file");
    for member in ["member0.txt", "member1.txt", "member2.txt"] {
        let path = small.join(member);
        assert_eq!(
            std::fs::metadata(&path).unwrap_or_else(|_| panic!("{member} missing")).len(),
            32000
        );
    }
    assert_eq!(
        std::fs::read_dir(&outdir).unwrap().count(),
        1,
        "nothing extracts beside the `small` directory"
    );

    let _ = std::fs::remove_dir_all(&outdir);
}
