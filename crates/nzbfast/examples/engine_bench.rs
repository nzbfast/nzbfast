//! Standalone harness to time our PAR2 repair and RAR extraction engines
//! against external tools on identical on-disk sets. Dev-only; not shipped.
//!
//!   engine_bench repair  <dir>          - PAR2 verify+repair via nzbkit::par2repair::repair_dir
//!   engine_bench verify  <dir>          - PAR2 parse+verify via nzbkit::par2 (whole-file read)
//!   engine_bench extract <dir> <first>  - rars volume-set extraction (same path as the daemon)

use std::path::{Path, PathBuf};
use std::time::Instant;

fn main() -> anyhow::Result<()> {
    let args: Vec<String> = std::env::args().collect();
    let cmd = args.get(1).map(String::as_str).unwrap_or("");
    let dir = PathBuf::from(args.get(2).map(String::as_str).unwrap_or("."));
    let t0 = Instant::now();
    match cmd {
        "repair" => {
            let status = nzbkit::par2repair::repair_dir(&dir)?;
            println!("repair_dir status: {status:?}");
        }
        "verify" => {
            let mut par2_bytes: Vec<Vec<u8>> = Vec::new();
            for entry in std::fs::read_dir(&dir)? {
                let path = entry?.path();
                if path
                    .extension()
                    .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
                {
                    par2_bytes.push(std::fs::read(&path)?);
                }
            }
            let refs: Vec<&[u8]> = par2_bytes.iter().map(|v| v.as_slice()).collect();
            // Every set in the directory, not one. This read every
            // `.par2` in `dir` into ONE `Par2Set::parse`, which refuses
            // the whole input the moment two of them carry different
            // recovery-set ids - so on a per-file-set directory (GH
            // #63's shape) this harness bailed with `MixedRecoverySets`
            // and timed nothing at all. The third surface of TODO 311's
            // defect, after `unpack::verify_dir` and
            // `preflight::probe_par2_sets`; it is dev-only, which is
            // why it went unnoticed and not why it is left.
            let sets = nzbkit::live::pick_sets(&refs)?;
            let mut bad_total = 0usize;
            let mut files = 0usize;
            for set in &sets {
                files += set.files.len();
                for f in &set.files {
                    let path = dir.join(nzbkit::disk::sanitize_filename(&f.name));
                    match std::fs::read(&path) {
                        Ok(data) => {
                            let v = nzbkit::par2::verify_file(f, set.block_size, &data);
                            bad_total += v.blocks.iter().filter(|ok| !**ok).count();
                        }
                        Err(_) => bad_total += 1,
                    }
                }
            }
            println!(
                "verify: {} set(s), {files} file(s), {bad_total} bad block(s)/missing",
                sets.len()
            );
        }
        "extract" => {
            let first = PathBuf::from(args.get(3).expect("extract needs <first-volume>"));
            extract_volumes(&dir, &first)?;
        }
        other => anyhow::bail!("unknown command {other:?}"),
    }
    println!("elapsed: {:.3}s", t0.elapsed().as_secs_f64());
    Ok(())
}

fn extract_volumes(dir: &Path, first: &Path) -> anyhow::Result<()> {
    use nzbkit::extract::{release_stem, vol_sort_key};
    let first_name = first
        .file_name()
        .unwrap_or_default()
        .to_string_lossy()
        .to_string();
    // Lowercased to match the `name` side below - see `stem_volume_set`.
    let stem = release_stem(&first_name.to_lowercase());
    let mut volumes: Vec<PathBuf> = Vec::new();
    for entry in std::fs::read_dir(dir)? {
        let path = entry?.path();
        let name = path
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_lowercase();
        let by_name = name.ends_with(".rar")
            || (name.rfind('.').is_some_and(|p| {
                let t = &name[p + 1..];
                t.len() >= 3 && t.starts_with('r') && t[1..].bytes().all(|c| c.is_ascii_digit())
            }));
        if by_name && release_stem(&name) == stem {
            volumes.push(path);
        }
    }
    volumes
        .sort_by_cached_key(|p| vol_sort_key(&p.file_name().unwrap_or_default().to_string_lossy()));
    anyhow::ensure!(!volumes.is_empty(), "no volumes for {first_name}");
    let archives = volumes
        .iter()
        .map(rars::ArchiveReader::read_path)
        .collect::<Result<Vec<_>, _>>()
        .map_err(|e| anyhow::anyhow!("parsing volumes: {e}"))?;
    let out = dir.join("extracted");
    std::fs::create_dir_all(&out)?;
    rars::extract_volumes_to(&archives, None, |meta| {
        let target = out.join(meta.name_lossy());
        if meta.is_directory {
            std::fs::create_dir_all(&target)?;
            return Ok(Box::new(std::io::sink()) as Box<dyn std::io::Write>);
        }
        if let Some(parent) = target.parent() {
            std::fs::create_dir_all(parent)?;
        }
        Ok(Box::new(std::io::BufWriter::new(std::fs::File::create(
            target,
        )?)))
    })
    .map_err(|e| anyhow::anyhow!("{e}"))?;
    println!(
        "extracted {} volume set to {}",
        volumes.len(),
        out.display()
    );
    Ok(())
}
