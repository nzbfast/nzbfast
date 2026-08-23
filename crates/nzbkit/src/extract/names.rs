//! File-naming rules for posted release files: the shared stem a whole
//! set reduces to, the volume sort order, and the "this container IS the
//! deliverable" extension guard. Pure functions over names - no extractor
//! state - moved out of `extract/mod.rs` bodily so that file stays inside
//! its size-gate baseline (TODO 106 pattern; re-exported from `mod.rs`,
//! so every `nzbkit::extract::release_stem` caller is unchanged).

/// Strip release-file suffixes down to the shared stem:
/// `x.part01.rar`/`x.r00`/`x.vol000+01.par2`/`x.par2`/`x.rar` → `x`,
/// and split-container volumes `x.7z.001`/`x.zip.001` → `x.7z`/`x.zip`
/// (the container extension stays: it is the shared base every part
/// and its par2 sidecar reduce to, mirroring `sevenz_part_name`).
///
/// The split rule exists because without it a 100-part obfuscated 7z
/// set indexes as 100 half-GB "releases" - found live 2 Aug 2026 via
/// the Supergirl acceptance case (122 rows, 67 GB) - which hides the
/// set's true size from everything that reasons about it.
pub fn release_stem(name: &str) -> String {
    let lower = name.to_ascii_lowercase();
    let mut end = lower.len();
    let cut = |s: &str, end: usize, f: &dyn Fn(&str) -> Option<usize>| -> usize {
        f(&s[..end]).unwrap_or(end)
    };
    end = cut(&lower, end, &|s| s.strip_suffix(".par2").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        // par2cmdline "vol01+02", range-style "vol001-003", or the
        // bare-ordinal "vol-01". One rule, shared with the deferral
        // classifier in nzb::kind() - this cut and that classifier
        // drifted apart once (both missing `.vol-NN`), which left the
        // ordinal on the stem and shattered the release in the index.
        crate::nzb::par2_vol_suffix(s)
    });
    end = cut(&lower, end, &|s| {
        // Split-container volume: 3-4 digit tail (7-Zip names volumes
        // `%s.%03d`, four digits past 999 - same bounds as
        // `sevenz_part_name`) directly after a container extension.
        // One and two digits stay: `Track.01` is somebody's music.
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        if tail.len() < 3 || tail.len() > 4 || !tail.bytes().all(|c| c.is_ascii_digit()) {
            return None;
        }
        let head = &s[..p];
        (head.ends_with(".7z") || head.ends_with(".zip")).then_some(p)
    });
    end = cut(&lower, end, &|s| s.strip_suffix(".rar").map(|r| r.len()));
    end = cut(&lower, end, &|s| {
        let p = s.rfind(".part")?;
        let tail = &s[p + 5..];
        (!tail.is_empty() && tail.bytes().all(|c| c.is_ascii_digit())).then_some(p)
    });
    end = cut(&lower, end, &|s| {
        let p = s.rfind('.')?;
        let tail = &s[p + 1..];
        // Old-style continuations roll past .r99 into .s00 … .z99 (and
        // vol_sort_key already orders that whole range) - accepting only
        // r/s here left .t00+ volumes with their extension in the stem,
        // splitting 200+ volume sets across "releases" and starving the
        // repair path's stem filter of everything past .s99.
        (tail.len() >= 2
            && (b'r'..=b'z').contains(&tail.as_bytes()[0])
            && tail[1..].bytes().all(|c| c.is_ascii_digit()))
        .then_some(p)
    });
    name[..end].to_string()
}

/// Extensions whose bytes ARE a RAR or 7z container but whose file is
/// the deliverable: `.cbr` is a comic wearing a RAR wrapper, `.cb7` its
/// 7-Zip twin. Unpacking one is data loss, not extraction - the user
/// asked for the comic, not a folder of loose pages (GitHub issue #40).
/// The zip family's counterpart list (`.cbz`, `.epub`, office files)
/// lives in `zip::FINAL_FILE_EXTS`; the same standing rule applies here:
/// the guard keys on the NAMED extension only, so an obfuscated post
/// (hash names, no meaningful extension) still earns the magic sniff.
const FINAL_FILE_EXTS: &[&str] = &["cbr", "cb7"];

/// A RAR/7z-container file whose extension marks it as the payload
/// itself. Never unpack one - and never let a sweep count it as a spent
/// volume or nested layer.
pub fn is_final_file(path: &std::path::Path) -> bool {
    path.file_name()
        .is_some_and(|n| is_final_name(&n.to_string_lossy()))
}

/// [`is_final_file`] over a bare file name (any case).
pub fn is_final_name(name: &str) -> bool {
    std::path::Path::new(name)
        .extension()
        .is_some_and(|e| FINAL_FILE_EXTS.contains(&&*e.to_string_lossy().to_ascii_lowercase()))
}

/// Natural volume order key: `.rar` < `.r00` < `.r01`; `.part1` < `.part2`.
pub fn vol_sort_key(name: &str) -> (u64, String) {
    let lower = name.to_ascii_lowercase();
    if let Some(p) = lower.rfind(".part") {
        let tail = &lower[p + 5..];
        let digits: String = tail.chars().take_while(|c| c.is_ascii_digit()).collect();
        if let Ok(n) = digits.parse::<u64>() {
            return (n, lower.clone());
        }
    }
    if lower.ends_with(".rar") {
        return (0, lower.clone());
    }
    if let Some(p) = lower.rfind('.') {
        let tail = &lower[p + 1..];
        // Old-style continuations roll the letter past .r99: .s00 = 101,
        // .t00 = 201… (each letter is another 10^digits volumes). Keying
        // only 'r' broke base-resolution at the r→s boundary on 100+
        // volume sets.
        if tail.len() >= 2
            && (b'r'..=b'z').contains(&tail.as_bytes()[0])
            && let Ok(n) = tail[1..].parse::<u64>()
        {
            let span = 10u64.pow((tail.len() - 1) as u32);
            return (
                (tail.as_bytes()[0] - b'r') as u64 * span + n + 1,
                lower.clone(),
            );
        }
        // WinRAR numeric volume naming: .001, .002 …
        if tail.len() >= 2
            && tail.bytes().all(|c| c.is_ascii_digit())
            && let Ok(n) = tail.parse::<u64>()
        {
            return (n, lower.clone());
        }
    }
    (u64::MAX, lower)
}
