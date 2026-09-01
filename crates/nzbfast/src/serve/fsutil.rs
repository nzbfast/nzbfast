//! Filesystem helpers the settings and browse surfaces need: import-file
//! reading, writability probes, category destination lists, the root
//! listing, and the largest-media-file search.
//!
//! Split out of serve/mod.rs by TODO 106 phase 4 - the code is verbatim,
//! only visibility changed.

use super::*;

/// Read a candidate SABnzbd/NZBGet config for import. The path is
/// caller-supplied, so refuse non-regular files (/dev/zero, FIFOs) and
/// anything implausibly large before slurping it into RAM.
pub(super) fn read_import_config(path: &std::path::Path) -> std::io::Result<String> {
    const CAP: u64 = 4 * 1024 * 1024;
    let meta = std::fs::metadata(path)?;
    if !meta.is_file() || meta.len() > CAP {
        return Err(std::io::Error::new(
            std::io::ErrorKind::InvalidData,
            "not a config file",
        ));
    }
    std::fs::read_to_string(path)
}

/// Open a path with the OS default handler ON THE DAEMON'S MACHINE (the
/// dashboard's Play / Show-in-folder actions - the normal local setup).
pub(super) fn os_open(path: &std::path::Path) -> bool {
    #[cfg(target_os = "macos")]
    let mut cmd = std::process::Command::new("open");
    #[cfg(all(unix, not(target_os = "macos")))]
    let mut cmd = std::process::Command::new("xdg-open");
    // Windows: explorer, NOT `cmd /C start` - cmd re-parses its command
    // line, so metacharacters (&, ^, %) in a path would execute. These
    // paths derive from release names, which arrive in NZBs.
    #[cfg(windows)]
    let mut cmd = std::process::Command::new("explorer");
    let opened = cmd
        .arg(path)
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .spawn()
        .is_ok();
    // On Windows that window opens BEHIND the browser the user clicked
    // in, and only a foreground-lock bypass gets it in front (TODO 204,
    // `winfront`). Folders only: the other caller here plays a media
    // file, and the window that appears then belongs to whatever the
    // user's default player is, with a title we cannot predict.
    #[cfg(windows)]
    if opened && path.is_dir() {
        super::winfront::raise_folder_soon(path.to_path_buf());
    }
    opened
}

/// Can the daemon actually write into this directory? Shown next to the
/// download-folder picker so the user learns a chosen location is
/// read-only BEFORE a download fails there.
pub(super) fn path_writable(p: &std::path::Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::ffi::OsStrExt;
        match std::ffi::CString::new(p.as_os_str().as_bytes()) {
            // SAFETY: `c` is a live `CString` for the duration of the
            // call, so the pointer is a valid NUL-terminated path;
            // access(2) only reads it and returns an int.
            Ok(c) => (unsafe { libc::access(c.as_ptr(), libc::W_OK) }) == 0,
            Err(_) => false,
        }
    }
    #[cfg(not(unix))]
    {
        p.metadata()
            .map(|m| !m.permissions().readonly())
            .unwrap_or(false)
    }
}

/// Prove a destination accepts writes by DOING one: create and remove a
/// uniquely named marker directory inside `p`.
///
/// `path_writable` above asks `access(2)`, which consults permission
/// bits - and permission bits are not the only gatekeeper. On 7 Aug
/// 2026 macOS denied the daemon every actual write to an SMB share
/// (per-process network-volume consent) while `access` kept saying
/// yes, so the setting was accepted and the failure surfaced 78 GB
/// later, one finished job at a time. A real write is the only probe
/// that answers the question being asked.
///
/// A directory, not a file: it is exactly what `move_tree` creates
/// first, and it cannot collide with payload names.
pub(super) fn write_probe(p: &std::path::Path) -> std::io::Result<()> {
    let marker = p.join(format!(".nzbfast-write-probe-{}", std::process::id()));
    std::fs::create_dir(&marker)?;
    let _ = std::fs::remove_dir(&marker);
    Ok(())
}

/// A move destination has to be an absolute path.
///
/// `create_dir_all` is perfectly happy to make a relative one, and it
/// lands under the daemon's WORKING DIRECTORY: `/var/lib/nzbfast` under
/// the systemd unit, the container's workdir under Docker, and wherever
/// the launcher happened to be otherwise. Typing `movies/anime` into the
/// settings field therefore created a real directory, passed
/// `path_writable`, passed the `same_dir` check against the download
/// folder, and was stored - and finished downloads were then moved into
/// a folder the user never chose and would not think to look in.
///
/// Refusing is deliberately preferred over resolving it against
/// something ourselves. Every candidate base is a guess (the download
/// root? the config's directory? the home directory?), and a
/// destination the user cannot predict is worse than an error that says
/// what was expected.
///
/// This applies to the MOVE destinations only. `out_dir` and `watch` are
/// left alone on purpose: both are passed relative by the CLI's own
/// defaults (`--out downloads`, `--watch watch`), so cwd-relative is
/// their documented behaviour rather than a trap.
pub(super) fn require_absolute_dest(p: &std::path::Path) -> Result<(), String> {
    if p.is_absolute() {
        return Ok(());
    }
    Err(format!(
        "{} is a relative path - give the full path to the folder, \
         starting from the top of the drive",
        p.display()
    ))
}

/// M33 v2: parse the per-category destination list ("tv=/NAS/TV,
/// movies=/NAS/Movies"; comma or semicolon separated; empty = none).
/// Category names get the same sanitizing the enqueue path applies, so
/// a rule here always matches the folder the job actually used.
pub(super) fn parse_cat_dests(v: &str) -> Result<Vec<(String, PathBuf)>, String> {
    let mut out: Vec<(String, PathBuf)> = Vec::new();
    for item in v.split([',', ';']) {
        let item = item.trim();
        if item.is_empty() {
            continue;
        }
        let Some((cat, path)) = item.split_once('=') else {
            return Err(format!("{item:?} is not category=path"));
        };
        let cat = nzbkit::disk::sanitize_filename(cat.trim());
        let path = path.trim();
        if cat.is_empty() || path.is_empty() {
            return Err(format!("{item:?} is not category=path"));
        }
        if out.iter().any(|(c, _)| *c == cat) {
            return Err(format!("category {cat:?} listed twice"));
        }
        out.push((cat, PathBuf::from(path)));
    }
    Ok(out)
}

/// TODO 317: parse a bare category NAME list ("tv, movies"; comma or
/// semicolon separated; empty = none) into the canonical, deduplicated,
/// order-preserving form.
///
/// Names are sanitized exactly as [`parse_cat_dests`] sanitizes its
/// left-hand side, and for the same reason spelled there: the enqueue
/// path sanitizes the category before it becomes a folder, so a rule
/// written any other way would silently match nothing. Total rather
/// than fallible - a name that sanitizes away is dropped, since the
/// only thing a refusal could protect here is a typo, and refusing the
/// whole list would take the categories that ARE usable down with it.
pub(super) fn parse_cat_names(v: &str) -> Vec<String> {
    let mut out: Vec<String> = Vec::new();
    for item in v.split([',', ';']) {
        let item = item.trim();
        // BEFORE sanitizing, not after: `sanitize_filename` answers an
        // empty string with the literal `unnamed`, so a trailing comma
        // in "tv, movies," would otherwise mint a rule for a category
        // called `unnamed` that the user never typed.
        if item.is_empty() {
            continue;
        }
        let name = nzbkit::disk::sanitize_filename(item);
        if !name.is_empty() && !out.contains(&name) {
            out.push(name);
        }
    }
    out
}

/// Inverse of [`parse_cat_dests`] - the canonical echo/persist form.
pub(super) fn fmt_cat_dests(list: &[(String, PathBuf)]) -> String {
    list.iter()
        .map(|(c, p)| format!("{c}={}", p.display()))
        .collect::<Vec<_>>()
        .join(", ")
}

/// Quick-access roots for the directory browser: home, the current
/// download folder, and every mounted volume/drive - the whole point being
/// to reach a *second* drive without knowing its path.
pub(super) fn fs_roots(cur_download: &std::path::Path) -> Value {
    let home = std::env::var_os("HOME")
        .or_else(|| std::env::var_os("USERPROFILE"))
        .map(PathBuf::from)
        .unwrap_or_else(|| PathBuf::from("/"));
    // Mobile targets have no volume enumeration arm below: the app
    // sandbox is the whole visible filesystem, so `roots` never grows.
    #[cfg_attr(any(target_os = "ios", target_os = "android"), expect(unused_mut))]
    let mut roots = vec![
        json!({"name": "Home", "path": home.to_string_lossy()}),
        json!({"name": "Current downloads", "path": cur_download.to_string_lossy()}),
    ];
    #[cfg(target_os = "macos")]
    {
        roots.push(json!({"name": "Macintosh HD", "path": "/"}));
        // Every mounted volume, external drives included.
        if let Ok(rd) = std::fs::read_dir("/Volumes") {
            for e in rd.flatten() {
                let name = e.file_name().to_string_lossy().to_string();
                if !name.starts_with('.') {
                    roots.push(
                        json!({"name": name, "path": e.path().to_string_lossy(), "drive": true}),
                    );
                }
            }
        }
    }
    // FreeBSD shares this arm: /mnt is the same convention, and the
    // desktop automounters that own /media/<user>/<label> (udisks2,
    // via the ports tree) put it in the same place.
    #[cfg(any(target_os = "linux", target_os = "freebsd"))]
    {
        roots.push(json!({"name": "Filesystem", "path": "/"}));
        // /media/<user>/<label> and /mnt/<label> are the usual mount points.
        for base in ["/media", "/mnt"] {
            if let Ok(rd) = std::fs::read_dir(base) {
                for e in rd.flatten() {
                    let p = e.path();
                    if !p.is_dir() {
                        continue;
                    }
                    // /media nests one level deeper (per-user).
                    if base == "/media" {
                        if let Ok(inner) = std::fs::read_dir(&p) {
                            for i in inner.flatten() {
                                if i.path().is_dir() {
                                    roots.push(json!({"name": i.file_name().to_string_lossy(), "path": i.path().to_string_lossy(), "drive": true}));
                                }
                            }
                        }
                    } else {
                        roots.push(json!({"name": e.file_name().to_string_lossy(), "path": p.to_string_lossy(), "drive": true}));
                    }
                }
            }
        }
    }
    #[cfg(windows)]
    {
        for letter in b'A'..=b'Z' {
            let drive = format!("{}:\\", letter as char);
            if std::path::Path::new(&drive).exists() {
                roots.push(json!({"name": drive.clone(), "path": drive, "drive": true}));
            }
        }
    }
    Value::Array(roots)
}

/// Largest media file under `dir` (one level of subdirs too - extraction
/// can nest a release folder).
pub(super) fn largest_media_file(dir: &std::path::Path) -> Option<PathBuf> {
    const EXTS: [&str; 6] = [".mkv", ".mp4", ".avi", ".m4v", ".ts", ".wmv"];
    let mut best: Option<(u64, PathBuf)> = None;
    let mut consider = |p: PathBuf| {
        let l = p
            .file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .to_ascii_lowercase();
        if EXTS.iter().any(|x| l.ends_with(x))
            && let Ok(md) = p.metadata()
            && best.as_ref().is_none_or(|(sz, _)| md.len() > *sz)
        {
            best = Some((md.len(), p));
        }
    };
    for entry in std::fs::read_dir(dir).ok()?.flatten() {
        let p = entry.path();
        if p.is_dir() {
            for sub in std::fs::read_dir(&p).ok().into_iter().flatten().flatten() {
                consider(sub.path());
            }
        } else {
            consider(p);
        }
    }
    best.map(|(_, p)| p)
}
