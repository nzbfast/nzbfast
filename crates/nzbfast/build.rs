// Embed the app icon, a VERSIONINFO block and an application manifest
// into nzbfast.exe on Windows builds.
//
// The daemon shipped without any of this until 1.0.9: a PE carrying no
// version resource, no icon and no manifest reads as hand-assembled
// rather than built by a toolchain, which is a (small) input to the
// reputation scoring that flagged us. nzbtray.exe has had a version
// resource all along, so this brings the daemon in line with it.
//
// It has a SECOND job since R10/C9 that has nothing to do with Windows:
// `precompress_pages` gzips the immutable embedded pages (the i18n
// catalogues and the manuals) so the binary carries the compressed
// member rather than 9.0 MB of plain text. That runs on every target -
// see the note above the early return in main().
//
// TWIN FILE: crates/nzbtray/build.rs does the same job for the tray and
// carries the same rc_path / find_rc_exe / compile_rc_* helpers. They
// diverged once - §172 fixed the tray for MSVC and left this one on
// windres - and the ARM64 release job is the ONLY thing in CI that
// catches that (see compile_rc_msvc below). Change both together.

fn main() {
    println!("cargo:rerun-if-changed=../../packaging/icon/nzbfast.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/nzbfast.manifest");
    // Beta serial: local deploys and tester builds carry "beta N" after
    // the version so anyone can tell a between-releases build from the
    // published release it grew out of. packaging/beta-serial.txt is
    // bumped by the deploy-daemon / release-bundle workflows and RESET
    // TO 0 by publish-release, so a release build shows a bare version.
    // Missing file or 0 (or a public-repo build, which has no file)
    // means "not a beta": the suffix simply never appears.
    println!("cargo:rerun-if-changed=../../packaging/beta-serial.txt");
    let beta =
        std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../packaging/beta-serial.txt");
    let beta = std::fs::read_to_string(beta)
        .ok()
        .and_then(|s| s.trim().parse::<u32>().ok())
        .filter(|&n| n > 0)
        .map(|n| n.to_string())
        .unwrap_or_default();
    println!("cargo:rustc-env=NZBFAST_BETA={beta}");

    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
    // Every target, before the Windows-only half below returns - but
    // only when the browser-facing pages are being compiled IN. Without
    // the `dashboard` feature (TODO 281 IO3b: the store build, and both
    // phones) nothing includes these members, so gzipping 11.5 MB of
    // catalogues and manuals into OUT_DIR is work whose whole output is
    // discarded. `CARGO_FEATURE_DASHBOARD` is cargo's own spelling of the
    // feature for a build script, and the `include_bytes!` sites that
    // read these keys carry the SAME cfg - so a build that skips this
    // cannot reach a missing file.
    if std::env::var_os("CARGO_FEATURE_DASHBOARD").is_some() {
        precompress_pages(&root, &out);
    }

    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    let Ok(ico) = root.join("packaging/icon/nzbfast.ico").canonicalize() else {
        println!("cargo:warning=nzbfast.ico missing - building without an embedded icon");
        return;
    };
    let ver = std::env::var("CARGO_PKG_VERSION").unwrap();
    let ver_commas = ver.replace('.', ",");

    // RT_MANIFEST (resource type 24, id 1) only for the gnu toolchain.
    // MSVC's linker embeds a default manifest of its own and a second one
    // is a hard link error, so leave that target alone.
    let gnu = std::env::var("CARGO_CFG_TARGET_ENV").as_deref() == Ok("gnu");
    let manifest = root
        .join("packaging/windows/nzbfast.manifest")
        .canonicalize()
        .ok();
    let manifest_line = match (&manifest, gnu) {
        (Some(m), true) => format!("1 24 \"{}\"\n", rc_path(m)),
        _ => String::new(),
    };

    let rc = out.join("nzbfast.rc");
    std::fs::write(
        &rc,
        format!(
            r#"1 ICON "{ico}"
{manifest_line}1 VERSIONINFO
FILEVERSION {ver_commas},0
PRODUCTVERSION {ver_commas},0
BEGIN
  BLOCK "StringFileInfo"
  BEGIN
    BLOCK "040904b0"
    BEGIN
      VALUE "CompanyName", "nzbfast"
      VALUE "ProductName", "nzbfast"
      VALUE "FileDescription", "nzbfast download engine"
      VALUE "InternalName", "nzbfast"
      VALUE "OriginalFilename", "nzbfast.exe"
      VALUE "FileVersion", "{ver}"
      VALUE "ProductVersion", "{ver}"
      VALUE "LegalCopyright", "GPL-3.0-or-later"
    END
  END
  BLOCK "VarFileInfo"
  BEGIN
    VALUE "Translation", 0x409, 1200
  END
END
"#,
            ico = rc_path(&ico),
        ),
    )
    .unwrap();
    if gnu {
        compile_rc_windres(&rc, &out);
    } else {
        compile_rc_msvc(&rc, &out);
    }
}

/// Spell a path the way an .rc file wants it.
///
///   - `canonicalize()` returns a VERBATIM path (`\\?\C:\...`) on Windows.
///     Neither `rc.exe` nor `windres` accepts that prefix.
///   - a backslash inside an .rc string literal is an ESCAPE character,
///     so `"C:\Users\..."` is read as `C:Users...`. Both compilers take
///     forward slashes, which need no escaping.
fn rc_path(p: &std::path::Path) -> String {
    let s = p.display().to_string();
    let s = s.strip_prefix(r"\\?\").unwrap_or(&s);
    s.replace('\\', "/")
}

/// mingw: `windres` straight to a COFF object, link-arg'd in.
///
/// gnu only, and that restriction is the whole point. A COFF object has a
/// machine type baked in and `windres` stamps its own; the mingw we ship
/// with is x86_64, so handing its output to an ARM64 `link.exe` is a hard
/// LNK1112. That is not hypothetical - it is what this file did until the
/// first aarch64-pc-windows-msvc build was ever run.
fn compile_rc_windres(rc: &std::path::Path, out: &std::path::Path) {
    let windres =
        std::env::var("WINDRES").unwrap_or_else(|_| "x86_64-w64-mingw32-windres".to_string());
    let res = out.join("nzbfast.res.o");
    match std::process::Command::new(&windres)
        .args([
            rc.to_str().unwrap(),
            "-O",
            "coff",
            "-o",
            res.to_str().unwrap(),
        ])
        .status()
    {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg={}", res.display()),
        _ => println!("cargo:warning={windres} unavailable - no embedded icon/version resource"),
    }
}

/// MSVC: `rc.exe` to a .res, which `link.exe` takes as an ordinary input.
///
/// A .res is architecture-NEUTRAL - the linker places it - so the same
/// x64-host rc.exe serves the ARM64 cross-build, which is exactly what a
/// windres COFF object cannot do.
///
/// This arm used to be `windres` under a bare name. On a Mac cross-build
/// that name is absent and the daemon simply shipped unadorned, which is
/// what the old comment here described. On a Windows box it is WORSE than
/// absent: the runner image has a mingw `windres` on PATH, so the build
/// script succeeded and emitted an x86_64 object, and the ARM64 link died
/// on it (LNK1112) rather than degrading. Nothing in CI reaches this line
/// except the release job's ARM64 build - `cargo clippy --target` runs
/// build scripts but never links, so it cannot see a bad object.
fn compile_rc_msvc(rc: &std::path::Path, out: &std::path::Path) {
    let Some(rc_exe) = find_rc_exe() else {
        println!("cargo:warning=rc.exe not found - no embedded icon/version resource");
        return;
    };
    let res = out.join("nzbfast.res");
    match std::process::Command::new(&rc_exe)
        .args([
            "/nologo",
            "/fo",
            res.to_str().unwrap(),
            rc.to_str().unwrap(),
        ])
        .status()
    {
        Ok(s) if s.success() => println!("cargo:rustc-link-arg={}", res.display()),
        _ => println!(
            "cargo:warning={} failed - no embedded icon/version resource",
            rc_exe.display()
        ),
    }
}

/// Locate `rc.exe`: the `RC` override, then PATH, then the Windows SDK.
///
/// The SDK sweep is what makes this work unattended. rc.exe ships with the
/// Windows Kits, and nothing puts it on PATH outside a Visual Studio
/// developer prompt - a plain `cargo build` on a Windows box, and a GitHub
/// `windows-latest` runner, both have the SDK installed and rc.exe
/// unreachable. Highest SDK version wins; the host-x64 binary is the one to
/// run whatever the target is.
fn find_rc_exe() -> Option<std::path::PathBuf> {
    if let Ok(explicit) = std::env::var("RC") {
        return Some(std::path::PathBuf::from(explicit));
    }
    if std::process::Command::new("rc.exe")
        .arg("/?")
        .output()
        .is_ok()
    {
        return Some(std::path::PathBuf::from("rc.exe"));
    }
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    for var in ["ProgramFiles(x86)", "ProgramFiles"] {
        if let Ok(pf) = std::env::var(var) {
            roots.push(std::path::PathBuf::from(pf).join("Windows Kits/10/bin"));
        }
    }
    let mut found: Vec<std::path::PathBuf> = Vec::new();
    for root in roots {
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.flatten() {
            // Both layouts exist: bin/<sdk-version>/x64/rc.exe on modern
            // kits, bin/x64/rc.exe on older ones.
            for cand in [e.path().join("x64/rc.exe"), e.path().join("rc.exe")] {
                if cand.is_file() {
                    found.push(cand);
                }
            }
        }
    }
    // read_dir order is unspecified, so sort rather than trust it. Lexical
    // order over `10.0.<build>.0` directory names is version order.
    found.sort();
    found.pop()
}

/// Compress the embedded pages that CANNOT change between builds, and
/// compute their validators here rather than per request (R10 / Codex
/// C9).
///
/// The 27 i18n catalogues and the 16 manuals are 9.0 MB of plain text
/// in the binary's read-only data - a quarter of the whole executable -
/// and every byte of them goes to a browser that would have taken gzip.
/// Embedding the gzip MEMBER instead costs 2.8 MB (-69%), and the
/// request path stops deflating a 250 KB catalogue on every fetch: the
/// ETag lands beside it as a string constant, so a revalidation is a
/// header compare with no page to build and nothing to hash.
///
/// Only pages with no per-request input may pass through here. The
/// manuals have exactly one substitution - `__NZBFAST_UI_TOKENS__`, the
/// shared design system - and its input is another compiled-in file, so
/// it is folded in HERE and the manual route no longer calls
/// `ui_themed`. The dashboard and the wall are deliberately NOT in this
/// set: they carry daemon state (locale, indexer switches) and are
/// cached at run time instead, keyed on those inputs.
///
/// The keys written here are named one by one in
/// `crates/nzbfast/src/serve/assets.rs`, so a locale that loses its file
/// is a compile error naming the key, not a page that quietly stops
/// being served.
fn precompress_pages(root: &std::path::Path, out: &std::path::Path) {
    let tokens_at = root.join("web/ui-tokens.html");
    println!("cargo:rerun-if-changed={}", tokens_at.display());
    let tokens = std::fs::read_to_string(&tokens_at)
        .unwrap_or_else(|e| panic!("{}: {e}", tokens_at.display()));

    // The DIRECTORY dependency catches an added or removed locale; the
    // per-file ones inside `emit_page` catch an edited translation.
    for (dir, key, prefix, suffix, themed) in [
        (root.join("web/i18n"), "i18n", "", ".json", false),
        (root.join("docs/i18n"), "manual", "MANUAL.", ".html", true),
    ] {
        println!("cargo:rerun-if-changed={}", dir.display());
        let entries = std::fs::read_dir(&dir).unwrap_or_else(|e| panic!("{}: {e}", dir.display()));
        for entry in entries.flatten() {
            let name = entry.file_name().to_string_lossy().into_owned();
            // Two lowercase letters and nothing else, which is what every
            // UI locale tag is. It is also what keeps the translators'
            // own files out: `en.reference.json` sits in web/i18n and is
            // not a served catalogue.
            let Some(tag) = name
                .strip_prefix(prefix)
                .and_then(|n| n.strip_suffix(suffix))
                .filter(|t| t.len() == 2 && t.bytes().all(|b| b.is_ascii_lowercase()))
            else {
                continue;
            };
            let tokens = themed.then_some(tokens.as_str());
            emit_page(&entry.path(), out, &format!("{key}-{tag}"), tokens);
        }
    }
    // English is the source language: its manual is the one at the top
    // of docs/, not a translation.
    emit_page(
        &root.join("docs/MANUAL.html"),
        out,
        "manual-en",
        Some(&tokens),
    );
}

/// Write one asset's gzip member and its ETag into OUT_DIR under `key`.
fn emit_page(src: &std::path::Path, out: &std::path::Path, key: &str, tokens: Option<&str>) {
    use std::io::Write as _;
    println!("cargo:rerun-if-changed={}", src.display());
    let body = std::fs::read(src).unwrap_or_else(|e| panic!("{}: {e}", src.display()));
    let body = match tokens {
        // The one substitution an immutable page has, folded in once
        // here instead of once per request - `ui_themed`'s job, done at
        // build time. A page that does not name the placeholder simply
        // keeps its bytes.
        Some(t) => String::from_utf8(body)
            .unwrap_or_else(|e| panic!("{}: {e}", src.display()))
            .replace("__NZBFAST_UI_TOKENS__", t)
            .into_bytes(),
        None => body,
    };

    // FNV-1a over the FINAL bytes, byte for byte the function
    // serve/webasset.rs runs for the pages it still builds per request.
    // The two kinds of asset therefore carry the same shape of
    // validator, and a browser cannot tell them apart.
    let mut h: u64 = 0xcbf29ce484222325;
    for &b in &body {
        h = (h ^ b as u64).wrapping_mul(0x100000001b3);
    }
    let etag = out.join(format!("{key}.etag"));
    std::fs::write(&etag, format!("\"{h:016x}\""))
        .unwrap_or_else(|e| panic!("{}: {e}", etag.display()));

    // Level 9 rather than the request path's 6: this runs once per
    // build, not once per load, so there is no reason to leave bytes on
    // the table. flate2 stamps mtime 0, so the member is byte-identical
    // from one build of the same input to the next - a rebuild that
    // changes nothing must not change the ETag.
    let mut enc = flate2::write::GzEncoder::new(Vec::new(), flate2::Compression::new(9));
    enc.write_all(&body).expect("gzip to a Vec");
    let gz = out.join(format!("{key}.gz"));
    std::fs::write(&gz, enc.finish().expect("gzip trailer"))
        .unwrap_or_else(|e| panic!("{}: {e}", gz.display()));
}
