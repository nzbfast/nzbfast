// Embed the app icon, a VERSIONINFO block and an application manifest
// into nzbfast.exe on Windows builds.
//
// The daemon shipped without any of this until 1.0.9: a PE carrying no
// version resource, no icon and no manifest reads as hand-assembled
// rather than built by a toolchain, which is a (small) input to the
// reputation scoring that flagged us. nzbtray.exe has had a version
// resource all along, so this brings the daemon in line with it.
//
// IT USED TO HAVE A SECOND JOB and does not any more: `precompress_pages`
// gzipped the immutable embedded pages into OUT_DIR, and it moved to
// `crates/nzbfast-api/build.rs` with the `include_bytes!` sites that
// read its output (lane 3 of Option C). `env!("OUT_DIR")` names the
// OUT_DIR of the package being compiled, so the two halves cannot be
// apart - a member written here is unreachable from a file in another
// crate. Everything left below is about the EXE.
//
// TWIN FILE: crates/nzbtray/build.rs does the same job for the tray and
// carries the same rc_path / find_rc_exe / compile_rc_* helpers. They
// diverged once - §172 fixed the tray for MSVC and left this one on
// windres - and the ARM64 release job is the ONLY thing in CI that
// catches that (see compile_rc_msvc below). Change both together.
//
// IT HAS A SECOND JOB AGAIN, and this one runs on EVERY target rather
// than only Windows: `emit_layout_tests` writes one nextest test per
// posting-layout profile in `crates/postfast/catalog/`. Its own header
// says why the tests are generated instead of looped over, and it runs
// BEFORE the `CARGO_CFG_WINDOWS` early return below - a step added
// after that return would silently never run on this fleet.

fn main() {
    emit_layout_tests();
    println!("cargo:rerun-if-changed=../../packaging/icon/nzbfast.ico");
    println!("cargo:rerun-if-changed=../../packaging/windows/nzbfast.manifest");
    // THE BETA SERIAL MOVED with `precompress_pages`, to
    // `crates/nzbfast-api/build.rs` (lane 3 of Option C). `env!` reads
    // the environment of the package being COMPILED, and its one reader
    // - the `beta` field of `mode=version` - is `api/system.rs`, which
    // is in that crate now. A `cargo:rustc-env` set here would simply
    // not be visible there.

    if std::env::var("CARGO_CFG_WINDOWS").is_err() {
        return;
    }
    let out = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap());
    let root = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../..");
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

/// Write one `#[tokio::test]` per profile in the posting-layout
/// catalog, each a one-line call into the shared runner.
///
/// ref-gate: the destination is `$OUT_DIR/layouts_gen.rs`, which no
/// tree path names because the build writes it - the includer is
/// `crates/nzbfast/tests/integration/layouts.rs`, and that file is
/// where a reader should start.
///
/// WHY ONE TEST PER PROFILE AND NOT A LOOP OVER THE DIRECTORY. A loop
/// inside one test gives one test NAME, so a failure says "layouts
/// failed" and a bisect runs the whole catalog to reach the one row it
/// cares about. Generated names make a failure self-describing, make
/// `-E 'test(layout_n2_opaque_c0_p0)'` a single row, and keep the test
/// file free of a case table that would walk it toward a size-gate
/// ceiling as the catalog grows. Spec section 9.2
/// (research/SPEC-POSTING-LAYOUT-TOOLKIT-2026-09-03.md) states the rule
/// and says a directory loop is refused by review.
///
/// FAILING TO FIND IS FAILING. A catalog this cannot read, or one that
/// yields no profile, is a build error rather than an empty file: an
/// empty `layouts_gen.rs` is a test target that passes over nothing,
/// which is the rubber stamp the whole toolkit exists to make
/// impossible.
fn emit_layout_tests() {
    let catalog = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../postfast/catalog");
    // The DIRECTORY, not each file: a profile ADDED tomorrow has to
    // re-run this script, and a per-file list only re-runs when a file
    // already known changes. Cargo watches the directory's mtime, which
    // moves on create and on delete.
    println!("cargo:rerun-if-changed={}", catalog.display());

    let entries = std::fs::read_dir(&catalog).unwrap_or_else(|e| {
        panic!(
            "the layout catalog at {} is unreadable: {e}",
            catalog.display()
        )
    });
    let mut stems: Vec<String> = Vec::new();
    for entry in entries {
        let path = entry.expect("a readable catalog directory entry").path();
        if path.extension().and_then(|e| e.to_str()) != Some("toml") {
            continue;
        }
        // A profile changing its own bytes must re-run this too, or a
        // renamed `[layout] name` leaves a stale generated file behind.
        println!("cargo:rerun-if-changed={}", path.display());
        let stem = path
            .file_stem()
            .and_then(|s| s.to_str())
            .unwrap_or_else(|| panic!("{} has no usable file stem", path.display()))
            .to_string();
        stems.push(stem);
    }
    // read_dir order is unspecified, so sort rather than trust it: the
    // generated file is an input to the build fingerprint, and a set of
    // tests that reorders run to run rewrites it for no reason.
    stems.sort();
    assert!(
        !stems.is_empty(),
        "no .toml profiles under {} - the layouts target would pass over nothing",
        catalog.display()
    );

    let mut out = String::from(
        "// GENERATED by crates/nzbfast/build.rs from crates/postfast/catalog/*.toml.\n\
         // Do not edit: add a PROFILE, not a test.\n",
    );
    for stem in &stems {
        let ident = test_ident(stem);
        // `multi_thread`, because the mock server has to keep answering
        // while the blocking child process runs - the flavour every
        // `run_norar` caller in `e2e.rs` already dials, for that reason.
        out.push_str(&format!(
            "\n#[tokio::test(flavor = \"multi_thread\")]\nasync fn {ident}() {{\n    \
             runner::run(\"{stem}\").await;\n}}\n"
        ));
    }
    let dest = std::path::PathBuf::from(std::env::var("OUT_DIR").unwrap()).join("layouts_gen.rs");
    std::fs::write(&dest, out).unwrap_or_else(|e| panic!("writing {}: {e}", dest.display()));
}

/// `n2-opaque-c0-p0` to `layout_n2_opaque_c0_p0`.
///
/// Only the characters a catalog filename is allowed to carry are
/// mapped, and anything else is REFUSED rather than smoothed away: two
/// stems that folded onto one identifier would be a build error nobody
/// could read, and silently dropping a character is how a profile ends
/// up named after a different one.
fn test_ident(stem: &str) -> String {
    assert!(
        !stem.is_empty() && stem.starts_with(|c: char| c.is_ascii_lowercase()),
        "catalog profile {stem:?} must start with a lowercase ascii letter"
    );
    assert!(
        stem.chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || c == '_'),
        "catalog profile {stem:?} must be lowercase ascii, digits, '-' and '_' only - it \
         becomes a rust test name"
    );
    format!("layout_{}", stem.replace('-', "_"))
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
