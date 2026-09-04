//! Interactive first-run / server-management wizard (`nzbfast setup`).
//!
//! The friendly front door: no config file to hand-edit. Walks a new user
//! through adding their first usenet server, lets them add more (backup /
//! fill accounts), and on later runs offers a quick "start now / add /
//! remove" menu. Returns `Ok(true)` to proceed to `serve`, `Ok(false)` if
//! the user chose to quit - the launcher only starts the daemon on `true`.
//!
//! It writes the same `config.local.json` the engine reads, so a
//! SABnzbd-style ini or a hand-written config still work unchanged; if a
//! SABnzbd install is detected and we have no local config yet, we offer
//! to just use its servers (the loader already reads them directly).

use std::io::{self, Write};
use std::path::Path;

use anyhow::Result;
use serde_json::{Value, json};

fn header() {
    // A few blank lines stand in for a clear on a plain terminal.
    print!("\n\n");
    println!("======================================");
    println!("   nzbfast - setup");
    println!("======================================");
}

fn prompt(label: &str) -> io::Result<String> {
    print!("{label}");
    io::stdout().flush()?;
    let mut s = String::new();
    if io::stdin().read_line(&mut s)? == 0 {
        // EOF: stdin is closed (piped / non-interactive). Returning an empty
        // string here would make the required-field loops below re-prompt
        // forever (every read is another instant EOF), so surface it as an
        // error and let setup exit cleanly instead of spinning at 100% CPU.
        return Err(io::Error::new(
            io::ErrorKind::UnexpectedEof,
            "no input received (stdin is closed) - run `nzbfast setup` in a terminal",
        ));
    }
    Ok(s.trim().to_string())
}

fn pause() -> io::Result<()> {
    prompt("\nPress Return to continue.").map(|_| ())
}

/// Human-readable one-liner for a server object.
fn describe(s: &Value) -> String {
    let host = s.get("host").and_then(Value::as_str).unwrap_or("?");
    let port = s.get("port").and_then(Value::as_u64).unwrap_or(563);
    let conns = s.get("connections").and_then(Value::as_u64).unwrap_or(8);
    let tls = s.get("tls").and_then(Value::as_bool).unwrap_or(true);
    let level = s.get("level").and_then(Value::as_u64).unwrap_or(0);
    format!(
        "{host}:{port}  ·  {conns} connections{}{}",
        if tls { "" } else { "  ·  no TLS" },
        if level > 0 { "  ·  backup/fill" } else { "" },
    )
}

/// Serializes a whole read-modify-write of the JSON config.
///
/// Every server edit - save, enable, reorder, delete, import - reads the
/// entire array, changes a copy, and writes the array back. The atomic
/// rename stops a torn FILE; it does nothing about a stale READ. Eight
/// HTTP workers run requests concurrently, so two edits could both load
/// the same array, both succeed, and the second rename erase the first's
/// change with no error anywhere. Hold this across the read AND the
/// write, not just the write.
pub fn config_write_lock() -> std::sync::MutexGuard<'static, ()> {
    static LOCK: std::sync::Mutex<()> = std::sync::Mutex::new(());
    LOCK.lock().unwrap_or_else(|e| e.into_inner())
}

/// Read the `servers` array out of an existing config (if any). Anything
/// else in the file (e.g. `tmdb_key`) is preserved separately on write.
/// pub(crate): the dashboard's server editor shares these (crates/nzbfast-daemon/src/servers.rs
/// reads, api/servers.rs writes) so both write the exact same
/// config.local.json shape.
pub fn read_servers(config_path: &Path) -> Vec<Value> {
    // Non-destructive: the path may be a SABnzbd .ini (a supported runtime
    // config). load_json_with_backup would quarantine a non-JSON file to
    // .corrupt - destroying the user's config on a read-only action.
    crate::persist::load_json_config(config_path)
        .and_then(|v| v.get("servers").and_then(Value::as_array).cloned())
        .unwrap_or_default()
}

/// Replace the `servers` array, keeping any other top-level keys intact.
/// Backup-aware read + atomic write: this file holds the server
/// credentials - a torn read must not make the next save clobber them.
pub fn write_servers(config_path: &Path, servers: &[Value]) -> Result<()> {
    // Never write JSON at a `.ini` path. `Config::load` picks its parser
    // from exactly this predicate, so a JSON body here is fed to the
    // SABnzbd ini parser and comes back NoServers - and the file we
    // overwrote was the user's live sabnzbd.ini, so we would have broken
    // both installs at once. Refuse before touching anything: a backup
    // (below) makes it recoverable, not un-broken.
    if config_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ini"))
    {
        anyhow::bail!(
            "{} is a SABnzbd ini, which nzbfast reads but cannot write - \
             server edits need a JSON config; point --config at config.local.json",
            config_path.display()
        );
    }
    let root = crate::persist::load_json_config(config_path);
    // Still possible past the `.ini` guard: a corrupt/truncated JSON config,
    // or an ini-format file living under some other name. load_json_config
    // returns None but the file is NOT empty, and there is no .bak for a
    // non-JSON file. Preserve the original once before the first overwrite
    // so it is always recoverable.
    if root.is_none()
        && let Ok(orig) = std::fs::read(config_path)
        && !orig.is_empty()
        && serde_json::from_slice::<Value>(&orig).is_err()
    {
        let mut b = config_path.as_os_str().to_owned();
        b.push(".orig");
        let backup = std::path::PathBuf::from(b);
        if !backup.exists() {
            // 0600: `orig` is the whole SABnzbd ini, including `password = …`
            // for every configured server.
            let _ = crate::persist::write_atomic(&backup, &orig);
            eprintln!(
                "[setup] {} is not a JSON config (SABnzbd ini?); backed it up to {} before writing server settings",
                config_path.display(),
                backup.display()
            );
        }
    }
    let mut root = root.filter(Value::is_object).unwrap_or_else(|| json!({}));
    root["servers"] = json!(servers);
    let text = serde_json::to_string_pretty(&root)?;
    crate::persist::write_atomic(config_path, text.as_bytes())?;
    Ok(())
}

/// Collect one server interactively. `existing` is how many are already
/// configured (0 ⇒ this is the primary; >0 ⇒ offer backup/fill).
fn add_server(existing: usize) -> Result<Value> {
    println!();
    if existing == 0 {
        println!("Let's add your usenet provider.");
    } else {
        println!("Let's add another server.");
    }
    println!("(You'll find these in your provider's welcome email.)");
    println!();

    let host = loop {
        let h = prompt("  Server address (e.g. news.provider.com): ")?;
        if !h.is_empty() {
            break h;
        }
        println!("  A server address is required.");
    };
    let port: u16 = {
        let p = prompt("  Port [563 for secure, 119 for plain]: ")?;
        if p.is_empty() {
            563
        } else {
            p.parse().unwrap_or(563)
        }
    };
    let tls = port != 119;
    let user = prompt("  Username: ")?;
    let pass = rpassword::prompt_password("  Password (hidden as you type): ")?;
    let connections: u32 = {
        let c = prompt("  Max connections your plan allows [20]: ")?;
        if c.is_empty() {
            20
        } else {
            c.parse().unwrap_or(20)
        }
    };
    let level = if existing > 0 {
        let a = prompt(
            "  Is this a backup/fill account, used only when your main\n  \
             server is missing articles? [y/N]: ",
        )?;
        u32::from(matches!(a.to_ascii_lowercase().as_str(), "y" | "yes"))
    } else {
        0
    };

    let mut o = json!({
        "host": host,
        "port": port,
        "tls": tls,
        "connections": connections,
    });
    if !user.is_empty() {
        o["username"] = json!(user);
    }
    if !pass.is_empty() {
        // Obfuscated on the way out. Built by hand rather than serialized from
        // a ServerConfig, so the serde hook does not apply here. Obfuscation,
        // not encryption - see nzbkit::config::obfuscate_input, which is the
        // RAW-INPUT encoder: what the user just typed is never already
        // encoded, so a password that happens to start `obf1:` must not be
        // mistaken for one.
        o["password"] = json!(nzbkit::config::obfuscate_input(&pass));
    }
    if level > 0 {
        o["level"] = json!(level);
    }
    println!("\n  Added:  {}", describe(&o));
    Ok(o)
}

/// Human-readable label for an interest key. Deliberately English-only
/// and deliberately here rather than in the i18n catalogues: the CLI
/// wizard is a plain terminal with no locale machinery, and the dashboard
/// (which does have it) carries its own translated labels.
fn interest_label(key: &str) -> &'static str {
    match key {
        "linux" => "Linux and other freely distributable software",
        "movies" => "Films",
        "tv" => "TV shows",
        "sports" => "Sport (football, motorsport, MMA, boxing, wrestling)",
        "music" => "Music",
        "books" => "Books and audiobooks",
        "comics" => "Comics",
        "anime" => "Anime",
        "games" => "Games",
        "apps" => "Applications",
        _ => "",
    }
}

/// One line for the menu: what the stored answer currently says.
fn indexing_summary(config_path: &Path) -> String {
    let settings = config_path.with_file_name("settings.json");
    let stored = std::fs::read(&settings)
        .ok()
        .and_then(|b| serde_json::from_slice::<Value>(&b).ok())
        .and_then(|v| {
            v.get("index_interests")
                .and_then(Value::as_str)
                .map(str::to_string)
        });
    match stored {
        None => "not asked yet".into(),
        Some(s) => {
            let keys = crate::interests::parse(&s);
            if keys.is_empty() {
                "nothing".into()
            } else {
                keys.iter()
                    .map(|k| interest_label(k))
                    .collect::<Vec<_>>()
                    .join(", ")
            }
        }
    }
}

/// Forget the stored answer so the question can be asked again.
fn clear_interests(config_path: &Path) {
    let settings = config_path.with_file_name("settings.json");
    let Ok(bytes) = std::fs::read(&settings) else {
        return;
    };
    let Ok(Value::Object(mut map)) = serde_json::from_slice::<Value>(&bytes) else {
        return;
    };
    map.remove("index_interests");
    if let Ok(text) = serde_json::to_string_pretty(&Value::Object(map)) {
        let _ = crate::persist::write_atomic(&settings, text.as_bytes());
    }
}

/// Ask what the indexer should look for.
///
/// The index is what fills the poster wall and what the watchlist
/// matches against, and it is OFF until someone says otherwise. This
/// step is where they say. Skipping it is a first-class answer: press
/// Return and nothing is indexed, with no list quietly chosen on the
/// user's behalf.
///
/// Only the CHOICE is recorded here. Turning it into newsgroup names
/// needs the provider's group list, which the daemon fetches on its
/// first connection - so the wizard prints exactly which groups each
/// answer stands for, and the daemon subscribes the ones that provider
/// actually carries.
fn ask_interests(config_path: &Path) -> Result<()> {
    let settings = config_path.with_file_name("settings.json");
    // Already answered (including answered "nothing")? Don't ask again.
    if let Ok(bytes) = std::fs::read(&settings)
        && let Ok(Value::Object(map)) = serde_json::from_slice::<Value>(&bytes)
        && map.contains_key("index_interests")
    {
        return Ok(());
    }
    header();
    println!(
        "
What should nzbfast keep an index of?"
    );
    println!(
        "
The index is what fills the browsable wall and what the"
    );
    println!("watchlist matches against. It is OFF unless you choose here:");
    println!("pick nothing and nothing is indexed.");
    println!(
        "
You can change this at any time in Settings.
"
    );
    let opts = crate::interests::INTERESTS;
    for (i, it) in opts.iter().enumerate() {
        println!("  {}. {}", i + 1, interest_label(it.key));
        println!("       {}", it.groups.join(", "));
    }
    println!(
        "
Enter the numbers you want, separated by commas (e.g. 1,3)."
    );
    let answer = prompt("Or just press Return to index nothing: ")?;
    let chosen: Vec<&str> = answer
        .split(',')
        .filter_map(|t| t.trim().parse::<usize>().ok())
        .filter(|n| *n >= 1 && *n <= opts.len())
        .map(|n| opts[n - 1].key)
        .collect();
    // Written even when empty: the stored answer is what stops this
    // question coming back, and "nothing" is an answer.
    let value = chosen.join(",");
    // This writer rewrites the WHOLE settings map, so where it starts
    // from is load bearing. Reading the primary raw and falling back to
    // an EMPTY map on any failure meant a store that was merely
    // interrupted - absent primary with an intact `.bak`, which is
    // exactly what a crash between write_atomic's temp write and its
    // rename leaves - published a one-key document over the top of it.
    // out_dir, categories, feeds, watchlist, notify tokens, servers'
    // sibling apikey: all gone, and permanently, because the next start
    // parses that document successfully and REFRESHES the .bak from it.
    // Same guard and same recovery as `import_sab`'s writer, which was
    // fixed for this and pins it with a test: refuse outright when the
    // store is unreadable, and otherwise start from the backup-aware
    // load rather than from nothing.
    if crate::persist::json_store_unreadable(&settings) {
        println!(
            "  (not recording your answer: {} exists but won't parse - \
             fix or remove it first, then run setup again)",
            settings.display()
        );
        return Ok(());
    }
    let mut map = match crate::persist::load_json_with_backup(&settings) {
        Some(Value::Object(m)) => m,
        _ => serde_json::Map::new(),
    };
    map.insert("index_interests".into(), Value::String(value.clone()));
    let text = serde_json::to_string_pretty(&Value::Object(map))?;
    // Through `write_atomic`, like every other writer of this file: the
    // wizard rewrites the WHOLE settings map, apikey included, and a plain
    // `fs::write` truncates in place. A crash mid-write leaves a truncated
    // settings.json, which `json_store_unreadable` (called from
    // bootstrap.rs) sees on the next start - the daemon mints a FRESH
    // apikey and every *arr connection stops working. It also gets the 0600
    // creation mode the credential-bearing stores are supposed to have.
    crate::persist::write_atomic(&settings, text.as_bytes())?;
    if chosen.is_empty() {
        println!(
            "
Nothing will be indexed. Nothing else changes."
        );
    } else {
        println!(
            "
Saved. nzbfast will index:"
        );
        for k in &chosen {
            println!("  - {}", interest_label(k));
        }
        println!(
            "
It subscribes the groups above that your provider carries,"
        );
        println!("once it has connected. Downloading works either way.");
    }
    pause()?;
    Ok(())
}

/// Run the wizard. Returns `true` to proceed to the daemon, `false` to quit.
pub fn run(config_path: &Path) -> Result<bool> {
    let mut servers = read_servers(config_path);

    // No local config yet, but a SABnzbd install is present → offer to use
    // its servers as-is (the engine reads sabnzbd.ini directly at runtime).
    if servers.is_empty()
        && let Some(sab) =
            nzbkit::config::sabnzbd_ini_path(&config_path.parent().into_iter().collect::<Vec<_>>())
    {
        header();
        println!("\nFound your SABnzbd servers:");
        println!("  {}", sab.display());
        println!("\nnzbfast can use them directly - nothing to set up.");
        println!("\n  [Return]  Use SABnzbd's servers and start");
        println!("  s         Set up nzbfast's own server instead");
        println!("  q         Quit");
        match prompt("\nChoose: ")?.to_ascii_lowercase().as_str() {
            "s" => {} // fall through to first-run add
            "q" => return Ok(false),
            _ => return Ok(true), // Return / anything else → use SAB
        }
    }

    // First run with nothing configured → add the primary server.
    if servers.is_empty() {
        header();
        println!("\nWelcome! Let's get you set up - takes about a minute.");
        servers.push(add_server(0)?);
        write_servers(config_path, &servers)?;
        println!("\nSaved.");
        // Straight on to the one other question worth asking a new user.
        ask_interests(config_path)?;
    }

    // Management menu.
    loop {
        header();
        println!("\nYour usenet server(s):");
        for (i, s) in servers.iter().enumerate() {
            println!("  {}. {}", i + 1, describe(s));
        }
        println!("\n  [Return]  Start downloading");
        println!("  a         Add another server (e.g. a backup/fill account)");
        println!("  r         Remove a server");
        println!(
            "  i         Choose what to index (currently: {})",
            indexing_summary(config_path)
        );
        println!("  q         Quit without starting");
        match prompt("\nChoose: ")?.to_ascii_lowercase().as_str() {
            "" => return Ok(true),
            "a" => {
                let s = add_server(servers.len())?;
                servers.push(s);
                write_servers(config_path, &servers)?;
                println!("\nSaved - you now have {} server(s).", servers.len());
                pause()?;
            }
            "r" => {
                let n = prompt("  Remove which number (Return to cancel): ")?;
                if let Ok(idx) = n.parse::<usize>() {
                    if idx >= 1 && idx <= servers.len() {
                        let removed = servers.remove(idx - 1);
                        write_servers(config_path, &servers)?;
                        println!("  Removed {}.", describe(&removed));
                        if servers.is_empty() {
                            println!("  You need at least one server - let's add it.");
                            servers.push(add_server(0)?);
                            write_servers(config_path, &servers)?;
                        }
                        pause()?;
                    } else {
                        println!("  No server numbered {idx}.");
                        pause()?;
                    }
                }
            }
            "i" => {
                // Re-asking is the same question, so drop the stored
                // answer first: ask_interests is a no-op once answered.
                clear_interests(config_path);
                ask_interests(config_path)?;
            }
            "q" => return Ok(false),
            _ => {}
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn write_then_read_roundtrips_and_preserves_other_keys() {
        let dir = std::env::temp_dir().join(format!("nzbfast-setup-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");

        // Pre-existing file with an unrelated key we must not clobber.
        std::fs::write(&cfg, r#"{"tmdb_key":"abc123","servers":[]}"#).unwrap();

        let s1 = json!({"host":"a.example.com","port":563,"tls":true,"connections":20});
        let s2 = json!({"host":"b.example.com","port":119,"tls":false,"connections":8,"level":1});
        write_servers(&cfg, &[s1.clone(), s2.clone()]).unwrap();

        let back = read_servers(&cfg);
        assert_eq!(back.len(), 2);
        assert_eq!(back[0]["host"], "a.example.com");
        assert_eq!(back[1]["level"], 1);

        // tmdb_key survived, and the engine loader accepts the result.
        let root: Value = serde_json::from_slice(&std::fs::read(&cfg).unwrap()).unwrap();
        assert_eq!(root["tmdb_key"], "abc123");
        let loaded = nzbkit::config::Config::load(&cfg).unwrap();
        assert_eq!(loaded.servers.len(), 2);
        assert_eq!(loaded.servers[1].level, 1);
        assert!(!loaded.servers[1].tls);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Regression: write_servers used to write JSON straight over a `.ini`
    /// config path. `Config::load` routes a `.ini` to the SABnzbd parser,
    /// so the result was NoServers for nzbfast AND a destroyed sabnzbd.ini
    /// for SAB. It must refuse, leaving the file byte-for-byte intact.
    #[test]
    fn refuses_to_write_json_over_an_ini_config() {
        let dir = std::env::temp_dir().join(format!("nzbfast-setup-ini-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("sabnzbd.ini");
        let original = "__version__ = 19\n[servers]\n[[news.example.com]]\nhost = news.example.com\nport = 563\nssl = 1\nenable = 1\n";
        std::fs::write(&ini, original).unwrap();

        // Sanity: the loader really does read this path as an ini today.
        let before = nzbkit::config::Config::load(&ini).unwrap();
        assert_eq!(before.servers.len(), 1);

        let s = json!({"host":"new.example.com","port":563,"tls":true,"connections":20});
        let err = write_servers(&ini, &[s]).unwrap_err().to_string();
        assert!(err.contains("config.local.json"), "unhelpful error: {err}");

        // Nothing was written - not the config, not a .orig sidecar.
        assert_eq!(std::fs::read_to_string(&ini).unwrap(), original);
        assert!(!dir.join("sabnzbd.ini.orig").exists());
        // And the user's SAB install still loads.
        let after = nzbkit::config::Config::load(&ini).unwrap();
        assert_eq!(after.servers.len(), 1);
        assert_eq!(after.servers[0].host, "news.example.com");

        // Upper-case extension is the same file to the loader's
        // eq_ignore_ascii_case check, so it must be to us too.
        let shouty = dir.join("SABNZBD.INI");
        std::fs::write(&shouty, original).unwrap();
        assert!(write_servers(&shouty, &[]).is_err());
        assert_eq!(std::fs::read_to_string(&shouty).unwrap(), original);

        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The other half of the guard: a genuinely corrupt JSON config (no
    /// `.ini` extension) is still preserved to `.orig` and overwritten.
    #[test]
    fn corrupt_json_config_is_backed_up_then_rewritten() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-setup-corrupt-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let cfg = dir.join("config.local.json");
        std::fs::write(&cfg, "this is not json at all").unwrap();

        let s = json!({"host":"a.example.com","port":563,"tls":true,"connections":20});
        write_servers(&cfg, &[s]).unwrap();

        let orig = dir.join("config.local.json.orig");
        assert_eq!(
            std::fs::read_to_string(&orig).unwrap(),
            "this is not json at all"
        );
        assert_eq!(read_servers(&cfg).len(), 1);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn describe_reads_fields() {
        let s = json!({"host":"h","port":563,"tls":true,"connections":30});
        let d = describe(&s);
        assert!(d.contains("h:563"));
        assert!(d.contains("30 connections"));
    }
}
