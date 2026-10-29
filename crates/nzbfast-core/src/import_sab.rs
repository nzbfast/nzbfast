//! M14c: one-command migration from SABnzbd - parse `sabnzbd.ini`
//! (configobj format) and emit our config JSON.
//!
//! We take the `[servers]` tree: each `[[name]]` subsection's host, port,
//! username, password, connections, ssl, priority, retention, enable.
//! SAB priority 0 is "first": it is both the listing order AND the tier,
//! so it maps to our M14e `level` (a level-N server is only asked for
//! articles every live lower level already missed) as well as to the
//! order we emit servers in. Dropping it - as this importer used to -
//! silently promoted a cheap block account to a co-equal primary and
//! spent its prepaid bytes on articles the flatrate primary would have
//! served. `retention` maps to `retention_days` for the same reason: a
//! short-retention filler must not be asked for old articles it cannot
//! hold. Same mapping config.rs's own sabnzbd.ini loader uses.

use std::path::Path;

use anyhow::{Context, Result};
use serde_json::json;

#[derive(Debug, Default, Clone)]
struct SabServer {
    name: String,
    host: String,
    port: Option<u16>,
    username: Option<String>,
    password: Option<String>,
    connections: Option<u32>,
    ssl: bool,
    priority: i32,
    /// SAB `retention` in days; 0 = unlimited (our `retention_days`).
    retention: u32,
    enable: bool,
}

fn unquote(v: &str) -> &str {
    let v = v.trim();
    // configobj (SAB's ini writer) wraps a value in whichever quote it does
    // NOT contain, so a password with a `"` is stored single-quoted:
    // `password = 's3cr,et"x'`. Stripping only double quotes left those
    // apostrophes in the emitted config, breaking AUTHINFO. Strip a matching
    // pair of EITHER quote.
    for q in ['"', '\''] {
        if let Some(inner) = v.strip_prefix(q).and_then(|s| s.strip_suffix(q)) {
            return inner;
        }
    }
    v
}

/// Parse the `[servers]` section of a sabnzbd.ini. Only depth-2
/// subsections under `[servers]` are read; everything else is skipped.
fn parse_servers(ini: &str) -> Vec<SabServer> {
    let mut out: Vec<SabServer> = Vec::new();
    let mut in_servers = false;
    let mut cur: Option<SabServer> = None;
    for line in ini.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if let Some(name) = line.strip_prefix("[[").and_then(|l| l.strip_suffix("]]")) {
            if in_servers {
                if let Some(s) = cur.take() {
                    out.push(s);
                }
                cur = Some(SabServer {
                    name: name.to_string(),
                    enable: true,
                    // SAB's default is TLS ON; a section with no `ssl` key must
                    // NOT downgrade the server to plaintext NNTP (would send
                    // credentials in the clear). Mirrors config.rs's loader.
                    ssl: true,
                    ..Default::default()
                });
            }
            continue;
        }
        if let Some(sect) = line.strip_prefix('[').and_then(|l| l.strip_suffix(']')) {
            if let Some(s) = cur.take() {
                out.push(s);
            }
            in_servers = sect.eq_ignore_ascii_case("servers");
            continue;
        }
        let Some((k, v)) = line.split_once('=') else {
            continue;
        };
        let (k, v) = (k.trim(), unquote(v));
        if let Some(s) = cur.as_mut() {
            match k {
                "host" => s.host = v.to_string(),
                "port" => s.port = v.parse().ok(),
                "username" => {
                    if !v.is_empty() {
                        s.username = Some(v.to_string());
                    }
                }
                "password" => {
                    if !v.is_empty() {
                        s.password = Some(v.to_string());
                    }
                }
                "connections" => s.connections = v.parse().ok(),
                "ssl" => s.ssl = v != "0",
                "priority" => s.priority = v.parse().unwrap_or(0),
                "retention" => s.retention = v.parse().unwrap_or(0),
                "enable" => s.enable = v == "1" || v.eq_ignore_ascii_case("true"),
                _ => {}
            }
        }
    }
    if let Some(s) = cur.take() {
        out.push(s);
    }
    out
}

/// A top-level (non-server) key's value from a SABnzbd ini - e.g.
/// `password_file` under `[misc]`. Depth-2 `[[server]]` sections are
/// skipped so a server's key of the same name can never shadow it.
pub fn sab_ini_value(ini: &str, key: &str) -> Option<String> {
    let mut in_subsection = false;
    for line in ini.lines() {
        let line = line.trim();
        if line.starts_with("[[") {
            in_subsection = true;
            continue;
        }
        if line.starts_with('[') {
            in_subsection = false;
            continue;
        }
        if in_subsection {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            let v = unquote(v);
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// A key's value from an nzbget.conf - plain `Key=Value` lines, no
/// sections, `#` comments.
pub fn nzbget_conf_value(conf: &str, key: &str) -> Option<String> {
    for line in conf.lines() {
        let line = line.trim();
        if line.starts_with('#') {
            continue;
        }
        if let Some((k, v)) = line.split_once('=')
            && k.trim() == key
        {
            let v = v.trim();
            if !v.is_empty() {
                return Some(v.to_string());
            }
        }
    }
    None
}

/// SAB's `password_file` (the archive-passwords list) rides the same
/// import: when the ini names one and the file is really there, record
/// it in the sibling settings.json so the daemon unpacks with it from
/// the next start. Never overwrites a path the user already saved -
/// their curation wins over a re-import.
fn adopt_password_file(ini: &str, out_path: &Path) {
    let Some(pw_path) = sab_ini_value(ini, "password_file") else {
        return;
    };
    if !Path::new(&pw_path).is_file() {
        return;
    }
    let wrote = edit_settings(out_path, "SABnzbd's password_file", |doc| {
        if doc
            .get("password_file")
            .and_then(serde_json::Value::as_str)
            .is_some_and(|p| !p.trim().is_empty())
        {
            return false;
        }
        doc["password_file"] = json!(pw_path);
        true
    });
    if wrote {
        println!("  adopted SABnzbd's archive passwords file: {pw_path}");
    }
}

/// `--arr`: the dashboard's "Sonarr, Radarr or another app drives it"
/// preset (`roleDefs()` in web/dashboard.html, the `arr` role), for an
/// install set up from the command line, which never sees that card
/// (GitHub #102). Key, value and stored type exactly as the card's Apply
/// writes them; `the_arr_preset_matches_the_dashboard_card` holds the two
/// copies together, so a row added to the card fails here until it is
/// added below.
///
/// Every key is a setup answer to the first-run API key test
/// (`SETUP_ANSWER_KEYS` in nzbfast-daemon's bootstrap.rs): this runs
/// before the daemon has, and a settings.json holding only these must
/// still mint a key.
pub const ARR_PRESET: &[(&str, ArrValue)] = &[
    ("dupe_action", ArrValue::Str("fail")),
    ("out_umask", ArrValue::Str("002")),
    ("arr_giveup_threshold", ArrValue::Num(3)),
    ("index_enabled", ArrValue::Bool(false)),
    ("spot_enabled", ArrValue::Bool(false)),
    ("auto_rename", ArrValue::Bool(false)),
    ("delete_to_trash", ArrValue::Bool(false)),
];

/// One [`ARR_PRESET`] value, in the type the daemon reads that key back
/// as (`dupe_action` and `out_umask` are strings, the threshold a
/// number, the rest switches).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ArrValue {
    Str(&'static str),
    Num(u64),
    Bool(bool),
}

impl ArrValue {
    fn json(self) -> serde_json::Value {
        match self {
            ArrValue::Str(s) => json!(s),
            ArrValue::Num(n) => json!(n),
            ArrValue::Bool(b) => json!(b),
        }
    }
}

/// Write [`ARR_PRESET`] into the sibling settings.json. A key the user
/// already saved is kept, exactly as the card leaves an unticked row
/// alone: the preset fills in, it never overrides.
fn adopt_arr_preset(out_path: &Path) {
    let mut set: Vec<&str> = Vec::new();
    let mut kept: Vec<&str> = Vec::new();
    let wrote = edit_settings(out_path, "the Sonarr/Radarr preset", |doc| {
        for (k, v) in ARR_PRESET {
            if doc.get(*k).is_some() {
                kept.push(k);
            } else {
                doc[*k] = v.json();
                set.push(k);
            }
        }
        !set.is_empty()
    });
    if wrote {
        println!(
            "  Sonarr/Radarr preset: set {} (finished downloads are left for the app to rename, file and clean up)",
            set.join(", ")
        );
    }
    if !kept.is_empty() {
        println!("  kept your own value for: {}", kept.join(", "));
    }
}

/// Load the sibling settings.json, let `edit` change it, and write it
/// back if `edit` says it did. Returns whether a write landed. `what`
/// names the change in the two refusal lines.
///
/// The daemon's own loader rules apply here too (review sweep 3 Aug
/// MH1): a torn primary with a good .bak must recover from the .bak,
/// and a store that exists but yields NOTHING must be refused - a raw
/// parse-to-{} would write a valid settings.json that the next daemon
/// start trusts, refreshing the .bak from it and permanently erasing
/// every other saved setting. (A daemon saving settings concurrently
/// can still race this CLI write; import-sab is a setup-time command
/// and documents running it with the daemon stopped.)
fn edit_settings(
    out_path: &Path,
    what: &str,
    edit: impl FnOnce(&mut serde_json::Value) -> bool,
) -> bool {
    let settings = out_path.with_file_name("settings.json");
    if crate::persist::json_store_unreadable(&settings) {
        println!(
            "  (not recording {what}: {} exists but won't parse - \
             fix or remove it first)",
            settings.display()
        );
        return false;
    }
    let mut doc = crate::persist::load_json_with_backup(&settings)
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    if !edit(&mut doc) {
        return false;
    }
    match serde_json::to_string_pretty(&doc)
        .map_err(anyhow::Error::from)
        .and_then(|s| crate::persist::write_atomic(&settings, s.as_bytes()).map_err(Into::into))
    {
        Ok(()) => true,
        Err(e) => {
            println!("  (could not record {what}: {e})");
            false
        }
    }
}

/// `--arr` on an install that already has a config, without `--force`
/// (GitHub #102 follow-up): apply ONLY the preset. The config at
/// `out_path` - its server list above all - is not read or written,
/// because a re-import replaces every server wholesale and drops what
/// was edited on them since (a `block_account` flag, say, which a
/// sabnzbd.ini has no way to carry). The ini is still the command's
/// argument and is still read, for the one thing taken from it here:
/// `password_file`, which, like the preset, only ever fills in a value
/// the user has not saved, so it behaves the same as on a full import.
/// No server, enabled or not, is required of the ini on this path.
fn apply_arr_preset_only(ini: &str, out_path: &Path) -> Result<()> {
    let shown = std::fs::canonicalize(out_path).unwrap_or_else(|_| out_path.to_path_buf());
    adopt_password_file(ini, out_path);
    adopt_arr_preset(out_path);
    println!(
        "{} already exists: applied the Sonarr/Radarr preset only and left its servers as they are",
        shown.display()
    );
    println!(
        "  pass --force to re-import the servers from the ini as well (that replaces the server list)"
    );
    println!("  a running nzbfast picks up the preset when you restart it");
    Ok(())
}

pub fn import(ini_path: &Path, out_path: &Path, force: bool, arr: bool) -> Result<()> {
    let text = std::fs::read_to_string(ini_path)
        .with_context(|| format!("reading {}", ini_path.display()))?;
    // Never write JSON at a `.ini` path, and `--force` does NOT lift
    // this one. `Config::load` picks its parser from exactly this
    // predicate, so a JSON body here would be fed to the SABnzbd ini
    // parser and come back NoServers - and the file overwritten is the
    // user's live sabnzbd.ini, which is very often the same file this
    // import is READING. Breaking both installs at once is not something
    // a flag named "overwrite the destination" asks for.
    //
    // `setup::write_servers` has carried this guard since it was written;
    // this sibling writer did not, and `--force` reached it.
    if out_path
        .extension()
        .is_some_and(|e| e.eq_ignore_ascii_case("ini"))
    {
        anyhow::bail!(
            "{} is a SABnzbd ini, which nzbfast reads but cannot write - \
             point --out at a JSON config such as config.local.json",
            out_path.display()
        );
    }
    if out_path.exists() && !force {
        if arr {
            return apply_arr_preset_only(&text, out_path);
        }
        anyhow::bail!(
            "{} already exists - pass --force to overwrite",
            out_path.display()
        );
    }
    let mut servers = parse_servers(&text);
    let skipped = servers.len();
    servers.retain(|s| s.enable && !s.host.is_empty());
    let skipped = skipped - servers.len();
    if servers.is_empty() {
        anyhow::bail!("no enabled servers found in {}", ini_path.display());
    }
    // SAB priority: lower number = preferred. Stable order within a tier.
    servers.sort_by_key(|s| s.priority);

    let json_servers: Vec<_> = servers
        .iter()
        .map(|s| {
            let mut o = json!({
                "host": s.host,
                "port": s.port.unwrap_or(if s.ssl { 563 } else { 119 }),
                "tls": s.ssl,
                // Same default as config.rs's own sabnzbd.ini loader: an
                // ini with no connections line must not import at 8 when
                // the direct-read fallback would run it at 100.
                "connections": s.connections.unwrap_or(nzbkit::config::default_connections()),
            });
            if let Some(u) = &s.username {
                o["username"] = json!(u);
            }
            if let Some(p) = &s.password {
                // Obfuscated on the way out. This map is built by hand rather
                // than serialized from a ServerConfig, so it does not get the
                // serde hook and has to call this itself. Obfuscation, not
                // encryption - and the RAW-INPUT encoder, because a
                // sabnzbd.ini password is cleartext whatever it starts with.
                o["password"] = json!(nzbkit::config::obfuscate_input(p));
            }
            // Tier + retention only when they say something. Omitting the
            // zero cases keeps a single-server import a minimal config, and
            // both fields are `#[serde(default)]` on ServerConfig.
            // `.max(0)`: a hand-edited negative priority would not
            // deserialize into our u32 `level`; clamping to 0 (primary) is
            // exactly what config.rs's ini loader already does with its
            // `parse::<u32>().unwrap_or(0)`, so both import paths agree.
            if s.priority > 0 {
                o["level"] = json!(s.priority.max(0) as u32);
            }
            if s.retention != 0 {
                o["retention_days"] = json!(s.retention);
            }
            o
        })
        .collect();

    // Replace `servers` in place rather than the whole document. --force used
    // to mean "write a file containing nothing but servers", which was
    // survivable while the default target was a cwd-relative
    // config.local.json that usually did not exist. It is not survivable now
    // that the default follows $NZBFAST_CONFIG onto the config the daemon is
    // actually serving from: re-running an import to pick up a new provider
    // would silently drop tmdb_key and any hand-added key alongside it.
    // Unparseable JSON is left to the wholesale write - there is nothing in
    // it we could preserve, and refusing would strand the user on a file they
    // asked us to overwrite.
    let mut doc = std::fs::read_to_string(out_path)
        .ok()
        .and_then(|s| serde_json::from_str::<serde_json::Value>(&s).ok())
        .filter(|v| v.is_object())
        .unwrap_or_else(|| json!({}));
    doc["servers"] = json!(json_servers);
    let cfg = serde_json::to_string_pretty(&doc)?;
    // 0600 via write_atomic, not fs::write's 0644: `cfg` holds every imported
    // provider's cleartext password, and on a shared box or a bind-mounted
    // /config every local user could read it. Same rule persist.rs already
    // states for state files that can hold credentials.
    crate::persist::write_atomic(out_path, cfg.as_bytes())
        .with_context(|| format!("writing {}", out_path.display()))?;
    adopt_password_file(&text, out_path);
    if arr {
        adopt_arr_preset(out_path);
    }
    for s in &servers {
        println!(
            "  imported {} → {}:{} ({} conns{}{}{}{})",
            s.name,
            s.host,
            s.port.unwrap_or(if s.ssl { 563 } else { 119 }),
            s.connections
                .unwrap_or(nzbkit::config::default_connections()),
            if s.ssl { ", tls" } else { "" },
            if s.username.is_some() { ", auth" } else { "" },
            // Say the tier out loud: the whole point of the fix is that a
            // backup account stays a backup account.
            if s.priority > 0 {
                format!(", level {}", s.priority.max(0) as u32)
            } else {
                String::new()
            },
            if s.retention != 0 {
                format!(", {}d retention", s.retention)
            } else {
                String::new()
            },
        );
    }
    if skipped > 0 {
        println!("  ({skipped} disabled/empty server(s) skipped)");
    }
    // #17: categories, and what could not come with them.
    //
    // The CLI writes a SERVER config; categories are daemon settings and
    // live in settings.json, which this command does not own. So it
    // reports rather than writes - a line the user can paste, and the
    // dashboard's own importer does the merging. Saying nothing here
    // would leave `import-sab` looking like it had migrated everything
    // when the *arrs are still about to fail their category check.
    let cats = nzbkit::config::parse_sabnzbd_categories(&text);
    if !cats.cats.is_empty() {
        let names: Vec<&str> = cats.cats.iter().map(|c| c.name.as_str()).collect();
        println!("\n{} categor(ies) found:", names.len());
        println!("  Categories:            {}", names.join(", "));
        let dirs: Vec<String> = cats
            .cats
            .iter()
            .filter_map(|c| c.dir.as_ref().map(|d| format!("{}={d}", c.name)))
            .collect();
        if !dirs.is_empty() {
            println!("  Per-category folders:  {}", dirs.join(", "));
        }
        println!("  Paste those into Settings, or press Import in the dashboard");
        println!("  to merge them for you. Sonarr and Radarr refuse to connect");
        println!("  while a category they are configured for is missing here.");
        for d in &cats.dropped {
            println!("  not imported: {d}");
        }
    }
    // Absolute, because the relative form is what made this land in the wrong
    // place unnoticed: "wrote config.local.json" from a /config cwd reads
    // exactly like success even when the daemon is serving another file.
    let shown = std::fs::canonicalize(out_path).unwrap_or_else(|_| out_path.to_path_buf());
    println!("wrote {} - verify with: nzbfast probe", shown.display());
    println!("  a running nzbfast keeps its old servers until you restart it");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const INI: &str = r#"
__version__ = 19
[misc]
host = 127.0.0.1
port = 8080
[servers]
[[news.example.com]]
host = news.example.com
port = 563
username = user@mail.com
password = "p@ss = word"
connections = 50
ssl = 1
priority = 1
enable = 1
[[fill.cheap.net]]
host = fill.cheap.net
port = 119
connections = 20
ssl = 0
priority = 0
enable = 1
[[old.dead.org]]
host = old.dead.org
enable = 0
[categories]
[[tv]]
name = tv
"#;

    #[test]
    fn parses_and_orders_servers() {
        let s = parse_servers(INI);
        assert_eq!(s.len(), 3);
        let mut live: Vec<_> = s.into_iter().filter(|s| s.enable).collect();
        live.sort_by_key(|s| s.priority);
        // priority 0 first (SAB: lower = preferred).
        assert_eq!(live[0].host, "fill.cheap.net");
        assert!(!live[0].ssl);
        assert_eq!(live[1].host, "news.example.com");
        assert_eq!(live[1].connections, Some(50));
        assert_eq!(live[1].password.as_deref(), Some("p@ss = word"));
        assert_eq!(live[1].username.as_deref(), Some("user@mail.com"));
    }

    /// A careful three-tier SAB setup: flatrate primary, a block account
    /// as backup, a short-retention filler last. Negative priority is a
    /// hand-edit we must survive.
    const INI_TIERS: &str = r#"
[servers]
[[primary]]
host = fast.primary.com
port = 563
connections = 50
ssl = 1
priority = 0
enable = 1
[[block]]
host = block.backup.net
port = 563
connections = 10
ssl = 1
priority = 1
enable = 1
[[filler]]
host = short.filler.org
port = 563
connections = 4
ssl = 1
priority = 2
retention = 1200
enable = 1
[[weird]]
host = hand.edited.example
port = 563
ssl = 1
priority = -5
enable = 1
"#;

    /// Regression: the importer used to drop SAB's `priority` and
    /// `retention`, landing every server as a co-equal level-0 primary
    /// with unlimited retention - block accounts burned on articles the
    /// primary holds. Tiers and retention must survive the round trip.
    #[test]
    fn import_preserves_tiers_and_retention() {
        let dir = std::env::temp_dir().join(format!("nzbfast-impsab-tiers-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(&ini, INI_TIERS).unwrap();
        let out = dir.join("config.local.json");
        import(&ini, &out, false, false).unwrap();

        // Raw JSON: zero-valued keys stay omitted so a plain single-server
        // import still writes a minimal config.
        let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        let arr = raw["servers"].as_array().unwrap();
        assert_eq!(arr.len(), 4);
        // [0] = the -5 hand-edit, [1] = the priority-0 primary: neither
        // may emit a `level` key at all.
        assert!(
            arr[0].get("level").is_none(),
            "negative priority must omit level"
        );
        assert!(arr[1].get("level").is_none(), "primary must omit level");
        assert!(
            arr[1].get("retention_days").is_none(),
            "no retention key = omit"
        );
        assert_eq!(arr[2]["level"], 1);
        assert_eq!(arr[3]["retention_days"], 1200);

        // Through the real loader: order by priority is unchanged, and the
        // tier/retention now actually reach the router.
        let cfg = nzbkit::config::Config::load(&out).unwrap();
        assert_eq!(cfg.servers.len(), 4);
        // priority -5 clamps to level 0 and still sorts first.
        assert_eq!(cfg.servers[0].host, "hand.edited.example");
        assert_eq!(cfg.servers[0].level, 0);
        assert_eq!(cfg.servers[1].host, "fast.primary.com");
        assert_eq!(cfg.servers[1].level, 0);
        assert_eq!(cfg.servers[1].retention_days, 0);
        assert_eq!(cfg.servers[2].host, "block.backup.net");
        assert_eq!(
            cfg.servers[2].level, 1,
            "block account must stay a backup tier"
        );
        assert_eq!(cfg.servers[3].host, "short.filler.org");
        assert_eq!(cfg.servers[3].level, 2);
        assert_eq!(cfg.servers[3].retention_days, 1200);

        // The ini loader reading the SAME file directly agrees - both
        // import paths converge on the same tiers.
        let direct = nzbkit::config::parse_sabnzbd_ini(INI_TIERS).unwrap();
        let mut direct: Vec<_> = direct
            .into_iter()
            .map(|s| (s.host, s.level, s.retention_days))
            .collect();
        direct.sort_by_key(|s| s.1);
        assert_eq!(direct[0].1, 0);
        assert!(direct.iter().any(|s| s.0 == "block.backup.net" && s.1 == 1));
        assert!(
            direct
                .iter()
                .any(|s| s.0 == "short.filler.org" && s.2 == 1200)
        );
        assert!(
            direct
                .iter()
                .any(|s| s.0 == "hand.edited.example" && s.1 == 0),
            "negative priority clamps to 0 on both paths"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn import_writes_config() {
        let dir = std::env::temp_dir().join(format!("nzbfast-impsab-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(&ini, INI).unwrap();
        let out = dir.join("config.local.json");
        import(&ini, &out, false, false).unwrap();
        // Round-trips through our real config loader.
        let cfg = nzbkit::config::Config::load(&out).unwrap();
        assert_eq!(cfg.servers.len(), 2);
        assert_eq!(cfg.servers[0].host, "fill.cheap.net");
        assert_eq!(cfg.servers[1].connections, 50);
        // Refuses to clobber without --force.
        assert!(import(&ini, &out, false, false).is_err());
        assert!(import(&ini, &out, true, false).is_ok());

        // ...and refuses an `.ini` TARGET whatever --force says. That
        // path is the SABnzbd config nzbfast reads and cannot write, and
        // it is very often the same file this import is reading: a JSON
        // body there comes back NoServers from the ini parser, so
        // --force used to break both installs at once. `write_servers`
        // has carried this guard since it was written; this writer did
        // not.
        //
        // NEGATIVE CONTROL, run: drop the extension guard and the second
        // assertion fails, having overwritten the ini.
        let sab = dir.join("live-sabnzbd.ini");
        std::fs::write(&sab, INI).unwrap();
        for force in [false, true] {
            assert!(
                import(&ini, &sab, force, false).is_err(),
                "an .ini target must be refused with force={force}"
            );
        }
        assert_eq!(
            std::fs::read_to_string(&sab).unwrap(),
            INI,
            "the SABnzbd ini must be byte-for-byte untouched"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Issue #8, second half: with the default target now following
    /// $NZBFAST_CONFIG onto the daemon's own config, a re-import must
    /// replace `servers` without taking the rest of the document with it.
    #[test]
    fn reimport_preserves_other_config_keys() {
        let dir = std::env::temp_dir().join(format!("nzbfast-impsab-merge-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(&ini, INI).unwrap();
        let out = dir.join("config.json");
        std::fs::write(
            &out,
            r#"{"servers":[{"host":"stale.example","port":119}],"tmdb_key":"keepme"}"#,
        )
        .unwrap();

        import(&ini, &out, true, false).unwrap();
        let raw: serde_json::Value = serde_json::from_slice(&std::fs::read(&out).unwrap()).unwrap();
        assert_eq!(
            raw["tmdb_key"], "keepme",
            "--force must not drop sibling keys"
        );
        let arr = raw["servers"].as_array().unwrap();
        assert_eq!(arr.len(), 2, "servers are replaced, not appended to");
        assert!(
            !arr.iter().any(|s| s["host"] == "stale.example"),
            "the previous server list must not survive the import"
        );

        // A file that is not JSON at all still gets overwritten rather than
        // erroring - there is nothing in it to preserve.
        std::fs::write(&out, "not json").unwrap();
        import(&ini, &out, true, false).unwrap();
        assert_eq!(nzbkit::config::Config::load(&out).unwrap().servers.len(), 2);

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn top_level_key_parsers() {
        // The [misc] key is found; a server's key of the same name in a
        // [[section]] is never mistaken for it.
        let ini = "[misc]\npassword_file = \"/data/pw.txt\"\n[servers]\n[[s1]]\npassword_file = red-herring\nhost = h\n";
        assert_eq!(
            sab_ini_value(ini, "password_file").as_deref(),
            Some("/data/pw.txt")
        );
        assert_eq!(
            sab_ini_value("[misc]\npassword_file =\n", "password_file"),
            None
        );
        let conf = "# UnpackPassFile=commented\nUnpackPassFile=/etc/pw.txt\nUnrarCmd=unrar\n";
        assert_eq!(
            nzbget_conf_value(conf, "UnpackPassFile").as_deref(),
            Some("/etc/pw.txt")
        );
        assert_eq!(nzbget_conf_value(conf, "Missing"), None);
    }

    /// SAB's password_file rides the import into the sibling
    /// settings.json - when the file really exists, and never over a
    /// path the user already saved.
    /// GitHub #102: `--arr` fills in the dashboard card's preset and
    /// keeps anything the user already saved, the way an unticked row on
    /// the card is left alone. Without the flag nothing is written.
    #[test]
    fn import_arr_applies_the_preset_and_keeps_saved_values() {
        let dir = std::env::temp_dir().join(format!("nzbfast-impsab-arr-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(&ini, INI).unwrap();
        let out = dir.join("config.json");
        let read = || -> serde_json::Value {
            serde_json::from_slice(&std::fs::read(dir.join("settings.json")).unwrap()).unwrap()
        };

        import(&ini, &out, true, false).unwrap();
        assert!(
            !dir.join("settings.json").exists(),
            "an import without --arr wrote settings"
        );

        import(&ini, &out, true, true).unwrap();
        let got = read();
        for (k, v) in ARR_PRESET {
            assert_eq!(got[*k], v.json(), "{k}");
        }
        assert_eq!(got["auto_rename"], false);
        assert_eq!(got["arr_giveup_threshold"], 3);

        std::fs::write(
            dir.join("settings.json"),
            r#"{"auto_rename":true,"out_umask":"022"}"#,
        )
        .unwrap();
        import(&ini, &out, true, true).unwrap();
        let got = read();
        assert_eq!(got["auto_rename"], true, "a saved value was overridden");
        assert_eq!(got["out_umask"], "022", "a saved value was overridden");
        assert_eq!(got["delete_to_trash"], false, "the rest still filled in");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// GitHub #102 follow-up: `--arr` on an install that already has a
    /// config, without `--force`, applies ONLY the preset. The config's
    /// bytes - its servers, and a flag on one that no sabnzbd.ini can
    /// carry - are untouched, saved settings are kept, and an ini with no
    /// usable server is no obstacle since none is imported. Without
    /// `--arr` the refusal stands and writes nothing at all.
    #[test]
    fn import_arr_on_an_existing_config_applies_only_the_preset() {
        let dir =
            std::env::temp_dir().join(format!("nzbfast-impsab-arr-only-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(&ini, INI).unwrap();
        let out = dir.join("config.json");
        let cfg = br#"{"servers":[{"host":"edited.example","port":563,"tls":true,"connections":20,"level":2,"block_account":true}],"tmdb_key":"k"}"#;
        std::fs::write(&out, cfg).unwrap();
        let settings = dir.join("settings.json");

        let err = import(&ini, &out, false, false).unwrap_err().to_string();
        assert!(err.contains("already exists"), "{err}");
        assert_eq!(
            std::fs::read(&out).unwrap(),
            cfg,
            "a refusal wrote the config"
        );
        assert!(!settings.exists(), "a refusal wrote settings");

        std::fs::write(&settings, r#"{"auto_rename":true,"port":7000}"#).unwrap();
        import(&ini, &out, false, true).unwrap();
        assert_eq!(
            std::fs::read(&out).unwrap(),
            cfg,
            "the preset-only path touched the config"
        );
        let got: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings).unwrap()).unwrap();
        for (k, v) in ARR_PRESET {
            if *k != "auto_rename" {
                assert_eq!(got[*k], v.json(), "{k}");
            }
        }
        assert_eq!(got["auto_rename"], true, "a saved value was overridden");
        assert_eq!(got["port"], 7000, "an unrelated setting was lost");

        // No enabled server in the ini: still fine, none is imported.
        std::fs::write(&ini, "[misc]\nport = 8080\n").unwrap();
        import(&ini, &out, false, true).unwrap();
        assert_eq!(std::fs::read(&out).unwrap(), cfg);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The CLI preset and the dashboard card are two copies of one list
    /// (the card is JavaScript, this is Rust), so this reads the card's
    /// `arr` rows out of the shipped page and requires the same keys and
    /// values. A row added to the card fails here until ARR_PRESET has it.
    /// The card holds FORM values - the threshold is `'3'`, which its
    /// setter parses and stores as a number - so a number is compared by
    /// value, quoted or not; the stored type is ARR_PRESET's to state.
    #[test]
    fn the_arr_preset_matches_the_dashboard_card() {
        let page = include_str!("../../../web/dashboard.html");
        let start = page
            .find("{id:'arr',")
            .expect("the dashboard lost its arr role - this test reads it");
        let rest = &page[start + 1..];
        let end = rest.find("{id:'").unwrap_or(rest.len());
        let block = &rest[..end];
        // Each row opens `{k:'<key>', id:'s_<key>', v:<value>` and the
        // value is a quoted string or a bare number.
        let card: Vec<(String, String)> = block
            .split("{k:'")
            .skip(1)
            .filter_map(|r| {
                let (key, tail) = r.split_once('\'')?;
                let v = tail.split_once("v:")?.1.trim_start();
                let v = match v.strip_prefix('\'') {
                    Some(q) => format!("'{}'", q.split_once('\'')?.0),
                    None => v.chars().take_while(char::is_ascii_digit).collect(),
                };
                Some((key.to_string(), v))
            })
            .collect();
        assert!(!card.is_empty(), "read no rows from the arr card");
        let ours: Vec<(String, String)> = ARR_PRESET
            .iter()
            .map(|(k, v)| {
                let v = match v {
                    ArrValue::Str(s) => format!("'{s}'"),
                    ArrValue::Num(n) => n.to_string(),
                    ArrValue::Bool(b) => u8::from(*b).to_string(),
                };
                (k.to_string(), v)
            })
            .collect();
        let numeric: Vec<&str> = ARR_PRESET
            .iter()
            .filter(|(_, v)| matches!(v, ArrValue::Num(_)))
            .map(|(k, _)| *k)
            .collect();
        let card: Vec<(String, String)> = card
            .into_iter()
            .map(|(k, v)| match numeric.contains(&k.as_str()) {
                true => (k, v.trim_matches('\'').to_string()),
                false => (k, v),
            })
            .collect();
        let mut a = card.clone();
        let mut b = ours.clone();
        a.sort();
        b.sort();
        assert_eq!(a, b, "the card's rows and ARR_PRESET disagree");
    }

    #[test]
    fn import_adopts_password_file() {
        let dir = std::env::temp_dir().join(format!("nzbfast-impsab-pw-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pw = dir.join("passwords.txt");
        std::fs::write(&pw, "secret1\n").unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(
            &ini,
            format!("[misc]\npassword_file = {}\n{INI}", pw.display()),
        )
        .unwrap();
        let out = dir.join("config.json");
        import(&ini, &out, true, false).unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["password_file"], pw.to_string_lossy().as_ref());

        // A user-saved path survives a re-import untouched.
        std::fs::write(
            dir.join("settings.json"),
            r#"{"password_file":"/my/own.txt"}"#, // a PATH, not a password - leakcheck-allow-synthetic
        )
        .unwrap();
        import(&ini, &out, true, false).unwrap();
        let settings: serde_json::Value =
            serde_json::from_slice(&std::fs::read(dir.join("settings.json")).unwrap()).unwrap();
        assert_eq!(settings["password_file"], "/my/own.txt");

        // A dangling path in the ini is ignored entirely.
        std::fs::remove_file(dir.join("settings.json")).unwrap();
        std::fs::remove_file(&pw).unwrap();
        import(&ini, &out, true, false).unwrap();
        assert!(
            !dir.join("settings.json").exists(),
            "dangling path must not be adopted"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }

    #[test]
    fn adopt_recovers_settings_from_backup_and_refuses_an_unreadable_store() {
        // Review sweep 3 Aug MH1: a torn settings.json with a good .bak
        // must never be replaced by a one-key file - the next daemon
        // start would trust the primary, refresh the .bak from it, and
        // every other saved setting would be gone for good.
        let dir = std::env::temp_dir().join(format!("nzbfast-impsab-mh1-{}", std::process::id()));
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir).unwrap();
        let pw = dir.join("passwords.txt");
        std::fs::write(&pw, "secret1\n").unwrap();
        let ini = dir.join("sabnzbd.ini");
        std::fs::write(
            &ini,
            format!("[misc]\npassword_file = {}\n{INI}", pw.display()),
        )
        .unwrap();
        let out = dir.join("config.json");
        let settings = dir.join("settings.json");

        // Torn primary, intact backup: adoption must merge into the
        // BACKUP's keys, not into {}.
        std::fs::write(&settings, "{\"completed_dir\": \"/mn").unwrap();
        std::fs::write(
            dir.join("settings.json.bak"),
            r#"{"completed_dir": "/mnt/done", "ui_locale": "de"}"#,
        )
        .unwrap();
        import(&ini, &out, true, false).unwrap();
        let doc: serde_json::Value =
            serde_json::from_slice(&std::fs::read(&settings).unwrap()).unwrap();
        assert_eq!(doc["completed_dir"], "/mnt/done", "backup keys preserved");
        assert_eq!(doc["ui_locale"], "de", "backup keys preserved");
        assert_eq!(doc["password_file"], pw.to_string_lossy().as_ref());

        // Torn primary and NO usable backup: refuse to touch the store
        // rather than defaulting it to one key.
        std::fs::write(&settings, "{\"completed_dir\": \"/mn").unwrap();
        std::fs::remove_file(dir.join("settings.json.bak")).unwrap();
        let before = std::fs::read(&settings).unwrap();
        import(&ini, &out, true, false).unwrap();
        assert_eq!(
            std::fs::read(&settings).unwrap(),
            before,
            "an unreadable store must be left untouched"
        );

        let _ = std::fs::remove_dir_all(&dir);
    }
}
