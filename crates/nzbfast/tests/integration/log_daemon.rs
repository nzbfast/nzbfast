//! The daemon half of what `log_split.rs` pins for the CLI.
//!
//! In `nzbfast serve` both fds are the same logtee pipe, so the
//! stderr/stdout split is invisible and the test next door has nothing
//! to say. What the daemon DOES promise, and what nothing else spawned a
//! process to check, is two things the dashboard's log pane and the
//! `NZBFAST_LOG` docs rest on:
//!
//! 1. `serve` selects `Style::Daemon`, so every line carries the
//!    `2026-08-02 14:03:11Z WARN  ` prefix. The formatter's unit tests in
//!    `logging.rs` render that prefix in-process; the dispatch in
//!    `main.rs` that picks the style per subcommand was covered by no
//!    test at all. A `serve` that fell through to `Style::Cli` would
//!    pass every `log.contains("[tag] ...")` in the daemon suite.
//! 2. `NZBFAST_LOG` is read, parsed, applied, and wins over `RUST_LOG`.
//!    Every daemon case sets `NZBFAST_LOG=info` - which is the default,
//!    so an `init` that ignored the variable entirely (dropped the
//!    `with_filter`, read the wrong name) would also pass every one of
//!    them. The unit tests pin `Targets` grammar, not the env read.
//!
//! One spawn checks all of it: `NZBFAST_LOG=warn` with `RUST_LOG=info`
//! deliberately set against it, a settings.json whose
//! `queue_finished_action` is a word nobody recognises (the one WARN
//! `startup.rs` emits deterministically before the ready banner), and
//! the `[settings] applying saved settings` INFO that is written BEFORE
//! that warning on the same path - so by the time the warning is in the
//! log, the INFO line's absence is a verdict and not a race.

use std::path::Path;
use std::process::{Child, Command, Stdio};
use std::time::Duration;

struct KillOnDrop(Child);
impl Drop for KillOnDrop {
    fn drop(&mut self) {
        let _ = self.0.kill();
        let _ = self.0.wait();
    }
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .unwrap()
        .local_addr()
        .unwrap()
        .port()
}

/// `2026-08-02 14:03:11Z WARN  ` - the daemon prefix, fixed width.
fn has_daemon_prefix(line: &str, level: &str) -> bool {
    let b = line.as_bytes();
    let stamp_ok = b.len() > 20
        && b[..20].iter().enumerate().all(|(i, c)| match i {
            4 | 7 => *c == b'-',
            10 => *c == b' ',
            13 | 16 => *c == b':',
            19 => *c == b'Z',
            _ => c.is_ascii_digit(),
        });
    stamp_ok && line[20..].starts_with(&format!(" {level:<5} ["))
}

#[test]
fn serve_stamps_its_lines_and_honours_nzbfast_log_over_rust_log() {
    let dir = std::env::temp_dir().join(format!("nzbfast-logdaemon-{}", std::process::id()));
    let _ = std::fs::remove_dir_all(&dir);
    std::fs::create_dir_all(&dir).unwrap();
    let cfg = dir.join("config.json");
    // No servers: nothing dials out, and the daemon holds its (empty)
    // queue rather than reading the host's SABnzbd ini, which is what a
    // MISSING config.json makes it do.
    std::fs::write(&cfg, "{\"servers\":[]}").unwrap();
    std::fs::write(
        dir.join("settings.json"),
        "{\"queue_finished_action\":\"teleport\"}",
    )
    .unwrap();

    let port = free_port();
    let log = dir.join("daemon.log");
    let out = std::fs::File::create(&log).unwrap();
    let err = out.try_clone().unwrap();
    let child = Command::new(env!("CARGO_BIN_EXE_nzbfast"))
        .env("NZBFAST_NO_ENRICH", "1")
        .env("NZBFAST_OPEN", "1")
        .env("NZBFAST_LOG", "warn")
        .env("RUST_LOG", "info")
        .arg("--config")
        .arg(&cfg)
        .arg("serve")
        .arg("--port")
        .arg(port.to_string())
        .arg("--bind")
        .arg("127.0.0.1")
        .arg("--out")
        .arg(dir.join("out"))
        .stdout(Stdio::from(out))
        .stderr(Stdio::from(err))
        .spawn()
        .unwrap();
    let _child = KillOnDrop(child);

    let warn = "[finish] ignoring saved queue_finished_action \"teleport\"";
    let mut text = String::new();
    for _ in 0..300 {
        text = std::fs::read_to_string(&log).unwrap_or_default();
        if text.contains(warn) {
            break;
        }
        std::thread::sleep(Duration::from_millis(100));
    }
    drop(_child);
    let _ = std::fs::remove_dir_all(Path::new(&dir));
    assert!(
        text.contains(warn),
        "never saw the startup warning:\n{text}"
    );

    let line = text.lines().find(|l| l.contains(warn)).unwrap();
    assert!(
        has_daemon_prefix(line, "WARN"),
        "serve must stamp and level its lines (Style::Daemon):\n{line}"
    );
    // Emitted before the warning, at INFO, on the same startup path:
    // present means the filter was not applied, or RUST_LOG won.
    let info = "[settings] applying saved settings";
    assert!(
        !text.contains(info),
        "NZBFAST_LOG=warn must suppress INFO (and beat RUST_LOG=info):\n{text}"
    );
    assert!(
        !text.lines().any(|l| has_daemon_prefix(l, "INFO")),
        "an INFO line got past NZBFAST_LOG=warn:\n{text}"
    );
}
