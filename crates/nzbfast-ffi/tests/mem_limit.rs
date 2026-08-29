//! `mem_limit_bytes` really reaches the engine's budget, and a silly
//! value is clamped rather than obeyed.
//!
//! ITS OWN TARGET, like `out_dir.rs`, `reclaim.rs` and `stop_bound.rs`
//! beside it, and for the reason those are: `ENGINE` is a
//! process-global, so two tests that start an engine in one binary see
//! each other's - `cargo test` runs the tests of ONE binary on threads
//! and nextest gives every test its own process, so the split is what
//! makes the answer the same under both.
//!
//! WHY THE ARGUMENT NEEDS A TEST AT ALL. It is the one parameter of
//! this ABI whose being wrong is INVISIBLE on every box this fleet
//! owns. A wrong `out_dir` puts files somewhere you can look; a wrong
//! port refuses to answer. A budget that quietly stayed at
//! `MemBudget::auto` - a quarter of physical RAM - runs a desktop and a
//! Simulator perfectly well, and shows up only as a phone the low-memory
//! killer takes during PAR2 repair, on hardware nothing here compiles
//! for. That is the same class as the gates CLAUDE.md's numbered list
//! keeps growing to catch, and this is the cheap version: ask the engine
//! what budget it is running under.

use std::ffi::CString;
use std::io::{Read, Write};
use std::time::{Duration, Instant};

/// A budget no `MemBudget::auto` could ever produce on any box this
/// runs on.
///
/// `auto` is RAM/4 clamped to [256 MB, 16 GB], so the only machine whose
/// auto answer is 256 MB is one with 1 GB of RAM or less - and even
/// there this figure differs. 300 MB is also inside the band the phone
/// profile picks from (192..512 MB), so the number under test is the
/// shape of the number that will really be passed.
const LIMIT: u64 = 300 * 1_000_000;

/// Below `MemBudget::MIN` (64 MB), so `with_total` must clamp it up.
const TOO_SMALL: u64 = 1;
const MIN_BUDGET: u64 = 64 << 20;

#[test]
fn the_mem_limit_argument_sets_the_budget_and_a_silly_one_is_clamped() {
    let port = free_port();
    let root = std::env::temp_dir().join(format!("nzbfast-ffi-memlimit-{port}"));
    let cfg_dir = root.join("state");
    std::fs::create_dir_all(&cfg_dir).expect("config dir");
    let key = "testkey";

    assert_eq!(
        budget_of(&cfg_dir, port, key, LIMIT),
        LIMIT,
        "the budget the engine reports must be the one the ABI was handed"
    );

    // A SECOND GENERATION, sequentially, which is what makes the clamp
    // arm honest: `with_total` is what holds a host's nonsense to the
    // engine's floor, and an arm that never runs is a claim nobody
    // checked. Start-after-stop is a supported cycle (see cycle.rs).
    let port2 = free_port();
    assert_eq!(
        budget_of(&cfg_dir, port2, key, TOO_SMALL),
        MIN_BUDGET,
        "a budget under the engine's own floor must be clamped UP to it, \
         never obeyed - every tier of a 1-byte budget rounds to nothing"
    );

    let _ = std::fs::remove_dir_all(&root);
}

/// Start an engine with `limit`, ask it what budget it is running under,
/// and stop it again.
///
/// `mode=stats` answers `host.rss_budget`, which is `Daemon`'s own
/// `mem_budget_total` - the figure `startup` took from the opts the
/// engine really constructed itself with. So this cannot pass on a
/// number that merely travelled as far as the ABI boundary.
fn budget_of(cfg_dir: &std::path::Path, port: u16, key: &str, limit: u64) -> u64 {
    // SEEDED HERE, BESIDE THE START, and not once in the caller. A
    // missing config is not "no config": `nzbkit::config::Config::load`
    // answers one by finding a SABnzbd install's `sabnzbd.ini` through
    // `$HOME`, so an unseeded start runs against whatever server list
    // the BOX has - the developer's on this fleet, none at all on a CI
    // runner (see `CONFIG_FILE`'s own note). Writing it in the function
    // that starts the engine is what makes that guarantee hold for
    // every generation rather than for whichever one the caller
    // happened to seed first, and it is what `tools/host-config-gate.py`
    // asks for.
    std::fs::write(
        cfg_dir.join(nzbfast_ffi::CONFIG_FILE),
        r#"{"servers":[{"host":"flat.example","enabled":true}]}"#,
    )
    .expect("seed config");
    let cfg_c = CString::new(cfg_dir.to_str().expect("utf8 dir")).unwrap();
    let key_c = CString::new(key).unwrap();
    assert_eq!(
        // SAFETY: both pointers come from `CString`s that live for the
        // whole call, so each is a valid NUL-terminated UTF-8 string for
        // its duration - the whole of `nzbfast_start`'s safety contract.
        // NULL for `out_dir` is explicitly allowed.
        unsafe {
            nzbfast_ffi::nzbfast_start(
                cfg_c.as_ptr(),
                std::ptr::null(),
                port,
                key_c.as_ptr(),
                limit,
            )
        },
        0,
        "start with mem_limit_bytes={limit}"
    );
    let deadline = Instant::now() + Duration::from_secs(30);
    loop {
        if http_body(port, &format!("/api?mode=version&output=json&apikey={key}"))
            .contains("version")
        {
            break;
        }
        assert!(Instant::now() < deadline, "mode=version never answered");
        std::thread::sleep(Duration::from_millis(100));
    }
    let body = http_body(port, &format!("/api?mode=stats&output=json&apikey={key}"));
    let got = rss_budget(&body)
        .unwrap_or_else(|| panic!("mode=stats carried no host.rss_budget, got: {body}"));
    assert_eq!(nzbfast_ffi::nzbfast_stop(), 0, "stop");
    got
}

/// Pull `rss_budget` out of a `mode=stats` body.
///
/// Scanned rather than deserialized because this crate has no JSON
/// dependency and adding one to read a single integer would put a
/// dependency in the SHIPPED staticlib's tree to serve a test.
fn rss_budget(body: &str) -> Option<u64> {
    let at = body.find("\"rss_budget\"")?;
    let rest = &body[at + "\"rss_budget\"".len()..];
    let rest = rest.trim_start().strip_prefix(':')?.trim_start();
    let end = rest.find(|c: char| !c.is_ascii_digit())?;
    rest[..end].parse().ok()
}

fn free_port() -> u16 {
    std::net::TcpListener::bind("127.0.0.1:0")
        .expect("probe port")
        .local_addr()
        .expect("addr")
        .port()
}

/// GET a path from the engine and hand back the body. A connection
/// refused while the listener is still coming up is not a failure - it
/// is what the readiness poll above is FOR - so it reads as an empty
/// body rather than a panic.
fn http_body(port: u16, path: &str) -> String {
    let Ok(mut s) = std::net::TcpStream::connect(("127.0.0.1", port)) else {
        return String::new();
    };
    let _ = s.set_read_timeout(Some(Duration::from_secs(5)));
    let req = format!("GET {path} HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    if s.write_all(req.as_bytes()).is_err() {
        return String::new();
    }
    let mut body = String::new();
    let _ = s.read_to_string(&mut body);
    body
}
