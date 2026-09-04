//! Exit when the test process that launched us is gone.
//!
//! WHY THIS EXISTS, MEASURED. On 2 Sep 2026 this machine was carrying
//! **70 leaked `nzbfast serve` processes**, every one a
//! `target/debug/nzbfast` started on 30 Aug 2026 between 22:28 and
//! 22:50 from three worktrees, listening on 127.0.0.1 ephemeral ports,
//! sharing provider accounts and CPU with every live lane for three
//! days. The census is in the dev repo's notes for that date, under the
//! leaked-test-daemons item.
//!
//! THE GAP THEY CAME THROUGH. `harness::KillOnDrop` kills and reaps the
//! child in `Drop`, which covers a normal end and a panicking unwind.
//! It cannot cover the case that actually happened: the TEST PROCESS
//! itself dying without unwinding. A `cargo nextest` run killed at the
//! terminal, a runner killed by pattern (CLAUDE.md invariant 2a is
//! about exactly that mistake), an OOM kill - in each of them the test
//! binary takes SIGKILL, no destructor anywhere runs, and every daemon
//! it spawned is reparented to launchd and serves forever.
//!
//! THE 2 AUG FIX COVERED THE DIRECTORY, NOT THE PROCESS, and the
//! evidence for that is in the census: `scratch::ScratchDir` (memory
//! topic `nzbfast-tmpdir-test-leak`, commit 16cf730b) had left ALL 69
//! fixture trees correctly removed - `--config` pointed at a
//! `config.json` that no longer existed for every single one - while
//! the daemons reading them were still up. Disk was reaped; processes
//! were not. Nothing on the harness side can close that, because the
//! harness is the thing that died.
//!
//! So the CHILD watches. A daemon spawned by a test binary is handed
//! [`ENV`] naming that binary's pid, and polls its own parent id: on
//! Unix a process whose parent dies is reparented to pid 1, so the
//! moment `parent_id()` stops being the pid we were told, our launcher
//! is gone and nothing will ever reap us. We exit.
//!
//! # Two properties this is built around
//!
//! **It arms only for a process that really is that pid's child.** The
//! variable is inherited by every descendant of the test binary, and a
//! daemon two levels down would be watching a pid that was never its
//! parent - so [`arm`] declines unless `parent_id()` ALREADY matches at
//! arm time. That also makes the variable inert in any in-process
//! caller of `serve()`: a unit test that reached this code with the
//! variable set would be watching nextest itself, and killing the test
//! process is the one outcome worse than the leak.
//!
//! **It cannot mistake a recycled pid for a live parent.** `parent_id()`
//! is answered by the kernel about THIS process, not by a lookup on a
//! number that another process could later be handed. A pid-liveness
//! probe (`kill(pid, 0)`) would have that hazard; this does not.
//!
//! # Stated limit: Unix only
//!
//! Windows has no `parent_id()` and no reparenting rule to read, so
//! [`arm`] is a no-op there and the leak class remains open on Windows.
//! That is a deliberate scope cut, not an oversight. The `integration`
//! binary DOES run on the `windows-unit` shards, but those are ephemeral
//! runner VMs that are destroyed with the job, so a daemon that outlives
//! its runner outlives it by minutes and costs nobody a provider slot.
//! The leak that cost three days of shared CPU was on the dev Mac. If a
//! Windows developer box ever grows the same pile, the shape to add is
//! `OpenProcess` + `WaitForSingleObject(h, 0)` on the watched pid behind
//! a `Win32_System_Threading` feature - with the pid-reuse false
//! negative that this Unix arm does not have.

/// Names the pid of the test binary that spawned us. Set by
/// `harness::spawn_under_test`, which is the single spawn chokepoint
/// every daemon-launching suite goes through; never set in production.
pub const ENV: &str = "NZBFAST_PARENT_WATCH";

/// How often the watchdog asks. The parent is dead either way, so the
/// only thing latency buys is how long a leaked daemon holds a port and
/// a provider slot before it lets go; half a second of that is free and
/// one `getppid` per half second is not measurable.
#[cfg(unix)]
const POLL: std::time::Duration = std::time::Duration::from_millis(500);

/// Exit status for "my launcher is gone".
///
/// Non-zero and distinctive on purpose. Nobody is waiting on it - the
/// process that would have is the one that died - so its whole job is to
/// be legible in a daemon log that somebody later fishes out of $TMPDIR.
/// A `0` here would read as an orderly shutdown that was asked for.
#[cfg(unix)]
const PARENT_GONE_EXIT: i32 = 70;

/// The pid [`ENV`] names, if it names one at all.
///
/// A malformed value is not an error worth failing a daemon over: this
/// is test plumbing, and the honest answer to "that is not a pid" is to
/// leave the watchdog off rather than to refuse to serve.
fn watched_pid(raw: Option<&str>) -> Option<u32> {
    raw?.trim().parse::<u32>().ok().filter(|p| *p > 0)
}

/// The whole decision, as a function of the two numbers it is made from:
/// the pid we were told to watch, and who our parent actually is.
///
/// Out of line so it can be tested against pids this process does not
/// have. Both call sites read it - the arm-time check and the poll -
/// because they are the same question asked at two moments, and a
/// version where they disagreed would arm and then exit immediately.
///
/// `cfg(any(unix, test))` because the only production caller is the Unix
/// arm below: on a Windows build with no test harness this would be dead
/// code, and `-D warnings` in the windows-clippy job makes dead code
/// fatal there. The tests still reach it on every platform.
#[cfg(any(unix, test))]
fn parent_is_ours(watched: u32, current_parent: u32) -> bool {
    watched == current_parent
}

/// Start watching, if we were launched by a test binary that asked us to.
///
/// Call once, as early in `main` as anything runs. Idempotence is not
/// required of callers and is not offered: a second call would start a
/// second watcher thread, which is harmless but pointless.
pub fn arm() {
    let raw = std::env::var(ENV).ok();
    let Some(watched) = watched_pid(raw.as_deref()) else {
        return;
    };
    #[cfg(unix)]
    {
        // Decline unless we are that process's child right now. See the
        // module note: this is what keeps an inherited variable from
        // arming a grandchild against a pid that was never its parent.
        if !parent_is_ours(watched, std::os::unix::process::parent_id()) {
            return;
        }
        // A plain thread, not a tokio task: this has to keep working
        // when every runtime worker is wedged, which is one of the
        // states a leaked daemon is found in.
        let spawned = std::thread::Builder::new()
            .name("parent-watch".into())
            .spawn(move || {
                loop {
                    std::thread::sleep(POLL);
                    if parent_is_ours(watched, std::os::unix::process::parent_id()) {
                        continue;
                    }
                    // Raw stderr, like the panic hook in main: this can
                    // run after the tracing subscriber is gone, and the
                    // line has to reach the daemon log either way.
                    eprintln!(
                        "[parentwatch] the test process {watched} that launched this daemon is \
                         gone; exiting rather than leaking a listener"
                    );
                    std::process::exit(PARENT_GONE_EXIT);
                }
            });
        // Spawning a thread can fail, and a daemon that cannot start a
        // watchdog is still a daemon somebody asked for. Say so and
        // serve.
        if spawned.is_err() {
            eprintln!("[parentwatch] could not start the watchdog thread; not watching {watched}");
        }
    }
    #[cfg(not(unix))]
    {
        // Named so the binding is not "unused" on Windows, and so the
        // stated limit above is visible at the site rather than only in
        // the module note.
        let _watched_but_unwatchable = watched;
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_missing_or_malformed_value_leaves_the_watchdog_off() {
        // The whole point of parsing leniently: none of these is worth
        // refusing to serve over, and every one of them must answer
        // "do not watch" rather than "watch pid 0".
        assert_eq!(watched_pid(None), None);
        assert_eq!(watched_pid(Some("")), None);
        assert_eq!(watched_pid(Some("nope")), None);
        assert_eq!(watched_pid(Some("-1")), None);
        assert_eq!(watched_pid(Some("12.5")), None);
        // Zero is parseable and is not a pid we can be the child of.
        assert_eq!(watched_pid(Some("0")), None);
    }

    #[test]
    fn a_pid_is_read_with_the_whitespace_a_shell_leaves_on_it() {
        assert_eq!(watched_pid(Some("1009")), Some(1009));
        assert_eq!(watched_pid(Some(" 1009\n")), Some(1009));
    }

    /// The arm-time guard, and the reason it is a guard rather than a
    /// tidiness check: a daemon two levels below the test binary
    /// inherits [`ENV`] just as its parent did, and a version without
    /// this would have it watching a pid that was never its parent - so
    /// it would exit the moment the intermediate process ended, which
    /// is nothing like the rule this module states.
    #[test]
    fn only_a_direct_child_of_the_watched_pid_arms() {
        assert!(parent_is_ours(1009, 1009), "our own launcher");
        assert!(
            !parent_is_ours(1009, 1),
            "reparented to init: this is the leak, and it must read as one"
        );
        assert!(
            !parent_is_ours(1009, 4242),
            "a grandchild's parent is the intermediate process, not the test binary"
        );
    }

    /// `arm()` with nothing in the environment must not start a thread
    /// or panic. This one runs IN PROCESS, so a regression that armed
    /// against nextest itself would take the whole test binary down
    /// rather than fail one line - which is the loudest possible report
    /// of the one mistake that would matter.
    #[test]
    fn arm_is_inert_with_no_environment_set() {
        // The variable is never set for a unit-test build, and this test
        // deliberately does not set it: `set_var` would race every other
        // test in the shared process (CLAUDE.md's `--bin nzbfast`
        // one-process note). If some future caller does set it, skip
        // rather than assert a world we did not build.
        if std::env::var_os(ENV).is_none() {
            arm();
        }
    }
}
