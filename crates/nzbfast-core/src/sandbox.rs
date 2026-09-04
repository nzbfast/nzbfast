//! One spawn wrapper for every child that runs code we did not write.
//!
//! TODO 314 stage 1, from `research/SANDBOX-SCOPING-2026-08.md` section
//! 3.5. The study's finding that sets this module's scope: every
//! in-process container parser in the tree is safe Rust with zero
//! `unsafe`, so the best security-per-week available is NOT another
//! worker split - it is confining the three things that are ALREADY
//! subprocesses and run proprietary or user-supplied code with the
//! download directory as their working directory:
//!
//!  * the external `unrar` fallback (`nzbfast-unpack`'s `rarfix.rs`) -
//!    the only closed-source C++ parser we invoke, with a live traversal
//!    and RCE history, handed the poster's bytes directly;
//!  * the external `par2` fallback (`nzbfast-unpack`'s
//!    `repair/extpar2.rs`);
//!  * the user's post-processing / pre-queue / queue-finished scripts
//!    (`nzbfast`'s `script.rs`, `prequeue.rs` and
//!    `finish_action.rs`).
//!
//! Every one of those goes through [`command`], so a fourth subprocess
//! added tomorrow inherits the policy by construction rather than by
//! somebody remembering. That is the point of the module: ONE rule, one
//! copy. It lives in `nzbfast-core` for the same reason: it is a leaf
//! that depends on nothing of ours, and three layers above it call it.
//!
//! # The two policies, and why there are two
//!
//! [`Policy::tool`] is the strict one. An archive tool has no business
//! reading `$HOME`, so it does not: on macOS the generated profile is
//! `(deny default)` with reads allowed only under the system prefixes
//! and the tool's own directory, writes allowed only under the job
//! directory, and no network at all. That matters because the daemon's
//! own config file holds the provider password in cleartext-equivalent
//! form (`config.rs:600` documents the `obf1:` wrapper as NOT
//! encryption), so a read-confined child cannot lift it and a
//! network-confined one could not post it anywhere if it did.
//!
//! [`Policy::script`] is deliberately weaker, and the difference is a
//! judgement rather than an oversight. A post-processing script is code
//! the USER installed: the two commonest kinds are a notifier (which
//! needs the network) and a library filer (which needs to read a media
//! tree and write outside the job directory). A policy that broke both
//! would be turned off wholesale, taking the part that is worth having
//! with it. So a confined script keeps its network and its reads, and
//! is write-confined to the directories the daemon already knows about:
//! the job, the download root, the move-completed destinations and the
//! watch folder. That still removes traversal writes and every
//! persistence trick (`~/.zshrc`, LaunchAgents, cron, the daemon's own
//! settings file), which is the half that turns a bad script into a
//! foothold. `script_confined` (default on) is the escape hatch for a
//! script that genuinely needs more.
//!
//! # Confinement is best-effort, always
//!
//! **A missing mechanism must never fail an unpack.** A user on a
//! minimal container image still gets their files. So [`detect`] runs
//! once, PROBES whatever it found by actually confining `/usr/bin/true`
//! with the same argv builder a real spawn uses, and falls back down a
//! ladder to plain unconfined spawning with one `warn!` line and a
//! settings-page health row. The probe is the load-bearing part: it
//! turns "this platform's mechanism is subtly different from the one we
//! tested" from a broken unpack into a declined confinement.
//!
//! `NZBFAST_SANDBOX=0` turns the whole module off (see
//! `docs/ENVIRONMENT.md`).
//!
//! # Stated limits
//!
//! * **The Windows arm confines NEITHER the filesystem NOR the
//!   network.** It is a job object and nothing else, so it bounds what
//!   the child IS (lifetime, process count, desktop and clipboard
//!   reach, crash dialogs) and says nothing about what it may OPEN. A
//!   hostile `unrar` under it can still read `config.json` and still
//!   post it somewhere. The health row is explicit about all three axes
//!   for exactly this reason - `reads_confined`, `writes_confined` and
//!   `network_confined` are all false there - and the settings-page
//!   sentence says it in words. Do not read `confined: true` on Windows
//!   as the confinement the macOS and Linux arms give.
//! * **What would close that gap, and why it is not here.** Write
//!   confinement on Windows means a LOW INTEGRITY token
//!   (`SetTokenInformation(TokenIntegrityLevel)` in the helper before it
//!   spawns, which needs no `CreateProcessAsUser` because a process may
//!   always lower its own), and a low-integrity child cannot write to a
//!   medium-integrity directory - so it also means stamping a low
//!   mandatory label on every directory the policy makes writable. For
//!   [`Policy::tool`] that is our own job directory and defensible; for
//!   [`Policy::script`] it is the user's library and watch folders, and
//!   labelling those is a product decision rather than an engineering
//!   one. Read confinement and network confinement need AppContainer,
//!   which the scoping study declined for the daemon and which for a
//!   child means capability SIDs and ACL grants on the same
//!   directories.
//!
//!   Those two are ONE piece of work and not two: an AppContainer token
//!   already runs at Low integrity, so AppContainer subsumes the
//!   low-integrity step rather than following it. And **do not read the
//!   `raw_attribute` limit below as blocking either of them** - that one
//!   is about the SEAM, where [`command`] hands back a
//!   `std::process::Command` and std is what cannot carry the attribute.
//!   The HELPER spawns the child itself, so it is free to call
//!   `CreateProcessW` with `STARTUPINFOEX` and
//!   `PROC_THREAD_ATTRIBUTE_SECURITY_CAPABILITIES` directly, and to
//!   lower its own token first. Reachable from there; not cheap, which
//!   is a different objection. Follow-on work, not oversights.
//! * **The Windows arm needs a HELPER PROCESS, and the helper is our own
//!   executable.** A job object is joined by the process that creates
//!   it or inherited from a parent already in one, and stable Rust
//!   cannot hand a job to `Command` at creation time
//!   (`CommandExt::raw_attribute`, which would carry
//!   `PROC_THREAD_ATTRIBUTE_JOB_LIST`, is unstable on the pinned
//!   1.98.0 - checked, not assumed). Putting the DAEMON in a
//!   kill-on-close job instead was rejected: every child would inherit
//!   it, including the browser launch and any future updater, and
//!   keeping those out would mean remembering `CREATE_BREAKAWAY_FROM_JOB`
//!   at each new spawn site, which is the by-remembering failure this
//!   module exists to remove. So [`command`] returns
//!   `<our exe> --nzbfast-confine <spec> <program> ...`, exactly the
//!   shape `sandbox-exec -p <profile> <program> ...` already has on
//!   macOS. In a TEST build our exe is the test binary and cannot
//!   answer, so [`detect`] falls back to the cargo layout and then
//!   declines - a skipped test, never a broken spawn.
//! * **A process that is ALREADY in a job cannot join a second one.**
//!   Measured on a native x86 box, 2 Sep 2026: the second
//!   `AssignProcessToJobObject` answers error 50,
//!   `ERROR_NOT_SUPPORTED`. Job membership is inherited, so a daemon
//!   launched by something that uses a job (some service wrappers and CI
//!   agents do) makes every helper unconfinable. That is why the probe
//!   sets `NZBFAST_CONFINE_REQUIRE=1`: the helper then refuses with
//!   [`windows::EXIT_NOT_CONFINED`] instead of running the child, so
//!   [`detect`] learns the difference. A REAL spawn never sets it and
//!   always degrades to running the child unconfined.
//! * **The macOS strict profile leans on an Apple SPI file.** A
//!   `(deny default)` profile that does not
//!   `(import "/System/Library/Sandbox/Profiles/bsd.sb")` aborts the
//!   child at dyld time (measured 2 Sep 2026 on macOS 27: exit 134 with
//!   the import removed, exit 0 with it). That file's own header warns
//!   it is private interface and may change. So its presence is checked
//!   at detect time and the strict shape degrades to the write-confining
//!   shape when it is gone - still no network, still no writes outside
//!   the job, but reads are no longer restricted.
//! * **No arm bounds CPU, memory or file descriptors, and only Windows
//!   bounds process count.** A hostile archive that makes `unrar` spin
//!   is bounded by the existing bomb gates and the script deadline, not
//!   by anything here. On Linux a `bwrap` child does get a fresh IPC and
//!   UTS namespace, which is not a resource bound either. The Windows
//!   job object caps the ACTIVE PROCESS count for a tool (not for a
//!   script, which may legitimately fan out) and turns an unhandled
//!   exception into an exit rather than a modal crash dialog nobody is
//!   at the console to dismiss. A job memory cap is deliberately NOT
//!   set: one low enough to matter would refuse a large archive the
//!   bomb gates already passed.
//! * **It does not bound what the child does with descriptors we hand
//!   it.** stdout and stderr are pipes the parent opened; the sandbox
//!   has nothing to say about writes to an already-open fd, which is
//!   exactly why a confined `par2 -q` still reports through our
//!   plumbing.
//! * **The macOS tool profile gives the child no temp directory.** A
//!   tool that insists on writing outside the job directory fails under
//!   it. Real `unrar` 7.23 and real `par2` 1.3.0 were both driven
//!   through it on 2 Sep 2026 and neither needed one. The Linux strict
//!   arm does better - `bwrap --tmpfs /tmp` costs nothing and gives the
//!   child a private one - and the asymmetry is deliberate: SBPL has no
//!   way to conjure a filesystem, only to permit paths that exist.
//! * **`unshare` (the Linux second rung) is network-only.** It buys no
//!   filesystem confinement at all, and the health row says which rung
//!   is in force so a reader is never left guessing.

use std::path::{Path, PathBuf};
use std::sync::OnceLock;
use tracing::warn;

/// The Apple-private profile a `(deny default)` sandbox needs before a
/// child can get through dyld. See the module doc's stated limits.
const BSD_PROFILE: &str = "/System/Library/Sandbox/Profiles/bsd.sb";

/// How a child is confined on this machine.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
// Each variant is constructed only by its OWN platform's
// `detect_uncached`, and no test constructs one (the health row reads a
// variant, it does not build one), so off that platform the lint fires
// in every build shape including --all-targets.
pub enum Mechanism {
    /// macOS: `sandbox-exec -p <generated profile>`.
    // Not #[expect]: built only under cfg(target_os = "macos"), so off
    // macOS the expectation would go unfulfilled and redden that build.
    #[cfg_attr(not(target_os = "macos"), allow(dead_code))]
    SandboxExec,
    /// Linux: `bwrap`, the least invasive of the namespace tools and
    /// the only rung that confines the filesystem as well as the
    /// network.
    // Not #[expect]: built only under cfg(target_os = "linux").
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    Bwrap,
    /// Linux: `unshare --user --map-current-user --net`. Network only -
    /// no filesystem confinement whatsoever.
    // Not #[expect]: built only under cfg(target_os = "linux").
    #[cfg_attr(not(target_os = "linux"), allow(dead_code))]
    UnshareNet,
    /// Windows: our own executable re-invoked as a job-object helper.
    /// Bounds the child's lifetime, process count, desktop reach and
    /// crash behaviour; confines neither the filesystem nor the
    /// network. See the module doc's stated limits before reading
    /// anything more into it.
    // Not #[expect]: built only under cfg(windows).
    #[cfg_attr(not(windows), allow(dead_code))]
    JobObject,
    /// Nothing available. Children are spawned exactly as they were
    /// before this module existed.
    None,
}

impl Mechanism {
    pub fn as_str(self) -> &'static str {
        match self {
            Mechanism::SandboxExec => "sandbox-exec",
            Mechanism::Bwrap => "bwrap",
            Mechanism::UnshareNet => "unshare",
            Mechanism::JobObject => "job-object",
            Mechanism::None => "none",
        }
    }
}

/// What [`detect`] settled on, and why - the health row reads this.
#[derive(Clone, Debug)]
pub struct Availability {
    pub mechanism: Mechanism,
    /// The wrapper binary, when there is one.
    pub wrapper: Option<PathBuf>,
    /// Whether the strict (read-confining) shape is usable. False on
    /// macOS without [`BSD_PROFILE`], and on every rung that cannot
    /// restrict reads at all. This is the health row's `reads_confined`.
    pub strict: bool,
    /// Whether a write outside the policy's directories is refused.
    ///
    /// SEPARATE from `strict` because the rungs disagree about it and
    /// one boolean cannot say so: `unshare` confines the network and
    /// NOTHING else, and the Windows job object confines neither. Both
    /// used to report the same `confined: true` a `bwrap` child does,
    /// which is the shape of over-claim this module is supposed to
    /// refuse.
    pub writes_confined: bool,
    /// Whether the child is denied sockets. Only ever true where the
    /// policy asked for it - a [`Policy::script`] keeps its network by
    /// design, so this describes the MECHANISM's reach, not one spawn.
    pub network_confined: bool,
    /// One sentence, written for a user reading the settings page.
    pub detail: String,
}

impl Availability {
    fn unavailable(detail: impl Into<String>) -> Self {
        Self {
            mechanism: Mechanism::None,
            wrapper: None,
            strict: false,
            writes_confined: false,
            network_confined: false,
            detail: detail.into(),
        }
    }
}

/// What a child may do. Built by [`Policy::tool`] or [`Policy::script`];
/// the two differ in exactly the ways the module doc explains.
#[derive(Clone, Debug)]
pub struct Policy {
    /// Names this policy in logs and in the health row.
    pub label: &'static str,
    /// Read AND write allowed under each of these.
    pub writable: Vec<PathBuf>,
    /// Read allowed under each of these, on top of the system prefixes.
    /// Ignored when `read_all` is set.
    pub readable: Vec<PathBuf>,
    /// Let the child read anything it could read unconfined.
    pub read_all: bool,
    /// Let the child open sockets.
    pub network: bool,
    /// Tear the child's sandbox down when the daemon dies. Wanted for a
    /// tool, NOT for a script: `nzbfast`'s `run_capped_inner` leaves a
    /// backgrounded descendant (`transcode &`) running past a clean
    /// exit, and this flag would kill it.
    pub tie_lifetime: bool,
}

impl Policy {
    /// An external archive tool: reads the poster's bytes, writes only
    /// where the job already is, and has no reason to touch the network
    /// or anything under `$HOME`.
    pub fn tool(label: &'static str, dir: &Path) -> Self {
        Self {
            label,
            writable: vec![resolve(dir)],
            readable: Vec::new(),
            read_all: false,
            network: false,
            tie_lifetime: true,
        }
    }

    /// The user's own script. Write-confined only - see the module doc
    /// for why this one is deliberately weaker than [`Self::tool`].
    pub fn script(writable: Vec<PathBuf>) -> Self {
        Self {
            label: "script",
            writable: writable.iter().map(|p| resolve(p)).collect(),
            readable: Vec::new(),
            read_all: true,
            network: true,
            tie_lifetime: false,
        }
    }

    /// Let the child read under `dir` as well. Symlinks are resolved the
    /// same way the constructors do - see [`resolve`].
    pub fn allow_read(&mut self, dir: &Path) {
        let dir = resolve(dir);
        if !self.readable.contains(&dir) {
            self.readable.push(dir);
        }
    }
}

/// A path as the KERNEL will see it, which is the only spelling a
/// sandbox rule matches.
///
/// This is not tidiness, it is the difference between a rule that binds
/// and one that silently does nothing: `std::env::temp_dir()` on macOS
/// answers `/var/folders/...`, and `/var` is a symlink to `/private/var`,
/// so a `(subpath "/var/folders/x")` rule never matches the resolved
/// path the child actually opens. `/tmp` -> `/private/tmp` is the same
/// trap and it is where every test scratch directory lives.
///
/// A path that does not exist yet (a move-completed destination on a
/// share that is not mounted) canonicalizes as far as it can and keeps
/// the rest verbatim, so the rule is still the best available spelling
/// rather than nothing at all.
fn resolve(p: &Path) -> PathBuf {
    if let Ok(c) = std::fs::canonicalize(p) {
        return c;
    }
    let mut rest: Vec<&std::ffi::OsStr> = Vec::new();
    let mut cur = p;
    while let Some(parent) = cur.parent() {
        let Some(name) = cur.file_name() else { break };
        rest.push(name);
        if let Ok(c) = std::fs::canonicalize(parent) {
            let mut out = c;
            for name in rest.iter().rev() {
                out.push(name);
            }
            return out;
        }
        cur = parent;
    }
    p.to_path_buf()
}

/// Every path this policy names, writable first. Used by both argv
/// builders and by the UTF-8 check.
fn all_paths(policy: &Policy) -> impl Iterator<Item = &PathBuf> {
    policy.writable.iter().chain(policy.readable.iter())
}

// Every platform arm compiles everywhere so its profile/argv builder is
// unit-tested everywhere; only its dispatch runs on its own OS.
//
// Not #[expect]: `sandbox_tests` drives both builders, so under
// --all-targets these modules are live on EVERY host and an expectation
// here would go unfulfilled in exactly the shape CI's clippy gate runs.
// The lint fires only in a plain build off the module's own platform.
#[cfg_attr(not(target_os = "macos"), allow(dead_code))]
pub mod mac {
    use super::{Policy, all_paths};
    use std::path::Path;

    /// Escape a path for an SBPL string literal. Backslash and double
    /// quote are the only two characters that can end the literal early.
    fn sbpl_escape(s: &str) -> String {
        s.replace('\\', "\\\\").replace('"', "\\\"")
    }

    /// Read-only prefixes a `(deny default)` profile must grant or the
    /// child cannot load a dylib. `/private/var/db` carries the dyld
    /// closure cache; `/private/var/folders` is deliberately absent, so
    /// a confined tool gets no view of the user's per-user temp tree.
    pub const SYSTEM_READ: &[&str] = &[
        "/usr",
        "/bin",
        "/sbin",
        "/System",
        "/Library",
        "/opt",
        "/etc",
        "/private/etc",
        "/private/var/db",
        "/dev",
    ];

    /// The `sandbox-exec` profile for `policy`, or `None` when a path in
    /// it is not valid UTF-8 (SBPL has no way to spell such a literal,
    /// and a lossy conversion would silently confine a DIFFERENT
    /// directory - the one failure mode a sandbox must not have).
    ///
    /// `bsd_profile` says whether [`super::BSD_PROFILE`] is on this
    /// machine; with it false the strict shape is not attempted at all,
    /// because without that import a `(deny default)` profile aborts the
    /// child at dyld time.
    pub fn profile(program: &Path, policy: &Policy, bsd_profile: bool) -> Option<String> {
        if all_paths(policy).any(|p| p.to_str().is_none()) || program.to_str().is_none() {
            return None;
        }
        let strict = !policy.read_all && bsd_profile;
        let mut p = String::from("(version 1)\n");
        if strict {
            p.push_str("(deny default)\n");
            p.push_str(&format!("(import \"{}\")\n", super::BSD_PROFILE));
            // dyld maps the executable and every dylib behind it;
            // without this a `(deny default)` profile aborts the child
            // (SIGABRT, exit 134) before `main` runs. Measured 2 Sep
            // 2026 on macOS 27 against real unrar 7.23.
            p.push_str("(allow file-map-executable)\n");
            p.push_str("(allow process-exec*)\n(allow process-fork)\n");
            p.push_str("(allow file-read*\n");
            for dir in SYSTEM_READ {
                p.push_str(&format!("  (subpath \"{dir}\")\n"));
            }
            // The tool's own directory: a sibling-to-nzbfast binary, or
            // a package prefix that is not on the list above.
            if let Some(parent) = program.parent().and_then(Path::to_str)
                && !parent.is_empty()
            {
                p.push_str(&format!("  (subpath \"{}\")\n", sbpl_escape(parent)));
            }
            for dir in &policy.readable {
                p.push_str(&format!("  (subpath \"{}\")\n", sbpl_escape(dir.to_str()?)));
            }
            p.push_str(")\n");
        } else {
            p.push_str("(allow default)\n");
            p.push_str("(deny file-write*)\n");
        }
        if !policy.network {
            p.push_str("(deny network*)\n");
        }
        for dir in &policy.writable {
            p.push_str(&format!(
                "(allow file-read* file-write* (subpath \"{}\"))\n",
                sbpl_escape(dir.to_str()?)
            ));
        }
        // The child's own stdio and the null sink. Everything else under
        // /dev stays read-only.
        p.push_str("(allow file-write-data (literal \"/dev/null\"))\n");
        Some(p)
    }

    /// `sandbox-exec -p <profile> <program>`, with the program's own
    /// arguments still to be appended by the caller.
    pub fn wrap(exec: &Path, profile: &str, program: &Path) -> std::process::Command {
        let mut c = std::process::Command::new(exec);
        c.arg("-p").arg(profile).arg(program);
        c
    }
}

// Not #[expect]: same as `mod mac` above - live under --all-targets on
// every host, dead only in a plain build off Linux.
#[cfg_attr(not(target_os = "linux"), allow(dead_code))]
pub mod linux {
    use super::Policy;
    use std::ffi::OsString;
    use std::path::Path;

    /// Read-only binds a strict `bwrap` sandbox grants. `-try`
    /// throughout: a distribution that has folded `/bin` into `/usr`
    /// must not make the whole invocation fail.
    pub const SYSTEM_READ: &[&str] = &[
        "/usr", "/bin", "/sbin", "/lib", "/lib32", "/lib64", "/etc", "/opt",
    ];

    /// The `bwrap` arguments for `policy`, up to and including the `--`
    /// that ends them. The program and its own arguments follow.
    pub fn bwrap_args(policy: &Policy) -> Vec<OsString> {
        let mut a: Vec<OsString> = Vec::new();
        if policy.tie_lifetime {
            a.push("--die-with-parent".into());
        }
        if !policy.network {
            a.push("--unshare-net".into());
        }
        // Namespaces that cost nothing and remove a signalling channel.
        // NOT `--unshare-pid`: with it bwrap becomes pid 1 of the
        // namespace and tearing the sandbox down kills a script's
        // deliberately backgrounded descendant, which
        // `nzbfast`'s `run_capped_inner` documents as something a
        // post-script is
        // allowed to do.
        a.push("--unshare-ipc".into());
        a.push("--unshare-uts".into());
        if policy.read_all {
            a.push("--ro-bind".into());
            a.push("/".into());
            a.push("/".into());
        } else {
            for dir in SYSTEM_READ {
                a.push("--ro-bind-try".into());
                a.push(dir.into());
                a.push(dir.into());
            }
            for dir in &policy.readable {
                a.push("--ro-bind-try".into());
                a.push(dir.into());
                a.push(dir.into());
            }
        }
        // Over the top of whatever the binds above laid down: later
        // operations win in bwrap, so the ORDER here is the policy.
        a.push("--proc".into());
        a.push("/proc".into());
        a.push("--dev".into());
        a.push("/dev".into());
        if !policy.read_all {
            // A PRIVATE /tmp for the strict arm, which binds nothing
            // writable outside the job. It costs nothing (the tmpfs is
            // the child's alone and goes with it) and it removes the one
            // failure this policy could plausibly cause: a tool that
            // insists on a scratch file somewhere other than its working
            // directory. The macOS profile has no equivalent and is
            // measured rather than assumed - real unrar and real par2
            // both run under it with no temp of any kind. The script arm
            // needs none: `--ro-bind / /` plus the writable set already
            // carries the system temp directory.
            a.push("--tmpfs".into());
            a.push("/tmp".into());
        }
        for dir in &policy.writable {
            a.push("--bind-try".into());
            a.push(dir.into());
            a.push(dir.into());
        }
        a.push("--".into());
        a
    }

    /// The `unshare` arguments for the network-only rung. A user
    /// namespace is what makes this work without privilege;
    /// `--map-current-user` keeps the uid the files are owned by.
    pub fn unshare_args(policy: &Policy) -> Vec<OsString> {
        let mut a: Vec<OsString> = vec!["--user".into(), "--map-current-user".into()];
        if !policy.network {
            a.push("--net".into());
        }
        a.push("--".into());
        a
    }

    /// What the settings row says when NEITHER wrapper is on `$PATH`.
    ///
    /// "on `$PATH`", not "installed", and that distinction is the whole
    /// reason the two builders below this one exist: until 2 Sep 2026
    /// this one string was ALSO what a box with bubblewrap installed and
    /// refused was told, which sends its owner to `apt install
    /// bubblewrap` and then nowhere.
    pub const NOTHING_INSTALLED: &str =
        "neither bwrap nor unshare is on $PATH - install bubblewrap to confine these processes";

    /// One line of a refused probe's stderr, fit for a settings row.
    ///
    /// The LAST non-empty line: a wrapper prints its fatal reason last,
    /// and the `--ro-bind-try` arms that skipped a directory this
    /// distribution folded away print nothing at all. Control characters
    /// go, and the line is capped, because a wrapper we did not write
    /// owns this wording and it is rendered into a page.
    pub fn probe_reason(stderr: &str) -> Option<String> {
        const CAP: usize = 160;
        let line = stderr
            .lines()
            .rev()
            .map(str::trim)
            .find(|l| !l.is_empty())?;
        // A control byte becomes a SPACE and runs of space collapse:
        // dropping a tab outright would join the two words it separated.
        // An escape SEQUENCE is only half-removed by this (the escape
        // goes, `[31m` stays) and that is deliberate - parsing another
        // program's colour codes to tidy a diagnostic is not worth a
        // parser, and neither bwrap nor unshare colours its errors.
        let kept = line
            .chars()
            .map(|c| if c.is_control() { ' ' } else { c })
            .collect::<String>()
            .split_whitespace()
            .collect::<Vec<_>>()
            .join(" ");
        if kept.is_empty() {
            return None;
        }
        Some(match kept.char_indices().nth(CAP) {
            Some((cut, _)) => format!("{}...", &kept[..cut]),
            None => kept,
        })
    }

    /// Why `bwrap` was found and then not used.
    ///
    /// **Measured 2 Sep 2026 on Ubuntu 24.04.4** (kernel 6.8.0-137,
    /// bubblewrap 0.9.0, apparmor 4.0.1, a non-root user): the argv
    /// [`bwrap_args`] builds answers rc=1 and
    /// `bwrap: loopback: Failed RTM_NEWADDR: Operation not permitted`.
    /// `kernel.apparmor_restrict_unprivileged_userns` is 1 on that
    /// release and an unconfined binary creating a user namespace
    /// transitions into the shipped `unprivileged_userns` profile, whose
    /// first line is `audit deny capability` - so bwrap gets its
    /// namespace and no capability inside it, and bringing loopback up
    /// in its own network namespace is refused. `dpkg -L bubblewrap |
    /// grep -i apparmor` returns nothing, so the package ships no
    /// profile of its own. Adding the four lines named below took the
    /// IDENTICAL argv to rc=0, and removing them took it back to rc=1.
    /// Ubuntu is the outlier - Debian, Fedora and Arch allow this - but
    /// it is also the commonest seedbox and home-server distribution.
    pub fn bwrap_refused(bwrap: &Path, stderr: &str) -> String {
        let mut s = format!(
            "bwrap is installed at {} but a test sandbox would not start",
            bwrap.display()
        );
        if let Some(why) = probe_reason(stderr) {
            s.push_str(&format!(" ({why})"));
        }
        s.push_str(
            ", so unrar, par2 and scripts run unconfined. On Ubuntu 24.04 and later this is \
             AppArmor refusing capabilities inside an unprivileged user namespace: add a \
             four-line /etc/apparmor.d/bwrap naming that binary, in the shape of the \
             /etc/apparmor.d/flatpak the system already ships, then run apparmor_parser -r on \
             it. Under systemd, a RestrictNamespaces, RestrictAddressFamilies or \
             SystemCallFilter setting too tight for bwrap refuses it the same way.",
        );
        s
    }

    /// Why `unshare` was found and then not used. Only ever reached with
    /// no usable `bwrap`, so the remedy names both halves.
    ///
    /// Measured beside the bwrap case above, same box, same day:
    /// `unshare --user --map-current-user --net -- /usr/bin/true`
    /// answers rc=1 and `unshare: write failed /proc/self/uid_map:
    /// Operation not permitted`. The `/etc/apparmor.d/bwrap` profile
    /// does NOT fix this rung, because it names bwrap and not unshare;
    /// installing bubblewrap and profiling it is what restores
    /// confinement on such a box.
    pub fn unshare_refused(unshare: &Path, stderr: &str) -> String {
        let mut s = format!(
            "unshare is installed at {} but a test sandbox would not start",
            unshare.display()
        );
        if let Some(why) = probe_reason(stderr) {
            s.push_str(&format!(" ({why})"));
        }
        s.push_str(
            ", so unrar, par2 and scripts run unconfined. This machine refuses unprivileged \
             user namespaces. On Ubuntu 24.04 and later, install bubblewrap and give it a \
             four-line /etc/apparmor.d/bwrap profile in the shape of the \
             /etc/apparmor.d/flatpak the system already ships.",
        );
        s
    }
}

// The builders and the spec codec compile and are tested on EVERY host,
// for the same reason `mod mac` and `mod linux` are; only `apply` and
// the dispatch are Windows-only, because only they touch the API.
//
// Not #[expect]: `sandbox_tests` drives the builders everywhere, so
// under --all-targets this module is live on every host.
#[cfg_attr(not(windows), allow(dead_code))]
pub mod windows {
    use super::Policy;
    use std::ffi::OsString;

    /// The helper's first argument. Long and branded on purpose: it is
    /// prepended to a command line that otherwise belongs to `unrar`,
    /// `par2` or a user's script, and it must never be mistakable for
    /// one of theirs.
    pub const CONFINE_FLAG: &str = "--nzbfast-confine";

    /// Set by [`super::detect`]'s probe and by NOTHING else.
    ///
    /// With it the helper REFUSES to run the child when it could not
    /// establish the job object, exiting [`EXIT_NOT_CONFINED`]. Without
    /// it - which is every real spawn - the helper runs the child
    /// unconfined instead, because a missing mechanism must never fail
    /// an unpack. That split is the whole reason the probe can tell
    /// "confined" from "ran anyway", and it is why the probe's ARGV is
    /// still identical to a real spawn's.
    pub const REQUIRE_ENV: &str = "NZBFAST_CONFINE_REQUIRE";

    /// The helper's answer to `REQUIRE_ENV` when it could not confine.
    ///
    /// Chosen high and odd so it cannot be read as a tool's own verdict:
    /// `par2cmdline` exits 0 to 8, `unrar` 0 to 11, and the sysexits
    /// range a shell reports tops out at 78. Only the probe ever sees
    /// it.
    pub const EXIT_NOT_CONFINED: i32 = 231;

    /// The helper's answer when the child could not be spawned at all.
    /// [`super::locate`] resolves the program before anything is
    /// wrapped, so reaching this means the file went away in between.
    /// 127 is the shell's own "not found", which is the nearest true
    /// thing to say.
    pub const EXIT_NO_CHILD: i32 = 127;

    /// A tool may hold this many processes at once. Generous: `unrar`
    /// and `par2` each spawn nothing, so the cap exists to bound a
    /// compromised one rather than to fit a measured need.
    pub const TOOL_ACTIVE_PROCESSES: u32 = 64;

    /// What the helper is asked to put on the job object.
    ///
    /// Deliberately small and dumb. Everything a job object can express
    /// that this module wants is three facts, and a spec a human can
    /// read in a process listing is worth more here than a compact one.
    #[derive(Clone, Copy, PartialEq, Eq, Debug)]
    pub struct Limits {
        /// `JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE`. The child dies when the
        /// helper does, which is [`Policy::tie_lifetime`] exactly:
        /// measured both ways on a native x86 box, 2 Sep 2026 - with the
        /// flag the child stopped beating the instant the helper exited,
        /// without it it ran its full span.
        pub tie: bool,
        /// The `JOBOBJECT_BASIC_UI_RESTRICTIONS` set: no desktop switch,
        /// no display-settings change, no `ExitWindows`, no global
        /// atoms, no USER handles belonging to processes outside the
        /// job, and no clipboard either way.
        ///
        /// OFF for a script, and for the same reason a script keeps its
        /// network: a user's post-processing script may legitimately
        /// drive a window that the daemon did not start, and a
        /// confinement that broke that would be switched off wholesale.
        pub ui: bool,
        /// `JOB_OBJECT_LIMIT_ACTIVE_PROCESS`, or 0 for no cap. A script
        /// gets no cap: fanning out is what a post-processing chain
        /// does.
        pub procs: u32,
    }

    /// The limits `policy` asks for.
    ///
    /// `read_all` is the strict/permissive discriminator here for the
    /// same reason `linux::bwrap_args` uses it: it is the field the two
    /// constructors disagree on that means "this is a tool, not the
    /// user's own code".
    pub fn limits(policy: &Policy) -> Limits {
        let tool = !policy.read_all;
        Limits {
            tie: policy.tie_lifetime,
            ui: tool,
            procs: if tool { TOOL_ACTIVE_PROCESSES } else { 0 },
        }
    }

    /// The wire form of [`Limits`], as the helper receives it.
    ///
    /// Versioned because the helper is resolved rather than linked: in a
    /// test build it may be a `nzbfast.exe` beside the test binary and
    /// not this build at all, and a spec a stale helper half-understands
    /// would confine less than the caller believes. An unknown tag is
    /// refused outright.
    pub fn spec(l: &Limits) -> String {
        format!(
            "v1:tie={},ui={},procs={}",
            u8::from(l.tie),
            u8::from(l.ui),
            l.procs
        )
    }

    /// [`spec`]'s inverse. `None` for anything it did not write - a
    /// missing field, an unknown tag, a value it cannot read. Strict on
    /// purpose: a spec that half-parses is a confinement nobody can
    /// describe.
    pub fn parse_spec(text: &str) -> Option<Limits> {
        let body = text.strip_prefix("v1:")?;
        let (mut tie, mut ui, mut procs) = (None, None, None);
        for field in body.split(',') {
            let (k, v) = field.split_once('=')?;
            match k {
                "tie" => tie = Some(bit(v)?),
                "ui" => ui = Some(bit(v)?),
                "procs" => procs = Some(v.parse().ok()?),
                _ => return None,
            }
        }
        Some(Limits {
            tie: tie?,
            ui: ui?,
            procs: procs?,
        })
    }

    fn bit(v: &str) -> Option<bool> {
        match v {
            "0" => Some(false),
            "1" => Some(true),
            _ => None,
        }
    }

    /// The helper arguments for `policy`, up to but not including the
    /// program. The program and its own arguments follow, so everything
    /// the caller appends still lands after the program.
    pub fn confine_args(policy: &Policy) -> Vec<OsString> {
        vec![CONFINE_FLAG.into(), spec(&limits(policy)).into()]
    }

    /// `<helper> --nzbfast-confine <spec> <program>`, with the program's
    /// own arguments still to be appended by the caller. The same shape
    /// as `mac::wrap`.
    pub fn wrap(
        helper: &std::path::Path,
        args: &[OsString],
        program: &std::path::Path,
    ) -> std::process::Command {
        let mut c = std::process::Command::new(helper);
        c.args(args).arg(program);
        c
    }

    /// Put THIS process in a fresh job object carrying `l`.
    ///
    /// The helper calls this and then spawns the child with an ordinary
    /// [`std::process::Command`]: a child inherits its parent's job, so
    /// the child lands inside it with no handle passing and no
    /// `CREATE_SUSPENDED` window in which it is running but unconfined.
    ///
    /// **The job handle is deliberately never closed.**
    /// `KILL_ON_JOB_CLOSE` fires when the LAST handle to the job goes,
    /// so holding it open until the helper exits IS the mechanism, not
    /// a leak. Process exit closes it and takes the child with it. The
    /// error paths drop it the same way and that is harmless: nothing
    /// was ever assigned to the job, so closing it kills nothing, and
    /// the helper is about to run one child and exit either way.
    #[cfg(windows)]
    pub fn apply(l: &Limits) -> Result<(), String> {
        use std::mem::size_of;
        use windows_sys::Win32::Foundation::GetLastError;
        use windows_sys::Win32::System::JobObjects::*;
        use windows_sys::Win32::System::Threading::GetCurrentProcess;

        // SAFETY: every call below is a plain Win32 entry point taking
        // either null (no security attributes, no job name) or a
        // pointer to a live, fully initialised local of exactly the
        // struct the information class names, with its own `size_of` as
        // the length. `GetCurrentProcess` returns a pseudo-handle that
        // needs no release. Each result is checked before the next call
        // uses it, so no failed handle is ever passed on.
        unsafe {
            let job = CreateJobObjectW(std::ptr::null(), std::ptr::null());
            if job.is_null() {
                return Err(format!("CreateJobObjectW failed ({})", GetLastError()));
            }
            let mut li: JOBOBJECT_EXTENDED_LIMIT_INFORMATION = std::mem::zeroed();
            // An unhandled exception becomes an exit rather than a modal
            // Windows Error Reporting dialog. There is nobody at the
            // console of a daemon box to dismiss one, and a hostile
            // archive that crashes `unrar` would otherwise wedge the
            // unpack until somebody logged in.
            li.BasicLimitInformation.LimitFlags = JOB_OBJECT_LIMIT_DIE_ON_UNHANDLED_EXCEPTION;
            if l.tie {
                li.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE;
            }
            if l.procs > 0 {
                li.BasicLimitInformation.LimitFlags |= JOB_OBJECT_LIMIT_ACTIVE_PROCESS;
                li.BasicLimitInformation.ActiveProcessLimit = l.procs;
            }
            if SetInformationJobObject(
                job,
                JobObjectExtendedLimitInformation,
                std::ptr::addr_of!(li).cast(),
                size_of::<JOBOBJECT_EXTENDED_LIMIT_INFORMATION>() as u32,
            ) == 0
            {
                return Err(format!("job limits refused ({})", GetLastError()));
            }
            if l.ui {
                let mut ui: JOBOBJECT_BASIC_UI_RESTRICTIONS = std::mem::zeroed();
                ui.UIRestrictionsClass = JOB_OBJECT_UILIMIT_DESKTOP
                    | JOB_OBJECT_UILIMIT_DISPLAYSETTINGS
                    | JOB_OBJECT_UILIMIT_EXITWINDOWS
                    | JOB_OBJECT_UILIMIT_GLOBALATOMS
                    | JOB_OBJECT_UILIMIT_HANDLES
                    | JOB_OBJECT_UILIMIT_READCLIPBOARD
                    | JOB_OBJECT_UILIMIT_SYSTEMPARAMETERS
                    | JOB_OBJECT_UILIMIT_WRITECLIPBOARD;
                if SetInformationJobObject(
                    job,
                    JobObjectBasicUIRestrictions,
                    std::ptr::addr_of!(ui).cast(),
                    size_of::<JOBOBJECT_BASIC_UI_RESTRICTIONS>() as u32,
                ) == 0
                {
                    return Err(format!("job UI restrictions refused ({})", GetLastError()));
                }
            }
            // Error 50, ERROR_NOT_SUPPORTED, is the one that actually
            // happens: this process is already in somebody else's job
            // and cannot join a second. Measured 2 Sep 2026.
            if AssignProcessToJobObject(job, GetCurrentProcess()) == 0 {
                return Err(format!(
                    "could not join the job ({}) - this process may already be in one",
                    GetLastError()
                ));
            }
        }
        Ok(())
    }
}

// ------------------------------------------------------------- the helper

/// **The Windows helper.** Returns at once unless this process was
/// started as one, in which case it never returns.
///
/// Call it as the FIRST thing in `main`, before any logging, listener or
/// signal handler: a helper is not a daemon and must not become one.
///
/// The argv it answers to is
/// `<exe> --nzbfast-confine <spec> <program> [args...]`, which
/// [`windows::wrap`] builds and to which the caller of [`command`] has
/// appended the program's own arguments. Working directory, environment
/// and stdio all arrive already set on THIS process, so the child
/// inherits them by simply not being told otherwise - which is what
/// makes a confined `par2 -q` still report through the daemon's
/// plumbing.
pub fn confine_main_if_asked() {
    let mut argv = std::env::args_os();
    let _exe = argv.next();
    let Some(flag) = argv.next() else { return };
    if flag != windows::CONFINE_FLAG {
        return;
    }
    // Past here this process is a helper and exits rather than returning.
    let limits = argv
        .next()
        .and_then(|s| s.into_string().ok())
        .as_deref()
        .and_then(windows::parse_spec);
    let Some(program) = argv.next() else {
        eprintln!("{}: no program to run", windows::CONFINE_FLAG);
        std::process::exit(windows::EXIT_NO_CHILD);
    };
    let applied: Result<(), String> = match limits {
        #[cfg(windows)]
        Some(l) => windows::apply(&l),
        #[cfg(not(windows))]
        Some(_) => Err("job objects exist only on Windows".to_string()),
        None => Err("the confinement spec was not one this build writes".to_string()),
    };
    // Only the probe asks to be told; a real spawn wants the child run.
    // See `windows::REQUIRE_ENV` for why the two differ here and nowhere
    // else.
    if let Err(why) = &applied
        && std::env::var_os(windows::REQUIRE_ENV).is_some_and(|v| v == "1")
    {
        eprintln!("{}: {why}", windows::CONFINE_FLAG);
        std::process::exit(windows::EXIT_NOT_CONFINED);
    }
    match std::process::Command::new(&program).args(argv).status() {
        // The child's own verdict, passed through untouched. `unrar` and
        // `par2` exit codes are read by their call sites and a helper
        // that rounded them off would be worse than no helper at all.
        Ok(st) => std::process::exit(st.code().unwrap_or(windows::EXIT_NO_CHILD)),
        Err(e) => {
            eprintln!(
                "{}: could not run {}: {e}",
                windows::CONFINE_FLAG,
                program.to_string_lossy()
            );
            std::process::exit(windows::EXIT_NO_CHILD);
        }
    }
}

// ------------------------------------------------------------- dispatch

/// The file names `Command::new(name)` would actually try inside a
/// `$PATH` directory, in order.
///
/// **On Windows this is not `name`.** `CreateProcessW` appends `.exe` to
/// a name that carries no extension, so `Command::new("unrar")` runs
/// `unrar.exe` and would run neither a bare `unrar` with no extension
/// nor an `unrar.bat` - it does not consult `PATHEXT`. Joining the bare
/// name, which is what this did until 2 Sep 2026, therefore matched
/// nothing on a Windows box, [`locate`] answered `None` for every
/// `$PATH`-resolved tool, and every such spawn took the "not installed,
/// spawn it bare" arm. The confinement was not weakened on Windows; it
/// was never reachable there at all.
///
/// `windows` is a parameter rather than a `cfg` so both arms are tested
/// on every host, the same reason `mod mac` and `mod linux` compile
/// everywhere.
fn path_candidates(name: &str, windows: bool) -> Vec<String> {
    if windows && Path::new(name).extension().is_none() {
        return vec![format!("{name}.exe")];
    }
    vec![name.to_string()]
}

/// First runnable match for `name` on `$PATH`, as an absolute path.
fn find_in_path(name: &str) -> Option<PathBuf> {
    let names = path_candidates(name, cfg!(windows));
    std::env::var_os("PATH").and_then(|paths| {
        std::env::split_paths(&paths)
            .flat_map(|d| names.iter().map(move |n| d.join(n)))
            .find(|p| runnable(p))
    })
}

/// Is this a file the OS would actually exec? `execvp` skips a
/// same-named file with no execute bit and keeps walking `$PATH`, so a
/// plain `is_file()` would resolve to something `Command::new` never
/// would.
fn runnable(p: &Path) -> bool {
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt as _;
        std::fs::metadata(p).is_ok_and(|m| m.is_file() && m.permissions().mode() & 0o111 != 0)
    }
    #[cfg(not(unix))]
    {
        p.is_file()
    }
}

/// Where `program` actually is, or `None` when nothing by that name can
/// be run.
///
/// **A program that is not installed must be spawned BARE**, and that is
/// not a tidiness point - it is a bug this wrapper shipped with for an
/// afternoon. `Command::new("par2").status()` on a box with no par2
/// answers `Err(ErrorKind::NotFound)`, and BOTH tool call sites branch
/// on exactly that: `rarfix` says "unrar is not installed, so there was
/// nothing to fall back to" and `repair` keeps a missing par2 apart from
/// a par2 that ran and failed. Wrap it and the spawn SUCCEEDS - it is
/// `sandbox-exec` that starts - and the tool's absence arrives as
/// `exit status: 71` instead, which is a tool that ran and refused.
/// `e2e_repair::no_recovery_on_disk_does_not_advertise_par2cmdline` and
/// `::a_missing_external_par2_still_reaches_the_native_escalation` are
/// the two tests that caught it; `an_uninstalled_tool_is_spawned_bare`
/// in `sandbox_tests` is the unit pin.
///
/// Resolving also gives the macOS profile the path the KERNEL will see
/// (a Homebrew binary is a symlink into the Cellar), and it is what
/// makes `program.parent()` a real directory to grant reads under.
fn locate(program: &Path) -> Option<PathBuf> {
    match program.parent() {
        // Path-bearing: `Command` would exec it directly, no `$PATH`.
        Some(parent) if !parent.as_os_str().is_empty() => runnable(program)
            .then(|| std::fs::canonicalize(program).unwrap_or_else(|_| program.to_path_buf())),
        // A bare name is a `$PATH` lookup - `tools::resolve` returns one
        // when nothing is installed beside our own executable.
        _ => program.to_str().and_then(find_in_path),
    }
}

/// A trivially-succeeding program to probe a mechanism with. On Windows
/// it needs `/c exit` after it, which its one caller appends.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn probe_program() -> Option<PathBuf> {
    #[cfg(windows)]
    {
        // COMSPEC is what the shell itself uses; `SystemRoot` is the
        // fallback because a Windows installed on any other drive still
        // names its own root there, and only then a literal.
        std::env::var_os("COMSPEC")
            .map(PathBuf::from)
            .into_iter()
            .chain(
                std::env::var_os("SystemRoot").map(|r| PathBuf::from(r).join(r"System32\cmd.exe")),
            )
            .chain([PathBuf::from(r"C:\Windows\System32\cmd.exe")])
            .find(|p| p.is_file())
    }
    #[cfg(not(windows))]
    {
        ["/usr/bin/true", "/bin/true"]
            .iter()
            .map(PathBuf::from)
            .find(|p| p.is_file())
    }
}

/// Run `cmd` and say whether it exited 0 within `secs`. Only [`detect`]
/// calls this, and only once per process.
#[cfg(target_os = "macos")]
fn probe_ok(cmd: std::process::Command, secs: u64) -> bool {
    probe_status_capturing(cmd, secs, false)
        .0
        .is_some_and(|st| st.success())
}

/// [`probe_ok`]'s body, kept apart because the Windows arm needs the
/// EXIT CODE and not just the verdict: `EXIT_NOT_CONFINED` is how the
/// helper says "I ran, and I could not confine", which reads nothing
/// like a helper that is missing.
#[cfg(windows)]
fn probe_status(cmd: std::process::Command, secs: u64) -> Option<std::process::ExitStatus> {
    probe_status_capturing(cmd, secs, false).0
}

/// [`probe_status`]'s body, plus the child's stderr when `capture` asks
/// for it.
///
/// **The Linux arm asks, and that is the point of this parameter.** The
/// difference between "bubblewrap is not installed" and "bubblewrap is
/// installed and the kernel refused it" is one line the child has
/// ALREADY printed, and no sentence we could write from an exit code is
/// worth as much to the person reading the settings row as quoting it.
///
/// Stated bound, because a pipe is not free of failure modes: a child
/// that filled the pipe buffer without exiting would block on the write
/// and be killed at `secs`, which reads as a declined rung - the same
/// answer a hung child already got before this existed. The stderr is
/// therefore read only AFTER the child is known to have exited, and the
/// probe is `/usr/bin/true` under a wrapper that prints one line when it
/// fails, so that is a bound worth naming rather than a case worth
/// engineering around.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn probe_status_capturing(
    mut cmd: std::process::Command,
    secs: u64,
    capture: bool,
) -> (Option<std::process::ExitStatus>, String) {
    use std::process::Stdio;
    cmd.stdin(Stdio::null())
        .stdout(Stdio::null())
        .stderr(if capture {
            Stdio::piped()
        } else {
            Stdio::null()
        });
    let Ok(mut child) = cmd.spawn() else {
        return (None, String::new());
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_secs(secs);
    let status = loop {
        match child.try_wait() {
            Ok(Some(st)) => break Some(st),
            Ok(None) => {}
            Err(_) => break None,
        }
        if std::time::Instant::now() >= deadline {
            let _ = child.kill();
            let _ = child.wait();
            break None;
        }
        std::thread::sleep(std::time::Duration::from_millis(20));
    };
    let mut err = String::new();
    // Only once it has exited: see the bound in the doc above.
    if status.is_some()
        && let Some(mut pipe) = child.stderr.take()
    {
        use std::io::Read as _;
        let _ = pipe.read_to_string(&mut err);
    }
    (status, err)
}

/// The strictest policy a probe can ask for, over a directory that
/// exists. Deliberately the SAME shape a real tool spawn uses, so a
/// green probe is evidence about the thing we are about to do rather
/// than about a simpler thing we are not.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
fn probe_policy() -> Policy {
    Policy::tool("probe", &std::env::temp_dir())
}

/// Settle on a mechanism, once per process, and say so in the log.
///
/// Every rung is probed by actually confining a trivial program with the
/// argv builder a real spawn would use. A rung that does not come back 0
/// is not taken - which is what keeps an untested platform difference
/// from turning into a broken unpack.
pub fn detect() -> &'static Availability {
    static AVAIL: OnceLock<Availability> = OnceLock::new();
    AVAIL.get_or_init(|| {
        let a = if std::env::var("NZBFAST_SANDBOX").is_ok_and(|v| v == "0") {
            Availability::unavailable("turned off by NZBFAST_SANDBOX=0")
        } else {
            detect_uncached()
        };
        if a.mechanism == Mechanism::None {
            warn!(
                target: "sandbox",
                "subprocess confinement is unavailable - unrar, par2 and post-processing \
                 scripts run unconfined ({})",
                a.detail
            );
        } else {
            tracing::info!(target: "sandbox", "{}", a.detail);
        }
        a
    })
}

#[cfg(target_os = "macos")]
fn detect_uncached() -> Availability {
    let Some(probe) = probe_program() else {
        return Availability::unavailable(
            "no /usr/bin/true to probe with, so no mechanism could be verified",
        );
    };
    let exec = PathBuf::from("/usr/bin/sandbox-exec");
    if !exec.is_file() {
        return Availability::unavailable("this macOS has no /usr/bin/sandbox-exec");
    }
    let bsd = Path::new(BSD_PROFILE).is_file();
    let policy = probe_policy();
    if bsd
        && mac::profile(&probe, &policy, true)
            .is_some_and(|p| probe_ok(mac::wrap(&exec, &p, &probe), PROBE_SECS))
    {
        return Availability {
            mechanism: Mechanism::SandboxExec,
            wrapper: Some(exec),
            strict: true,
            writes_confined: true,
            network_confined: true,
            detail: "confining subprocesses with sandbox-exec: no network, and reads and \
                     writes confined to the job directory"
                .to_string(),
        };
    }
    if mac::profile(&probe, &policy, false)
        .is_some_and(|p| probe_ok(mac::wrap(&exec, &p, &probe), PROBE_SECS))
    {
        return Availability {
            mechanism: Mechanism::SandboxExec,
            wrapper: Some(exec),
            strict: false,
            writes_confined: true,
            network_confined: true,
            detail: format!(
                "confining subprocesses with sandbox-exec: no network and no writes outside \
                 the job directory. Reads are NOT confined, because {}",
                if bsd {
                    "the strict profile would not run on this macOS"
                } else {
                    "this macOS has no /System/Library/Sandbox/Profiles/bsd.sb"
                }
            ),
        };
    }
    Availability::unavailable("sandbox-exec is present but refused a test profile")
}

#[cfg(target_os = "linux")]
fn detect_uncached() -> Availability {
    let Some(probe) = probe_program() else {
        return Availability::unavailable(
            "no /usr/bin/true to probe with, so no mechanism could be verified",
        );
    };
    let policy = probe_policy();
    // A rung that was FOUND and then refused is remembered, and that is
    // the shape of this arm rather than an ornament on it. Until 2 Sep
    // 2026 both `if let`s simply fell through to one sentence saying
    // neither wrapper was installed, which is what a stock Ubuntu 24.04
    // read on a box where bubblewrap IS installed - so the row named the
    // one remedy that cannot work (`apt install bubblewrap`) and never
    // named the one that does. The measurement, both directions, is in
    // `linux::bwrap_refused`'s doc comment.
    let mut refused: Option<String> = None;
    if let Some(bwrap) = find_in_path("bwrap") {
        let mut c = std::process::Command::new(&bwrap);
        c.args(linux::bwrap_args(&policy)).arg(&probe);
        let (st, err) = probe_status_capturing(c, PROBE_SECS, true);
        if st.is_some_and(|st| st.success()) {
            return Availability {
                mechanism: Mechanism::Bwrap,
                wrapper: Some(bwrap),
                strict: true,
                writes_confined: true,
                network_confined: true,
                detail: "confining subprocesses with bwrap: no network, and reads and writes \
                         confined to the job directory"
                    .to_string(),
            };
        }
        refused = Some(linux::bwrap_refused(&bwrap, &err));
    }
    if let Some(unshare) = find_in_path("unshare") {
        let mut c = std::process::Command::new(&unshare);
        c.args(linux::unshare_args(&policy)).arg(&probe);
        let (st, err) = probe_status_capturing(c, PROBE_SECS, true);
        if st.is_some_and(|st| st.success()) {
            return Availability {
                mechanism: Mechanism::UnshareNet,
                wrapper: Some(unshare),
                strict: false,
                writes_confined: false,
                network_confined: true,
                detail: "confining subprocesses with unshare: no network. Install bubblewrap \
                         (bwrap) to confine the filesystem as well"
                    .to_string(),
            };
        }
        // bwrap's refusal wins where there is one: it is the rung worth
        // having, and on the box this was measured on its remedy is the
        // only one that restores any confinement at all.
        refused.get_or_insert_with(|| linux::unshare_refused(&unshare, &err));
    }
    Availability::unavailable(refused.unwrap_or_else(|| linux::NOTHING_INSTALLED.to_string()))
}

/// Executables that might answer [`confine_main_if_asked`], best first.
///
/// In production the answer is the first one: the daemon IS the helper.
/// The other two exist so a TEST build is not permanently unconfined -
/// a cargo test binary is `target\debug\deps\<name>-<hash>.exe`, libtest
/// owns its argv, and it can never answer, so the real binary beside it
/// is looked for instead.
///
/// **Measured 2 Sep 2026, and it decides what a Windows test run
/// proves:** `cargo test` and `cargo nextest run` build test HARNESSES,
/// not bin targets, so `target\debug\nzbfast.exe` is absent unless a
/// `cargo build` also ran. Without it this returns nothing usable, the
/// live arms report "no job-object helper on this box" and skip, and a
/// green Windows test run says nothing about the mechanism. That is the
/// honest degradation and not a defect - but do not read a green
/// `windows-unit` as evidence the arm works. Run the module as itself
/// with the binary built, the way
/// `research/NOTE-2026-09-02-SANDBOX-TESTS-RESOLVE-ON-WINDOWS.md`
/// describes.
///
/// **Neither fallback may contain a `..`**, and that is a rule rather
/// than a style: `exe.parent()/../nzbfast.exe` in a normal install
/// resolves to the directory ABOVE the program directory, which is
/// routinely writable by an unprivileged user. So the deps hop is taken
/// only when the parent directory is literally named `deps`, which is
/// the cargo layout naming itself and nothing else.
#[cfg(windows)]
fn helper_candidates() -> Vec<PathBuf> {
    let Ok(exe) = std::env::current_exe() else {
        return Vec::new();
    };
    let mut v = vec![exe.clone()];
    if let Some(dir) = exe.parent() {
        v.push(dir.join("nzbfast.exe"));
        if dir.file_name() == Some(std::ffi::OsStr::new("deps"))
            && let Some(up) = dir.parent()
        {
            v.push(up.join("nzbfast.exe"));
        }
    }
    v.dedup();
    v
}

/// Windows, stage 1's second half.
///
/// The mechanism is a job object joined by a HELPER process, which is
/// this executable re-invoked - see the module doc's stated limits for
/// why it cannot be done inside [`command`]'s returned `Command`, and
/// for the three things this arm does NOT confine.
///
/// Every candidate is probed by confining a real child with the argv a
/// real spawn uses, and the probe alone sets [`windows::REQUIRE_ENV`],
/// so a helper that ran the child WITHOUT confining it is not mistaken
/// for one that confined it. That distinction is the whole point: a
/// process already inside somebody else's job cannot join a second one,
/// and without the flag the helper would degrade silently and this
/// function would report a confinement that was not there.
#[cfg(windows)]
fn detect_uncached() -> Availability {
    let Some(probe) = probe_program() else {
        return Availability::unavailable(
            "no cmd.exe to probe with, so no mechanism could be verified",
        );
    };
    let policy = probe_policy();
    let args = windows::confine_args(&policy);
    let mut refused_to_confine = false;
    for helper in helper_candidates() {
        if !helper.is_file() {
            continue;
        }
        let mut c = windows::wrap(&helper, &args, &probe);
        c.arg("/c").arg("exit").env(windows::REQUIRE_ENV, "1");
        match probe_status(c, PROBE_SECS).and_then(|st| st.code()) {
            Some(0) => {
                return Availability {
                    mechanism: Mechanism::JobObject,
                    wrapper: Some(helper),
                    strict: false,
                    writes_confined: false,
                    network_confined: false,
                    detail: "limiting subprocesses with a Windows job object: unrar and \
                             par2 cannot outlive nzbfast, cannot escape the job, cannot \
                             reach the desktop or the clipboard, and raise no crash \
                             dialog. Your own scripts keep the desktop and may outlive \
                             nzbfast, just as they keep their network. What a subprocess \
                             may READ, WRITE or send is NOT confined on Windows"
                        .to_string(),
                };
            }
            Some(windows::EXIT_NOT_CONFINED) => refused_to_confine = true,
            _ => {}
        }
    }
    Availability::unavailable(if refused_to_confine {
        "a job object could not be created for subprocesses, which usually means nzbfast \
         is itself running inside one. unrar, par2 and scripts run exactly as they \
         always have"
    } else {
        "no job-object helper answered on this machine, so unrar, par2 and scripts run \
         exactly as they always have"
    })
}

/// Neither macOS, nor Linux, nor Windows.
#[cfg(not(any(target_os = "macos", target_os = "linux", windows)))]
fn detect_uncached() -> Availability {
    Availability::unavailable("subprocess confinement is not built for this platform")
}

/// How long a probe may take before the rung is declined. Generous: it
/// runs once, and a cold `bwrap` on a loaded NAS is slow.
#[cfg(any(target_os = "macos", target_os = "linux", windows))]
const PROBE_SECS: u64 = 10;

/// **The wrapper.** Build the `Command` for `program` under `policy`.
///
/// The caller then adds arguments, environment and `current_dir` to the
/// returned command exactly as it would to a bare
/// `Command::new(program)`: every argument it appends lands after the
/// program, whichever mechanism is in force.
///
/// Never fails. With no mechanism available this IS `Command::new`.
pub fn command(program: &Path, policy: &Policy) -> std::process::Command {
    let a = detect();
    // Not installed: spawn it bare so its own ENOENT arm still fires.
    // See [`locate`] - this is the whole reason that function exists.
    let Some(located) = locate(program) else {
        return std::process::Command::new(program);
    };
    let program = located.as_path();
    match (a.mechanism, a.wrapper.as_deref()) {
        (Mechanism::SandboxExec, Some(exec)) => match mac::profile(program, policy, a.strict) {
            Some(p) => mac::wrap(exec, &p, program),
            None => {
                warn!(
                    target: "sandbox",
                    "running {} unconfined: the {} policy names a path that is not valid \
                     UTF-8, which a sandbox profile cannot spell",
                    program.display(),
                    policy.label
                );
                std::process::Command::new(program)
            }
        },
        (Mechanism::Bwrap, Some(bwrap)) => {
            let mut c = std::process::Command::new(bwrap);
            c.args(linux::bwrap_args(policy)).arg(program);
            c
        }
        (Mechanism::UnshareNet, Some(unshare)) => {
            let mut c = std::process::Command::new(unshare);
            c.args(linux::unshare_args(policy)).arg(program);
            c
        }
        // No REQUIRE_ENV here, on purpose: a real spawn that cannot be
        // confined must still run the program. Only the probe asks to
        // be refused - see `windows::REQUIRE_ENV`.
        (Mechanism::JobObject, Some(helper)) => {
            windows::wrap(helper, &windows::confine_args(policy), program)
        }
        _ => std::process::Command::new(program),
    }
}

/// The settings-page health row: which mechanism is in force, and the
/// sentence explaining it. Read-only - there is nothing here a user
/// sets, only something they should be able to see.
pub fn health() -> serde_json::Value {
    let a = detect();
    serde_json::json!({
        "mechanism": a.mechanism.as_str(),
        "confined": a.mechanism != Mechanism::None,
        "reads_confined": a.strict,
        "writes_confined": a.writes_confined,
        "network_confined": a.network_confined,
        "detail": a.detail,
    })
}

#[cfg(test)]
#[path = "sandbox_tests.rs"]
mod tests;
