//! Bring a just-opened Explorer window to the front on Windows (TODO 204).
//!
//! The dashboard's Show-in-folder action has the daemon spawn
//! `explorer <path>` (`fsutil::os_open`), and on Windows the folder window
//! appears BEHIND the browser. That is the foreground lock: only the
//! process that received the last input event may take the foreground, and
//! that is the browser the user clicked in. Neither the daemon nor the
//! Explorer it spawns inherits the right, so nothing about HOW we spawn
//! changes it - `start`, ShellExecute and PowerShell AppActivate all hit
//! the same wall.
//!
//! What does work is the bypass every "reveal in Explorer" app uses:
//! `AttachThreadInput` our thread to the thread that owns the foreground
//! window, which makes the two share one input queue for the duration, and
//! call `SetForegroundWindow` from inside that window. Raw externs, no new
//! dependency, same shape as `nzbkit::disk::hide_from_user`.
//!
//! Best-effort throughout, and deliberately so. A daemon running as a
//! service in session 0 has no desktop to raise a window on; every call
//! here then does nothing and the folder still opens behind, which is
//! exactly what happens today.

/// How well does this window title name the folder we just opened?
/// 4 = the whole path, 3 = the whole path with a suffix, 2 = the last
/// component, 1 = the last component with a suffix, 0 = not ours.
///
/// Explorer titles a folder window with the folder's LEAF name, or with
/// the whole path when "Display the full path in the title bar" is turned
/// on. Case-insensitively, because Windows paths are. A Windows 11
/// Explorer that opened the folder as a new TAB matches too: the window
/// title follows the active tab.
///
/// **And it appends an application name.** Measured on Windows 11
/// (NT 10.0.26200): a window on `LegB.Plain` is titled
/// `LegB.Plain - File Explorer`, not `LegB.Plain`. That suffix is
/// LOCALISED, so this cannot look for the English words - it takes any
/// trailing dash-introduced remainder instead, which is why the dash set
/// below includes en and em dashes that our own copy rules would never
/// allow. They are Windows' punctuation, not ours.
///
/// The ranks exist because these are not equally good evidence. A whole
/// path is proof. A bare leaf is a guess: two downloads can both end in
/// `Season 01`. A suffixed match is a weaker guess again, because the
/// folder name is only a PREFIX of the title, so a window on
/// `Show - S01E01` also prefix-matches a request for `Show`. The caller
/// takes the best rank it can find anywhere in the z-order, and breaks a
/// tie on the shortest title - the right window's title is the name plus
/// the suffix and nothing else.
///
/// The last component is split off by hand rather than with
/// `Path::file_name` so this stays honest on any host: off Windows a
/// backslash is an ordinary filename character, and the whole matcher
/// would be untestable anywhere but the machine it ships to.
// Not #[expect]: dead off Windows in a PLAIN build only. The `mod tests`
// below is ungated on purpose - the matcher is testable on any host - so
// under --all-targets, which is the shape CI's clippy gate runs, the lint
// does not fire and the expectation goes unfulfilled. Measured 23 Aug 2026:
// unfulfilled on macOS, Linux and slim Linux --all-targets; fulfilled in
// every plain build.
#[cfg_attr(not(windows), allow(dead_code))]
pub(crate) fn title_rank(title: &str, path: &std::path::Path) -> u8 {
    let title = title.trim();
    if title.is_empty() {
        return 0;
    }
    let full = path.to_string_lossy();
    let full = full.trim_end_matches(['\\', '/']);
    if full.is_empty() {
        return 0;
    }
    match names(title, full) {
        Named::Exact => return 4,
        Named::Suffixed => return 3,
        Named::No => {}
    }
    // A drive root (`D:\`) leaves nothing after the separator, and its
    // window is titled by volume label anyway ("Local Disk (D:)"), so
    // there is nothing here to match on.
    match full.rsplit(['\\', '/']).next() {
        Some(leaf) if !leaf.is_empty() => match names(title, leaf) {
            Named::Exact => 2,
            Named::Suffixed => 1,
            Named::No => 0,
        },
        _ => 0,
    }
}

/// How `title` names `candidate`, if it does.
// Not #[expect]: same as `title_rank` above - the ungated `mod tests` reaches
// it through that function, so under --all-targets the expectation goes
// unfulfilled. Measured 23 Aug 2026 in the same five configurations.
#[cfg_attr(not(windows), allow(dead_code))]
enum Named {
    Exact,
    Suffixed,
    No,
}

/// Does this title read as `candidate`, alone or with an appended
/// application name?
// Not #[expect]: same as `title_rank` above - the ungated `mod tests` reaches
// it through that function, so under --all-targets the expectation goes
// unfulfilled. Measured 23 Aug 2026 in the same five configurations.
#[cfg_attr(not(windows), allow(dead_code))]
fn names(title: &str, candidate: &str) -> Named {
    if title.eq_ignore_ascii_case(candidate) {
        return Named::Exact;
    }
    // ASCII case folding never changes a byte length, and non-ASCII bytes
    // are compared as they are, so the candidate's length is also its
    // length inside the title.
    if title.len() <= candidate.len() || !title.is_char_boundary(candidate.len()) {
        return Named::No;
    }
    if !title[..candidate.len()].eq_ignore_ascii_case(candidate) {
        return Named::No;
    }
    // What follows has to be the START of a suffix, not more folder name:
    // `Season` must not claim a window titled `Season 01 - File Explorer`.
    let rest = title[candidate.len()..].trim_start();
    match rest.starts_with(['-', '\u{2013}', '\u{2014}']) {
        true => Named::Suffixed,
        false => Named::No,
    }
}

#[cfg(windows)]
mod imp {
    use std::path::{Path, PathBuf};
    use std::time::{Duration, Instant};
    use tracing::debug;

    /// Explorer can take a moment to put the window up - a cold shell
    /// cache, a network path. Poll for it rather than sleep-and-hope, and
    /// give up quietly: a missed raise is the behaviour we have today.
    const WAIT: Duration = Duration::from_secs(5);
    const POLL: Duration = Duration::from_millis(100);

    /// `SW_RESTORE`.
    const SW_RESTORE: i32 = 9;

    /// `WNDENUMPROC`. Returns 0 to stop the enumeration, non-zero to carry
    /// on - the Win32 convention, not a bool.
    type WndEnumProc = unsafe extern "system" fn(isize, isize) -> i32;

    // SAFETY: these declarations must match the real user32 exports; they
    // mirror the documented Win32 signatures, with HWND as a
    // pointer-sized integer (which is what a handle is) and BOOL as i32.
    unsafe extern "system" {
        fn EnumWindows(cb: WndEnumProc, lparam: isize) -> i32;
        fn IsWindowVisible(hwnd: isize) -> i32;
        fn GetClassNameW(hwnd: isize, buf: *mut u16, cap: i32) -> i32;
        fn GetWindowTextW(hwnd: isize, buf: *mut u16, cap: i32) -> i32;
        fn GetForegroundWindow() -> isize;
        fn GetWindowThreadProcessId(hwnd: isize, pid: *mut u32) -> u32;
        fn GetCurrentThreadId() -> u32;
        fn AttachThreadInput(from: u32, to: u32, attach: i32) -> i32;
        fn SetForegroundWindow(hwnd: isize) -> i32;
        fn BringWindowToTop(hwnd: isize) -> i32;
        fn ShowWindow(hwnd: isize, cmd: i32) -> i32;
        fn IsIconic(hwnd: isize) -> i32;
    }

    /// Run one of the W-suffixed text getters into a `String`. They all
    /// share the shape: write into a caller-owned buffer, return the
    /// character count written, 0 on failure or an empty string.
    fn wide_text(cap: usize, read: impl FnOnce(*mut u16, i32) -> i32) -> String {
        let mut buf = vec![0u16; cap];
        let n = read(buf.as_mut_ptr(), cap as i32);
        if n <= 0 {
            return String::new();
        }
        String::from_utf16_lossy(&buf[..(n as usize).min(cap)])
    }

    /// What the enumeration is looking for, and the best it has found:
    /// the rank, the length of that window's title, and the window.
    struct Hunt<'a> {
        path: &'a Path,
        rank: u8,
        title_len: usize,
        hwnd: isize,
    }

    /// The rank `title_rank` cannot beat - the title IS the whole path,
    /// so there is no point enumerating the rest of the desktop.
    const BEST: u8 = 4;

    unsafe extern "system" fn visit(hwnd: isize, lparam: isize) -> i32 {
        // SAFETY: `lparam` is the `&raw mut Hunt` handed to EnumWindows in
        // `find_window` below, and that borrow outlives this call because
        // EnumWindows is synchronous.
        let hunt = unsafe { &mut *(lparam as *mut Hunt) };
        // SAFETY: `hwnd` comes from the enumeration itself, so it names a
        // live top-level window for the length of this callback.
        if unsafe { IsWindowVisible(hwnd) } == 0 {
            return 1;
        }
        // SAFETY: as above, plus each buffer is owned by `wide_text` and
        // its capacity is passed alongside it.
        let class = wide_text(64, |p, c| unsafe { GetClassNameW(hwnd, p, c) });
        // `CabinetWClass` is a folder window; `ExploreWClass` is the same
        // thing with the old navigation-pane layout. Everything else the
        // shell owns - the desktop's Progman and WorkerW, the taskbar -
        // must never be fronted, whatever it happens to be called.
        if class != "CabinetWClass" && class != "ExploreWClass" {
            return 1;
        }
        // SAFETY: as above.
        let title = wide_text(512, |p, c| unsafe { GetWindowTextW(hwnd, p, c) });
        let rank = super::title_rank(&title, hunt.path);
        if rank == 0 {
            return 1;
        }
        // Better evidence wins; equal evidence goes to the shorter title,
        // which is the one carrying no folder name but ours.
        let better = rank > hunt.rank || (rank == hunt.rank && title.len() < hunt.title_len);
        if better {
            hunt.rank = rank;
            hunt.title_len = title.len();
            hunt.hwnd = hwnd;
        }
        // Only an exact whole-path title ends the search early.
        i32::from(hunt.rank < BEST)
    }

    /// The folder window for `path`, if the shell has one open.
    fn find_window(path: &Path) -> Option<isize> {
        let mut hunt = Hunt {
            path,
            rank: 0,
            title_len: usize::MAX,
            hwnd: 0,
        };
        // SAFETY: `visit` has the WNDENUMPROC signature, and the pointer
        // passed as lparam is to the live local above - EnumWindows
        // returns before it goes out of scope.
        unsafe { EnumWindows(visit, &raw mut hunt as isize) };
        (hunt.hwnd != 0).then_some(hunt.hwnd)
    }

    /// Take the foreground for `hwnd`, borrowing the standing of the
    /// thread that currently holds it.
    fn front(hwnd: isize) {
        // SAFETY: every handle here comes from the API itself, the one
        // pointer is the documented null for GetWindowThreadProcessId's
        // optional out-param, and the attach is undone on the way out.
        unsafe {
            let fg = GetForegroundWindow();
            let owner = if fg == 0 {
                0
            } else {
                GetWindowThreadProcessId(fg, std::ptr::null_mut())
            };
            let ours = GetCurrentThreadId();
            // Attaching a thread to itself fails, and there is nothing to
            // borrow when nothing holds the foreground at all (a locked
            // desktop, or session 0). Try the raise anyway: it costs
            // nothing and it succeeds outright when we already have the
            // standing.
            let attached = owner != 0 && owner != ours && AttachThreadInput(ours, owner, 1) != 0;
            // A minimised window will accept the foreground and stay
            // minimised, which looks exactly like the bug being fixed.
            if IsIconic(hwnd) != 0 {
                ShowWindow(hwnd, SW_RESTORE);
            }
            SetForegroundWindow(hwnd);
            BringWindowToTop(hwnd);
            if attached {
                AttachThreadInput(ours, owner, 0);
            }
        }
    }

    /// Wait for the window and raise it. Also covers the case where
    /// Explorer opened no new window at all because one for this folder
    /// was already up: it dedups to that window, whose title still
    /// matches, and fronting it is the behaviour the user wanted anyway.
    fn raise_folder(path: &Path) {
        let deadline = Instant::now() + WAIT;
        loop {
            if let Some(hwnd) = find_window(path) {
                front(hwnd);
                debug!(target: "open", "fronted the folder window for {}", path.display());
                return;
            }
            if Instant::now() >= deadline {
                // Worth a line. From the outside a raise that did not
                // happen looks exactly like one that was never attempted,
                // and this is the only place that can tell the difference.
                debug!(
                    target: "open",
                    "no folder window named {} within {WAIT:?}, left where the shell put it",
                    path.display()
                );
                return;
            }
            std::thread::sleep(POLL);
        }
    }

    /// Front the folder window Explorer is about to open, without making
    /// the API handler wait for it.
    pub(in crate::serve) fn raise_folder_soon(path: PathBuf) {
        // The dashboard is blocked on this request's response and the
        // window can be seconds away, so the waiting happens off to one
        // side. There is nothing to report back either way: the folder is
        // open regardless, and the raise is a courtesy.
        let _ = std::thread::Builder::new()
            .name("winfront".into())
            .spawn(move || raise_folder(&path));
    }
}

#[cfg(windows)]
pub(super) use imp::raise_folder_soon;

#[cfg(test)]
mod tests {
    use super::title_rank;
    use std::path::Path;

    /// The paths this matcher sees are always Windows-shaped, whatever
    /// host the test runs on.
    fn p(s: &str) -> &Path {
        Path::new(s)
    }

    #[test]
    fn full_path_title_outranks_a_leaf_title() {
        let dir = p(r"C:\Users\Public\Downloads\Show.S01E01");
        assert_eq!(title_rank(r"C:\Users\Public\Downloads\Show.S01E01", dir), 4);
        assert_eq!(title_rank("Show.S01E01", dir), 2);
    }

    /// The form Windows 11 actually produces, measured on NT 10.0.26200.
    /// The matcher that shipped without this test would have matched
    /// NOTHING on that machine.
    #[test]
    fn the_appended_application_name_still_matches() {
        let dir = p(r"C:\t204\LegB.Plain");
        assert_eq!(title_rank("LegB.Plain - File Explorer", dir), 1);
        assert_eq!(title_rank(r"C:\t204\LegB.Plain - File Explorer", dir), 3);
        // The suffix is localised, so the words cannot be looked for -
        // only the dash that introduces them, in any of its shapes.
        assert_eq!(title_rank("LegB.Plain \u{2013} Datei-Explorer", dir), 1);
        assert_eq!(title_rank("LegB.Plain\u{2014}Explorateur", dir), 1);
    }

    /// A folder name that is a PREFIX of another folder's name must not
    /// claim that other folder's window.
    #[test]
    fn a_prefix_of_another_folder_name_is_not_a_match() {
        assert_eq!(
            title_rank("Season 01 - File Explorer", p(r"D:\media\Season")),
            0
        );
        assert_eq!(
            title_rank("Show.S02 - File Explorer", p(r"D:\media\Show")),
            0
        );
        // ...but the same name followed by the suffix still is.
        assert_eq!(
            title_rank("Season - File Explorer", p(r"D:\media\Season")),
            1
        );
    }

    #[test]
    fn matching_ignores_case_and_surrounding_space() {
        let dir = p(r"D:\media\Season 01");
        assert_eq!(title_rank("season 01", dir), 2);
        assert_eq!(title_rank("  Season 01  ", dir), 2);
        assert_eq!(title_rank(r"d:\MEDIA\season 01", dir), 4);
    }

    #[test]
    fn a_trailing_separator_does_not_lose_the_match() {
        let dir = p(r"D:\media\Season 01\");
        assert_eq!(title_rank(r"D:\media\Season 01", dir), 4);
        assert_eq!(title_rank("Season 01", dir), 2);
    }

    #[test]
    fn other_windows_are_left_alone() {
        let dir = p(r"C:\Users\Public\Downloads\Show.S01E01");
        assert_eq!(title_rank("nzbfast - Chrome", dir), 0);
        assert_eq!(title_rank("Downloads", dir), 0);
        assert_eq!(title_rank("", dir), 0);
        assert_eq!(title_rank("   ", dir), 0);
    }

    #[test]
    fn a_drive_root_matches_nothing_by_leaf() {
        let root = p(r"D:\");
        // The volume label is not derivable from the path, and the empty
        // leaf must not turn into a match-anything.
        assert_eq!(title_rank("Local Disk (D:)", root), 0);
        assert_eq!(title_rank("", root), 0);
        // Its own full form still matches, trailing separator trimmed.
        assert_eq!(title_rank("D:", root), 4);
    }
}
