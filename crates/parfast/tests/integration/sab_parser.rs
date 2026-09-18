//! What SABnzbd's own parser gets out of a parfast repair.
//!
//! SAB runs its par2 binary and reads NOTHING but stdout (with stderr
//! merged into it - `misc.py`'s `build_and_run_command` sets
//! `stderr=subprocess.STDOUT`). It never reads the exit code. So every
//! fact SAB acts on is a LINE, and the four facts that matter most are
//! the ones it takes out of the "Scanning extra files:" section:
//!
//! * `renames` - the obfuscated name a member really has, which SAB
//!   records against the job.
//! * `reconstructed` - the incomplete original the repair consumed,
//!   which SAB then deletes instead of shipping it to the completed
//!   folder as junk.
//! * `used_joinables` - the same regex when `.rar` is on both sides, so
//!   a joined `.001` is not read as a phantom extra rar-set.
//! * `used_for_repair` - a duplicate extra, removed.
//!
//! Until 17 Sep 2026 parfast emitted neither of the two lines those
//! four are parsed from, and all four silently stayed empty on every
//! obfuscated post - which is the ordinary shape of a Usenet post.
//! Measured and written up in
//! `research/SAB-PARFAST-METER-DROPIN-2026-09-17.md`, addendum A.
//!
//! # Why the test replays SAB rather than grepping
//!
//! The lines are necessary and not sufficient: SAB stops reading
//! rename announcements the moment it sees "Repair is required."
//! (`newsunpack.py`'s `verified` flag), and it only enters the
//! extra-file state after "Verifying source files:" and then "Scanning
//! extra files:". A grep would pass on output whose ORDER makes every
//! line dead, which is precisely the failure mode the fix had to move -
//! parfast's adoption runs inside the engine, after the point the
//! reference has already printed this section. So the assertion is
//! made by running SAB's state machine, transcribed from upstream tag
//! 5.1.2, over what the binary actually printed.
//!
//! The transcription is DELIBERATELY not a full copy: it carries the
//! states and the two regexes, not SAB's fetch/retry behaviour.
//!
//! # What this has that `tools/sab-parser-gate.py` does not
//!
//! That gate landed the same day (claim `sab-parser-contract-gate`) and
//! is the broader check: a committed roster of all 24 SAB branches, a
//! transcription of the whole parser, and now eight fixtures (claim
//! `sab-gate-obfuscated-damaged-fixture` added the `obfuscated-damaged`
//! one, whose donor is both damaged and misnamed, which is what fires
//! the PARTIAL `extra-blocks-found` line and the reason this file's own
//! whole-file-match test was removed as a duplicate). It subsumes the
//! whole-file-match case, ORDER INCLUDED - a branch only counts as
//! reached when its state machine actually took it, which cannot happen
//! if the section prints after "Repair is required.".
//!
//! One thing it still cannot see, which is why the remaining tests below
//! are not a second copy:
//!
//! * EXIT CODES. The gate is built on SAB reading none of them, which
//!   is true of SAB and not of the drop-in contract. The second test
//!   below pins exit 4 for a `.par2` with no set and exit 3 for an
//!   argument that is not named `.par2`, which is par2cmdline v1.3.0's
//!   split.

use std::path::Path;
use std::process::Command;

use crate::scratch::scratch;

fn parfast(dir: &Path, args: &[&str]) -> (i32, String) {
    let out = Command::new(env!("CARGO_BIN_EXE_parfast"))
        .args(args)
        .current_dir(dir)
        .env("NZBFAST_NO_ENRICH", "1")
        .output()
        .expect("parfast runs");
    // SAB merges the two streams, so the test reads what SAB reads.
    let mut merged = String::from_utf8_lossy(&out.stdout).into_owned();
    merged.push_str(&String::from_utf8_lossy(&out.stderr));
    (out.status.code().unwrap_or(-1), merged)
}

fn payload(n: usize, seed: u32) -> Vec<u8> {
    (0..n as u32)
        .map(|i| (i.wrapping_mul(seed | 1).wrapping_add(i >> 3)) as u8)
        .collect()
}

/// The lines have to land BEFORE "Repair is required.", and this is the
/// half a grep cannot see. It is also the half that was hard: parfast's
/// adoption decision is made inside the engine, after the observer has
/// already been asked for a verdict, so the announcement's tail is held
/// back until the engine reports. A regression that printed the same
/// lines after the fold would leave both lists empty above and this
/// assertion is what names the reason.
#[test]
fn the_extra_file_section_comes_before_the_verdict_that_ends_it() {
    let s = scratch("sab-section-order");
    let dir: &Path = &s;
    for (name, seed) in [("one.bin", 5u32), ("two.bin", 71)] {
        std::fs::write(dir.join(name), payload(3000, seed)).unwrap();
    }
    let (code, out) = parfast(
        dir,
        &["c", "-s256", "-c8", "set.par2", "one.bin", "two.bin"],
    );
    assert_eq!(code, 0, "create failed:\n{out}");
    std::fs::rename(dir.join("one.bin"), dir.join("0123456789ab")).unwrap();

    let (code, out) = parfast(dir, &["r", "set.par2"]);
    assert_eq!(code, 0, "repair failed:\n{out}");
    let header = out
        .find("Scanning extra files:")
        .expect("the section header");
    let line = out
        .find("File: \"0123456789ab\" - is a match for \"one.bin\".")
        .unwrap_or_else(|| panic!("no announcement for the donor:\n{out}"));
    let verdict = out.find("Repair is required.").expect("the verdict");
    assert!(
        header < line && line < verdict,
        "the announcement must sit inside the section and ahead of the verdict:\n{out}"
    );
}

/// A `.par2` argument whose bytes carry no set is the reference's
/// "Main packet not found.", which is SAB's signal to fetch a DIFFERENT
/// par2 out of the NZB and retry the whole repair - the ordinary cure
/// for a first par2 that arrived with bad articles. parfast answered
/// "You must specify a Recovery file." and exit 3, which reaches no
/// branch of SAB's parser at all, so the job failed with recovery data
/// still sitting on the server.
#[test]
fn a_par2_with_no_main_packet_says_so_in_the_dialect() {
    let s = scratch("sab-main-packet");
    let dir: &Path = &s;
    std::fs::write(dir.join("payload.bin"), payload(3000, 3)).unwrap();
    std::fs::write(dir.join("set.par2"), payload(4096, 97)).unwrap();
    let (code, out) = parfast(dir, &["r", "set.par2"]);
    assert!(
        out.lines().any(|l| l.trim() == "Main packet not found."),
        "not the reference's line:\n{out}"
    );
    // par2cmdline's eInsufficientCriticalData, captured from v1.3.0.
    assert_eq!(code, 4, "not the reference's exit code:\n{out}");

    // And the control: an argument that is not named `.par2` never
    // becomes the par file on the reference either, and keeps the old
    // line and the old code.
    let (code, out) = parfast(dir, &["r", "payload.bin"]);
    assert!(
        out.lines()
            .any(|l| l.trim() == "You must specify a Recovery file."),
        "the non-par2 argument changed answer:\n{out}"
    );
    assert_eq!(code, 3, "the non-par2 argument changed code:\n{out}");
}
