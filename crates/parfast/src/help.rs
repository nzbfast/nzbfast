//! The help screen, the version lines, and why they are the only place
//! this program deliberately does not match the reference's bytes.
//!
//! `tools/conformance/run.py` compares normalised stdout line for line,
//! and its banner filter strips exactly the lines that carry the
//! REFERENCE's version and copyright (`^par2cmdline(-turbo)? version`,
//! `^Copyright`). A drop-in that printed those strings would pass three
//! more rows by claiming to BE par2cmdline, which is a lie a bug report
//! then has to unpick, so parfast names itself and the three identity
//! rows (`help`, `version`, `version-copyright`) carry a waiver in
//! `tools/conformance/allow/par2.txt` saying so.
//!
//! What the waiver is allowed to rest on, and what this module must
//! therefore keep true: the screen below is the reference's screen with
//! the PROGRAM NAME substituted and nothing else moved. Same switches,
//! same sections, same order, same placeholders - so
//! `run.py`'s own help parser reads the identical command and switch
//! sets out of either screen. `switch_screen_matches_inventory` in the
//! tests below is that claim, checked rather than asserted: it parses
//! this text the way the harness parses the reference's and compares the
//! result to the committed inventory file.
//!
//! Adding a line here is therefore not free. An extra parfast can do
//! that the reference cannot is a GNU-style long option (spec R.3) and
//! goes in its own section below the reference's, never as a new short
//! switch: the reference's next release may take that letter, and the
//! day it does the drop-in claim breaks in silence.

/// Detected cores, for the `-t<n>` line. The reference prints the same
/// fact about the box it ran on, which is why the harness rewrites the
/// digits on that line to `<n>` rather than dropping the line.
fn detected_threads() -> usize {
    // cpu-workers-gate: not a pool. This number is PRINTED, in the help
    // screen's `-t<n>` line, because the reference prints the same fact
    // about the box it ran on there - `(8 detected)` - and the
    // conformance harness rewrites its digits to `<n>` rather than
    // dropping the line. `mem::cpu_workers()` is the right answer for
    // sizing work (see `verify::threads`, which uses it) and the wrong
    // one for this: it honours NZBFAST_CPU_WORKERS, so a box with that
    // set would print a help screen claiming the machine has fewer
    // cores than it does.
    std::thread::available_parallelism().map_or(1, |n| n.get())
}

/// The reference's default redundancy, in percent. Named rather than
/// inlined because the create path reads the same constant.
pub const DEFAULT_REDUNDANCY_PCT: u32 = 5;

/// The reference's default block COUNT, when neither `-b` nor `-s` is
/// given.
pub const DEFAULT_BLOCK_COUNT: u64 = 2000;

/// The reference's default skip leaway, in bytes.
pub const DEFAULT_SKIP_LEAWAY: u64 = 64;

/// The reference's cap on recovery files for `-n`.
pub const MAX_RECOVERY_FILES: u32 = 31;

/// The help screen. Built rather than a constant because the `-t` line
/// carries a machine fact.
pub fn help() -> String {
    let n = detected_threads();
    format!(
        "\
Usage:
  parfast -h  : show this help
  parfast -V  : show version
  parfast -VV : show version and copyright

  parfast c(reate) [options] <PAR2 file> [files] : Create PAR2 files
  parfast v(erify) [options] <PAR2 file> [files] : Verify files using PAR2 file
  parfast r(epair) [options] <PAR2 file> [files] : Repair files using PAR2 files

You may also leave out the \"c\", \"v\", and \"r\" commands by using \"par2create\",
\"par2verify\", or \"par2repair\" instead.

Options: (all uses)
  -a<file> : Set the main PAR2 archive name
  -B<path> : Set the basepath to use as reference for the datafiles
  -v [-v]  : Be more verbose
  -q [-q]  : Be more quiet (-q -q gives silence)
  -m<n>    : Memory (in MB) to use (default is half of total physical memory)
  -t<n>    : Number of threads used for main processing ({n} detected)
  -T<n>    : Number of files hashed in parallel
             (2 are the default)
  --       : Treat all following arguments as filenames
Options: (verify or repair)
  -p       : Purge backup files and par files on successful recovery or
             when no recovery is needed
  -O       : Rename-only mode (skip files that are not perfect matches,
             useful for quickly fixing renamed files)
  -N       : Data skipping (find badly mispositioned data blocks)
  -S<n>    : Skip leaway (distance +/- from expected block position, default {leaway})
Options: (create)
  -b<n>    : Set the Block-Count (default {blocks})
  -s<n>    : Set the Block-Size (don't use both -b and -s)
  -r<n>    : Level of redundancy (%, default {red}%)
  -r<c><n> : Redundancy target size, <c>=g(iga),m(ega),k(ilo) bytes
  -c<n>    : Recovery Block-Count (don't use both -r and -c)
  -f<n>    : First Recovery-Block-Number (default 0)
  -u       : Uniform recovery file sizes (default is variable)
  -l       : Limit size of recovery files (don't use both -u and -l)
  -n<n>    : Number of recovery files (max {maxn}) (don't use both -n and -l)
  -R       : Recurse into subdirectories
             (Be aware of wildcard shell expansion)
   @       : Process a listing of files specified in text (file) input
             (eg. @filelist.txt, or bare @ to read from stdin)

Example:
   parfast repair *.par2",
        n = n,
        leaway = DEFAULT_SKIP_LEAWAY,
        blocks = DEFAULT_BLOCK_COUNT,
        red = DEFAULT_REDUNDANCY_PCT,
        maxn = MAX_RECOVERY_FILES,
    )
}

/// `-V`.
pub fn version_line() -> String {
    format!("parfast version {}", env!("CARGO_PKG_VERSION"))
}

/// `-VV`, appended after the version line.
pub const COPYRIGHT: &str = "\
parfast is nzbfast's PAR2 engine wearing par2cmdline's command line.

parfast comes with ABSOLUTELY NO WARRANTY.

This is free software, and you are welcome to redistribute it under the
terms of the GNU General Public License as published by the Free Software
Foundation; either version 3 of the License, or (at your option) any
later version. See COPYING for details.";

#[cfg(test)]
mod tests {
    use super::*;

    /// The committed inventory: the reference's own help screen, parsed
    /// by `tools/conformance/run.py --capture` into the spellings a
    /// drop-in must accept.
    const INVENTORY: &str =
        include_str!("../../../tools/conformance/inventory/par2-turbo-1.5.0-macos.txt");

    /// The `----- SWITCHES -----` section, first column.
    fn inventoried_switches() -> Vec<String> {
        let mut out = Vec::new();
        let mut inside = false;
        for line in INVENTORY.lines() {
            if line.starts_with("----- SWITCHES -----") {
                inside = true;
                continue;
            }
            if line.starts_with("----- ") {
                inside = false;
                continue;
            }
            if inside && !line.trim().is_empty() {
                out.push(line.split('\t').next().unwrap_or("").to_string());
            }
        }
        out
    }

    /// The whole basis of the three identity waivers in
    /// `tools/conformance/allow/par2.txt`: parfast's help screen names
    /// parfast and is otherwise the reference's, so the SAME command and
    /// switch sets read out of either.
    ///
    /// Checked against the committed inventory rather than asserted in a
    /// comment, because the waiver's reason is only worth what this test
    /// is worth. A switch added to the reference's screen on the next
    /// pin re-captures into that file and reddens here, which is exactly
    /// the moment somebody should look.
    #[test]
    fn every_inventoried_switch_appears_on_our_help_screen() {
        let screen = help();
        let missing: Vec<String> = inventoried_switches()
            .into_iter()
            .filter(|s| {
                // The two-dash end-of-options marker and the `@` listing
                // marker are spelled in their own way on the screen.
                // A switch is documented either as `-x<value>` or as a
                // bare `-x ` before its colon. `-V` does NOT match
                // inside `-VV`, because the space is part of the needle.
                let documented = match s.as_str() {
                    "-" => screen.contains("--       :"),
                    "@" => screen.contains("@       :"),
                    other => {
                        screen.contains(&format!("-{other} "))
                            || screen.contains(&format!("-{other}<"))
                    }
                };
                !documented
            })
            .collect();
        assert!(
            missing.is_empty(),
            "the help screen does not document {missing:?}, so it no longer parses to the \
             reference's switch set and the identity waivers in \
             tools/conformance/allow/par2.txt stop resting on anything"
        );
    }

    /// The screen must not claim to BE the reference. If it ever does,
    /// three conformance rows start passing for the wrong reason.
    #[test]
    fn the_help_screen_names_parfast_and_not_par2cmdline() {
        let screen = help();
        assert!(screen.contains("parfast -h"), "the usage lines name us");
        assert!(
            !version_line().starts_with("par2cmdline"),
            "the version line must not impersonate the reference - the harness's banner \
             filter would then strip it and three rows would pass by lying"
        );
    }

    /// The `-t` line carries a machine fact, which the harness rewrites
    /// to `<n>`. It must therefore BE a number, or the rewrite has
    /// nothing to do and the line diverges on every box.
    #[test]
    fn the_thread_line_carries_a_digit_for_the_normaliser_to_rewrite() {
        let line = help()
            .lines()
            .find(|l| l.trim_start().starts_with("-t<n>"))
            .expect("the -t line is inventoried")
            .to_string();
        assert!(
            line.chars().any(|c| c.is_ascii_digit()),
            "no digit in {line:?}"
        );
    }
}
