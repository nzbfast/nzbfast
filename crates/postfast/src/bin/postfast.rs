//! `postfast`: the layout generator's command line.
//!
//! Two verbs. `postfast gen <profile.toml> <out dir>` loads a profile,
//! builds its layout and writes the whole of it to disk: the files that
//! would be posted, every article, and the NZB. That is what the
//! CLI-compatibility conformance harness drives (spec section 11) - it
//! needs a real directory of real bytes to hand a reference binary and
//! ours - and it is also the fastest way for a person to look at what a
//! profile actually produces before writing a test around it.
//!
//! `postfast post <profile.toml> <path>...` posts the layout a profile
//! describes over REAL files. It is behind the `live-post` feature and
//! **off by default**: uploading is a separately gated deliverable
//! (spec section 12), so an ordinary build carries no posting path at
//! all and the verb refuses with one line and exit 2. The verb still
//! exists in that build on purpose - a verb that vanished would read as
//! a packaging accident rather than as a decision. See
//! `crate::post`'s header for the deployment plane and the gate.

use std::path::{Path, PathBuf};
use std::process::ExitCode;

use postfast::layout::Layout;
use postfast::post;
use postfast::profile::Profile;

/// Exit classes, so a harness can branch on the reason rather than on
/// the message: 1 is a layout that would not build, 2 is a command line
/// this build cannot serve - a bad one, or (the same thing from the
/// caller's side) a gated verb this build does not carry.
const EXIT_GENERAL: u8 = 1;
const EXIT_USAGE: u8 = 2;

fn main() -> ExitCode {
    let args: Vec<String> = std::env::args().skip(1).collect();
    ExitCode::from(dispatch(&args))
}

/// The whole command line as a status code, so the gate's refusal is
/// something a test can assert on rather than something only a spawned
/// process can observe.
fn dispatch(args: &[String]) -> u8 {
    match args.first().map(String::as_str) {
        // `gen --help` is a request for help, not a malformed `gen`:
        // asking a verb what it takes is the habit every command line
        // trains, and answering it with a silent exit 2 reads as a
        // failure the caller cannot see the cause of.
        Some("gen") if args[1..].iter().any(|a| a == "--help" || a == "-h") => {
            print!("{USAGE}");
            0
        }
        Some("gen") if args.len() == 3 => run_gen(Path::new(&args[1]), Path::new(&args[2])),
        // A `gen` with the wrong arity used to fall into the catch-all
        // and print the usage screen with NOTHING saying what was
        // wrong, which `post` has never done - so the two verbs
        // disagreed about whether a refusal owes the caller a reason.
        // It does (research/CLI-SUBSTITUTION-2026-09-03.md, part 3).
        Some("gen") => {
            eprintln!(
                "postfast: gen takes a profile and an output directory: \
                 postfast gen <profile.toml> <out dir>"
            );
            EXIT_USAGE
        }
        Some("post") => run_post(&args[1..]),
        Some("--help") | Some("-h") | None => {
            print!("{USAGE}");
            0
        }
        other => {
            if let Some(verb) = other {
                eprintln!("postfast: unknown command {verb}");
            }
            eprint!("{USAGE}");
            EXIT_USAGE
        }
    }
}

const USAGE: &str = "\
postfast - posting-layout generator

  postfast gen  <profile.toml> <out dir>
  postfast post <profile.toml> <path>... --server <name> --config <path> --nzb <out>

gen builds the layout the profile describes and writes it to <out dir>:

  files/     the files that would be posted, under the names they carry
             on disk (directories and all)
  articles/  one file per article, named for its message-id
  <name>.nzb the NZB that recovers them

The layout is derived entirely from the profile and its seed, so the
same profile writes the same bytes on every machine and every run.

post builds the same layout over REAL input files (the paths replace the
profile's [source] list) and uploads it, writing the NZB to --nzb.
Uploading is gated: an ordinary build refuses this verb. Deployment
options, all optional:

  --group <name>     post into this group; repeat to crosspost
  --spread-ms <n>    pause n milliseconds between articles
  --nfo, --sfv       post a companion metadata file beside the payload
  --verify           re-download the post and compare hashes
  --connections <n>  connections the verify pool opens (default 4)
";

fn run_gen(profile_path: &Path, out: &Path) -> u8 {
    let profile = match Profile::load(profile_path) {
        Ok(p) => p,
        Err(e) => return fail(&e.to_string()),
    };
    let layout = match postfast::layout::generate(&profile) {
        Ok(l) => l,
        Err(e) => return fail(&e.to_string()),
    };
    match write_layout(&layout, &profile, out) {
        Ok(n) => {
            println!(
                "{}: {} file(s), {} article(s), fingerprint {:016x} -> {}",
                profile.layout.name,
                layout.files.len(),
                layout.articles.len(),
                layout.fingerprint(),
                n.display()
            );
            0
        }
        Err(e) => fail(&e),
    }
}

/// The posting verb.
///
/// The arguments are parsed in BOTH builds, and the gate is checked
/// after they are: a refusal that also told you the command line was
/// wrong is worth more than one that stopped at the feature flag, and
/// it keeps the two builds agreeing about what the verb accepts.
fn run_post(argv: &[String]) -> u8 {
    let args = match post::parse_args(argv) {
        Ok(a) => a,
        Err(e) => {
            eprintln!("postfast: {e}");
            return EXIT_USAGE;
        }
    };
    post_run(&args)
}

#[cfg(not(feature = "live-post"))]
fn post_run(_args: &post::Args) -> u8 {
    eprintln!("postfast: {}", post::GATE);
    post::GATE_EXIT
}

#[cfg(feature = "live-post")]
fn post_run(args: &post::Args) -> u8 {
    let rt = match tokio::runtime::Runtime::new() {
        Ok(rt) => rt,
        Err(e) => return fail(&format!("starting the runtime: {e}")),
    };
    match rt.block_on(post::run(args)) {
        Ok(r) => {
            println!(
                "{}: {} file(s), {} article(s), {} byte(s) posted, {} -> {}",
                r.profile,
                r.files,
                r.articles,
                r.bytes,
                if r.verified {
                    "round trip proven"
                } else {
                    "not verified"
                },
                r.nzb.display()
            );
            0
        }
        Err(e) => fail(&e.to_string()),
    }
}

fn fail(msg: &str) -> u8 {
    eprintln!("postfast: {msg}");
    EXIT_GENERAL
}

/// Write a layout out, returning the path of the NZB.
///
/// An article's file is named for its message-id WITHOUT the angle
/// brackets the map is keyed with: `<` and `>` are reserved characters
/// in a Windows filename, and a generator whose output directory cannot
/// be unpacked on one of the three platforms the client ships to is a
/// generator the conformance harness cannot run there.
fn write_layout(layout: &Layout, profile: &Profile, out: &Path) -> Result<PathBuf, String> {
    let files_dir = out.join("files");
    let arts_dir = out.join("articles");
    mkdir(&files_dir)?;
    mkdir(&arts_dir)?;
    for (name, bytes) in &layout.files {
        let path = files_dir.join(name);
        if let Some(parent) = path.parent() {
            mkdir(parent)?;
        }
        write(&path, bytes)?;
    }
    for (id, body) in &layout.articles {
        let bare = id.trim_start_matches('<').trim_end_matches('>');
        write(&arts_dir.join(format!("{bare}.txt")), body)?;
    }
    let nzb = out.join(format!("{}.nzb", profile.layout.name));
    write(&nzb, layout.nzb.as_bytes())?;
    Ok(nzb)
}

/// `std::io::Error` carries the errno and NOT the path, so an
/// unwritable output directory used to be the whole of `postfast:
/// Permission denied (os error 13)` - true, and useless: it named
/// neither the directory nor which of the four write sites hit it. Every
/// filesystem step in `write_layout` goes through these two so the
/// message says what was being done and to what
/// (research/CLI-SUBSTITUTION-2026-09-03.md, part 3).
fn mkdir(path: &Path) -> Result<(), String> {
    std::fs::create_dir_all(path)
        .map_err(|e| format!("cannot create directory {}: {e}", path.display()))
}

fn write(path: &Path, bytes: &[u8]) -> Result<(), String> {
    std::fs::write(path, bytes).map_err(|e| format!("cannot write {}: {e}", path.display()))
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    /// The gate, from the command line's side: a well-formed `post`
    /// exits 2 in a build without the feature, and the message it
    /// prints is the one the module owns.
    ///
    /// Feature-off only, deliberately. With `live-post` on this same
    /// line would open a socket, and the acceptance test for that build
    /// lives beside the mock in `post.rs`.
    #[cfg(not(feature = "live-post"))]
    #[test]
    fn a_gated_build_refuses_the_post_verb_with_exit_2() {
        let code = dispatch(&argv(
            "post p.toml a.bin --server news --config c.json --nzb out.nzb",
        ));
        assert_eq!(code, post::GATE_EXIT);
        assert_eq!(code, 2);
    }

    /// ...and the arguments are still parsed first, so a gated build
    /// and a posting build agree about what the verb accepts.
    #[test]
    fn a_bad_post_command_line_is_a_usage_refusal_in_either_build() {
        assert_eq!(dispatch(&argv("post")), EXIT_USAGE);
        assert_eq!(
            dispatch(&argv("post p.toml a.bin --server news")),
            EXIT_USAGE
        );
    }

    /// An unknown verb is a usage refusal and `--help` is not.
    #[test]
    fn the_verb_table_is_what_it_says() {
        assert_eq!(dispatch(&argv("frobnicate")), EXIT_USAGE);
        assert_eq!(dispatch(&argv("--help")), 0);
        assert_eq!(dispatch(&[]), 0);
    }

    /// `gen` with the wrong arity is a refusal that SAYS SO, and asking
    /// the verb for help is help. Both were silent exit-2 paths through
    /// the catch-all until 3 Sep 2026
    /// (research/CLI-SUBSTITUTION-2026-09-03.md, part 3); the arity arms
    /// are here so a later edit to the match cannot quietly put them
    /// back, and the `gen --help` arm is checked at BOTH spellings
    /// because a caller reaches for either.
    #[test]
    fn a_gen_that_cannot_run_is_refused_in_words_and_gen_help_is_help() {
        assert_eq!(dispatch(&argv("gen")), EXIT_USAGE);
        assert_eq!(dispatch(&argv("gen only-a-profile.toml")), EXIT_USAGE);
        assert_eq!(dispatch(&argv("gen a.toml out one-too-many")), EXIT_USAGE);
        assert_eq!(dispatch(&argv("gen --help")), 0);
        assert_eq!(dispatch(&argv("gen -h")), 0);
        // ...and the help arm must not swallow a real run whose PATHS
        // merely happen to sit either side of it.
        assert_eq!(dispatch(&argv("gen a.toml out")), EXIT_GENERAL);
    }
}
