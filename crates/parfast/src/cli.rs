//! par2cmdline's argument dialect: the commands, the switches, and the
//! refusals.
//!
//! # The refusals are half the interface
//!
//! A drop-in that ACCEPTS everything is not a drop-in - it silently
//! succeeds where a script expected exit 3 and branched on it. So this
//! parser refuses exactly what the reference refuses, with the
//! reference's own wording, and `tools/conformance/run.py` holds it to
//! that per input shape: `sweep/b` is `-b` twice, `sweep/s` is `-b` and
//! `-s` together, `sweep/S` is a skip leaway with no data skipping, and
//! each is an exit 3 with a named line on stderr.
//!
//! The other half is that it must not refuse anything the reference
//! accepts. `probe_refusals` in the harness checks precisely that, over
//! the whole captured inventory, and it is the check that makes "every
//! option" mechanical rather than a reading of the manual.
//!
//! # No new short switches, ever (spec R.3)
//!
//! Anything parfast can do that the reference cannot is a GNU-style long
//! option. A new single-dash letter would collide with the reference's
//! next release and break the drop-in claim in silence on the day it did.

use std::path::PathBuf;

/// What the command line asked for.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Command {
    Create,
    Verify,
    Repair,
    Help,
    Version,
    VersionCopyright,
}

impl Command {
    /// Is this one of the three that read a recovery set?
    fn is_create(self) -> bool {
        self == Command::Create
    }
}

/// `-r`'s two spellings: a percentage, or a target size with a
/// magnitude letter (`-r3m` is three megabytes of recovery data).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Redundancy {
    /// `-r<n>`: percent of the input's block count.
    Percent(u32),
    /// `-r<c><n>`: bytes of recovery data to aim for.
    TargetBytes(u64),
}

/// Everything the switches said, already validated against each other.
#[derive(Debug, Clone, Default)]
pub struct Options {
    /// `-v` count minus `-q` count. 0 is the reference's default, which
    /// already prints the packet-load detail: see `out::Level`.
    pub level: i32,
    pub threads: Option<usize>,
    pub file_threads: Option<usize>,
    pub mem_mb: Option<u64>,
    pub basepath: Option<PathBuf>,
    pub purge: bool,
    pub rename_only: bool,
    pub data_skip: bool,
    pub skip_leaway: Option<u64>,
    pub block_count: Option<u64>,
    pub block_size: Option<u64>,
    pub redundancy: Option<Redundancy>,
    pub recovery_count: Option<u64>,
    pub first_block: u64,
    pub uniform: bool,
    pub limit: bool,
    pub recovery_files: Option<u32>,
    pub recurse: bool,
    /// `-a`, with the reference's `.par2` suffix already appended when
    /// the switch did not carry one. NOT folded into `par2` at parse
    /// time, because the two commands resolve the pair differently:
    /// create always writes to `-a`, while verify and repair fall back
    /// to the bare argument when the named archive does not exist
    /// (measured against the reference, 3 Sep 2026, and it is what makes
    /// the harness's `sweep/a` row exit 0 rather than 3).
    pub archive: Option<PathBuf>,
    /// The first bare argument: the recovery-set file on verify and
    /// repair, the set to write on create.
    pub par2: Option<PathBuf>,
    /// The data files named after it.
    pub files: Vec<PathBuf>,
}

/// A parsed command line.
#[derive(Debug, Clone)]
pub struct Parsed {
    pub command: Command,
    pub opts: Options,
}

/// Why the command line was refused.
#[derive(Debug, Clone)]
pub struct ParseError {
    /// The reference's own wording, on stderr.
    pub message: String,
    /// `-h` given as an OPTION rather than as the command prints the
    /// help screen to stdout and still exits 3, which is the one refusal
    /// that says nothing on stderr.
    pub show_usage: bool,
}

impl ParseError {
    fn msg(m: impl Into<String>) -> ParseError {
        ParseError {
            message: m.into(),
            show_usage: false,
        }
    }
}

/// The argv[0] spellings that select a command by NAME. Part of the
/// drop-in claim because scripts invoke them, and exercised by the
/// harness's `argv0-*` rows through a symlink rather than through a flag.
fn command_from_argv0(argv0: &str) -> Option<Command> {
    let base = std::path::Path::new(argv0)
        .file_stem()
        .and_then(|s| s.to_str())
        .unwrap_or(argv0);
    match base {
        "par2create" => Some(Command::Create),
        "par2verify" => Some(Command::Verify),
        "par2repair" => Some(Command::Repair),
        _ => None,
    }
}

/// Parse one command line.
pub fn parse(argv0: &str, args: &[String]) -> Result<Parsed, ParseError> {
    let (command, rest) = match command_from_argv0(argv0) {
        Some(c) => (c, args),
        None => {
            let Some(first) = args.first() else {
                return Err(ParseError::msg("Not enough command line arguments."));
            };
            match first.as_str() {
                "c" | "create" => (Command::Create, &args[1..]),
                "v" | "verify" => (Command::Verify, &args[1..]),
                "r" | "repair" => (Command::Repair, &args[1..]),
                "-h" => (Command::Help, &args[1..]),
                "-V" => (Command::Version, &args[1..]),
                "-VV" => (Command::VersionCopyright, &args[1..]),
                // UNDOCUMENTED IN THE HELP SCREEN, AND REAL. par2cmdline
                // 1.3.0 answers `--help` with the usage screen and
                // `--version` with the version line, both exit 0, but
                // neither appears on the screen the inventory fixture is
                // parsed from - so the harness's switch-superset probe
                // cannot see them and no captured row covers them. Found
                // 3 Sep 2026 by driving the two binaries side by side
                // (research/CLI-SUBSTITUTION-2026-09-03.md); spec section
                // 6 lists both in the shared set, so they are part of the
                // drop-in whatever the help text omits. `--version` maps
                // to -V, not -VV: the reference prints no copyright for
                // it. Any OTHER long option here is "Not enough command
                // line arguments." on the reference, which is the
                // `other` arm's own wording question, below.
                "--help" => (Command::Help, &args[1..]),
                "--version" => (Command::Version, &args[1..]),
                other => {
                    return Err(ParseError::msg(format!(
                        "Invalid operation specified: {other}"
                    )));
                }
            }
        }
    };
    if matches!(
        command,
        Command::Help | Command::Version | Command::VersionCopyright
    ) {
        return Ok(Parsed {
            command,
            opts: Options::default(),
        });
    }
    let opts = parse_options(command, rest)?;
    Ok(Parsed { command, opts })
}

/// A create-only switch handed to verify or repair, in the reference's
/// wording. `what` names the switch the way its message does.
fn creating_only(what: &str) -> ParseError {
    ParseError::msg(format!("Cannot specify {what} unless creating."))
}

fn number(spell: char, value: &str) -> Result<u64, ParseError> {
    if value.is_empty() || !value.bytes().all(|b| b.is_ascii_digit()) {
        return Err(ParseError::msg(format!(
            "Invalid option specified: -{spell}{value}"
        )));
    }
    value
        .parse::<u64>()
        .map_err(|_| ParseError::msg(format!("Invalid option specified: -{spell}{value}")))
}

fn parse_options(command: Command, args: &[String]) -> Result<Options, ParseError> {
    let mut o = Options::default();
    let mut bare: Vec<PathBuf> = Vec::new();
    let mut archive: Option<PathBuf> = None;
    let mut end_of_switches = false;
    let mut it = args.iter();
    while let Some(arg) = it.next() {
        if end_of_switches {
            bare.push(PathBuf::from(arg));
            continue;
        }
        if arg == "--" {
            end_of_switches = true;
            continue;
        }
        if let Some(list) = arg.strip_prefix('@') {
            for name in read_listing(list)? {
                bare.push(PathBuf::from(name));
            }
            continue;
        }
        let Some(body) = arg.strip_prefix('-') else {
            bare.push(PathBuf::from(arg));
            continue;
        };
        if body.is_empty() {
            bare.push(PathBuf::from(arg));
            continue;
        }
        let mut chars = body.chars();
        let spell = chars.next().expect("body is non-empty");
        let value: String = chars.collect();
        apply_switch(command, &mut o, &mut archive, spell, &value)?;
        let _ = &mut it;
    }
    // -S without -N is the reference's own refusal, and it is checked
    // AFTER the whole line because the two may arrive in either order.
    if o.skip_leaway.is_some() && !o.data_skip {
        return Err(ParseError::msg(
            "Cannot specify skip leaway and no skipping.",
        ));
    }
    if o.block_count.is_some() && o.block_size.is_some() {
        return Err(ParseError::msg(
            "Cannot specify both block count and block size.",
        ));
    }
    if o.uniform && o.limit {
        return Err(ParseError::msg(
            "Cannot specify uniform and limit at the same time.",
        ));
    }
    if o.recovery_files.is_some() && o.limit {
        return Err(ParseError::msg(
            "Cannot specify limit and number of files at the same time.",
        ));
    }
    if o.redundancy.is_some() && o.recovery_count.is_some() {
        return Err(ParseError::msg(
            "Cannot specify both redundancy and recovery block count.",
        ));
    }
    let mut bare = bare.into_iter();
    o.archive = archive.map(with_par2_suffix);
    o.par2 = bare.next();
    o.files = bare.collect();
    Ok(o)
}

/// One switch. Split out of [`parse_options`] so neither function
/// approaches the size gate's 500-line ceiling as the dialect grows.
fn apply_switch(
    command: Command,
    o: &mut Options,
    archive: &mut Option<PathBuf>,
    spell: char,
    value: &str,
) -> Result<(), ParseError> {
    let creating = command.is_create();
    match spell {
        // ---- all uses ----
        'a' => *archive = Some(PathBuf::from(value)),
        'B' => o.basepath = Some(PathBuf::from(value)),
        'v' => o.level += 1 + value.chars().filter(|&c| c == 'v').count() as i32,
        'q' => o.level -= 1 + value.chars().filter(|&c| c == 'q').count() as i32,
        'm' => o.mem_mb = Some(number('m', value)?),
        't' => o.threads = Some(number('t', value)? as usize),
        'T' => o.file_threads = Some(number('T', value)? as usize),
        // ---- verify or repair ----
        'p' => o.purge = true,
        'O' => o.rename_only = true,
        'N' => o.data_skip = true,
        'S' => o.skip_leaway = Some(number('S', value)?),
        // ---- create ----
        'b' => {
            if !creating {
                return Err(creating_only("block count"));
            }
            if o.block_count.is_some() {
                return Err(ParseError::msg("Cannot specify block count twice."));
            }
            o.block_count = Some(number('b', value)?);
        }
        's' => {
            if !creating {
                return Err(creating_only("block size"));
            }
            if o.block_size.is_some() {
                return Err(ParseError::msg("Cannot specify block size twice."));
            }
            o.block_size = Some(number('s', value)?);
        }
        'r' => {
            if !creating {
                return Err(creating_only("redundancy"));
            }
            o.redundancy = Some(parse_redundancy(value)?);
        }
        'c' => {
            if !creating {
                return Err(creating_only("recovery block count"));
            }
            o.recovery_count = Some(number('c', value)?);
        }
        'f' => {
            if !creating {
                return Err(creating_only("first block"));
            }
            o.first_block = number('f', value)?;
        }
        'u' => {
            if !creating {
                return Err(creating_only("uniform files"));
            }
            o.uniform = true;
        }
        'l' => {
            if !creating {
                return Err(creating_only("limited files"));
            }
            o.limit = true;
        }
        'n' => {
            if !creating {
                return Err(creating_only("recovery file count"));
            }
            let n = number('n', value)? as u32;
            if n == 0 || n > crate::help::MAX_RECOVERY_FILES {
                return Err(ParseError::msg("Invalid recovery file count option."));
            }
            o.recovery_files = Some(n);
        }
        'R' => {
            if !creating {
                return Err(creating_only("recursive"));
            }
            o.recurse = true;
        }
        // `-h` as an OPTION prints the help to STDOUT and still exits 3.
        // The captured `sweep/h` row is the whole reason this is not an
        // ordinary "invalid option": stdout carries the screen and
        // stderr is empty.
        'h' if value.is_empty() => {
            return Err(ParseError {
                message: String::new(),
                show_usage: true,
            });
        }
        // A LONG option the reference does not know is refused in
        // different words from a short one: `Unknown option: --zzz`
        // rather than `Invalid option specified: -Z`. Both exit 3, so an
        // exit-code table cannot see the difference and none of the
        // captured rows did; a script that greps stderr can. Measured
        // against par2cmdline 1.3.0 on 3 Sep 2026.
        '-' if !value.is_empty() => {
            return Err(ParseError::msg(format!("Unknown option: --{value}")));
        }
        _ => {
            return Err(ParseError::msg(format!(
                "Invalid option specified: -{spell}{value}"
            )));
        }
    }
    Ok(())
}

/// `-r30` is 30 percent; `-r3m` is three megabytes of recovery data.
fn parse_redundancy(value: &str) -> Result<Redundancy, ParseError> {
    let bad = || ParseError::msg(format!("Invalid option specified: -r{value}"));
    let mut chars = value.chars();
    let first = chars.next().ok_or_else(bad)?;
    let scale = match first {
        'k' | 'K' => 1024u64,
        'm' | 'M' => 1024 * 1024,
        'g' | 'G' => 1024 * 1024 * 1024,
        _ => {
            let pct = value.parse::<u32>().map_err(|_| bad())?;
            return Ok(Redundancy::Percent(pct));
        }
    };
    let rest: String = chars.collect();
    let n = rest.parse::<u64>().map_err(|_| bad())?;
    n.checked_mul(scale)
        .map(Redundancy::TargetBytes)
        .ok_or_else(bad)
}

/// `-a` names a PAR2 archive, and the reference appends the extension
/// when the switch did not carry one: `-asweeplist.txt` looks for
/// `sweeplist.txt.par2`.
fn with_par2_suffix(p: PathBuf) -> PathBuf {
    let is_par2 = p
        .extension()
        .and_then(|e| e.to_str())
        .is_some_and(|e| e.eq_ignore_ascii_case("par2"));
    if is_par2 {
        return p;
    }
    let mut name = p.clone().into_os_string();
    name.push(".par2");
    PathBuf::from(name)
}

/// `@filelist.txt`, or a bare `@` for stdin. One name per line; blank
/// lines are skipped, as the reference's own listing reader does.
fn read_listing(path: &str) -> Result<Vec<String>, ParseError> {
    use std::io::Read as _;
    let text = if path.is_empty() {
        let mut s = String::new();
        std::io::stdin()
            .read_to_string(&mut s)
            .map_err(|e| ParseError::msg(format!("Failed to read file list from stdin: {e}")))?;
        s
    } else {
        std::fs::read_to_string(path)
            .map_err(|e| ParseError::msg(format!("Failed to open file list {path}: {e}")))?
    };
    Ok(text
        .lines()
        .map(str::trim)
        .filter(|l| !l.is_empty())
        .map(str::to_owned)
        .collect())
}
