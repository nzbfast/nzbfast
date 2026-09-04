//! `postfast post`: the profile-driven posting tool, behind the
//! `live-post` cargo feature.
//!
//! A layout profile plus REAL input files go in; the articles the
//! profile describes go out over NNTP, and the NZB that recovers them
//! is written beside them. It is the same [`crate::layout::Layout`] the
//! oracle runs against, so what a profile posts to a server is what the
//! catalog says that profile is - there is no second encoder, no second
//! namer and no second NZB emitter on this path.
//!
//! **Nothing here uploads to a live server, and the whole module is off
//! by default.** Spec section 12 puts the posting tool behind a
//! distribution gate: it is a separately gated deliverable that follows
//! the standing process for a legal read before public release, and
//! that read has not come back. So the network half is compiled ONLY
//! under `--features live-post`, the feature is off in every CI job and
//! in every documented build line, and the one test that exercises it
//! runs against `nzbkit::mock::MockServer` on loopback. Without the
//! feature the verb still exists, prints [`GATE`] and exits 2 - a verb
//! that vanished would read as a missing build rather than a decision.
//!
//! **What is always compiled** is everything that is not a socket: the
//! command line, the `[source]` override, the wire-article assembly and
//! the companion metadata. Those carry their own tests in an ordinary
//! feature-off build, which is where nearly all of this module's
//! behaviour is actually pinned.
//!
//! The deployment plane (spec 7.G) is flags rather than profile fields,
//! because no oracle row exercises it and a profile that could select a
//! newsgroup would be a catalog carrying group names:
//!
//! - **D1 group selection / crosspost**: `--group`, repeatable. Every
//!   named group rides the `Newsgroups` header and the NZB's
//!   `<groups>`; with none given the layout's own group stands.
//! - **D2 timing spread**: `--spread-ms`, a fixed pause between
//!   articles, so a post is not one burst.
//! - **D3 back-end selection**: `--server` resolved against a config
//!   file named by `--config`, the same resolution rule
//!   `nzbfast post --post-server` applies.
//! - **D4 companion metadata**: `--nfo` and `--sfv` post a companion
//!   file beside the payload and list it in the NZB.

use std::collections::HashSet;
use std::path::PathBuf;

use crate::layout::Layout;
use crate::profile::{self, Profile};

/// The one line the verb prints when the feature is off.
///
/// It names the gate rather than the flag, because "rebuild with
/// `--features live-post`" alone would read as a packaging oversight
/// and this is a decision: see spec section 12.
pub const GATE: &str = "post is gated: uploading is a separately gated deliverable awaiting a \
                        legal read (spec section 12), so this build carries no posting path. \
                        A build for posting against a local mock is cargo --features live-post.";

/// Exit status the gated verb returns. The same 2 the command line uses
/// for a usage refusal, and for the same reason from the caller's side:
/// this build cannot do what was asked, and no retry changes that.
pub const GATE_EXIT: u8 = 2;

// ---------------------------------------------------------------------
// The command line
// ---------------------------------------------------------------------

/// Parsed `postfast post` arguments.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Args {
    /// The layout profile. Its `[source]` list is REPLACED by the real
    /// files below; every other plane is honoured as written.
    pub profile: PathBuf,
    /// Files and directories to post. Walked by
    /// `nzbkit::post::plan_with`, so the admission rules (hidden files
    /// skipped, duplicate posted names refused) are the posting
    /// engine's own and not a second copy of them.
    pub paths: Vec<PathBuf>,
    /// D3: which configured server to post through.
    pub server: String,
    /// The config the server is resolved against. REQUIRED, with no
    /// default on purpose: a posting tool that finds an account config
    /// on its own is a posting tool that can reach a real provider
    /// because somebody left a file where it always is.
    pub config: PathBuf,
    /// Where the NZB is written.
    pub nzb: PathBuf,
    /// D1: groups to post into. Empty means the layout's own group.
    pub groups: Vec<String>,
    /// D2: pause between consecutive articles, in milliseconds.
    pub spread_ms: u64,
    /// D4: companion metadata to post beside the payload.
    pub companions: Companions,
    /// Re-download the post and compare hashes before reporting
    /// success, the way `nzbfast post --verify` does.
    pub verify: bool,
    /// Connections the verify pool opens. The post itself is one
    /// connection by construction - see [`Args::spread_ms`]: a spread
    /// is a statement about the ORDER articles reach a server in, and
    /// concurrent workers have no order to space out.
    pub connections: usize,
}

/// D4: which companion files to write and post.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct Companions {
    pub nfo: bool,
    pub sfv: bool,
}

impl Companions {
    fn any(&self) -> bool {
        self.nfo || self.sfv
    }
}

/// Why a command line was refused.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ArgError {
    /// A required option was not given.
    Missing(&'static str),
    /// An option that takes a value was written last.
    NeedsValue(String),
    /// A flag this verb does not have.
    Unknown(String),
    /// A numeric option whose value is not a number.
    NotANumber { flag: String, value: String },
    /// No profile, or no paths after it.
    NoInput,
    /// A `--group` value that could not ride a `Newsgroups` header or
    /// an NZB `<group>` element.
    BadGroup(String),
}

impl std::fmt::Display for ArgError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Missing(o) => write!(f, "{o} is required"),
            Self::NeedsValue(o) => write!(f, "{o} takes a value and was given none"),
            Self::Unknown(o) => write!(f, "unknown option {o:?}"),
            Self::NotANumber { flag, value } => {
                write!(f, "{flag} takes a number and was given {value:?}")
            }
            Self::NoInput => f.write_str(
                "post takes a profile and at least one file or directory to post: \
                 postfast post <profile.toml> <path>... --server <name> --config <path> \
                 --nzb <out>",
            ),
            Self::BadGroup(g) => write!(
                f,
                "--group {g:?} is not a group name a header can carry: it must be non-empty \
                 and hold no comma (the crosspost separator), whitespace or control character"
            ),
        }
    }
}

impl std::error::Error for ArgError {}

/// Parse the arguments that follow `postfast post`.
pub fn parse_args(argv: &[String]) -> Result<Args, ArgError> {
    let mut positional: Vec<PathBuf> = Vec::new();
    let mut server = String::new();
    let mut config: Option<PathBuf> = None;
    let mut nzb: Option<PathBuf> = None;
    let mut groups: Vec<String> = Vec::new();
    let mut spread_ms = 0u64;
    let mut companions = Companions::default();
    let mut verify = false;
    let mut connections = 4usize;

    let mut i = 0;
    while i < argv.len() {
        let a = argv[i].as_str();
        // A value-taking option, fetched once so a missing value is one
        // refusal rather than five copies of the same three lines.
        let value = |i: &mut usize| -> Result<String, ArgError> {
            *i += 1;
            argv.get(*i)
                .cloned()
                .ok_or_else(|| ArgError::NeedsValue(a.to_string()))
        };
        match a {
            "--server" => server = value(&mut i)?,
            "--config" => config = Some(PathBuf::from(value(&mut i)?)),
            "--nzb" => nzb = Some(PathBuf::from(value(&mut i)?)),
            "--group" => {
                let g = value(&mut i)?;
                check_group(&g)?;
                groups.push(g);
            }
            "--spread-ms" => {
                let v = value(&mut i)?;
                spread_ms = v.parse().map_err(|_| ArgError::NotANumber {
                    flag: "--spread-ms".into(),
                    value: v,
                })?;
            }
            "--connections" => {
                let v = value(&mut i)?;
                connections = v.parse().map_err(|_| ArgError::NotANumber {
                    flag: "--connections".into(),
                    value: v,
                })?;
            }
            "--nfo" => companions.nfo = true,
            "--sfv" => companions.sfv = true,
            "--verify" => verify = true,
            other if other.starts_with("--") => return Err(ArgError::Unknown(other.to_string())),
            other => positional.push(PathBuf::from(other)),
        }
        i += 1;
    }

    if positional.len() < 2 {
        return Err(ArgError::NoInput);
    }
    if server.trim().is_empty() {
        return Err(ArgError::Missing("--server"));
    }
    let profile = positional.remove(0);
    Ok(Args {
        profile,
        paths: positional,
        server,
        config: config.ok_or(ArgError::Missing("--config"))?,
        nzb: nzb.ok_or(ArgError::Missing("--nzb"))?,
        groups,
        spread_ms,
        companions,
        verify,
        // A zero here is a hang rather than a setting, the same way it
        // is in the pool: one connection is the smallest honest answer.
        connections: connections.clamp(1, 16),
    })
}

/// A group name has to survive a `Newsgroups` header line and an NZB
/// `<group>` element. The comma is excluded because it is the crosspost
/// separator, so a comma inside one name would silently become two.
fn check_group(g: &str) -> Result<(), ArgError> {
    let bad = g.is_empty()
        || g.chars()
            .any(|c| c.is_control() || c.is_whitespace() || c == ',' || c == '<' || c == '>');
    if bad {
        return Err(ArgError::BadGroup(g.to_string()));
    }
    Ok(())
}

// ---------------------------------------------------------------------
// Errors
// ---------------------------------------------------------------------

/// Why a post could not be prepared or sent.
#[derive(Debug)]
pub enum PostError {
    Args(ArgError),
    Profile(profile::ProfileError),
    Gen(crate::layout::GenError),
    Io(std::io::Error),
    /// The input walk refused the paths (the posting engine's own
    /// admission rules).
    Plan(String),
    /// The generated NZB does not parse, or does not carry the marker a
    /// companion entry is spliced before. Failing to find is failing:
    /// an emitter change that moved either is reported here rather than
    /// working around it.
    Nzb(String),
    /// An article in the map has no header block, so there is no From,
    /// Subject or Date to put in front of it.
    NoHeaders(String),
    /// A header block that is missing a header the wire needs, or whose
    /// Date this tree's own parser will not read back.
    BadHeaders {
        id: String,
        header: String,
    },
    /// `--server` did not resolve to exactly one enabled server.
    Server(String),
    /// The server refused, or the link failed.
    Wire(String),
    /// A verify that came back with something other than the bytes that
    /// went out.
    Verify(String),
}

impl std::fmt::Display for PostError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Args(e) => write!(f, "{e}"),
            Self::Profile(e) => write!(f, "{e}"),
            Self::Gen(e) => write!(f, "{e}"),
            Self::Io(e) => write!(f, "I/O: {e}"),
            Self::Plan(m) => write!(f, "{m}"),
            Self::Nzb(m) => write!(f, "{m}"),
            Self::NoHeaders(id) => write!(
                f,
                "the layout serves article {id} with no header block, so there is no From, \
                 Subject or Date to post it under"
            ),
            Self::BadHeaders { id, header } => write!(
                f,
                "article {id}'s header block carries no readable {header}"
            ),
            Self::Server(m) => write!(f, "{m}"),
            Self::Wire(m) => write!(f, "{m}"),
            Self::Verify(m) => write!(f, "{m}"),
        }
    }
}

impl std::error::Error for PostError {}

impl From<std::io::Error> for PostError {
    fn from(e: std::io::Error) -> Self {
        Self::Io(e)
    }
}
impl From<ArgError> for PostError {
    fn from(e: ArgError) -> Self {
        Self::Args(e)
    }
}
impl From<profile::ProfileError> for PostError {
    fn from(e: profile::ProfileError) -> Self {
        Self::Profile(e)
    }
}
impl From<crate::layout::GenError> for PostError {
    fn from(e: crate::layout::GenError) -> Self {
        Self::Gen(e)
    }
}

// ---------------------------------------------------------------------
// The `[source]` override
// ---------------------------------------------------------------------

/// One real input file: the name the post will carry it under, and its
/// bytes.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Input {
    /// Path relative to the posted root, forward-slashed. The same
    /// `rel` `nzbkit::post::plan_with` computes, so a posted directory
    /// tree reaches `[source]` the way it reaches a real post's
    /// recovery packets.
    pub rel: String,
    pub bytes: Vec<u8>,
}

/// Walk `paths` and read what the posting engine would post.
///
/// The WALK is `nzbkit::post::plan_with`'s, not a second copy of it:
/// hidden files skipped, directories walked, duplicate posted names
/// refused, and the ordering deterministic. `allow_empty` is on because
/// a 0-byte member is a real posted shape the catalog carries (the
/// placeholder row), and [`crate::assemble`] admits one.
///
/// `article_size` only decides how the plan splits parts, which this
/// function does not use; it is passed through so the plan is built the
/// way the profile would post it and an article size the engine refuses
/// is refused here rather than three stages later.
pub fn read_inputs(paths: &[PathBuf], article_size: usize) -> Result<Vec<Input>, PostError> {
    let plan = nzbkit::post::plan_with(
        paths,
        article_size,
        &nzbkit::post::PlanOpts {
            allow_empty: true,
            obfuscate: None,
        },
    )
    .map_err(|e| PostError::Plan(e.to_string()))?;
    // The cap BEFORE the read, not after: `[source]`'s own refusal
    // would arrive having already pulled the files into memory.
    let total: u64 = plan.iter().map(|f| f.size).sum();
    if total > crate::assemble::MAX_TOTAL_PAYLOAD {
        return Err(PostError::Plan(format!(
            "the named paths hold {total} bytes, over the {}-byte cap a layout's payload may \
             reach: post a smaller set",
            crate::assemble::MAX_TOTAL_PAYLOAD
        )));
    }
    let mut out = Vec::with_capacity(plan.len());
    for f in &plan {
        out.push(Input {
            rel: f.rel.clone(),
            bytes: std::fs::read(&f.path)?,
        });
    }
    Ok(out)
}

/// Replace a profile's `[source]` with the real files.
///
/// The override is total and it is loud: every `[source]` entry the
/// profile wrote is dropped, because a posting run is about files
/// somebody has and a catalog profile's lengths are an invention for
/// the oracle. Every OTHER plane is honoured exactly as written, which
/// is what makes "post this release the way profile X describes"
/// meaningful.
///
/// The rewritten profile is re-validated downstream by
/// [`crate::layout::generate_over`], so a real input set that
/// contradicts the profile (a one-file set under a plane that needs
/// two, say) is refused by name rather than quietly built.
pub fn override_source(profile: &Profile, inputs: &[Input]) -> Profile {
    let mut p = profile.clone();
    p.source.files = inputs
        .iter()
        .map(|i| profile::SourceFile {
            name: i.rel.clone(),
            bytes: i.bytes.len() as u64,
            // A real file's head is whatever the file's head is. G2's
            // zero head is a property of a GENERATED payload, and
            // `generate_over` throws the generated bytes away, so
            // carrying the profile's value here would state a fact
            // about these bytes that nothing checked.
            zero_head: 0,
            // Same reason: a posting run is over files somebody has, and
            // two of them being copies of each other is a fact about the
            // disk rather than a plane the profile selects.
            same_as: String::new(),
            // And a real post is over the files as they are: cutting
            // one into raw parts is a POSTING decision the deployment
            // plane owns, not a fact about the input.
            split: 0,
            split_names: profile::SplitNames::Join,
            // And G8's content shape, for the same reason as G2's head:
            // it describes bytes this crate GENERATES, and these bytes
            // came off somebody's disk. What a real file looks like is
            // whatever it looks like.
            content: profile::Content::Noise,
        })
        .collect();
    p
}

/// Profile plus real files to a layout, in one step: the whole of what
/// this tool does before a socket is opened.
pub fn layout_for(profile: &Profile, inputs: Vec<Input>) -> Result<(Profile, Layout), PostError> {
    let p = override_source(profile, &inputs);
    let payload: Vec<Vec<u8>> = inputs.into_iter().map(|i| i.bytes).collect();
    let layout = crate::layout::generate_over(&p, payload)?;
    Ok((p, layout))
}

// ---------------------------------------------------------------------
// Wire articles
// ---------------------------------------------------------------------

/// One article ready for the POST/IHAVE path.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Wire {
    /// Message-ID WITHOUT angle brackets, which is what
    /// `nzbkit::post::post_article` takes.
    pub message_id: String,
    /// The full wire form: headers, blank line, dot-stuffed body,
    /// terminating lone dot.
    pub wire: Vec<u8>,
}

/// Assemble every article the layout serves, in post order.
///
/// **Post order is the NZB's order**, then whatever the map holds that
/// the NZB does not name. Both halves are deliberate. The NZB is what a
/// client reads, so posting in its order is what a real poster does;
/// and an article the NZB leaves out is still an article the layout
/// generated, so it is posted rather than dropped - the Z plane's
/// "segments missing from the map" row is about what the NZB SAYS, and
/// a tool that answered by never posting those bytes would be pinning a
/// different shape than the profile asked for.
///
/// The From, Subject and Date come from the layout's own header block
/// for that article, so a plane that varies the subject per part or
/// backdates a post reaches the wire exactly as generated. The
/// Newsgroups line is the one header this tool overrides, because the
/// group is a deployment decision (D1) and not a layout plane.
pub fn wire_articles(layout: &Layout, groups: &[String]) -> Result<Vec<Wire>, PostError> {
    let nzb = nzbkit::nzb::Nzb::parse(layout.nzb.as_bytes())
        .map_err(|e| PostError::Nzb(format!("the generated NZB does not parse: {e}")))?;
    let mut order: Vec<String> = Vec::with_capacity(layout.articles.len());
    let mut seen: HashSet<String> = HashSet::new();
    for f in &nzb.files {
        for s in &f.segments {
            let key = format!("<{}>", s.message_id);
            if layout.articles.contains_key(&key) && seen.insert(key.clone()) {
                order.push(key);
            }
        }
    }
    let mut rest: Vec<&String> = layout
        .articles
        .keys()
        .filter(|k| !seen.contains(*k))
        .collect();
    rest.sort();
    order.extend(rest.into_iter().cloned());

    let crosspost = if groups.is_empty() {
        None
    } else {
        Some(groups.join(","))
    };
    let mut out = Vec::with_capacity(order.len());
    for key in order {
        let body = &layout.articles[&key];
        let block = layout
            .headers
            .get(&key)
            .ok_or_else(|| PostError::NoHeaders(key.clone()))?;
        let want = |h: &str| -> Result<String, PostError> {
            header_value(block, h).ok_or_else(|| PostError::BadHeaders {
                id: key.clone(),
                header: h.to_string(),
            })
        };
        let from = want("From")?;
        let subject = want("Subject")?;
        let date_text = want("Date")?;
        let date =
            nzbkit::nntp::parse_nntp_date(&date_text).ok_or_else(|| PostError::BadHeaders {
                id: key.clone(),
                header: "Date".into(),
            })?;
        let group = match &crosspost {
            Some(g) => g.clone(),
            None => want("Newsgroups")?,
        };
        let bare = key
            .trim_start_matches('<')
            .trim_end_matches('>')
            .to_string();
        out.push(Wire {
            wire: nzbkit::post::build_wire_article(&from, &group, &subject, &bare, date, body),
            message_id: bare,
        });
    }
    Ok(out)
}

/// One header's value out of a CRLF-framed block. Case-insensitive on
/// the name, because the block is ours today and a header block is not
/// a place to assume casing forever.
fn header_value(block: &[u8], key: &str) -> Option<String> {
    let text = String::from_utf8_lossy(block);
    for line in text.split("\r\n") {
        let (name, value) = line.split_once(':')?;
        if name.eq_ignore_ascii_case(key) {
            return Some(value.trim().to_string());
        }
    }
    None
}

// ---------------------------------------------------------------------
// D4: companion metadata
// ---------------------------------------------------------------------

/// A companion file: posted beside the payload and listed in the NZB,
/// but not part of the layout, because no plane selects it and no
/// oracle row grades it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Companion {
    /// The name on the wire and in the NZB subject.
    pub name: String,
    /// The file's own bytes, before yEnc.
    pub content: Vec<u8>,
    /// Message-ID without angle brackets.
    pub message_id: String,
    pub subject: String,
    /// The yEnc article body.
    pub body: Vec<u8>,
}

/// Build the companions `--nfo` / `--sfv` asked for.
///
/// Each is one article: an nfo is a few hundred bytes and an sfv is one
/// line per posted file, so neither is ever a multi-part file and the
/// single-part yEnc form is the honest framing for both.
///
/// The Message-ID is derived from the layout's fingerprint rather than
/// drawn, so the same profile over the same files posts the same
/// companion id. That matters for the same reason the layout's own ids
/// are seeded: a run that produced a different id every time could not
/// be compared with the run before it.
pub fn companions(profile: &Profile, layout: &Layout, want: Companions) -> Vec<Companion> {
    let mut out = Vec::new();
    if !want.any() {
        return out;
    }
    let stem = profile.layout.name.clone();
    let fp = layout.fingerprint();
    if want.nfo {
        out.push(companion(
            format!("{stem}.nfo"),
            nfo_text(profile, layout).into_bytes(),
            format!("{fp:016x}-nfo-1@mock"),
        ));
    }
    if want.sfv {
        out.push(companion(
            format!("{stem}.sfv"),
            sfv_text(layout).into_bytes(),
            format!("{fp:016x}-sfv-1@mock"),
        ));
    }
    out
}

fn companion(name: String, content: Vec<u8>, message_id: String) -> Companion {
    let subject = nzbkit::post::subject_for(None, &name, 1, 1, 1, 1);
    let body = nzbkit::yenc::encode(&name, content.len() as u64, Some((1, 1)), 1, &content);
    Companion {
        name,
        content,
        message_id,
        subject,
        body,
    }
}

/// The nfo a poster ships beside a release, cut to what is true here:
/// which profile built the post and what it carries. No group name, no
/// host, no account, nothing about the machine.
fn nfo_text(profile: &Profile, layout: &Layout) -> String {
    let mut s = String::new();
    s.push_str(&format!("{}\n", profile.layout.name));
    s.push_str(&format!(
        "built by postfast, seed {}\n",
        profile.layout.seed
    ));
    s.push_str(&format!(
        "layout fingerprint {:016x}\n",
        layout.fingerprint()
    ));
    s.push_str(&format!("{} file(s)\n\n", layout.files.len()));
    for (name, bytes) in &layout.files {
        s.push_str(&format!("{:>12}  {}\n", bytes.len(), name));
    }
    s
}

/// A simple-file-verification list: one `name crc32` line per posted
/// file, lower-case hex, which is the shape every sfv reader in the
/// wild parses.
fn sfv_text(layout: &Layout) -> String {
    let mut s = String::from("; generated by postfast\n");
    for (name, bytes) in &layout.files {
        s.push_str(&format!("{name} {:08x}\n", crc32fast::hash(bytes)));
    }
    s
}

/// Splice companion `<file>` entries into a generated NZB.
///
/// Refused rather than appended blind when the closing element is not
/// there: an emitter change that moved it would otherwise produce an
/// NZB with a companion outside the document, which parses as a
/// truncated file rather than as an error.
pub fn splice_companions(
    nzb: &str,
    companions: &[Companion],
    groups: &[String],
    poster: &str,
    date: i64,
) -> Result<String, PostError> {
    if companions.is_empty() {
        return Ok(nzb.to_string());
    }
    let at = nzb.rfind("</nzb>").ok_or_else(|| {
        PostError::Nzb("the generated NZB carries no </nzb> to splice a companion in before".into())
    })?;
    let groups: Vec<&str> = if groups.is_empty() {
        vec![crate::naming::GROUP]
    } else {
        groups.iter().map(String::as_str).collect()
    };
    let mut block = String::new();
    for c in companions {
        block.push_str(&format!(
            "  <file poster=\"{}\" date=\"{date}\" subject=\"{}\">\n    <groups>\n",
            esc(poster),
            esc(&c.subject)
        ));
        for g in &groups {
            block.push_str(&format!("      <group>{}</group>\n", esc(g)));
        }
        block.push_str("    </groups>\n    <segments>\n");
        block.push_str(&format!(
            "      <segment bytes=\"{}\" number=\"1\">{}</segment>\n",
            c.body.len(),
            esc(&c.message_id)
        ));
        block.push_str("    </segments>\n  </file>\n");
    }
    let mut out = String::with_capacity(nzb.len() + block.len());
    out.push_str(&nzb[..at]);
    out.push_str(&block);
    out.push_str(&nzb[at..]);
    Ok(out)
}

/// XML attribute and text escaping, the same five entities the two NZB
/// emitters in this tree write. Local because both of theirs are
/// private, and three lines of escaping is not a rule worth exporting.
fn esc(s: &str) -> String {
    s.replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

// ---------------------------------------------------------------------
// D3: which server
// ---------------------------------------------------------------------

/// Resolve `--server` against a config: exact host match
/// (case-insensitive), or `host:port` when one host has several
/// entries. Anything but exactly one ENABLED match is refused.
///
/// The same rule `nzbfast post --post-server` applies
/// (`crates/nzbfast/src/post_cmd.rs`, `select_server`), restated here
/// because that one is private to a crate this one does not depend on.
/// If either ever relaxes, the other is the thing to read: a posting
/// tool that picks "the first server" on its own is the failure both
/// exist to prevent.
pub fn select_server(
    cfg: &nzbkit::config::Config,
    wanted: &str,
) -> Result<nzbkit::config::ServerConfig, PostError> {
    let want = wanted.trim().to_ascii_lowercase();
    let matches: Vec<&nzbkit::config::ServerConfig> = cfg
        .servers
        .iter()
        .filter(|s| {
            s.host.to_ascii_lowercase() == want
                || format!("{}:{}", s.host.to_ascii_lowercase(), s.port) == want
        })
        .collect();
    let listed = || {
        cfg.servers
            .iter()
            .map(|s| {
                format!(
                    "  {}:{}{}",
                    s.host,
                    s.port,
                    if s.enabled { "" } else { " (disabled)" }
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    };
    match matches.as_slice() {
        [] => Err(PostError::Server(format!(
            "--server {wanted:?} matches no configured server. Configured servers:\n{}",
            listed()
        ))),
        [one] if one.enabled => Ok((*one).clone()),
        [_] => Err(PostError::Server(format!(
            "--server {wanted:?} is disabled in the config: enable it explicitly before posting"
        ))),
        many => Err(PostError::Server(format!(
            "--server {wanted:?} matches {} server entries: disambiguate with host:port. \
             Configured servers:\n{}",
            many.len(),
            listed()
        ))),
    }
}

// ---------------------------------------------------------------------
// What a run reports
// ---------------------------------------------------------------------

/// What one post did, for the CLI line and for a test to assert on.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Report {
    pub profile: String,
    /// Files the layout carries, companions included.
    pub files: usize,
    pub articles: usize,
    /// Wire bytes handed to the server.
    pub bytes: u64,
    pub nzb: PathBuf,
    /// Whether `--verify` ran AND passed. A run without `--verify`
    /// reports false, which is why the CLI line says which of the two
    /// it is rather than printing this flag.
    pub verified: bool,
}

// ---------------------------------------------------------------------
// The network half
// ---------------------------------------------------------------------

/// Everything below here is the gated half. It is compiled only under
/// `--features live-post`, and the one test that drives it drives
/// `nzbkit::mock::MockServer` on loopback.
#[cfg(feature = "live-post")]
mod live {
    use super::*;
    use std::collections::HashMap;

    /// Post a profile's layout over real files, and optionally prove
    /// the round trip.
    ///
    /// One connection, articles in NZB order, `--spread-ms` between
    /// them. Sequential rather than pooled on purpose: D2 is a
    /// statement about the order and spacing articles reach a server
    /// in, and concurrent workers have neither. A posting tool that
    /// needed throughput would be `nzbfast post`; this one needs a
    /// layout to arrive exactly as the profile describes it.
    pub async fn run(args: &Args) -> Result<Report, PostError> {
        let profile = Profile::load(&args.profile)?;
        let inputs = read_inputs(&args.paths, profile.encoding.article_bytes as usize)?;
        let (profile, layout) = layout_for(&profile, inputs)?;

        let cfg = nzbkit::config::Config::load(&args.config)
            .map_err(|e| PostError::Server(format!("reading {}: {e}", args.config.display())))?;
        let server = select_server(&cfg, &args.server)?;

        let mut wires = wire_articles(&layout, &args.groups)?;
        let extras = companions(&profile, &layout, args.companions);
        let group = if args.groups.is_empty() {
            crate::naming::GROUP.to_string()
        } else {
            args.groups.join(",")
        };
        for c in &extras {
            wires.push(Wire {
                wire: nzbkit::post::build_wire_article(
                    crate::naming::POSTER,
                    &group,
                    &c.subject,
                    &c.message_id,
                    crate::encode::FRESH_DATE_UNIX,
                    &c.body,
                ),
                message_id: c.message_id.clone(),
            });
        }

        let nzb_text = splice_companions(
            &layout.nzb,
            &extras,
            &args.groups,
            crate::naming::POSTER,
            crate::encode::FRESH_DATE_UNIX,
        )?;

        let bytes = upload(&server, &wires, args.spread_ms).await?;

        if let Some(parent) = args.nzb.parent()
            && !parent.as_os_str().is_empty()
        {
            std::fs::create_dir_all(parent)?;
        }
        std::fs::write(&args.nzb, nzb_text.as_bytes())?;

        let mut report = Report {
            profile: profile.layout.name.clone(),
            files: layout.files.len() + extras.len(),
            articles: wires.len(),
            bytes,
            nzb: args.nzb.clone(),
            verified: false,
        };
        if args.verify {
            verify(&server, &nzb_text, &layout, &extras, args.connections).await?;
            report.verified = true;
        }
        Ok(report)
    }

    /// Send every article over one connection, returning the wire bytes
    /// sent. Three attempts per article with a reconnect between them,
    /// the same bounded budget `nzbkit::post::post_files` spends, and
    /// the same IHAVE latch: a server that refuses POST outright is
    /// asked once and then never again.
    async fn upload(
        server: &nzbkit::config::ServerConfig,
        wires: &[Wire],
        spread_ms: u64,
    ) -> Result<u64, PostError> {
        use nzbkit::nntp::Connection;

        let mut conn: Option<Connection> = None;
        let mut ihave = false;
        let mut sent = 0u64;
        for (i, w) in wires.iter().enumerate() {
            if i > 0 && spread_ms > 0 {
                tokio::time::sleep(std::time::Duration::from_millis(spread_ms)).await;
            }
            let mut attempt = 0u32;
            loop {
                attempt += 1;
                if conn.is_none() {
                    match Connection::connect(server).await {
                        Ok((c, _)) => conn = Some(c),
                        Err(_) if attempt < 3 => {
                            // Give the listener a moment rather than
                            // spending the whole budget in a spin.
                            tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                            continue;
                        }
                        Err(e) => return Err(PostError::Wire(format!("connect: {e}"))),
                    }
                }
                let c = conn.as_mut().expect("connected just above");
                match nzbkit::post::post_article(c, &w.wire, &w.message_id, ihave, attempt > 1)
                    .await
                {
                    Ok(used_ihave) => {
                        ihave |= used_ihave;
                        sent += w.wire.len() as u64;
                        break;
                    }
                    Err(e) if attempt < 3 => {
                        // Reconnect and re-offer: a "not now" is a
                        // condition to wait out, not a verdict.
                        conn = None;
                        tokio::time::sleep(std::time::Duration::from_millis(200)).await;
                        let _ = e;
                    }
                    Err(e) => {
                        return Err(PostError::Wire(format!("article {}: {e}", w.message_id)));
                    }
                }
            }
        }
        if let Some(c) = conn.take() {
            c.quit().await;
        }
        Ok(sent)
    }

    /// Round-trip proof: parse the NZB that was just written, fetch
    /// every segment back through the engine's pool from the SAME
    /// server, decode, reassemble, and compare against what went out.
    ///
    /// The comparison is over the SET of file hashes rather than name
    /// by name, and that is the whole reason it works for this tool:
    /// a layout may put a token on the wire and the real name only in a
    /// recovery packet, so matching an NZB file to a posted file by
    /// name would fail every opaque profile by construction. Every file
    /// that was posted has to come back byte for byte; which subject
    /// carried it is the naming plane's business, not the wire's.
    ///
    /// It follows that `--verify` is a claim about a FAITHFUL layout.
    /// A profile that lies about a declared size, poisons a CRC or
    /// leaves a segment out of the NZB fails this check by design,
    /// because the bytes really do not come back. Those rows are the
    /// oracle's to grade, not this tool's.
    async fn verify(
        server: &nzbkit::config::ServerConfig,
        nzb_text: &str,
        layout: &Layout,
        extras: &[Companion],
        connections: usize,
    ) -> Result<(), PostError> {
        use nzbkit::pool::{ArticleReq, FetchOutcome, PoolConfig, fetch_all_multi};

        let nzb = nzbkit::nzb::Nzb::parse(nzb_text.as_bytes())
            .map_err(|e| PostError::Nzb(format!("the emitted NZB does not parse: {e}")))?;
        let mut id_to_file: HashMap<String, usize> = HashMap::new();
        let mut reqs: Vec<ArticleReq> = Vec::new();
        for (fi, f) in nzb.files.iter().enumerate() {
            for s in &f.segments {
                let bracketed = format!("<{}>", s.message_id);
                id_to_file.insert(bracketed.clone(), fi);
                reqs.push(ArticleReq::fresh(bracketed));
            }
        }
        let total = reqs.len();
        let pool = PoolConfig {
            connections: connections.clamp(1, 16),
            window: 4,
            ..PoolConfig::default()
        };
        let (tx, mut rx) = tokio::sync::mpsc::channel::<FetchOutcome>(64);
        let servers = vec![(server.clone(), pool)];
        let fetcher = tokio::spawn(async move { fetch_all_multi(&servers, reqs, tx).await });

        let mut got = 0usize;
        let mut buffers: Vec<Vec<u8>> = vec![Vec::new(); nzb.files.len()];
        let mut problems: Vec<String> = Vec::new();
        while let Some(outcome) = rx.recv().await {
            match outcome {
                FetchOutcome::Done { id, raw } => {
                    let Some(&fi) = id_to_file.get(&*id) else {
                        continue;
                    };
                    match nzbkit::yenc::decode(&raw) {
                        Ok(dec) => {
                            let at = dec.offset() as usize;
                            let end = at + dec.data.len();
                            if buffers[fi].len() < end {
                                buffers[fi].resize(end, 0);
                            }
                            buffers[fi][at..end].copy_from_slice(&dec.data);
                            got += 1;
                        }
                        Err(e) => problems.push(format!("{id}: decode: {e}")),
                    }
                }
                FetchOutcome::Missing { id, .. } => problems.push(format!("{id}: missing (430)")),
                FetchOutcome::Failed { id, error, .. } => problems.push(format!("{id}: {error}")),
            }
        }
        let _ = fetcher.await;
        if !problems.is_empty() {
            return Err(PostError::Verify(format!(
                "{got}/{total} articles came back; {}",
                problems.join("; ")
            )));
        }

        let mut want: HashMap<String, usize> = HashMap::new();
        for (_, bytes) in &layout.files {
            *want.entry(sha256_hex(bytes)).or_insert(0) += 1;
        }
        for c in extras {
            *want.entry(sha256_hex(&c.content)).or_insert(0) += 1;
        }
        for (fi, buf) in buffers.iter().enumerate() {
            let h = sha256_hex(buf);
            match want.get_mut(&h) {
                Some(n) if *n > 0 => *n -= 1,
                _ => {
                    return Err(PostError::Verify(format!(
                        "the file the NZB describes as {:?} came back as {} bytes that match \
                         nothing that was posted (sha256 {h})",
                        nzb.files[fi].subject,
                        buf.len()
                    )));
                }
            }
        }
        let short: usize = want.values().sum();
        if short > 0 {
            return Err(PostError::Verify(format!(
                "{short} posted file(s) had no match among the {} the NZB describes",
                nzb.files.len()
            )));
        }
        Ok(())
    }

    fn sha256_hex(bytes: &[u8]) -> String {
        use sha2::{Digest, Sha256};
        let mut h = Sha256::new();
        h.update(bytes);
        let d = h.finalize();
        let mut out = String::with_capacity(64);
        for b in d {
            out.push_str(&format!("{b:02x}"));
        }
        out
    }
}

#[cfg(feature = "live-post")]
pub use live::run;

#[cfg(test)]
mod tests {
    use super::*;
    use std::path::Path;

    fn argv(s: &str) -> Vec<String> {
        s.split_whitespace().map(String::from).collect()
    }

    const BASE: &str = "p.toml a.bin --server news --config c.json --nzb out.nzb";

    /// The whole deployment plane arrives as flags, and every one of
    /// them lands where the run reads it.
    #[test]
    fn the_deployment_plane_parses() {
        let a = parse_args(&argv(&format!(
            "{BASE} --group alt.test --group alt.binaries.test --spread-ms 250 --nfo --sfv \
             --verify --connections 8"
        )))
        .expect("parses");
        assert_eq!(a.profile, PathBuf::from("p.toml"));
        assert_eq!(a.paths, vec![PathBuf::from("a.bin")]);
        assert_eq!(a.server, "news");
        assert_eq!(a.config, PathBuf::from("c.json"));
        assert_eq!(a.nzb, PathBuf::from("out.nzb"));
        assert_eq!(a.groups, vec!["alt.test", "alt.binaries.test"]);
        assert_eq!(a.spread_ms, 250);
        assert_eq!(
            a.companions,
            Companions {
                nfo: true,
                sfv: true
            }
        );
        assert!(a.verify);
        assert_eq!(a.connections, 8);
    }

    /// The three options with no sane default are required by name.
    #[test]
    fn the_required_options_are_named() {
        assert_eq!(
            parse_args(&argv("p.toml a.bin --config c.json --nzb o.nzb")),
            Err(ArgError::Missing("--server"))
        );
        assert_eq!(
            parse_args(&argv("p.toml a.bin --server s --nzb o.nzb")),
            Err(ArgError::Missing("--config"))
        );
        assert_eq!(
            parse_args(&argv("p.toml a.bin --server s --config c.json")),
            Err(ArgError::Missing("--nzb"))
        );
        // A profile with nothing to post is not a post.
        assert_eq!(
            parse_args(&argv("p.toml --server s --config c.json --nzb o.nzb")),
            Err(ArgError::NoInput)
        );
    }

    /// There is no default config path, and that is a safety property
    /// rather than an omission: a posting tool that found an account
    /// config on its own could reach a real provider because a file was
    /// where it always is. The test above pins the refusal; this one
    /// pins that nothing fills it in later.
    #[test]
    fn no_config_is_ever_inferred() {
        let a = parse_args(&argv(BASE)).expect("parses");
        assert_eq!(a.config, PathBuf::from("c.json"));
    }

    #[test]
    fn a_typo_is_a_refusal_and_not_a_path() {
        assert_eq!(
            parse_args(&argv(&format!("{BASE} --obfsucate"))),
            Err(ArgError::Unknown("--obfsucate".into()))
        );
        assert_eq!(
            parse_args(&argv("p.toml a.bin --server")),
            Err(ArgError::NeedsValue("--server".into()))
        );
        assert!(matches!(
            parse_args(&argv(&format!("{BASE} --spread-ms soon"))),
            Err(ArgError::NotANumber { .. })
        ));
    }

    /// A comma inside one `--group` would silently become two groups on
    /// the Newsgroups line, so it is refused where it is written.
    ///
    /// Checked against the predicate rather than through `argv` above,
    /// because a value with a space in it never survives that splitter
    /// and the test would then be passing on the wrong refusal.
    #[test]
    fn a_group_that_cannot_ride_a_header_is_refused() {
        for g in [
            "alt.test,alt.binaries.test",
            "alt test",
            "",
            "a<b",
            "a\u{7f}b",
        ] {
            assert!(
                matches!(check_group(g), Err(ArgError::BadGroup(_))),
                "group {g:?} must be refused"
            );
        }
        assert!(check_group("alt.binaries.test").is_ok());
        // ...and it is reached from the command line.
        assert!(matches!(
            parse_args(&argv(&format!("{BASE} --group alt.test,alt.binaries.test"))),
            Err(ArgError::BadGroup(_))
        ));
    }

    /// Zero connections is a hang, not a setting.
    #[test]
    fn zero_connections_is_clamped_rather_than_taken() {
        let a = parse_args(&argv(&format!("{BASE} --connections 0"))).expect("parses");
        assert_eq!(a.connections, 1);
    }

    // -----------------------------------------------------------------
    // The `[source]` override and the layout it builds
    // -----------------------------------------------------------------

    /// The C2 + P1 profile the acceptance test posts: a stored RAR
    /// split into volumes, with a PAR2 set over them. Kept here rather
    /// than in the catalog because the catalog is graded by the oracle
    /// and this row exists to be POSTED.
    const C2_P1: &str = "\
[layout]
name = \"post-c2-p1\"
seed = 1509

[source]
files = [{ name = \"placeholder.bin\", bytes = 1 }]

[container]
kind = \"rar-stored\"
version = \"rar4\"
volume_bytes = 10000

[recovery]
kind = \"par2\"
redundancy_pct = 20

[encoding]
article_bytes = 4000

[expect]
complete = true
";

    fn write_inputs(dir: &Path, files: &[(&str, usize)]) -> Vec<PathBuf> {
        std::fs::create_dir_all(dir).expect("scratch");
        let mut out = Vec::new();
        for (name, len) in files {
            let p = dir.join(name);
            // Incompressible-ish and per-file distinct, so a stored
            // container really does carry different bytes per volume.
            let bytes: Vec<u8> = (0..*len)
                .map(|i| (i.wrapping_mul(31) ^ name.len().wrapping_mul(131)) as u8)
                .collect();
            std::fs::write(&p, &bytes).expect("write input");
            out.push(p);
        }
        out
    }

    fn scratch(tag: &str) -> PathBuf {
        let d = std::env::temp_dir().join(format!(
            "postfast-post-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        let _ = std::fs::remove_dir_all(&d);
        d
    }

    /// The override is total: the profile's own `[source]` is replaced
    /// by the real files, names and lengths both, and the layout is
    /// built over the REAL bytes rather than the seed's.
    #[test]
    fn real_files_replace_the_profiles_source_list() {
        let dir = scratch("override");
        let paths = write_inputs(&dir, &[("real-a.bin", 26000)]);
        let profile = Profile::parse(C2_P1).expect("profile parses");
        let inputs = read_inputs(&paths, 4000).expect("inputs read");
        assert_eq!(inputs.len(), 1);
        let over = override_source(&profile, &inputs);
        assert_eq!(
            over.source
                .files
                .iter()
                .map(|f| (f.name.as_str(), f.bytes))
                .collect::<Vec<_>>(),
            vec![("real-a.bin", 26000)],
            "the profile's own placeholder.bin must be gone"
        );
        let (_, layout) = layout_for(&profile, inputs).expect("layout builds");
        // A stored RAR of 26 KB at a 10 KB volume limit is three
        // volumes, so the container plane ran over the real payload
        // rather than over the profile's one placeholder byte.
        assert!(
            layout.files.len() > 3,
            "expected three volumes plus a recovery set, got {:?}",
            layout.files.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
        // And the payload really came back out of the container: the
        // expectation names the real file, not the profile's.
        assert!(
            layout.expect.payload.iter().any(|n| n == "real-a.bin"),
            "expected the real name in {:?}",
            layout.expect.payload
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// The rewritten profile is re-validated, so a real input set the
    /// profile cannot describe is refused by NAME rather than built
    /// into something else.
    ///
    /// The shape used to be TWO files under a split stored archive,
    /// because every RAR volume writer took a single member. The
    /// plurals landed on 4 Sep 2026 and that set builds now, so the
    /// contradiction here is the other way round: a payload too SMALL
    /// to cut at the volume size the profile names. `volume_bytes` is
    /// 10000 and the input is 500 bytes, so there is no second volume
    /// for the writer to make and it says so rather than emitting a
    /// one-volume set wearing volume flags.
    #[test]
    fn a_real_input_set_the_profile_cannot_describe_is_refused() {
        let dir = scratch("contradiction");
        let paths = write_inputs(&dir, &[("one.bin", 500)]);
        let profile = Profile::parse(C2_P1).expect("profile parses");
        let inputs = read_inputs(&paths, 4000).expect("inputs read");
        let e = layout_for(&profile, inputs).expect_err("500 bytes is not a split set");
        let text = e.to_string();
        assert!(
            text.contains("two volumes"),
            "the refusal must say what it cannot build: {text}"
        );
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A payload that does not match what `[source]` declares is
    /// refused by name rather than padded to fit.
    #[test]
    fn a_mismatched_payload_is_refused() {
        let profile = Profile::parse(C2_P1).expect("profile parses");
        assert!(matches!(
            crate::layout::generate_over(&profile, vec![vec![0u8; 2]]),
            Err(crate::layout::GenError::PayloadLength { .. })
        ));
        assert!(matches!(
            crate::layout::generate_over(&profile, vec![vec![0u8; 1], vec![0u8; 1]]),
            Err(crate::layout::GenError::PayloadCount { .. })
        ));
    }

    // -----------------------------------------------------------------
    // Wire articles
    // -----------------------------------------------------------------

    fn posted_layout(tag: &str) -> (Profile, Layout, PathBuf) {
        let dir = scratch(tag);
        let paths = write_inputs(&dir, &[("release.bin", 26000)]);
        let profile = Profile::parse(C2_P1).expect("profile parses");
        let inputs = read_inputs(&paths, 4000).expect("inputs read");
        let (profile, layout) = layout_for(&profile, inputs).expect("layout builds");
        (profile, layout, dir)
    }

    /// Every article the layout serves reaches the wire, in the NZB's
    /// order, under the layout's own From, Subject and Date.
    #[test]
    fn every_article_is_wired_in_nzb_order() {
        let (_, layout, dir) = posted_layout("wire");
        let wires = wire_articles(&layout, &[]).expect("wires");
        assert_eq!(wires.len(), layout.articles.len());
        let nzb = nzbkit::nzb::Nzb::parse(layout.nzb.as_bytes()).expect("nzb parses");
        let want: Vec<&str> = nzb
            .files
            .iter()
            .flat_map(|f| f.segments.iter().map(|s| s.message_id.as_str()))
            .collect();
        let got: Vec<&str> = wires.iter().map(|w| w.message_id.as_str()).collect();
        assert_eq!(got, want, "post order must be the NZB's order");
        let first = &wires[0];
        let text = String::from_utf8_lossy(&first.wire);
        assert!(text.starts_with("From: "), "headers first: {text:.80}");
        assert!(text.contains(&format!("Message-ID: <{}>\r\n", first.message_id)));
        assert!(text.contains(&format!("Newsgroups: {}\r\n", crate::naming::GROUP)));
        assert!(first.wire.ends_with(b"\r\n.\r\n"), "lone-dot terminated");
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// D1: the Newsgroups line is the one header the deployment plane
    /// overrides, and several `--group` values crosspost.
    #[test]
    fn the_group_flag_crossposts() {
        let (_, layout, dir) = posted_layout("group");
        let groups = vec!["alt.test".to_string(), "alt.binaries.test".to_string()];
        let wires = wire_articles(&layout, &groups).expect("wires");
        for w in &wires {
            let text = String::from_utf8_lossy(&w.wire);
            assert!(
                text.contains("Newsgroups: alt.test,alt.binaries.test\r\n"),
                "crosspost header missing: {text:.200}"
            );
        }
        let _ = std::fs::remove_dir_all(&dir);
    }

    // -----------------------------------------------------------------
    // D4: companions
    // -----------------------------------------------------------------

    /// The sfv lists every posted file under a CRC a reader can check,
    /// and the nfo says which profile built the post. Neither carries
    /// a group, a host or an account.
    #[test]
    fn the_companions_describe_the_post_and_nothing_else() {
        let (profile, layout, dir) = posted_layout("companion");
        let cs = companions(
            &profile,
            &layout,
            Companions {
                nfo: true,
                sfv: true,
            },
        );
        assert_eq!(cs.len(), 2);
        let sfv = String::from_utf8(cs[1].content.clone()).expect("sfv is text");
        for (name, bytes) in &layout.files {
            assert!(
                sfv.contains(&format!("{name} {:08x}", crc32fast::hash(bytes))),
                "sfv must carry {name}: {sfv}"
            );
        }
        let nfo = String::from_utf8(cs[0].content.clone()).expect("nfo is text");
        assert!(nfo.contains("post-c2-p1"));
        assert!(nfo.contains("seed 1509"));
        // Same profile, same files, same companion ids.
        let again = companions(
            &profile,
            &layout,
            Companions {
                nfo: true,
                sfv: true,
            },
        );
        assert_eq!(cs, again);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// A spliced NZB is still an NZB the client's own parser reads, and
    /// the companion is one more file in it.
    #[test]
    fn a_spliced_companion_still_parses() {
        let (profile, layout, dir) = posted_layout("splice");
        let cs = companions(
            &profile,
            &layout,
            Companions {
                nfo: true,
                sfv: false,
            },
        );
        let before = nzbkit::nzb::Nzb::parse(layout.nzb.as_bytes()).expect("nzb parses");
        let spliced = splice_companions(
            &layout.nzb,
            &cs,
            &["alt.test".to_string()],
            crate::naming::POSTER,
            crate::encode::FRESH_DATE_UNIX,
        )
        .expect("splices");
        let after = nzbkit::nzb::Nzb::parse(spliced.as_bytes()).expect("spliced nzb parses");
        assert_eq!(after.files.len(), before.files.len() + 1);
        let last = after.files.last().expect("a companion file");
        assert_eq!(last.groups, vec!["alt.test".to_string()]);
        assert_eq!(last.segments.len(), 1);
        assert_eq!(last.segments[0].message_id, cs[0].message_id);
        let _ = std::fs::remove_dir_all(&dir);
    }

    /// Failing to find is failing: an NZB with no closing element is
    /// reported, not appended to.
    #[test]
    fn a_splice_with_no_marker_is_refused() {
        let c = companion("x.nfo".into(), b"x".to_vec(), "id-1@mock".into());
        assert!(matches!(
            splice_companions("<nzb>\n", std::slice::from_ref(&c), &[], "p", 0),
            Err(PostError::Nzb(_))
        ));
        // ...and no companions is not a splice at all.
        assert_eq!(
            splice_companions("<nzb>\n", &[], &[], "p", 0).expect("no-op"),
            "<nzb>\n"
        );
    }

    // -----------------------------------------------------------------
    // D3: server resolution
    // -----------------------------------------------------------------

    fn config_json(entries: &str) -> nzbkit::config::Config {
        serde_json::from_str(&format!("{{\"servers\":[{entries}]}}")).expect("config parses")
    }

    #[test]
    fn server_selection_is_strict() {
        let cfg = config_json(
            "{\"host\":\"one.invalid\",\"port\":119},\
             {\"host\":\"two.invalid\",\"port\":119},\
             {\"host\":\"two.invalid\",\"port\":563},\
             {\"host\":\"off.invalid\",\"port\":119,\"enabled\":false}",
        );
        assert_eq!(
            select_server(&cfg, "One.Invalid").expect("one match").host,
            "one.invalid"
        );
        assert_eq!(
            select_server(&cfg, "two.invalid:563")
                .expect("host:port disambiguates")
                .port,
            563
        );
        for wanted in ["two.invalid", "off.invalid", "nope.invalid"] {
            assert!(
                matches!(select_server(&cfg, wanted), Err(PostError::Server(_))),
                "{wanted} must not resolve"
            );
        }
    }

    /// The gate is one line, it names the decision rather than the
    /// flag, and it obeys the house copy rules.
    #[test]
    fn the_gate_line_names_the_gate() {
        assert!(!GATE.contains('\n'));
        assert!(!GATE.contains('\u{2014}') && !GATE.contains('\u{2013}'));
        assert!(GATE.contains("gated"));
        assert!(GATE.contains("live-post"));
        assert_eq!(GATE_EXIT, 2);
    }

    // -----------------------------------------------------------------
    // The gated half, against the mock and nothing else
    // -----------------------------------------------------------------

    /// The acceptance run: a C2 + P1 profile over real files, posted to
    /// `nzbkit::mock::MockServer` on loopback and re-downloaded through
    /// the pool, with every posted file coming back byte for byte.
    ///
    /// Loopback and a mock, never a provider: this test is the only
    /// thing in the tree that drives the posting path at all, and it is
    /// compiled only under a feature no CI job passes.
    #[cfg(feature = "live-post")]
    #[tokio::test(flavor = "multi_thread", worker_threads = 2)]
    async fn a_c2_p1_profile_posts_to_the_mock_and_verifies() {
        let srv = nzbkit::mock::MockServer::start(Default::default(), Default::default()).await;
        let dir = scratch("live");
        let paths = write_inputs(&dir, &[("release.bin", 26000)]);
        let profile_path = dir.join("profile.toml");
        std::fs::write(&profile_path, C2_P1).expect("profile written");
        let config_path = dir.join("config.json");
        std::fs::write(
            &config_path,
            format!(
                "{{\"servers\":[{{\"host\":\"127.0.0.1\",\"port\":{},\"tls\":false}}]}}",
                srv.addr.port()
            ),
        )
        .expect("config written");
        let nzb_path = dir.join("posted.nzb");

        let args = Args {
            profile: profile_path,
            paths,
            server: format!("127.0.0.1:{}", srv.addr.port()),
            config: config_path,
            nzb: nzb_path.clone(),
            groups: vec!["alt.binaries.test".into()],
            spread_ms: 0,
            companions: Companions {
                nfo: true,
                sfv: true,
            },
            verify: true,
            connections: 4,
        };
        let report = run(&args).await.expect("post and verify");
        assert_eq!(report.profile, "post-c2-p1");
        assert!(report.verified, "the round trip has to be proven");
        assert!(report.articles > 1);
        assert!(report.bytes > 26_000);

        // The mock's own counter is the independent witness that the
        // articles really went over a socket and really came back: it
        // counts BODY requests, and the verify asked for one per
        // segment the NZB names.
        assert_eq!(
            srv.served.load(std::sync::atomic::Ordering::Relaxed) as usize,
            report.articles,
            "every posted article had to be fetched back"
        );

        let nzb = nzbkit::nzb::Nzb::parse(&std::fs::read(&nzb_path).unwrap()).expect("nzb parses");
        // The two companions ride the same NZB as the payload.
        assert_eq!(nzb.files.len(), report.files);
        for f in &nzb.files {
            assert_eq!(f.groups, vec!["alt.binaries.test".to_string()]);
        }
        let _ = std::fs::remove_dir_all(&dir);
    }
}
