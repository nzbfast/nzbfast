//! The [`Layout`] type and [`generate`], which is the whole of this
//! crate's API: a profile goes in, a layout comes out, and nothing else
//! shapes it.
//!
//! Spec section 3 states the rule and the reason. A layout holds the
//! files that would be posted, the article map keyed by Message-ID for
//! `nzbkit::mock::MockServer`, the NZB that recovers them, the `Chaos`
//! the profile asks the server for, and the end state the client must
//! reach. The gated posting tool's in-memory one-pass producer is
//! sequenced last precisely because it has to be a SECOND producer of
//! this same type rather than a change to it: the oracle needs
//! determinism, not one-pass, and shaping the crate around one-pass is
//! the single most likely way to spend a month for no test value.
//!
//! **Every plane this stage does not implement is refused by name.** A
//! profile selecting a container, a recovery set or a fault gets an
//! error saying so, not a bare-files layout that quietly ignored it.
//! That refusal is the whole reason the schema denies unknown fields
//! one layer up: a profile that passes because the plane it meant to
//! select was never selected is worse than no profile at all, and a
//! generator that silently drops a plane reintroduces exactly that
//! failure below the schema that was built to prevent it.

use std::collections::HashMap;

use crate::assemble::{self, SourceError};
use crate::companion;
use crate::container::{self, Contained, ContainerError};
use crate::encode::{self, EncodeError};
use crate::fault::{self, FaultError};
use crate::naming::{self, NamingError};
use crate::nzb::{self, NzbError};
use crate::profile::{IndexState, Profile, RecoveryKind};
use crate::recovery::{self, Recovered, RecoveryError};
use crate::rng::Rng;
use crate::serve::{self, ServeError};
use crate::split::{self, Split};

/// The end state the oracle asserts, derived by the generator from the
/// source and the planes.
///
/// [`Expectation::files`] is the source list under the names the naming
/// plane says the client must end with - which is the name the layout
/// actually CARRIES, never the name a source file happened to be given
/// in the profile. Under an opaque layout with no out-of-band name
/// source those are tokens, and that is the correct requirement: a real
/// name that was posted nowhere cannot be recovered by anybody.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Expectation {
    /// (final name, bytes) for every source file.
    pub files: Vec<(String, Vec<u8>)>,
    /// Whether the client is expected to reach that state in full.
    pub complete: bool,
    /// Non-empty only on a profile pinning today's behaviour rather
    /// than the right behaviour; the coverage report lists the profile
    /// under this text and counts its planes contemplated, not
    /// recognised.
    pub gap: String,
    /// The PAYLOAD's expected names, in `[source]` order - the leading
    /// entries of [`Expectation::files`], projected out so a grader can
    /// tell a deliverable from the recovery furniture beside it.
    pub payload: Vec<String>,
    /// Which of [`Expectation::payload`] today's client actually ends
    /// with, and every other payload name has to be ABSENT. The whole
    /// payload on a complete row; the profile's own list on a row whose
    /// `complete` is false. Read by the grader only when the row is not
    /// graded on its exact tree - see the runner.
    pub arrives: Vec<String>,
    /// Whether the process is expected to exit zero: what
    /// [`Expectation::complete`] implies, unless the profile's `exits`
    /// override says otherwise - which is always a gap, in either
    /// direction. A run that delivered everything and reported failure
    /// is the shape `complete` cannot describe.
    pub exit_zero: bool,
    /// Whether the layout damages the payload, so the run has to
    /// rebuild bytes from parity.
    ///
    /// Not an assertion of its own - it is what lets a grader tell the
    /// two kinds of "repair complete" apart. A row that damages nothing
    /// and still reports a repair is the recovery set NAMING an intact
    /// file (an adoption), which is the whole point of a P3 row and a
    /// defect in an F4 one. [`expects_repair`] is where the rule is
    /// written.
    pub repairs: bool,
    /// The identification rung the layout is expected to survive.
    /// Empty means the profile makes no claim.
    pub ladder: String,
}

/// One generated layout: everything a round trip needs.
#[derive(Clone)]
pub struct Layout {
    /// The files that would be posted, in the order the profile lists
    /// them, under the names they carry ON DISK: with no container that
    /// is the source relative path, directories and all, because that
    /// is what a posting tool would be pointed at. Distinct from
    /// [`Expectation::files`], which is what has to come back out.
    pub files: Vec<(String, Vec<u8>)>,
    /// `<message-id>` to yEnc body, exactly the map
    /// `nzbkit::mock::MockServer::start` takes.
    pub articles: HashMap<String, Vec<u8>>,
    /// `<message-id>` to header block, for the mock's HEAD plane.
    pub headers: HashMap<String, Vec<u8>>,
    /// The NZB text.
    pub nzb: String,
    /// What the first server does to its answers.
    pub chaos: nzbkit::mock::Chaos,
    /// S6: the FURTHER servers, each with its own fault plan, in the
    /// order the client's config lists them. A `Vec` because
    /// `[[serve.second]]` is an array of tables and a profile may write
    /// more than one; empty is the ordinary one-server row.
    pub second: Vec<nzbkit::mock::Chaos>,
    /// The end state the client must reach.
    pub expect: Expectation,
}

// Hand-written because `nzbkit::mock::Chaos` has no `Debug` and the
// payload bytes would drown the output anyway. A layout printed in a
// panic message should say what it IS, not recite a megabyte.
impl std::fmt::Debug for Layout {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("Layout")
            .field(
                "files",
                &self
                    .files
                    .iter()
                    .map(|(n, b)| format!("{n} ({} bytes)", b.len()))
                    .collect::<Vec<_>>(),
            )
            .field("articles", &self.articles.len())
            .field("nzb_bytes", &self.nzb.len())
            .field("second_servers", &self.second.len())
            .field("expect", &self.expect)
            .finish()
    }
}

impl Layout {
    /// A short fingerprint of the three things the determinism contract
    /// is about: the emitted files, the article map and the NZB.
    ///
    /// A debugging aid and a message, NOT the assertion: a test proving
    /// determinism compares the bytes themselves, because a fingerprint
    /// that collided would prove the opposite of what it printed. FNV-1a
    /// so it needs no dependency and is stable across machines and
    /// releases, which a `DefaultHasher` is explicitly not.
    pub fn fingerprint(&self) -> u64 {
        let mut h: u64 = 0xcbf2_9ce4_8422_2325;
        let mut eat = |b: &[u8]| {
            for &x in b {
                h ^= x as u64;
                h = h.wrapping_mul(0x100_0000_01b3);
            }
        };
        for (n, b) in &self.files {
            eat(n.as_bytes());
            eat(b);
        }
        // A HashMap has no order, so the ids are sorted before they are
        // eaten. Without that the fingerprint would differ run to run
        // for a layout that is byte-identical, which is the exact
        // property it exists to report on.
        let mut ids: Vec<&String> = self.articles.keys().collect();
        ids.sort();
        for id in ids {
            eat(id.as_bytes());
            eat(&self.articles[id]);
        }
        eat(self.nzb.as_bytes());
        h
    }
}

/// Why a layout could not be generated. Distinct from
/// [`crate::profile::ProfileError`]: the profile was well-formed and
/// self-consistent, and the generator still could not build it.
#[derive(Debug, Clone, PartialEq)]
pub enum GenError {
    Source(SourceError),
    Naming(NamingError),
    Encode(EncodeError),
    Nzb(NzbError),
    Recovery(RecoveryError),
    Container(ContainerError),
    Fault(FaultError),
    Serve(ServeError),
    /// `[expect] arrives` names something the layout does not carry.
    /// Failing to find is failing: an `arrives` entry that matched
    /// nothing would quietly assert nothing at all.
    ArrivesNotAPayloadName {
        name: String,
        payload: Vec<String>,
    },
    /// A gap row whose `arrives` list is the WHOLE payload, which says
    /// exactly what `complete = true` says.
    ArrivesIsEverything,
    /// A hand-built profile that never went through a loader and does
    /// not hold together. `Profile::parse` and `Profile::load` validate
    /// for themselves, so this is only reachable from a caller that
    /// assembled the struct itself - a generator test, or a future
    /// `postfast gen --set`. Returned rather than asserted: a public
    /// entry point that panics on its own input is a crash somebody
    /// else has to debug.
    Profile(crate::profile::Contradiction),
    /// [`generate_over`] was handed a different number of payload
    /// entries than the profile's `[source]` declares. Positional, so
    /// there is no name to match on and a short list would silently
    /// build a smaller post.
    PayloadCount {
        given: usize,
        declared: usize,
    },
    /// [`generate_over`] was handed a payload entry whose length is not
    /// the length `[source]` declares for that file. Refused rather
    /// than adopted: the profile's own volume count, recovery set and
    /// expectation are all derived from the declared length.
    PayloadLength {
        name: String,
        declared: u64,
        given: u64,
    },
    /// A plane this stage does not build yet. `plane` is the table and
    /// selection an author wrote; `owner` says which piece of work
    /// lands it, so the refusal points somewhere.
    NotImplemented {
        plane: String,
        owner: &'static str,
    },
    /// A recovery file's generated name (the covered set's `base_name`,
    /// or F6's competing-set name) equals a name already in the post -
    /// a payload file, or an earlier recovery file. `write_layout`
    /// would post the source and then silently overwrite it with the
    /// generated one, and the NZB would carry two files under one name.
    RecoveryNameCollides(String),
}

impl std::fmt::Display for GenError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::Source(e) => write!(f, "{e}"),
            Self::Naming(e) => write!(f, "{e}"),
            Self::Encode(e) => write!(f, "{e}"),
            Self::Nzb(e) => write!(f, "{e}"),
            Self::Recovery(e) => write!(f, "{e}"),
            Self::Container(e) => write!(f, "{e}"),
            Self::Fault(e) => write!(f, "{e}"),
            Self::Serve(e) => write!(f, "{e}"),
            Self::ArrivesNotAPayloadName { name, payload } => write!(
                f,
                "[expect] arrives names {name:?}, and the layout carries the payload as \
                 {payload:?}. A name is the one the LAYOUT carries, which under an opaque \
                 or FileDesc-named row is not the name [source] wrote"
            ),
            Self::ArrivesIsEverything => f.write_str(
                "[expect] arrives lists the whole payload, which says what complete = true \
                 says. A gap row exists because something does NOT arrive",
            ),
            Self::PayloadCount { given, declared } => write!(
                f,
                "the payload override carries {given} file(s) and [source] declares \
                 {declared}: the override is positional, so a list of a different length \
                 would build a post over files the profile does not describe"
            ),
            Self::PayloadLength {
                name,
                declared,
                given,
            } => write!(
                f,
                "the payload override gives {name:?} as {given} bytes and [source] declares \
                 {declared}: rewrite [source] from the real files rather than padding one \
                 to fit, because the volume count, the recovery set and the expectation are \
                 all derived from the declared length"
            ),
            Self::Profile(c) => write!(f, "contradictory profile: {c}"),
            Self::NotImplemented { plane, owner } => write!(
                f,
                "{plane} is not generated yet: it lands with {owner}. The plane is \
                 refused rather than ignored, so a profile never passes because the shape \
                 it selects was silently not emitted"
            ),
            Self::RecoveryNameCollides(n) => write!(
                f,
                "the recovery set's generated name {n:?} is already posted under that name. \
                 par2's base name is the stem of the first covered member's basename, so \
                 a [source] file named the same as the set it would be covered by (or as \
                 another recovery file, under F6's competing set) is two files under one \
                 name on the wire"
            ),
        }
    }
}

impl std::error::Error for GenError {}

macro_rules! from_stage {
    ($t:ty, $v:ident) => {
        impl From<$t> for GenError {
            fn from(e: $t) -> Self {
                Self::$v(e)
            }
        }
    };
}
from_stage!(SourceError, Source);
from_stage!(NamingError, Naming);
from_stage!(EncodeError, Encode);
from_stage!(NzbError, Nzb);
from_stage!(RecoveryError, Recovery);
from_stage!(ContainerError, Container);
from_stage!(FaultError, Fault);
from_stage!(ServeError, Serve);
from_stage!(crate::profile::Contradiction, Profile);

/// Build the layout a profile describes.
///
/// The one entry point, and the order of the stages is the order the
/// seeded stream is drawn in: payload, then names, then message-ids and
/// part permutations. Adding a draw anywhere but the end of a stage
/// changes every layout after it, which is why each stage documents its
/// own draw order rather than leaving it to be reverse-engineered from
/// a diff of two failing runs.
pub fn generate(profile: &Profile) -> Result<Layout, GenError> {
    let (sources, rng) = seeded_payload(profile)?;
    build(profile, sources, rng)
}

/// [`generate`] over a payload the caller supplies: the same layout,
/// built over REAL bytes instead of the seed's.
///
/// The one caller is the gated posting tool ([`crate::post`]), whose
/// `[source]` list is overridden from the command line - a person posts
/// files they have, not lengths a profile invented. `payload` is
/// positional: entry `i` replaces source file `i`'s bytes, and a count
/// or a length that does not match the profile is refused rather than
/// padded or truncated, because a layout built over a payload that is
/// not the one the profile describes is a layout whose recovery set,
/// volume count and expectation all describe something else.
///
/// **The seeded payload is still drawn and then thrown away**, and that
/// is the point rather than an oversight. Every rule [`assemble`] owns -
/// the unsafe-name refusal, the total-payload cap, the one-stream draw
/// order - applies to a real-file post without a second copy of any of
/// them; and because the stream is left at exactly the position a
/// catalog run leaves it at, one profile and one seed mint the same
/// names and the same message-ids whether the bytes came off the seed
/// or off a disk. The price is one ChaCha fill of the payload's size,
/// paid by a tool that is about to put those bytes on a wire.
pub fn generate_over(profile: &Profile, payload: Vec<Vec<u8>>) -> Result<Layout, GenError> {
    let (mut sources, rng) = seeded_payload(profile)?;
    if payload.len() != sources.len() {
        return Err(GenError::PayloadCount {
            given: payload.len(),
            declared: sources.len(),
        });
    }
    for (s, bytes) in sources.iter_mut().zip(payload) {
        if bytes.len() as u64 != s.bytes.len() as u64 {
            return Err(GenError::PayloadLength {
                name: s.rel.clone(),
                declared: s.bytes.len() as u64,
                given: bytes.len() as u64,
            });
        }
        s.bytes = bytes;
    }
    build(profile, sources, rng)
}

/// Validate, refuse what this stage does not build, and draw the
/// profile's own payload. Split out so [`generate_over`] enters the
/// pipeline at the same point with the same checks behind it.
fn seeded_payload(profile: &Profile) -> Result<(Vec<assemble::SourceFile>, Rng), GenError> {
    profile.validate()?;
    refuse_unimplemented_planes(profile)?;
    let mut rng = Rng::for_profile(profile);
    let sources = assemble::sources(profile, &mut rng)?;
    Ok((sources, rng))
}

/// Everything below the payload: containers, recovery, faults, naming,
/// encoding, the NZB and the serve plan.
fn build(
    profile: &Profile,
    sources: Vec<assemble::SourceFile>,
    mut rng: Rng,
) -> Result<Layout, GenError> {
    // The container plane runs between the payload and every plane
    // below it, and it REPLACES what those planes see: with an archive
    // selected, the posted files are its volumes and the source files
    // are what has to come back OUT of them. So the recovery set covers
    // volumes, the naming plane names volumes, and neither module
    // learns that a container exists. `None` is C0, where the sources
    // are the posted files and nothing changes.
    let mut contained = container::wrap(profile, &sources, &mut rng)?;
    // The recovery set is built BEFORE any name is drawn for it and
    // AFTER the payload is assembled, because it describes the payload
    // and draws nothing. What it decides - which members a set covers,
    // which are described but never posted - shapes everything below.
    // Scoped, because the fault plane below needs the volumes back
    // MUTABLY and the set has to exist first.
    // G3: one payload file cut into raw wire parts. It runs after the
    // container plane and is refused beside one - a split of an archive
    // is C2's `volume_bytes`, and the two would be two answers to one
    // question. What it decides is which files the WIRE carries and,
    // separately, which files the recovery set DESCRIBES: `join` hands
    // the set the whole file and `parts` hands it the parts, and that
    // single difference is the whole of the distance between n19 and
    // n18.
    let split = split::apply(profile, &sources);
    let mut recovered = {
        let carried = match &split {
            Some(s) => &s.described,
            None => carried_files(&contained, &sources),
        };
        recovery::build(profile, carried)?
    };
    // The generation-time fault plane, over the bytes the creator and
    // the writer just wrote correctly: F6 adds a competing set, F7
    // removes or unseals the index, F4 unseals packets, F3 and F5
    // damage a volume. It runs AFTER the set (which is what the client
    // repairs the damage FROM, so a set cut over damaged bytes would
    // agree with the damage) and BEFORE naming (so the files it adds or
    // removes are named, encoded and mapped like any other). It draws
    // from a stream of its own, so a fault row's payload names and
    // message-ids match the clean row it was copied from.
    // G1 forks the payload: `wire` holds the DAMAGED copy of the source
    // files when `[fault] corrupt_payload` asks for one, and stays
    // `None` for every other profile, which is what keeps a payload copy
    // off the 57 rows that do not need it. Everything below reads the
    // fork; the expectation keeps reading `sources`, because the source
    // bytes are still what has to land. `crate::fault::spoil_payload`
    // is where that split is argued.
    let mut wire: Option<Vec<assemble::SourceFile>> = None;
    // F6 builds its competing set over the slice the RECOVERY plane was
    // built on, because `Recovered::covered` indexes THAT slice - the
    // posted volumes under a container or a split, the sources
    // otherwise. It used to be handed `sources` and index it with those
    // indices, which described the wrong members under a container and
    // panicked outright on a split (`covered = [0,1,2]` over one source).
    //
    // Owned, and only when F6 asks: `carried_files` borrows `contained`
    // and `fault::apply` needs it mutably, so the two cannot overlap.
    // Every other row pays nothing for this.
    let carried_for_fault: Vec<assemble::SourceFile> = if profile.fault.duplicate_set {
        match &split {
            Some(s) => s.described.clone(),
            None => carried_files(&contained, &sources).to_vec(),
        }
    } else {
        Vec::new()
    };
    fault::apply(
        profile,
        &mut contained,
        &sources,
        &carried_for_fault,
        &mut wire,
        &mut recovered,
    )?;
    let posted_payload: &[assemble::SourceFile] = wire.as_deref().unwrap_or(&sources);
    let carried = match &split {
        Some(s) => s.posted.as_slice(),
        None => carried_files(&contained, posted_payload),
    };
    // P5: a described-but-unposted placeholder reaches the naming
    // plane, the encoder and the NZB not at all. It has no wire name to
    // decide and no article to serve; the client must materialise it
    // from a FileDesc packet alone, which is the whole row.
    let posted: Vec<assemble::SourceFile> = carried
        .iter()
        .enumerate()
        .filter(|(i, _)| !recovered.is_unposted(*i))
        .map(|(_, s)| s.clone())
        .collect();
    let mut plan = naming::plan(profile, &posted, &mut rng)?;
    // The post's own name: the stem of the first POSTED file's carried
    // name, which is a real name under a descriptive layout and a token
    // under an opaque one. Faithful either way, because faithful means
    // "agrees with what was posted", not "is descriptive". Taken before
    // the recovery files join the list, so a `.par2` never names a post.
    // With a container the post is named after the CONTAINER, not
    // after volume one: `movie.part01` is a volume name and no NZB
    // would carry it as the release.
    let post_name = match &contained {
        Some(c) => c.post_stem.clone(),
        None => {
            let first = &plan.files[0].final_name;
            first
                .rsplit_once('.')
                .map_or(first.as_str(), |(s, _)| s)
                .to_string()
        }
    };
    // The recovery files join the ordinary pipeline here, as posted
    // files like any other: named by the recovery plane's own
    // selection, then encoded, mapped and listed in the NZB by the same
    // code the payload goes through. Appended AFTER the payload so
    // every payload message-id is where a P0 profile with this seed put
    // it, and a diff between the two profiles reads.
    let mut all = posted;
    // Where the payload ends and the recovery set begins, for the one
    // plane that has to know: Z4 drops segments from the payload's map
    // and never from a `.par2`, because a holed recovery set is the
    // fault plane's F4 and would quietly disarm the set the row needs.
    let payload_files = all.len();
    for f in &recovered.files {
        // The recovery plane derives its own names (`base_name`, F6's
        // competing set) and never sees the payload's, so a set whose
        // stem matches a posted source (`movie.mkv` + `movie.par2`)
        // reaches here unrefused: nothing upstream compares the two
        // namespaces. Checked against `all` as it accumulates, which
        // covers a payload collision AND two recovery files landing on
        // the same name (F6's competing set beside the real one).
        if all.iter().any(|s| s.rel == f.name) {
            return Err(GenError::RecoveryNameCollides(f.name.clone()));
        }
        all.push(assemble::SourceFile {
            rel: f.name.clone(),
            base: f.name.clone(),
            bytes: f.bytes.clone(),
        });
    }
    plan.files
        .extend(naming::plan_recovery(profile, &recovered.files, &mut rng));
    // G4: the companion sidecar, LAST in the posted order. After the
    // recovery files because `arriving_recovery_files` walks
    // `plan.files` from where the payload ended and pairs it with
    // `recovered.files` positionally: a sidecar in between would put a
    // `.par2`'s expectation on a `.sfv`'s name. It lists what is on the
    // WIRE, so it is built over `all` as the payload left it, before
    // the recovery files joined.
    let companion = companion::build(profile, &all[..payload_files]);
    if let Some(c) = &companion {
        all.push(assemble::SourceFile {
            rel: c.name.clone(),
            base: c.name.clone(),
            bytes: c.bytes.clone(),
        });
        plan.files.extend(naming::plan_companion(
            profile,
            std::slice::from_ref(c),
            &mut rng,
        ));
    }
    let (encoded, articles) = encode::encode(profile, &all, &plan, payload_files, &mut rng)?;
    let nzb = nzb::emit(profile, &encoded, &post_name, payload_files)?;
    // The serve plane last, because it names ARTICLES and articles do
    // not exist until here. It draws from its own stream too, for the
    // same reason the fault plane does.
    let (chaos, second) = serve::plan(profile, &encoded)?;
    Ok(Layout {
        // The posted files: with no container the source files kept
        // under their relative paths, so a posting tool pointed at the
        // directory reproduces the tree; with one, the volumes, which
        // have no tree of their own. The recovery files sit beside
        // either, which is where a `par2 create` run would have left
        // them.
        files: all
            .iter()
            .map(|s| (s.rel.clone(), s.bytes.clone()))
            .collect(),
        articles: articles.bodies,
        headers: articles.headers,
        nzb,
        chaos,
        second,
        expect: expectation(
            profile,
            &sources,
            contained.as_ref(),
            split.as_ref(),
            &plan,
            &recovered,
            companion.as_ref(),
        )?,
    })
}

/// The files this post actually CARRIES: an archive's volumes, or the
/// source files when there is no archive.
///
/// One spelling, because the choice is made three times in `generate`
/// and a fourth site reaching for `contained.volumes` directly is how
/// a plane ends up seeing the payload where every other plane sees the
/// volumes.
fn carried_files<'a>(
    contained: &'a Option<Contained>,
    sources: &'a [assemble::SourceFile],
) -> &'a [assemble::SourceFile] {
    match contained {
        Some(c) => &c.volumes,
        None => sources,
    }
}

/// Assemble the [`Expectation`], and refuse an `[expect] arrives` list
/// that does not name what the layout carries.
fn expectation(
    profile: &Profile,
    sources: &[assemble::SourceFile],
    contained: Option<&Contained>,
    split: Option<&Split>,
    plan: &naming::Plan,
    recovered: &Recovered,
    companion: Option<&companion::CompanionFile>,
) -> Result<Expectation, GenError> {
    let mut files = expected_end_state(
        sources,
        contained,
        split,
        plan,
        recovered,
        companion.map(|c| c.names.as_slice()).unwrap_or(&[]),
        parity_is_fetched(profile),
        recovery_is_swept(profile),
    );
    // G4: a sidecar is posted, arrives, and stays. It is text under an
    // ordinary extension rather than packet-shaped bytes under a token,
    // so the leftover sweep that takes an opaque `.par2` away never
    // looks at it - and a client that removed the file carrying every
    // real name in the post would be removing the poster's own record.
    if let Some(c) = companion {
        files.push((c.name.clone(), c.bytes.clone()));
    }
    // The leading entries are the payload, in `[source]` order, and the
    // recovery files follow - the order `expected_end_state` builds in,
    // which is the contract between it and this function.
    let payload: Vec<String> = files
        .iter()
        .take(sources.len())
        .map(|(n, _)| n.clone())
        .collect();
    for name in &profile.expect.arrives {
        if !payload.contains(name) {
            return Err(GenError::ArrivesNotAPayloadName {
                name: name.clone(),
                payload,
            });
        }
    }
    if !profile.expect.complete && profile.expect.arrives.len() == payload.len() {
        return Err(GenError::ArrivesIsEverything);
    }
    // A complete row ends with the whole payload by definition, so it
    // needs no list; deriving one here means the grader has the same
    // field to read whichever kind of row it is holding.
    let arrives = if profile.expect.complete {
        payload.clone()
    } else {
        profile.expect.arrives.clone()
    };
    Ok(Expectation {
        files,
        complete: profile.expect.complete,
        gap: profile.expect.gap.clone(),
        payload,
        arrives,
        exit_zero: profile.expect.exit_zero(),
        repairs: repairs_anything(profile),
        ladder: profile.expect.ladder.reaches.clone(),
    })
}

/// The end state: one entry per SOURCE file in the order the profile
/// lists them, then the recovery files that are expected to arrive.
///
/// **Payload.** A covered member ends under the name the SET describes
/// it as (its relative path, or a patched one), because that is the
/// name the layout carries for it. An uncovered member keeps the naming
/// plane's answer, which is the name the WIRE carries. P8's whole point
/// is that one post can hold both.
///
/// **Recovery files.** The index arrives and the parity volumes do not:
/// `nzbfast get` fetches the manifest it verifies against and skips
/// parity until something needs repairing, and it does not sweep usenet
/// furniture afterwards (`smart::sweep_junk` is the DAEMON's filing
/// step, and this runner drives the CLI). So a `.par2` index really is
/// part of the end state of a clean CLI run, and the volumes really are
/// posted-and-not-arrived. Both halves are requirements rather than
/// observations: a client that pulled every volume on a clean download
/// would be spending bandwidth on parity it never used.
///
/// `repairing` is the other case, and it is not an exception to that
/// rule but the same rule read the other way: a run that HAS to repair
/// spends that bandwidth because it needs the blocks, writes the
/// volumes it fetched beside the payload, and does not sweep them. See
/// [`expects_repair`] for which selections put a layout in that case
/// and for why such a profile carries no spare parity.
fn expected_files(
    sources: &[assemble::SourceFile],
    plan: &naming::Plan,
    recovered: &Recovered,
    sidecar_names: &[String],
    repairing: bool,
    swept: bool,
) -> Vec<(String, Vec<u8>)> {
    // The naming plan lists the POSTED files, so walking the sources
    // needs its own cursor across it.
    let mut posted = 0usize;
    let mut out = Vec::with_capacity(sources.len() + recovered.files.len());
    for (i, s) in sources.iter().enumerate() {
        let wire = if recovered.is_unposted(i) {
            None
        } else {
            let n = plan.files[posted].final_name.clone();
            posted += 1;
            Some(n)
        };
        let name = if recovered.covers(i) {
            recovered.described_name(sources, i)
        } else if sidecar_names.contains(&s.rel) {
            // G4: an `.sfv` is a name source, so a member it lists lands
            // under the relative path the sidecar spells - directories
            // and all, which is what makes a checksum sidecar a tree
            // carrier as well. A SET still wins where both describe the
            // member: the set's claim is an MD5 pair over bytes it can
            // rebuild, and the sidecar's is the poster's unverified
            // word, which is the same precedence the client applies.
            s.rel.clone()
        } else {
            // An unposted member that no set covers is refused by the
            // recovery plane, so `wire` is always Some here.
            wire.expect("an unposted member is covered by a set")
        };
        out.push((name, s.bytes.clone()));
    }
    out.extend(arriving_recovery_files(
        plan, recovered, posted, repairing, swept,
    ));
    out
}

/// The end state for a whole layout, container or not.
///
/// **With no container** it is [`expected_files`] over the sources: the
/// payload under the names the layout carries for it.
///
/// **With one** the payload is what comes OUT of the archive - the
/// source files under their full relative paths, because an archive is
/// the first plane that carries a directory - and the volumes are
/// spent: a successful unpack deletes them, so a volume in the output
/// tree is a failed unpack, not an end state.
///
/// There is deliberately no third case for an archive the client
/// cannot open. That would be an ENCRYPTED layout, and `container::wrap`
/// refuses encryption outright for a reason its message spells out (the
/// key salt comes off the OS entropy, so the bytes are not reproducible
/// and a profile could not carry the shape at all), so no catalog row
/// reaches it. Adding the case before the shape exists would be writing
/// an expectation nothing can check.
fn expected_end_state(
    sources: &[assemble::SourceFile],
    contained: Option<&Contained>,
    split: Option<&Split>,
    plan: &naming::Plan,
    recovered: &Recovered,
    sidecar_names: &[String],
    repairing: bool,
    swept: bool,
) -> Vec<(String, Vec<u8>)> {
    // G3: a split post lands the JOIN and nothing else. The parts are
    // spent the way an archive's volumes are spent - a part left in the
    // output tree is a client that stopped at the wire files - and the
    // profile carries exactly one source, so the whole payload
    // expectation is that one file under its own name. Which side of
    // the cut the set describes does not change it: both directions end
    // with the same file, which is why one plane carries both.
    if let Some(s) = split {
        let whole = sources.first().expect("a split profile has one source");
        let mut out = vec![(whole.rel.clone(), whole.bytes.clone())];
        let posted = s.posted.len()
            - (0..s.posted.len())
                .filter(|i| recovered.is_unposted(*i))
                .count();
        out.extend(arriving_recovery_files(
            plan, recovered, posted, repairing, swept,
        ));
        return out;
    }
    let Some(c) = contained else {
        return expected_files(sources, plan, recovered, sidecar_names, repairing, swept);
    };
    let mut out = c.payload.clone();
    let posted = c.volumes.len()
        - (0..c.volumes.len())
            .filter(|i| recovered.is_unposted(*i))
            .count();
    out.extend(arriving_recovery_files(
        plan, recovered, posted, repairing, swept,
    ));
    out
}

/// The recovery files that are expected to ARRIVE, appended to whatever
/// payload expectation precedes them.
///
/// `posted` is how many entries of `plan.files` the payload used, which
/// is where the recovery plane's own naming entries start. The index
/// arrives and the parity volumes do not - see [`expected_files`] for
/// why both halves are requirements, and [`expects_repair`] for the one
/// case where the volumes DO arrive because the run had to spend them.
fn arriving_recovery_files(
    plan: &naming::Plan,
    recovered: &Recovered,
    posted: usize,
    repairing: bool,
    swept: bool,
) -> Vec<(String, Vec<u8>)> {
    // G6: an OUTER set changes what the inner set is. Its members are
    // the inner set's own files, so the inner files are that set's
    // PAYLOAD - and three consequences follow, none of which is a
    // special case for this row.
    //
    // 1. They land under their REAL `.par2` names, because the outer
    //    set describes them under those names and the post therefore
    //    carries them. It is the same rewrite `Recovered::described_name`
    //    makes for a covered payload member, one level up.
    // 2. They are not swept. The sweep takes packet-shaped bytes under
    //    a TOKEN; once the outer set has named them they are ordinary
    //    announced `.par2` furniture, which `nzbfast get` leaves alone.
    // 3. Every one of them arrives, parity volumes included. A parity
    //    volume is eager-skipped because it is parity FOR THE PAYLOAD
    //    and a clean run never needs it; the inner set's volumes are
    //    the outer set's members, and a client that skipped them could
    //    not verify the outer set at all.
    //
    // Measured rather than assumed: the row was first written with the
    // inner set expected to be swept, and the run kept all three inner
    // files under their real names. That is the client being right.
    let has_outer = recovered.files.iter().any(|f| f.outer);
    recovered
        .files
        .iter()
        .zip(&plan.files[posted..])
        .filter_map(|(f, nm)| {
            let inner_of_an_outer_set = has_outer && !f.outer && !f.decoy;
            // P10: THE DECOY ARRIVES, and that is the row's whole
            // discriminator rather than a detail of it. It is not
            // parity, so nothing eager-skips it; it is announced under
            // its own `.par2` name, so the sweep - which takes
            // packet-shaped bytes under a TOKEN - never looks at it;
            // and it is not a set, so no verify spends it. A client
            // that believed the extension would have taken it for
            // furniture and left it out of the tree, or spent it, and
            // this is where that shows.
            if f.decoy {
                return Some((nm.final_name.clone(), f.bytes.clone()));
            }
            if f.parity && !repairing && !inner_of_an_outer_set {
                return None;
            }
            if swept && !f.outer && !inner_of_an_outer_set {
                return None;
            }
            let name = if inner_of_an_outer_set {
                f.name.clone()
            } else {
                nm.final_name.clone()
            };
            Some((name, f.bytes.clone()))
        })
        .collect()
}

/// Whether the layout's own selections mean the client has to REPAIR
/// before it can reach the expected payload.
///
/// This decides one thing: whether the parity volumes are part of the
/// end state. On a clean run they are not - the client fetches the
/// manifest it verifies against and never spends the user's bandwidth
/// on parity it does not need. On a run that repairs it fetches them,
/// writes them beside the payload, and `nzbfast get` does not sweep
/// afterwards, so they are simply there.
///
/// **The profiles that select these arms carry EXACTLY as much parity
/// as the repair consumes, and that is load-bearing rather than
/// frugal.** With a margin, which volumes a repair pulls is a client
/// policy - it fetches whole volumes and picks among them - and a row
/// naming a particular set of volume files would be pinning that
/// policy by accident and would go red the day it improved. With no
/// margin, "every volume arrives" is forced by arithmetic: N blocks
/// cannot be rebuilt from fewer than N recovery blocks. That is why
/// each such profile's redundancy is stated to the block and its note
/// says so.
///
/// The fault and serve planes arrived at the same situation by other
/// routes and their arms are HERE, in this one function, exactly as
/// this comment asked for before they landed. A stall, a slow first
/// byte and a damaged recovery PACKET are deliberately not among them:
/// the first two cost time and the article still arrives whole, and the
/// third damages the SET rather than the payload, so a run over an
/// intact payload stays clean and never opens a volume. That is why an
/// F4 row pairs itself with real damage and says so in its note.
///
/// `pub(crate)` because `crate::fault` reads it to refuse a row whose
/// volume count it could not otherwise grade.
pub(crate) fn expects_repair(p: &Profile) -> bool {
    let s = &p.serve;
    // E3: one article is refused for its CRC, so its blocks are missing
    // and only the set can supply them.
    p.encoding.part_crc == crate::profile::PartCrc::Wrong
        // Z4: the map does not name the articles, so the client cannot
        // ask for them however healthy the server is.
        || p.nzb.drop_segments_pct > 0.0
        // S1-S4: a body that is refused, spoiled, short, or somebody
        // else's. Each loses the article's bytes; only the set has them.
        || !s.missing.is_empty()
        || !s.corrupt.is_empty()
        || s.missing_pct > 0.0
        || s.missing_once_pct > 0.0
        || s.corrupt_pct > 0.0
        || s.corrupt_once_pct > 0.0
        || !s.truncate.is_empty()
        || !s.swap.is_empty()
        // F3 and F5: a volume with a flipped header byte, or with its
        // tail cut off. Both damage the container the payload is inside.
        || p.fault.corrupt_headers
        || p.fault.truncate_last_volume_bytes > 0
        // G1: the posted payload is not the payload. The article is
        // well formed and its CRC is over the damage, so no re-ask
        // helps and the blocks have to come from parity.
        //
        // H5's levelled spans are deliberately NOT here, and the
        // distinction is the whole reason this function and
        // [`repairs_anything`] are two functions. A span on a nesting
        // LEVEL's archive is repaired from the set packed beside that
        // archive, INSIDE the post's outermost container - the posted
        // set never sees it, verifies clean, and is never spent. So the
        // posted parity volumes stay out of the end state exactly as
        // they would on an undamaged row, which is what this function
        // decides.
        || p.fault.corrupt_payload.iter().any(|d| d.inner_level.is_none())
}

/// Whether the run rebuilds bytes from parity ANYWHERE, which is a
/// wider question than [`expects_repair`]'s.
///
/// It feeds `Expectation::repairs`, which the oracle runner turns into
/// the adopt guard: a row that declares no repair arms a check refusing
/// a run that reported one having rebuilt nothing. H5's levelled damage
/// makes the client repair a nesting level's archive from the set
/// packed beside it, so a row carrying one must declare a repair - and
/// must still keep the POSTED parity out of its end state, because the
/// posted set was never touched. Two answers, two functions.
fn repairs_anything(p: &Profile) -> bool {
    expects_repair(p)
        || p.fault
            .corrupt_payload
            .iter()
            .any(|d| d.inner_level.is_some())
}

/// Whether the parity volumes are part of the END STATE.
///
/// [`expects_repair`] plus the one other reason a client opens a
/// volume: an index that is `damaged` or `absent`, where the real names
/// are inside the volumes and nowhere else. Such a row must carry
/// exactly ONE volume, because a client that only needs a NAME reads
/// volumes until it has one and stops - `crate::fault` refuses the
/// multi-volume shape by name, for the same reason this function's
/// twin above states about margins.
fn parity_is_fetched(p: &Profile) -> bool {
    expects_repair(p) || p.recovery.index != IndexState::Present
}

/// Whether the recovery set the client fetched is SWEPT off the disk
/// before the run ends, so no part of it belongs in the expected tree.
///
/// The discriminator is the set's WIRE NAME, and it is the client's
/// rule rather than a convention this crate invented. `nzbfast get`
/// finishes by walking `nzbkit::par2repair::sniffed_packet_files` -
/// files whose bytes are PAR2 packets and whose NAME is not `.par2` -
/// and removing the ones that are recovery-volume shaped. An announced
/// set (P1, P3) is never in that list, because its name says what it
/// is, so the index survives and is part of the end state. An opaque
/// set (P2) is entirely in it: every file of it had to be recognised by
/// content, and a token-named blob left in the output directory is
/// exactly the leftover the sweep exists to remove.
///
/// **How this was found, because it is not guessable from either side
/// alone.** P2 was the one recovery selection no catalog profile made,
/// and the expectation had been derived from P1 and P3 rows where the
/// index does land. Porting `bench/capability-corpus`'s n02 and n05
/// legs selected it for the first time and both rows failed on one
/// name: the generator required a `.par2` blob under a token that the
/// client had correctly taken away. The corpus grades a closed world
/// with an allow list, so an extra file there is permitted and a
/// missing one is unremarked - it could not have seen this, and neither
/// could this crate on its own. `research/POSTFAST-VS-CAPABILITY-CORPUS-2026-09-03.md`
/// is the round the two were compared in.
///
/// It is deliberately not conditioned on `repairing`: a run that spends
/// parity under an opaque set writes the volumes down and then sweeps
/// them by the same rule, because the sweep asks what a file IS and not
/// what the run did with it.
fn recovery_is_swept(p: &Profile) -> bool {
    p.recovery.names == crate::profile::RecoveryNames::Opaque
}

/// Refuse, by name, every plane a later stage owns.
///
/// The alternative - emitting a bare-files layout and letting the
/// oracle notice - is the rubber stamp the catalog README describes: a
/// profile that passes with the plane it selected never emitted turns a
/// missing feature into a green test.
fn refuse_unimplemented_planes(p: &Profile) -> Result<(), GenError> {
    let no = |plane: String, owner: &'static str| GenError::NotImplemented { plane, owner };
    // `[container]` is NOT listed here any more: chip 06 built it, and
    // `crate::container` refuses its own unbuildable shapes by name -
    // which is the rule this list states, applied by the stage that
    // knows which shapes those are rather than by a list here that
    // would go stale the first time a writer grew.
    // The recovery plane refuses its OWN unbuilt selections, by name,
    // in `crate::recovery` - it is the stage that knows which they are.
    // A recovery selection with no set is not a contradiction the
    // schema refuses (each is individually meaningful), but it is a
    // profile whose author expected a set to exist, so it is named
    // here rather than emitted as a P0 layout.
    // G4 under a container: the posted files are VOLUMES, so a sidecar
    // would list volume names and volume checksums - and a successful
    // unpack spends the volumes, so every line in it would name a file
    // that is correctly absent from the end state. The shape is real
    // (a poster shipping an `.sfv` beside a rar set), and it needs the
    // expectation to say what a sidecar over spent files means before a
    // profile may claim it.
    if p.companion.sfv && p.container.kind != crate::profile::ContainerKind::None {
        return Err(no(
            "[companion] sfv = true beside a [container]".into(),
            "nothing yet: a sidecar over an archive lists VOLUME names, and a successful              unpack spends the volumes, so what the sidecar names is absent from the end              state by construction. The expectation has to say what that means first",
        ));
    }
    if p.recovery.kind == RecoveryKind::None && p.recovery != Default::default() {
        return Err(no(
            "[recovery] with kind = \"none\"".into(),
            "nothing: a recovery selection needs a set to carry it, so set kind = \"par2\"",
        ));
    }
    // `[fault]` and `[serve]` are not listed here either: chip 07 built
    // them, and `crate::fault` and `crate::serve` refuse their own
    // unbuilt selections by name.
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    const BASELINE: &str = "\
[layout]
name = \"t\"
seed = 1

[source]
files = [
    { name = \"movie.mkv\", bytes = 8192 },
    { name = \"sample/s.mkv\", bytes = 3000 },
]

[encoding]
article_bytes = 1024
";

    fn built(text: &str) -> Layout {
        generate(&Profile::parse(text).expect("test profile parses")).expect("layout generates")
    }

    /// P2's end state carries NO recovery file, and P1's and P3's carry
    /// the index.
    ///
    /// The two halves are one test because either alone would pass over
    /// a generator that had simply stopped expecting recovery files at
    /// all, and that would quietly delete the requirement `expected_files`
    /// states at length: an announced index really does land, and a
    /// client that swept it would be taking away the manifest it
    /// verified against. See [`recovery_is_swept`] for the client rule
    /// and for the round that found it.
    #[test]
    fn an_opaque_named_set_is_swept_and_an_announced_one_lands() {
        const SET: &str = "\n[naming]\nwire = \"opaque\"\n\n[recovery]\nkind = \"par2\"\nredundancy_pct = 20\nnames = ";
        let names = |l: &Layout| {
            l.expect
                .files
                .iter()
                .map(|f| f.0.clone())
                .collect::<Vec<_>>()
        };

        let announced = names(&built(&format!("{BASELINE}{SET}\"filedesc-only\"\n")));
        assert!(
            announced.iter().any(|n| n.ends_with(".par2")),
            "an announced set keeps its own name, so its index survives the run \
             and is part of the end state: {announced:?}"
        );

        let opaque = names(&built(&format!("{BASELINE}{SET}\"opaque\"\n")));
        assert!(
            !opaque.iter().any(|n| n.ends_with(".par2")),
            "a set posted under tokens is named .par2 nowhere, so nothing here \
             should end in it either: {opaque:?}"
        );
        assert_eq!(
            opaque.len(),
            2,
            "the two payload members and nothing else - every file of an opaque \
             set is packet-shaped under a token, which is exactly what the \
             client's leftover sweep removes: {opaque:?}"
        );
    }

    /// The acceptance property, asserted on the bytes and reported on
    /// by the fingerprint. Two runs of one profile agree on the files,
    /// on every article and on the NZB.
    #[test]
    fn generating_twice_is_byte_identical() {
        let a = built(BASELINE);
        let b = built(BASELINE);
        assert_eq!(a.files, b.files);
        assert_eq!(a.articles, b.articles);
        assert_eq!(a.headers, b.headers);
        assert_eq!(a.nzb, b.nzb);
        assert_eq!(a.expect, b.expect);
        assert_eq!(a.fingerprint(), b.fingerprint());
    }

    /// ...and the seed is what makes it so, or the test above would
    /// also pass over a generator that emitted a constant.
    #[test]
    fn a_different_seed_is_a_different_layout() {
        let a = built(BASELINE);
        let b = built(&BASELINE.replace("seed = 1", "seed = 2"));
        assert_ne!(a.fingerprint(), b.fingerprint());
        // The names are descriptive in both, so it is the payload and
        // the message-ids that moved - which is the point: the SHAPE is
        // the profile's and only the material is the seed's.
        assert_eq!(
            a.expect.files.iter().map(|f| &f.0).collect::<Vec<_>>(),
            b.expect.files.iter().map(|f| &f.0).collect::<Vec<_>>()
        );
    }

    /// par2's own base name is the stem of the first covered member's
    /// basename (`base_name` in `crate::recovery`), so a descriptive set
    /// over `movie.mkv` writes `movie.par2`. A `[source]` file already
    /// spelled that way is refused rather than silently overwritten:
    /// nothing upstream compares the recovery plane's own names against
    /// the payload's.
    ///
    /// `covers` is narrowed to just `movie.mkv` so `movie.par2` is not
    /// itself staged into the real creator's scratch directory - that
    /// would surface as an on-disk collision the external `par2`
    /// binary refuses on its own terms ("changed length while the PAR2
    /// set was being built"), which is a real symptom of the same
    /// defect but not the one this test is pinning: a `[source]` entry
    /// the SET does not cover reaches `write_layout` unstaged and
    /// unchecked by the creator, and is exactly the shape this
    /// generator-level refusal exists to catch.
    #[test]
    fn a_source_file_named_like_the_recovery_set_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n\n\
                     [source]\nfiles = [\
                     { name = \"movie.mkv\", bytes = 8192 }, \
                     { name = \"movie.par2\", bytes = 16 }]\n\n\
                     [recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
                     covers = [\"movie.mkv\"]\n";
        let e = generate(&Profile::parse(text).expect("test profile parses"))
            .expect_err("a source name equal to the generated set's is a collision");
        assert!(
            matches!(e, GenError::RecoveryNameCollides(ref n) if n == "movie.par2"),
            "expected the recovery/source collision, got {e}"
        );
    }

    /// Every article decodes back to the source bytes at the offset it
    /// claims, so the layout the mock serves really is the payload.
    #[test]
    fn every_article_decodes_back_to_the_source() {
        let l = built(BASELINE);
        let mut rebuilt: HashMap<&str, Vec<u8>> = HashMap::new();
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        for (f, (name, bytes)) in parsed.files.iter().zip(&l.expect.files) {
            let mut buf = vec![0u8; bytes.len()];
            for s in &f.segments {
                let d = nzbkit::yenc::decode(&l.articles[&format!("<{}>", s.message_id)]).unwrap();
                let at = d.offset() as usize;
                buf[at..at + d.data.len()].copy_from_slice(&d.data);
            }
            rebuilt.insert(name.as_str(), buf);
        }
        for (name, bytes) in &l.expect.files {
            assert_eq!(&rebuilt[name.as_str()], bytes, "{name} round-trips");
        }
    }

    /// The posted files keep the tree; the expectation says flat,
    /// because with no container and no recovery set nothing carries a
    /// directory. Two different questions, two different answers, one
    /// layout.
    #[test]
    fn posted_files_keep_the_tree_and_the_expectation_does_not() {
        let l = built(BASELINE);
        assert_eq!(l.files[1].0, "sample/s.mkv");
        assert_eq!(l.expect.files[1].0, "s.mkv");
    }

    /// An opaque layout expects the TOKEN, because the real name was
    /// posted nowhere. Expecting the real name would be a requirement
    /// no client could ever meet.
    #[test]
    fn an_opaque_layout_expects_the_token() {
        let l = built(&format!("{BASELINE}\n[naming]\nwire = \"opaque\"\n"));
        for (name, _) in &l.expect.files {
            assert_eq!(name.len(), 24, "expected a token, got {name}");
        }
        let parsed = nzbkit::nzb::Nzb::parse(l.nzb.as_bytes()).unwrap();
        // The map is faithful to an opaque post: it names the token,
        // and it does not hand the real name back through the meta.
        assert!(!l.nzb.contains("movie.mkv"));
        assert_eq!(parsed.meta[0].1, l.expect.files[0].0);
    }

    /// `[expect]` overrides reach the Layout untouched, which is what
    /// makes a known-gap row a K row rather than a silent pass.
    #[test]
    fn an_expect_override_is_carried_through() {
        let l = built(&format!(
            "{BASELINE}\n[expect]\ncomplete = false\ngap = \"the tail is filed under its token\"\n\
             \n[expect.ladder]\nreaches = \"par2-set-id\"\n"
        ));
        assert!(!l.expect.complete);
        assert_eq!(l.expect.gap, "the tail is filed under its token");
        assert_eq!(l.expect.ladder, "par2-set-id");
    }

    /// The neutral serve plane is a neutral Chaos and no second server.
    #[test]
    fn a_neutral_profile_asks_the_server_for_nothing() {
        let l = built(BASELINE);
        assert!(l.chaos.missing.is_empty());
        assert!(l.chaos.corrupt.is_empty());
        assert!(l.second.is_empty());
    }

    /// Every plane a later stage owns is refused by name. Silently
    /// emitting bare files for a profile that selected a container is
    /// the rubber stamp this crate exists to make impossible.
    #[test]
    fn planes_a_later_stage_owns_are_refused_by_name() {
        for (extra, owner) in [
            // A recovery selection with no set to carry it: refused
            // here, because the author meant to select a plane and
            // selected nothing.
            (
                "[recovery]\nzero_byte_member = true\n",
                "recovery selection needs a set",
            ),
            // The fault planes are built, and refuse their own
            // impossible selections by name: F3 and F5 damage an
            // ARCHIVE, and a profile with no container has none.
            (
                "[fault]\ncorrupt_headers = true\n",
                "no container, so there is no archive to damage",
            ),
            (
                "[fault]\ntruncate_last_volume_bytes = 64\n",
                "no container, so there is no archive to damage",
            ),
            // A fault over a recovery set the profile does not have.
            (
                "[fault]\ncorrupt_recovery_packets = 1\n",
                "damages a PAR2 set and this profile has none",
            ),
        ] {
            let p = Profile::parse(&format!("{BASELINE}\n{extra}")).expect("profile parses");
            let msg = match generate(&p) {
                Err(e) => e.to_string(),
                Ok(_) => panic!("{extra:?} must be refused"),
            };
            assert!(
                msg.contains(owner),
                "{extra:?} was refused without naming {owner}: {msg}"
            );
        }
    }

    /// A gap row's `arrives` list names PAYLOAD entries and is carried
    /// through to the grader, which asserts everything else is absent.
    #[test]
    fn a_gap_rows_arrives_list_is_carried_through() {
        let l = built(&format!(
            "{BASELINE}\n[expect]\ncomplete = false\narrives = [\"movie.mkv\"]\n\
             gap = \"the sample is filed under its token\"\n"
        ));
        assert_eq!(l.expect.payload, vec!["movie.mkv", "s.mkv"]);
        assert_eq!(l.expect.arrives, vec!["movie.mkv"]);
        assert!(!l.expect.complete);
    }

    /// Failing to find is failing: `arrives` naming something the layout
    /// does not carry would assert nothing at all, so it is refused with
    /// the names that ARE carried.
    #[test]
    fn an_arrives_entry_the_layout_does_not_carry_is_refused() {
        let p = Profile::parse(&format!(
            "{BASELINE}\n[expect]\ncomplete = false\narrives = [\"sample/s.mkv\"]\n\
             gap = \"g\"\n"
        ))
        .expect("profile parses");
        // The tree is flattened with no container and no set, so the
        // name the LAYOUT carries is `s.mkv` and the [source] spelling
        // is not it - which is exactly the mistake worth naming.
        let msg = generate(&p).unwrap_err().to_string();
        assert!(msg.contains("sample/s.mkv"), "{msg}");
        assert!(msg.contains("s.mkv\"]"), "{msg}");
    }

    /// A gap row whose `arrives` is the whole payload says what
    /// `complete = true` says.
    #[test]
    fn an_arrives_list_of_everything_is_refused() {
        let p = Profile::parse(&format!(
            "{BASELINE}\n[expect]\ncomplete = false\narrives = [\"movie.mkv\", \"s.mkv\"]\n\
             gap = \"g\"\n"
        ))
        .expect("profile parses");
        assert!(matches!(generate(&p), Err(GenError::ArrivesIsEverything)));
    }

    /// A gap override without a reason, and a reason without a gap, are
    /// both refused by the SCHEMA - the override is the one door out of
    /// a derived expectation and it does not open half way.
    #[test]
    fn a_half_written_gap_override_is_a_load_error() {
        for extra in [
            "[expect]\ncomplete = false\n",
            "[expect]\ngap = \"why\"\n",
            "[expect]\narrives = [\"movie.mkv\"]\n",
        ] {
            let e = Profile::parse(&format!("{BASELINE}\n{extra}"))
                .expect_err(&format!("{extra:?} must not load"));
            assert!(e.to_string().contains("[expect]"), "{e}");
        }
    }

    /// `exits` is DERIVED from `complete` unless a profile overrides
    /// it, and the override always pins a gap in one direction or the
    /// other. Both requirements are real: a run that delivers
    /// everything exits zero, and one that cannot says so.
    #[test]
    fn the_expected_exit_follows_complete_unless_a_row_pins_a_gap() {
        assert!(built(BASELINE).expect.exit_zero);
        let incomplete = built(&format!(
            "{BASELINE}\n[expect]\ncomplete = false\narrives = [\"movie.mkv\"]\n\
             gap = \"the sample is lost\"\n"
        ));
        assert!(
            !incomplete.expect.exit_zero,
            "an incomplete run must say so"
        );
        // The shape `complete` cannot describe: every file arrived and
        // the process reported failure anyway.
        let wrong_verdict = built(&format!(
            "{BASELINE}\n[expect]\nexits = \"nonzero\"\ngap = \"the run reports failure \
             having produced every file correctly\"\n"
        ));
        assert!(wrong_verdict.expect.complete);
        assert!(!wrong_verdict.expect.exit_zero);
        // ...and it is not writable without saying why.
        let e = Profile::parse(&format!("{BASELINE}\n[expect]\nexits = \"nonzero\"\n"))
            .expect_err("an exits override with no gap must not load");
        assert!(e.to_string().contains("exits"), "{e}");
    }

    /// Whether the layout damages the PAYLOAD reaches the grader, which
    /// is what lets it tell a repair from an adoption.
    #[test]
    fn the_expectation_says_whether_a_repair_is_expected() {
        assert!(!built(BASELINE).expect.repairs);
        assert!(
            !built(&format!("{BASELINE}\n[serve]\nstall = [0]\n"))
                .expect
                .repairs
        );
        assert!(
            built(&format!("{BASELINE}\n[serve]\nmissing_pct = 10.0\n"))
                .expect
                .repairs
        );
    }

    /// EVERY profile the repo ships generates, generates the same
    /// bytes twice, decodes back to its own payload, and produces an
    /// NZB the client's own parser reads with every message-id in it
    /// answerable. This is the acceptance for the whole stage, and it
    /// is written over the catalog DIRECTORY rather than over a list of
    /// profile names so that a profile added tomorrow is covered the
    /// day it lands, with no test edit to forget.
    #[test]
    fn every_catalog_profile_generates_and_round_trips() {
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let mut seen = 0usize;
        for entry in std::fs::read_dir(&dir).expect("the catalog directory exists") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let p = Profile::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            let name = path.display();
            let a = generate(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
            let b = generate(&p).unwrap_or_else(|e| panic!("{name}: {e}"));
            assert_eq!(a.files, b.files, "{name}: files differ between runs");
            assert_eq!(a.articles, b.articles, "{name}: articles differ");
            assert_eq!(a.headers, b.headers, "{name}: headers differ");
            assert_eq!(a.nzb, b.nzb, "{name}: nzb differs");
            assert_eq!(a.fingerprint(), b.fingerprint(), "{name}: fingerprint");

            let parsed = nzbkit::nzb::Nzb::parse(a.nzb.as_bytes())
                .unwrap_or_else(|e| panic!("{name}: the client cannot parse the nzb: {e:?}"));
            // Against `files`, the POSTED list, and not against
            // `expect.files`: the two are deliberately different lists
            // once a recovery plane is selected. A `.par2` is posted
            // and swept, so it is in one and not the other; a 0-byte
            // FileDesc member is described and never posted, so it is
            // in the other and not this one.
            assert_eq!(
                parsed.files.len(),
                a.files.len(),
                "{name}: the map lists a different number of files than the layout posts"
            );
            // Two planes make a post deliberately un-round-trippable,
            // and each is checked as the property it actually is rather
            // than excused. Z4 leaves posted articles out of the map, so
            // the map becomes a strict SUBSET and the bytes it does
            // reach must still be exact. E3's `wrong` arm poisons one
            // article's CRC, so exactly one article must refuse to
            // decode and every other must not. Anything else here - a
            // hole a plane did not ask for, a second refusal, a plane
            // selected that changed nothing - is a generator defect and
            // fails.
            let dropping = p.nzb.drop_segments_pct > 0.0;
            let poisoning = p.encoding.part_crc == crate::profile::PartCrc::Wrong;
            let (mut in_map, mut refused) = (0usize, 0usize);
            for (f, (fname, bytes)) in parsed.files.iter().zip(&a.files) {
                let mut buf = vec![0u8; bytes.len()];
                let mut covered = vec![false; bytes.len()];
                assert!(
                    f.segments.iter().any(|s| s.number == 1),
                    "{name}: {fname} lost part 1 from the map"
                );
                for s in &f.segments {
                    let body = a
                        .articles
                        .get(&format!("<{}>", s.message_id))
                        .unwrap_or_else(|| {
                            panic!(
                                "{name}: the map names {} and no article answers it",
                                s.message_id
                            )
                        });
                    let d = match nzbkit::yenc::decode(body) {
                        Ok(d) => d,
                        Err(nzbkit::yenc::YencError::CrcMismatch { .. }) if poisoning => {
                            refused += 1;
                            in_map += 1;
                            continue;
                        }
                        Err(e) => {
                            panic!("{name}: {} does not decode: {e:?}", s.message_id)
                        }
                    };
                    let at = d.offset() as usize;
                    buf[at..at + d.data.len()].copy_from_slice(&d.data);
                    covered[at..at + d.data.len()].fill(true);
                    in_map += 1;
                }
                if !dropping && !poisoning {
                    assert_eq!(&buf, bytes, "{name}: {fname} does not round-trip");
                    continue;
                }
                // Every byte that DID arrive is the byte that was
                // posted, hole or no hole. A layout whose fault also
                // corrupted the surviving bytes would pass a
                // whole-file comparison's absence and fail here.
                for (i, (got, want)) in buf.iter().zip(bytes.iter()).enumerate() {
                    assert!(
                        !covered[i] || got == want,
                        "{name}: {fname} byte {i} arrived wrong"
                    );
                }
            }
            if dropping {
                assert!(
                    in_map < a.articles.len(),
                    "{name}: drop_segments_pct is selected and the map still names every \
                     article - the plane did nothing"
                );
            } else {
                assert_eq!(
                    in_map,
                    a.articles.len(),
                    "{name}: an article was posted that the map never mentions"
                );
            }
            assert_eq!(
                refused,
                usize::from(poisoning),
                "{name}: exactly one article may carry a CRC that does not describe it, \
                 and only where part_crc = \"wrong\" selected it"
            );
            seen += 1;
        }
        // Failing to find is failing: a catalog this walk could not
        // read would otherwise report a clean sweep over nothing.
        assert!(
            seen >= 2,
            "expected the catalog to hold profiles, walked {seen}"
        );
    }

    /// A hand-built profile that does not hold together is an error,
    /// not a panic. `generate` is public and the struct is public, so
    /// the invalid case is reachable without going near a loader.
    #[test]
    fn a_hand_built_contradictory_profile_is_an_error_not_a_panic() {
        let mut p = Profile::parse(BASELINE).expect("profile parses");
        p.source.files.clear();
        assert!(matches!(
            generate(&p),
            Err(GenError::Profile(
                crate::profile::Contradiction::NoSourceFiles
            ))
        ));
    }

    /// The refusal says which plane and what to do about it, so it
    /// points somewhere instead of just saying no.
    #[test]
    fn a_refusal_names_the_plane_and_the_fix() {
        let p = Profile::parse(&format!("{BASELINE}\n[fault]\ncorrupt_headers = true\n"))
            .expect("profile parses");
        let msg = generate(&p).unwrap_err().to_string();
        assert!(msg.contains("[fault]"), "{msg}");
        assert!(msg.contains("[container] kind"), "{msg}");
    }

    /// A container replaces what every plane below it sees: the posted
    /// files are the volumes, and the end state is what comes out of
    /// them - under the FULL relative path, because an archive is the
    /// first plane that carries a directory at all.
    #[test]
    fn a_container_posts_volumes_and_expects_the_payload() {
        let l = built(&format!("{BASELINE}\n[container]\nkind = \"rar-stored\"\n"));
        assert_eq!(l.files.len(), 1, "one stored volume: {:?}", l.files);
        assert_eq!(l.files[0].0, "movie.rar");
        assert_eq!(
            l.expect
                .files
                .iter()
                .map(|f| f.0.as_str())
                .collect::<Vec<_>>(),
            vec!["movie.mkv", "sample/s.mkv"],
            "the archive carries the tree, so the expectation keeps it"
        );
        // ...and the bytes are the SOURCE bytes, not the volume's.
        assert_eq!(l.expect.files[0].1.len(), 8192);
    }
    /// A container REPLACES what the recovery plane sees: the set
    /// covers the volumes, not the payload, so its index arrives beside
    /// the unpacked files and the volumes are spent by the unpack.
    #[test]
    fn a_container_and_a_recovery_set_expect_the_payload_and_the_index() {
        let l = built(&format!(
            "{BASELINE}\n[container]\nkind = \"rar-stored\"\n\n[recovery]\nkind = \"par2\"\n"
        ));
        let names: Vec<&str> = l.expect.files.iter().map(|f| f.0.as_str()).collect();
        assert_eq!(names[0], "movie.mkv");
        assert_eq!(names[1], "sample/s.mkv");
        assert!(
            names[2..].iter().all(|n| n.ends_with(".par2")),
            "the tail is the recovery set: {names:?}"
        );
        // The volumes are NOT in the end state: a successful unpack
        // spends them.
        assert!(!names.iter().any(|n| n.ends_with(".rar")), "{names:?}");
    }
}
