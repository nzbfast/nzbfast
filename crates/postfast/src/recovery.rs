//! `[recovery]`, plane 7.C: the PAR2 set beside the post.
//!
//! A recovery set is the only carrier in an obfuscated post that
//! reliably holds a REAL name: the wire may say nothing at all and the
//! map may say a token, and a FileDesc packet still says
//! `VIDEO_TS/VTS_01_1.VOB`. So this plane does two things that look
//! unrelated and are the same thing:
//!
//! 1. It builds the `.par2` files and hands them back as ordinary
//!    posted files, so they enter the article map under the naming
//!    plane like anything else.
//! 2. It REWRITES THE EXPECTATION for every member the set covers, from
//!    the flat name the naming plane could justify to the relative path
//!    the set actually carries. That is where N8's tree materialisation
//!    comes from, and [`crate::naming`]'s header hands it over in as
//!    many words.
//!
//! **The wire is not touched.** A covered member's yEnc name, subject
//! and NZB entry are exactly what the naming plane decided; only what
//! the client must END with changes. Rewriting the wire here would
//! quietly turn P3 (the set is the sole name source) into P1, and the
//! row would pass over a shape it never posted.
//!
//! **The set is built by `nzbkit::par2gen`, not by par2cmdline.** Two
//! reasons, both load-bearing. It takes no external binary, so a
//! profile generates the same bytes on a box with no `par2` installed
//! and CI needs no tool it does not have (and CI's par2 is 0.8.1 while
//! a dev box carries 1.3.0 - memory `nzbfast-ci-par2-version-skew`).
//! And par2cmdline cannot emit the 0-byte member at all: it prints
//! "Skipping 0 byte file" and omits it (matrix finding F3), which is
//! the exact hole `par2gen` was written to close. The e2e rows work
//! around it by PATCHING par2cmdline output after the fact; here the
//! set is written correctly the first time and
//! [`crate::par2patch::empty_filedesc`] is kept only for sets built by
//! something else.
//!
//! **par2gen wants files on disk**, so this stage stages the payload in
//! a scratch directory and deletes it again. The layout stays
//! deterministic across that: a PAR2 set records names, lengths and
//! hashes and nothing about where the bytes were read from, so the
//! blobs depend on the profile and the seed alone.

use std::path::PathBuf;

use nzbkit::par2gen::{Member, Par2Spec};

use crate::assemble::SourceFile;
use crate::par2patch::{self, PatchError};
use crate::profile::{Covers, Profile, RecoveryKind, RecoveryNames, WireName};
use crate::rng::Rng;

/// A generated recovery file: the name it would have on disk, and its
/// bytes. Fed back into the ordinary pipeline as a [`SourceFile`], so
/// it is named, encoded, posted and mapped like any other file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RecoveryFile {
    pub name: String,
    pub bytes: Vec<u8>,
    /// Whether this file carries RECOVERY SLICES rather than only the
    /// critical packets - `<base>.volNNN+MM.par2` rather than
    /// `<base>.par2`.
    ///
    /// It decides whether the file is expected to LAND. A clean run
    /// fetches the index, which is the manifest it verifies against,
    /// and fetches no parity at all: the volumes are eager-skipped and
    /// pulled only when something needs repairing. So a parity volume
    /// is posted and expected not to arrive, and that is a requirement
    /// worth stating rather than an accident - a client that pulled
    /// every volume on a clean download would be spending the user's
    /// bandwidth on parity it never used. A row that DAMAGES the post
    /// (the fault planes, chip 07) will expect them to arrive, which is
    /// the same rule read the other way.
    pub parity: bool,
    /// G6: this file belongs to the OUTER set - the one built over the
    /// inner set's own `.par2` files.
    ///
    /// It decides two things a stage below cannot work out for itself:
    /// the file is named DESCRIPTIVELY whatever `[recovery] names` says
    /// (an outer set nobody can find names nothing), and it is not
    /// swept, because the sweep takes packet-shaped bytes under a TOKEN
    /// and this file's name is its own.
    pub outer: bool,
    /// P10: this file is the DECOY - a `.par2` name over bytes that are
    /// not a PAR2 set.
    ///
    /// It rides in this list because it is `.par2`-named furniture as
    /// far as every stage below is concerned, and it is flagged because
    /// three of them must not treat it as a set: it keeps its own name
    /// whatever `[recovery] names` says (a decoy under a token announces
    /// nothing and poses nothing), it is never swept, and the
    /// par2cmdline conformance walk must not ask a reference tool to
    /// verify a file whose whole point is that no tool can.
    pub decoy: bool,
}

/// What the recovery plane decided, for the stages downstream of it.
#[derive(Debug, Clone, PartialEq, Eq, Default)]
pub struct Recovered {
    /// The `.par2` files, index first, in the order they are posted.
    pub files: Vec<RecoveryFile>,
    /// Indices into the assembled source list, of every member a set
    /// covers. Those are the members whose expected name becomes their
    /// relative path.
    pub covered: Vec<usize>,
    /// Indices into the assembled source list of members that are
    /// DESCRIBED and never posted: the 0-byte placeholders of P5. They
    /// have no articles, no NZB entry and no wire name, and the client
    /// must materialise each one from its FileDesc alone.
    pub unposted: Vec<usize>,
    /// P6: `(source index, patched name)` for every member whose
    /// FileDesc was rewritten to say something the creator would not
    /// have written. The patched name is what the set DESCRIBES the
    /// member as, so it is what [`Recovered::described_name`] answers.
    pub renamed: Vec<(usize, String)>,
}

impl Recovered {
    /// The final name a covered member must land under: the name the
    /// set DESCRIBES it as.
    ///
    /// That is the member's relative path, directories and all - which
    /// is where N8's tree materialisation comes from - unless a
    /// `hostile_names` entry rewrote the FileDesc, in which case it is
    /// the patched name, because the patched name is what the layout
    /// now carries.
    ///
    /// Derived from what the layout carries and never from what a
    /// client does with it: the rule [`crate::naming`]'s header states
    /// for `final_name` holds here unchanged.
    pub fn described_name(&self, sources: &[SourceFile], index: usize) -> String {
        match self.renamed.iter().find(|(i, _)| *i == index) {
            Some((_, n)) => n.clone(),
            None => sources[index].rel.clone(),
        }
    }

    /// Whether a set covers the member at `index`.
    pub fn covers(&self, index: usize) -> bool {
        self.covered.contains(&index)
    }

    /// Whether the member at `index` is described but never posted.
    pub fn is_unposted(&self, index: usize) -> bool {
        self.unposted.contains(&index)
    }
}

/// Why a recovery set could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum RecoveryError {
    /// `names = "filedesc-only"` beside a wire that still says the real
    /// name, so the set is not the sole name source the row claims.
    FiledescOnlyNeedsAnOpaqueWire,
    /// `zero_byte_member = true` with no 0-byte file in `[source]` to
    /// be the placeholder, or a 0-byte source file no set covers.
    ZeroByteMemberWithout(&'static str),
    /// `covers` (or the second set) names a file `[source]` does not
    /// have. Named against the source list because that is what an
    /// author would fix.
    NoSuchMember { name: String, plane: &'static str },
    /// The two sets of P9 would cover the same member, so neither is
    /// independent of the other.
    SetsOverlap(String),
    /// G5: a dedupe copy no set covers, so nothing in the post names it.
    DedupeCopyNotCovered(String),
    /// G6: an outer set over a set whose FileDesc packets are patched
    /// after it was hashed.
    OuterSetOverPatchedFiles,
    /// The two sets of P9 would be built under one base name, so one
    /// would write over the other.
    SetsShareABaseName(String),
    /// A `hostile_names` entry whose end state this generator cannot
    /// state as a requirement.
    HostileNameNotExpressible { name: String, why: &'static str },
    /// More `hostile_names` than there are covered members to rename.
    TooManyHostileNames { given: usize, members: usize },
    /// P10: the decoy's name is one the recovery plane already minted
    /// for a real set file.
    DecoyNameCollidesWithASetFile(String),
    /// P10: the decoy is shorter than the genuine head it carries.
    DecoyTooShort {
        name: String,
        bytes: u64,
        floor: u64,
    },
    /// A patch that could not be applied to the built set.
    Patch(PatchError),
    /// `par2gen` refused, or the scratch directory could not be used.
    Creator(String),
}

impl std::fmt::Display for RecoveryError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FiledescOnlyNeedsAnOpaqueWire => f.write_str(
                "[recovery] names = \"filedesc-only\" (P3) says the recovery set is the ONLY \
                 place a real name exists, and the wire still carries one. Set [naming] \
                 wire = \"opaque\", or select names = \"descriptive\" or \"opaque\"",
            ),
            Self::ZeroByteMemberWithout(what) => write!(
                f,
                "[recovery] zero_byte_member = true needs {what}. The placeholder is a \
                 [source] entry with bytes = 0: it is DESCRIBED by the set and never \
                 posted, which is the shape the client has to materialise from a FileDesc \
                 packet alone"
            ),
            Self::NoSuchMember { name, plane } => write!(
                f,
                "[recovery] {plane} names {name:?}, which is not a file in [source]. A set \
                 can only cover what the post carries"
            ),
            Self::DedupeCopyNotCovered(n) => write!(
                f,
                "[source] {n:?} has same_as, so it is described by a set and never posted - \
                 and no set covers it. A dedupe copy nothing describes exists in no part of \
                 the layout at all: not on the wire, and not in a descriptor. Widen \
                 [recovery] covers, or drop the entry"
            ),
            Self::OuterSetOverPatchedFiles => f.write_str(
                "[recovery] outer = true beside hostile_names: the patch rewrites FileDesc \
                 packets in the inner set's files AFTER the outer set was cut over them, so \
                 the outer set would describe bytes the post no longer carries and would \
                 report the whole inner set damaged. Select one",
            ),
            Self::SetsOverlap(n) => write!(
                f,
                "[recovery] both sets would cover {n:?}: P9 is TWO INDEPENDENT sets in one \
                 post, and a member in both makes them one set in two files"
            ),
            Self::SetsShareABaseName(b) => write!(
                f,
                "[recovery] both sets would be built under the base name {b:?}, so the \
                 second would write over the first. The base is the stem of a set's first \
                 covered member; give the two sets members whose stems differ"
            ),
            Self::HostileNameNotExpressible { name, why } => write!(
                f,
                "[recovery] hostile_names entry {name:?} {why}. The oracle grades a run by \
                 the exact output tree, so a profile may only select a hostile name whose \
                 correct end state this generator can state. The containment rows for the \
                 other shapes are in crates/nzbfast/tests/e2e_norar/pins.rs"
            ),
            Self::TooManyHostileNames { given, members } => write!(
                f,
                "[recovery] hostile_names has {given} entries and the set covers {members} \
                 members: each entry renames the FileDesc of the covered member at its own \
                 position, so there is nothing for the extras to rename"
            ),
            Self::DecoyNameCollidesWithASetFile(n) => write!(
                f,
                "[recovery] decoy is named {n:?}, which is a file the set itself is built                  under. The decoy is the one `.par2` in the post that is NOT parity, so a                  name the real set already owns would make the row unreadable and would                  leave one of the two files with nowhere to land. The set's names come                  from the stem of its first covered member, so rename the decoy"
            ),
            Self::DecoyTooShort { name, bytes, floor } => write!(
                f,
                "[recovery] decoy {name:?} asks for {bytes} bytes and its genuine head                  needs at least {floor}. The head is a real creator's critical packets, so                  its length is a fact about the creator rather than a number this schema                  could state - which is why the floor is reported here with both numbers                  instead of being written into the profile schema"
            ),
            Self::Patch(e) => write!(f, "[recovery] {e}"),
            Self::Creator(e) => write!(f, "[recovery] the PAR2 creator refused: {e}"),
        }
    }
}

impl std::error::Error for RecoveryError {}

impl From<PatchError> for RecoveryError {
    fn from(e: PatchError) -> Self {
        Self::Patch(e)
    }
}

/// Build the recovery plane for one profile.
///
/// Returns [`Recovered::default`] for P0, so a caller needs no special
/// case for "no set" - the empty answer really is the neutral one.
///
/// Draw order: nothing here draws from the seeded stream at all. The
/// set is a function of the payload and the profile, and the tokens the
/// recovery FILES are posted under are drawn by the caller, after the
/// payload's, so that adding a recovery set to a profile leaves every
/// payload message-id where it was.
pub fn build(profile: &Profile, sources: &[SourceFile]) -> Result<Recovered, RecoveryError> {
    if profile.recovery.kind == RecoveryKind::None {
        // The schema already refuses the selections that need a set
        // (redundancy without one, filedesc-only without one), so
        // there is nothing left here to check.
        //
        // P10 IS REACHABLE HERE, and deliberately: a decoy with no real
        // set beside it is the purest form of the row, a post whose
        // only self-announced parity is the thing that is not parity.
        // Refusing the pairing would have made the key mean "a decoy
        // beside a set", which is a narrower shape than the plane.
        let mut out = Recovered::default();
        if profile.recovery.decoy.is_some() {
            out.files.push(create_decoy(profile, &out.files)?);
        }
        return Ok(out);
    }
    // `[recovery] index` is BUILT here in full and DAMAGED by the fault
    // plane: a set is always created with its index, and `crate::fault`
    // then removes it (P7) or unseals its packets (F7). Keeping the
    // damage there rather than here is what stops the creator growing a
    // "build it wrong" mode, which is a thing no creator should have.
    if profile.recovery.names == RecoveryNames::FiledescOnly
        && profile.naming.wire != WireName::Opaque
    {
        return Err(RecoveryError::FiledescOnlyNeedsAnOpaqueWire);
    }

    let primary = select(sources, &profile.recovery.covers, "covers")?;
    let second = if profile.recovery.second_covers.is_empty() {
        Vec::new()
    } else {
        select_named(sources, &profile.recovery.second_covers, "second_covers")?
    };
    for i in &second {
        if primary.contains(i) {
            return Err(RecoveryError::SetsOverlap(sources[*i].rel.clone()));
        }
    }
    let mut covered: Vec<usize> = primary.iter().chain(&second).copied().collect();
    covered.sort_unstable();

    let unposted = described_but_unposted(profile, sources, &covered)?;

    // One scratch directory for both sets: par2gen reads the members
    // from disk and the two sets read the same payload. Only the
    // COVERED members are staged - an uncovered one is not read by any
    // creator, and a partial-coverage profile over a large payload
    // should not pay to write what nothing describes.
    let stage = Stage::new()?;
    for &i in &covered {
        stage.write(&sources[i].rel, &sources[i].bytes)?;
    }
    let base = base_name(sources, &primary);
    let mut files = create(&stage, sources, &primary, &base, profile)?;
    if !second.is_empty() {
        // A DISTINCT base, or the two sets would write over each
        // other's index in the same directory and the post would carry
        // one set wearing two names.
        let second_base = format!("{}-b", base_name(sources, &second));
        if second_base == base {
            return Err(RecoveryError::SetsShareABaseName(base));
        }
        files.extend(create(&stage, sources, &second, &second_base, profile)?);
    }

    // G7: the FOREIGN set, over members this post does not carry. Built
    // last so the real set's files come first in the posted order,
    // which is where a reader of a failing expectation looks for them,
    // and over a staging directory of its own so a future globbing
    // `covers` selection could never draw a phantom into a real set.
    if !profile.recovery.phantom_covers.is_empty() {
        files.extend(create_phantom_set(profile, &base)?);
    }

    // G6: the OUTER set, over the inner set's own files. Built after
    // every other set so it describes them all, and before the hostile
    // patch below - which rewrites FileDesc packets in the INNER set's
    // files and would otherwise invalidate what the outer set just
    // hashed. `create` refuses the pairing outright rather than leaving
    // that to be discovered.
    if profile.recovery.outer {
        if !profile.recovery.hostile_names.is_empty() {
            return Err(RecoveryError::OuterSetOverPatchedFiles);
        }
        files.extend(create_outer_set(profile, &files, &base)?);
    }

    let renamed = apply_hostile_names(profile, sources, &primary, &mut files)?;

    // P10: the DECOY, last of all. After `apply_hostile_names` because
    // that patch walks every file of the set rewriting FileDesc packets
    // and the decoy has none to rewrite, and after the outer set
    // because an outer set describes the set's own files and the decoy
    // is not one of them - a decoy an outer set had described would be
    // announced by name, which is the opposite of what it poses.
    if profile.recovery.decoy.is_some() {
        files.push(create_decoy(profile, &files)?);
    }

    Ok(Recovered {
        files,
        covered,
        unposted,
        renamed,
    })
}

/// The base-name suffix the outer set is built under.
const OUTER_SUFFIX: &str = "-outer";

/// G6: a set over the inner set's own `.par2` files.
///
/// **The chain, and why it is a shape rather than a curiosity.** With
/// `names = "opaque"` the payload rides under tokens AND so does its
/// recovery set, so nothing announced in the post describes the payload
/// at all. A small outer set under ordinary `.par2` names describes the
/// inner set's files by their real names, and a name-driven client has
/// to walk outer, then inner, then payload to get anywhere. A client
/// that recognises PAR2 packets by content shortcuts the whole chain,
/// which is the interesting half: both routes must reach the same
/// payload under the same name.
///
/// The outer set is built over the inner set's files EXACTLY as they
/// were posted, so it describes the bytes a client will actually
/// receive. It takes the profile's own `redundancy_pct` and
/// `block_bytes`, which over a few kilobytes of packets is a small set
/// whatever the numbers are.
fn create_outer_set(
    profile: &Profile,
    inner: &[RecoveryFile],
    real_base: &str,
) -> Result<Vec<RecoveryFile>, RecoveryError> {
    let members: Vec<SourceFile> = inner
        .iter()
        .map(|f| SourceFile {
            rel: f.name.clone(),
            base: f.name.clone(),
            bytes: f.bytes.clone(),
        })
        .collect();
    let stage = Stage::new()?;
    for m in &members {
        stage.write(&m.rel, &m.bytes)?;
    }
    let idx: Vec<usize> = (0..members.len()).collect();
    let base = format!("{real_base}{OUTER_SUFFIX}");
    let mut out = create(&stage, &members, &idx, &base, profile)?;
    for f in &mut out {
        f.outer = true;
    }
    Ok(out)
}

/// The stream label for the phantom payload, XORed into the profile's
/// seed. Its bytes are never posted and never expected, so they are
/// drawn away from the layout stream for the ordinary diffability
/// reason: adding a foreign set to a profile must not move a single
/// payload name or message-id in it.
const PHANTOM_STREAM: u64 = 0x5048_414e_544f_4d20; // "PHANTOM "

/// The base-name suffix the foreign set is built under.
const PHANTOM_SUFFIX: &str = "-foreign";

/// G7: a complete recovery set over members that are described and
/// never posted.
///
/// **Why a whole SET of its own rather than a phantom member inside the
/// real one.** A phantom in the primary set would make that set
/// describe a member the post lacks, which is a different shape and a
/// harsher one: every row carrying it would be incomplete by
/// construction, because the client is right to say a described member
/// never arrived. The shape in the wild - and the one
/// `bench/capability-corpus` leg n28 poses - is a second, complete,
/// self-consistent set that simply belongs to another release, sitting
/// beside a real post that is fine. The question is a negative one:
/// the phantom must neither fail the job nor be invented on disk.
///
/// The bytes are drawn here, from [`PHANTOM_STREAM`], and die with the
/// staging directory. Nothing in the layout carries them - which is
/// exactly the property being tested, so a stage that leaked them into
/// the posted files would be answering its own question.
fn create_phantom_set(
    profile: &Profile,
    real_base: &str,
) -> Result<Vec<RecoveryFile>, RecoveryError> {
    let members = phantom_members(profile)?;
    let stage = Stage::new()?;
    for m in &members {
        stage.write(&m.rel, &m.bytes)?;
    }
    let idx: Vec<usize> = (0..members.len()).collect();
    let base = format!("{}{PHANTOM_SUFFIX}", base_name(&members, &idx));
    if base == real_base {
        return Err(RecoveryError::SetsShareABaseName(base));
    }
    create(&stage, &members, &idx, &base, profile)
}

/// The phantom members a profile declares, with their bytes.
///
/// `pub(crate)` and separate from [`create_phantom_set`] for ONE
/// caller: the par2cmdline conformance test, which stages a set's
/// members and asks the reference tool to verify it. A phantom is
/// unposted by construction, so that walk has nothing to stage and
/// par2cmdline correctly answers "Target: missing" - which is the row's
/// own point and not a malformed set. Recomputing the bytes here lets
/// the guard prove what it exists to prove, that the FOREIGN SET IS
/// WELL FORMED, rather than skipping it and proving nothing.
///
/// This is a byte-for-byte second draw of the same stream, not a copy
/// kept alive: the bytes must never survive into a `Layout`, because a
/// post that carried them would answer the question the row asks.
pub(crate) fn phantom_members(profile: &Profile) -> Result<Vec<SourceFile>, RecoveryError> {
    let mut rng = Rng::from_seed(profile.layout.seed ^ PHANTOM_STREAM);
    let mut members = Vec::with_capacity(profile.recovery.phantom_covers.len());
    for ph in &profile.recovery.phantom_covers {
        // The same name rule a real source obeys, applied by the same
        // function: this crate must not be able to describe a member
        // under a name our own posting tool would refuse.
        let base = crate::assemble::check_name(&ph.name)
            .map_err(|e| RecoveryError::Creator(format!("[recovery] phantom_covers: {e}")))?;
        let mut bytes = vec![0u8; ph.bytes as usize];
        rng.fill(&mut bytes);
        members.push(SourceFile {
            rel: ph.name.clone(),
            base,
            bytes,
        });
    }
    Ok(members)
}

/// The stream label for the decoy's junk, XORed into the profile's
/// seed, and a second one for the scratch member its genuine head is
/// cut from. Two streams and not one: the head member's bytes are
/// thrown away with its staging directory, and a single stream would
/// have made the first two kilobytes of the junk a copy of them.
const DECOY_STREAM: u64 = 0x4445_434f_595f_4a4e; // "DECOY_JN"
const DECOY_HEAD_STREAM: u64 = 0x4445_434f_595f_4844; // "DECOY_HD"

/// The scratch member the decoy's head packets are cut from, and its
/// length. Neither is a profile selection: the head is not payload and
/// never reaches the post, so a knob here would be a number an author
/// could change without changing anything a row asserts.
const DECOY_HEAD_MEMBER: &str = "decoy-head.bin";
const DECOY_HEAD_MEMBER_BYTES: usize = 2048;

/// How much junk the decoy must have room for after its head: the
/// broken cell below is a 64-byte packet header, and a cell with no
/// body after it would sit flush against EOF and never exercise the
/// resume.
const DECOY_JUNK_FLOOR: u64 = 256;

/// The PAR2 packet magic, and the two packet types the head keeps.
const DECOY_MAGIC: &[u8; 8] = b"PAR2\0PKT";
const TYPE_MAIN: [u8; 16] = *b"PAR 2.0\0Main\0\0\0\0";
const TYPE_CREATOR: [u8; 16] = *b"PAR 2.0\0Creator\0";

/// P10: a file the post names `.par2` whose bytes are not a PAR2 set.
///
/// **What the bytes ARE, and why they are not random noise.** The
/// question this row poses is how a client decides that a file is
/// parity, and the answers form a ladder: the extension, the packet
/// magic at the head, the packet framing walk, each packet's own MD5
/// seal, and finally whether what the packets say adds up to a set. A
/// decoy of random bytes under a `.par2` name is turned away on the
/// second rung and says nothing about the four above it - a client
/// with no packet reader at all passes that row. So the decoy is built
/// to climb as far as a non-set can:
///
/// 1. A genuine **Main** packet and a genuine **Creator** packet, cut
///    out of a real `par2gen` index over a scratch member. Real bytes,
///    a real recovery-set id, and both MD5 seals correct - so the
///    magic check passes, the framing walk finds two whole packets, and
///    the seal check verifies them.
/// 2. Then a **broken cell**: the magic again, a length that is
///    structurally valid (at least a header, a multiple of four, and
///    inside the file), and a stored MD5 that is junk. The walk has to
///    hash it, reject it on the seal, and resume one byte on rather
///    than stopping at the first thing that is not a packet.
/// 3. Then junk to the profile's declared length.
///
/// What that leaves is a file that is packet-shaped all the way down
/// and is not a set: the Main packet declares a file id, and there is
/// no FileDesc packet to name it, no IFSC to check it and no recovery
/// slice to rebuild anything with. A client can compute the set id and
/// then has nothing whatever to do with it. That is the shape a client
/// must decline on the LAST rung, which is the only rung a `.par2`
/// extension cannot help it with.
///
/// **The set id is a foreign one and that is not P11.** A phantom set
/// (`phantom_covers`) is a complete, self-consistent set describing
/// members the post does not carry, and the requirement there is that
/// the client neither fails nor invents them. This is the opposite
/// half: not a set at all, and never mind whose.
fn create_decoy(profile: &Profile, taken: &[RecoveryFile]) -> Result<RecoveryFile, RecoveryError> {
    let d = profile
        .recovery
        .decoy
        .as_ref()
        .expect("create_decoy is called only when the profile selects one");
    // The schema refuses a collision with a [source] name and with the
    // sidecar; the names the set mints for itself are known only here.
    if taken.iter().any(|f| f.name == d.name) {
        return Err(RecoveryError::DecoyNameCollidesWithASetFile(d.name.clone()));
    }
    let head = decoy_head(profile)?;
    let floor = head.len() as u64 + DECOY_JUNK_FLOOR;
    if d.bytes < floor {
        return Err(RecoveryError::DecoyTooShort {
            name: d.name.clone(),
            bytes: d.bytes,
            floor,
        });
    }
    let mut bytes = vec![0u8; d.bytes as usize];
    Rng::from_seed(profile.layout.seed ^ DECOY_STREAM).fill(&mut bytes);
    bytes[..head.len()].copy_from_slice(&head);
    plant_a_broken_cell(&mut bytes, head.len());
    Ok(RecoveryFile {
        name: d.name.clone(),
        bytes,
        // Neither: a decoy carries no recovery slices, so it is not
        // parity and is not eager-skipped, and it is not an outer set's
        // file. `decoy` is what every stage below reads.
        parity: false,
        outer: false,
        decoy: true,
    })
}

/// The genuine Main and Creator packets, in that order, cut from a real
/// index.
///
/// Built by the same creator the rest of this plane uses, over a
/// scratch member of its own, so the packets are bytes a conforming
/// tool wrote rather than bytes this crate hand-rolled. Hand-rolling
/// them would have been shorter and would have made the row's first
/// three rungs assertions about our own packet writer instead of about
/// a client's packet reader.
fn decoy_head(profile: &Profile) -> Result<Vec<u8>, RecoveryError> {
    let mut member = vec![0u8; DECOY_HEAD_MEMBER_BYTES];
    Rng::from_seed(profile.layout.seed ^ DECOY_HEAD_STREAM).fill(&mut member);
    // 0 % redundancy: an index and nothing else, which is where every
    // critical packet lives anyway.
    let built = set_over_one_file(DECOY_HEAD_MEMBER, &member, 0)?;
    let (_, index) = built
        .into_iter()
        .next()
        .ok_or_else(|| RecoveryError::Creator("the decoy head set has no index".into()))?;
    let found = par2patch::packets(&index);
    let mut head = Vec::new();
    for want in [TYPE_MAIN, TYPE_CREATOR] {
        let (at, len, _) = found
            .iter()
            .find(|(_, _, ty)| *ty == want)
            .copied()
            .ok_or_else(|| {
                RecoveryError::Creator(format!(
                    "the decoy head set carries no {} packet",
                    String::from_utf8_lossy(&want).trim_end_matches('\0')
                ))
            })?;
        head.extend_from_slice(&index[at..at + len]);
    }
    Ok(head)
}

/// Write a packet-shaped cell at `at` that the framing walk must reject
/// on the SEAL rather than on the framing.
///
/// The magic, then a length that reaches to the end of the buffer
/// rounded down to a multiple of four - so it clears every structural
/// test a walker applies - and the stored-MD5 field left as junk, which
/// no body will ever hash to. A length that did NOT fit would be
/// rejected on arithmetic alone and would exercise one rung less.
fn plant_a_broken_cell(buf: &mut [u8], at: usize) {
    buf[at..at + DECOY_MAGIC.len()].copy_from_slice(DECOY_MAGIC);
    let len = ((buf.len() - at) / 4 * 4) as u64;
    buf[at + 8..at + 16].copy_from_slice(&len.to_le_bytes());
    // Bytes 16..32 are the packet checksum and are LEFT as drawn: the
    // seal is what this cell fails, and writing anything deliberate
    // there would only be a second way of saying junk.
}

/// Resolve a `covers` selection to source indices.
fn select(
    sources: &[SourceFile],
    covers: &Covers,
    plane: &'static str,
) -> Result<Vec<usize>, RecoveryError> {
    match covers {
        Covers::All => Ok((0..sources.len()).collect()),
        Covers::First => Ok(vec![0]),
        Covers::Names(names) => select_named(sources, names, plane),
    }
}

fn select_named(
    sources: &[SourceFile],
    names: &[String],
    plane: &'static str,
) -> Result<Vec<usize>, RecoveryError> {
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        // Matched against the RELATIVE path, which is the name the
        // profile writes in [source] and the name the FileDesc will
        // carry. Matching a basename would make `a/x.bin` and `b/x.bin`
        // ambiguous in the one plane that exists to tell them apart.
        let Some(i) = sources.iter().position(|s| &s.rel == n) else {
            return Err(RecoveryError::NoSuchMember {
                name: n.clone(),
                plane,
            });
        };
        if !out.contains(&i) {
            out.push(i);
        }
    }
    Ok(out)
}

/// The members that are DESCRIBED by a set and never posted: P5's
/// 0-byte placeholders, and G5's dedupe copies.
///
/// **Two shapes, one mechanism, and they are not the same requirement.**
/// A P5 placeholder is empty, so materialising it costs nothing and the
/// set's descriptor is the only record it exists at all (the VIDEO_TS
/// `.BUP`). A G5 copy is the full length of a file the post carries
/// exactly one copy of, so the client has to notice that two
/// descriptors describe one set of bytes and write the second file from
/// the first - which is what a poster buys by shipping one copy.
///
/// A 0-byte `[source]` file is a legal posted shape on its own (one
/// lone `=ybegin size=0` article - `crate::assemble` says so), so which
/// of the two shapes a profile means is `zero_byte_member`'s to say.
/// A `same_as` entry has no such ambiguity: posting the copy as well
/// would simply be a post of two identical files, which is not the
/// dedupe shape and needs no key to express.
fn described_but_unposted(
    profile: &Profile,
    sources: &[SourceFile],
    covered: &[usize],
) -> Result<Vec<usize>, RecoveryError> {
    let mut out: Vec<usize> = profile
        .source
        .files
        .iter()
        .enumerate()
        .filter(|(_, f)| !f.same_as.is_empty())
        .map(|(i, _)| i)
        .collect();
    // A dedupe copy nothing describes is a file that exists in no part
    // of the post: not on the wire, and not in a descriptor.
    if let Some(&i) = out.iter().find(|i| !covered.contains(i)) {
        return Err(RecoveryError::DedupeCopyNotCovered(sources[i].rel.clone()));
    }
    if profile.recovery.zero_byte_member {
        let empties: Vec<usize> = sources
            .iter()
            .enumerate()
            .filter(|(_, s)| s.bytes.is_empty())
            .map(|(i, _)| i)
            .collect();
        if empties.is_empty() {
            return Err(RecoveryError::ZeroByteMemberWithout(
                "a [source] file with bytes = 0",
            ));
        }
        // An uncovered placeholder is posted nowhere and described
        // nowhere, so nothing in the layout could ever name it. Refused
        // rather than emitted as a file the client is asked to invent.
        if empties.iter().any(|i| !covered.contains(i)) {
            return Err(RecoveryError::ZeroByteMemberWithout(
                "every 0-byte [source] file to be covered by a set",
            ));
        }
        for i in empties {
            if !out.contains(&i) {
                out.push(i);
            }
        }
    }
    // Everything withheld is a post with no articles at all, which is
    // not a layout: the naming plane has nothing to name and the NZB
    // has nothing to map. Refused here, where the reason is legible,
    // rather than as an index panic two stages later.
    if out.len() == sources.len() {
        return Err(RecoveryError::ZeroByteMemberWithout(
            "at least one [source] file with bytes to post: every member of this profile \
             is described and never posted, so the post would carry no articles at all",
        ));
    }
    out.sort_unstable();
    Ok(out)
}

/// The base name a set's files are built under.
///
/// The stem of the first covered member's basename, which is what a
/// real poster's `par2 create` line produces. Under an opaque layout
/// that stem is already a token, so the base is opaque for free and
/// nothing descriptive leaks back through a file name.
pub(crate) fn base_name(sources: &[SourceFile], members: &[usize]) -> String {
    let base = &sources[members[0]].base;
    let stem = base.rsplit_once('.').map_or(base.as_str(), |(s, _)| s);
    // par2gen refuses a base with a path separator in it, and a stem
    // taken from a basename cannot have one. An empty stem (a file
    // named `.bin`) would though, so it falls back to the whole name.
    if stem.is_empty() {
        base.clone()
    } else {
        stem.to_string()
    }
}

/// Build one set over `members` and read its files back into memory.
///
/// `pub(crate)` for the fault plane, which builds F6's competing set
/// over the same members under a base of its own. The staging rule
/// (par2gen reads members from disk) lives here, and there is exactly
/// one copy of it.
pub(crate) fn create(
    stage: &Stage,
    sources: &[SourceFile],
    members: &[usize],
    base: &str,
    profile: &Profile,
) -> Result<Vec<RecoveryFile>, RecoveryError> {
    let m: Vec<Member> = members
        .iter()
        .map(|&i| Member {
            // The RELATIVE path, which is how a set preserves a tree -
            // and the reason a covered member's expected name becomes
            // that path.
            name: sources[i].rel.clone(),
            path: stage.dir.join(rel_to_path(&sources[i].rel)),
        })
        .collect();
    let spec = Par2Spec {
        redundancy_pct: profile.recovery.redundancy_pct,
        block_size: (profile.recovery.block_bytes != 0).then_some(profile.recovery.block_bytes),
    };
    let names = nzbkit::par2gen::create_into(&stage.dir, &m, base, &spec)
        .map_err(|e| RecoveryError::Creator(e.to_string()))?;
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        let path = stage.dir.join(&n);
        let bytes = std::fs::read(&path)
            .map_err(|e| RecoveryError::Creator(format!("reading back {n}: {e}")))?;
        // Removed as it is read: the next set writes into this same
        // directory and must not describe the first set's files if a
        // future `covers` selection ever globs.
        let _ = std::fs::remove_file(&path);
        // `create_into` documents its own answer: the index first, then
        // any volumes. Read off the name rather than off the position
        // so a second set in the same list cannot be misread, and so a
        // reader of a failing expectation can see WHY a file is parity.
        let parity = n.contains(".vol");
        out.push(RecoveryFile {
            name: n,
            bytes,
            parity,
            outer: false,
            decoy: false,
        });
    }
    Ok(out)
}

/// H4: build one PAR2 set over ONE file that is not a `[source]` entry,
/// and read its files back into memory.
///
/// The container plane's entry point, for a set cut over a NESTING
/// LEVEL's archive and packed into the level above it. It is here
/// rather than in `crate::container` because the staging rule -
/// par2gen reads its members off disk, into a scratch directory that
/// is removed as it is read - lives in this module and has exactly one
/// copy.
///
/// `base` is the archive's own file name, so the set comes out as
/// `<archive>.par2` and `<archive>.vol00+NN.par2`: the spelling
/// par2cmdline gives, and the one a client pairs with the file beside
/// it without being told.
pub(crate) fn set_over_one_file(
    name: &str,
    bytes: &[u8],
    redundancy_pct: u32,
) -> Result<Vec<(String, Vec<u8>)>, RecoveryError> {
    let stage = Stage::new()?;
    stage.write(name, bytes)?;
    let members = vec![Member {
        name: name.to_string(),
        path: stage.dir.join(rel_to_path(name)),
    }];
    let spec = Par2Spec {
        redundancy_pct,
        block_size: None,
    };
    let names = nzbkit::par2gen::create_into(&stage.dir, &members, name, &spec)
        .map_err(|e| RecoveryError::Creator(e.to_string()))?;
    let mut out = Vec::with_capacity(names.len());
    for n in names {
        let path = stage.dir.join(&n);
        let file = std::fs::read(&path)
            .map_err(|e| RecoveryError::Creator(format!("reading back {n}: {e}")))?;
        let _ = std::fs::remove_file(&path);
        out.push((n, file));
    }
    Ok(out)
}

/// P6: patch each `hostile_names` entry over the FileDesc of the
/// covered member at the same position, in every file of the set.
///
/// Returns the (source index, patched name) pairs so the expectation
/// can be derived from them.
fn apply_hostile_names(
    profile: &Profile,
    sources: &[SourceFile],
    members: &[usize],
    files: &mut [RecoveryFile],
) -> Result<Vec<(usize, String)>, RecoveryError> {
    let hostile = &profile.recovery.hostile_names;
    if hostile.is_empty() {
        return Ok(Vec::new());
    }
    if hostile.len() > members.len() {
        return Err(RecoveryError::TooManyHostileNames {
            given: hostile.len(),
            members: members.len(),
        });
    }
    let mut out = Vec::with_capacity(hostile.len());
    for (pos, name) in hostile.iter().enumerate() {
        check_expressible(name, sources, hostile)?;
        let idx = members[pos];
        for f in files.iter_mut() {
            // A member may be absent from a file only if a future
            // selection stops repeating critical packets; today every
            // file of every set carries every FileDesc, so a miss is a
            // real failure and `rename_filedesc` reports it.
            par2patch::rename_filedesc(&mut f.bytes, &sources[idx].rel, name)?;
        }
        out.push((idx, name.clone()));
    }
    Ok(out)
}

/// Refuse a hostile name whose correct end state this generator cannot
/// state, with the reason.
///
/// The oracle grades a run by the EXACT output tree, so a name whose
/// right answer is "whatever the sanitizer makes of it" cannot be a
/// catalog row without writing the client's answer into the
/// requirement - the one thing `crate::naming`'s header forbids. What
/// is left is the shape the chip's own work list names: a PATH-SHAPED
/// name, a legal relative path that puts the member somewhere else in
/// the tree. That is a requirement a reader can check by eye.
fn check_expressible(
    name: &str,
    sources: &[SourceFile],
    hostile: &[String],
) -> Result<(), RecoveryError> {
    let bad = |why| {
        Err(RecoveryError::HostileNameNotExpressible {
            name: name.to_string(),
            why,
        })
    };
    if name.is_empty()
        || name.starts_with('/')
        || name.ends_with('/')
        || name
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
    {
        return bad(
            "is not a relative path a client is required to keep, so its correct end state \
             is the sanitizer's answer rather than a requirement this catalog can state",
        );
    }
    if name
        .chars()
        .any(|c| c.is_control() || c == '\\' || c == ':')
    {
        return bad(
            "carries a byte whose containment answer differs by platform, so one expected \
             tree could not be right on all three",
        );
    }
    if name.split('/').any(component_is_reserved_or_padded) {
        return bad(
            "carries a component the destination filesystem will not store verbatim (a \
             reserved DOS device name, or a trailing dot or space), so its landed name is \
             the sanitizer's answer rather than a requirement this catalog can state",
        );
    }
    if hostile.iter().filter(|h| h.as_str() == name).count() > 1 {
        return bad(
            "appears twice, and two members under one name have no output tree this oracle \
             can grade - which of the two lands under the name, and what the other is \
             called, is the client's answer and not a requirement",
        );
    }
    if sources.iter().any(|s| s.rel == name) {
        return bad("is already a [source] file's name, which is the same collision");
    }
    Ok(())
}

/// A path component no filesystem in the fleet stores as written: a
/// reserved DOS device name, or one padded with a trailing dot or
/// space.
///
/// **Why these belong with the control bytes above and not with the
/// path-shaped names this plane exists for.** The client sanitizes all
/// three, and the names it produces (`_CON.mkv`, `_NUL`, `trail.txt`)
/// are a security answer rather than a spelling: they are pinned, as
/// exact strings, by `hostile_filedesc_names_land_sanitized` in
/// `crates/nzbfast/tests/e2e_norar/mod.rs`. A catalog row could only
/// agree with that answer by writing it down a second time, and the
/// generator deriving the client's own sanitizer is the one thing
/// `crate::naming`'s header forbids - it would turn today's spelling
/// into a requirement and go red the day the sanitizer improved.
///
/// **This arm was missing until 3 Sep 2026**, and the guard above it
/// read as though it covered these: it refuses "a byte whose
/// containment answer differs by platform", which is what a reserved
/// device name IS, but it tested only control bytes, `\` and `:`. A
/// profile selecting `hostile_names = ["CON.mkv"]` was accepted, and
/// the expectation derived from it asked for `CON.mkv` on disk - a red
/// test whose message blamed the client for the one answer that was
/// right. Found by porting `bench/capability-corpus`'s n23 leg; the
/// round is `research/POSTFAST-VS-CAPABILITY-CORPUS-2026-09-03.md`.
fn component_is_reserved_or_padded(c: &str) -> bool {
    if c.ends_with('.') || c.ends_with(' ') {
        return true;
    }
    // The device name is the stem, so `CON.mkv` is reserved and
    // `CONTACT.mkv` is not.
    let stem = c.split('.').next().unwrap_or(c).to_ascii_uppercase();
    matches!(stem.as_str(), "CON" | "PRN" | "AUX" | "NUL")
        || matches!(stem.split_at_checked(3), Some(("COM" | "LPT", n))
            if matches!(n, "1" | "2" | "3" | "4" | "5" | "6" | "7" | "8" | "9"))
}

/// Convert a forward-slashed relative name to a platform path.
/// `[source]` names are validated by `crate::assemble`, so every
/// component here is a plain one.
fn rel_to_path(rel: &str) -> PathBuf {
    rel.split('/').collect()
}

/// A scratch directory that deletes itself, because `par2gen` reads its
/// members from disk and this crate is otherwise pure.
///
/// Not `tempfile`: the crate has no dev-only build here and one
/// dependency for eight lines is not a trade worth making. The name
/// carries the process id and a per-process counter, so two profiles
/// generating at once in one nextest process cannot collide, and the
/// LAYOUT does not depend on it - a PAR2 set records names, lengths and
/// hashes, never a source directory.
pub(crate) struct Stage {
    dir: PathBuf,
}

static STAGE_SEQ: std::sync::atomic::AtomicU64 = std::sync::atomic::AtomicU64::new(0);

impl Stage {
    pub(crate) fn new() -> Result<Self, RecoveryError> {
        let n = STAGE_SEQ.fetch_add(1, std::sync::atomic::Ordering::Relaxed);
        let dir = std::env::temp_dir().join(format!("postfast-par2-{}-{n}", std::process::id()));
        // A leftover from a crashed run under the same pid would be
        // described by the creator as if it were payload.
        let _ = std::fs::remove_dir_all(&dir);
        std::fs::create_dir_all(&dir)
            .map_err(|e| RecoveryError::Creator(format!("{}: {e}", dir.display())))?;
        Ok(Self { dir })
    }

    pub(crate) fn write(&self, rel: &str, bytes: &[u8]) -> Result<(), RecoveryError> {
        let path = self.dir.join(rel_to_path(rel));
        if let Some(p) = path.parent() {
            std::fs::create_dir_all(p)
                .map_err(|e| RecoveryError::Creator(format!("{}: {e}", p.display())))?;
        }
        std::fs::write(&path, bytes)
            .map_err(|e| RecoveryError::Creator(format!("{}: {e}", path.display())))
    }
}

impl Drop for Stage {
    fn drop(&mut self) {
        // Best effort: a failure here would mask the real error on the
        // way out of a failing generate, and the directory is under the
        // system scratch root either way.
        let _ = std::fs::remove_dir_all(&self.dir);
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::profile::Profile;
    // Placed first so a reader of this module's tests meets G7 where
    // the plane itself sits, at the end of `build`.

    const TWO: &str = "{ name = \"movie.mkv\", bytes = 32768 }, \
                       { name = \"sample/s.mkv\", bytes = 8192 }";

    fn profile(files: &str, extra: &str) -> Profile {
        Profile::parse(&format!(
            "[layout]\nname = \"r\"\nseed = 4\n\n[source]\nfiles = [{files}]\n\n{extra}"
        ))
        .expect("test profile parses")
    }

    fn built(files: &str, extra: &str) -> (Vec<SourceFile>, Recovered) {
        let p = profile(files, extra);
        let mut rng = crate::Rng::for_profile(&p);
        let s = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
        let r = build(&p, &s).unwrap_or_else(|e| panic!("{e}"));
        (s, r)
    }

    fn refusal(files: &str, extra: &str) -> RecoveryError {
        let p = profile(files, extra);
        let mut rng = crate::Rng::for_profile(&p);
        let s = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
        build(&p, &s).expect_err("must be refused")
    }

    fn names_of(r: &Recovered) -> Vec<&str> {
        r.files.iter().map(|f| f.name.as_str()).collect()
    }

    /// P0 is the empty answer, so no caller needs a special case.
    #[test]
    fn no_recovery_set_is_the_empty_answer() {
        let (_, r) = built(TWO, "");
        assert_eq!(r, Recovered::default());
    }

    /// P1: an index and its volumes, under a base taken from the first
    /// covered member, with the parity half marked as parity.
    #[test]
    fn a_set_is_an_index_and_its_volumes() {
        let (_, r) = built(TWO, "[recovery]\nkind = \"par2\"\nredundancy_pct = 20\n");
        assert_eq!(r.files[0].name, "movie.par2");
        assert!(!r.files[0].parity, "the index carries no recovery slices");
        assert!(r.files.len() > 1, "20 % redundancy emits volumes");
        assert!(
            r.files[1..]
                .iter()
                .all(|f| f.parity && f.name.contains(".vol")),
            "{:?}",
            names_of(&r)
        );
    }

    /// P4 at 0 %: an index-only set. One file, no parity, and it still
    /// names every member - which is the whole of what a manifest-only
    /// set is for.
    #[test]
    fn an_index_only_set_is_one_file_that_still_names_its_members() {
        let (s, r) = built(TWO, "[recovery]\nkind = \"par2\"\n");
        assert_eq!(names_of(&r), vec!["movie.par2"]);
        assert!(!r.files[0].parity);
        assert_eq!(r.covered, vec![0, 1]);
        assert_eq!(r.described_name(&s, 1), "sample/s.mkv");
    }

    /// The described name is the RELATIVE path, which is where N8's
    /// tree materialisation comes from: nothing else in a no-container
    /// post carries a directory at all.
    #[test]
    fn a_covered_member_is_described_under_its_relative_path() {
        let (s, r) = built(TWO, "[recovery]\nkind = \"par2\"\n");
        assert_eq!(r.described_name(&s, 0), "movie.mkv");
        assert_eq!(r.described_name(&s, 1), "sample/s.mkv");
    }

    /// P8: `covers` selects, and an uncovered member is not covered -
    /// which is what lets one post hold a named half and a nameless one.
    #[test]
    fn covers_selects_the_members_a_set_protects() {
        let (_, r) = built(TWO, "[recovery]\nkind = \"par2\"\ncovers = \"first\"\n");
        assert_eq!(r.covered, vec![0]);
        assert!(r.covers(0) && !r.covers(1));
        let (_, byname) = built(
            TWO,
            "[recovery]\nkind = \"par2\"\ncovers = [\"sample/s.mkv\"]\n",
        );
        assert_eq!(byname.covered, vec![1]);
        // ...and the base follows the covered member, so a partial set
        // is not named after a file it does not protect.
        assert_eq!(byname.files[0].name, "s.par2");
    }

    /// `covers` is matched against the RELATIVE path. Matching a
    /// basename would make the one plane that tells `a/x.bin` from
    /// `b/x.bin` apart unable to name either.
    #[test]
    fn covers_names_the_relative_path_and_refuses_anything_else() {
        match refusal(TWO, "[recovery]\nkind = \"par2\"\ncovers = [\"s.mkv\"]\n") {
            RecoveryError::NoSuchMember { name, plane } => {
                assert_eq!(name, "s.mkv");
                assert_eq!(plane, "covers");
            }
            other => panic!("expected NoSuchMember, got {other}"),
        }
    }

    /// P9: two independent sets in one post, each under a base of its
    /// own, and neither describing the other's members.
    #[test]
    fn two_independent_sets_carry_disjoint_members() {
        let (_, r) = built(
            TWO,
            "[recovery]\nkind = \"par2\"\ncovers = [\"movie.mkv\"]\n\
             second_covers = [\"sample/s.mkv\"]\n",
        );
        assert_eq!(names_of(&r), vec!["movie.par2", "s-b.par2"]);
        assert_eq!(r.covered, vec![0, 1]);
        // Each set names ONE member, or they are one set in two files.
        for (f, want) in r.files.iter().zip(["movie.mkv", "sample/s.mkv"]) {
            let set = nzbkit::par2::Par2Set::parse(&[&f.bytes]).expect("the set parses");
            let named: Vec<&str> = set.files.iter().map(|x| x.name.as_str()).collect();
            assert_eq!(named, vec![want], "{}", f.name);
        }
    }

    /// ...and a member in both is refused, because it would make them
    /// one set wearing two names.
    #[test]
    fn two_sets_that_overlap_are_refused() {
        assert_eq!(
            refusal(
                TWO,
                "[recovery]\nkind = \"par2\"\nsecond_covers = [\"movie.mkv\"]\n"
            ),
            RecoveryError::SetsOverlap("movie.mkv".into())
        );
    }

    // -----------------------------------------------------------------
    // G7 / P11: the foreign set
    // -----------------------------------------------------------------

    /// A phantom adds a whole SET and adds nothing to the payload, and
    /// the second half is the one the row rests on: a stage that leaked
    /// the phantom's bytes into the posted files would be answering the
    /// question this plane exists to ask.
    #[test]
    fn a_phantom_adds_a_second_set_and_no_payload() {
        const PH: &str = "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
                          phantom_covers = [{ name = \"Ghost.bin\", bytes = 40000 }]\n";
        let (sources, plain) = built(TWO, "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n");
        let (with_ph, r) = built(TWO, PH);
        assert_eq!(
            sources, with_ph,
            "the payload is untouched by a foreign set"
        );
        assert_eq!(
            r.covered, plain.covered,
            "and so is the real set's member list"
        );
        let names: Vec<&str> = r.files.iter().map(|f| f.name.as_str()).collect();
        assert!(
            names.iter().any(|n| n.starts_with("Ghost-foreign")),
            "the foreign set is emitted under a base of its own: {names:?}"
        );
        // The phantom's own bytes exist only inside `create_phantom_set`
        // and in the recomputation the conformance guard makes, so no
        // emitted file may contain a run of them.
        let ghost = &phantom_members(&profile(TWO, PH)).expect("phantom members")[0].bytes;
        let probe = &ghost[..64];
        for f in &r.files {
            assert!(
                !f.bytes.windows(probe.len()).any(|w| w == probe),
                "{} carries the phantom's payload bytes",
                f.name
            );
        }
    }

    /// A phantom that names a posted file is not a phantom, and a
    /// 0-byte one is P5 wearing this plane's name. Both are refused by
    /// the schema, which is where a reader looks for them.
    #[test]
    fn a_phantom_that_is_not_one_is_refused_by_the_schema() {
        use crate::profile::{Contradiction, ProfileError};
        let parse = |ph: &str| {
            Profile::parse(&format!(
                "[layout]\nname = \"r\"\nseed = 4\n\n[source]\nfiles = [{TWO}]\n\n\
                 [recovery]\nkind = \"par2\"\nredundancy_pct = 10\nphantom_covers = [{ph}]\n"
            ))
        };
        assert!(matches!(
            parse("{ name = \"movie.mkv\", bytes = 40000 }"),
            Err(ProfileError::Invalid(
                Contradiction::PhantomNamesAPostedFile(_)
            ))
        ));
        assert!(matches!(
            parse("{ name = \"Ghost.bin\", bytes = 0 }"),
            Err(ProfileError::Invalid(Contradiction::PhantomWithoutBytes(_)))
        ));
    }

    // -----------------------------------------------------------------
    // P10: the `.par2`-named decoy.
    // -----------------------------------------------------------------

    const DECOY: &str = "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
                         decoy = { name = \"extras.par2\", bytes = 3072 }\n";

    fn only_decoy(r: &Recovered) -> &RecoveryFile {
        let mut it = r.files.iter().filter(|f| f.decoy);
        let f = it.next().expect("the profile selects a decoy");
        assert!(it.next().is_none(), "one decoy, not several");
        f
    }

    /// The decoy is emitted under the name the profile writes, is
    /// neither parity nor an outer set's file, and is the length asked
    /// for.
    #[test]
    fn a_par2_named_decoy_is_emitted_under_its_own_name() {
        let (_, r) = built(TWO, DECOY);
        let d = only_decoy(&r);
        assert_eq!(d.name, "extras.par2");
        assert_eq!(d.bytes.len(), 3072);
        assert!(!d.parity, "a decoy carries no recovery slices");
        assert!(!d.outer);
        // And it is the LAST file, after every real set file: a reader
        // of a failing expectation looks for the real set first, and
        // `apply_hostile_names` must never have walked it.
        assert!(r.files.last().expect("files").decoy);
    }

    /// The head is two GENUINE packets - a client's framing walk finds
    /// them, its seal check verifies them - and what follows is
    /// packet-shaped and not sealed.
    ///
    /// The whole value of the row is in this assertion. A decoy of
    /// random bytes would fail a client at the magic check and would
    /// say nothing about the four rungs above it; this one has to be
    /// declined by what the packets MEAN.
    #[test]
    fn the_decoy_is_two_sealed_packets_and_then_stops_being_a_set() {
        let (_, r) = built(TWO, DECOY);
        let d = only_decoy(&r);
        assert_eq!(
            &d.bytes[..8],
            DECOY_MAGIC,
            "the magic is at offset 0, so an 8-byte sniff nominates it"
        );
        let found = par2patch::packets(&d.bytes);
        assert_eq!(
            found.len(),
            3,
            "two head packets and the broken cell: {:?}",
            found
                .iter()
                .map(|(a, l, t)| (*a, *l, String::from_utf8_lossy(t).into_owned()))
                .collect::<Vec<_>>()
        );
        assert_eq!(found[0].2, TYPE_MAIN);
        assert_eq!(found[1].2, TYPE_CREATOR);
        for (at, len, _) in &found[..2] {
            assert!(
                par2patch::is_sealed(&d.bytes, *at, *len),
                "a head packet at {at} is not sealed, so a client would drop it as \
                 damaged and the row would be testing packet rejection instead"
            );
        }
        let (at, len, _) = found[2];
        assert!(
            !par2patch::is_sealed(&d.bytes, at, len),
            "the third cell is framing-valid on purpose and must fail on its SEAL, \
             which is the rung below the framing walk"
        );
        // ...and it is not a set: no packet names a member, so nothing
        // can be verified against it or rebuilt from it.
        for (at, len, ty) in &found {
            assert_ne!(
                ty, b"PAR 2.0\0FileDesc",
                "a FileDesc packet at {at} (len {len}) would make this a set that \
                 describes something, which is P11's shape and not P10's"
            );
        }
    }

    /// One profile, one seed, the same decoy bytes - and a different
    /// seed a different decoy, or the test above would also pass over a
    /// generator that emitted a constant.
    #[test]
    fn the_decoy_is_deterministic_and_moves_with_the_seed() {
        let a = built(TWO, DECOY).1;
        let b = built(TWO, DECOY).1;
        assert_eq!(only_decoy(&a).bytes, only_decoy(&b).bytes);
        let p = profile(TWO, DECOY);
        let mut moved = p.clone();
        moved.layout.seed = p.layout.seed + 1;
        let mut rng = crate::Rng::for_profile(&moved);
        let sources = crate::assemble::sources(&moved, &mut rng).expect("sources assemble");
        let c = build(&moved, &sources).expect("builds");
        assert_ne!(only_decoy(&a).bytes, only_decoy(&c).bytes);
    }

    /// A decoy is expressible with NO recovery set beside it, which is
    /// the purest form of the row: the post's only self-announced
    /// parity is the thing that is not parity.
    #[test]
    fn a_decoy_needs_no_set_of_its_own() {
        let (_, r) = built(
            TWO,
            "[recovery]\ndecoy = { name = \"extras.par2\", bytes = 3072 }\n",
        );
        assert_eq!(r.files.len(), 1);
        assert!(r.files[0].decoy);
        assert!(r.covered.is_empty(), "no set covers anything here");
    }

    /// A decoy shorter than the genuine head it carries is refused with
    /// both numbers, because the head's length is a fact about the
    /// creator rather than one the schema could state.
    #[test]
    fn a_decoy_shorter_than_its_head_is_refused() {
        let e = refusal(
            TWO,
            "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
             decoy = { name = \"extras.par2\", bytes = 64 }\n",
        );
        let RecoveryError::DecoyTooShort { bytes, floor, .. } = &e else {
            panic!("expected DecoyTooShort, got {e}");
        };
        assert_eq!(*bytes, 64);
        assert!(*floor > 64, "the floor is the head plus room for junk");
        assert!(e.to_string().contains("64"));
    }

    /// A decoy under a name the set itself is built under is refused
    /// where those names are known, which is here and not the schema.
    #[test]
    fn a_decoy_named_after_a_set_file_is_refused() {
        let e = refusal(
            TWO,
            "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
             decoy = { name = \"movie.par2\", bytes = 3072 }\n",
        );
        assert!(
            matches!(e, RecoveryError::DecoyNameCollidesWithASetFile(ref n) if n == "movie.par2"),
            "expected the set-file collision, got {e}"
        );
    }

    /// A name that is not `.par2` poses nothing, and one the post
    /// already carries has no output tree. Both are refused by the
    /// schema, which is where a reader looks for them.
    #[test]
    fn a_decoy_that_is_not_one_is_refused_by_the_schema() {
        use crate::profile::{Contradiction, ProfileError};
        let parse = |d: &str| {
            Profile::parse(&format!(
                "[layout]\nname = \"r\"\nseed = 4\n\n[source]\nfiles = [{TWO}]\n\n\
                 [recovery]\nkind = \"par2\"\nredundancy_pct = 10\ndecoy = {d}\n"
            ))
        };
        assert!(matches!(
            parse("{ name = \"extras.bin\", bytes = 3072 }"),
            Err(ProfileError::Invalid(Contradiction::DecoyIsNotPar2Named(_)))
        ));
        assert!(matches!(
            parse("{ name = \"movie.mkv\", bytes = 3072 }"),
            Err(ProfileError::Invalid(Contradiction::DecoyIsNotPar2Named(_)))
        ));
        // A `.par2` name the post already carries, which needs a source
        // file spelled that way to reach the collision arm at all.
        assert!(matches!(
            Profile::parse(
                "[layout]\nname = \"r\"\nseed = 4\n\n[source]\n\
                 files = [{ name = \"extras.par2\", bytes = 4096 }]\n\n\
                 [recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
                 decoy = { name = \"extras.par2\", bytes = 3072 }\n"
            ),
            Err(ProfileError::Invalid(Contradiction::DecoyNameCollides(_)))
        ));
        // `.PAR2` is the same claim: a client's own extension test is
        // case-insensitive, so the schema's must be too.
        assert!(parse("{ name = \"extras.PAR2\", bytes = 3072 }").is_ok());
    }

    /// G5: a dedupe copy is a member the set describes and the wire
    /// never carries - one copy of the bytes, two descriptors.
    #[test]
    fn a_dedupe_copy_is_described_and_not_posted() {
        const TWIN: &str = "{ name = \"one.bin\", bytes = 32768 }, \
                            { name = \"two.bin\", bytes = 32768, same_as = \"one.bin\" }";
        let (sources, r) = built(TWIN, "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n");
        assert_eq!(r.covered, vec![0, 1], "the set describes both");
        assert_eq!(r.unposted, vec![1], "and the wire carries only the first");
        assert_eq!(
            sources[0].bytes, sources[1].bytes,
            "over one copy of the bytes"
        );
    }

    /// ...and a copy no set covers exists in no part of the layout at
    /// all, so it is refused rather than emitted as a file the client
    /// is asked to invent.
    #[test]
    fn a_dedupe_copy_no_set_covers_is_refused() {
        assert_eq!(
            refusal(
                "{ name = \"one.bin\", bytes = 32768 }, \
                 { name = \"two.bin\", bytes = 32768, same_as = \"one.bin\" }",
                "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\ncovers = [\"one.bin\"]\n"
            ),
            RecoveryError::DedupeCopyNotCovered("two.bin".into())
        );
    }

    // -----------------------------------------------------------------
    // G6 / P13: the chain
    // -----------------------------------------------------------------

    /// The outer set's members are the inner set's FILES, and the outer
    /// set is the only thing in the post with a name of its own.
    #[test]
    fn an_outer_set_covers_the_inner_sets_files_and_keeps_its_name() {
        const CHAIN: &str = "[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
                             names = \"opaque\"\nouter = true\n";
        let (_, r) = built(TWO, CHAIN);
        let (inner, outer): (Vec<_>, Vec<_>) = r.files.iter().partition(|f| !f.outer);
        assert!(!inner.is_empty() && !outer.is_empty(), "both sets exist");
        // Every outer file's base is the inner base plus the suffix, so
        // the two sets can never write over each other.
        for f in &outer {
            assert!(f.name.contains(OUTER_SUFFIX), "{}", f.name);
        }
        // And the outer set really describes the inner FILES: each
        // inner file's name appears in the outer index's packets.
        let index = outer
            .iter()
            .find(|f| !f.parity)
            .expect("the outer set has an index");
        for f in &inner {
            assert!(
                index
                    .bytes
                    .windows(f.name.len())
                    .any(|w| w == f.name.as_bytes()),
                "the outer index does not name {}",
                f.name
            );
        }
    }

    /// A chain over an announced set has nothing in it, so it is
    /// refused by the schema rather than emitted as a row a client
    /// passes without chasing anything.
    #[test]
    fn an_outer_set_over_an_announced_set_is_refused() {
        use crate::profile::{Contradiction, ProfileError};
        for names in ["descriptive", "filedesc-only"] {
            let text = format!(
                "[layout]\nname = \"r\"\nseed = 4\n\n[source]\nfiles = [{TWO}]\n\n\
                 [naming]\nwire = \"opaque\"\n\n[recovery]\nkind = \"par2\"\n\
                 redundancy_pct = 10\nnames = \"{names}\"\nouter = true\n"
            );
            assert!(
                matches!(
                    Profile::parse(&text),
                    Err(ProfileError::Invalid(
                        Contradiction::OuterSetOverAnAnnouncedSet
                    ))
                ),
                "names = {names:?} must be refused"
            );
        }
    }

    /// P5: a 0-byte source becomes a member that is DESCRIBED and never
    /// posted, so the client has a FileDesc packet and nothing else.
    #[test]
    fn a_zero_byte_member_is_described_and_never_posted() {
        let (s, r) = built(
            "{ name = \"Feature.mkv\", bytes = 4096 }, { name = \"VIDEO_TS.bup\", bytes = 0 }",
            "[recovery]\nkind = \"par2\"\nzero_byte_member = true\n",
        );
        assert_eq!(r.unposted, vec![1]);
        assert!(!r.is_unposted(0));
        assert_eq!(r.described_name(&s, 1), "VIDEO_TS.bup");
        // The creator wrote it correctly: length 0 and no slices, which
        // is the shape par2cmdline cannot emit at all.
        let set = nzbkit::par2::Par2Set::parse(&[&r.files[0].bytes]).expect("the set parses");
        let empty = set
            .files
            .iter()
            .find(|f| f.name == "VIDEO_TS.bup")
            .expect("the placeholder is described");
        assert_eq!(empty.length, 0);
    }

    /// Without the flag, a 0-byte source is the OTHER real shape: one
    /// lone `=ybegin size=0` article. Two shapes, one selection.
    #[test]
    fn without_the_flag_a_zero_byte_source_is_posted() {
        let (_, r) = built(
            "{ name = \"Feature.mkv\", bytes = 4096 }, { name = \"VIDEO_TS.bup\", bytes = 0 }",
            "[recovery]\nkind = \"par2\"\n",
        );
        assert!(r.unposted.is_empty());
    }

    /// The flag with nothing to be the placeholder is a refusal that
    /// says what a profile is missing, not a set with no empty member.
    #[test]
    fn a_zero_byte_selection_with_no_empty_source_is_refused() {
        let e = refusal(
            TWO,
            "[recovery]\nkind = \"par2\"\nzero_byte_member = true\n",
        );
        assert!(
            matches!(e, RecoveryError::ZeroByteMemberWithout(_)),
            "got {e}"
        );
        assert!(e.to_string().contains("bytes = 0"), "{e}");
    }

    /// ...and a profile that withholds EVERYTHING is refused where the
    /// reason is legible, rather than as an index panic two stages on.
    #[test]
    fn a_post_with_nothing_left_to_post_is_refused() {
        let e = refusal(
            "{ name = \"a.bup\", bytes = 0 }, { name = \"b.bup\", bytes = 0 }",
            "[recovery]\nkind = \"par2\"\nzero_byte_member = true\n",
        );
        assert!(e.to_string().contains("no articles at all"), "{e}");
    }

    /// P3 says the set is the ONLY place a real name exists, so a wire
    /// that still carries one is a contradiction and not a shortcut.
    #[test]
    fn filedesc_only_beside_a_descriptive_wire_is_refused() {
        assert_eq!(
            refusal(
                TWO,
                "[recovery]\nkind = \"par2\"\nnames = \"filedesc-only\"\n"
            ),
            RecoveryError::FiledescOnlyNeedsAnOpaqueWire
        );
    }

    /// The creator always writes a COMPLETE set, whatever `[recovery]
    /// index` says: removing or unsealing the index is the fault
    /// plane's edit over the finished bytes (`crate::fault`), so this
    /// stage never grows a "build it wrong" mode. Asserted here because
    /// the two selections used to be refused at this door, and a reader
    /// following that history needs the door they moved to.
    #[test]
    fn a_set_is_built_whole_whatever_the_index_selection_says() {
        for sel in ["present", "damaged", "absent"] {
            let (_, r) = built(
                TWO,
                &format!("[recovery]\nkind = \"par2\"\nredundancy_pct = 10\nindex = \"{sel}\"\n"),
            );
            assert!(
                r.files.iter().any(|f| !f.parity),
                "index = {sel:?} built a set with no index for the fault plane to damage"
            );
            assert!(r.files.iter().any(|f| f.parity), "no volumes at 10 %");
        }
    }

    /// P6: a path-shaped hostile name is patched into every file of the
    /// set, and it becomes what the client must end with, because it is
    /// what the layout now carries.
    #[test]
    fn a_path_shaped_hostile_name_is_patched_and_expected() {
        // The source name is LONGER than the patched one on purpose: a
        // FileDesc name region is the creator's own padded name, so a
        // patch can only ever shorten. That is the one thing a profile
        // author has to plan for, and the refusal below says so.
        let (s, r) = built(
            "{ name = \"a-name-with-room-in-it.mkv\", bytes = 32768 }, \
             { name = \"sample/s.mkv\", bytes = 8192 }",
            "[recovery]\nkind = \"par2\"\nredundancy_pct = 20\n\
             hostile_names = [\"elsewhere/moved.mkv\"]\n",
        );
        assert_eq!(r.described_name(&s, 0), "elsewhere/moved.mkv");
        // The second member is untouched: entries are positional.
        assert_eq!(r.described_name(&s, 1), "sample/s.mkv");
        // EVERY file of the set, not only the index - the critical
        // packets repeat in every volume and a half-patched set would
        // name the member two different things.
        for f in &r.files {
            let set = nzbkit::par2::Par2Set::parse(&[&f.bytes]).expect("parses");
            assert!(
                set.files.iter().any(|x| x.name == "elsewhere/moved.mkv"),
                "{} was not patched",
                f.name
            );
        }
    }

    /// A hostile name whose right answer is the sanitizer's is refused,
    /// with the reason. The oracle grades an exact output tree, so a
    /// row it cannot state is a row that would be graded against
    /// whatever the client happened to do.
    #[test]
    fn a_hostile_name_with_no_stateable_end_state_is_refused() {
        for name in ["../evil.bin", "/abs.bin", "a\\\\b.bin", "x:stream"] {
            let e = refusal(
                TWO,
                &format!("[recovery]\nkind = \"par2\"\nhostile_names = [\"{name}\"]\n"),
            );
            assert!(
                matches!(e, RecoveryError::HostileNameNotExpressible { .. }),
                "{name} gave {e}"
            );
        }
        // A duplicate is the same refusal for the same reason: which of
        // two members lands under the name is the client's answer.
        let e = refusal(
            TWO,
            "[recovery]\nkind = \"par2\"\nhostile_names = [\"same.bin\", \"same.bin\"]\n",
        );
        assert!(
            matches!(e, RecoveryError::HostileNameNotExpressible { .. }),
            "{e}"
        );
    }

    /// More entries than covered members is a profile that thinks it is
    /// renaming something it is not.
    /// A reserved DOS device name and a dot-space tail are refused for
    /// the same reason a control byte is: the client sanitizes them and
    /// the landed name is its answer, not a requirement. `CONTACT.mkv`
    /// is the control - it only LOOKS like one, and a rule that matched
    /// on a prefix would take it too.
    #[test]
    fn a_reserved_or_padded_hostile_name_is_refused() {
        for name in [
            "CON.mkv",
            "NUL",
            "aux",
            "COM3.bin",
            "trail.txt. ",
            "dir/PRN/x.bin",
        ] {
            assert!(
                matches!(
                    refusal(
                        TWO,
                        &format!("[recovery]\nkind = \"par2\"\nhostile_names = [\"{name}\"]\n"),
                    ),
                    RecoveryError::HostileNameNotExpressible { .. }
                ),
                "{name:?} was accepted, and the expectation derived from it is a name \
                 the client never lands"
            );
        }
        // The control: it only LOOKS reserved, and a rule matching on a
        // prefix rather than on the stem would take it too.
        let (_, r) = built(
            TWO,
            "[recovery]\nkind = \"par2\"\nhostile_names = [\"CONTACT.mkv\"]\n",
        );
        assert!(
            !r.files.is_empty(),
            "an ordinary relative name stays selectable"
        );
    }

    #[test]
    fn more_hostile_names_than_members_is_refused() {
        assert_eq!(
            refusal(
                TWO,
                "[recovery]\nkind = \"par2\"\ncovers = \"first\"\n\
                 hostile_names = [\"a.bin\", \"b.bin\"]\n",
            ),
            RecoveryError::TooManyHostileNames {
                given: 2,
                members: 1
            }
        );
    }

    /// A patched name may only ever be SHORTER than the one the
    /// creator wrote, because the region is that name's padded length
    /// and a patch may not resize a packet. Refused with both numbers
    /// rather than silently truncated.
    #[test]
    fn a_hostile_name_longer_than_its_region_is_refused() {
        let e = refusal(
            TWO,
            "[recovery]\nkind = \"par2\"\n\
             hostile_names = [\"a-very-much-longer-replacement-name.mkv\"]\n",
        );
        assert!(matches!(e, RecoveryError::Patch(_)), "{e}");
        assert!(e.to_string().contains("may not resize a packet"), "{e}");
    }

    /// The determinism contract, at this stage: a set is a function of
    /// the payload and the profile, and the scratch directory it was
    /// staged through leaves no trace in it.
    #[test]
    fn a_set_is_byte_identical_between_runs() {
        let a = built(TWO, "[recovery]\nkind = \"par2\"\nredundancy_pct = 20\n").1;
        let b = built(TWO, "[recovery]\nkind = \"par2\"\nredundancy_pct = 20\n").1;
        assert_eq!(a, b);
    }

    /// The staging directory is gone when the set is: a generator that
    /// left one behind per profile would fill a CI runner's scratch
    /// over a nextest sweep.
    #[test]
    fn the_staging_directory_does_not_outlive_the_build() {
        let dir = {
            let stage = Stage::new().expect("a scratch directory");
            stage.write("a/b.bin", b"x").expect("writes");
            stage.dir.clone()
        };
        assert!(!dir.exists(), "{} outlived its Stage", dir.display());
    }

    // -----------------------------------------------------------------
    // The conformance arm: par2cmdline reads what this generator writes.
    // -----------------------------------------------------------------

    /// The reference binary: whatever `NZBFAST_PAR2_BIN` names, else
    /// `par2` off PATH.
    ///
    /// AN ENV VAR RATHER THAN A PATH PREPEND, and the reason is what
    /// the distro package is. `apt-get install par2` on ubuntu is
    /// **0.8.1**, which cannot verify ANY set describing a 0-byte
    /// member (memory topic `nzbfast-ci-par2-version-skew`, upstream
    /// #128, fixed in 1.0.0) - and this catalog carries three such
    /// rows. So the job that runs this guard hands it a v1.3.0 built
    /// from tag, and an explicit path is what makes that binary WIN:
    /// a PATH prepend is silently defeated by any later step that
    /// installs the distro package, and it leaves the log unable to
    /// say which par2 answered. Same spelling as `parfast`'s
    /// creator-packet interop test next door, which is this tree's
    /// existing convention for pointing a test at a par2 that is not
    /// the box's own - one name, not a second mechanism.
    fn par2_bin() -> std::ffi::OsString {
        std::env::var_os("NZBFAST_PAR2_BIN").unwrap_or_else(|| "par2".into())
    }

    /// par2cmdline is not installed everywhere in this fleet, and CI's
    /// distro package is 0.8.1 against a dev box's 1.3.0 (memory topic
    /// `nzbfast-ci-par2-version-skew`), so the test says which it found.
    fn par2_version() -> Option<String> {
        let out = std::process::Command::new(par2_bin())
            .arg("-V")
            .output()
            .ok()?;
        out.status.success().then(|| {
            let mut t = String::from_utf8_lossy(&out.stdout).into_owned();
            t.push_str(&String::from_utf8_lossy(&out.stderr));
            t.lines().next().unwrap_or("unknown").trim().to_string()
        })
    }

    /// EVERY unpatched set the generator emits, over EVERY catalog
    /// profile that selects one, verified by the reference tool.
    ///
    /// This is the claim that cannot be self-consistent. The rest of
    /// this file has our creator judged by our own parser, and a writer
    /// and a reader that share a mistake pass that together; here a
    /// third implementation reads the bytes. Written over the catalog
    /// DIRECTORY rather than over a list of profile names, so a
    /// recovery profile added tomorrow is covered the day it lands.
    ///
    /// UNPATCHED only, and the profiles below are the reason it is
    /// worth saying: `hostile_names` deliberately writes names no
    /// creator would emit, and holding par2cmdline to those would be
    /// asserting that the reference tool accepts a hostile set, which
    /// is nobody's requirement. A profile that patches is skipped by
    /// name and the skip is printed, so this can never quietly cover
    /// nothing.
    ///
    /// WHERE IT RUNS, because for its first weeks there was no job on
    /// which it both ran AND could pass. This is a `postfast` LIB test,
    /// so per-push it rides ci-private's `linux-tests` sweep and
    /// `unit-one-process`, neither of which installed a reference, so
    /// the skip arm below fired on both - quietly, and indistinguishably
    /// from passing in every summary line either job prints.
    ///
    /// THE ONE JOB THAT DID RUN IT MADE THAT WORSE, and the first
    /// version of this comment got it wrong by trusting a handoff
    /// instead of reading the workflow - so read the workflow. Nightly's
    /// `one-process-loaded` runs the `postfast:lib` leg and DOES install
    /// par2 (nightly.yml, `test deps (par2 for repair fixtures)`) and
    /// DOES set `NZBFAST_REQUIRE_PAR2`. That par2 is ubuntu's **0.8.1**,
    /// which cannot verify a set describing a 0-byte member, and this
    /// catalog carries three such rows - so there the guard runs and
    /// FAILS, on sets that are perfectly good, for a reason two majors
    /// old. That red is `red-one-process-loaded-d7d89a88` and it is a
    /// separate item from this one; the leg wants the same pinned
    /// reference the per-push half now has. Do NOT answer it with a
    /// minimum-version floor here - that silently drops coverage on the
    /// runner, which is the standing rule in the version-skew memory
    /// topic. `unit-one-process` now restores the pinned v1.3.0
    /// that `par2-conformance` already builds and caches, points
    /// `NZBFAST_PAR2_BIN` at it and sets `NZBFAST_REQUIRE_PAR2=1`, so
    /// on that one job a missing reference is RED rather than a skip.
    /// That job and not the four `linux-tests` shards because only one
    /// shard would ever draw this test and all four would pay the
    /// restore; and per-push rather than nightly because the whole run
    /// is 0.5 s once the binary is there. Failing to find is failing:
    /// the counts are printed and the walk refuses to report a clean
    /// sweep over nothing.
    #[test]
    fn par2cmdline_verifies_every_unpatched_set_the_catalog_emits() {
        let Some(version) = par2_version() else {
            // The half that makes the reference conformance a fleet
            // property instead of a dev-box one: a runner that was
            // SUPPOSED to have the binary and does not reddens here
            // rather than printing "skipping".
            assert!(
                std::env::var_os("NZBFAST_REQUIRE_PAR2").is_none(),
                "NZBFAST_REQUIRE_PAR2 is set and no par2 answered at {:?}. \
                 ci-private's `unit-one-process` job sets both that and \
                 NZBFAST_PAR2_BIN from its cached par2cmdline v1.3.0, so this \
                 is the reference having gone missing, not a box without one.",
                par2_bin()
            );
            eprintln!(
                "skipping par2cmdline_verifies_every_unpatched_set_the_catalog_emits: \
                 no `par2` on PATH. Install par2cmdline to run it (or set \
                 NZBFAST_PAR2_BIN); ci-private's `unit-one-process` job does."
            );
            return;
        };
        eprintln!("par2cmdline conformance against: {version}");
        let dir = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog");
        let mut checked = 0usize;
        let mut with_sets = 0usize;
        let mut decoys = 0usize;
        for entry in std::fs::read_dir(&dir).expect("the catalog directory exists") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let p = Profile::load(&path).unwrap_or_else(|e| panic!("{}: {e}", path.display()));
            if p.recovery.kind == RecoveryKind::None {
                continue;
            }
            with_sets += 1;
            let name = path.file_name().unwrap().to_string_lossy().into_owned();
            if !p.recovery.hostile_names.is_empty() {
                eprintln!("{name}: skipped, it patches FileDesc names on purpose");
                continue;
            }
            let mut rng = crate::Rng::for_profile(&p);
            let sources = crate::assemble::sources(&p, &mut rng).expect("sources assemble");
            let r = build(&p, &sources).unwrap_or_else(|e| panic!("{name}: {e}"));

            // The payload under the names the set DESCRIBES it by, plus
            // the set's own files, is exactly the directory a user
            // would point `par2 verify` at.
            let stage = Stage::new().expect("a scratch directory");
            for (i, s) in sources.iter().enumerate() {
                if r.covers(i) {
                    stage.write(&s.rel, &s.bytes).expect("stages a member");
                }
            }
            // G7: a foreign set's member is unposted by construction,
            // so the walk above staged nothing for it and par2cmdline
            // answers "Target: missing" - the row's own point, and not
            // a set the reference tool cannot read. Staged here so this
            // guard asks the question it exists to ask, is the emitted
            // set WELL FORMED; skipping the row instead would have left
            // the one set in the catalog that no reference tool had
            // ever read.
            for m in phantom_members(&p).expect("phantom members recompute") {
                stage.write(&m.rel, &m.bytes).expect("stages a phantom");
            }
            for f in &r.files {
                stage.write(&f.name, &f.bytes).expect("stages a set file");
            }
            // P10: the DECOY is skipped, and this is not the gate
            // being loosened. The claim this walk makes is that every
            // SET the generator emits is well formed; a decoy is by
            // construction not a set, so asking par2cmdline to verify
            // one would be asserting that the reference tool accepts a
            // file whose point is that no tool can. The count is
            // printed below beside the others, so the skip can never be
            // the whole of what this walk did.
            decoys += r.files.iter().filter(|f| f.decoy).count();
            for f in r.files.iter().filter(|f| !f.parity && !f.decoy) {
                let out = std::process::Command::new(par2_bin())
                    .args(["verify", "-q", &f.name])
                    .current_dir(&stage.dir)
                    .output()
                    .expect("par2 runs");
                assert!(
                    out.status.success(),
                    "{name}: par2cmdline ({version}) will not verify {}\n{}{}",
                    f.name,
                    String::from_utf8_lossy(&out.stdout),
                    String::from_utf8_lossy(&out.stderr)
                );
                checked += 1;
            }
        }
        // PRINTED, not merely asserted on. A CI log that says only
        // "ok" cannot tell a real sweep from the skip arm above, which
        // is the whole reason this guard went unnoticed for weeks; the
        // counts are what a reader checks the job log for.
        eprintln!(
            "par2cmdline conformance: {checked} set file(s) verified across \
             {with_sets} recovery profile(s); {decoys} P10 decoy file(s) skipped as \
             not-a-set by construction"
        );
        // Failing to find is failing: a walk that reached no set would
        // otherwise report a clean sweep over nothing.
        assert!(
            with_sets > 0 && checked > 0,
            "the catalog holds {with_sets} recovery profile(s) and this verified {checked} \
             set(s) - a conformance test that reached nothing is reporting its own blindness"
        );
    }
}
