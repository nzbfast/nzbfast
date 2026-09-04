//! The layout profile: section 10 of the spec, as serde structs.
//!
//! A profile is a TOML document that names one selection per plane -
//! naming, container, recovery, encoding, NZB, generation-time fault,
//! serve-time fault - plus the source payload to build it over and the
//! end state the client must reach. It is DATA: "any variation" is a
//! value here, never new code in the generator.
//!
//! Two properties this module exists to hold, both of which a later
//! stage would otherwise have to remember:
//!
//! 1. **A typo is a load error.** Every table carries
//!    `#[serde(deny_unknown_fields)]`, so `redundancy_pc = 10` refuses
//!    by name instead of silently selecting the neutral plane and
//!    quietly turning a recovery-set profile into a P0 one. A profile
//!    that passes review because its test passed, while the plane it
//!    meant to exercise was never selected, is the exact failure the
//!    whole toolkit is built to make impossible.
//! 2. **An absent table is the neutral selection.** Every plane table
//!    is optional and every `Default` here equals the neutral row: N1
//!    descriptive names, C0 no container, P0 no recovery set, the
//!    encoding defaults, a faithful NZB, no faults. So a profile states
//!    only what it varies, and a reader can take the whole difference
//!    from the neutral baseline by reading the file.
//!
//! Contradictions between planes are refused by [`Profile::validate`]
//! rather than encoded in the types: an unrepresentable-illegal-state
//! model of seven interacting planes would be a combinatorial type
//! salad, and the error a validator gives ("encryption is on and the
//! password is empty") is the one an author can act on.

use std::collections::HashSet;
use std::fmt;
use std::path::{Path, PathBuf};

use serde::Deserialize;

use crate::assemble;

/// The profile format version the catalog is written against. A
/// loader refuses a file that names a different one, so a schema change
/// is a deliberate migration of every profile rather than a silent
/// reinterpretation.
pub const FORMAT_VERSION: u32 = 0;

// ---------------------------------------------------------------------
// The document
// ---------------------------------------------------------------------

/// One layout profile: one selection per plane over one source payload.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Profile {
    /// Identity and the seed. The one table with no neutral default:
    /// a profile that does not say what it is or which seed it draws
    /// from is not a profile.
    pub layout: LayoutMeta,
    #[serde(default)]
    pub source: Source,
    #[serde(default)]
    pub naming: Naming,
    #[serde(default)]
    pub container: Container,
    #[serde(default)]
    pub recovery: Recovery,
    #[serde(default)]
    pub encoding: Encoding,
    #[serde(default)]
    pub nzb: Nzb,
    #[serde(default)]
    pub companion: Companion,
    #[serde(default)]
    pub fault: Fault,
    #[serde(default)]
    pub serve: Serve,
    #[serde(default)]
    pub expect: Expect,
}

/// `[layout]`: what this profile is and where its randomness starts.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct LayoutMeta {
    /// Stable identifier, and the stem of the generated oracle test
    /// name. Conventionally the plane IDs it selects, so a failure line
    /// says which planes were in play.
    pub name: String,
    /// The ONE seed every random choice in the run is derived from
    /// (see [`crate::rng`]). Same profile plus same seed equals a
    /// byte-identical layout, msgids and fault picks included.
    pub seed: u64,
    /// Free text: the matrix row, handoff or incident this profile
    /// pins, so a reader knows what deleting it would lose.
    pub note: String,
    /// The schema this file is written against; [`FORMAT_VERSION`] is
    /// the only value that loads.
    pub format_version: u32,
}

impl Default for LayoutMeta {
    fn default() -> Self {
        Self {
            name: String::new(),
            seed: 0,
            note: String::new(),
            format_version: FORMAT_VERSION,
        }
    }
}

/// `[source]`: the payload the layout is built over. Generated from the
/// seed rather than read from a fixture directory, so a profile is
/// self-contained and the catalog carries no binaries.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Source {
    /// The files to post. A `name` containing `/` puts the file in a
    /// directory, which is how a source tree is expressed.
    pub files: Vec<SourceFile>,
    /// Repeating (highly compressible, block-identical) payload bytes.
    ///
    /// ALWAYS REFUSED, and the key exists only so that trying it gets
    /// this reason instead of an unknown-field error that reads like a
    /// typo: par2cmdline 0.8.1 - the version CI carries, against 1.3.0
    /// on the dev box (memory topic `nzbfast-ci-par2-version-skew`) -
    /// miscounts identical recovery blocks, so a periodic payload makes
    /// the par2gen interop check disagree with itself by environment.
    /// A layout that needs incompressible bytes gets them from the seed.
    pub periodic: bool,
}

/// One generated source file: a name (possibly with directories) and a
/// length. The bytes themselves come from the seed.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct SourceFile {
    pub name: String,
    pub bytes: u64,
    /// G2: how many of the file's LEADING bytes are zeros rather than
    /// seed noise. 0, the neutral value, is the ordinary all-noise file.
    ///
    /// The padded-VOB and disk-image shape, and the only way a profile
    /// can put two members in one post that share a first 16 KiB: that
    /// collides the `(length, md5-16k)` matcher key, which is the whole
    /// identical-head family (`bench/capability-corpus` legs n15, n16,
    /// n25, n26 and n29).
    ///
    /// **This is not the return of [`Source::periodic`], and the
    /// difference is enforced rather than argued.** Every block PAST
    /// the head still comes off the ChaCha stream and is unique, so two
    /// members can never hand par2gen the same recovery block - and
    /// [`Contradiction::ZeroHeadReachesAWholeBlock`] refuses the one
    /// shape where they could, a head as long as the set's own block.
    /// A profile with a recovery set therefore has to state
    /// `[recovery] block_bytes` before it may state a head at all,
    /// which is what makes that refusal checkable from the file.
    #[serde(default)]
    pub zero_head: u64,
    /// G5: this file's bytes ARE another `[source]` file's bytes, and
    /// only that other file is posted.
    ///
    /// MultiPar's dedupe shape: a poster who has two files with the
    /// same content ships one copy of the bytes and two FileDesc
    /// packets, buying a whole duplicate file for a few kilobytes of
    /// descriptor. Both members are described, both must land, and the
    /// client has to derive the second from the first - a PAR2 file id
    /// is hashed over the name as well as the content, so the two
    /// descriptors are distinct and their content hashes agree.
    ///
    /// The entry is DESCRIBED AND NEVER POSTED, which is the same
    /// mechanism [`Recovery::zero_byte_member`] uses and a different
    /// requirement: a P5 placeholder is empty, so materialising it is
    /// free, and this one is the length of a real file the post carries
    /// exactly one copy of.
    #[serde(default)]
    pub same_as: String,
    /// G3: post this file as `split` contiguous wire files instead of
    /// one, and land it joined.
    ///
    /// The no-container split recipe. A poster who wants volumes but
    /// not an archive cuts the file into raw parts and posts each one:
    /// no rar bytes, no unpack pass, and a client with a
    /// block-harvesting scan can put it back together with no recovery
    /// spend at all. `bench/capability-corpus` legs n18, n19 and n33
    /// are the family.
    ///
    /// 0, the neutral value, is one file posted as one file.
    /// [`SourceFile::split_names`] says which side of the cut the
    /// recovery set describes, and that is the whole of the difference
    /// between the two directions.
    #[serde(default)]
    pub split: u32,
    /// G3: whether a recovery set describes the JOINED file or the
    /// PARTS. Meaningless, and refused, without a `split`.
    #[serde(default)]
    pub split_names: SplitNames,
    /// G8: what the file's bytes LOOK like, past being the right
    /// length. `"noise"`, the neutral value, is the ordinary all-stream
    /// file every other row is built over.
    ///
    /// Two rows in the corpus rounds turned out to be the same
    /// question asked twice - the payload's bytes are not pure noise -
    /// so this is one key rather than two. `bench/capability-corpus`
    /// leg n03 wants a real container pattern under an extensionless
    /// name, and C3 wants bytes an archiver can actually shrink; see
    /// [`Content`] for the arm each one selects and what keeps it
    /// apart from [`Source::periodic`].
    #[serde(default)]
    pub content: Content,
}

/// G8: the shape of a source file's bytes.
///
/// **None of these is [`Source::periodic`] returning by another name,
/// and the difference is enforced rather than argued** - which is the
/// bar [`SourceFile::zero_head`] set and the one this key had to clear
/// before it could exist at all. `periodic` is refused because
/// par2cmdline 0.8.1, the version CI carries, miscounts identical
/// recovery BLOCKS, so what every arm here owes is that no two blocks
/// of a generated payload can be equal:
///
/// - [`Content::Mpegts`] rewrites one byte in 188 and leaves the other
///   187 as drawn, so two blocks are exactly as unequal as they are in
///   the neutral case.
/// - [`Content::Compressible`] is the harder one, and it is answered
///   twice over. Its runs are bounded to a couple of dozen bytes, far
///   under any PAR2 block, so no block it produces can be constant;
///   and it is refused beside a recovery set that would actually COVER
///   it ([`Contradiction::CompressibleUnderARecoverySet`]), which is
///   the half a reader can check from the profile text. par2gen
///   therefore never sees a byte of it. A set beside a `[container]`
///   is not that shape - `crate::layout::carried_files` cuts it over
///   the volumes, which are an archive's output - so the two compose,
///   and the nested-corpus r2c leg is what needs them to.
///
/// This key gets NO plane ID, for the reason `periodic` and `zero_head`
/// have none: `[source]` is the payload a layout is built OVER rather
/// than one of the seven planes, so the shape of the bytes is a
/// property and not a selection.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Content {
    /// The ordinary file: every byte off the ChaCha stream.
    #[default]
    Noise,
    /// An MPEG transport stream's sync pattern - `0x47` at every
    /// 188-byte packet boundary, stream noise everywhere else.
    ///
    /// The extensionless-payload shape (`bench/capability-corpus` leg
    /// n03): a post carrying no name source at all, over bytes a
    /// container sniffer has something real to recognise in. Without
    /// it a row over that leg cannot ask its actual question - does a
    /// client resolve a REAL extension, and never a junk one - because
    /// seed noise sniffs as nothing and passing means only that there
    /// was nothing there to see.
    ///
    /// The corpus's own `ts_payload` builds the same bytes the same
    /// way, so the two sides are equivalent at rung 2 by construction
    /// rather than by argument.
    Mpegts,
    /// Bytes an archiver can actually shrink: each drawn byte repeated
    /// for a drawn run of a couple of dozen at most.
    ///
    /// C3, the compressed-container plane, is unreachable without it.
    /// The RAR writers silently STORE a member they cannot shrink, so a
    /// compressed selection over incompressible bytes emits a C1
    /// archive wearing a C3 label - which
    /// `crate::container::ContainerError::NothingToCompress` refuses by
    /// name rather than emitting, and names this key as the fix.
    ///
    /// The value of every run is still the stream's own byte, so the
    /// alphabet is the full 256 and what the transform adds is
    /// repetition rather than a pattern. That is what makes it
    /// compressible under any LZ77 coder without being periodic.
    Compressible,
}

/// G3: which side of a raw split a recovery set describes.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SplitNames {
    /// The set describes the whole joined file, and the parts ride with
    /// nothing but the naming plane's answer. The MultiPar join shape:
    /// every joined block exists in the post at its own offset, so a
    /// client that harvests blocks assembles it and spends no parity.
    #[default]
    Join,
    /// The set describes the PARTS, as `name.001`, `name.002`, ... and
    /// the client joins what it has named. The `.001`/`.002` shape a
    /// splitter produces, with a set cut over the parts as they sit on
    /// disk.
    Parts,
}

// ---------------------------------------------------------------------
// 7.A Naming plane
// ---------------------------------------------------------------------

/// `[naming]`: what the wire says a file is called. Neutral is N1,
/// a descriptive name in both the yEnc header and the subject.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Naming {
    /// N1 / N2 / N3: the yEnc `name=` value.
    pub wire: WireName,
    /// N1 / N5: whether the Subject line names the file or is neutral
    /// furniture with no linkage between the files of one post.
    pub subject: SubjectStyle,
    /// N6: whether part indices arrive in their natural order.
    pub part_order: PartOrder,
    /// N7: UTF-8 names, or raw non-UTF-8 name bytes on the wire.
    pub name_bytes: NameBytes,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum WireName {
    /// N1: the real name.
    #[default]
    Descriptive,
    /// N2: a random token, the same one in the subject and in `name=`.
    Opaque,
    /// N3: `name=` present but empty.
    Empty,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SubjectStyle {
    /// The quoted-filename yEnc convention.
    #[default]
    Descriptive,
    /// N5: furniture only, no name and no cross-file linkage.
    Neutral,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartOrder {
    #[default]
    Natural,
    /// N6: part indices shuffled, from the seed.
    Reordered,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum NameBytes {
    #[default]
    #[serde(rename = "utf8")]
    Utf8,
    /// N7: bytes that are not valid UTF-8 (M4-86).
    #[serde(rename = "raw")]
    Raw,
}

// ---------------------------------------------------------------------
// 7.B Container plane
// ---------------------------------------------------------------------

/// `[container]`: the archive wrapped around the payload, if any.
/// Neutral is C0, bare files.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Container {
    /// C0 / C1-C3: no container, stored, or compressed.
    pub kind: ContainerKind,
    /// Which RAR generation writes it.
    pub version: RarVersion,
    /// C2: payload bytes per volume; 0 is a single volume.
    pub volume_bytes: u64,
    /// C6: whether the volume names describe the content.
    pub volume_names: VolumeNames,
    /// C11: `.part01.rar`, `.rar` + `.r00`, or numeric.
    pub volume_style: VolumeStyle,
    /// C4 / C5: data or header encryption.
    pub encryption: Encryption,
    /// Required whenever `encryption` is not `none`. A profile
    /// password is test furniture and is never a real credential.
    pub password: String,
    /// C10: percent of the archive given to an embedded recovery
    /// record (RAR's own, not PAR2).
    pub recovery_record_pct: u32,
    /// C7: depth of nesting; 0 is a single container. Every level is
    /// described by THIS table, so kind, version and
    /// `recovery_record_pct` are uniform all the way down.
    /// [`Container::inner`] is the other way of saying it.
    pub nested: u32,
    /// C9: bytes of SFX-stub-shaped prefix before the signature.
    pub leading_bytes: u64,
    /// C13, H2: per-level tables for a nested stack whose levels are
    /// NOT all alike, written `[[container.inner]]`, OUTERMOST-INNER
    /// FIRST - the level just below the posted set, then the one below
    /// that, down to the archive that holds the payload.
    ///
    /// Outermost-first because that is how the shape is named
    /// everywhere else: the nested corpus calls a leg
    /// `x3-mixed-7z-rar-store` for `RAR > 7z > RAR > payload`, and a
    /// profile that listed the same chain backwards would be one more
    /// thing for a reader to get wrong. `crate::container` builds
    /// inner-to-outer and does the reversal once, where the loop is.
    ///
    /// **It REPLACES `nested` rather than joining it**, and writing
    /// both is refused by name: they are two spellings of the depth and
    /// a profile that disagreed with itself would need a precedence
    /// rule, which is a silent answer to a question the author asked
    /// out loud. `nested = N` stays the short way to say "N further
    /// levels, all like this one" and is what every profile written
    /// before 4 Sep 2026 says.
    ///
    /// An inner level carries only what an unsplit inner archive can
    /// have. The volume split, the volume naming and the SFX prefix
    /// belong to the OUTERMOST level, because that is the set a poster
    /// puts on the wire, and they stay on `[container]` itself.
    pub inner: Vec<InnerLevel>,
    /// C8: a SECOND, complete archive of another format appended after
    /// the selected one, so the emitted file is structurally valid as
    /// both at once.
    ///
    /// Neutral is [`Polyglot::None`], and the key is the whole C8
    /// plane: nothing else in the catalog makes one file answer to two
    /// container readers. It rides the OUTERMOST level and the first
    /// volume, beside [`Container::leading_bytes`], because that is the
    /// file a client scans.
    pub polyglot: Polyglot,
    /// C14, H3: extra files carried at the OUTERMOST level, beside the
    /// archive below it.
    ///
    /// This key is the outermost level's ALONE, `nested` or not: under
    /// a uniform stack the levels below it carry none. A sibling at
    /// every level - which is what the nested corpus's x1 and x2 legs
    /// build - is written with a `[[container.inner]]` table per level,
    /// each naming its own, and that is deliberate rather than a
    /// limitation. Repeating one list down a stack would put the same
    /// NAME at every depth, and every one of them lands in the same
    /// output directory.
    pub siblings: Vec<Sibling>,
}

/// C14: one extra file carried inside a container level, beside the
/// archive below it.
///
/// The shape the nested corpus's ladder legs build at every depth, and
/// the one a3 uses to ship each level the next level's password: a
/// client that stopped denesting the moment a level held something
/// besides an archive would pass a ladder row without siblings and
/// fail both of those legs.
///
/// Its bytes come from a stream of the container plane's own, so adding
/// one moves no payload name and no message-id of the row it was copied
/// from - the same property the fault planes have.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Sibling {
    /// The name the archive carries it under, which is also the name it
    /// lands under. A `/` puts it in a directory, exactly as a
    /// `[source]` name does inside an archive.
    pub name: String,
    /// How long it is, when the content is noise. Zero is refused
    /// UNLESS [`Sibling::text`] says what the bytes are: a described
    /// member with neither a length nor a content is
    /// [`Recovery::zero_byte_member`]'s shape and belongs to the
    /// recovery plane, where the requirement is about a FileDesc packet
    /// rather than about an archive entry.
    #[serde(default)]
    pub bytes: u64,
    /// The sibling's content, literally, instead of noise of a stated
    /// length. Writing both is refused: they are two answers to what
    /// the file holds.
    ///
    /// This is what makes a PASSWORD CHAIN emitable, which is the shape
    /// this key exists for and the corpus's `a3` leg. The client's
    /// unlock ladder harvests candidates from each level's own outputs
    /// - `nzbfast_unpack::rarfix::passwords::harvest_password_candidates`
    /// reads the trimmed lines of small `.txt` / `.nfo` / `.diz`
    /// sidecars - so a level that carries a text file holding the NEXT
    /// level's password hands the client what it needs to keep
    /// denesting. Noise of a stated length cannot say anything, so
    /// before this key the outermost password was the only one a
    /// profile could deliver.
    ///
    /// A newline is appended when the text does not end in one, because
    /// the harvest reads LINES and a file with no terminator is a shape
    /// no editor writes.
    ///
    /// Test furniture, like every other password in a profile: the text
    /// travels in the clear inside the archive above it, which is
    /// exactly the point of the shape and exactly why nothing real goes
    /// here.
    #[serde(default)]
    pub text: Option<String>,
}

/// C13: one inner level of a nested stack.
///
/// Deliberately a small table rather than a second [`Container`]:
/// three quarters of that type's keys describe the POSTED set, and an
/// inner level is an ordinary unsplit archive inside the level above
/// it. `deny_unknown_fields` therefore refuses `volume_bytes` here by
/// name, with the shape it would have meant, rather than accepting it
/// and applying it nowhere.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct InnerLevel {
    /// The format and storage mode of this level's archive. `none` is
    /// refused: a level that is not an archive is not a level.
    pub kind: ContainerKind,
    /// Which RAR generation writes it, where it is a RAR at all.
    #[serde(default)]
    pub version: RarVersion,
    /// C10 at THIS level: percent of the archive given to an embedded
    /// recovery record. The corpus's `a1` leg puts one at level 3 and
    /// nowhere else, which is the shape a uniform table cannot state.
    #[serde(default)]
    pub recovery_record_pct: u32,
    /// C14: extra files carried at THIS level, beside the archive
    /// below it. See [`Container::siblings`].
    #[serde(default)]
    pub siblings: Vec<Sibling>,
    /// C4 / C5 at THIS level: data or header encryption.
    ///
    /// A stack whose levels are encrypted DIFFERENTLY is the shape a
    /// single `[container] encryption` cannot state, and the one a
    /// password chain is built on: the level a client meets first is
    /// the one whose password the NZB can announce, and every level
    /// under it has to be discovered from what the level above it
    /// dropped.
    #[serde(default)]
    pub encryption: Encryption,
    /// This level's own password, required whenever its `encryption` is
    /// not `none`.
    ///
    /// Empty means "the same password as `[container] password`", which
    /// is what a stack with one password all the way down says and what
    /// every profile written before 4 Sep 2026 means by saying nothing.
    /// A DIFFERENT password here is the chain: see [`Sibling::text`]
    /// for how it reaches the client, because the NZB can announce only
    /// one and it announces the outermost.
    ///
    /// Test furniture, never a real credential.
    #[serde(default)]
    pub password: String,
    /// C15, H4: percent redundancy of a PAR2 set cut over THIS level's
    /// archive and packed into the level ABOVE it, beside that archive.
    ///
    /// The shape the nested corpus's `r4` leg is built around and the
    /// one it says most downloaders stop at: the post itself is intact,
    /// so the posted set verifies and the client unpacks happily, and
    /// what comes out is a damaged archive together with the complete
    /// recovery set that would fix it. A client that files that and
    /// reports success has delivered nothing.
    ///
    /// Distinct from [`Recovery`], which is the set posted BESIDE the
    /// volumes and covers what goes on the wire, and from
    /// [`InnerLevel::recovery_record_pct`] (C10), which is RAR's own
    /// record INSIDE the archive rather than a set beside it. All three
    /// can hold at once, which is `a1`.
    ///
    /// 0 is no set.
    #[serde(default)]
    pub recovery_pct: u32,
}

impl Container {
    /// How many levels sit ABOVE the payload archive: `nested`, or the
    /// length of the per-level list when one is written.
    ///
    /// One spelling, because the two keys are two ways of saying the
    /// same number and a second site that read only `nested` would
    /// silently build a one-level stack for a profile that asked for
    /// three.
    pub fn depth(&self) -> u32 {
        if self.inner.is_empty() {
            self.nested
        } else {
            u32::try_from(self.inner.len()).unwrap_or(u32::MAX)
        }
    }
}

/// C0-C3 and C12: the archive FORMAT and the storage mode, in one
/// selection.
///
/// **One key rather than a `kind` plus a `format`**, which is what
/// `research/POSTFAST-VS-NESTED-CORPUS-2026-09-03.md`'s H1 diagnosis
/// guessed at. Two keys would have made three of the four combinations
/// need a refusal of their own the day a format arrived that has no
/// stored mode, and `deny_unknown_fields` gives a misspelled variant
/// its own error either way. It also leaves every profile written
/// before 7z existed untouched: `rar-stored` still spells what it
/// always spelled. The zip arm, added the day after, cost this type two
/// variants and no key at all, which is the choice paying off once.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum ContainerKind {
    /// C0: the payload files are posted as they are.
    #[default]
    #[serde(rename = "none")]
    None,
    /// C1 / C2: stored, single volume or split.
    #[serde(rename = "rar-stored")]
    RarStored,
    /// C3: genuinely compressed (W4, and the shape that still reaches
    /// an external unrar on desktop and has no reader on the phones).
    ///
    /// Not reachable from a catalog profile yet, and refused by name
    /// rather than emitted: the RAR writers silently STORE an entry
    /// they cannot shrink and `[source]` bytes are incompressible by
    /// construction, so the archive would be a C1 wearing this label.
    /// [`ContainerKind::SevenzCompressed`] has no such fallback and is
    /// the arm a C3 row selects today.
    #[serde(rename = "rar-compressed")]
    RarCompressed,
    /// C12 + C1 / C2: a 7z archive whose every member is COPY.
    #[serde(rename = "7z-stored")]
    SevenzStored,
    /// C12 + C3: a 7z archive whose content method is LZMA2, which is
    /// what a 7-Zip build writes by default and what the nested
    /// corpus's own 7z legs carry.
    #[serde(rename = "7z-compressed")]
    SevenzCompressed,
    /// C12 + C1 / C2: a zip archive whose every entry is Stored, which
    /// is what `zip -0` writes and what the nested corpus's `r5-zip`
    /// leg carries.
    #[serde(rename = "zip-stored")]
    ZipStored,
    /// C12 + C3: a zip archive whose every entry is Deflated, the
    /// method every zip tool writes by default.
    ///
    /// A real C3 for the reason [`ContainerKind::SevenzCompressed`] is
    /// and [`ContainerKind::RarCompressed`] is not: the zip writer
    /// records the method per entry and does NOT fall back to Stored
    /// for an entry that did not shrink, so a deflated archive over
    /// incompressible `[source]` bytes is still one the client must run
    /// the inflate over.
    #[serde(rename = "zip-compressed")]
    ZipCompressed,
}

impl ContainerKind {
    /// Whether this kind selects a RAR archive.
    pub fn is_rar(self) -> bool {
        matches!(self, Self::RarStored | Self::RarCompressed)
    }

    /// Whether this kind selects a 7z archive.
    pub fn is_sevenz(self) -> bool {
        matches!(self, Self::SevenzStored | Self::SevenzCompressed)
    }

    /// Whether this kind selects a zip archive.
    pub fn is_zip(self) -> bool {
        matches!(self, Self::ZipStored | Self::ZipCompressed)
    }

    /// Whether this kind asks the writer to compress rather than store.
    pub fn is_compressed(self) -> bool {
        matches!(
            self,
            Self::RarCompressed | Self::SevenzCompressed | Self::ZipCompressed
        )
    }

    /// The extension an archive of this kind takes, empty for C0.
    ///
    /// Used for the volume names and for the name an inner level goes
    /// under inside the level above it, so a nested set spells what
    /// each of its levels actually is.
    pub fn extension(self) -> &'static str {
        match self {
            Self::None => "",
            Self::RarStored | Self::RarCompressed => "rar",
            Self::SevenzStored | Self::SevenzCompressed => "7z",
            Self::ZipStored | Self::ZipCompressed => "zip",
        }
    }
}

/// C8: which OTHER container format the emitted file is also a valid
/// archive of.
///
/// # The plane, in one paragraph
///
/// A polyglot is not malformed. It is honestly two things, so what a
/// client does with it depends on which signature it trusts and in what
/// order, and "the client got it wrong" is a judgement somebody has to
/// make rather than something the bytes say. The catalog's answer, at
/// length in `c8-polyglot-rar-then-7z.toml`: the client must produce
/// what RUNNING the self-extractor would produce, which is the archive
/// its stub launches - the EARLIEST confirmed one.
///
/// # Why the value is a FAMILY and not a generation
///
/// The client disambiguates with `nzbkit::sfx::sfx_payload_at`, which
/// folds both RAR signatures onto one `SfxFamily::Rar`. A `rar4` and a
/// `rar5` value would therefore select the same client decision twice,
/// so the RAR arm writes RAR5 and there is no generation key here.
/// [`Container::version`] is the generation of the archive the row is
/// ABOUT, and it is refused outright on a 7z kind - which is the arm
/// that would have had to borrow it.
///
/// # Why zip is not a value
///
/// It is the pairing whose disambiguation is hardest - a zip is located
/// from its TAIL (`nzbkit::zip::stubbed_archive`) rather than by a
/// forward scan, so a RAR/zip polyglot gives the client two independent
/// locators with no position to compare and forces a real preference
/// rule - and it is the one this crate cannot write. Nothing in this
/// repo emits a zip; spec section 7.B calls that out as C12's missing
/// half and as what leaves the nested corpus's `r5-zip` leg
/// unexpressible. Hand-assembling one here is the approximation
/// `crate::container`'s header refuses by name.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum Polyglot {
    /// The file is one archive and answers to one reader.
    #[default]
    #[serde(rename = "none")]
    None,
    /// A RAR5 archive follows the selected one.
    #[serde(rename = "rar")]
    Rar,
    /// A 7z archive follows the selected one.
    #[serde(rename = "7z")]
    SevenZ,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum RarVersion {
    #[serde(rename = "rar4")]
    Rar4,
    #[default]
    #[serde(rename = "rar5")]
    Rar5,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum VolumeNames {
    #[default]
    Descriptive,
    /// C6: reassembly has to come from the content.
    Opaque,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum VolumeStyle {
    /// `name.part01.rar`, `name.part02.rar`, ...
    #[default]
    #[serde(rename = "partNN")]
    PartNn,
    /// `name.rar`, `name.r00`, `name.r01`, ...
    #[serde(rename = "r00")]
    R00,
    /// `name.001`, `name.002`, ...
    #[serde(rename = "numeric")]
    Numeric,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Encryption {
    #[default]
    None,
    /// C4: file data encrypted, headers readable.
    Data,
    /// C5: headers encrypted too, so even the file list is gated.
    Header,
}

// ---------------------------------------------------------------------
// 7.C Recovery plane
// ---------------------------------------------------------------------

/// `[recovery]`: the PAR2 set beside the post, if any. Neutral is P0,
/// no recovery set at all.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Recovery {
    /// P0 / P1: absent, or a PAR2 set.
    pub kind: RecoveryKind,
    /// P4: percent redundancy; 0 is an index-only set.
    pub redundancy_pct: u32,
    /// PAR2 block size; 0 lets the creator derive it.
    pub block_bytes: u64,
    /// P1 / P2 / P3: whether the `.par2` files themselves are named
    /// descriptively, opaquely, or carry the only real names in the
    /// post (in their FileDesc packets).
    pub names: RecoveryNames,
    /// P7 / F7: the index volume present, damaged, or absent.
    pub index: IndexState,
    /// P8: which payload files the set covers.
    pub covers: Covers,
    /// P5: include a 0-byte member, which names a file and protects no
    /// blocks.
    pub zero_byte_member: bool,
    /// P6: extra FileDesc names patched in, resealed - traversal
    /// attempts, duplicates, names no creator would emit.
    pub hostile_names: Vec<String>,
    /// P9: the members of a SECOND, independent set in the same post,
    /// written under a base name of its own. Empty is the neutral
    /// selection - one set, or none.
    ///
    /// A list rather than a `bool` because the two sets of P9 are
    /// independent, which means each one's membership is a separate
    /// fact: the row is about a client routing two sets over disjoint
    /// halves of one post, and a flag could only ever mean "split it
    /// somehow". The generator refuses a member that both sets would
    /// cover, for the same reason.
    pub second_covers: Vec<String>,
    /// G7: members of a FOREIGN set - described in full, and never
    /// posted at all.
    ///
    /// A complete recovery set of its own rides beside the real one,
    /// covering a file this post does not carry: the poisoned or
    /// misfiled set that turns up in the wild when somebody uploads the
    /// `.par2` files of one release beside the articles of another. The
    /// question it asks is a negative one, which is why it is worth a
    /// row: the phantom must neither fail the job nor be invented on
    /// disk.
    ///
    /// Distinct from [`Recovery::zero_byte_member`] (P5), which is also
    /// described-and-unposted. A P5 placeholder is a member of the REAL
    /// set with no bytes, so materialising it is correct and the row
    /// asserts it happens; a phantom has bytes the post never carried,
    /// so materialising it is impossible and inventing anything under
    /// its name is a defect.
    pub phantom_covers: Vec<PhantomMember>,
    /// G6: build a SECOND set over the first set's own `.par2` files,
    /// posted under its own real names.
    ///
    /// The chain. The payload rides under tokens and its recovery set
    /// rides under tokens too, so nothing announced in the post
    /// describes the payload at all; a small OUTER set, posted under
    /// ordinary `.par2` names, describes the inner set's files. A
    /// name-driven client has to chase the chain - outer set, inner set,
    /// payload - and a content-sniffing one can shortcut it by
    /// recognising PAR2 packets under a token.
    ///
    /// Requires `names = "opaque"`: with the inner set announced there
    /// is no chain to chase, because the thing the outer set would name
    /// is already named.
    pub outer: bool,
    /// P10: a file the post NAMES `.par2` whose bytes are not a PAR2
    /// set. Absent is the neutral selection.
    ///
    /// The plane's other rows all ask what a client does with a set;
    /// this one asks how it decides that a thing IS one. A `.par2`
    /// suffix is a poster's choice and nothing more, so the answer has
    /// to come from the packets - and a client that reads the
    /// extension instead has a file it will try to verify against, or
    /// spend, or sweep away as furniture.
    ///
    /// What the bytes ARE is [`crate::recovery`]'s to say and is
    /// deliberately not a selection here: the shape is the one worth
    /// posing (a real creator's critical packets, and then not a set),
    /// and a second, weaker arm would only be a row that stops at the
    /// first magic check. That module's `create_decoy` argues it at
    /// length.
    pub decoy: Option<Decoy>,
}

/// P10: the `.par2`-named non-parity file, its name and its length.
///
/// `bytes` is the whole file, head packets included, so a profile
/// controls what the row costs on the wire the way every other plane
/// lets it. The floor is the head's own length plus room for the junk
/// to be junk, and [`crate::recovery`] refuses a shorter one with both
/// numbers in the message - the head comes out of a real creator run,
/// so its length is not a number this schema can state.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct Decoy {
    pub name: String,
    pub bytes: u64,
}

/// G7: one member of a foreign set: a name and a length, described by
/// a set of its own and posted nowhere.
///
/// It carries a `bytes` because a set describes lengths and block
/// hashes, so a phantom with no size would be a set the creator could
/// not cut. The bytes themselves are drawn from a stream of this
/// plane's own and are thrown away with the scratch directory: nothing
/// in the layout ever carries them, which is the whole point.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PhantomMember {
    pub name: String,
    pub bytes: u64,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum RecoveryKind {
    /// P0.
    #[default]
    None,
    Par2,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
pub enum RecoveryNames {
    /// P1: the set is named after what it protects.
    #[default]
    #[serde(rename = "descriptive")]
    Descriptive,
    /// P2: opaque wire names, real names still in the FileDesc packets.
    #[serde(rename = "opaque")]
    Opaque,
    /// P3: the recovery set is the ONLY place a real name exists.
    #[serde(rename = "filedesc-only")]
    FiledescOnly,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum IndexState {
    #[default]
    Present,
    /// F7: the index is there and does not parse.
    Damaged,
    /// P7: no index at all, so naming must come from the volumes.
    Absent,
}

/// P8: which payload members the recovery set protects.
#[derive(Debug, Clone, Default, PartialEq, Eq)]
pub enum Covers {
    /// Every payload member.
    #[default]
    All,
    /// The first member only. Refused when the set provably has one
    /// member, where it would mean the same thing as `all`.
    First,
    /// An explicit list of member names.
    Names(Vec<String>),
}

// Hand-written rather than `#[serde(untagged)]`: untagged answers a bad
// value with "data did not match any variant", and the whole point of
// this schema is that a typo names itself.
impl<'de> Deserialize<'de> for Covers {
    fn deserialize<D: serde::Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> serde::de::Visitor<'de> for V {
            type Value = Covers;

            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("\"all\", \"first\", or a list of member names")
            }

            fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<Covers, E> {
                match s {
                    "all" => Ok(Covers::All),
                    "first" => Ok(Covers::First),
                    other => Err(E::unknown_variant(other, &["all", "first"])),
                }
            }

            fn visit_seq<A: serde::de::SeqAccess<'de>>(
                self,
                mut seq: A,
            ) -> Result<Covers, A::Error> {
                let mut names = Vec::new();
                while let Some(n) = seq.next_element::<String>()? {
                    names.push(n);
                }
                Ok(Covers::Names(names))
            }
        }
        d.deserialize_any(V)
    }
}

// ---------------------------------------------------------------------
// 7.D Encoding plane
// ---------------------------------------------------------------------

/// `[encoding]`: how the payload becomes articles. The defaults are the
/// ordinary posting shape, so a profile states only the deviation.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Encoding {
    /// E1: yEnc line width.
    pub line_width: u32,
    /// E6: payload bytes per article before encoding.
    pub article_bytes: u32,
    /// E3: the `=ypart` CRC.
    pub part_crc: PartCrc,
    /// E4: the `=ybegin size` value against the real total.
    pub declared_size: DeclaredSize,
    /// E5: what follows the `=yend` trailer, which per the yEnc spec
    /// describes nothing and may not decide what lands on disk.
    pub trailing: Trailing,
    /// E2: whether a single-part file is posted in the multi-part form
    /// (`part=`/`total=`/`=ypart`) or the single-part one.
    pub ypart: Ypart,
}

impl Default for Encoding {
    fn default() -> Self {
        Self {
            line_width: 128,
            article_bytes: 768_000,
            part_crc: PartCrc::Present,
            declared_size: DeclaredSize::True,
            trailing: Trailing::None,
            ypart: Ypart::Present,
        }
    }
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum PartCrc {
    #[default]
    Present,
    Absent,
    /// A CRC that is present and does not match the bytes.
    Wrong,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum DeclaredSize {
    /// The declared total equals the real one.
    #[default]
    True,
    /// E4: declared smaller than the bytes that arrive.
    Short,
    /// E4: declared larger, so the file never looks complete.
    Long,
}

/// E2: which of the two yEnc article forms a single-part file is
/// posted in.
///
/// `present` is the multi-part form - `=ybegin part=1 total=1`, a
/// `=ypart begin=/end=` line, and a `=yend ... part=1 pcrc32=` trailer
/// - which is what this repo's own fixtures and posting engine emit
/// for every file, one part or not. `absent` is the ORIGINAL yEnc form
/// a single-file post has always been allowed to use: no part number
/// anywhere, and a `crc32=` on the trailer rather than a `pcrc32=`.
///
/// The two are not cosmetic variants of each other in the decoder:
/// `nzbkit::yenc::trailer_gates` reads `crc32` on a part as ADVISORY
/// and `crc32` on a non-part as FATAL, and the placement of the bytes
/// comes off `=ypart begin=` in one form and off nothing at all in the
/// other. E2 is the row that says both forms reach the same file.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Ypart {
    #[default]
    Present,
    /// Refused by the encoder over a file of more than one part.
    Absent,
}

/// E5: what an article carries AFTER its `=yend` trailer.
///
/// Both non-neutral arms are shapes M4-84 names by name at
/// `nzbkit::yenc::decode_checked`: before that rule, lines after the
/// first `=yend` kept flowing into the decoder and silently GREW the
/// slot, measured at double length with nothing to notice it. So this
/// is not a corrupt post - it is a post whose tail describes nothing,
/// and the requirement is that it decides nothing either.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Trailing {
    /// The article ends at its trailer, as an encoder writes it.
    #[default]
    None,
    /// Poster furniture: plain text lines after the trailer, the shape
    /// a signature or a group advert takes.
    Signature,
    /// The sharp one: a second complete copy of the article's own yEnc
    /// block, appended with no separator. A decoder that does not stop
    /// at the first `=yend` writes the payload twice.
    Article,
}

// ---------------------------------------------------------------------
// 7.E NZB plane
// ---------------------------------------------------------------------

/// `[nzb]`: what the map says, against what the wire says. Neutral is a
/// faithful NZB that agrees with the articles in every particular.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Nzb {
    /// Z1: `<meta type="name">` faithful, absent, or naming something
    /// the post does not contain.
    pub meta_name: MetaName,
    /// Z2: carry the container password in `<meta type="password">`.
    pub meta_password: bool,
    /// Z3: the segment `bytes` attribute against the real size.
    pub segment_bytes: SegmentBytes,
    /// Z4: percent of segments dropped from the map (the articles are
    /// still posted; the map just does not mention them).
    pub drop_segments_pct: f64,
    /// Z6: the `<file date>` stamp.
    pub date: NzbDate,
    /// Z5: the `<file subject>` against the Subject header the articles
    /// really carry.
    pub subject: NzbSubject,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum MetaName {
    #[default]
    Faithful,
    Absent,
    /// Present and wrong, which is the interesting case: the client has
    /// to decide how much authority the map has.
    Lying,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum SegmentBytes {
    #[default]
    True,
    Wrong,
}

/// Z5: whether the `<file subject>` in the map is the Subject the
/// articles were posted under.
///
/// A real disagreement, not a cosmetic one: the map's subject is the
/// only place many clients look for a filename, so a map that names one
/// thing while the wire names another is the sharp form of "who has
/// authority over the name".
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NzbSubject {
    #[default]
    Faithful,
    /// The map carries a different subject, naming a different file.
    Differing,
}

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum NzbDate {
    #[default]
    Fresh,
    /// Backdated past any plausible retention, which is what makes a
    /// 430 ambiguous between "gone" and "never there".
    Old,
    Undated,
}

// ---------------------------------------------------------------------
// 7.J Companion plane
// ---------------------------------------------------------------------

/// `[companion]`, G4: a metadata sidecar posted beside the payload,
/// with no companion at all as the neutral selection.
///
/// **Why this is a plane of its own and not a `[recovery] kind` arm.**
/// A recovery set protects bytes; a checksum sidecar protects nothing
/// and cannot repair a byte. What it does is carry NAMES, which is the
/// half of a PAR2 set that an obfuscated post actually depends on - and
/// it does it for a few hundred bytes against even a manifest-only
/// set's kilobytes, which is why the field ships it. A post may carry
/// both, and folding the sidecar into the recovery plane would have
/// made "both" unsayable.
///
/// Spec 7.G lists companion metadata as D4, a DEPLOYMENT control on the
/// posting tool that no oracle row reaches. That stays true of the
/// `--nfo` / `--sfv` flags in [`crate::post`]; this is the layout half,
/// where the sidecar is the only thing in the post that knows a real
/// name and the oracle has to grade what the client makes of it.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Companion {
    /// Post an `.sfv` listing every source file's relative path against
    /// its CRC32.
    pub sfv: bool,
    /// The sidecar's own file name. Posted under this name whatever the
    /// naming plane says, and [`Companion::DEFAULT_SFV_NAME`] is the
    /// value an empty string means.
    pub sfv_name: String,
}

impl Companion {
    /// The name an `.sfv` takes when a profile does not spell one.
    ///
    /// Deliberately not derived from the payload: under an opaque
    /// layout every payload name is a token, so a derived sidecar name
    /// would be a token too - and a name source nothing can find is not
    /// a name source. A fixed, ordinary name is what a poster ships.
    pub const DEFAULT_SFV_NAME: &'static str = "post.sfv";

    /// The sidecar's file name, with the default filled in.
    pub fn sfv_file_name(&self) -> &str {
        if self.sfv_name.is_empty() {
            Self::DEFAULT_SFV_NAME
        } else {
            &self.sfv_name
        }
    }
}

// ---------------------------------------------------------------------
// 7.F Fault plane, generation-time
// ---------------------------------------------------------------------

/// `[fault]`: damage baked into the emitted bytes. Distinct from
/// `[serve]`, which damages the answer rather than the article.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Fault {
    /// F3: corrupt the archive headers.
    pub corrupt_headers: bool,
    /// F5: cut this many bytes off the last volume.
    pub truncate_last_volume_bytes: u64,
    /// F4: how many recovery packets to damage.
    pub corrupt_recovery_packets: u32,
    /// F6: emit a SECOND recovery set over the same members, under a
    /// base name of its own - two sets competing to describe one post.
    ///
    /// Distinct from `[recovery] second_covers` (P9), which is two
    /// sets over DISJOINT halves and is refused the moment they
    /// overlap. This is the overlap on purpose: the donor shape, where
    /// a client offered two descriptions of the same bytes has to take
    /// blocks from whichever set can supply them rather than picking
    /// one and failing.
    pub duplicate_set: bool,
    /// G1: spans of a PAYLOAD file to spoil, after the recovery set was
    /// cut over the clean bytes.
    ///
    /// The one fault where what goes on the wire and what the client
    /// must end with are different bytes. Every other arm of this table
    /// damages the recovery set or the archive around the payload; this
    /// one damages the payload itself, so the article's own yEnc CRC
    /// agrees with the damage and only the set can see it. That is the
    /// half `[serve] corrupt` cannot reach: `nzbkit::mock` flips its
    /// byte in the ENCODED article, so the part CRC fails and the client
    /// meets a REFUSED article rather than plausible wrong bytes.
    /// `bench/capability-corpus` legs n14, n25 and n26 are the shape.
    pub corrupt_payload: Vec<PayloadDamage>,
}

/// G1: one span of one payload file to spoil.
///
/// The file and the offset are the PROFILE's answers rather than the
/// seed's, unlike F3's choice of volume - and the difference is not an
/// inconsistency. How many volumes an archive has is the writer's
/// decision, so a profile naming volume 2 would be pinning a framing it
/// does not control; a payload file's name and length are what
/// `[source]` itself declares, so an offset into one is a fact the
/// author already holds. WHICH bytes replace the span still comes off
/// the fault stream.
#[derive(Debug, Clone, PartialEq, Eq, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct PayloadDamage {
    /// The `[source]` file to spoil, by its `name`. Exactly one of this
    /// and [`PayloadDamage::inner_level`] is written.
    #[serde(default)]
    pub file: String,
    /// H5: spoil a NESTING LEVEL's archive instead of a payload file -
    /// the `[[container.inner]]` entry at this position, counting from
    /// the outermost inner level, which is the same numbering the
    /// profile already used to describe the stack.
    ///
    /// **The same key at two depths, deliberately, rather than a second
    /// table.** Both are "spoil these bytes AFTER the recovery data
    /// that covers them was cut", and both are plane F8; what differs
    /// is which recovery data, and therefore where the generator has to
    /// do it. A payload span is written in `crate::fault`, after
    /// `recovery::build`; a level's span is written in
    /// `crate::container`, inside the loop that builds the stack,
    /// immediately after that level's own [`InnerLevel::recovery_pct`]
    /// set. Two tables would have said one thing twice.
    ///
    /// It names an INNER level and never the posted one: damaging the
    /// archive that goes on the wire is F3 (`corrupt_headers`) and F5
    /// (`truncate_last_volume_bytes`), whose whole difference is that
    /// the POSTED set is what repairs them.
    #[serde(default)]
    pub inner_level: Option<u32>,
    /// Byte offset of the first spoiled byte.
    pub at: u64,
    /// How many bytes to spoil. Zero is not damage and is refused.
    pub bytes: u64,
}

// ---------------------------------------------------------------------
// 7.F Fault plane, serve-time
// ---------------------------------------------------------------------

/// `[serve]`: what the mock server does to the answers, by name onto
/// `nzbkit::mock::Chaos`. The generator picks WHICH articles from the
/// seed and hands the server the resulting sets, so the percentages
/// here stay reproducible without the profile naming a msgid it cannot
/// know. Anything Chaos cannot express is a Chaos change in
/// `nzbkit::mock`, never a parallel mechanism in this crate.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Serve {
    /// S1: article positions answered 430, permanently. The "by name"
    /// half of the selection, for a row that has to damage a
    /// PARTICULAR article rather than a share of them.
    pub missing: Vec<u32>,
    /// S1: percent of articles answered 430, permanently.
    pub missing_pct: f64,
    /// S1: percent of articles answered 430 on their FIRST request and
    /// served on every one after it - the refusal that was never true.
    pub missing_once_pct: f64,
    /// S2: article positions served with a flipped byte.
    pub corrupt: Vec<u32>,
    /// S2: percent of articles served with a flipped byte, on every
    /// request (a damaged article in the spool).
    pub corrupt_pct: f64,
    /// S2: percent damaged on their FIRST request only (a broken cache
    /// node behind a load balancer, where a re-ask usually lands
    /// somewhere healthy).
    pub corrupt_once_pct: f64,
    /// S3: article positions cut off mid-body.
    pub truncate: Vec<u32>,
    /// S5: article positions that hang after the status line.
    pub stall: Vec<u32>,
    /// S5: article positions that hang BEFORE the status line - the
    /// dead-air shape a flat read timeout waits out in full.
    pub stall_pre: Vec<u32>,
    /// S4: article positions answered with a DIFFERENT article's body.
    /// The partner is drawn from the seed; the body is well formed and
    /// its own CRC passes, so only its declared identity gives it away.
    pub swap: Vec<u32>,
    /// S5: article positions whose every answer is preceded by
    /// [`Serve::slow_ttfb_ms`] of dead air.
    pub slow_ttfb: Vec<u32>,
    /// The dead air [`Serve::slow_ttfb`] opens, in ms. Required when
    /// that list is non-empty: a delay of zero is not a fault.
    pub slow_ttfb_ms: u64,
    /// S6: further servers, each with its own fault plan, in the order
    /// the client's config lists them.
    pub second: Vec<SecondServer>,
}

/// S6: one additional server, carrying the same fault plan a first
/// server does.
///
/// Spelled out rather than flattened over [`Serve`] because
/// `deny_unknown_fields` and `flatten` cannot both hold, and refusing a
/// typo in a fault plan is worth the repeated field list. Only the
/// SCHEMA repeats: the mapping onto `nzbkit::mock::Chaos` is written
/// once, in `crate::serve`, over a view both of these produce.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct SecondServer {
    pub missing: Vec<u32>,
    pub missing_pct: f64,
    pub corrupt: Vec<u32>,
    pub missing_once_pct: f64,
    pub corrupt_pct: f64,
    pub corrupt_once_pct: f64,
    pub truncate: Vec<u32>,
    pub stall: Vec<u32>,
    pub stall_pre: Vec<u32>,
    pub swap: Vec<u32>,
    pub slow_ttfb: Vec<u32>,
    pub slow_ttfb_ms: u64,
}

// ---------------------------------------------------------------------
// The expectation
// ---------------------------------------------------------------------

/// `[expect]`: the end state the oracle asserts. The generator derives
/// it from the source and the planes; a profile overrides it ONLY to
/// pin a known gap, and then `gap` says why in words.
#[derive(Debug, Clone, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Expect {
    /// Whether the client is expected to end with every source file,
    /// under its real name, byte for byte.
    pub complete: bool,
    /// Non-empty ONLY on a profile that pins today's behaviour rather
    /// than the right behaviour. The coverage report lists the profile
    /// under this text and counts the planes it selects as contemplated
    /// rather than recognised, so a gap is never papered over by an
    /// assertion that agrees with today.
    pub gap: String,
    /// On a gap row, which SOURCE files today's client actually ends
    /// with, under the names the layout carries for them. Everything
    /// else the layout carries has to be ABSENT, which is what makes a
    /// gap row go red the day the engine gets better rather than
    /// quietly keeping its old verdict.
    ///
    /// Empty on a gap row means the client ends with none of them. Only
    /// legal beside `complete = false` and a `gap` text: an `arrives`
    /// list on a row that claims to be complete is the rubber stamp
    /// this whole table exists to refuse.
    pub arrives: Vec<String>,
    /// Whether the process is expected to exit zero, when the answer
    /// is NOT the one `complete` implies.
    ///
    /// Unset is the requirement, and it is a real one in both
    /// directions: a run that delivers every source file must exit
    /// zero, and a run that cannot must say so rather than reporting
    /// success. Writing it therefore always pins a gap and always needs
    /// a `gap` text - `"nonzero"` on a complete row is the shape
    /// `complete` cannot describe, where every file arrived correctly
    /// and the process reported failure anyway.
    pub exits: Option<Exit>,
    /// 7.I: the identification rung the layout is expected to survive.
    pub ladder: Ladder,
}

/// `[expect] exits`.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Exit {
    Zero,
    Nonzero,
}

impl Default for Expect {
    fn default() -> Self {
        Self {
            complete: true,
            gap: String::new(),
            arrives: Vec::new(),
            exits: None,
            ladder: Ladder::default(),
        }
    }
}

/// `[expect.ladder]`: which rung of the evidence ladder identification
/// is expected to reach (body-probe, msgid-set, par2-set-id,
/// md5-manifest, sparse-blake3, crc32-len, hash16k-len, adjacency).
/// Empty means the profile makes no claim.
#[derive(Debug, Clone, Default, PartialEq, Deserialize)]
#[serde(default, deny_unknown_fields)]
pub struct Ladder {
    pub reaches: String,
}

// ---------------------------------------------------------------------
// Loading and validation
// ---------------------------------------------------------------------

/// Why a profile did not load.
#[derive(Debug)]
pub enum ProfileError {
    /// The file could not be read.
    Read(PathBuf, std::io::Error),
    /// The TOML did not parse, or named a field no table has.
    Syntax(Box<toml::de::Error>),
    /// It parsed, and the planes it selects cannot all hold at once.
    Invalid(Contradiction),
}

impl fmt::Display for ProfileError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::Read(p, e) => write!(f, "cannot read profile {}: {e}", p.display()),
            Self::Syntax(e) => write!(f, "profile does not parse: {e}"),
            Self::Invalid(c) => write!(f, "contradictory profile: {c}"),
        }
    }
}

impl std::error::Error for ProfileError {}

impl From<Contradiction> for ProfileError {
    fn from(c: Contradiction) -> Self {
        Self::Invalid(c)
    }
}

/// A pair of plane selections that cannot both hold. One variant per
/// rule so a test can name the rule it is proving rather than matching
/// on a message.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Contradiction {
    /// The file names a schema this build does not implement.
    FormatVersion { found: u32, expected: u32 },
    /// `[layout] name` is not a name this generator can write a file
    /// under: empty, an absolute path, a `..` component, or (unlike a
    /// `[source]` name) any `/` at all - it names the NZB file itself,
    /// not a tree entry, so a separator has no directory to mean.
    LayoutNameUnsafe(String),
    /// Nothing to post.
    NoSourceFiles,
    /// Two source files with the same name: the layout would be
    /// ambiguous before any plane is applied.
    DuplicateSourceName(String),
    /// `[source] periodic = true`; see [`Source::periodic`].
    PeriodicSource,
    /// Encryption selected with no password to open it.
    EncryptionWithoutPassword,
    /// The NZB is told to carry a password the container does not have.
    NzbPasswordWithoutPassword,
    /// `covers = "first"` where the set provably has one member, so it
    /// says exactly what `all` says and the profile does not select P8.
    CoversFirstWithOneFile,
    /// Names come only from FileDesc packets, and no FileDesc packet is
    /// emitted.
    NoNameSource,
    /// Redundancy asked for with no recovery set to carry it.
    RedundancyWithoutRecoverySet,
    /// `[expect] complete = false` with no `gap` text, or an `arrives`
    /// list on a row that claims to be complete.
    GapRowContradiction(&'static str),
    /// G2: a `zero_head` longer than the file it heads.
    ZeroHeadPastTheFile { name: String, head: u64, bytes: u64 },
    /// G2: a `zero_head` beside a recovery set whose block size is left
    /// for the creator to derive, so the refusal below cannot be checked
    /// from the file.
    ZeroHeadNeedsAStatedBlockSize(String),
    /// G2: a `zero_head` at or past the set's block size, where two
    /// members with heads would hand the creator an identical recovery
    /// block - [`Source::periodic`]'s trap in miniature.
    ZeroHeadReachesAWholeBlock { name: String, head: u64, block: u64 },
    /// G8: `content` on a `same_as` entry, whose bytes are another
    /// file's by definition.
    ContentOnADedupeCopy(String),
    /// G8: `content` beside a `zero_head`, where one transform eats the
    /// other's evidence.
    ContentBesideAZeroHead(String),
    /// G8: `content = "mpegts"` on a file too short to carry the
    /// packet stride a sniffer looks for.
    MpegtsTooShortToSync { name: String, bytes: u64, need: u64 },
    /// G8: `content = "compressible"` beside a recovery set. The one
    /// arm of [`Content`] whose bytes are kept away from par2gen
    /// entirely rather than argued safe.
    CompressibleUnderARecoverySet(String),
    /// G1: `[fault] corrupt_payload` names a file `[source]` does not
    /// have.
    DamageNoSuchFile(String),
    /// G1: a damage span of zero bytes, or one reaching past the file's
    /// declared length.
    DamageOffTheFile {
        file: String,
        at: u64,
        bytes: u64,
        length: u64,
    },
    /// G7: a phantom member that names a `[source]` file, so it is not
    /// a phantom at all.
    PhantomNamesAPostedFile(String),
    /// G7: a 0-byte phantom, which is [`Recovery::zero_byte_member`]'s
    /// shape wearing this plane's name.
    PhantomWithoutBytes(String),
    /// P10: a decoy whose name does not end `.par2`, so it is not the
    /// shape this key exists to pose.
    DecoyIsNotPar2Named(String),
    /// P10: a decoy whose name is already a posted file's, so the post
    /// would carry two files under one name.
    DecoyNameCollides(String),
    /// A decoy name that is not a name this generator can write a file
    /// under: empty, an absolute path, or a `..` component. Checked
    /// before [`Contradiction::DecoyIsNotPar2Named`] would even matter -
    /// an unsafe name is unsafe whatever its extension.
    DecoyNameUnsafe(String),
    /// G5: a `same_as` that names nothing this profile lists before it,
    /// names itself, or names another `same_as` entry.
    SameAsNotAnEarlierFile { name: String, points_at: String },
    /// G5: a `same_as` entry whose declared length is not the length of
    /// the file it copies.
    SameAsLengthDiffers {
        name: String,
        bytes: u64,
        source_bytes: u64,
    },
    /// G5: a `same_as` entry beside a head of its own, or beside a
    /// container.
    SameAsCannotHold(&'static str),
    /// G4: `[companion] sfv_name` written with `sfv = false`, so the
    /// name names nothing.
    CompanionNameWithoutACompanion,
    /// G4: an `.sfv` whose own name collides with a `[source]` file.
    CompanionNameCollides(String),
    /// G4: a `sfv_name` that is not a name this generator can write a
    /// file under: empty, an absolute path, or a `..` component.
    CompanionNameUnsafe(String),
    /// G3: `split_names` written without a `split`.
    SplitNamesWithoutASplit(String),
    /// G3: a split of fewer than two parts, or of more parts than the
    /// file has bytes.
    SplitCountNotAPart {
        name: String,
        split: u32,
        bytes: u64,
    },
    /// G3: a split beside a selection this stage cannot hold - a
    /// container, a dedupe copy, or a second `[source]` entry.
    SplitCannotHold(&'static str),
    /// G6: `outer = true` over a set that is already announced, so
    /// there is no chain for it to be the head of.
    OuterSetOverAnAnnouncedSet,
    /// H2: `[container] nested` written beside `[[container.inner]]`,
    /// which are two spellings of the same depth.
    NestedBesideInnerLevels { nested: u32, levels: usize },
    /// H2: an inner level whose `kind` is `none`, which is not a level.
    InnerLevelWithoutAnArchive(usize),
    /// H2: `[[container.inner]]` written with no `[container] kind`, so
    /// the stack has inner levels and no outermost one.
    InnerLevelsWithoutAContainer,
    /// H3: a sibling in a profile with no container to carry it.
    SiblingWithoutAContainer(String),
    /// H3: a 0-byte sibling, which is the recovery plane's shape.
    SiblingWithoutBytes(String),
    /// H3: two files that would land under one name - two siblings, or
    /// a sibling and a `[source]` file.
    SiblingNameCollides(String),
    /// A sibling that states both a length and a content.
    SiblingBytesAndText(String),
    /// An inner level that encrypts with no password at that level and
    /// none on `[container]` to inherit.
    InnerEncryptionWithoutPassword(usize),
    /// H5: a `corrupt_payload` entry naming both a file and a level, or
    /// neither.
    DamageNamesBothOrNeither,
    /// H5: `inner_level` written with no `[[container.inner]]` table at
    /// that position.
    DamageNoSuchLevel { level: u32, levels: usize },
}

impl fmt::Display for Contradiction {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            Self::FormatVersion { found, expected } => write!(
                f,
                "[layout] format_version = {found}, but this build implements v{expected}"
            ),
            Self::LayoutNameUnsafe(n) => write!(
                f,
                "[layout] name {n:?} is not a name this generator can write a file under: it \
                 must be relative, non-empty, hold no \"..\" component and no \"/\" at all - \
                 it names the NZB itself, not a tree entry a \"/\" could put in a directory"
            ),
            Self::NoSourceFiles => f.write_str("[source] files is empty: there is nothing to post"),
            Self::DuplicateSourceName(n) => write!(
                f,
                "[source] names {n} twice: the layout would be ambiguous before any plane \
                 is applied"
            ),
            Self::PeriodicSource => f.write_str(
                "[source] periodic = true is never allowed: par2cmdline 0.8.1 miscounts \
                 identical recovery blocks, so the interop check disagrees by environment",
            ),
            Self::EncryptionWithoutPassword => f.write_str(
                "[container] encryption is on and password is empty: nothing could open it",
            ),
            Self::NzbPasswordWithoutPassword => f.write_str(
                "[nzb] meta_password = true with no [container] password: the meta would be a lie \
                 rather than a password source",
            ),
            Self::CoversFirstWithOneFile => f.write_str(
                "[recovery] covers = \"first\" over a one-member set says what \"all\" says: \
                 P8 partial coverage is not selected",
            ),
            Self::NoNameSource => f.write_str(
                "[recovery] names = \"filedesc-only\" with no FileDesc packet emitted \
                 (no recovery set, or an index-only set whose index is absent): \
                 the layout has no name source at all",
            ),
            Self::RedundancyWithoutRecoverySet => f.write_str(
                "[recovery] redundancy_pct > 0 with kind = \"none\": no set would carry it",
            ),
            Self::ZeroHeadPastTheFile { name, head, bytes } => write!(
                f,
                "[source] {name:?} has zero_head = {head} and bytes = {bytes}: a head longer \
                 than the file is a file that is entirely zeros, which is the periodic \
                 payload this schema refuses by name"
            ),
            Self::ZeroHeadNeedsAStatedBlockSize(name) => write!(
                f,
                "[source] {name:?} has a zero_head beside a recovery set with \
                 [recovery] block_bytes = 0. The head has to be shorter than the set's \
                 block or two headed members hand the creator an identical recovery block, \
                 and a block size the creator derives is not a number this file can be \
                 checked against. State block_bytes"
            ),
            Self::ZeroHeadReachesAWholeBlock { name, head, block } => write!(
                f,
                "[source] {name:?} has zero_head = {head} and [recovery] block_bytes = \
                 {block}: the head fills a whole recovery block, so two headed members \
                 would hand par2gen the same block. That is [source] periodic = true's \
                 trap in miniature - par2cmdline 0.8.1 miscounts identical recovery blocks \
                 - and it is the ONE shape a zero head must not reach. Shorten the head, or \
                 raise block_bytes: a head over 16384 already collides the \
                 (length, md5-16k) matcher key, which is what the identical-head family is \
                 about"
            ),
            Self::ContentOnADedupeCopy(name) => write!(
                f,
                "[source] {name:?} states a content shape beside same_as. A dedupe copy's \
                 bytes ARE the file it names - that is the whole claim the entry makes - so \
                 it draws nothing of its own and there is nothing here to shape. Put the \
                 content on the file it points at"
            ),
            Self::ContentBesideAZeroHead(name) => write!(
                f,
                "[source] {name:?} states a content shape beside a zero_head. Both make the \
                 bytes not-noise and the head is applied LAST, so it would overwrite exactly \
                 the leading bytes the content shape exists to put there - a row that selects \
                 both is a row whose point one of them silently removes. Select one"
            ),
            Self::MpegtsTooShortToSync { name, bytes, need } => write!(
                f,
                "[source] {name:?} has content = \"mpegts\" and bytes = {bytes}, under the \
                 {need} a transport stream needs to SYNC. One 0x47 is one byte of evidence \
                 and every sniffer worth the name reads the 188-byte stride instead, over \
                 several packets (nzbfast's own is nzbfast_unpack::smart::videoext, at four). \
                 A file too short to carry the stride is a row that selects the shape and \
                 emits nothing recognisable, which is the profile that passes because the \
                 thing it asked for was never there"
            ),
            Self::CompressibleUnderARecoverySet(name) => write!(
                f,
                "[source] {name:?} has content = \"compressible\" beside a [recovery] set. \
                 Compressible bytes are the one content shape that sits near [source] \
                 periodic = true, which is refused because par2cmdline 0.8.1 miscounts \
                 identical recovery blocks - so this arm keeps the two apart the way a \
                 reader can check from the file: par2gen never sees a byte of it. (The \
                 construction is independently safe - runs are bounded well under any block, \
                 so no block it makes can be constant - and this refusal is what makes that \
                 a belt rather than the only brace.) A set BESIDE A CONTAINER is a different \
                 matter and is allowed: it is cut over the volumes, which are an archive's \
                 output and incompressible by the act of having compressed them, so the \
                 payload never reaches par2gen. Select a [container], or drop the set"
            ),
            Self::DamageNoSuchFile(n) => write!(
                f,
                "[fault] corrupt_payload names {n:?}, which is not a file in [source]. \
                 The span is written into a payload file, so it can only name one"
            ),
            Self::DamageOffTheFile {
                file,
                at,
                bytes,
                length,
            } => write!(
                f,
                "[fault] corrupt_payload spoils {bytes} byte(s) at offset {at} of {file:?}, \
                 which is {length} bytes long. Damage that falls off the end of a file is \
                 no damage at all, and a zero-byte span is not damage either"
            ),
            Self::PhantomNamesAPostedFile(n) => write!(
                f,
                "[recovery] phantom_covers names {n:?}, which is also a [source] file. A \
                 phantom is a member the post does NOT carry - naming one it does carry \
                 makes the foreign set a second description of a real file, which is \
                 [fault] duplicate_set (F6)"
            ),
            Self::PhantomWithoutBytes(n) => write!(
                f,
                "[recovery] phantom_covers names {n:?} with bytes = 0. A described-and-never\
                 -posted member of ZERO length is the P5 placeholder, which is \
                 zero_byte_member over a [source] entry and is a shape the client is \
                 required to materialise. A phantom is the opposite requirement, so it \
                 needs bytes the post could not have carried"
            ),
            Self::DecoyIsNotPar2Named(n) => write!(
                f,
                "[recovery] decoy is named {n:?}, and P10 is the `.par2` NAME over bytes                  that are not a set. A decoy under any other name poses nothing: it is an                  ordinary file, and the post already carries those. Give it a name ending                  in `.par2`"
            ),
            Self::DecoyNameCollides(n) => write!(
                f,
                "[recovery] decoy is named {n:?}, which the post already carries under that                  name. Two files under one name have no output tree this oracle can grade,                  and the shape the row wants is a decoy BESIDE what the post carries"
            ),
            Self::DecoyNameUnsafe(n) => write!(
                f,
                "[recovery] decoy is named {n:?}, which is not a name this generator can \
                 write a file under: it must be relative, non-empty, and hold no \"..\" \
                 component"
            ),
            Self::SameAsNotAnEarlierFile { name, points_at } => write!(
                f,
                "[source] {name:?} has same_as = {points_at:?}, which is not a plain \
                 [source] file listed BEFORE it. The copy is made as the payload is drawn, \
                 in list order, so the file it copies has to exist already - and it may not \
                 be a same_as entry itself, because a chain of copies is one duplicate \
                 written twice rather than a shape a poster produces"
            ),
            Self::SameAsLengthDiffers {
                name,
                bytes,
                source_bytes,
            } => write!(
                f,
                "[source] {name:?} declares bytes = {bytes} and copies a file of \
                 {source_bytes} bytes. The dedupe shape is two descriptors over ONE set of \
                 bytes, so the two lengths are the same number and the profile says it \
                 twice on purpose - a reader can see the pair without resolving the link"
            ),
            Self::SameAsCannotHold(why) => write!(
                f,
                "[source] same_as {why}. The entry is described by the recovery set and \
                 never posted, so its bytes are the other file's in every particular"
            ),
            Self::CompanionNameWithoutACompanion => f.write_str(
                "[companion] sfv_name is written with sfv = false, so it names a sidecar the \
                 layout does not carry. Set sfv = true, or drop the name",
            ),
            Self::CompanionNameCollides(n) => write!(
                f,
                "[companion] the sidecar would be posted as {n:?}, which is also a [source] \
                 file. The sidecar is posted under its own name whatever the naming plane \
                 says - it is the one file in an obfuscated post that has to be findable - \
                 so a collision is two files under one name on the wire"
            ),
            Self::CompanionNameUnsafe(n) => write!(
                f,
                "[companion] sfv_name {n:?} is not a name this generator can write a file \
                 under: it must be relative, non-empty, and hold no \"..\" component"
            ),
            Self::SplitNamesWithoutASplit(n) => write!(
                f,
                "[source] {n:?} writes split_names with no split, so it names a side of a \
                 cut the layout does not make"
            ),
            Self::SplitCountNotAPart { name, split, bytes } => write!(
                f,
                "[source] {name:?} asks for split = {split} over {bytes} bytes. A split is \
                 two parts or more - one part is the file - and every part has to carry at \
                 least a byte"
            ),
            Self::SplitCannotHold(why) => write!(
                f,
                "[source] split {why}. A raw split posts the ONE file as several wire files \
                 and lands it joined, so what the client must end with is that file and \
                 nothing else - an end state this generator can derive only over a post it \
                 can describe whole"
            ),
            Self::NestedBesideInnerLevels { nested, levels } => write!(
                f,
                "[container] nested = {nested} is written beside {levels} \
                 [[container.inner]] table(s), and the two are the same number said twice. \
                 nested says \"this many further levels, all like this one\"; the inner \
                 tables say what each level IS, and their COUNT is the depth. Resolving a \
                 disagreement by precedence would be a silent answer to a question the \
                 profile asked out loud, so it is refused: drop nested, or drop the tables"
            ),
            Self::InnerLevelWithoutAnArchive(i) => write!(
                f,
                "[[container.inner]] entry {i} has kind = \"none\", which is not a level. \
                 C0 means the payload files are posted as they are, and a nesting level is \
                 by definition an archive holding the level below it - so a `none` entry \
                 would be a level that is neither an archive nor absent. Give it a kind, or \
                 delete the table"
            ),
            Self::InnerLevelsWithoutAContainer => f.write_str(
                "[[container.inner]] describes the levels BELOW the posted set, and \
                 [container] kind = \"none\" says there is no posted set. The outermost \
                 level is [container] itself: give it a kind, or drop the inner tables",
            ),
            Self::SiblingWithoutAContainer(n) => write!(
                f,
                "[container] siblings names {n:?} and this profile has no container to carry \
                 it. A sibling is an extra file INSIDE an archive level, beside the archive \
                 below it; with no container the posted files are the payload itself, and an \
                 extra one is a [source] entry"
            ),
            Self::SiblingWithoutBytes(n) => write!(
                f,
                "[container] siblings names {n:?} with bytes = 0. A described member with no \
                 bytes is [recovery] zero_byte_member's shape, whose requirement is about a \
                 FileDesc packet rather than about an archive entry, and the two would be \
                 graded differently for the same profile. Give it a length"
            ),
            Self::InnerEncryptionWithoutPassword(i) => write!(
                f,
                "[[container.inner]] entry {i} sets encryption with an empty password, and \
                 [container] password is empty too, so there is nothing for it to inherit and \
                 nothing could open the level. Give the level its own password, or give the \
                 whole stack one on [container]"
            ),
            Self::SiblingBytesAndText(n) => write!(
                f,
                "[container] siblings names {n:?} with BOTH bytes and text, which are two \
                 answers to what the file holds: bytes is noise of a stated length, text is \
                 the content itself. Drop whichever one you did not mean - a password note \
                 wants text, a filler member wants bytes"
            ),
            Self::SiblingNameCollides(n) => write!(
                f,
                "[container] two files would land under {n:?}: two siblings, or a sibling and \
                 a [source] file. Every level of a stack extracts into ONE output directory, \
                 so a name repeated at two depths is one file overwriting another and the \
                 expectation could not say which won"
            ),
            Self::DamageNamesBothOrNeither => f.write_str(
                "[fault] a corrupt_payload entry names a `file` and an `inner_level`, or \
                 neither. One entry spoils one thing: a [source] file's bytes, written after \
                 the posted recovery set was cut over them, or a nesting level's archive, \
                 written after that level's own set was cut. Write exactly one",
            ),
            Self::DamageNoSuchLevel { level, levels } => write!(
                f,
                "[fault] corrupt_payload has inner_level = {level} and this profile writes \
                 {levels} [[container.inner]] table(s). The index counts them in the order \
                 they are written, outermost inner level first, which is the same numbering \
                 the stack is described in. A uniform `nested = N` stack has no tables to \
                 point at, so a levelled damage needs the per-level spelling; and the \
                 OUTERMOST level is not addressable here at all, because damaging what goes \
                 on the wire is [fault] corrupt_headers (F3) and truncate_last_volume_bytes \
                 (F5), where the POSTED set is what repairs it"
            ),
            Self::OuterSetOverAnAnnouncedSet => f.write_str(
                "[recovery] outer = true needs names = \"opaque\". The outer set exists to \
                 NAME the inner set's files, and an announced set is already named - so the \
                 chain would have nothing in it and a client would pass the row without \
                 chasing anything",
            ),
            Self::GapRowContradiction(why) => write!(
                f,
                "[expect] {why}. A gap row pins what the engine DOES today rather than what \
                 it should do, and it is the ONE override allowed: complete = false says the \
                 client does not end with every source file, gap says in words why that is \
                 not the right answer, and arrives says which of them it does end with"
            ),
        }
    }
}

impl Expect {
    /// Whether the process is expected to exit zero: the `exits`
    /// override if the profile wrote one, and otherwise what `complete`
    /// implies. One place, because the derivation is a rule and not a
    /// default value serde can hold.
    pub fn exit_zero(&self) -> bool {
        match self.exits {
            Some(Exit::Zero) => true,
            Some(Exit::Nonzero) => false,
            None => self.complete,
        }
    }
}

impl Profile {
    /// Parse and validate one profile. The only loader: nothing in this
    /// crate hands a later stage a profile that has not been through
    /// [`Profile::validate`].
    pub fn parse(text: &str) -> Result<Self, ProfileError> {
        let p: Self = toml::from_str(text).map_err(|e| ProfileError::Syntax(Box::new(e)))?;
        p.validate()?;
        Ok(p)
    }

    /// [`Profile::parse`] over a file, naming the path when the read
    /// fails. The catalog walk and the oracle's build step use this.
    pub fn load(path: &Path) -> Result<Self, ProfileError> {
        let text =
            std::fs::read_to_string(path).map_err(|e| ProfileError::Read(path.to_path_buf(), e))?;
        Self::parse(&text)
    }

    /// Refuse plane selections that cannot all hold at once.
    ///
    /// Public because a hand-built `Profile` (a generator test, a
    /// future `postfast gen --set`) owes the same check as a file.
    pub fn validate(&self) -> Result<(), Contradiction> {
        if self.layout.format_version != FORMAT_VERSION {
            return Err(Contradiction::FormatVersion {
                found: self.layout.format_version,
                expected: FORMAT_VERSION,
            });
        }
        if assemble::check_name(&self.layout.name).is_err() || self.layout.name.contains('/') {
            return Err(Contradiction::LayoutNameUnsafe(self.layout.name.clone()));
        }
        if self.source.files.is_empty() {
            return Err(Contradiction::NoSourceFiles);
        }
        let mut seen = HashSet::new();
        for f in &self.source.files {
            if !seen.insert(f.name.as_str()) {
                return Err(Contradiction::DuplicateSourceName(f.name.clone()));
            }
        }
        if self.source.periodic {
            return Err(Contradiction::PeriodicSource);
        }
        if !self.companion.sfv && !self.companion.sfv_name.is_empty() {
            return Err(Contradiction::CompanionNameWithoutACompanion);
        }
        if self.companion.sfv {
            let n = self.companion.sfv_file_name();
            if assemble::check_name(n).is_err() {
                return Err(Contradiction::CompanionNameUnsafe(n.to_string()));
            }
            if self.source.files.iter().any(|f| f.name == n) {
                return Err(Contradiction::CompanionNameCollides(n.to_string()));
            }
        }
        if self.recovery.outer && self.recovery.names != RecoveryNames::Opaque {
            return Err(Contradiction::OuterSetOverAnAnnouncedSet);
        }
        self.check_nesting_levels()?;
        self.check_siblings()?;
        self.check_split()?;
        self.check_same_as()?;
        self.check_zero_heads()?;
        self.check_content()?;
        self.check_payload_damage()?;
        for ph in &self.recovery.phantom_covers {
            if self.source.files.iter().any(|f| f.name == ph.name) {
                return Err(Contradiction::PhantomNamesAPostedFile(ph.name.clone()));
            }
            if ph.bytes == 0 {
                return Err(Contradiction::PhantomWithoutBytes(ph.name.clone()));
            }
        }
        if let Some(d) = &self.recovery.decoy {
            if assemble::check_name(&d.name).is_err() {
                return Err(Contradiction::DecoyNameUnsafe(d.name.clone()));
            }
            // ASCII-insensitive: the poster chooses the spelling and a
            // client's own extension test is case-insensitive, so
            // `.PAR2` is the same claim and the same row.
            if !std::path::Path::new(&d.name)
                .extension()
                .is_some_and(|e| e.eq_ignore_ascii_case("par2"))
            {
                return Err(Contradiction::DecoyIsNotPar2Named(d.name.clone()));
            }
            // Against the SOURCE names and the sidecar, which are the
            // names this schema knows. A collision with a name the
            // recovery plane mints for itself is refused where that
            // plane knows them, in `crate::recovery`.
            if self.source.files.iter().any(|f| f.name == d.name)
                || (self.companion.sfv && self.companion.sfv_file_name() == d.name)
            {
                return Err(Contradiction::DecoyNameCollides(d.name.clone()));
            }
        }
        if self.container.encryption != Encryption::None && self.container.password.is_empty() {
            return Err(Contradiction::EncryptionWithoutPassword);
        }
        // The same rule one level down, where "empty" has a second
        // meaning: an inner level with no password of its own uses
        // `[container] password`, so the refusal is only for a level
        // that encrypts when there is no password ANYWHERE to inherit.
        for (i, l) in self.container.inner.iter().enumerate() {
            if l.encryption != Encryption::None
                && l.password.is_empty()
                && self.container.password.is_empty()
            {
                return Err(Contradiction::InnerEncryptionWithoutPassword(i));
            }
        }
        if self.nzb.meta_password && self.container.password.is_empty() {
            return Err(Contradiction::NzbPasswordWithoutPassword);
        }
        if self.recovery.kind == RecoveryKind::None && self.recovery.redundancy_pct > 0 {
            return Err(Contradiction::RedundancyWithoutRecoverySet);
        }
        // The name source the profile declares has to exist. With no
        // recovery set there is no FileDesc packet at all; with an
        // index-only set (0 % redundancy) the index IS the only file,
        // so removing it removes every packet with it.
        if self.recovery.names == RecoveryNames::FiledescOnly
            && (self.recovery.kind == RecoveryKind::None
                || (self.recovery.index == IndexState::Absent && self.recovery.redundancy_pct == 0))
        {
            return Err(Contradiction::NoNameSource);
        }
        if self.recovery.covers == Covers::First && self.recovery_members() == Some(1) {
            return Err(Contradiction::CoversFirstWithOneFile);
        }
        if !self.expect.complete && self.expect.gap.is_empty() {
            return Err(Contradiction::GapRowContradiction(
                "complete = false with no gap text",
            ));
        }
        if self.expect.complete && !self.expect.arrives.is_empty() {
            return Err(Contradiction::GapRowContradiction(
                "arrives is set beside complete = true, so it names files the row already \
                 asserts arrive",
            ));
        }
        if self.expect.exits.is_some() && self.expect.gap.is_empty() {
            return Err(Contradiction::GapRowContradiction(
                "exits is written with no gap text. Unset is the requirement in both \
                 directions - a run that delivers everything exits zero, and one that \
                 cannot says so - so writing it always pins a gap",
            ));
        }
        if !self.expect.gap.is_empty() && self.expect.complete && self.expect.exits.is_none() {
            return Err(Contradiction::GapRowContradiction(
                "gap is set beside complete = true and no exits override: a row that \
                 asserts today's answer is right in every particular is not pinning a gap",
            ));
        }
        Ok(())
    }

    /// H2: refuse a nested stack that says its own depth twice, or an
    /// inner level that is not a level.
    fn check_nesting_levels(&self) -> Result<(), Contradiction> {
        let c = &self.container;
        if c.inner.is_empty() {
            return Ok(());
        }
        if c.nested > 0 {
            return Err(Contradiction::NestedBesideInnerLevels {
                nested: c.nested,
                levels: c.inner.len(),
            });
        }
        if c.kind == ContainerKind::None {
            return Err(Contradiction::InnerLevelsWithoutAContainer);
        }
        for (i, level) in c.inner.iter().enumerate() {
            if level.kind == ContainerKind::None {
                return Err(Contradiction::InnerLevelWithoutAnArchive(i));
            }
        }
        Ok(())
    }

    /// H3: refuse a sibling nothing would carry, one with no bytes, and
    /// any two files that would land under one name.
    ///
    /// The collision rule is over the WHOLE stack and the `[source]`
    /// list together, because every level extracts into one output
    /// directory: a name repeated at two depths is one file
    /// overwriting another, and the expectation could not say which
    /// won. The generated inner-archive names are not checked here -
    /// they carry a `.innerN.` infix this crate mints and a `[source]`
    /// or sibling name that collided with one would be a profile
    /// deliberately impersonating the generator, which the round trip
    /// inside `crate::container` catches by name.
    fn check_siblings(&self) -> Result<(), Contradiction> {
        let c = &self.container;
        let all: Vec<&Sibling> = c
            .siblings
            .iter()
            .chain(c.inner.iter().flat_map(|l| l.siblings.iter()))
            .collect();
        if all.is_empty() {
            return Ok(());
        }
        if c.kind == ContainerKind::None {
            return Err(Contradiction::SiblingWithoutAContainer(all[0].name.clone()));
        }
        let mut seen: HashSet<&str> = self.source.files.iter().map(|f| f.name.as_str()).collect();
        for s in all {
            match (s.bytes, s.text.as_deref()) {
                // Both: two answers to what the file holds, and the
                // length would silently win or silently lose.
                (b, Some(_)) if b > 0 => {
                    return Err(Contradiction::SiblingBytesAndText(s.name.clone()));
                }
                // Neither.
                (0, None) => {
                    return Err(Contradiction::SiblingWithoutBytes(s.name.clone()));
                }
                // A text that says nothing is the same empty member as
                // bytes = 0, reached by the other spelling.
                (_, Some(t)) if t.trim().is_empty() => {
                    return Err(Contradiction::SiblingWithoutBytes(s.name.clone()));
                }
                _ => {}
            }
            if !seen.insert(s.name.as_str()) {
                return Err(Contradiction::SiblingNameCollides(s.name.clone()));
            }
        }
        Ok(())
    }

    /// G3: refuse a split this stage cannot derive an end state for.
    ///
    /// **The one-file rule is the load-bearing one, and it is a stated
    /// limitation rather than an oversight.** With a split, the wire
    /// files and the `[source]` files are not one to one, so the
    /// positional walk every other stage makes over the payload no
    /// longer lines up - and the end state of a MIXED post, where one
    /// member is joined out of parts and another is named by the wire
    /// or by a descriptor, has no derivation this generator can state.
    /// The three legs the plane exists for (n18, n19, n33) are each one
    /// logical file, which is what the shape is in the field: a poster
    /// cutting a release into raw parts cuts one file.
    fn check_split(&self) -> Result<(), Contradiction> {
        let splits = self
            .source
            .files
            .iter()
            .filter(|f| f.split > 0)
            .collect::<Vec<_>>();
        for f in &self.source.files {
            if f.split == 0 && f.split_names != SplitNames::default() {
                return Err(Contradiction::SplitNamesWithoutASplit(f.name.clone()));
            }
        }
        let Some(f) = splits.first() else {
            return Ok(());
        };
        if f.split < 2 || u64::from(f.split) > f.bytes {
            return Err(Contradiction::SplitCountNotAPart {
                name: f.name.clone(),
                split: f.split,
                bytes: f.bytes,
            });
        }
        if self.source.files.len() > 1 {
            return Err(Contradiction::SplitCannotHold(
                "is written in a profile with more than one [source] file",
            ));
        }
        if self.container.kind != ContainerKind::None {
            return Err(Contradiction::SplitCannotHold(
                "is written beside a [container], whose own volume_bytes IS the split (C2)                  and whose volumes are spent by the unpack",
            ));
        }
        if !f.same_as.is_empty() {
            return Err(Contradiction::SplitCannotHold(
                "is written beside same_as, and a dedupe copy is never posted at all",
            ));
        }
        Ok(())
    }

    /// G5: refuse a `same_as` link that does not resolve backwards to
    /// a plain file of the same length.
    fn check_same_as(&self) -> Result<(), Contradiction> {
        for (i, f) in self.source.files.iter().enumerate() {
            if f.same_as.is_empty() {
                continue;
            }
            if f.zero_head != 0 {
                return Err(Contradiction::SameAsCannotHold(
                    "is written beside a zero_head of its own",
                ));
            }
            if self.container.kind != ContainerKind::None {
                return Err(Contradiction::SameAsCannotHold(
                    "is written beside a [container], where the posted files are volumes                      and the payload does not reach the wire at all",
                ));
            }
            let Some(src) = self.source.files[..i]
                .iter()
                .find(|s| s.name == f.same_as && s.same_as.is_empty())
            else {
                return Err(Contradiction::SameAsNotAnEarlierFile {
                    name: f.name.clone(),
                    points_at: f.same_as.clone(),
                });
            };
            if src.bytes != f.bytes {
                return Err(Contradiction::SameAsLengthDiffers {
                    name: f.name.clone(),
                    bytes: f.bytes,
                    source_bytes: src.bytes,
                });
            }
        }
        Ok(())
    }

    /// G2: refuse a zero head that is not a head, and the one head
    /// shape that would hand the PAR2 creator two identical blocks.
    ///
    /// The block rule is applied whenever a set exists, rather than
    /// only to the members it covers, and that is deliberate: resolving
    /// `covers` here would be a second copy of `crate::recovery`'s own
    /// selection, and the stricter rule costs an author one number on
    /// a row whose point is the head anyway.
    fn check_zero_heads(&self) -> Result<(), Contradiction> {
        let block = self.recovery.block_bytes;
        let has_set = self.recovery.kind != RecoveryKind::None;
        for f in &self.source.files {
            if f.zero_head == 0 {
                continue;
            }
            if f.zero_head > f.bytes {
                return Err(Contradiction::ZeroHeadPastTheFile {
                    name: f.name.clone(),
                    head: f.zero_head,
                    bytes: f.bytes,
                });
            }
            if !has_set {
                continue;
            }
            if block == 0 {
                return Err(Contradiction::ZeroHeadNeedsAStatedBlockSize(f.name.clone()));
            }
            if f.zero_head >= block {
                return Err(Contradiction::ZeroHeadReachesAWholeBlock {
                    name: f.name.clone(),
                    head: f.zero_head,
                    block,
                });
            }
        }
        Ok(())
    }

    /// G8: refuse a content shape that another selection has already
    /// answered, and the one arm that must never reach par2gen.
    ///
    /// The compressible rule is applied whenever a set exists rather
    /// than only to the members it covers, for the same reason
    /// [`Profile::check_zero_heads`] is: resolving `covers` here would
    /// be a second copy of `crate::recovery`'s own selection, and the
    /// stricter rule costs nothing on a plane whose rows carry no set.
    fn check_content(&self) -> Result<(), Contradiction> {
        let has_set = self.recovery.kind != RecoveryKind::None;
        for f in &self.source.files {
            if f.content == Content::Noise {
                continue;
            }
            if !f.same_as.is_empty() {
                return Err(Contradiction::ContentOnADedupeCopy(f.name.clone()));
            }
            if f.zero_head != 0 {
                return Err(Contradiction::ContentBesideAZeroHead(f.name.clone()));
            }
            match f.content {
                Content::Noise => unreachable!("skipped above"),
                Content::Mpegts => {
                    let need = crate::assemble::TS_SYNC_FLOOR;
                    if f.bytes < need {
                        return Err(Contradiction::MpegtsTooShortToSync {
                            name: f.name.clone(),
                            bytes: f.bytes,
                            need,
                        });
                    }
                }
                Content::Compressible => {
                    // The set has to be over the PAYLOAD for the rule
                    // to bite. `crate::layout::carried_files` hands
                    // `recovery::build` the outermost VOLUMES whenever
                    // a container is selected, so under one the source
                    // bytes never reach par2gen however compressible
                    // they are - and the volumes it does cut over are
                    // an archive's output, which is incompressible by
                    // the act of having compressed it. Same reasoning
                    // `check_same_as` uses about a container: the
                    // posted files are volumes and the payload does not
                    // reach the wire at all.
                    if has_set && self.container.kind == ContainerKind::None {
                        return Err(Contradiction::CompressibleUnderARecoverySet(f.name.clone()));
                    }
                }
            }
        }
        Ok(())
    }

    /// G1 and H5: refuse a damage span that names nothing, names two
    /// things, or does not land inside the file it names.
    ///
    /// A levelled span's bounds are NOT checked here and cannot be:
    /// how long a level's archive is is the writer's answer, not the
    /// profile's, so `crate::container` refuses one that does not fit
    /// and names the length it measured. A `[source]` file's length is
    /// what `[source]` itself declares, which is why that half is
    /// checkable from the file.
    fn check_payload_damage(&self) -> Result<(), Contradiction> {
        for d in &self.fault.corrupt_payload {
            if d.file.is_empty() == d.inner_level.is_none() {
                return Err(Contradiction::DamageNamesBothOrNeither);
            }
            if let Some(level) = d.inner_level {
                if usize::try_from(level).unwrap_or(usize::MAX) >= self.container.inner.len() {
                    return Err(Contradiction::DamageNoSuchLevel {
                        level,
                        levels: self.container.inner.len(),
                    });
                }
                if d.bytes == 0 {
                    return Err(Contradiction::DamageOffTheFile {
                        file: format!("[[container.inner]] {level}"),
                        at: d.at,
                        bytes: d.bytes,
                        length: 0,
                    });
                }
                continue;
            }
            let Some(f) = self.source.files.iter().find(|f| f.name == d.file) else {
                return Err(Contradiction::DamageNoSuchFile(d.file.clone()));
            };
            let end = d.at.checked_add(d.bytes);
            if d.bytes == 0 || end.is_none_or(|e| e > f.bytes) {
                return Err(Contradiction::DamageOffTheFile {
                    file: d.file.clone(),
                    at: d.at,
                    bytes: d.bytes,
                    length: f.bytes,
                });
            }
        }
        Ok(())
    }

    /// How many members the recovery set will have, where that is
    /// knowable from the profile alone. `None` for a split container,
    /// whose volume count depends on the payload size and the writer's
    /// framing and is therefore the generator's answer, not the
    /// schema's.
    fn recovery_members(&self) -> Option<usize> {
        match self.container.kind {
            ContainerKind::None => Some(self.source.files.len()),
            // A container with no volume limit is one volume, whatever
            // it holds.
            _ if self.container.volume_bytes == 0 => Some(1),
            _ => None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The smallest profile that loads: identity, a seed, one file.
    /// Every test below is a diff from this, for the same reason every
    /// profile is a diff from the neutral row.
    const MINIMAL: &str = r#"
[layout]
name = "t"
seed = 1

[source]
files = [{ name = "a.bin", bytes = 4096 }]
"#;

    fn minimal() -> Profile {
        Profile::parse(MINIMAL).expect("the minimal profile loads")
    }

    fn refusal(text: &str) -> Contradiction {
        match Profile::parse(text) {
            Err(ProfileError::Invalid(c)) => c,
            Err(other) => panic!("wanted a contradiction, got {other}"),
            Ok(_) => panic!("wanted a refusal, the profile loaded"),
        }
    }

    /// v0 is the draft-3 schema; bumping this is a catalog migration.
    #[test]
    fn format_version_is_v0() {
        assert_eq!(FORMAT_VERSION, 0);
    }

    // -----------------------------------------------------------------
    // The catalog itself
    // -----------------------------------------------------------------

    fn catalog_dir() -> PathBuf {
        Path::new(env!("CARGO_MANIFEST_DIR")).join("catalog")
    }

    /// Every profile the repo ships loads AND validates. This is the
    /// test that makes the catalog a directory of data rather than a
    /// directory of hopes: a hand-edited profile that no longer parses
    /// fails here, in a unit test, rather than in the oracle where it
    /// would read as a generator bug.
    #[test]
    fn every_catalog_profile_loads() {
        let dir = catalog_dir();
        let mut seen = 0usize;
        let mut names = HashSet::new();
        for entry in std::fs::read_dir(&dir).expect("the catalog directory exists") {
            let path = entry.expect("a readable directory entry").path();
            if path.extension().and_then(|e| e.to_str()) != Some("toml") {
                continue;
            }
            let p = match Profile::load(&path) {
                Ok(p) => p,
                Err(e) => panic!("{}: {e}", path.display()),
            };
            let stem = path
                .file_stem()
                .and_then(|s| s.to_str())
                .expect("a UTF-8 file stem")
                .to_string();
            // The oracle generates a test named after the file stem and
            // the coverage report keys on `[layout] name`, so the two
            // disagreeing would put a failure under a name no file has.
            assert_eq!(p.layout.name, stem, "{}: [layout] name", path.display());
            assert!(
                names.insert(stem),
                "{}: duplicate profile name",
                path.display()
            );
            seen += 1;
        }
        // Failing to find is failing: an empty catalog would otherwise
        // pass this test forever, which is exactly the rubber stamp a
        // catalog-walking test exists to avoid.
        assert!(seen > 0, "no profiles found in {}", dir.display());
    }

    /// The baseline is the control arm, and it is neutral on every
    /// plane. If a later chip changes a default, this is the test that
    /// says the control arm moved with it.
    #[test]
    fn the_baseline_profile_is_neutral_on_every_plane() {
        let p = Profile::load(&catalog_dir().join("n1-c0-p0-baseline.toml"))
            .expect("the baseline profile loads");
        assert_eq!(p.naming, Naming::default());
        assert_eq!(p.container, Container::default());
        assert_eq!(p.recovery, Recovery::default());
        assert_eq!(p.encoding, Encoding::default());
        assert_eq!(p.nzb, Nzb::default());
        assert_eq!(p.fault, Fault::default());
        assert_eq!(p.serve, Serve::default());
        assert!(p.expect.gap.is_empty(), "the baseline pins no gap");
        assert!(p.expect.complete);
    }

    // -----------------------------------------------------------------
    // Neutral defaults
    // -----------------------------------------------------------------

    /// An absent table is the neutral selection, plane by plane. The
    /// values are spelled out rather than compared to `Default` so this
    /// test says WHICH row is neutral and a change to one has to be
    /// made here on purpose.
    #[test]
    fn an_absent_table_is_the_neutral_row() {
        let p = minimal();
        assert_eq!(p.layout.format_version, FORMAT_VERSION);
        assert!(!p.source.periodic);

        assert_eq!(p.naming.wire, WireName::Descriptive); // N1
        assert_eq!(p.naming.subject, SubjectStyle::Descriptive);
        assert_eq!(p.naming.part_order, PartOrder::Natural);
        assert_eq!(p.naming.name_bytes, NameBytes::Utf8);

        assert_eq!(p.container.kind, ContainerKind::None); // C0
        assert_eq!(p.container.version, RarVersion::Rar5);
        assert_eq!(p.container.volume_bytes, 0);
        assert_eq!(p.container.encryption, Encryption::None);
        assert_eq!(p.container.volume_style, VolumeStyle::PartNn);
        assert_eq!(p.container.nested, 0);
        assert_eq!(p.container.leading_bytes, 0);
        assert_eq!(p.container.polyglot, Polyglot::None); // C8 neutral
        assert_eq!(p.container.recovery_record_pct, 0);

        assert_eq!(p.recovery.kind, RecoveryKind::None); // P0
        assert_eq!(p.recovery.redundancy_pct, 0);
        assert_eq!(p.recovery.names, RecoveryNames::Descriptive);
        assert_eq!(p.recovery.index, IndexState::Present);
        assert_eq!(p.recovery.covers, Covers::All);
        assert!(!p.recovery.zero_byte_member);
        assert!(p.recovery.hostile_names.is_empty());
        assert!(p.recovery.second_covers.is_empty()); // P9 neutral: one set

        assert_eq!(p.encoding.line_width, 128);
        assert_eq!(p.encoding.article_bytes, 768_000);
        assert_eq!(p.encoding.part_crc, PartCrc::Present);
        assert_eq!(p.encoding.declared_size, DeclaredSize::True);
        assert_eq!(p.encoding.trailing, Trailing::None);
        assert_eq!(p.encoding.ypart, Ypart::Present);

        assert_eq!(p.nzb.meta_name, MetaName::Faithful);
        assert!(!p.nzb.meta_password);
        assert_eq!(p.nzb.segment_bytes, SegmentBytes::True);
        assert_eq!(p.nzb.drop_segments_pct, 0.0);
        assert_eq!(p.nzb.date, NzbDate::Fresh);
        assert_eq!(p.nzb.subject, NzbSubject::Faithful);

        assert_eq!(p.fault, Fault::default());
        assert_eq!(p.serve.missing_pct, 0.0);
        assert!(p.serve.second.is_empty());

        assert!(p.expect.complete);
        assert!(p.expect.gap.is_empty());
        assert!(p.expect.ladder.reaches.is_empty());
    }

    /// A table that IS present keeps the neutral value for the keys it
    /// does not mention. Without this, stating one deviation would
    /// silently zero the rest of the plane - `line_width = 256` with a
    /// 0-byte article, say.
    #[test]
    fn a_present_table_keeps_the_neutral_value_of_the_keys_it_omits() {
        let p =
            Profile::parse(&format!("{MINIMAL}\n[encoding]\nline_width = 256\n")).expect("loads");
        assert_eq!(p.encoding.line_width, 256);
        assert_eq!(p.encoding.article_bytes, 768_000);
        assert_eq!(p.encoding.part_crc, PartCrc::Present);
    }

    // -----------------------------------------------------------------
    // Unknown fields
    // -----------------------------------------------------------------

    /// An unknown key in ANY table is a load error that names the key.
    ///
    /// One test over every table rather than fourteen, because the
    /// thing being proved is a property of the schema and a table added
    /// tomorrow needs one line here, not a new test. The assertion
    /// names the table it was checking, so a failure still says which.
    #[test]
    fn an_unknown_key_in_any_table_names_itself() {
        // Whole documents rather than snippets over MINIMAL: a case
        // that varies `[layout]` or `[source]` would otherwise declare
        // the table twice, which TOML refuses for its own reason and
        // would pass this test without ever reaching the schema.
        let cases: &[(&str, String)] = &[
            ("top level", format!("{MINIMAL}\n[nope]\nx = 1\n")),
            (
                "layout",
                "[layout]\nname = \"t\"\nseed = 1\nnope = 1\n\
                 [source]\nfiles = [{ name = \"a.bin\", bytes = 1 }]\n"
                    .to_string(),
            ),
            (
                "source",
                "[layout]\nname = \"t\"\nseed = 1\n\
                 [source]\nfiles = [{ name = \"a.bin\", bytes = 1 }]\nnope = 1\n"
                    .to_string(),
            ),
            (
                "source.files",
                "[layout]\nname = \"t\"\nseed = 1\n\
                 [source]\nfiles = [{ name = \"a.bin\", bytes = 1, nope = 1 }]\n"
                    .to_string(),
            ),
            ("naming", format!("{MINIMAL}\n[naming]\nnope = 1\n")),
            ("container", format!("{MINIMAL}\n[container]\nnope = 1\n")),
            ("recovery", format!("{MINIMAL}\n[recovery]\nnope = 1\n")),
            ("encoding", format!("{MINIMAL}\n[encoding]\nnope = 1\n")),
            ("nzb", format!("{MINIMAL}\n[nzb]\nnope = 1\n")),
            ("fault", format!("{MINIMAL}\n[fault]\nnope = 1\n")),
            ("serve", format!("{MINIMAL}\n[serve]\nnope = 1\n")),
            (
                "serve.second",
                format!("{MINIMAL}\n[[serve.second]]\nnope = 1\n"),
            ),
            ("expect", format!("{MINIMAL}\n[expect]\nnope = 1\n")),
            (
                "expect.ladder",
                format!("{MINIMAL}\n[expect.ladder]\nnope = 1\n"),
            ),
        ];
        for (table, text) in cases {
            match Profile::parse(text) {
                Err(ProfileError::Syntax(e)) => {
                    let msg = e.to_string();
                    assert!(
                        msg.contains("nope"),
                        "[{table}] refused without naming the key: {msg}"
                    );
                }
                Err(other) => panic!("[{table}] wanted a syntax error, got {other}"),
                Ok(_) => panic!("[{table}] accepted an unknown key"),
            }
        }
    }

    /// A misspelled ENUM VALUE is refused the same way. `covers` gets
    /// its own arm because it is the one hand-written `Deserialize` in
    /// the schema, and an untagged derive there would have answered
    /// "data did not match any variant" instead of naming the value.
    #[test]
    fn an_unknown_enum_value_names_itself() {
        for (key, snippet) in [
            ("wire", "[naming]\nwire = \"opake\"\n"),
            ("kind", "[container]\nkind = \"rar-stored-split\"\n"),
            ("covers", "[recovery]\ncovers = \"frist\"\n"),
        ] {
            let text = format!("{MINIMAL}\n{snippet}");
            let e = match Profile::parse(&text) {
                Err(ProfileError::Syntax(e)) => e.to_string(),
                other => panic!("{key}: wanted a syntax error, got {other:?}"),
            };
            assert!(
                e.contains("opake") || e.contains("rar-stored-split") || e.contains("frist"),
                "{key}: refused without naming the value: {e}"
            );
        }
    }

    /// `covers` still takes the two keywords and an explicit list.
    #[test]
    fn covers_takes_a_keyword_or_a_list() {
        let list = format!("{MINIMAL}\n[recovery]\ncovers = [\"a.bin\", \"b.bin\"]\n");
        let p = Profile::parse(&list).expect("a list of names loads");
        assert_eq!(
            p.recovery.covers,
            Covers::Names(vec!["a.bin".into(), "b.bin".into()])
        );
        let all = format!("{MINIMAL}\n[recovery]\ncovers = \"all\"\n");
        assert_eq!(
            Profile::parse(&all).expect("loads").recovery.covers,
            Covers::All
        );
    }

    // -----------------------------------------------------------------
    // One test per validate() rule
    // -----------------------------------------------------------------

    #[test]
    fn a_foreign_format_version_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\nformat_version = 1\n\
                    [source]\nfiles = [{ name = \"a.bin\", bytes = 1 }]\n";
        assert_eq!(
            refusal(text),
            Contradiction::FormatVersion {
                found: 1,
                expected: FORMAT_VERSION
            }
        );
    }

    #[test]
    fn an_empty_source_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n";
        assert_eq!(refusal(text), Contradiction::NoSourceFiles);
    }

    #[test]
    fn a_duplicate_source_name_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n[source]\nfiles = [\
                    { name = \"a.bin\", bytes = 1 }, { name = \"a.bin\", bytes = 2 }]\n";
        assert_eq!(
            refusal(text),
            Contradiction::DuplicateSourceName("a.bin".into())
        );
    }

    /// `[layout] name` reaches `out.join(format!("{name}.nzb"))`
    /// unchecked otherwise, so the same escapes a `[source]` name is
    /// refused for apply here - plus a bare `/`, which a source name
    /// may carry (it means a directory) but this key may not (it names
    /// the NZB itself).
    #[test]
    fn a_layout_name_that_is_unsafe_is_refused() {
        let case = |name: &str| {
            refusal(&format!(
                "[layout]\nname = {name:?}\nseed = 1\n\n\
                 [source]\nfiles = [{{ name = \"a.bin\", bytes = 4096 }}]\n"
            ))
        };
        assert_eq!(case(""), Contradiction::LayoutNameUnsafe(String::new()));
        assert_eq!(
            case("/tmp/x"),
            Contradiction::LayoutNameUnsafe("/tmp/x".into())
        );
        assert_eq!(case("a/b"), Contradiction::LayoutNameUnsafe("a/b".into()));
    }

    /// `[companion] sfv_name` reaches `files_dir.join(name)` unchecked
    /// otherwise: a `..` component escapes the output directory the
    /// same way an unchecked `[source]` name would.
    #[test]
    fn an_sfv_name_that_is_unsafe_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n\n\
                    [source]\nfiles = [{ name = \"a.bin\", bytes = 4096 }]\n\n\
                    [companion]\nsfv = true\nsfv_name = \"../../x.sfv\"\n";
        assert_eq!(
            refusal(text),
            Contradiction::CompanionNameUnsafe("../../x.sfv".into())
        );
    }

    /// `[recovery] decoy.name` reaches `files_dir.join(name)` the same
    /// way, and is checked before `DecoyIsNotPar2Named` even looks at
    /// the extension: an unsafe name is unsafe whatever it ends in.
    #[test]
    fn a_decoy_name_that_is_unsafe_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n\n\
                    [source]\nfiles = [{ name = \"a.bin\", bytes = 4096 }]\n\n\
                    [recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
                    decoy = { name = \"../d.par2\", bytes = 3072 }\n";
        assert_eq!(
            refusal(text),
            Contradiction::DecoyNameUnsafe("../d.par2".into())
        );
    }

    /// Never periodic, whatever else the profile says: par2cmdline
    /// 0.8.1 (CI's version, against 1.3.0 on the dev box) miscounts
    /// identical recovery blocks.
    #[test]
    fn a_periodic_source_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n\
                    [source]\nfiles = [{ name = \"a.bin\", bytes = 1 }]\nperiodic = true\n";
        assert_eq!(refusal(text), Contradiction::PeriodicSource);
    }

    // -----------------------------------------------------------------
    // G2 zero_head, G1 corrupt_payload
    // -----------------------------------------------------------------

    /// A head longer than the file is a file that is entirely zeros -
    /// [`Source::periodic`] under another name.
    #[test]
    fn a_zero_head_past_the_file_is_refused() {
        let text = "[layout]\nname = \"t\"\nseed = 1\n\
                    [source]\nfiles = [{ name = \"a.vob\", bytes = 100, zero_head = 101 }]\n";
        assert!(
            matches!(refusal(text), Contradiction::ZeroHeadPastTheFile { .. }),
            "a head past the file must be refused"
        );
    }

    /// The one shape a zero head must not reach: a head that fills a
    /// whole recovery block, where two headed members hand par2gen the
    /// same block. Both arms of the rule are here, because the "state
    /// block_bytes" half exists only so this half is checkable.
    #[test]
    fn a_zero_head_may_not_reach_a_whole_recovery_block() {
        let head = |extra: &str| {
            format!(
                "[layout]\nname = \"t\"\nseed = 1\n\
                 [source]\nfiles = [{{ name = \"a.vob\", bytes = 100000, zero_head = 20000 }}]\n\
                 [recovery]\nkind = \"par2\"\nredundancy_pct = 10\n{extra}"
            )
        };
        assert!(
            matches!(
                refusal(&head("")),
                Contradiction::ZeroHeadNeedsAStatedBlockSize(_)
            ),
            "a derived block size is not a number this file can be checked against"
        );
        assert!(
            matches!(
                refusal(&head("block_bytes = 16384\n")),
                Contradiction::ZeroHeadReachesAWholeBlock { .. }
            ),
            "a head at or past the block is the identical-block trap"
        );
        Profile::parse(&head("block_bytes = 32768\n"))
            .expect("a head shorter than the block loads");
        // ...and with no set at all there is no block to reach, so the
        // rule does not apply and a head needs no number beside it.
        Profile::parse(
            "[layout]\nname = \"t\"\nseed = 1\n\
             [source]\nfiles = [{ name = \"a.vob\", bytes = 100000, zero_head = 20000 }]\n",
        )
        .expect("a head with no recovery set loads");
    }

    // G8 content

    /// The one refusal that keeps the compressible arm and
    /// [`Source::periodic`] apart, and the one a reader can check from
    /// the profile text: compressible bytes never reach par2gen.
    #[test]
    fn compressible_bytes_beside_a_recovery_set_are_refused() {
        let one = |extra: &str| {
            format!(
                "[layout]\nname = \"t\"\nseed = 1\n\
                 [source]\nfiles = [{{ name = \"a.bin\", bytes = 60000, \
                 content = \"compressible\" }}]\n{extra}"
            )
        };
        let e = refusal(&one("[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n"));
        assert!(matches!(e, Contradiction::CompressibleUnderARecoverySet(_)));
        assert!(
            e.to_string().contains("par2cmdline 0.8.1"),
            "the refusal has to carry the reason, not just the rule: {e}"
        );
        // ...and with no set there is nothing to keep it away from, so
        // the plane it exists for (C3) loads.
        Profile::parse(&one("[container]\nkind = \"rar-compressed\"\n"))
            .expect("compressible bytes under a compressed container load");
        // ...and so does a set BESIDE a container, which is the shape
        // the nested-corpus r2c leg needs. `crate::layout::carried_files`
        // cuts that set over the VOLUMES, so par2gen still never sees a
        // compressible byte - the rule is unchanged and only the proxy
        // for it is narrower.
        Profile::parse(&one(
            "[container]\nkind = \"rar-stored\"\nvolume_bytes = 10000\n\n\
             [[container.inner]]\nkind = \"rar-compressed\"\n\n\
             [recovery]\nkind = \"par2\"\nredundancy_pct = 10\n",
        ))
        .expect("a set over the volumes of a compressed inner level loads");
        // The MPEG-TS arm is NOT refused beside a set: it rewrites one
        // byte in 188 and leaves the rest drawn, so two blocks are as
        // unequal as in the neutral case.
        Profile::parse(
            "[layout]\nname = \"t\"\nseed = 1\n\
             [source]\nfiles = [{ name = \"vid\", bytes = 60000, content = \"mpegts\" }]\n\
             [recovery]\nkind = \"par2\"\nredundancy_pct = 10\n",
        )
        .expect("a transport stream under a recovery set loads");
    }

    /// A file too short to carry the packet stride selects the shape
    /// and emits nothing a sniffer could see, which is the profile that
    /// passes because what it asked for was never there.
    #[test]
    fn a_transport_stream_too_short_to_sync_is_refused() {
        let n = |bytes: u64| {
            format!(
                "[layout]\nname = \"t\"\nseed = 1\n\
                 [source]\nfiles = [{{ name = \"vid\", bytes = {bytes}, \
                 content = \"mpegts\" }}]\n"
            )
        };
        match refusal(&n(crate::assemble::TS_SYNC_FLOOR - 1)) {
            Contradiction::MpegtsTooShortToSync { bytes, need, .. } => {
                assert_eq!(need, crate::assemble::TS_SYNC_FLOOR);
                assert_eq!(bytes, need - 1);
            }
            other => panic!("wanted MpegtsTooShortToSync, got {other:?}"),
        }
        Profile::parse(&n(crate::assemble::TS_SYNC_FLOOR)).expect("four whole packets load");
    }

    /// A content shape beside a selection that has already answered
    /// what the bytes are: a dedupe copy draws none of its own, and a
    /// zero head would overwrite the leading bytes the shape exists to
    /// put there.
    #[test]
    fn a_content_shape_beside_a_selection_that_answers_it_is_refused() {
        let dup = "[layout]\nname = \"t\"\nseed = 1\n\
                   [source]\nfiles = [{ name = \"one.bin\", bytes = 4096 }, \
                   { name = \"two.bin\", bytes = 4096, same_as = \"one.bin\", \
                   content = \"compressible\" }]\n";
        assert!(matches!(
            refusal(dup),
            Contradiction::ContentOnADedupeCopy(_)
        ));
        let head = "[layout]\nname = \"t\"\nseed = 1\n\
                    [source]\nfiles = [{ name = \"vid\", bytes = 60000, zero_head = 20000, \
                    content = \"mpegts\" }]\n";
        assert!(matches!(
            refusal(head),
            Contradiction::ContentBesideAZeroHead(_)
        ));
    }

    /// G1: a damage span that names nothing, or that does not land
    /// inside the file it names, is refused before any stage runs.
    #[test]
    fn a_damage_span_that_misses_the_file_is_refused() {
        let dmg = |d: &str| format!("{MINIMAL}\n[fault]\ncorrupt_payload = [{d}]\n");
        assert!(matches!(
            refusal(&dmg("{ file = \"nope.bin\", at = 0, bytes = 8 }")),
            Contradiction::DamageNoSuchFile(_)
        ));
        for span in [
            "{ file = \"a.bin\", at = 0, bytes = 0 }",
            "{ file = \"a.bin\", at = 4090, bytes = 8 }",
            "{ file = \"a.bin\", at = 4096, bytes = 1 }",
        ] {
            assert!(
                matches!(refusal(&dmg(span)), Contradiction::DamageOffTheFile { .. }),
                "{span} must be refused"
            );
        }
        Profile::parse(&dmg("{ file = \"a.bin\", at = 4088, bytes = 8 }"))
            .expect("a span that ends exactly at the end of the file loads");
    }

    #[test]
    fn encryption_without_a_password_is_refused() {
        for kind in ["data", "header"] {
            let text =
                format!("{MINIMAL}\n[container]\nkind = \"rar-stored\"\nencryption = \"{kind}\"\n");
            assert_eq!(refusal(&text), Contradiction::EncryptionWithoutPassword);
        }
        // ...and it loads once there is one.
        let ok = format!(
            "{MINIMAL}\n[container]\nkind = \"rar-stored\"\nencryption = \"data\"\npassword = \"not-a-real-password\"\n"
        );
        Profile::parse(&ok).expect("encryption with a password loads");
    }

    #[test]
    fn an_inner_level_that_encrypts_with_no_password_anywhere_is_refused() {
        let inner = |pw: &str, outer: &str| {
            format!(
                "{MINIMAL}\n[container]\nkind = \"rar-stored\"\n{outer}\n\
                 [[container.inner]]\nkind = \"rar-stored\"\nencryption = \"data\"\n{pw}\n"
            )
        };
        // Nothing at the level and nothing to inherit.
        assert_eq!(
            refusal(&inner("", "")),
            Contradiction::InnerEncryptionWithoutPassword(0)
        );
        // Its own password is enough...
        Profile::parse(&inner("password = \"inner-fixture-pw\"", ""))
            .expect("an inner level with its own password loads");
        // ...and so is one on [container] to inherit, which is what a
        // uniform chain says by saying nothing at the level.
        Profile::parse(&inner("", "password = \"stack-fixture-pw\""))
            .expect("an inner level inherits the stack's password");
    }

    #[test]
    fn a_sibling_with_both_bytes_and_text_is_refused() {
        let sib = |spec: &str| {
            format!("{MINIMAL}\n[container]\nkind = \"rar-stored\"\nsiblings = [{spec}]\n")
        };
        assert!(matches!(
            refusal(&sib("{ name = \"n.txt\", bytes = 40, text = \"hi\" }")),
            Contradiction::SiblingBytesAndText(_)
        ));
        // Neither is the older refusal, and a text that says nothing
        // reaches it by the other spelling.
        for empty in [
            "{ name = \"n.txt\" }",
            "{ name = \"n.txt\", text = \"  \" }",
        ] {
            assert!(
                matches!(refusal(&sib(empty)), Contradiction::SiblingWithoutBytes(_)),
                "{empty} must be refused"
            );
        }
        // Either one alone loads.
        Profile::parse(&sib("{ name = \"n.txt\", bytes = 40 }")).expect("a noise sibling loads");
        Profile::parse(&sib("{ name = \"n.txt\", text = \"inner-fixture-pw\" }"))
            .expect("a text sibling loads");
    }

    #[test]
    fn an_nzb_password_meta_without_a_password_is_refused() {
        let text = format!("{MINIMAL}\n[nzb]\nmeta_password = true\n");
        assert_eq!(refusal(&text), Contradiction::NzbPasswordWithoutPassword);
    }

    #[test]
    fn covers_first_over_a_one_member_set_is_refused() {
        let text = format!("{MINIMAL}\n[recovery]\nkind = \"par2\"\ncovers = \"first\"\n");
        assert_eq!(refusal(&text), Contradiction::CoversFirstWithOneFile);

        // A single volume is one member too, however many files went in.
        let one_volume = "[layout]\nname = \"t\"\nseed = 1\n\
             [source]\nfiles = [{ name = \"a.bin\", bytes = 1 }, { name = \"b.bin\", bytes = 2 }]\n\
             [container]\nkind = \"rar-stored\"\n\
             [recovery]\nkind = \"par2\"\ncovers = \"first\"\n";
        assert_eq!(refusal(one_volume), Contradiction::CoversFirstWithOneFile);

        // Two bare files, or a split container: `first` selects P8 and
        // the profile loads.
        let two_files = "[layout]\nname = \"t\"\nseed = 1\n\
             [source]\nfiles = [{ name = \"a.bin\", bytes = 1 }, { name = \"b.bin\", bytes = 2 }]\n\
             [recovery]\nkind = \"par2\"\ncovers = \"first\"\n";
        Profile::parse(two_files).expect("two members load");
        let split = format!(
            "{MINIMAL}\n[container]\nkind = \"rar-stored\"\nvolume_bytes = 1024\n\
             [recovery]\nkind = \"par2\"\ncovers = \"first\"\n"
        );
        Profile::parse(&split).expect("a split container's member count is the generator's answer");
    }

    #[test]
    fn a_layout_with_no_name_source_is_refused() {
        // The spec's rule: filedesc-only names, an index-only set, and
        // the index removed.
        let text = format!(
            "{MINIMAL}\n[recovery]\nkind = \"par2\"\nredundancy_pct = 0\n\
             names = \"filedesc-only\"\nindex = \"absent\"\n"
        );
        assert_eq!(refusal(&text), Contradiction::NoNameSource);

        // The same defect one step earlier: no recovery set at all, so
        // no FileDesc packet either.
        let no_set = format!("{MINIMAL}\n[recovery]\nnames = \"filedesc-only\"\n");
        assert_eq!(refusal(&no_set), Contradiction::NoNameSource);

        // With recovery volumes, the FileDesc packets survive the
        // index's absence and P7 is exactly the shape being tested.
        let with_volumes = format!(
            "{MINIMAL}\n[recovery]\nkind = \"par2\"\nredundancy_pct = 10\n\
             names = \"filedesc-only\"\nindex = \"absent\"\n"
        );
        Profile::parse(&with_volumes).expect("volumes carry the names when the index is gone");
    }

    #[test]
    fn redundancy_without_a_recovery_set_is_refused() {
        let text = format!("{MINIMAL}\n[recovery]\nredundancy_pct = 10\n");
        assert_eq!(refusal(&text), Contradiction::RedundancyWithoutRecoverySet);
    }

    /// A refusal has to say what to do about it. Every contradiction's
    /// text names the table it is about, so an author reading one line
    /// of test output knows where to edit.
    #[test]
    fn every_contradiction_names_its_table() {
        let all = [
            Contradiction::FormatVersion {
                found: 9,
                expected: FORMAT_VERSION,
            },
            Contradiction::NoSourceFiles,
            Contradiction::DuplicateSourceName("a.bin".into()),
            Contradiction::PeriodicSource,
            Contradiction::EncryptionWithoutPassword,
            Contradiction::NzbPasswordWithoutPassword,
            Contradiction::CoversFirstWithOneFile,
            Contradiction::NoNameSource,
            Contradiction::RedundancyWithoutRecoverySet,
        ];
        for c in all {
            let msg = c.to_string();
            assert!(msg.starts_with('['), "{c:?}: does not name a table: {msg}");
            assert!(msg.len() > 30, "{c:?}: too terse to act on: {msg}");
        }
    }

    /// A missing file names the path rather than reporting a bare io
    /// error, which is the difference between a fixable message and a
    /// hunt through the catalog walk.
    #[test]
    fn a_missing_file_names_the_path() {
        let e = Profile::load(Path::new("catalog/no-such-profile.toml"))
            .expect_err("a missing file is an error");
        assert!(e.to_string().contains("no-such-profile.toml"), "{e}");
    }
}
