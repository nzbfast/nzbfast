//! `[container]`, plane 7.B: the archive wrapped around the payload.
//!
//! A profile selects a kind, a RAR generation, a volume size, a naming
//! style, an encryption mode, an embedded recovery record, a nesting
//! depth, a leading-bytes prefix and a polyglot second format; this
//! stage turns that into the
//! files that go on the wire and into the end state the client must
//! reach once it has opened them. Everything below this stage - the
//! recovery set, the naming plane, the encoder, the NZB - then treats a
//! volume as an ordinary posted file, so no other module in this crate
//! learns what a container is.
//!
//! **The archives are written by a LIBRARY, and never by hand.** RAR
//! comes from `rars`: the workspace member is `vendor/rars`, the
//! mirror, and the fork at `~/Claude/rars` is where a writer change is
//! made and synced in from (memory
//! `nzbfast-rars-fork-location-and-drift`). 7z comes from the vendored
//! `sevenz-rust2`, through [`crate::sevenz`], which is that module's
//! whole subject. ZIP comes from the `zip` crate, through
//! [`crate::zip`] - the one format here whose writer WAS a real
//! dependency decision, priced in that module's header and in
//! `crates/postfast/Cargo.toml`. A shape no writer produces is
//! REFUSED BY NAME
//! here - see [`ContainerError::NoWriter`] - and never approximated by
//! assembling header bytes in this file. An approximation would be a
//! fixture that agrees with our own reader and with nothing else,
//! which is the exact failure the oracle exists to catch rather than
//! to commit.
//!
//! # Three formats, one plane
//!
//! `kind` names the format and the storage mode together
//! (`rar-stored`, `rar-compressed`, `7z-stored`, `7z-compressed`,
//! `zip-stored`, `zip-compressed`), so C1, C2 and C3 are the MODE and
//! C12 is the format. C8 is the one selection that puts TWO formats in
//! one file: `polyglot` appends a second, complete archive of another
//! format behind the first, so what the client does with the file
//! depends on which signature it trusts and in what order. See
//! [`refuse_a_polyglot_the_client_never_has_to_read`] for the two
//! shapes that look like C8 and are not. Several keys on this table are
//! RAR's alone - `version`, `recovery_record_pct` (C10) and
//! `volume_style` (C11) - and a 7z or zip profile that writes one is
//! refused by name rather than having it quietly dropped
//! ([`refuse_a_sevenz_shape_that_is_rars`],
//! [`refuse_a_zip_shape_that_is_rars`]).
//!
//! **A split archive means three different things on this plane.** A
//! RAR volume set is self-describing - every volume carries a header -
//! while both a split 7z and a byte-split zip are the finished archive
//! CUT at fixed offsets, so `volume_bytes` means payload bytes per
//! volume on a rar kind and bytes of ARCHIVE per part on the other two.
//! The cut itself is one function, [`crate::sevenz::split_parts`],
//! because chunking a byte slice knows nothing about either format; the
//! part NAMES differ (`.7z.001` against `.zip.001`) and live in
//! [`volume_names`]. The zip format has a second multi-part spelling -
//! WinZip spanning, `.z01` ... `.zip` - which `nzbkit::zip` reads and
//! no writer here emits; [`crate::zip`]'s header says why it is left
//! unemitted rather than approximated.
//!
//! # Every archive is read back before it is emitted
//!
//! [`wrap`] does not return a layout it has not opened. Each set is
//! parsed with the `rars` READER, extracted in full, peeled through
//! however many nesting levels the profile asked for, and compared
//! byte for byte against the payload that went in. A writer defect
//! therefore fails AT GENERATION, naming the profile and the shape,
//! rather than surfacing as an oracle failure that reads like a client
//! bug. That distinction is the whole reason this check is here and not
//! in a test: a red row that says "nzbfast lost the payload" when the
//! fixture never held it costs a lane an afternoon.
//!
//! It is not a tautology, either, even though one library writes and
//! reads. It cannot see a spec disagreement that `rars` makes on both
//! sides, and it is not meant to - the CLIENT round trip in the oracle
//! is what says the shape is real. What it does see is the whole class
//! of "the writer emitted something nothing can open", which is what a
//! generator gets wrong.
//!
//! # Where the tree goes, and why a container changes the answer
//!
//! With no container the directory part of a source name is carried
//! nowhere and the honest expectation is a flat file
//! (`crate::naming`'s header says why). An archive is the first plane
//! that DOES carry it: entries go in under their relative path, so a
//! payload posted as `sample/s.bin` must come back out under
//! `sample/s.bin`. That is a requirement rather than a courtesy - the
//! bytes for it are on the wire.

use std::cell::RefCell;
use std::io::Write;
use std::rc::Rc;

use rars::{ArchiveReadOptions, ArchiveReader, ArchiveVersion, FeatureSet};

use crate::assemble::SourceFile;
use crate::profile::{
    Container, ContainerKind, Encryption, Polyglot, Profile, RarVersion, VolumeNames, VolumeStyle,
};
use crate::recovery;
use crate::rng::Rng;

/// The stream C14's sibling bytes are drawn from.
///
/// A stream of the container plane's own, seeded off the profile seed,
/// for the reason `crate::fault`'s does: a sibling row is almost always
/// a nested row with a table added, and the two have to be diffable.
/// Drawing from the layout stream instead would move every payload
/// name and message-id below it, so the diff would be the whole post.
pub const STREAM: u64 = 0x434f_4e54_4149_4e45; // "CONTAINE"

/// The stream each encrypted level's key salt (and, on RAR5, its
/// initialisation vectors) is drawn from.
///
/// A stream of its own rather than the sibling one above, for the
/// reason that one is separate from the layout stream: adding
/// encryption to a profile must not move the sibling bytes, or a C4 row
/// and the C1 row it was copied from would differ in every file rather
/// than in the one selection that changed.
///
/// # This is a SEEDED salt, and it weakens the encryption it feeds
///
/// The salt exists so two archives written under one password derive
/// different keys, and a seeded one hands that to anyone holding the
/// seed - which travels in the profile, in a public catalog. That is
/// the whole trade this crate makes: a catalog archive is a fixture
/// with no secrecy at all, and its reproducibility is the property the
/// walk is built on. `rars` defaults to [`rars::Entropy::Os`] and this
/// is the only place in the crate that says otherwise, so nothing but
/// a generated fixture is ever written this way.
pub const ENTROPY_STREAM: u64 = 0x4b45_5953_414c_5453; // "KEYSALTS"

/// The smallest `leading_bytes` that can hold a structurally valid PE
/// header, which is what the client's stub check actually reads.
///
/// `MZ`, then `e_lfanew` at 0x3c pointing at 0x40, then `PE\0\0` there:
/// the last byte of that is 0x43, so 0x44 bytes is the floor. A shorter
/// prefix is refused rather than padded, because a prefix the client
/// declines is not the C9 row - it is a bare archive wearing a stub's
/// name, and it would pass or fail for reasons that have nothing to do
/// with the signature scan the row exists to exercise.
pub const SFX_STUB_MIN: u64 = 0x44;

/// C8: the one member the SECOND archive of a polyglot carries.
///
/// A name of its own rather than a copy of a `[source]` name, and that
/// is the whole measurement: the two readings of a polyglot produce
/// DISJOINT trees, so an oracle row graded on its exact tree says which
/// archive the client opened and cannot be green for having opened the
/// other one. A second archive holding the same payload under the same
/// name would pass either way, which is a row that tests nothing.
///
/// It reads as a sentence in a failure message on purpose: a tree
/// carrying this name is a client that took the LATER signature.
pub const POLYGLOT_MEMBER: &str = "second-archive.bin";

/// How long [`POLYGLOT_MEMBER`] is, and what is in it.
///
/// A fixed byte and a fixed length, drawn from no stream at all, for
/// the reason [`sfx_stub`]'s filler is zeros: a second archive whose
/// bytes came off the seed would move every message-id of a layout
/// whose only change was selecting C8, so a polyglot row and the row it
/// was copied from would differ in the whole post rather than in the
/// one selection. Not zeros, so the member is distinguishable from stub
/// filler in a hexdump of a failing row.
const POLYGLOT_MEMBER_BYTES: usize = 1024;
const POLYGLOT_MEMBER_FILL: u8 = 0xC8;

/// What the container plane produced.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Contained {
    /// The volumes to post, in order, as ordinary source files. A
    /// volume has no tree, so `rel` and `base` are equal.
    pub volumes: Vec<SourceFile>,
    /// What must come OUT of the archive: the payload under the names
    /// the archive carries, which for a container is the source's full
    /// relative path, and then C14's siblings under theirs.
    ///
    /// The sources come FIRST and the order is load-bearing:
    /// `crate::layout::expectation` projects the payload names off the
    /// leading `sources.len()` entries, so a sibling appended after
    /// them is part of the expected TREE without becoming a payload
    /// name a gap row's `arrives` could name. That is the right
    /// distinction - a sibling is archive furniture the post carries,
    /// not a `[source]` deliverable.
    pub payload: Vec<(String, Vec<u8>)>,
    /// The stem an NZB would name the post after. The container's own,
    /// not a volume's: `movie.part01` is a volume name, not a release.
    pub post_stem: String,
}

/// Why a container could not be built.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ContainerError {
    /// The shape is meaningful and no `rars` writer produces it. The
    /// fix is a writer change IN THE FORK, synced in; it is never a
    /// hand-assembled archive here, and it is never a quietly different
    /// shape that happens to build.
    NoWriter { shape: String, writer: String },
    /// Two selections that cannot both be honoured. Refused rather than
    /// resolved by precedence, because a precedence rule is a silent
    /// answer to a question the author asked out loud.
    Contradiction(String),
    /// A `rars` writer refused the input.
    Writer { shape: String, detail: String },
    /// The archive was written and could not be read back. A writer
    /// defect, surfaced here rather than as a client failure.
    RoundTrip(String),
    /// `kind = "rar-compressed"` was selected and the writer stored
    /// every member, so the emitted archive is a C1 wearing a C3
    /// selection. See [`refuse_a_compressed_archive_that_stored`].
    NothingToCompress,
    /// H4: a level's own PAR2 set could not be built.
    LevelRecovery { level: usize, detail: String },
    /// H5: a levelled damage span that does not land inside the archive
    /// the writer produced.
    DamageOffTheLevel {
        level: usize,
        name: String,
        at: u64,
        bytes: u64,
        length: u64,
    },
}

impl std::fmt::Display for ContainerError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NoWriter { shape, writer } => write!(
                f,
                "[container] {shape} is not a shape the vendored writers build: {writer}. \
                 The profile loads because the selection is meaningful; the generator refuses \
                 it because emitting a DIFFERENT shape that happens to build would be a row \
                 that tests something nobody asked for. Widening a RAR writer is a change in \
                 the fork at ~/Claude/rars, synced into vendor/rars - never a hand-edit of \
                 the vendored source"
            ),
            Self::Contradiction(why) => write!(f, "[container] {why}"),
            Self::Writer { shape, detail } => {
                write!(
                    f,
                    "[container] the archive writer refused {shape}: {detail}"
                )
            }
            Self::RoundTrip(why) => write!(
                f,
                "[container] the archive this profile describes was written and could not be \
                 read back: {why}. This is a WRITER defect, caught at generation on purpose - \
                 an oracle failure over the same bytes would have read like a client bug"
            ),
            Self::LevelRecovery { level, detail } => write!(
                f,
                "[container] the PAR2 set for [[container.inner]] {level} could not be built: \
                 {detail}"
            ),
            Self::DamageOffTheLevel {
                level,
                name,
                at,
                bytes,
                length,
            } => write!(
                f,
                "[fault] corrupt_payload spoils {bytes} byte(s) at offset {at} of \
                 [[container.inner]] {level}, whose archive ({name}) is {length} bytes. \
                 Damage that falls off the end is no damage at all. Unlike a [source] file, \
                 how long a level's archive is is the WRITER's answer rather than the \
                 profile's - so this is measured here, at the archive, instead of being \
                 checked against a length the file declares. Move the span, or give the \
                 payload more bytes"
            ),
            Self::NothingToCompress => f.write_str(
                "[container] a compressed selection produced an archive whose every member \
                 is STORED, so it is a C1 archive wearing a C3 selection and a row over it \
                 would be green without a byte of decompression having run. On the RAR arm \
                 the cause is the SOURCE plane rather than the writer: `[source]` bytes come \
                 off the ChaCha stream and are incompressible by construction \
                 (crate::assemble's header says why), the RAR writers silently store an \
                 entry they cannot shrink, and `[source] periodic` is refused \
                 unconditionally - for a par2cmdline reason that does not apply to a profile \
                 with no recovery set. A RAR C3 row therefore waits on a compressibility \
                 selection in `[source]`, which is the source plane's key to add and not \
                 this one's. **kind = \"7z-compressed\" needs none of that** and is the arm a \
                 C3 row selects today: the 7z writer records ONE content method for the \
                 archive and never falls back per entry, so an LZMA2 archive over \
                 incompressible bytes is still an archive the client must run the LZMA2 \
                 decoder over - it just comes out bigger than its payload. Reaching this \
                 message from the 7z arm means the writer grew a store fallback, which is a \
                 finding rather than a profile error",
            ),
        }
    }
}

impl std::error::Error for ContainerError {}

/// Build the container a profile describes, or `None` for C0.
///
/// Draw order, which is part of the determinism contract: this stage
/// runs AFTER `crate::assemble::sources` and BEFORE the recovery and
/// naming planes, and draws from the stream exactly once per volume,
/// only under `volume_names = "opaque"`. A layout with descriptive
/// volume names draws nothing here, so adding a container to a profile
/// does not move the message-ids of a layout that had none.
pub fn wrap(
    profile: &Profile,
    sources: &[SourceFile],
    rng: &mut Rng,
) -> Result<Option<Contained>, ContainerError> {
    let c = &profile.container;
    if c.kind == ContainerKind::None {
        return Ok(None);
    }
    // No member count is passed: the guard stopped asking on 4 Sep
    // 2026, when the plural volume writers landed. It asked because the
    // single-entry writers refused a split set of several files, and
    // the count that mattered was what the SPLIT level holds - with any
    // nesting at all that is one, the archive below it, however many
    // sources there are. Passing `sources.len()` there refused the very
    // shape the refusal's own message recommended (found 3 Sep 2026 on
    // the nested corpus's r2 leg). The nesting fact is still true and
    // still asserted, by
    // `the_same_several_files_behind_a_nesting_level_are_not`.
    refuse_a_shape_no_writer_builds(c)?;
    let stem = post_stem(sources);
    // C14: every level's sibling bytes, drawn up front from this
    // plane's own stream in level order (innermost first, the order the
    // loop below wants them in). Up front rather than inside the loop
    // so the draw order is a property of the STACK and not of which
    // branch of the loop each level took.
    let mut sib_rng = Rng::from_seed(profile.layout.seed ^ STREAM);
    // C4/C5: one salt source per level, drawn up front in level order
    // for the same reason the siblings are - so the draw order is a
    // property of the STACK rather than of which branch each level
    // took, and a level that turns out not to encrypt still spends its
    // draw. A level that does encrypt is written TWICE when something
    // below it is damaged (the clean stack the round trip reads, and
    // the copy that goes on the wire), and both writes take the SAME
    // source: two salts there would make one profile emit two archives
    // that differ in bytes carrying no damage.
    let mut salt_rng = Rng::from_seed(profile.layout.seed ^ ENTROPY_STREAM);

    // Level 0 is the payload archive; each further level wraps the one
    // below it whole. The OUTERMOST level is the one that gets split,
    // because that is the set a poster puts on the wire. H2: each
    // level has its OWN selections, which for a uniform stack are the
    // one `[container]` table repeated.
    let stack = level_stack(c);
    let levels = stack.len();
    let salts: Vec<[u8; 32]> = (0..levels).map(|_| draw_entropy(&mut salt_rng)).collect();
    for level in &stack[..levels - 1] {
        refuse_a_level_shape(&level.c)?;
    }
    let mut members: Vec<(String, Vec<u8>)> = sources
        .iter()
        .map(|s| (s.rel.clone(), s.bytes.clone()))
        .collect();
    let mut volumes: Vec<Vec<u8>> = Vec::new();
    // What comes OUT of the whole stack besides the payload: every
    // level's siblings and every level's own recovery set, in the order
    // they were written. Read by the round-trip check alone.
    let mut escapes: Vec<(String, Vec<u8>)> = Vec::new();
    // ...and the subset of it that LANDS. A sibling is an ordinary file
    // the post carries and the client has nothing to do with it but
    // write it out. A level's own PAR2 set (C15) is recovery data, and
    // the client spends it: it repairs the archive that set covers and
    // the set itself never reaches the output tree, which is the same
    // rule the posted parity volumes follow one level up and is why
    // `[recovery]`'s volumes are not in an end state either.
    //
    // Measured rather than assumed, and the first `nc-r4` run is what
    // measured it: the row was written with the packed set expected to
    // land, and `nzbfast get` finished with the payload and the posted
    // index alone, having reported `nested set: repaired`. That is the
    // client being right - three `.par2` files left in a user's output
    // directory would be leftovers from a repair that already
    // succeeded.
    let mut landed: Vec<(String, Vec<u8>)> = Vec::new();
    // H5: the stack is built TWICE when a level is damaged, and only
    // then. `members` is the clean stack, which is what the round-trip
    // check reads and what each level's own recovery set is cut over;
    // `wire` is the copy that carries the damage upward, and it is what
    // goes on the wire. They are the same list until the first damaged
    // level, and `None` for the whole build of a profile that damages
    // nothing - so no undamaged row pays a second write.
    //
    // The fork is the same one `crate::fault::spoil_payload` makes over
    // a payload file and for the same reason: a set cut over already
    // damaged bytes would describe the damage, agree with it, and ask
    // the client to repair nothing. Here the ordering has to live
    // inside this loop, because the set a level's damage hides from is
    // that level's own, built one line earlier.
    let mut wire: Option<Vec<(String, Vec<u8>)>> = None;
    let mut wire_volumes: Option<Vec<Vec<u8>>> = None;
    let mut extras: Vec<usize> = Vec::with_capacity(levels);
    for (level, lv) in stack.iter().enumerate() {
        let lc = &lv.c;
        // C14: the siblings join the members of THIS level, after the
        // archive below it. After, so the first member of an inner
        // level is still the archive - which is what a reader of a
        // failing extraction looks at first.
        let siblings = draw_siblings(lc, &mut sib_rng);
        members.extend(siblings.iter().cloned());
        if let Some(w) = wire.as_mut() {
            w.extend(siblings.iter().cloned());
        }
        escapes.extend(siblings.iter().cloned());
        landed.extend(siblings);
        // What this level holds BESIDES the archive below it (or,
        // at the bottom, besides the payload): its own siblings, and
        // the recovery set the level below packed up here. Recorded
        // rather than recomputed, because the round-trip check has to
        // know the count exactly and deriving it there a second time is
        // how the two disagree. It did disagree for one run: the check
        // counted siblings alone and refused the first H4 profile
        // written, whose level held an archive and a three-file set.
        let below = if level == 0 { sources.len() } else { 1 };
        extras.push(members.len() - below);
        let outermost = level + 1 == levels;
        if outermost && lc.volume_bytes > 0 {
            volumes = write_volume_set(lc, &members, salts[level])?;
            refuse_a_compressed_archive_that_stored(lc, &volumes)?;
            if let Some(w) = &wire {
                wire_volumes = Some(write_volume_set(lc, w, salts[level])?);
            }
            break;
        }
        let bytes = write_one_archive(lc, &members, salts[level])?;
        refuse_a_compressed_archive_that_stored(lc, std::slice::from_ref(&bytes))?;
        let wire_bytes = match &wire {
            Some(w) => Some(write_one_archive(lc, w, salts[level])?),
            None => None,
        };
        if outermost {
            volumes = vec![bytes];
            wire_volumes = wire_bytes.map(|b| vec![b]);
            break;
        }
        // An inner archive is one member of the level above it, under a
        // name that says which level it is AND which format: same-named
        // archives at two depths would make a failing extraction
        // ambiguous to read, and a mixed stack's `.rar` sitting inside
        // a `.7z` is exactly the shape whose failure needs reading.
        let inner_name = format!("{stem}.inner{}.{}", level + 1, lc.kind.extension());
        // H4: this level's OWN recovery set, cut over the CLEAN archive
        // and packed into the level above it beside that archive. It is
        // furniture the client has to notice on its own: nothing in the
        // posted NZB mentions it, because it is inside an archive.
        let own_set = if lv.recovery_pct > 0 {
            recovery::set_over_one_file(&inner_name, &bytes, lv.recovery_pct).map_err(|e| {
                ContainerError::LevelRecovery {
                    level: level_label(levels, level),
                    detail: e.to_string(),
                }
            })?
        } else {
            Vec::new()
        };
        escapes.extend(own_set.iter().cloned());
        // ...and NOT `landed`: see its declaration.
        // H5: and NOW the damage, over the copy that goes on the wire,
        // after the set above was cut over the clean bytes.
        //
        // **Over `wire_bytes` when the fork is open, and NOT over a
        // fresh copy of the clean archive.** Written the wrong way for
        // one run and it cost the first `nc-a1` a green test over a
        // post that carried no damage below the top level: this level's
        // wire archive is the one holding the DAMAGED level below it,
        // so spoiling a clean copy here throws that away and every
        // deeper span with it. The oracle could not see it - the
        // payload lands either way, which is what an absent fault looks
        // like - so `deeper_damage_survives_the_levels_above_it` is the
        // pin.
        let base = wire_bytes.unwrap_or_else(|| bytes.clone());
        let spoiled = spoil_a_level(profile, levels, level, base, &inner_name, rng)?;
        let mut next_wire: Vec<(String, Vec<u8>)> = vec![(inner_name.clone(), spoiled)];
        next_wire.extend(own_set.iter().cloned());
        let mut next_clean: Vec<(String, Vec<u8>)> = vec![(inner_name, bytes)];
        next_clean.extend(own_set);
        // The fork opens at the first damaged level and stays open.
        if wire.is_some() || next_wire != next_clean {
            wire = Some(next_wire);
        }
        members = next_clean;
    }

    // C9 and C8: the furniture that rides the FIRST volume, which is
    // where a self-extractor puts its launcher and where a poster
    // appends. The stub is a program with an archive behind it and the
    // rest of a split set are ordinary volumes; the polyglot's second
    // archive goes at the very end, after the stub and after the
    // archive the profile is about.
    //
    // Applied to BOTH copies of the set, which is what `dress` is for.
    // Before 4 Sep 2026 the stub was prepended to `volumes` alone, and
    // `posted` below takes `wire_volumes` whenever a level is damaged -
    // so an H5 row that also selected C9 would have posted a set with
    // no stub on it while the profile said it had one, and the row's
    // own `[expect]` could not have seen the difference. Found while
    // adding the second piece of furniture to the same place.
    if c.leading_bytes > 0 || c.polyglot != Polyglot::None {
        let stub = (c.leading_bytes > 0).then(|| sfx_stub(c.leading_bytes));
        let tail = polyglot_tail(c.polyglot)?;
        let dress = |set: &mut Vec<Vec<u8>>| {
            let head = set
                .first_mut()
                .expect("a container always produces at least one volume");
            if let Some(stub) = &stub {
                let mut with_stub = stub.clone();
                with_stub.extend_from_slice(head);
                *head = with_stub;
            }
            head.extend_from_slice(&tail);
        };
        dress(&mut volumes);
        if let Some(w) = wire_volumes.as_mut() {
            dress(w);
        }
    }

    // The CLEAN stack is what is read back, and it has to be: a damaged
    // level does not extract, which is the point of damaging it. What
    // this proves is the same thing it always proved - that the
    // generator built the structure it described - and the damaged copy
    // differs from it by exactly the spans the profile named.
    read_the_set_back(c, &stack, &volumes, sources, &escapes, &extras)?;
    let posted = wire_volumes.unwrap_or(volumes);

    let names = volume_names(c, &stem, posted.len(), rng);
    Ok(Some(Contained {
        volumes: names
            .into_iter()
            .zip(posted)
            .map(|(name, bytes)| SourceFile {
                base: name.clone(),
                rel: name,
                bytes,
            })
            .collect(),
        payload: sources
            .iter()
            .map(|s| (s.rel.clone(), s.bytes.clone()))
            .chain(landed)
            .collect(),
        post_stem: stem,
    }))
}

/// Which `[[container.inner]]` table a stack level corresponds to, for
/// an error message and for [`spoil_a_level`]'s lookup.
///
/// The stack is innermost-first and the inner tables are written
/// outermost-inner first, so the two are reverses of each other. One
/// spelling, because getting it backwards would silently damage the
/// wrong level and still produce a layout.
fn level_label(levels: usize, level: usize) -> usize {
    levels - 2 - level
}

/// H5: write fault-stream bytes over the spans this level declares,
/// AFTER its own recovery set was cut over the clean ones.
///
/// Returns the bytes unchanged when the profile names no span here, so
/// the caller's clean/wire fork never opens for an undamaged stack.
///
/// The replacement bytes come from the LAYOUT stream rather than from a
/// fault stream of its own, which is the one place this arm differs
/// from `crate::fault::spoil_payload` and is forced: the container
/// plane already holds that generator and its draw order is part of the
/// determinism contract. Nothing below it draws before the volume names,
/// so a damaged row's opaque tokens do move against the clean row it was
/// copied from - stated here rather than discovered, and the reason no
/// catalog row pairs C6 with a levelled damage.
fn spoil_a_level(
    profile: &Profile,
    levels: usize,
    level: usize,
    mut bytes: Vec<u8>,
    name: &str,
    rng: &mut Rng,
) -> Result<Vec<u8>, ContainerError> {
    let label = level_label(levels, level);
    for d in &profile.fault.corrupt_payload {
        if d.inner_level.map(|l| l as usize) != Some(label) {
            continue;
        }
        let at = usize::try_from(d.at).unwrap_or(usize::MAX);
        let len = usize::try_from(d.bytes).unwrap_or(usize::MAX);
        let end = at.checked_add(len);
        if end.is_none_or(|e| e > bytes.len()) {
            return Err(ContainerError::DamageOffTheLevel {
                level: label,
                name: name.to_string(),
                at: d.at,
                bytes: d.bytes,
                length: bytes.len() as u64,
            });
        }
        let span = &mut bytes[at..at + len];
        let before = span.to_vec();
        rng.fill(span);
        // Failing to find is failing, in its smallest form: a fill that
        // reproduced the bytes it replaced would leave an undamaged
        // archive under a row whose whole point is that only the packed
        // set can see the difference.
        if span == before.as_slice() {
            for b in span.iter_mut() {
                *b ^= 0xff;
            }
        }
    }
    Ok(bytes)
}

/// C14: one level's sibling files, with their bytes drawn from the
/// container plane's own stream.
///
/// Drawn even for a level that declares none, in the sense that the
/// stream is not advanced: a level with an empty list draws nothing, so
/// adding a sibling at level 2 does not move level 1's bytes. The order
/// is the profile's own list order, at every level, so the stream
/// position is a function of the stack the profile wrote.
fn draw_siblings(c: &Container, rng: &mut Rng) -> Vec<(String, Vec<u8>)> {
    c.siblings
        .iter()
        .map(|s| {
            // A text sibling draws NOTHING, which is the property that
            // lets a password note be added to a row without moving the
            // noise of the sibling beside it.
            if let Some(t) = &s.text {
                let mut text = t.clone();
                // The client harvests LINES; a file with no terminator
                // is a shape no editor writes.
                if !text.ends_with('\n') {
                    text.push('\n');
                }
                return (s.name.clone(), text.into_bytes());
            }
            let mut bytes = vec![0u8; usize::try_from(s.bytes).unwrap_or(usize::MAX)];
            rng.fill(&mut bytes);
            (s.name.clone(), bytes)
        })
        .collect()
}

/// One level's salt source, drawn from [`ENTROPY_STREAM`].
///
/// Always drawn, even for a level that does not encrypt, so that adding
/// encryption to ONE level of a stack does not move the salts of the
/// levels beside it.
///
/// The raw SEED and not a writer's entropy type, because a stack mixes
/// formats: the same 32 bytes become `rars::Entropy::Seeded` on a RAR
/// level and `sevenz_rust2::Entropy::Seeded` on a 7z one, so a level's
/// draw position is a property of the STACK rather than of which writer
/// that level happened to select. Two per-format streams would put the
/// two formats' levels on different sequences and make `nc-x3`'s
/// alternating stack undiffable against a uniform one.
fn draw_entropy(rng: &mut Rng) -> [u8; 32] {
    let mut seed = [0u8; 32];
    rng.fill(&mut seed);
    seed
}

/// H2: one [`Container`] per nesting level, INNERMOST FIRST, which is
/// the order [`wrap`] builds in.
///
/// A uniform stack (`nested = N`, no `[[container.inner]]`) is the one
/// table repeated, which is exactly what this stage did before the
/// per-level tables existed. A per-level stack takes the outermost
/// selections from `[container]` itself and each inner level from its
/// own table, REVERSED here because a profile lists them outermost-inner
/// first (the order the corpus names a leg in: `RAR > 7z > RAR >
/// payload`) and this loop runs the other way. The reversal is done
/// once, here, rather than asked of every reader.
///
/// An inner level gets DEFAULTS for everything a posted set owns - the
/// volume split, the volume naming, the SFX prefix - because those
/// belong to the outermost level by definition and an inner archive is
/// unsplit. That is why the inner table has no such keys to inherit or
/// override.
fn level_stack(c: &Container) -> Vec<Level> {
    let depth = usize::try_from(c.depth()).unwrap_or(usize::MAX);
    if c.inner.is_empty() {
        let mut stack: Vec<Level> = vec![
            Level {
                c: c.clone(),
                recovery_pct: 0,
            };
            depth + 1
        ];
        // C14: `[container] siblings` is the OUTERMOST level's alone,
        // even under a uniform stack. Repeating the list down the stack
        // would put one NAME at every depth, and every level extracts
        // into the same output directory - so a sibling at every level
        // is written with an inner table apiece, each naming its own.
        for level in &mut stack[..depth] {
            level.c.siblings = Vec::new();
        }
        return stack;
    }
    let mut stack: Vec<Level> = c
        .inner
        .iter()
        .rev()
        .map(|l| Level {
            c: Container {
                kind: l.kind,
                version: l.version,
                recovery_record_pct: l.recovery_record_pct,
                siblings: l.siblings.clone(),
                encryption: l.encryption,
                // An empty password at this level means the stack's,
                // which is what a uniform chain says by saying nothing.
                // Resolved HERE rather than at the write sites, so
                // every reader of a `Level` sees the password that
                // level is actually written with.
                password: if l.password.is_empty() {
                    c.password.clone()
                } else {
                    l.password.clone()
                },
                ..Container::default()
            },
            recovery_pct: l.recovery_pct,
        })
        .collect();
    let mut outermost = c.clone();
    // The outermost level's own table carries the list; clearing it
    // keeps `depth()` honest for anything that reads one level of the
    // stack on its own.
    outermost.inner = Vec::new();
    // H4 is an INNER level's key: a set over the outermost level is the
    // ordinary `[recovery]` plane, posted beside the volumes.
    stack.push(Level {
        c: outermost,
        recovery_pct: 0,
    });
    stack
}

/// One level of a nested stack: the archive selections that level makes,
/// and whether the level above it carries a PAR2 set over it (H4).
///
/// A small wrapper rather than two more keys on [`Container`], because
/// `recovery_pct` is meaningless on the OUTERMOST level - a set over
/// what goes on the wire is the `[recovery]` plane - and a type that
/// could hold it there would need a refusal instead of a shape.
#[derive(Debug, Clone)]
struct Level {
    c: Container,
    recovery_pct: u32,
}

/// The refusals that apply to ANY level of a stack, not only the posted
/// one.
///
/// Split out of [`refuse_a_shape_no_writer_builds`] when the per-level
/// tables landed: the volume split, the launcher stub and the opaque
/// volume names are questions only the outermost level can be asked,
/// and these three are questions about the archive itself. Without the
/// split, a `[[container.inner]]` naming `rar4` with a recovery record
/// would have reached the writer and been refused there with a message
/// about the wrong level.
fn refuse_a_level_shape(c: &Container) -> Result<(), ContainerError> {
    if c.kind.is_sevenz() {
        // `split = false`: an inner level is never the posted set, so
        // the two split-only arms of that check cannot fire here.
        refuse_a_sevenz_shape_that_is_rars(c, false)?;
    }
    if c.kind.is_zip() {
        refuse_a_zip_shape_that_is_rars(c, false)?;
    }
    // A RAR4 recovery record is an embedded "Protect+" NEWSUB block that
    // protects the archive bytes before it, and a header-encrypted
    // archive stores that block encrypted too. `rar15_40`'s writer emits
    // it in the clear and its own extractor refuses to read an encrypted
    // one back (`newsub_recovery_data`), so the pair would produce a
    // record no reader accepts - which is the shape this whole arm
    // exists to keep out of the catalog. The plain RAR4 archive builds
    // it since 4 Sep 2026; only this pairing is left.
    if c.version == RarVersion::Rar4
        && c.recovery_record_pct > 0
        && c.encryption == Encryption::Header
    {
        return Err(ContainerError::NoWriter {
            shape: format!(
                "recovery_record_pct = {} on a header-encrypted rar4 archive",
                c.recovery_record_pct
            ),
            writer: "rars::rar15_40::write refuses recovery_record beside header_encryption \
                     (allows_recovery_record): it would write the RR block in the clear and \
                     the extractor declines an encrypted one, so the record would repair \
                     nowhere. Build C10 on a plain or data-encrypted rar4 archive, or on \
                     version = \"rar5\", which encrypts its own recovery service"
                .into(),
        });
    }
    Ok(())
}

/// Refuse, by name, every combination the vendored writers do not build
/// or that two selections make meaningless.
///
/// Each arm names the writer entry point that would have to grow, so a
/// reader knows what a fix costs before opening `vendor/rars`.
fn refuse_a_shape_no_writer_builds(c: &Container) -> Result<(), ContainerError> {
    let split = c.volume_bytes > 0;
    refuse_a_level_shape(c)?;
    // A recovery record over a SPLIT rar4 set, which `refuse_a_level_shape`
    // cannot ask about: only the outermost level is ever split. `rar`
    // writes one record per volume over that volume's own bytes;
    // `rar15_40::write`'s volume writers have no per-volume plan and
    // refuse the feature outright (`validate_volume_writer_inputs`), so
    // without this arm the row would take the writer's error instead of
    // a message naming the gap.
    if split && c.version == RarVersion::Rar4 && c.recovery_record_pct > 0 {
        return Err(ContainerError::NoWriter {
            shape: format!(
                "recovery_record_pct = {} on a split rar4 set",
                c.recovery_record_pct
            ),
            writer: "every rar15_40 volume entry point (::write_stored_volumes, \
                     ::write_compressed_volumes, ::write_stored_volume_set, \
                     ::write_compressed_volume_set) refuses features.recovery_record in \
                     validate_volume_writer_inputs: a record protects the bytes before it in \
                     ONE file, so a volume set needs one per volume and the writer has no such \
                     plan. version = \"rar5\" carries recovery_percent on its volume path"
                .into(),
        });
    }
    if c.kind.is_sevenz() && split {
        // The two split-only 7z arms; the rest ran above, for every
        // level of the stack.
        refuse_a_sevenz_shape_that_is_rars(c, true)?;
    }
    if c.kind.is_zip() && split {
        refuse_a_zip_shape_that_is_rars(c, true)?;
    }
    // The RAR volume writers used to take a SINGLE entry each, so a
    // split set holding several files was refused here by name. Every
    // one of those arms has a plural beside it now: RAR5 gained
    // `Rar50VolumeWriter::stored_entries` (gap H0, 4 Sep 2026) and
    // `::encrypted_stored_entries`, and `rar15_40::write` gained
    // `write_stored_volume_set` and `write_compressed_volume_set` the
    // same day - together with the ENDARC next-volume flag those RAR4
    // sets need, which a single member split across every volume never
    // did. `::compressed_entries` and `::encrypted_compressed_entries`
    // always took a slice.
    //
    // A split 7z or zip set never asked the question: it is the
    // finished archive CUT (crate::sevenz's header and crate::zip's),
    // so how many members it holds is invisible to the split. That is
    // why H0 had no twin in either other format.
    //
    // The RAR4 header-encrypted split arm went with the member-count
    // one. It refused on the reading that
    // `write_header_encrypted_split_volumes` is reached only from
    // `write_stored_volumes`; `write_compressed_volumes_impl` reaches
    // it too and always did, and nothing tested that path on either
    // side of the vendor line, which is how the wrong reading survived.
    // Both compressed paths carry a test in the fork now.
    if c.encryption != Encryption::None && c.password.is_empty() {
        // Reachable only for an INNER level: `Profile::check` refuses
        // the same shape on `[container]` itself, and on an inner level
        // that has nothing to inherit. A level that encrypts with an
        // empty password would write an archive whose key derives from
        // no bytes at all, which opens for anyone.
        return Err(ContainerError::Contradiction(format!(
            "{} with an empty password: nothing could open it",
            shape_word(c)
        )));
    }
    if c.leading_bytes > 0 {
        if c.leading_bytes < SFX_STUB_MIN {
            return Err(ContainerError::Contradiction(format!(
                "leading_bytes = {} is too short to be a launcher stub: the client's SFX arm \
                 requires a PROGRAM at offset 0 (nzbkit::sfx::is_launcher_stub), and the \
                 smallest structurally valid PE header is {SFX_STUB_MIN} bytes. A shorter \
                 prefix is declined by the scan, so the row would pass or fail for reasons \
                 that have nothing to do with the signature search it exists to exercise",
                c.leading_bytes
            )));
        }
        if split {
            // STILL REFUSED, and for a different reason than it was
            // until 4 Sep 2026. The old message deferred the end state
            // to chip 09's census, on the grounds that "the client's
            // SFX arm takes the stub off ONE file and the rest of the
            // set has to be paired with the carved remainder". The
            // census landed (`d16b3e1d8`) and does not answer that,
            // because the question was the wrong one, and both halves
            // of it are wrong:
            //
            // - There is no carve on the arm a POSTED split set takes.
            //   The one-pass router asks
            //   `nzbkit::sfx::sfx_archive_behind_stub` about the
            //   offset-0 article (`nzbkit/src/extract/routing.rs`) and
            //   starts the volume mapper AT the stub's offset. Nothing
            //   is copied and no remainder file exists to name.
            //   `carve_sfx` - which does write a fixed `carved.rar`
            //   into a scratch directory, and could indeed pair with
            //   nothing - is the DISK arm's,
            //   `nzbfast_unpack::sfx::extract_sfx`, and it is a
            //   fallback the posted shape does not reach.
            // - The end state is therefore not in doubt at all: the
            //   payload lands, whole and byte-exact. Measured 4 Sep
            //   2026 by building the shape and running it through the
            //   layouts oracle - `selfextract.part01.exe` beside
            //   `.part02.rar` and `.part03.rar`, which is what WinRAR
            //   itself writes - and the run reported `[RAR5 · stored ·
            //   one-pass]`, `volumes never touched disk`.
            //
            // WHAT IS ACTUALLY MISSING is the thing that measurement
            // also found: the row would be green whether or not the SFX
            // arm ever ran, so it would not be a C9 row. Renaming that
            // first volume `.part01.rar` - so `is_sfx_name` declines it
            // and no stub is ever looked for - still completes, because
            // the `.partNN` grouping alone carries the set to rars,
            // whose own reader scans past a stub with
            // `find_archive_start(input, SFX_SCAN_LIMIT)` whatever the
            // file is called. The SINGLE-volume C9 row does not have
            // that hole: the same control fails it, because a lone
            // stubbed `.rar` is never opened at all.
            //
            // So this refusal is now about the ORACLE and not about the
            // writer or the client. What would lift it is an
            // `[expect]` key that asserts WHICH ARM handled the set -
            // the shape badge the run already prints, `one-pass`
            // against `partly on disk` - which is the same missing
            // assertion machinery `[expect.ladder]` is refused for in
            // `crates/nzbfast/tests/integration/layouts/runner.rs`.
            // Until a profile can say that, a split C9 row would count
            // C9 recognised in `tools/layout-coverage.py` for a shape
            // it does not exercise, which is the rubber stamp this
            // crate refuses planes to prevent.
            //
            // Full measurement, both controls and the arm census:
            // research/POSTFAST-SFX-SPLIT-END-STATE-2026-09-04.md.
            return Err(ContainerError::NoWriter {
                shape: "a split archive behind a launcher stub".into(),
                writer: "the shape is emitable, and the END STATE is known: only the first \
                         volume carries the stub, the one-pass router starts the volume mapper \
                         at its offset (no carve, no remainder to name), and the payload lands \
                         byte-exact - measured 4 Sep 2026. What is missing is an ORACLE that \
                         could tell that apart from the fallback: renaming the first volume \
                         `.rar`, so the client never looks for a stub, completes too, because \
                         rars scans past a stub in any file handed to it. A row would be green \
                         without exercising C9 at all. It needs an [expect] key asserting the \
                         shape badge (`one-pass` against `partly on disk`), the same machinery \
                         [expect.ladder] waits on. Set volume_bytes = 0"
                    .into(),
            });
        }
    }
    refuse_a_polyglot_the_client_never_has_to_read(c)?;
    if c.volume_names == VolumeNames::Opaque && c.volume_style != VolumeStyle::default() {
        return Err(ContainerError::Contradiction(format!(
            "volume_names = \"opaque\" with volume_style = {:?} selects two answers to one \
             question. C6 is the row where reassembly has to come from the CONTENT, so an \
             opaque set's names carry no ordering at all; a style is what a descriptive set's \
             names spell the ordering with. Drop the style, or set volume_names = \
             \"descriptive\"",
            c.volume_style
        )));
    }
    Ok(())
}

/// C8: refuse a polyglot the client would never have to disambiguate.
///
/// `nzbkit::sfx::sfx_payload_at` is the ONLY place in the engine that
/// weighs two container signatures against each other. Everywhere else
/// the format is settled by the byte at offset 0 or by the name
/// (`extract::routing`'s offset-0 sniff, `archive_sniff_eligible_name`),
/// and a file whose first signature sits at offset 0 is answered by that
/// sniff before a second candidate is ever looked for. So the launcher
/// stub is not decoration on this plane, it is the precondition for the
/// plane existing at all: without it there is no scan, no second
/// candidate, and the row would be a bare archive with an unread
/// appendix.
///
/// The second refusal is the same rule from the other side. The scan
/// folds `Rar!\x1a\x07\x00` and `Rar!\x1a\x07\x01` onto one
/// `SfxFamily::Rar`, so a RAR behind a RAR is one candidate said twice
/// and the client has nothing to choose between.
fn refuse_a_polyglot_the_client_never_has_to_read(c: &Container) -> Result<(), ContainerError> {
    let Some(second) = polyglot_family(c.polyglot) else {
        return Ok(());
    };
    if c.leading_bytes == 0 {
        return Err(ContainerError::Contradiction(format!(
            "polyglot = {second:?} with no launcher stub in front of it. The file would carry \
             its first signature at offset 0, where the client's offset-0 sniff answers the \
             format outright and never looks for a second candidate - so nothing would be \
             disambiguated and the row would measure a bare archive with bytes appended. \
             nzbkit::sfx::sfx_payload_at is the one place two container signatures are \
             weighed against each other, and it runs only behind a stub. Set leading_bytes \
             (C9), or drop the polyglot key"
        )));
    }
    let first = if c.kind.is_sevenz() { "7z" } else { "rar" };
    if first == second {
        return Err(ContainerError::Contradiction(format!(
            "polyglot = {second:?} beside a {first} container names ONE format twice. C8 is \
             format disambiguation and the client's scan folds both RAR signatures onto a \
             single nzbkit::sfx::SfxFamily, so a second archive of the same family gives it \
             nothing to choose between - the earliest match wins for the same reason it would \
             have won with no second archive there. Select the other format"
        )));
    }
    Ok(())
}

/// Refuse a 7z profile that selected something only a RAR archive has.
///
/// Each of these is a key that means nothing in the 7z format rather
/// than a writer gap, so the fix is deleting the key. They are refused
/// rather than ignored for the reason the whole crate refuses a plane
/// it did not apply: a profile whose selection was silently dropped is
/// green for a shape nobody asked for.
fn refuse_a_sevenz_shape_that_is_rars(c: &Container, split: bool) -> Result<(), ContainerError> {
    if c.version != RarVersion::default() {
        return Err(ContainerError::Contradiction(format!(
            "version = {:?} names a RAR GENERATION and this profile selects a 7z container. \
             Drop the key, or select a rar kind",
            version_word(c)
        )));
    }
    // ENCRYPTION IS NOT REFUSED HERE ANY MORE, and the arm that used to
    // be is worth knowing about. Until 4 Sep 2026 an encrypted 7z
    // profile was a `NoWriter`: `crate::sevenz::write_archive` set a
    // content method and pushed entries, was handed no password, and
    // emitted an archive that opened for ANYONE while the profile
    // claimed C4 - and `extract_kind` dropped the password on the floor
    // on the way back, so the round trip agreed with itself. Both halves
    // moved together (claim `postfast-sevenz-encryption`): the writer
    // takes a `crate::sevenz::Encrypt`, the reader takes the level's
    // password, and the vendored crate grew a caller-supplied entropy
    // source so the salt and the IV stop coming from the OS. The
    // control is `sevenz::tests::an_encrypted_archive_does_not_open_unpassworded`.
    if c.recovery_record_pct > 0 {
        return Err(ContainerError::NoWriter {
            shape: format!(
                "recovery_record_pct = {} on a 7z archive",
                c.recovery_record_pct
            ),
            writer: "C10 is RAR's own in-archive recovery record and the 7z format has no \
                     equivalent, so there is no writer to grow. Select a rar kind with \
                     version = \"rar5\", or protect the post with a PAR2 set ([recovery])"
                .into(),
        });
    }
    if split && c.volume_style != VolumeStyle::default() {
        return Err(ContainerError::Contradiction(format!(
            "volume_style = {:?} beside a 7z container selects a spelling the format does not \
             have: a split 7z is `<name>.7z.001`, `.002`, ... and nothing else, because the \
             parts are the archive cut up and the index is the only thing that tells them \
             apart. C11 is the RAR plane. Drop the style",
            c.volume_style
        )));
    }
    if split && c.volume_names == VolumeNames::Opaque {
        return Err(ContainerError::Contradiction(
            "volume_names = \"opaque\" beside a SPLIT 7z container asks for a set nothing can \
             reassemble. C6's premise is that the ordering comes from the CONTENT, and it \
             holds for RAR because every volume carries a header of its own; a 7z part past \
             the first is raw archive bytes with no signature, no index and nothing to sort \
             on, so an independently-tokened set is unrecoverable rather than merely hard. \
             Set volume_bytes = 0, or select a rar kind"
                .into(),
        ));
    }
    Ok(())
}

/// Refuse a zip profile that selected something only a RAR archive has,
/// or a zip shape this writer does not build.
///
/// The 7z twin of this function is [`refuse_a_sevenz_shape_that_is_rars`]
/// and the arms are deliberately NOT shared: each message names the
/// writer entry point that would have to grow and the alternative that
/// carries the plane today, and those differ per format. A shared arm
/// would have to say "some format" in both.
fn refuse_a_zip_shape_that_is_rars(c: &Container, split: bool) -> Result<(), ContainerError> {
    if c.version != RarVersion::default() {
        return Err(ContainerError::Contradiction(format!(
            "version = {:?} names a RAR GENERATION and this profile selects a zip container. \
             Drop the key, or select a rar kind",
            version_word(c)
        )));
    }
    if c.encryption != Encryption::None {
        // As with 7z, NOT a key that means nothing in the format: zip
        // encrypts two ways and `nzbkit::zip` reads both (ZipCrypto and
        // WinZip AE, in `Archive::read_entry_to_with`). It is the
        // WRITER that has no arm, and turning one on is a bigger
        // decision than a feature flip: the `zip` crate gates its AE
        // writer behind `aes-crypto`, which pulls `getrandom/std` for
        // the key salt with no seeded alternative anywhere in its API.
        // That is exactly the reproducibility problem the RAR arms had
        // until `rars::Entropy` landed on 4 Sep 2026, and `rars` was
        // ours to change while this crate is not.
        return Err(ContainerError::NoWriter {
            shape: format!("an encrypted {} archive", shape_word(c)),
            writer: "crate::zip::write_archive drives the zip crate's ZipWriter, which this \
                     crate builds with a compression method and a pinned timestamp and \
                     nothing else - it is handed no password and emits no encrypted entry, so \
                     the archive would open for anyone while the profile claimed C4. The \
                     crate's own AE writer is behind its `aes-crypto` feature and draws the \
                     key salt from `getrandom` with no seeded alternative, so turning it on \
                     would emit different bytes every run. The RAR writers take a password AND \
                     a caller-supplied entropy source on both generations, so kind = \
                     \"rar-stored\" or \"rar-compressed\" carries C4 and C5 today"
                .into(),
        });
    }
    if c.recovery_record_pct > 0 {
        return Err(ContainerError::NoWriter {
            shape: format!(
                "recovery_record_pct = {} on a zip archive",
                c.recovery_record_pct
            ),
            writer: "C10 is RAR's own in-archive recovery record and the zip format has no \
                     equivalent, so there is no writer to grow. Select a rar kind with \
                     version = \"rar5\", or protect the post with a PAR2 set ([recovery])"
                .into(),
        });
    }
    if split && c.volume_style != VolumeStyle::default() {
        return Err(ContainerError::Contradiction(format!(
            "volume_style = {:?} beside a zip container selects a RAR spelling. A split zip \
             this crate emits is `<name>.zip.001`, `.002`, ... and nothing else, because the \
             parts are the archive cut up and the index is the only thing that tells them \
             apart. The format's OTHER multi-part spelling - WinZip spanning, `.z01` ... with \
             the trailing `.zip` holding the central directory - is a grammar rather than a \
             style: `nzbkit::zip` reads it, the zip crate's writer emits neither the spanning \
             marker nor the per-entry disk numbers it needs, and crate::zip's header says why \
             it is left unemitted rather than hand-assembled. C11 is the RAR plane. Drop the \
             style",
            c.volume_style
        )));
    }
    if split && c.volume_names == VolumeNames::Opaque {
        return Err(ContainerError::Contradiction(
            "volume_names = \"opaque\" beside a SPLIT zip container asks for a set nothing can \
             reassemble. C6's premise is that the ordering comes from the CONTENT, and it \
             holds for RAR because every volume carries a header of its own. A byte-split zip \
             is worse off than a split 7z: the central directory sits at the END of the \
             archive, so part one carries an index of nothing and every later part is raw \
             bytes with no signature to sort on. `nzbkit::zip`'s bare-numeric arm only admits \
             a `.001` set whose FIRST part carries the magic, and an opaque set is not \
             numbered at all. Set volume_bytes = 0, or select a rar kind"
                .into(),
        ));
    }
    Ok(())
}

/// The stem a container and its NZB are named after: the first source
/// file's basename with its extension off.
fn post_stem(sources: &[SourceFile]) -> String {
    let first = &sources[0].base;
    first
        .rsplit_once('.')
        .map_or(first.as_str(), |(s, _)| s)
        .to_string()
}

/// `rar4` or `rar5`, for a message.
fn version_word(c: &Container) -> &'static str {
    match c.version {
        RarVersion::Rar4 => "rar4",
        RarVersion::Rar5 => "rar5",
    }
}

/// The 7z writer's spelling of this level's encryption selection.
///
/// The twin of [`features`], which is the RAR writers' spelling of the
/// same key. Both read `c.password`, which `level_stack` has already
/// resolved to the level's own - an inner level with no password of its
/// own inherits the stack's there and not here, so no write site has to
/// know the inheritance rule.
fn sevenz_encrypt(c: &Container) -> crate::sevenz::Encrypt<'_> {
    match c.encryption {
        Encryption::None => crate::sevenz::Encrypt::None,
        Encryption::Data => crate::sevenz::Encrypt::Data(&c.password),
        // 7z header encryption gates the file list and the data with
        // it, exactly as both RAR generations do: one password derives
        // both keys, and the writer encrypts the end header with the
        // same AES configuration it gave the content.
        Encryption::Header => crate::sevenz::Encrypt::Header(&c.password),
    }
}

/// The feature set a profile's selections turn on.
fn features(c: &Container) -> FeatureSet {
    let mut f = FeatureSet::store_only();
    match c.encryption {
        Encryption::None => {}
        Encryption::Data => f.file_encryption = true,
        // Header encryption gates the file list too, and the data with
        // it: both writers derive the file key from the same password.
        Encryption::Header => {
            f.file_encryption = true;
            f.header_encryption = true;
        }
    }
    f
}

/// Which archive version the writers target.
///
/// RAR4 is spelled `Rar40` rather than `Rar29`: the two are the same
/// container generation to a reader, and `Rar40` is the only 1.5-family
/// target whose writer accepts header encryption
/// (`rar15_40::write::writer_supports_header_encryption`), so choosing
/// it is what lets one `version = "rar4"` selection carry C1 through C5
/// instead of carrying some of them.
fn target(c: &Container) -> ArchiveVersion {
    match c.version {
        RarVersion::Rar4 => ArchiveVersion::Rar40,
        RarVersion::Rar5 => ArchiveVersion::Rar50,
    }
}

/// A shape name for an error message.
fn shape_word(c: &Container) -> String {
    let kind = match c.kind {
        ContainerKind::None => "none",
        ContainerKind::RarStored | ContainerKind::SevenzStored | ContainerKind::ZipStored => {
            "stored"
        }
        ContainerKind::RarCompressed
        | ContainerKind::SevenzCompressed
        | ContainerKind::ZipCompressed => "compressed",
    };
    let enc = match c.encryption {
        Encryption::None => "",
        Encryption::Data => ", data-encrypted",
        Encryption::Header => ", header-encrypted",
    };
    let generation = if c.kind.is_sevenz() {
        "7z"
    } else if c.kind.is_zip() {
        "zip"
    } else {
        version_word(c)
    };
    format!("a {generation} {kind} archive{enc}")
}

fn writer_err(c: &Container, e: rars::Error) -> ContainerError {
    ContainerError::Writer {
        shape: shape_word(c),
        detail: e.to_string(),
    }
}

/// One unsplit archive holding `members`.
fn write_one_archive(
    c: &Container,
    members: &[(String, Vec<u8>)],
    seed: [u8; 32],
) -> Result<Vec<u8>, ContainerError> {
    if c.kind.is_zip() {
        return crate::zip::write_archive(members, c.kind.is_compressed()).map_err(|detail| {
            ContainerError::Writer {
                shape: shape_word(c),
                detail,
            }
        });
    }
    if c.kind.is_sevenz() {
        return crate::sevenz::write_archive(
            members,
            c.kind.is_compressed(),
            sevenz_encrypt(c),
            seed,
        )
        .map_err(|detail| ContainerError::Writer {
            shape: shape_word(c),
            detail,
        });
    }
    let entropy = rars::Entropy::Seeded(seed);
    let pw = c.password.as_bytes();
    let recovery = (c.recovery_record_pct > 0).then_some(u64::from(c.recovery_record_pct));
    match c.version {
        RarVersion::Rar5 => {
            let opts =
                rars::rar50::WriterOptions::new(target(c), features(c)).with_entropy(entropy);
            let w = rars::rar50::Rar50Writer::new(opts).recovery_percent(recovery);
            let bytes = match (c.kind, c.encryption) {
                (ContainerKind::None, _) => unreachable!("guarded by wrap"),
                (
                    ContainerKind::SevenzStored
                    | ContainerKind::SevenzCompressed
                    | ContainerKind::ZipStored
                    | ContainerKind::ZipCompressed,
                    _,
                ) => {
                    unreachable!("only a rar kind reaches the rar writers")
                }
                (ContainerKind::RarStored, Encryption::None) => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::StoredEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                        })
                        .collect();
                    w.stored_entries(&e).finish()
                }
                (ContainerKind::RarStored, _) => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::EncryptedStoredEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                            password: pw,
                        })
                        .collect();
                    w.encrypted_stored_entries(&e).finish()
                }
                (ContainerKind::RarCompressed, Encryption::None) => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::CompressedEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                        })
                        .collect();
                    w.compressed_entries(&e).finish()
                }
                (ContainerKind::RarCompressed, _) => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::EncryptedCompressedEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                            password: pw,
                        })
                        .collect();
                    w.encrypted_compressed_entries(&e).finish()
                }
            };
            bytes.map_err(|e| writer_err(c, e))
        }
        RarVersion::Rar4 => {
            // Both halves or neither: `rar15_40` refuses a percent with
            // the feature flag off (`validate_recovery_request`) rather
            // than dropping it, which is what makes a row asserting a
            // record over an archive carrying none unreachable here.
            let mut f = features(c);
            f.recovery_record = recovery.is_some();
            let mut opts = rars::rar15_40::WriterOptions::new(target(c), f).with_entropy(entropy);
            if let Some(percent) = recovery {
                opts = opts.with_recovery_percent(percent as u32);
            }
            let password = (c.encryption != Encryption::None).then_some(pw);
            let bytes = match c.kind {
                ContainerKind::None => unreachable!("guarded by wrap"),
                ContainerKind::SevenzStored
                | ContainerKind::SevenzCompressed
                | ContainerKind::ZipStored
                | ContainerKind::ZipCompressed => {
                    unreachable!("only a rar kind reaches the rar writers")
                }
                ContainerKind::RarStored => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar15_40::StoredEntry {
                            name: n.as_bytes(),
                            data: d,
                            file_time: 0,
                            file_attr: 0,
                            host_os: 0,
                            password,
                            file_comment: None,
                        })
                        .collect();
                    rars::rar15_40::write_stored_archive(&e, opts)
                }
                ContainerKind::RarCompressed => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar15_40::FileEntry {
                            name: n.as_bytes(),
                            data: d,
                            file_time: 0,
                            file_attr: 0,
                            host_os: 0,
                            password,
                            file_comment: None,
                        })
                        .collect();
                    rars::rar15_40::write_compressed_archive(&e, opts)
                }
            };
            bytes.map_err(|e| writer_err(c, e))
        }
    }
}

/// A split set holding `members`.
///
/// Every arm takes the whole slice since 4 Sep 2026. The RAR4 pair is
/// the one place the member count still picks the entry point:
/// `write_stored_volumes` / `write_compressed_volumes` and the
/// `_volume_set` plurals beside them write DIFFERENT bytes for one
/// member - the set writers close every volume with an ENDARC block,
/// which a single member split across every volume does not need and
/// which no shipped single-member row carries - so a one-member RAR4
/// split stays on the writer it has always used.
fn write_volume_set(
    c: &Container,
    members: &[(String, Vec<u8>)],
    seed: [u8; 32],
) -> Result<Vec<Vec<u8>>, ContainerError> {
    let per_volume = usize::try_from(c.volume_bytes).unwrap_or(usize::MAX);
    if c.kind.is_sevenz() || c.kind.is_zip() {
        // A multi-volume 7z, and a byte-split zip, are the finished
        // archive CUT, with no per-volume header anywhere - see
        // `crate::sevenz`'s own header and `crate::zip`'s. So
        // `volume_bytes` means bytes of ARCHIVE per part here, where on
        // the RAR path it means payload bytes per volume: same key, and
        // the difference is the format's, not this crate's. The catalog
        // note on a split row of either kind says so.
        //
        // ONE cut for both, and it lives in `crate::sevenz` because
        // that is where the argument for why a cut is not
        // hand-assembly was first written. Chunking a byte slice at a
        // fixed offset knows nothing about either format, so a second
        // copy in `crate::zip` would be a second copy of one rule.
        let whole = write_one_archive(c, members, seed)?;
        return Ok(crate::sevenz::split_parts(&whole, per_volume));
    }
    let entropy = rars::Entropy::Seeded(seed);
    let pw = c.password.as_bytes();
    let one = &members[0];
    match c.version {
        RarVersion::Rar5 => {
            let opts =
                rars::rar50::WriterOptions::new(target(c), features(c)).with_entropy(entropy);
            let recovery = (c.recovery_record_pct > 0).then_some(u64::from(c.recovery_record_pct));
            let w = rars::rar50::Rar50VolumeWriter::new(opts)
                .max_payload_per_volume(per_volume)
                .recovery_percent(recovery);
            let bytes = match (c.kind, c.encryption) {
                (ContainerKind::None, _) => unreachable!("guarded by wrap"),
                (
                    ContainerKind::SevenzStored
                    | ContainerKind::SevenzCompressed
                    | ContainerKind::ZipStored
                    | ContainerKind::ZipCompressed,
                    _,
                ) => {
                    unreachable!("only a rar kind reaches the rar writers")
                }
                (ContainerKind::RarStored, Encryption::None) => {
                    // The whole slice, not `one`: a plain RAR5 stored
                    // set carries several members since the H0 writer
                    // arm landed. One member still splits across the
                    // volumes exactly as before - `stored_entries` with
                    // a single entry packs it the same way.
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::StoredEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                        })
                        .collect();
                    w.stored_entries(&e).finish()
                }
                (ContainerKind::RarStored, _) => {
                    // The whole slice, not `one`: the encrypted stored
                    // plural landed beside the singular on 4 Sep 2026,
                    // which is what stopped an encrypted split set
                    // being compressed-only.
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::EncryptedStoredEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                            password: pw,
                        })
                        .collect();
                    w.encrypted_stored_entries(&e).finish()
                }
                (ContainerKind::RarCompressed, Encryption::None) => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::CompressedEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                        })
                        .collect();
                    w.compressed_entries(&e).finish()
                }
                (ContainerKind::RarCompressed, _) => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar50::EncryptedCompressedEntry {
                            name: n.as_bytes(),
                            data: d,
                            mtime: None,
                            attributes: 0,
                            host_os: 0,
                            password: pw,
                        })
                        .collect();
                    w.encrypted_compressed_entries(&e).finish()
                }
            };
            bytes.map_err(|e| writer_err(c, e))
        }
        RarVersion::Rar4 => {
            // The volume COUNT the numbering depends on is not known
            // until the writer has cut the set, and the writer needs the
            // setting to cut it. It is knowable anyway: this arm is only
            // reached for a SPLIT container, and every RAR4 writer below
            // refuses a payload that does not reach two volumes, so `n`
            // is at least 2 whenever these bytes exist.
            let opts = rars::rar15_40::WriterOptions::new(target(c), features(c))
                .with_entropy(entropy)
                .with_volume_numbering(rar4_volume_numbering(c, 2));
            let password = (c.encryption != Encryption::None).then_some(pw);
            let bytes = match c.kind {
                ContainerKind::None => unreachable!("guarded by wrap"),
                ContainerKind::SevenzStored
                | ContainerKind::SevenzCompressed
                | ContainerKind::ZipStored
                | ContainerKind::ZipCompressed => {
                    unreachable!("only a rar kind reaches the rar writers")
                }
                ContainerKind::RarStored if members.len() > 1 => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar15_40::StoredEntry {
                            name: n.as_bytes(),
                            data: d,
                            file_time: 0,
                            file_attr: 0,
                            host_os: 0,
                            password,
                            file_comment: None,
                        })
                        .collect();
                    rars::rar15_40::write_stored_volume_set(&e, opts, per_volume)
                }
                ContainerKind::RarStored => rars::rar15_40::write_stored_volumes(
                    rars::rar15_40::StoredEntry {
                        name: one.0.as_bytes(),
                        data: &one.1,
                        file_time: 0,
                        file_attr: 0,
                        host_os: 0,
                        password,
                        file_comment: None,
                    },
                    opts,
                    per_volume,
                ),
                ContainerKind::RarCompressed if members.len() > 1 => {
                    let e: Vec<_> = members
                        .iter()
                        .map(|(n, d)| rars::rar15_40::FileEntry {
                            name: n.as_bytes(),
                            data: d,
                            file_time: 0,
                            file_attr: 0,
                            host_os: 0,
                            password,
                            file_comment: None,
                        })
                        .collect();
                    rars::rar15_40::write_compressed_volume_set(&e, opts, per_volume)
                }
                ContainerKind::RarCompressed => rars::rar15_40::write_compressed_volumes(
                    rars::rar15_40::FileEntry {
                        name: one.0.as_bytes(),
                        data: &one.1,
                        file_time: 0,
                        file_attr: 0,
                        host_os: 0,
                        password,
                        file_comment: None,
                    },
                    opts,
                    per_volume,
                ),
            };
            bytes.map_err(|e| writer_err(c, e))
        }
    }
}

/// Refuse a compressed selection the writer answered by storing.
///
/// The RAR writers fall back to store per entry whenever compression
/// would not shrink it, and say nothing. That is right for an archiver
/// and wrong for a fixture generator: the emitted bytes would exercise
/// the client's STORED path under a profile whose whole point is
/// decompression, and the row would be green for a reason nobody asked
/// for. Measured 3 Sep 2026 on a 32 KiB `[source]` file: the member
/// comes back `is_stored: true` and the archive is 87 bytes LARGER
/// than the payload.
///
/// Checked on every level of a nested set and on the posted set of a
/// split one, because `kind` applies at every level.
///
/// **It takes the whole SET and not volume one, and on the two CUT
/// formats that is load-bearing.** A RAR volume carries a header of its
/// own and can be read alone, so the first volume was all this ever
/// needed. A 7z split set is the finished archive CUT (`crate::sevenz`'s
/// header) and its end header is at the TAIL, so part one on its own
/// parses as "next header offset out of range" - and the guard reported
/// that as a `RoundTrip`, which is the generator's way of saying "the
/// writer emitted something nothing can open", over an archive that
/// opens perfectly well. A byte-split zip is cut the same way and its
/// central directory is at the tail too, so the same thing was true of
/// the zip arm the moment it landed.
///
/// Found 4 Sep 2026 while lifting the encrypted-7z refusal, by asking
/// what else the refusal had been standing in front of. It was reachable
/// before that and by a plain profile - `kind = "7z-compressed"` with
/// any `volume_bytes` - and no catalog row had selected the pair, which
/// is the whole reason a latent arm like this survives: the shape it
/// refuses is one nobody had written down yet.
fn refuse_a_compressed_archive_that_stored(
    c: &Container,
    set: &[Vec<u8>],
) -> Result<(), ContainerError> {
    if !c.kind.is_compressed() {
        return Ok(());
    }
    if c.kind.is_zip() {
        // Per ENTRY here, where 7z records one method for the whole
        // archive: in a zip the method is the entry's own property, so
        // a writer that stored one member of several would be a partial
        // C3, and looking at EVERY entry is what catches it. Asked at
        // all for the reason
        // the 7z arm is asked - a future bump that grew a store
        // fallback would otherwise turn every zip C3 row green over an
        // archive nothing had to inflate.
        //
        // The whole SET, for the reason the header above gives about
        // the 7z arm and which applies here verbatim: a byte-split zip
        // is the finished archive cut, its central directory is at the
        // TAIL, and part one alone parses as no zip at all.
        let joined: Vec<u8> = set.concat();
        let methods = crate::zip::declared_methods(&joined).map_err(ContainerError::RoundTrip)?;
        if methods.contains(&crate::zip::STORED) {
            return Err(ContainerError::NothingToCompress);
        }
        return Ok(());
    }
    if c.kind.is_sevenz() {
        // The 7z writer records ONE content method for the archive and
        // never falls back per entry, so the question here is whether
        // the header says LZMA2 - not whether the bytes got smaller,
        // which for an incompressible payload they do not. Asked all
        // the same, because a future writer bump that grew a store
        // fallback would otherwise turn every 7z C3 row green over a
        // COPY archive in silence.
        //
        // With the level's password: a HEADER-encrypted archive keeps
        // its coder list inside the encrypted end header, so this check
        // parses nothing without it and would report a RoundTrip failure
        // over an archive that is perfectly well formed.
        let joined: Vec<u8> = set.concat();
        let method = crate::sevenz::declared_method(&joined, sevenz_encrypt(c).password())
            .map_err(ContainerError::RoundTrip)?;
        if method.as_deref() == Some(crate::sevenz::COPY_ID) {
            return Err(ContainerError::NothingToCompress);
        }
        return Ok(());
    }
    let bytes = &set[0];
    // A header-encrypted archive cannot be walked without its password,
    // and the read-back below already opens the set with one; this is
    // the cheap pre-check, so it uses the plain reader and skips the
    // shape it cannot see rather than deriving a key twice.
    let Ok(archive) = ArchiveReader::read(bytes) else {
        return Ok(());
    };
    let mut any = false;
    let mut compressed = false;
    for m in archive.members() {
        any = true;
        compressed |= !m.meta.is_stored;
    }
    if any && !compressed {
        return Err(ContainerError::NothingToCompress);
    }
    Ok(())
}

/// C8: the SECOND archive of a polyglot, complete and openable on its
/// own, carrying [`POLYGLOT_MEMBER`] and nothing else.
///
/// Written by the same two libraries every other archive in this module
/// comes from, for the same reason: an approximation assembled here
/// would be a fixture that agrees with our own reader and with nothing
/// else, and a POLYGLOT whose second half was not really an archive is
/// not a polyglot at all - it is a bare archive with junk appended, and
/// a row over it would be green without the client having had a second
/// candidate to decline.
///
/// Stored on both arms. The plane is which SIGNATURE the client trusts,
/// and a compressed second archive would put an LZMA2 decode behind an
/// answer the row wants to be about the scan.
fn polyglot_tail(p: Polyglot) -> Result<Vec<u8>, ContainerError> {
    if p == Polyglot::None {
        return Ok(Vec::new());
    }
    let members = vec![(
        POLYGLOT_MEMBER.to_string(),
        vec![POLYGLOT_MEMBER_FILL; POLYGLOT_MEMBER_BYTES],
    )];
    match p {
        Polyglot::None => unreachable!("returned above"),
        Polyglot::SevenZ => {
            // Never encrypted, and a fixed seed for the same reason the
            // RAR arm below gives: the second archive is furniture, no
            // key of the profile shapes it, and it must not spend a draw
            // from the entropy stream. With `Encrypt::None` the 7z
            // writer draws nothing at all, so the seed is inert - it is
            // passed because the signature takes one, and passing a
            // drawn one would make a C8 row's second half move when an
            // unrelated level started encrypting.
            crate::sevenz::write_archive(&members, false, crate::sevenz::Encrypt::None, [0u8; 32])
                .map_err(|e| ContainerError::Writer {
                    shape: "the 7z half of a polyglot".into(),
                    detail: e,
                })
        }
        Polyglot::Rar => {
            let c = Container {
                kind: ContainerKind::RarStored,
                version: RarVersion::Rar5,
                ..Container::default()
            };
            // A fixed seed rather than a draw, for the reason the 7z
            // arm above gives. An unencrypted RAR5 writer touches the
            // entropy only for a salt it never emits, and a SEEDED
            // source is the one that is reproducible at all - both
            // writers default to the OS, which the seed a write site
            // takes replaces for the duration of one archive.
            write_one_archive(&c, &members, [0u8; 32])
        }
    }
}

/// Which archive family a polyglot's second half belongs to, in the
/// client's own vocabulary.
///
/// `nzbkit::sfx::SfxFamily` is what `sfx_payload_at` returns, and it is
/// deliberately the comparison this crate makes too: the disambiguation
/// the plane exists to exercise is over FAMILY, so a refusal that
/// compared anything finer would let a shape through that the client
/// cannot tell apart from a single archive.
fn polyglot_family(p: Polyglot) -> Option<&'static str> {
    match p {
        Polyglot::None => None,
        Polyglot::Rar => Some("rar"),
        Polyglot::SevenZ => Some("7z"),
    }
}

/// A launcher-stub-shaped prefix of exactly `len` bytes.
///
/// A structurally valid PE header - `MZ`, an `e_lfanew` at 0x3c
/// pointing at 0x40, `PE\0\0` there - because that is what the client
/// reads: `nzbkit::sfx::is_launcher_stub` walks `e_lfanew` rather than
/// trusting the two-byte magic, and the M4-101 record in its header
/// says why (a data file that merely CONTAINS an archive must not be
/// carved). The filler is zeros and draws nothing from the seed: a
/// prefix drawn from the stream would move every message-id of a layout
/// whose only change was its stub length, and zeros cannot contain a
/// second RAR signature for the scan to find first.
fn sfx_stub(len: u64) -> Vec<u8> {
    let mut v = vec![0u8; usize::try_from(len).unwrap_or(usize::MAX)];
    v[0] = b'M';
    v[1] = b'Z';
    v[0x3c..0x40].copy_from_slice(&0x40u32.to_le_bytes());
    v[0x40..0x44].copy_from_slice(b"PE\0\0");
    v
}

/// Which numbering a RAR4 volume set's headers DECLARE, which has to be
/// the one [`volume_names`] then spells.
///
/// The RAR4 writer never sees a file name, so `MHD_NEWNUMBERING` cannot
/// be inferred there and arrives as a `WriterOptions` setting. Left
/// disagreeing with the names, the set is one no reference reader can
/// follow: on a `.partNN.rar` set whose headers say classic, unrar 7.23
/// swaps the first volume's EXTENSION, looks for `<stem>.part01.r00`,
/// says `Cannot find volume` and then reports a checksum error on the
/// member it had to truncate. Our own client passes such a set either
/// way, because it joins volumes from the NZB and not from the archive
/// headers, which is how `c2-rar4-stored-split` shipped one for months
/// with nothing noticing. That row's note carries the rest.
///
/// So this reads the same three fields `volume_names` reads and answers
/// `NewStyle` for exactly the case that produces `.partNN.rar`;
/// `the_declared_rar4_numbering_matches_the_names_emitted` holds the
/// mirrored rule to the names actually emitted. `Numeric` and C6's
/// opaque tokens answer `Classic`, because measured, unrar follows a
/// `<stem>.001` set under either setting and an opaque set under
/// neither - so the honest answer to both is the one claiming no
/// `.partNN` naming.
fn rar4_volume_numbering(c: &Container, n: usize) -> rars::rar15_40::VolumeNumbering {
    let partnn = n > 1
        && c.volume_names == VolumeNames::Descriptive
        && !(c.kind.is_sevenz() || c.kind.is_zip())
        && c.volume_style == VolumeStyle::PartNn;
    if partnn {
        rars::rar15_40::VolumeNumbering::NewStyle
    } else {
        rars::rar15_40::VolumeNumbering::Classic
    }
}

/// The name each volume goes on the wire under.
///
/// Draws from the seed once per volume under C6 and not at all
/// otherwise; see [`wrap`]'s header for why that matters.
fn volume_names(c: &Container, stem: &str, n: usize, rng: &mut Rng) -> Vec<String> {
    if c.volume_names == VolumeNames::Opaque {
        // C6: an INDEPENDENT token per volume, and `.bin` on all of
        // them. Nothing in the name says which volume this is or that
        // the volumes belong together, which is the row: reassembly has
        // to come from the content. `.bin` rather than no extension
        // because it is this product's commonest obfuscated-volume
        // extension and the one `nzbkit::sfx::is_sfx_name` admits, so a
        // C6+C9 profile is one selection away.
        return (0..n).map(|_| format!("{}.bin", rng.token())).collect();
    }
    if n == 1 {
        // C9's single volume is the file the client scans for a stub,
        // and it only scans a name that could be a self-extractor.
        let ext = if c.leading_bytes > 0 {
            "exe"
        } else {
            c.kind.extension()
        };
        return vec![format!("{stem}.{ext}")];
    }
    if c.kind.is_sevenz() || c.kind.is_zip() {
        // A split set of either cut kind has ONE spelling -
        // `<name>.7z.001` / `<name>.zip.001`, `.002`, ... zero-padded
        // to three - because the parts are the archive cut up and the
        // index is all that tells them apart. It is also the spelling
        // the client's own detectors read: `nzbkit::zip::split_part_name`
        // "Mirrors the 7z `split_7z_part` grammar exactly, with
        // `.zip`/`.zipx` as the stem". C11 is RAR's plane and is
        // refused beside both kinds, so there is no style to consult
        // here.
        let ext = c.kind.extension();
        return (0..n)
            .map(|i| format!("{stem}.{ext}.{:03}", i + 1))
            .collect();
    }
    // Two digits is what every real archiver writes for a set this
    // size, and a wider set widens rather than truncating.
    let width = 2.max(n.to_string().len());
    (0..n)
        .map(|i| match c.volume_style {
            VolumeStyle::PartNn => format!("{stem}.part{:0width$}.rar", i + 1, width = width),
            VolumeStyle::R00 if i == 0 => format!("{stem}.rar"),
            VolumeStyle::R00 => format!("{stem}.r{:0width$}", i - 1, width = width),
            VolumeStyle::Numeric => format!("{stem}.{:0width$}", i + 1, width = 3.max(width)),
        })
        .collect()
}

/// Read the whole set back with each level's own reader and prove it
/// holds the payload that went in.
///
/// Peels exactly as many wrapping levels as `stack` has, because this
/// stage KNOWS how many it wrote: guessing by sniffing each extracted
/// member for an archive signature would pass over a set that nested
/// one level too few, which is the defect most worth catching. The
/// FORMAT comes from the same place for the same reason - `stack` is
/// innermost-first, so peel `p` from the outside reads level
/// `stack.len() - 1 - p`, and a mixed stack whose levels the writer
/// built in the wrong order fails here rather than at the client.
fn read_the_set_back(
    outer: &Container,
    stack: &[Level],
    volumes: &[Vec<u8>],
    sources: &[SourceFile],
    escapes: &[(String, Vec<u8>)],
    extras: &[usize],
) -> Result<(), ContainerError> {
    let deepest = stack.len() - 1;
    let mut set: Vec<Vec<u8>> = volumes.to_vec();
    // C9: the stub is stepped over rather than scanned past. This stage
    // wrote the prefix and knows how long it is, and only one of the two
    // readers would find the archive behind it anyway - `rars` scans for
    // a signature, `sevenz_rust2::ArchiveReader` requires one at offset
    // 0 and answers `BadSignature([77, 90, ..])`, the `MZ` of our own
    // stub. Leaning on the scan is what left `leading_bytes` unusable on
    // a 7z kind with nothing refusing it and a message that named a
    // WRITER defect for a reader limitation. A polyglot's trailing
    // second archive needs no such step: both readers take an archive's
    // extent from its own headers and ignore what follows.
    //
    // What this stops proving is that `rars` can scan past our stub,
    // which was never the property - it is a fact about that library and
    // the 7z reader does not share it. That the EMITTED file presents
    // the stub the profile asked for is asserted against the client's
    // own locator instead, in
    // `tests::c9_leading_bytes_are_a_launcher_stub` and
    // `tests::c8_is_two_confirmed_archives_and_the_client_settles_on_the_earlier`,
    // which is a stronger check than a reader that happened to cope.
    if outer.leading_bytes > 0 {
        let head = set.first_mut().expect("a set holds at least a volume");
        let at = usize::try_from(outer.leading_bytes).unwrap_or(usize::MAX);
        if head.len() <= at {
            return Err(ContainerError::RoundTrip(format!(
                "the first volume is {} bytes and the launcher stub in front of it is {at}",
                head.len()
            )));
        }
        *head = head.split_off(at);
    }
    // C14: what a level should hold beside the archive below it, keyed
    // by the level's index from the OUTSIDE, which is how this loop
    // counts.
    let mut set_aside: Vec<(String, Vec<u8>)> = Vec::new();
    for level in 0..=deepest {
        let lc = &stack[deepest - level].c;
        // THIS level's password, not the stack's. A chain gives each
        // level its own, and reading every level with the outermost
        // one would fail the chain here - or, worse, pass a stack whose
        // inner levels had all silently been written with the outer
        // password.
        let password = (lc.encryption != Encryption::None).then_some(lc.password.as_bytes());
        let out = extract_kind(lc.kind, &set, password)
            .map_err(|e| ContainerError::RoundTrip(format!("at nesting level {level}: {e}")))?;
        // The archive below (or, at the bottom, the payload) comes
        // first and this level's siblings follow it, in the order
        // `wrap` wrote them.
        let below = if level == deepest { sources.len() } else { 1 };
        let (carried, beside) = out.split_at(out.len().min(below));
        set_aside.extend(beside.iter().cloned());
        if level == deepest {
            let want: Vec<(String, usize)> = sources
                .iter()
                .map(|s| (s.rel.clone(), s.bytes.len()))
                .collect();
            let got: Vec<(String, usize)> =
                carried.iter().map(|(n, b)| (n.clone(), b.len())).collect();
            if got != want {
                return Err(ContainerError::RoundTrip(format!(
                    "the payload came back as {got:?}, and the sources are {want:?}"
                )));
            }
            for ((name, bytes), s) in carried.iter().zip(sources) {
                if bytes != &s.bytes {
                    return Err(ContainerError::RoundTrip(format!(
                        "{name} came back with different bytes than went in"
                    )));
                }
            }
            // Every sibling of every level, once, and nothing else.
            // Sorted on both sides because they come off the stack
            // innermost-first and off the peel outermost-first, and
            // which order a level's own list lands in is not the fact
            // under test - "all of them, byte for byte" is.
            let mut got_sib = set_aside;
            let mut want_sib = escapes.to_vec();
            got_sib.sort_by(|a, b| a.0.cmp(&b.0));
            want_sib.sort_by(|a, b| a.0.cmp(&b.0));
            if got_sib != want_sib {
                let names = |v: &[(String, Vec<u8>)]| {
                    v.iter()
                        .map(|(n, b)| format!("{n} ({} bytes)", b.len()))
                        .collect::<Vec<_>>()
                };
                return Err(ContainerError::RoundTrip(format!(
                    "the siblings came back as {:?}, and the stack declares {:?}",
                    names(&got_sib),
                    names(&want_sib)
                )));
            }
            return Ok(());
        }
        // An inner level holds the archive below it, plus exactly what
        // `wrap` put there beside it: this level's siblings (C14) and
        // the recovery set the level below packed up here (C15). More
        // or fewer would mean the generator had lost count of its own
        // nesting, which is the defect this check exists for.
        let want = 1 + extras[deepest - level];
        if out.len() != want {
            return Err(ContainerError::RoundTrip(format!(
                "nesting level {level} holds {} members and must hold {want} - the archive \
                 below it, {} sibling(s), and the {} recovery file(s) the level below packs \
                 up here",
                out.len(),
                lc.siblings.len(),
                extras[deepest - level] - lc.siblings.len()
            )));
        }
        set = vec![
            carried
                .first()
                .expect("a level holds at least the archive below it")
                .1
                .clone(),
        ];
    }
    unreachable!("the loop returns at the deepest level")
}

/// Extract one archive or volume set into (name, bytes), in archive
/// order, with whichever reader the KIND names.
///
/// The kind and not a signature sniff: this stage knows what it wrote,
/// and sniffing would quietly read a level the writer built in the
/// wrong format as though it were right.
fn extract_kind(
    kind: ContainerKind,
    set: &[Vec<u8>],
    password: Option<&[u8]>,
) -> Result<Vec<(String, Vec<u8>)>, String> {
    if kind.is_zip() {
        return crate::zip::extract_set(set);
    }
    if kind.is_sevenz() {
        // The password reaches the 7z reader too since 4 Sep 2026. It
        // was dropped on the floor before that, which was invisible
        // while `wrap` refused every encrypted 7z profile by name: the
        // writer was handed no password either, so the round trip agreed
        // with itself over an archive that opened for anyone.
        return crate::sevenz::extract_set(set, password.map(as_password_str));
    }
    extract_set(set, password)
}

/// The password as the `&str` the 7z reader takes.
///
/// `extract_kind` carries bytes because that is what the RAR reader
/// wants, and a profile password is a `String` at its source, so this is
/// a round trip through UTF-8 rather than a re-encoding: a password that
/// did not survive it would have been refused at profile load. Lossy so
/// there is no panic on a path a future non-UTF-8 password key could
/// reach; such a password would fail loudly at the round trip instead.
fn as_password_str(p: &[u8]) -> &str {
    std::str::from_utf8(p).unwrap_or_default()
}

/// Extract one RAR archive or volume set into (name, bytes), in archive
/// order.
fn extract_set(set: &[Vec<u8>], password: Option<&[u8]>) -> Result<Vec<(String, Vec<u8>)>, String> {
    let options = match password {
        Some(p) => ArchiveReadOptions::with_password(p),
        None => ArchiveReadOptions::new(),
    };
    let mut archives = Vec::with_capacity(set.len());
    for (i, bytes) in set.iter().enumerate() {
        archives.push(
            ArchiveReader::read_with_options(bytes, options)
                .map_err(|e| format!("volume {} does not parse: {e}", i + 1))?,
        );
    }
    // `Rc<RefCell<..>>` and not a channel or a `Mutex`: the closure and
    // the collector are on one thread and the reader's writers are
    // `Box<dyn Write>`, which has to own its sink.
    let out: Rc<RefCell<Vec<(String, Rc<RefCell<Vec<u8>>>)>>> = Rc::new(RefCell::new(Vec::new()));
    {
        let out = Rc::clone(&out);
        rars::extract_volumes_to_with_options(&archives, options, move |meta| {
            let cell = Rc::new(RefCell::new(Vec::new()));
            out.borrow_mut().push((meta.name_lossy(), Rc::clone(&cell)));
            Ok(Box::new(Collect(cell)) as Box<dyn Write>)
        })
        .map_err(|e| format!("the set does not extract: {e}"))?;
    }
    let taken = Rc::try_unwrap(out)
        .map_err(|_| "the extractor kept its writer alive past the walk".to_string())?
        .into_inner();
    Ok(taken
        .into_iter()
        .map(|(name, cell)| (name, cell.borrow().clone()))
        .collect())
}

/// A `Write` sink that keeps what it is given, for the round trip.
struct Collect(Rc<RefCell<Vec<u8>>>);

impl Write for Collect {
    fn write(&mut self, buf: &[u8]) -> std::io::Result<usize> {
        self.0.borrow_mut().extend_from_slice(buf);
        Ok(buf.len())
    }

    fn flush(&mut self) -> std::io::Result<()> {
        Ok(())
    }
}

// The case table, out of line so the production file keeps its whole
// ceiling: a `#[cfg(test)] mod foo;` TARGET is scored against size-gate's
// TEST_FILE_CEILING rather than the flat production one.
#[cfg(test)]
mod tests;
