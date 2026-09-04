//! `[fault]`, the generation-time half of plane 7.F: damage baked into
//! the EMITTED BYTES, as opposed to damage the server does to its
//! answers.
//!
//! The split is the whole point of having two tables. A serve-time
//! fault is a fact about one download - ask again, or ask a second
//! server, and the article is fine. A generation-time fault is a fact
//! about the POST: every client that ever fetches it gets the same
//! damaged header, the same short volume, the same unparseable index,
//! and no amount of re-asking helps. Only recovery data does. So these
//! rows are the ones that prove the repair path rather than the retry
//! path, and a row that mixes them up proves the wrong one.
//!
//! **The stream is this plane's own.** Faults draw from
//! `Rng::from_seed(seed ^ STREAM)` rather than from the layout stream
//! every other stage shares. The reason is diffability: a fault row is
//! almost always written by copying a clean row and adding a table, and
//! if the fault plane drew from the shared stream every opaque name and
//! every message-id in the copy would move, so the two layouts could
//! not be compared at all. It is still ONE source of randomness in the
//! sense `crate::rng`'s header means - the profile's seed, never the
//! operating system - and the derivation is a constant, so the same
//! seed picks the same packets on every box and every release.
//!
//! **Order of application, and why it is this one.** F6 first (a second
//! set is more files, and the faults below may land on them), then F7
//! (the index, which is a whole-file decision), then F4 (packets, over
//! what is left). F4 skips a damaged or absent index for the obvious
//! reason: there is nothing there for it to break that is not broken.
//!
//! **F3 and F5 need a container and refuse without one.** Both damage
//! an ARCHIVE - a header, or the tail of the last volume - so a profile
//! that selects one with `[container] kind = "none"` is refused by
//! name rather than having the damage applied to a payload file that is
//! not a volume: a row that truncated `movie.mkv` and called it a short
//! final volume would be a different test wearing this one's name.
//!
//! **And they run LAST, after the recovery set is built**, which is the
//! whole reason this stage sits where it does in `generate`. A PAR2 set
//! describes the bytes it was cut over; damaging a volume before the
//! set exists would produce a set that describes the damage, agrees
//! with it, and asks the client to repair nothing.

use crate::assemble::SourceFile;
use crate::container::Contained;
use crate::par2patch;
use crate::profile::{ContainerKind, IndexState, Profile, RecoveryKind};
use crate::recovery::{self, Recovered, RecoveryError};
use crate::rng::Rng;

/// The stream label for the generation-time fault plane, XORed into the
/// profile's seed. An arbitrary constant with no property but being
/// different from `crate::serve`'s, so the two planes' choices are
/// independent.
pub const STREAM: u64 = 0x4641_554c_5420_2020; // "FAULT   "

/// The base-name suffix F6's competing set is built under.
///
/// A DISTINCT base, or the second set would write over the first in the
/// same directory and the post would carry one set wearing two names -
/// the same rule `crate::recovery` states for P9's disjoint sets, for
/// the same reason.
const DUPLICATE_SUFFIX: &str = "-dup";

/// Why a generation-time fault could not be applied.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum FaultError {
    /// A fault this stage does not build. `plane` is what the author
    /// wrote; `owner` says which work lands it.
    NotImplemented { plane: String, owner: &'static str },
    /// A fault over a recovery set, on a profile that has none.
    NeedsARecoverySet(&'static str),
    /// A fault over an ARCHIVE, on a profile with no container.
    NeedsAnArchive(&'static str),
    /// `truncate_last_volume_bytes` at or past the volume's length.
    TruncationEatsTheVolume { asked: u64, volume: usize },
    /// A volume whose archive signature this stage does not know, so it
    /// cannot say where the header region begins.
    UnknownArchiveSignature(String),
    /// More packets asked for than the emitted set carries.
    NotEnoughPackets { asked: u32, packets: usize },
    /// `index = "absent"` over a set whose only file IS the index.
    AbsentIndexRemovesTheSet,
    /// Two two-set stories in one profile.
    TwoSetPlansAtOnce,
    /// F6 beside a patch that only the first set would carry.
    DuplicateSetWithPatchedNames,
    /// A naming-only index row whose set has more than one volume.
    VolumeCountNotGradeable { volumes: usize },
    /// The recovery plane refused while building F6's set.
    Recovery(Box<RecoveryError>),
    /// G1: `corrupt_payload` beside a container, where the posted files
    /// are volumes and the payload is not on the wire at all.
    PayloadDamageUnderAContainer,
    /// G1: `corrupt_payload` over a member no recovery set covers, so
    /// nothing in the post can rebuild it.
    PayloadDamageWithoutCover(String),
    /// G1: `corrupt_payload` over a member that is described and never
    /// posted, so the damage reaches no wire.
    PayloadDamageOnAnUnpostedMember(String),
}

impl std::fmt::Display for FaultError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::NotImplemented { plane, owner } => write!(
                f,
                "{plane} is not generated yet: it lands with {owner}. Refused rather than \
                 ignored, so a profile never passes because the damage it selects was \
                 silently not done"
            ),
            Self::NeedsARecoverySet(what) => write!(
                f,
                "[fault] {what} damages a PAR2 set and this profile has none. Select \
                 [recovery] kind = \"par2\", or drop the fault"
            ),
            Self::NeedsAnArchive(what) => write!(
                f,
                "[fault] {what} damages an ARCHIVE and this profile has no container, so \
                 there is no archive to damage. Select [container] kind, or drop the \
                 fault. It is refused rather than applied to a payload file, because a \
                 row that truncated a .mkv and called it a short final volume would be a \
                 different test wearing this one's name"
            ),
            Self::TruncationEatsTheVolume { asked, volume } => write!(
                f,
                "[fault] truncate_last_volume_bytes = {asked} and the last volume is \
                 {volume} bytes. A volume cut to nothing is an absent file, which is a \
                 serve-time fault and not a short tail: raise [container] volume_bytes, or \
                 cut less"
            ),
            Self::UnknownArchiveSignature(head) => write!(
                f,
                "[fault] corrupt_headers = true and the volume does not begin with a RAR \
                 signature this stage knows (starts {head}). Failing to find is failing: \
                 without the signature there is no way to say where the header region \
                 ends and the payload begins, and a flipped byte in the payload is a \
                 different fault"
            ),
            Self::NotEnoughPackets { asked, packets } => write!(
                f,
                "[fault] corrupt_recovery_packets = {asked} and the emitted set carries \
                 {packets} damageable packet(s). Raise [recovery] redundancy_pct so the set \
                 has volumes to damage, or ask for fewer"
            ),
            Self::AbsentIndexRemovesTheSet => f.write_str(
                "[recovery] index = \"absent\" over an index-only set (redundancy_pct = 0) \
                 removes every file the set has, so the layout carries no recovery data at \
                 all rather than the P7 shape of naming from the volumes",
            ),
            Self::TwoSetPlansAtOnce => f.write_str(
                "[fault] duplicate_set = true beside [recovery] second_covers: P9 is two \
                 sets over DISJOINT members and F6 is two sets over the SAME members, and a \
                 post carrying both has no end state this catalog can state. Select one",
            ),
            Self::DuplicateSetWithPatchedNames => f.write_str(
                "[fault] duplicate_set = true beside [recovery] hostile_names: the patch is \
                 applied to the first set only, so the two sets would describe one member \
                 under two different names and which one the client files it under is its \
                 answer rather than a requirement",
            ),
            Self::VolumeCountNotGradeable { volumes } => write!(
                f,
                "[recovery] index is not \"present\" and the set has {volumes} volumes, and \
                 nothing in this profile damages the post. A run that only needs a NAME \
                 reads volumes until it has one and stops, so which of the {volumes} land \
                 is the client's answer rather than a requirement. Lower redundancy_pct (or \
                 raise block_bytes) until the set has ONE volume, or select a fault that \
                 makes the run repair, which pulls them all"
            ),
            Self::Recovery(e) => write!(f, "[fault] the competing set could not be built: {e}"),
            Self::PayloadDamageUnderAContainer => f.write_str(
                "[fault] corrupt_payload names a `file` beside a [container]: with an archive \
                 selected the posted files are its VOLUMES and the payload never reaches the \
                 wire, so a span written into a source file would be damage nobody could \
                 fetch. Three shapes DO reach it, and each is a different question: the \
                 archive's own damage is corrupt_headers (F3) and \
                 truncate_last_volume_bytes (F5), which the POSTED set repairs; and a span \
                 on a nesting LEVEL's archive is this same key with `inner_level` instead of \
                 `file`, cut after that level's own [[container.inner]] recovery_pct set, \
                 which nothing in the NZB mentions",
            ),
            Self::PayloadDamageOnAnUnpostedMember(n) => write!(
                f,
                "[fault] corrupt_payload spoils {n:?}, which is DESCRIBED and never posted - \
                 a P5 placeholder or a G5 dedupe copy. There is no article of its own to \
                 spoil, so the span would be written into bytes no client ever fetches. \
                 Damage the file it is a copy of, or the file it sits beside"
            ),
            Self::PayloadDamageWithoutCover(n) => write!(
                f,
                "[fault] corrupt_payload spoils {n:?}, which no recovery set covers. The \
                 damage is invisible to the article's own CRC by construction, so the set \
                 is the only thing in the post that can see it or rebuild it: over an \
                 uncovered member the expectation this generator derives - the SOURCE \
                 bytes, byte-exact - is unreachable by any client. Cover the member, or \
                 select [serve] corrupt for a fault the client can simply re-ask past"
            ),
        }
    }
}

impl std::error::Error for FaultError {}

impl From<RecoveryError> for FaultError {
    fn from(e: RecoveryError) -> Self {
        Self::Recovery(Box::new(e))
    }
}

/// Apply the generation-time fault plane to a built recovery set.
///
/// Returns without touching anything for the neutral `[fault]` and a
/// present index, so a caller needs no special case.
pub fn apply(
    profile: &Profile,
    contained: &mut Option<Contained>,
    sources: &[SourceFile],
    carried: &[SourceFile],
    wire: &mut Option<Vec<SourceFile>>,
    recovered: &mut Recovered,
) -> Result<(), FaultError> {
    let has_set = profile.recovery.kind != RecoveryKind::None;
    let f = &profile.fault;
    if f.duplicate_set && !has_set {
        return Err(FaultError::NeedsARecoverySet("duplicate_set = true"));
    }
    if f.corrupt_recovery_packets > 0 && !has_set {
        return Err(FaultError::NeedsARecoverySet("corrupt_recovery_packets"));
    }
    let mut rng = Rng::from_seed(profile.layout.seed ^ STREAM);
    if !has_set {
        // `[recovery] index` over no set is already a contradiction the
        // schema refuses, so the recovery-set arms have nothing to do -
        // but an archive fault beside no set is a legal (and bleak) row,
        // so it still runs. G1 is refused here rather than silently
        // skipped: an uncovered damaged payload has no client that could
        // reach the expectation.
        if let Some(d) = f.corrupt_payload.iter().find(|d| d.inner_level.is_none()) {
            return Err(FaultError::PayloadDamageWithoutCover(d.file.clone()));
        }
        return damage_the_archive(profile, contained, &mut rng);
    }
    if f.duplicate_set {
        add_duplicate_set(profile, carried, recovered)?;
    }
    let index_state = profile.recovery.index;
    match index_state {
        IndexState::Present => {}
        IndexState::Damaged => damage_indexes(recovered),
        IndexState::Absent => remove_indexes(profile, recovered)?,
    }
    if f.corrupt_recovery_packets > 0 {
        corrupt_packets(f.corrupt_recovery_packets, index_state, recovered, &mut rng)?;
    }
    if index_state != IndexState::Present {
        refuse_an_ungradeable_naming_row(profile, recovered)?;
    }
    // The ARCHIVE faults last, over bytes the recovery set has already
    // described. Everything above damages the set; these damage what
    // the set protects, which is the only order in which the set has
    // something to say.
    damage_the_archive(profile, contained, &mut rng)?;
    // G1 is the other half of that same rule, over the payload rather
    // than over the archive around it, and it draws after the archive
    // arm for the ordinary reason: a stream position is part of the
    // determinism contract and appending is the only edit that leaves
    // every earlier draw where it was.
    spoil_payload(profile, sources, wire, recovered, &mut rng)?;
    Ok(())
}

/// G1: replace named spans of a payload file with fault-stream bytes,
/// AFTER the recovery set was cut over the clean ones.
///
/// **The wire copy and the expectation part company here, and this is
/// the only place in the crate where they do.** Every other stage
/// derives the end state from the same `sources` it posts, because the
/// bytes on the wire ARE the bytes that must land. Here they are not:
/// the source bytes stay the truth and the post carries a plausible
/// wrong copy of them, so the client has to notice from the set and
/// rebuild. `wire` is therefore forked lazily - a profile with no
/// `corrupt_payload` pays no copy of its payload at all - and every
/// stage below `fault::apply` reads the fork while the expectation
/// keeps reading `sources`.
///
/// **Why this is not `[serve] corrupt`, restated because the two look
/// alike and prove different things.** `nzbkit::mock` flips its byte in
/// the ENCODED article, so the yEnc part CRC fails and the client meets
/// a refused article: it knows which bytes are missing and asks the set
/// for exactly those. Here the article is well formed and its CRC is
/// over the damage, so nothing short of the set's own block hashes can
/// see that anything is wrong. A row that used the serve plane for this
/// would prove the retry path while claiming to prove detection.
fn spoil_payload(
    profile: &Profile,
    sources: &[SourceFile],
    wire: &mut Option<Vec<SourceFile>>,
    recovered: &Recovered,
    rng: &mut Rng,
) -> Result<(), FaultError> {
    // H5: an entry naming an `inner_level` is the SAME plane at a
    // different depth and is written by `crate::container`, inside the
    // loop that builds the stack - because the recovery data it has to
    // hide from is that level's own, not the posted set. This arm owns
    // the entries that name a `[source]` file, and the schema refuses an
    // entry that names both or neither.
    let payload_spans: Vec<&crate::profile::PayloadDamage> = profile
        .fault
        .corrupt_payload
        .iter()
        .filter(|d| d.inner_level.is_none())
        .collect();
    if payload_spans.is_empty() {
        return Ok(());
    }
    if profile.container.kind != ContainerKind::None {
        return Err(FaultError::PayloadDamageUnderAContainer);
    }
    for d in payload_spans {
        // The schema has already refused a name no `[source]` entry
        // carries and a span that does not fit the declared length, so
        // the only judgement left here is the one that needs the
        // recovery plane's answer.
        let i = sources
            .iter()
            .position(|s| s.rel == d.file)
            .expect("the schema refuses a corrupt_payload file [source] does not have");
        if !recovered.covers(i) {
            return Err(FaultError::PayloadDamageWithoutCover(d.file.clone()));
        }
        if recovered.is_unposted(i) {
            return Err(FaultError::PayloadDamageOnAnUnpostedMember(d.file.clone()));
        }
        let files = wire.get_or_insert_with(|| sources.to_vec());
        let at = d.at as usize;
        let span = &mut files[i].bytes[at..at + d.bytes as usize];
        let before = span.to_vec();
        rng.fill(span);
        // Failing to find is failing, in its smallest form: a fill that
        // reproduced the bytes it replaced would be a green row over an
        // undamaged post, and the whole point of G1 is that only the
        // set can see the difference.
        if span == before.as_slice() {
            for b in span.iter_mut() {
                *b ^= 0xff;
            }
        }
    }
    Ok(())
}

/// The RAR signatures this stage knows, longest first, so a prefix
/// cannot shadow a longer magic.
///
/// RAR5 is `Rar!\x1a\x07\x01\x00` and RAR4 `Rar!\x1a\x07\x00`; RAR 1.3
/// is `RE~^`. Named here rather than reached for in `rars` because what
/// this stage needs is only where the header region STARTS, and reading
/// a writer's internal constant for that would couple the fault plane
/// to the writer's own layout.
const SIGNATURES: [&[u8]; 3] = [b"Rar!\x1a\x07\x01\x00", b"Rar!\x1a\x07\x00", b"RE~^"];

/// How far past the signature `corrupt_headers` may reach.
///
/// The first bytes of a RAR archive header are its CRC, its size, its
/// type and its flags - the fields a reader has to trust before it can
/// find anything else - so a flip inside this window is a header fault
/// on every generation of the format, without this stage parsing one.
/// Deliberately short: a wider window would eventually reach a file's
/// data and quietly become a payload fault wearing a header fault's
/// name.
const HEADER_WINDOW: usize = 16;

/// F3 and F5: damage the archive the container plane wrote.
///
/// F3 flips one byte inside a VOLUME's archive header, the volume and
/// the offset both drawn from the fault stream. F5 cuts the tail off
/// the last volume. Both are refused when there is no container to
/// damage, and both leave the recovery set alone: the set was cut over
/// these bytes a moment ago and it is what the client has to repair
/// from.
fn damage_the_archive(
    profile: &Profile,
    contained: &mut Option<Contained>,
    rng: &mut Rng,
) -> Result<(), FaultError> {
    let f = &profile.fault;
    if !f.corrupt_headers && f.truncate_last_volume_bytes == 0 {
        return Ok(());
    }
    let Some(c) = contained else {
        debug_assert_eq!(profile.container.kind, ContainerKind::None);
        return Err(FaultError::NeedsAnArchive(if f.corrupt_headers {
            "corrupt_headers = true"
        } else {
            "truncate_last_volume_bytes"
        }));
    };
    if f.corrupt_headers {
        // WHICH volume is the seed's answer, which is what makes the row
        // reproducible without a profile naming a volume it cannot know
        // the count of - the writer decides how many there are.
        let which = rng.below(c.volumes.len() as u64) as usize;
        let bytes = &mut c.volumes[which].bytes;
        let head = signature_len(bytes)?;
        // Bounded by the volume as well as by the window: a tiny volume
        // could be shorter than the window, and a flip past its end
        // would be no flip at all.
        let span = HEADER_WINDOW.min(bytes.len().saturating_sub(head));
        if span == 0 {
            return Err(FaultError::UnknownArchiveSignature(
                "a volume with no header after its signature".into(),
            ));
        }
        let at = head + rng.below(span as u64) as usize;
        bytes[at] ^= 0xff;
    }
    if f.truncate_last_volume_bytes > 0 {
        let last = c
            .volumes
            .last_mut()
            .expect("the container plane emits at least one volume");
        let len = last.bytes.len();
        if f.truncate_last_volume_bytes as usize >= len {
            return Err(FaultError::TruncationEatsTheVolume {
                asked: f.truncate_last_volume_bytes,
                volume: len,
            });
        }
        last.bytes
            .truncate(len - f.truncate_last_volume_bytes as usize);
    }
    Ok(())
}

/// Where a volume's header region begins: the length of the archive
/// signature it starts with.
///
/// Failing to find is failing: a volume whose first bytes are none of
/// the known magics is refused rather than damaged at a guessed offset,
/// because a flipped byte at the wrong place is a payload fault and the
/// row would be testing something else entirely.
fn signature_len(bytes: &[u8]) -> Result<usize, FaultError> {
    // C9's SFX-stub prefix sits BEFORE the signature, so the magic is
    // searched for rather than required at offset zero - within a bound,
    // so a volume that simply is not an archive is still refused.
    const SCAN: usize = 4096;
    let window = &bytes[..SCAN.min(bytes.len())];
    for sig in SIGNATURES {
        if let Some(at) = window.windows(sig.len()).position(|w| w == sig) {
            return Ok(at + sig.len());
        }
    }
    Ok(0).and(Err(FaultError::UnknownArchiveSignature(format!(
        "{:02x?}",
        &window[..8.min(window.len())]
    ))))
}

/// F6: a SECOND set over the same members, under a base of its own.
///
/// The donor shape. Two independent descriptions of one post exist all
/// the time in the wild - a re-post carrying its own set, an
/// obfuscated set beside a descriptive one - and a client that picks
/// one and fails has thrown away blocks it was handed. The primary set
/// is left exactly as it was, so a row can assert the payload lands
/// whichever set answers.
///
/// `carried` is the slice the RECOVERY plane was built over, and it has
/// to be: `Recovered::covered` holds indices into that slice, which is
/// the posted VOLUMES when a container or a split is selected and the
/// sources only when neither is. Indexing `sources` with them was wrong
/// in both directions. On a single-volume container the primary set
/// described `movie.rar` while this "duplicate" described `movie.bin`,
/// so F6's whole premise - two descriptions of the SAME members - was
/// false. On a split, `covered` is `[0,1,2]` over one source file and
/// `sources[1]` panicked the generator outright.
fn add_duplicate_set(
    profile: &Profile,
    carried: &[SourceFile],
    recovered: &mut Recovered,
) -> Result<(), FaultError> {
    if !profile.recovery.second_covers.is_empty() {
        return Err(FaultError::TwoSetPlansAtOnce);
    }
    if !profile.recovery.hostile_names.is_empty() {
        return Err(FaultError::DuplicateSetWithPatchedNames);
    }
    let stage = recovery::Stage::new()?;
    for &i in &recovered.covered {
        stage.write(&carried[i].rel, &carried[i].bytes)?;
    }
    let base = format!(
        "{}{DUPLICATE_SUFFIX}",
        recovery::base_name(carried, &recovered.covered)
    );
    let files = recovery::create(&stage, carried, &recovered.covered, &base, profile)?;
    recovered.files.extend(files);
    Ok(())
}

/// F7 `index = "damaged"`: the index is posted, arrives, and holds not
/// one packet a parser will accept.
///
/// Every packet body gets a byte flipped and is NOT resealed, which is
/// what makes it damage rather than an edit: a PAR2 packet carries its
/// own MD5 over set id, type and body, so an unsealed change is exactly
/// the "this packet is corrupt, skip it" case every reader has. The
/// file keeps its name, its length and its PAR2 magic, so a client
/// still FINDS it and then has to cope - which is the row. Rewriting it
/// as random bytes would test whether the client recognises a `.par2`
/// by extension, a different question and P10's.
fn damage_indexes(recovered: &mut Recovered) {
    for f in recovered.files.iter_mut().filter(|f| !f.parity) {
        let spans = par2patch::packets(&f.bytes);
        for (start, len, _) in spans {
            // The first body byte, which is inside the region the
            // packet's own checksum covers and outside the header a
            // scanner walks by. Flipped rather than zeroed so a packet
            // whose body was already zero is damaged too.
            let at = start + 64;
            if at < start + len && at < f.bytes.len() {
                f.bytes[at] ^= 0xff;
            }
        }
    }
}

/// F7 `index = "absent"`: the index was never posted, so every real
/// name has to come out of the volumes.
///
/// A `.volNNN+MM.par2` carries the whole critical packet set as well as
/// its recovery slices - that repetition is what PAR2 is for - so a
/// post with no index still names its members. This row is the one that
/// proves the client reads them there rather than only from the file it
/// usually finds first.
fn remove_indexes(profile: &Profile, recovered: &mut Recovered) -> Result<(), FaultError> {
    if profile.recovery.redundancy_pct == 0 {
        return Err(FaultError::AbsentIndexRemovesTheSet);
    }
    recovered.files.retain(|f| f.parity);
    Ok(())
}

/// F4: flip a byte inside the body of `n` packets, chosen from the
/// seed, spread across the emitted recovery files.
///
/// Not resealed, for the reason [`damage_indexes`] gives. Which packets
/// is the seed's answer and not a selection a profile makes: the row is
/// "some of this set is unreadable", and a profile that named the
/// packets would be pinning the creator's own packet order, which is
/// par2gen's business and not a layout.
fn corrupt_packets(
    n: u32,
    index_state: IndexState,
    recovered: &mut Recovered,
    rng: &mut Rng,
) -> Result<(), FaultError> {
    // (file index, packet start, packet length) for every packet F4 may
    // damage. A damaged or absent index is skipped: there is nothing
    // there to break that F7 has not broken already, and counting those
    // packets would let `corrupt_recovery_packets = 3` spend its whole
    // budget on a file no reader will accept anyway.
    let mut pool: Vec<(usize, usize, usize)> = Vec::new();
    for (i, f) in recovered.files.iter().enumerate() {
        if !f.parity && index_state != IndexState::Present {
            continue;
        }
        for (start, len, _) in par2patch::packets(&f.bytes) {
            pool.push((i, start, len));
        }
    }
    if (n as usize) > pool.len() {
        return Err(FaultError::NotEnoughPackets {
            asked: n,
            packets: pool.len(),
        });
    }
    // Partial Fisher-Yates from the front: the first `n` entries of the
    // shuffled pool are the chosen packets, and the draw count depends
    // on `n` alone, so raising it damages a superset rather than a
    // different set.
    for i in 0..n as usize {
        let j = i + rng.below((pool.len() - i) as u64) as usize;
        pool.swap(i, j);
    }
    for &(file, start, len) in &pool[..n as usize] {
        let bytes = &mut recovered.files[file].bytes;
        let at = start + 64;
        if at < start + len && at < bytes.len() {
            bytes[at] ^= 0xff;
        }
    }
    Ok(())
}

/// Refuse a naming-only index row that emits more than one volume.
///
/// A run that REPAIRS pulls every volume, so a row that damages the
/// post can state its whole set as the end state (and `expects_repair`
/// in `crate::layout` is the ONE place that predicate lives, which is
/// why this reads it there rather than deciding again). A run that only needs
/// a NAME pulls volumes until it has one and then stops, and how many
/// that is - one, or all of them - is the client's answer, not a
/// requirement a profile may write down. So the one shape this catalog
/// can grade is a set with exactly one volume, where "the volumes it
/// read" and "the volumes there are" cannot differ.
///
/// Refused rather than approximated: an expectation that listed volumes
/// the client had no reason to fetch would fail as a client defect, and
/// one that listed none would pass over a client that fetched the lot.
fn refuse_an_ungradeable_naming_row(
    profile: &Profile,
    recovered: &Recovered,
) -> Result<(), FaultError> {
    let volumes = recovered.files.iter().filter(|f| f.parity).count();
    if volumes > 1 && !crate::layout::expects_repair(profile) {
        return Err(FaultError::VolumeCountNotGradeable { volumes });
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::layout::{GenError, generate};

    const BASE: &str = "\
[layout]
name = \"t\"
seed = 5

[source]
files = [{ name = \"payload.bin\", bytes = 120000 }]

[encoding]
article_bytes = 20000
";

    /// A 20 % set over six 20,000-byte blocks: an index and two
    /// volumes, which is the smallest shape with a volume to spare.
    const SET: &str = "\n[recovery]\nkind = \"par2\"\nredundancy_pct = 20\nblock_bytes = 20000\n";

    /// The same set at one volume, which is what a naming-only index row
    /// has to carry - see `refuse_an_ungradeable_naming_row`.
    const ONE_VOL: &str =
        "\n[recovery]\nkind = \"par2\"\nredundancy_pct = 10\nblock_bytes = 20000\n";

    fn built(extra: &str) -> crate::Layout {
        let p = Profile::parse(&format!("{BASE}{extra}")).expect("profile parses");
        generate(&p).unwrap_or_else(|e| panic!("layout generates: {e}"))
    }

    fn refused(extra: &str) -> FaultError {
        let p = Profile::parse(&format!("{BASE}{extra}")).expect("profile parses");
        match generate(&p) {
            Err(GenError::Fault(e)) => e,
            other => panic!("expected a fault refusal, got {other:?}"),
        }
    }

    /// The recovery files a layout POSTS, index first, as (name, bytes).
    fn recovery_files(l: &crate::Layout) -> Vec<(String, Vec<u8>)> {
        l.files
            .iter()
            .filter(|(n, _)| n.ends_with(".par2"))
            .cloned()
            .collect()
    }

    // -----------------------------------------------------------------
    // G1: corrupt_payload
    // -----------------------------------------------------------------

    /// The property the whole gap is about: what goes on the WIRE is
    /// not what has to come back, and the difference is exactly the
    /// span the profile named.
    ///
    /// Both halves are asserted in one test because either alone passes
    /// over the wrong thing - a posted copy that differs proves nothing
    /// if the expectation drifted with it, and an intact expectation
    /// proves nothing if the post was never damaged.
    #[test]
    fn a_damaged_span_is_posted_and_is_not_expected() {
        let l = built(&format!(
            "{SET}\n[fault]\ncorrupt_payload = [{{ file = \"payload.bin\", at = 1000, bytes = 64 }}]\n"
        ));
        let posted = &l
            .files
            .iter()
            .find(|(n, _)| n == "payload.bin")
            .expect("the payload is posted")
            .1;
        let expected = &l
            .expect
            .files
            .iter()
            .find(|(n, _)| n == "payload.bin")
            .expect("the payload is expected")
            .1;
        assert_ne!(
            posted[1000..1064],
            expected[1000..1064],
            "the named span must be spoiled on the wire"
        );
        assert_eq!(
            posted[..1000],
            expected[..1000],
            "nothing before the span moves"
        );
        assert_eq!(
            posted[1064..],
            expected[1064..],
            "nothing after the span moves"
        );
    }

    /// ...and a profile that names no span forks nothing, so every row
    /// that came before this plane is byte-identical to what it was.
    #[test]
    fn a_profile_with_no_damage_posts_what_it_expects() {
        let l = built(SET);
        let posted = &l.files.iter().find(|(n, _)| n == "payload.bin").unwrap().1;
        let expected = &l
            .expect
            .files
            .iter()
            .find(|(n, _)| n == "payload.bin")
            .unwrap()
            .1;
        assert_eq!(posted, expected);
    }

    /// The damage has to be REPAIRABLE, or the expectation this
    /// generator derives is one no client could reach.
    #[test]
    fn damage_over_an_uncovered_member_is_refused_by_name() {
        let e = refused(
            "\n[fault]\ncorrupt_payload = [{ file = \"payload.bin\", at = 10, bytes = 8 }]\n",
        );
        assert!(
            matches!(e, FaultError::PayloadDamageWithoutCover(ref n) if n == "payload.bin"),
            "got {e:?}"
        );
    }

    /// With an archive the payload never reaches the wire at all, so a
    /// span written into a source file is damage nobody could fetch.
    #[test]
    fn damage_under_a_container_is_refused_by_name() {
        let e = refused(&format!(
            "{SET}\n[container]\nkind = \"rar-stored\"\n\n[fault]\n\
             corrupt_payload = [{{ file = \"payload.bin\", at = 10, bytes = 8 }}]\n"
        ));
        assert!(
            matches!(e, FaultError::PayloadDamageUnderAContainer),
            "got {e:?}"
        );
    }

    /// The set describes the CLEAN bytes, which is the whole reason
    /// this arm runs after `recovery::build`: a set cut over the damage
    /// would agree with it and ask the client to repair nothing.
    #[test]
    fn the_set_is_cut_over_the_bytes_before_the_damage() {
        let clean = built(SET);
        let damaged = built(&format!(
            "{SET}\n[fault]\ncorrupt_payload = [{{ file = \"payload.bin\", at = 1000, bytes = 64 }}]\n"
        ));
        assert_eq!(
            recovery_files(&clean),
            recovery_files(&damaged),
            "the recovery set must be identical to the undamaged row's"
        );
    }

    /// How many of a `.par2` file's packets still agree with their own
    /// checksum. A packet's MD5 covers set id, type and body - offset 32
    /// to the end - so this is the same arithmetic
    /// [`crate::par2patch::reseal`] writes.
    fn sealed(bytes: &[u8]) -> (usize, usize) {
        let spans = par2patch::packets(bytes);
        let total = spans.len();
        let ok = spans
            .iter()
            .filter(|(start, len, _)| par2patch::is_sealed(bytes, *start, *len))
            .count();
        (ok, total)
    }

    // ------------------------------------------------------------
    // F3 and F5: refused, and the refusal points somewhere.
    // ------------------------------------------------------------

    /// With no container the two archive faults have nothing to damage,
    /// and they say so rather than flipping a byte in a payload file
    /// that is not a volume.
    #[test]
    fn the_archive_faults_without_a_container_are_refused() {
        for (extra, what) in [
            (
                "\n[fault]\ncorrupt_headers = true\n",
                "corrupt_headers = true",
            ),
            (
                "\n[fault]\ntruncate_last_volume_bytes = 64\n",
                "truncate_last_volume_bytes",
            ),
        ] {
            let e = refused(extra);
            assert_eq!(e, FaultError::NeedsAnArchive(what));
            assert!(e.to_string().contains("[container] kind"), "{e}");
        }
    }

    /// F3 flips ONE byte, inside the header region of one volume, and
    /// leaves every other byte of every other volume alone.
    #[test]
    fn corrupting_headers_flips_one_byte_in_one_volumes_header() {
        const SPLIT: &str = "\n[container]\nkind = \"rar-stored\"\nvolume_bytes = 40000\n";
        let clean = built(SPLIT);
        let broken = built(&format!("{SPLIT}\n[fault]\ncorrupt_headers = true\n"));
        assert_eq!(clean.files.len(), broken.files.len(), "a volume moved");
        let mut differing = 0usize;
        for ((cn, cb), (bn, bb)) in clean.files.iter().zip(&broken.files) {
            assert_eq!(cn, bn, "the damage renamed a volume");
            assert_eq!(cb.len(), bb.len(), "{cn}: the damage changed a length");
            let at: Vec<usize> = (0..cb.len()).filter(|&i| cb[i] != bb[i]).collect();
            if at.is_empty() {
                continue;
            }
            differing += 1;
            assert_eq!(at.len(), 1, "{cn}: {} bytes moved, wanted 1", at.len());
            // Inside the header region: past the signature and within
            // the window, which is what makes it a HEADER fault.
            let head = signature_len(cb).expect("a rars volume carries a signature");
            assert!(
                at[0] >= head && at[0] < head + HEADER_WINDOW,
                "{cn}: byte {} is outside the header window at {head}",
                at[0]
            );
        }
        assert_eq!(differing, 1, "the damage landed on {differing} volumes");
    }

    /// F5 cuts the tail off the LAST volume and nothing else.
    #[test]
    fn truncating_the_last_volume_shortens_only_it() {
        const SPLIT: &str = "\n[container]\nkind = \"rar-stored\"\nvolume_bytes = 40000\n";
        let clean = built(SPLIT);
        let cut = built(&format!(
            "{SPLIT}\n[fault]\ntruncate_last_volume_bytes = 512\n"
        ));
        let vols = |l: &crate::Layout| -> Vec<(String, usize)> {
            l.files
                .iter()
                .filter(|(n, _)| !n.ends_with(".par2"))
                .map(|(n, b)| (n.clone(), b.len()))
                .collect()
        };
        let (a, b) = (vols(&clean), vols(&cut));
        assert!(a.len() >= 2, "the row needs a split set, got {}", a.len());
        for (i, ((an, al), (bn, bl))) in a.iter().zip(&b).enumerate() {
            assert_eq!(an, bn);
            let want = if i + 1 == a.len() { al - 512 } else { *al };
            assert_eq!(*bl, want, "{an}");
        }
    }

    /// A cut that would leave nothing is an ABSENT volume, which is a
    /// serve-time fault and not a short tail.
    #[test]
    fn a_truncation_that_eats_the_volume_is_refused() {
        let e = refused(
            "\n[container]\nkind = \"rar-stored\"\nvolume_bytes = 40000\n\
             \n[fault]\ntruncate_last_volume_bytes = 4000000\n",
        );
        assert!(
            matches!(
                e,
                FaultError::TruncationEatsTheVolume { asked: 4000000, .. }
            ),
            "{e}"
        );
    }

    /// The archive faults run AFTER the recovery set, or the set would
    /// describe the damage and there would be nothing to repair.
    #[test]
    fn the_set_describes_the_archive_as_it_was_before_the_damage() {
        const SPLIT: &str = "\n[container]\nkind = \"rar-stored\"\nvolume_bytes = 40000\n\
             \n[recovery]\nkind = \"par2\"\nredundancy_pct = 20\n";
        let clean = built(SPLIT);
        let broken = built(&format!("{SPLIT}\n[fault]\ncorrupt_headers = true\n"));
        let par2 = |l: &crate::Layout| -> Vec<(String, Vec<u8>)> {
            l.files
                .iter()
                .filter(|(n, _)| n.ends_with(".par2"))
                .cloned()
                .collect()
        };
        assert!(!par2(&clean).is_empty(), "the row needs a set");
        assert_eq!(
            par2(&clean),
            par2(&broken),
            "the recovery set moved with the damage, so it agrees with it"
        );
    }

    // ------------------------------------------------------------
    // F7: the index.
    // ------------------------------------------------------------

    /// `index = "absent"` posts the volumes and no index at all.
    #[test]
    fn an_absent_index_is_not_posted_and_the_volumes_are() {
        let l = built(&format!("{SET}\n[serve]\nmissing = [0]\n"));
        let with = recovery_files(&l);
        let l = built(&format!(
            "{SET}index = \"absent\"\n\n[serve]\nmissing = [0]\n"
        ));
        let without = recovery_files(&l);
        assert!(with.iter().any(|(n, _)| !n.contains(".vol")));
        assert!(
            without.iter().all(|(n, _)| n.contains(".vol")),
            "an index survived: {:?}",
            without.iter().map(|(n, _)| n).collect::<Vec<_>>()
        );
        assert_eq!(
            with.iter().filter(|(n, _)| n.contains(".vol")).count(),
            without.len(),
            "removing the index must not disturb the volumes"
        );
    }

    /// `index = "damaged"` posts the index, at its own name and length,
    /// with nothing inside it a reader will accept.
    #[test]
    fn a_damaged_index_is_posted_whole_and_holds_no_sealed_packet() {
        let clean = built(ONE_VOL);
        let broken = built(&format!("{ONE_VOL}index = \"damaged\"\n"));
        let (cname, cbytes) = recovery_files(&clean)
            .into_iter()
            .find(|(n, _)| !n.contains(".vol"))
            .expect("a clean index");
        let (bname, bbytes) = recovery_files(&broken)
            .into_iter()
            .find(|(n, _)| !n.contains(".vol"))
            .expect("a damaged index");
        assert_eq!(cname, bname, "the damage must not rename the file");
        assert_eq!(cbytes.len(), bbytes.len(), "or change its length");
        assert_eq!(&bbytes[..8], b"PAR2\0PKT", "or its magic");
        let (ok, total) = sealed(&bbytes);
        assert!(total >= 4, "an index carries the critical packets");
        assert_eq!(ok, 0, "{ok} of {total} packets are still readable");
        // ...and the VOLUMES are untouched, or the row would be testing
        // a wrecked set rather than a wrecked index.
        for (n, b) in recovery_files(&broken) {
            if n.contains(".vol") {
                let (ok, total) = sealed(&b);
                assert_eq!(ok, total, "{n} was damaged and only the index should be");
            }
        }
    }

    /// An index-only set has no volumes, so removing the index removes
    /// the set. Refused, because it is not the P7 shape the author
    /// asked for.
    #[test]
    fn an_absent_index_over_an_index_only_set_is_refused() {
        assert_eq!(
            refused("\n[recovery]\nkind = \"par2\"\nindex = \"absent\"\n"),
            FaultError::AbsentIndexRemovesTheSet
        );
    }

    /// A naming-only row whose set has more than one volume cannot state
    /// its end state, so it is refused with the fix in the message.
    #[test]
    fn a_multi_volume_naming_only_row_is_refused_with_the_fix() {
        let e = refused(&format!("{SET}index = \"absent\"\n"));
        assert_eq!(e, FaultError::VolumeCountNotGradeable { volumes: 2 });
        assert!(e.to_string().contains("ONE volume"), "{e}");
        // ...and a row that DAMAGES the post states it fine, because a
        // repair pulls every volume.
        built(&format!(
            "{SET}index = \"absent\"\n\n[serve]\nmissing = [0]\n"
        ));
    }

    // ------------------------------------------------------------
    // F4: packets.
    // ------------------------------------------------------------

    /// Exactly N packets are unsealed and every other one is left alone.
    #[test]
    fn corrupting_n_packets_unseals_exactly_n() {
        let clean = built(SET);
        let (clean_ok, clean_total) = recovery_files(&clean)
            .iter()
            .map(|(_, b)| sealed(b))
            .fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
        assert_eq!(clean_ok, clean_total, "the creator writes a sealed set");
        for n in [1u32, 3] {
            let l = built(&format!("{SET}\n[fault]\ncorrupt_recovery_packets = {n}\n"));
            let (ok, total) = recovery_files(&l)
                .iter()
                .map(|(_, b)| sealed(b))
                .fold((0, 0), |(a, b), (c, d)| (a + c, b + d));
            assert_eq!(total, clean_total, "a packet was added or lost");
            assert_eq!(
                total - ok,
                n as usize,
                "{} unsealed, wanted {n}",
                total - ok
            );
        }
    }

    /// Raising the count damages a SUPERSET, because the draw is a
    /// partial shuffle consumed from the front. That is what makes two
    /// rows at different counts comparable.
    #[test]
    fn raising_the_count_damages_a_superset() {
        let one = built(&format!("{SET}\n[fault]\ncorrupt_recovery_packets = 1\n"));
        let two = built(&format!("{SET}\n[fault]\ncorrupt_recovery_packets = 2\n"));
        for (name, bytes) in recovery_files(&one) {
            let other = recovery_files(&two)
                .into_iter()
                .find(|(n, _)| *n == name)
                .expect("the same files")
                .1;
            let broken = |b: &[u8]| {
                par2patch::packets(b)
                    .into_iter()
                    .enumerate()
                    .filter(|(_, (s, l, _))| !par2patch::is_sealed(b, *s, *l))
                    .map(|(i, _)| i)
                    .collect::<Vec<_>>()
            };
            for i in broken(&bytes) {
                assert!(broken(&other).contains(&i), "{name} packet {i} healed");
            }
        }
    }

    /// More packets than the set has.
    #[test]
    fn asking_for_more_packets_than_the_set_has_is_refused() {
        let e = refused(&format!("{SET}\n[fault]\ncorrupt_recovery_packets = 400\n"));
        assert!(
            matches!(e, FaultError::NotEnoughPackets { asked: 400, .. }),
            "{e}"
        );
    }

    /// A fault over a set the profile does not have.
    #[test]
    fn a_set_fault_without_a_set_is_refused_by_name() {
        for (extra, what) in [
            (
                "\n[fault]\ncorrupt_recovery_packets = 1\n",
                "corrupt_recovery_packets",
            ),
            ("\n[fault]\nduplicate_set = true\n", "duplicate_set"),
        ] {
            let e = refused(extra);
            assert!(e.to_string().contains(what), "{e}");
        }
    }

    // ------------------------------------------------------------
    // F6: the competing set.
    // ------------------------------------------------------------

    /// A second set over the SAME members, under a base of its own.
    #[test]
    fn a_duplicate_set_covers_the_same_members_under_a_second_base() {
        let one = built(SET);
        let two = built(&format!("{SET}\n[fault]\nduplicate_set = true\n"));
        let a = recovery_files(&one);
        let b = recovery_files(&two);
        assert_eq!(b.len(), a.len() * 2, "one set became two");
        // The first set is untouched, byte for byte and name for name.
        assert_eq!(b[..a.len()], a[..]);
        for (n, _) in &b[a.len()..] {
            assert!(
                n.contains(DUPLICATE_SUFFIX),
                "{n} is not under a second base"
            );
        }
        // ...and the duplicate really describes the same payload: the
        // FileDesc name is there, in a file the first set did not write.
        let dup = &b[a.len()].1;
        // FileDesc packets only: `filedesc_name` reads the tail of a
        // packet BODY as a name, which is only a name in a FileDesc.
        let names: Vec<String> = par2patch::packets(dup)
            .into_iter()
            .filter(|(_, _, ty)| ty == b"PAR 2.0\0FileDesc")
            .map(|(s, l, _)| par2patch::filedesc_name(dup, s, l))
            .collect();
        assert!(
            names.iter().any(|n| n.contains("payload.bin")),
            "the second set does not describe the payload: {names:?}"
        );
    }

    /// F6 BESIDE A CONTAINER, which the catalog's F6 row does not have.
    ///
    /// `Recovered::covered` indexes the slice the recovery plane was
    /// built over, and under a container that is the posted VOLUMES.
    /// F6 was handed `sources` and indexed it with those indices, so
    /// the two sets described different things: the primary named the
    /// volume, the "duplicate" named the unposted source file. F6's
    /// entire premise is two descriptions of the SAME members, so the
    /// row was proving nothing it claimed to.
    #[test]
    fn a_duplicate_set_beside_a_container_describes_the_posted_volumes() {
        let with_rar = format!(
            "{SET}\n[container]\nkind = \"rar-stored\"\nversion = \"rar4\"\n\
             [fault]\nduplicate_set = true\n"
        );
        let built = built(&with_rar);
        let files = recovery_files(&built);
        let (primary, dup): (Vec<_>, Vec<_>) = files
            .iter()
            .partition(|(n, _)| !n.contains(DUPLICATE_SUFFIX));
        assert!(!dup.is_empty(), "F6 wrote no second set");
        let described = |blob: &[u8]| -> Vec<String> {
            par2patch::packets(blob)
                .into_iter()
                .filter(|(_, _, ty)| ty == b"PAR 2.0\0FileDesc")
                .map(|(s, l, _)| par2patch::filedesc_name(blob, s, l))
                .collect()
        };
        let a = described(&primary[0].1);
        let b = described(&dup[0].1);
        assert_eq!(
            a, b,
            "the two sets describe different members: primary {a:?}, duplicate {b:?}"
        );
        // And what they describe is the VOLUME, not the source file that
        // was packed into it and never posted.
        assert!(
            a.iter().all(|n| !n.contains("payload.bin")),
            "the sets name the unposted source rather than the volume: {a:?}"
        );
    }

    /// The same defect's other ending, and the louder one: a SPLIT
    /// source gives `covered` more indices than `sources` has entries
    /// (three parts described, one source file), so indexing `sources`
    /// with them was an out-of-bounds panic in the generator rather
    /// than a merely wrong set.
    #[test]
    fn a_duplicate_set_over_a_split_source_does_not_panic() {
        let text = "\
[layout]
name = \"t\"
seed = 5

[source]
files = [{ name = \"payload.bin\", bytes = 120000, split = 3, split_names = \"parts\" }]

[encoding]
article_bytes = 20000

[recovery]
kind = \"par2\"
redundancy_pct = 20
block_bytes = 20000

[fault]
duplicate_set = true
";
        let p = Profile::parse(text).expect("profile parses");
        let built = generate(&p).unwrap_or_else(|e| panic!("layout generates: {e}"));
        let files = recovery_files(&built);
        assert!(
            files.iter().any(|(n, _)| n.contains(DUPLICATE_SUFFIX)),
            "F6 wrote no second set over a split source"
        );
    }

    /// Two two-set stories in one profile, and a patch only one set
    /// would carry: both refused, both with the reason.
    #[test]
    fn a_duplicate_set_beside_another_two_set_plan_is_refused() {
        let two_files = BASE.replace(
            "files = [{ name = \"payload.bin\", bytes = 120000 }]",
            "files = [{ name = \"payload.bin\", bytes = 120000 }, \
             { name = \"a-second-payload.bin\", bytes = 40000 }]",
        );
        let go = |extra: &str| {
            let p = Profile::parse(&format!("{two_files}{extra}")).expect("profile parses");
            match generate(&p) {
                Err(GenError::Fault(e)) => e,
                other => panic!("expected a fault refusal, got {other:?}"),
            }
        };
        assert_eq!(
            go(&format!(
                "{SET}covers = [\"payload.bin\"]\n\
                 second_covers = [\"a-second-payload.bin\"]\n\
                 \n[fault]\nduplicate_set = true\n"
            )),
            FaultError::TwoSetPlansAtOnce
        );
        assert_eq!(
            go(&format!(
                "{SET}hostile_names = [\"renamed.bin\"]\n\n[fault]\nduplicate_set = true\n"
            )),
            FaultError::DuplicateSetWithPatchedNames
        );
    }

    // ------------------------------------------------------------
    // The stream, and determinism.
    // ------------------------------------------------------------

    /// Adding a generation-time fault leaves every PAYLOAD name and
    /// message-id where it was, which is what lets a fault row be
    /// diffed against the clean row it was copied from. The recovery
    /// files' names move, and must: the fault changed how many there
    /// are.
    #[test]
    fn adding_a_fault_moves_no_payload_name_and_no_payload_message_id() {
        let clean = built(SET);
        let faulty = built(&format!("{SET}\n[fault]\ncorrupt_recovery_packets = 1\n"));
        assert_eq!(clean.files[0], faulty.files[0], "the payload moved");
        assert_eq!(clean.expect.payload, faulty.expect.payload);
        let ids = |l: &crate::Layout| {
            let mut v: Vec<String> = l
                .articles
                .keys()
                .filter(|id| l.articles[*id].len() > 10_000)
                .cloned()
                .collect();
            v.sort();
            v
        };
        assert_eq!(ids(&clean), ids(&faulty), "a payload message-id moved");
    }

    /// The whole plane, twice, byte for byte.
    #[test]
    fn a_fault_plane_is_byte_identical_between_runs() {
        for extra in [
            format!("{SET}\n[fault]\ncorrupt_recovery_packets = 2\n"),
            format!("{SET}\n[fault]\nduplicate_set = true\n"),
            format!("{ONE_VOL}index = \"damaged\"\n"),
            format!("{SET}index = \"absent\"\n\n[serve]\nmissing = [0]\n"),
        ] {
            let a = built(&extra);
            let b = built(&extra);
            assert_eq!(a.files, b.files, "{extra}");
            assert_eq!(a.articles, b.articles, "{extra}");
            assert_eq!(a.fingerprint(), b.fingerprint(), "{extra}");
        }
    }

    /// The two planes draw from different streams, so a profile that
    /// selects both does not get one plane's choices in the other.
    #[test]
    fn the_two_fault_streams_are_not_the_same_stream() {
        assert_ne!(STREAM, crate::serve::STREAM);
    }
}
