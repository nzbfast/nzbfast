//! `[source]`: the payload a layout is built over.
//!
//! A profile names files and lengths; the bytes come from the profile's
//! own seed and from nowhere else. That is what lets the catalog carry
//! no binaries at all, and what makes a failing oracle run reproduce
//! from the profile text alone rather than from a fixture directory
//! somebody has to still have.
//!
//! Two properties this stage is responsible for:
//!
//! 1. **No two PAR2 blocks of a generated payload are equal.** The
//!    bytes come straight off the ChaCha stream, so by default they
//!    are incompressible and non-repeating. `[source] periodic = true`
//!    is refused by the schema for the reason its own field documents
//!    (par2cmdline 0.8.1, the version CI carries, miscounts identical
//!    recovery blocks), and this stage is where "enforced by
//!    construction" actually means something: there is no
//!    repeating-payload code path here to select, so the refusal
//!    cannot be worked around by a later plane.
//!
//!    **`[source] content` (G8) narrows that rule and does not repeal
//!    it.** Two arms make a file's bytes not-noise in one stated way
//!    each, and neither can hand par2gen two equal blocks:
//!    [`Content::Mpegts`] rewrites one byte in 188 and leaves the rest
//!    as drawn, and [`Content::Compressible`] - the arm that IS close
//!    to `periodic`, and the one this crate had to think hardest about
//!    - bounds every run well under a block AND is refused beside a
//!    recovery set that would COVER it, so par2gen never sees it. The
//!    argument in full, and why the second half is the one that
//!    matters, is on [`Content`] itself.
//! 2. **A source file's name is a relative path, not a basename.** A
//!    `name` with `/` in it is a file under a directory, and the
//!    directory part is the thing that has to survive the round trip
//!    for N8 to mean anything. It is kept here verbatim; which name
//!    reaches the wire is [`crate::naming`]'s decision.

use crate::profile::{Content, Profile};
use crate::rng::Rng;

/// Total generated payload this stage will produce for one profile.
///
/// Not a schema rule, because a profile asking for a gigabyte is not
/// contradictory - it is a test that runs on every push and costs the
/// fleet minutes for a shape a megabyte would have proven just as well
/// (the catalog README's rule 4). A named refusal here is what a typed
/// extra zero deserves; the alternative is a CI runner that swaps.
pub const MAX_TOTAL_PAYLOAD: u64 = 256 << 20;

/// One MPEG-TS packet. The sync byte repeats at exactly this stride,
/// and the stride is the whole of what makes the format recognisable.
const TS_PACKET: u64 = 188;

/// The shortest file [`Content::Mpegts`] may be written over: four
/// packets, which is what it takes for a stride to be a stride rather
/// than a coincidence. Read by [`Profile::validate`], which refuses a
/// shorter one by name - a file carrying one lone `0x47` selects the
/// shape and emits nothing a sniffer could see.
///
/// Four rather than two because that is where the format's own
/// readers sit; nzbfast's is `nzbfast_unpack::smart::videoext`, whose
/// header records what one byte of evidence cost (a GIF counted as a
/// second video). The floor is a property of the FORMAT, not a copy of
/// that client's constant: a row here must not encode the client's
/// answer, only refuse to emit bytes that ask no question.
pub const TS_SYNC_FLOOR: u64 = 4 * TS_PACKET;

/// The shortest run [`Content::Compressible`] writes, and the width of
/// the drawn byte's high bits that pick the rest. Runs land in
/// `MIN_RUN ..= MIN_RUN + 15`, so 4..=19 bytes: long enough that any
/// LZ77 coder folds each one into a single match, and short enough that
/// no run can fill a PAR2 block - which is the shape `periodic` is
/// refused for.
const MIN_RUN: usize = 4;

/// One generated source file, before any plane has touched it.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct SourceFile {
    /// The profile's `name`, verbatim: forward-slashed, possibly with
    /// directory components. The name a recovery set would describe
    /// this file under, and the only place the tree exists.
    pub rel: String,
    /// The last path component. What an ordinary post puts on the wire
    /// (`nzbkit::post::plan_with` makes the same split for the same
    /// reason: the tree is out-of-band by construction).
    pub base: String,
    /// The payload, drawn from the seed.
    pub bytes: Vec<u8>,
}

/// Why a source could not be assembled.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum SourceError {
    /// A `name` that is empty, absolute, has an empty or `..`
    /// component, or carries a byte no poster would put on a wire.
    /// The same rule `nzbkit::post::plan_with` applies to a real post,
    /// stated here so a hostile name is something a profile SELECTS
    /// (the `[recovery] hostile_names` plane, patched into FileDesc
    /// packets) rather than something a source file smuggles in.
    UnsafeName(String),
    /// The profile asks for more payload than [`MAX_TOTAL_PAYLOAD`].
    TooLarge { asked: u64, cap: u64 },
}

impl std::fmt::Display for SourceError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::UnsafeName(n) => write!(
                f,
                "[source] name {n:?} is not a name a post can carry: it must be relative, \
                 have no empty or \"..\" component, and hold no control or quote character \
                 (a deliberately hostile name is the [recovery] hostile_names plane)"
            ),
            Self::TooLarge { asked, cap } => write!(
                f,
                "[source] asks for {asked} bytes of payload, over the {cap}-byte cap: every \
                 profile runs on every push, so keep the payload as small as the shape allows"
            ),
        }
    }
}

/// Generate the payload for one profile.
///
/// Draw order is part of the determinism contract: files in the order
/// the profile lists them, each one filled in full before the next
/// starts. Every later stage draws AFTER this one, so adding a file to
/// a profile changes the names and message-ids of the files after it -
/// which is correct, because it is a different layout.
pub fn sources(profile: &Profile, rng: &mut Rng) -> Result<Vec<SourceFile>, SourceError> {
    let asked: u64 = profile.source.files.iter().map(|f| f.bytes).sum();
    if asked > MAX_TOTAL_PAYLOAD {
        return Err(SourceError::TooLarge {
            asked,
            cap: MAX_TOTAL_PAYLOAD,
        });
    }
    let mut out: Vec<SourceFile> = Vec::with_capacity(profile.source.files.len());
    for f in &profile.source.files {
        let base = check_name(&f.name)?;
        // G5: a dedupe entry's bytes are another file's bytes, so it
        // draws NOTHING. That is the one place this stage's one-stream
        // rule bends, and it bends the right way: the whole claim the
        // entry makes is that the two files are the same bytes, so a
        // draw of its own would be a draw whose result is thrown away
        // for a file that is by definition not its own. The schema has
        // already resolved the link backwards to a plain earlier file
        // of the same length, so the copy below cannot miss.
        if !f.same_as.is_empty() {
            let src = out
                .iter()
                .find(|s| s.rel == f.same_as)
                .expect("the schema refuses a same_as that names no earlier plain file");
            out.push(SourceFile {
                rel: f.name.clone(),
                base,
                bytes: src.bytes.clone(),
            });
            continue;
        }
        let mut bytes = vec![0u8; f.bytes as usize];
        rng.fill(&mut bytes);
        // G8: the shape is stamped over the drawn bytes IN PLACE, so
        // the stream position is the same one a noise file of this
        // length would leave - adding `content` to a profile moves no
        // later file's bytes, no opaque name and no message-id, which
        // is the same diffability rule G2 states below and the fault
        // planes state about their own streams.
        match f.content {
            Content::Noise => {}
            Content::Mpegts => stamp_ts_syncs(&mut bytes),
            Content::Compressible => run_encode_in_place(&mut bytes),
        }
        // G2: the head is zeroed AFTER the whole file is drawn, not
        // drawn short. That is what keeps the stream position identical
        // to the same row without a head, so adding `zero_head` to an
        // existing profile moves no later file's bytes, no opaque name
        // and no message-id - the same diffability rule the fault
        // planes state for their own streams. The schema has already
        // refused a head longer than the file and a head that would
        // fill a whole recovery block.
        // Clamped in u64 and narrowed after, never the other way
        // round: `usize` is 32 bits on the shipped armv7 target and a
        // head narrowed first would wrap into a different number.
        // `validate` has already refused a head past the file, so the
        // clamp is the belt to that braces rather than the rule.
        let head = f.zero_head.min(f.bytes) as usize;
        bytes[..head].fill(0);
        out.push(SourceFile {
            rel: f.name.clone(),
            base,
            bytes,
        });
    }
    Ok(out)
}

/// G8: put an MPEG-TS sync byte on every 188-byte packet boundary and
/// leave everything else as drawn.
///
/// One byte in 188, which is what keeps the arm safe beside a recovery
/// set: 187 of every 188 bytes are still unique stream noise, so two
/// blocks are exactly as unequal here as in the neutral case.
///
/// The same construction `bench/capability-corpus`'s own `ts_payload`
/// uses, deliberately - the two sides of the n03 comparison are then
/// structurally equal by construction rather than by argument.
fn stamp_ts_syncs(bytes: &mut [u8]) {
    let stride = usize::try_from(TS_PACKET).expect("188 fits every target's usize");
    for i in (0..bytes.len()).step_by(stride) {
        bytes[i] = 0x47;
    }
}

/// G8: rewrite the drawn bytes as short runs, so an archiver has
/// something to shrink.
///
/// Each run takes its VALUE and its LENGTH from the one drawn byte that
/// starts it: the byte itself is the value, so the alphabet stays the
/// full 256 and the redundancy this adds is repetition and nothing
/// else, and its high nibble picks a length in `MIN_RUN ..= MIN_RUN+15`.
/// Every later drawn byte inside a run is discarded rather than read,
/// which is why the file still costs exactly its own length off the
/// stream and a compressible row diffs against a noise one.
///
/// **Bounded runs are the half of the periodic argument that lives
/// here.** The longest run is 19 bytes, orders under any PAR2 block, so
/// no block this produces can be constant however the author sizes the
/// file. The other half - that the schema refuses this arm beside a
/// recovery set at all - is on `Contradiction::CompressibleUnderARecoverySet`,
/// and it is the one a reader can check without running anything.
fn run_encode_in_place(bytes: &mut [u8]) {
    let mut i = 0;
    while i < bytes.len() {
        let drawn = bytes[i];
        let run = MIN_RUN + usize::from(drawn >> 4);
        let end = (i + run).min(bytes.len());
        bytes[i..end].fill(drawn);
        i = end;
    }
}

/// Refuse a source name a post could not carry, and return its
/// basename. Deliberately the same shape as the `rel` check in
/// `nzbkit::post::plan_with`: this crate must not be able to create a
/// layout our own posting tool would refuse to post, or a conformance
/// run would be comparing two tools over an input neither should
/// accept.
pub(crate) fn check_name(name: &str) -> Result<String, SourceError> {
    let bad = name.is_empty()
        || name.starts_with('/')
        || name.ends_with('/')
        || name
            .split('/')
            .any(|c| c.is_empty() || c == "." || c == "..")
        || name
            .chars()
            .any(|c| c.is_control() || c == '"' || c == '\\');
    if bad {
        return Err(SourceError::UnsafeName(name.to_string()));
    }
    Ok(name.rsplit('/').next().unwrap_or(name).to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn profile(files: &str) -> Profile {
        Profile::parse(&format!(
            "[layout]\nname = \"t\"\nseed = 1\n\n[source]\nfiles = [{files}]\n"
        ))
        .expect("test profile parses")
    }

    /// The contract this whole crate rests on, at this stage: one seed,
    /// one payload.
    #[test]
    fn payload_is_reproducible_from_the_seed() {
        let p = profile("{ name = \"a.bin\", bytes = 4096 }");
        let a = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        let b = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        assert_eq!(a, b);
        assert_eq!(a[0].bytes.len(), 4096);
    }

    /// ...and it is the profile's OWN seed, not a constant.
    #[test]
    fn a_different_seed_is_a_different_payload() {
        let p = profile("{ name = \"a.bin\", bytes = 4096 }");
        let a = sources(&p, &mut Rng::from_seed(1)).unwrap();
        let b = sources(&p, &mut Rng::from_seed(2)).unwrap();
        assert_ne!(a[0].bytes, b[0].bytes);
    }

    /// Two files draw from ONE stream in list order, so the second
    /// file's bytes are not the first file's bytes. A stage that
    /// re-seeded per file would pass the reproducibility test above and
    /// hand par2gen two identical blocks.
    #[test]
    fn files_draw_in_order_from_one_stream() {
        let p = profile("{ name = \"a.bin\", bytes = 4096 }, { name = \"b.bin\", bytes = 4096 }");
        let s = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        assert_ne!(s[0].bytes, s[1].bytes);
    }

    /// The tree is kept whole in `rel` and split off into `base`. Which
    /// of the two reaches the wire is the naming plane's call, and it
    /// cannot make it if this stage has already thrown one away.
    #[test]
    fn a_directory_name_keeps_both_halves() {
        let p = profile("{ name = \"sample/s.bin\", bytes = 16 }");
        let s = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        assert_eq!(s[0].rel, "sample/s.bin");
        assert_eq!(s[0].base, "s.bin");
    }

    /// A name no post could carry is refused here rather than emitted
    /// and then refused by the posting tool downstream.
    #[test]
    fn unsafe_names_are_refused() {
        for n in [
            "/abs.bin",
            "../up.bin",
            "a//b.bin",
            "dir/",
            "",
            "quote\".bin",
            "back\\slash.bin",
        ] {
            // TOML-escape, so the test proves the NAME is refused and
            // not that the profile failed to parse around it.
            let toml_name = n.replace('\\', "\\\\").replace('"', "\\\"");
            let p = profile(&format!("{{ name = \"{toml_name}\", bytes = 16 }}"));
            assert!(
                matches!(
                    sources(&p, &mut Rng::from_seed(1)),
                    Err(SourceError::UnsafeName(_))
                ),
                "name {n:?} must be refused"
            );
        }
    }

    /// A typed extra zero is a refusal with a number in it, not a
    /// swapping CI runner.
    #[test]
    fn an_oversized_payload_is_refused_by_name() {
        let p = profile("{ name = \"a.bin\", bytes = 536870912 }");
        match sources(&p, &mut Rng::from_seed(1)) {
            Err(SourceError::TooLarge { asked, cap }) => {
                assert_eq!(asked, 536_870_912);
                assert_eq!(cap, MAX_TOTAL_PAYLOAD);
            }
            other => panic!("expected TooLarge, got {other:?}"),
        }
    }

    /// G2: the head is zeros and the tail is not, which is the shape
    /// the whole identical-head family rests on.
    #[test]
    fn a_zero_head_is_zeros_and_the_tail_is_not() {
        let p = profile("{ name = \"a.vob\", bytes = 4096, zero_head = 1024 }");
        let s = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        assert!(s[0].bytes[..1024].iter().all(|&b| b == 0));
        assert!(
            s[0].bytes[1024..].iter().any(|&b| b != 0),
            "the tail still comes off the stream"
        );
    }

    /// ...and two files with the same head and the same length agree on
    /// BOTH halves of the live matcher's key, which is the collision
    /// the family exists to pose. Asserted over 16,384 bytes because
    /// that is the window the key hashes, not because it is the head.
    #[test]
    fn two_headed_files_of_one_length_collide_the_head_window() {
        let p = profile(
            "{ name = \"a.vob\", bytes = 40000, zero_head = 20000 }, \
             { name = \"b.vob\", bytes = 40000, zero_head = 20000 }",
        );
        let s = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        assert_eq!(s[0].bytes.len(), s[1].bytes.len());
        assert_eq!(s[0].bytes[..16384], s[1].bytes[..16384]);
        assert_ne!(
            s[0].bytes[20000..],
            s[1].bytes[20000..],
            "and nothing past the head is shared, so no two PAR2 blocks are equal"
        );
    }

    /// The head is zeroed after the whole file is drawn, so adding one
    /// to a profile moves nothing after it. That is the same
    /// diffability rule the fault planes state about their own streams,
    /// and it is why a headed row can be read as a diff of a clean one.
    #[test]
    fn adding_a_zero_head_leaves_the_next_files_bytes_where_they_were() {
        let plain =
            profile("{ name = \"a.vob\", bytes = 4096 }, { name = \"b.vob\", bytes = 4096 }");
        let headed = profile(
            "{ name = \"a.vob\", bytes = 4096, zero_head = 1024 }, \
             { name = \"b.vob\", bytes = 4096 }",
        );
        let a = sources(&plain, &mut Rng::from_seed(7)).unwrap();
        let b = sources(&headed, &mut Rng::from_seed(7)).unwrap();
        assert_eq!(a[1].bytes, b[1].bytes);
        assert_eq!(
            a[0].bytes[1024..],
            b[0].bytes[1024..],
            "and the headed file's own tail is where it was too"
        );
    }

    /// G5: a dedupe entry IS the other file's bytes, and it draws
    /// nothing of its own - so the file after it gets the bytes it
    /// would have got if the copy were not there.
    #[test]
    fn a_dedupe_copy_is_the_same_bytes_and_draws_none() {
        let with_copy = profile(
            "{ name = \"one.bin\", bytes = 4096 }, \
             { name = \"two.bin\", bytes = 4096, same_as = \"one.bin\" }, \
             { name = \"three.bin\", bytes = 4096 }",
        );
        let without =
            profile("{ name = \"one.bin\", bytes = 4096 }, { name = \"three.bin\", bytes = 4096 }");
        let a = sources(&with_copy, &mut Rng::from_seed(9)).unwrap();
        let b = sources(&without, &mut Rng::from_seed(9)).unwrap();
        assert_eq!(a[0].bytes, a[1].bytes, "the copy is the same bytes");
        assert_eq!(a[1].rel, "two.bin", "under a name of its own");
        assert_eq!(
            a[2].bytes, b[1].bytes,
            "and the file after it drew where it would have drawn anyway"
        );
    }

    // G8 content

    /// The sync byte lands on every packet boundary and nowhere else
    /// by construction: 187 bytes in 188 are the stream's, which is
    /// what keeps this arm safe beside a recovery set.
    #[test]
    fn mpegts_syncs_on_the_packet_stride_and_leaves_the_rest_drawn() {
        let p = profile("{ name = \"vid\", bytes = 4096, content = \"mpegts\" }");
        let stamped = sources(&p, &mut Rng::from_seed(3)).unwrap();
        let plain = profile("{ name = \"vid\", bytes = 4096 }");
        let drawn = sources(&plain, &mut Rng::from_seed(3)).unwrap();
        let stride = 188usize;
        for i in (0..4096).step_by(stride) {
            assert_eq!(stamped[0].bytes[i], 0x47, "no sync at {i}");
        }
        for i in 0..4096 {
            if i % stride != 0 {
                assert_eq!(
                    stamped[0].bytes[i], drawn[0].bytes[i],
                    "byte {i} is not on a boundary and must be the byte that was drawn"
                );
            }
        }
    }

    /// ...and the whole file is still drawn, so a content shape is a
    /// diff of the row without it: no later file's bytes move.
    #[test]
    fn a_content_shape_leaves_the_next_files_bytes_where_they_were() {
        let plain =
            profile("{ name = \"a.bin\", bytes = 4096 }, { name = \"b.bin\", bytes = 4096 }");
        for shape in ["mpegts", "compressible"] {
            let shaped = profile(&format!(
                "{{ name = \"a.bin\", bytes = 4096, content = \"{shape}\" }}, \
                 {{ name = \"b.bin\", bytes = 4096 }}"
            ));
            let a = sources(&plain, &mut Rng::from_seed(11)).unwrap();
            let b = sources(&shaped, &mut Rng::from_seed(11)).unwrap();
            assert_eq!(a[1].bytes, b[1].bytes, "{shape} moved the next file");
        }
    }

    /// The compressible arm's whole point: bytes that actually shrink,
    /// measured against the WEAKEST coder that could work. The claim
    /// that matters - that the RAR writers do not store the member -
    /// is `crate::container`'s, over the real writer; this one pins
    /// the property of the bytes themselves, and pins the control arm
    /// beside it so a change that quietly made every payload
    /// compressible would be caught here.
    #[test]
    fn compressible_bytes_shrink_and_noise_does_not() {
        let shaped = profile("{ name = \"a.bin\", bytes = 60000, content = \"compressible\" }");
        let plain = profile("{ name = \"a.bin\", bytes = 60000 }");
        let s = sources(&shaped, &mut Rng::from_seed(5)).unwrap();
        let n = sources(&plain, &mut Rng::from_seed(5)).unwrap();
        let shrunk = rle_size(&s[0].bytes);
        let didnt = rle_size(&n[0].bytes);
        assert!(
            shrunk * 2 < s[0].bytes.len(),
            "compressible payload must at least halve, got {shrunk} of 60000"
        );
        assert!(
            didnt > n[0].bytes.len() * 9 / 10,
            "and the neutral row must still be incompressible, got {didnt} of 60000"
        );
    }

    /// No run reaches a PAR2 block, which is the half of the periodic
    /// argument that lives in this file - the other half is the schema
    /// refusing this arm beside a set at all.
    #[test]
    fn no_compressible_run_could_fill_a_recovery_block() {
        let p = profile("{ name = \"a.bin\", bytes = 200000, content = \"compressible\" }");
        let s = sources(&p, &mut Rng::from_seed(6)).unwrap();
        let b = &s[0].bytes;
        let (mut longest, mut run) = (1usize, 1usize);
        for i in 1..b.len() {
            run = if b[i] == b[i - 1] { run + 1 } else { 1 };
            longest = longest.max(run);
        }
        // Two adjacent runs can draw the same value, so the longest
        // observed run is up to twice the cap and not the cap itself.
        // What matters is the ORDER of magnitude against a block.
        assert!(
            longest < 64,
            "longest run {longest} is nowhere near a block, and must stay that way"
        );
    }

    /// What a trivial run-length coder would spend on these bytes: two
    /// bytes per run, counting runs. The weakest coder that could
    /// possibly work, and the point of choosing it - a payload THIS
    /// shrinks is a payload every LZ77 coder shrinks, so the test
    /// takes no compression dependency of its own and still says
    /// something a real writer will honour.
    fn rle_size(b: &[u8]) -> usize {
        let mut out = 0usize;
        let mut i = 0;
        while i < b.len() {
            let mut j = i + 1;
            while j < b.len() && b[j] == b[i] && j - i < 255 {
                j += 1;
            }
            out += 2;
            i = j;
        }
        out
    }

    /// A 0-byte file is a real posted shape (the VIDEO_TS placeholder),
    /// so it assembles rather than being refused.
    #[test]
    fn a_zero_byte_file_assembles() {
        let p = profile("{ name = \"empty.bin\", bytes = 0 }");
        let s = sources(&p, &mut Rng::for_profile(&p)).unwrap();
        assert!(s[0].bytes.is_empty());
    }
}
