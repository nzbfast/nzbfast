//! Tree-preserving output names (the relpath-preserve ruling, 29 Aug
//! 2026: a DVD or Blu-ray has to have its directory structure intact
//! for it to play).
//!
//! [`sanitize_filename`] maps every path separator to `_`, so a PAR2
//! FileDesc or archive member named `VIDEO_TS/VTS_01_1.VOB` landed flat
//! as `VIDEO_TS_VTS_01_1.VOB` and the disc could not play. The functions
//! here honor a member path when it is PROVABLY SAFE and fall back to
//! the flat form byte-for-byte when it is not - which also means a name
//! carrying no separator at all (every ordinary post) behaves exactly as
//! it always has: `sanitize_out_name(x) == sanitize_filename(x)` for
//! every separator-free `x`, by construction.
//!
//! ONE exception to that equality, and it is the one case where the
//! flat form is not a name at all: a component over 255 bytes, which no
//! filesystem this ships on will create. [`cap_component`] shortens it
//! deterministically. Nothing that works today changes - every name the
//! cap touches is one the write refused with `ENAMETOOLONG` - and the
//! measurement behind it is at that function.
//!
//! That cap CAPS rather than refuses, since 31 Aug 2026, and a
//! separator-carrying name with one overlong component therefore keeps
//! its tree instead of being flattened to save one leaf. The other two
//! caps still refuse, and why the three answer differently is on
//! [`sanitize_relpath_for`] - read that before moving any of them.
//!
//! The disk-side ladder set the precedent long ago:
//! `rarfix::sanitized_entry_path` has preserved trees for the external
//! unrar / native / 7z / zip disk paths (with the same traversal rules),
//! so job directories containing subdirectories are not a new state -
//! this closes the two flatteners left: the in-stream extractor and the
//! PAR2 FileDesc path.
//!
//! `sanitize_out_name` is an IDENTITY function as much as a path
//! builder: settle's name sets, the live verifier's FileDesc index,
//! adoption/donor keys and the extractor's collision claims all compare
//! its output against each other. Every member-name site must use this
//! ONE function - a site left on `sanitize_filename` computes a
//! different name for the same FileDesc and stops finding the file.

use super::sanitize_filename_for;
use std::fs::File;
use std::io;
use std::path::{Path, PathBuf};

/// Most components a preserved path may carry. A real disc tree is 2-3
/// deep; past this the name is nobody's directory layout.
///
/// A REFUSAL (the caller flattens), and it stays one - see the "which
/// cap refuses and which caps" block on [`sanitize_relpath_for`], which
/// records why this one and [`MAX_TOTAL`] answer differently from
/// [`MAX_COMPONENT`]. Measured on APFS 31 Aug 2026: a 20-deep tree of
/// short components creates without complaint, so this is a POLICY
/// budget and not a filesystem fact - and it is load-bearing at a
/// second site, `journal::restore::unquarantine_partials`, which bounds
/// its directory walk by it. That is why this is `pub(crate)` and
/// re-exported from `disk`: it was private and that site carried a
/// hand-copied literal, so raising this number left the walk silently
/// short of the trees it would then have to find - which is the 30 Aug
/// 2026 defect that function was written for. The two read one
/// constant now, and a test pins the walk's reach to it.
pub const MAX_DEPTH: usize = 16;
/// Per-component byte cap (the common filesystem limit).
///
/// A CAP, not a refusal, since 31 Aug 2026: a component over this is
/// shortened in place by [`cap_component`] and its tree is KEPT. The
/// reasoning is on [`sanitize_relpath_for`].
const MAX_COMPONENT: usize = 255;
/// Whole-name byte cap: the OUTPUT budget that keeps a joined path both
/// writable AND REACHABLE under any job directory up to 511 bytes.
///
/// A REFUSAL, and it stays one, for the reason on
/// [`sanitize_relpath_for`]: there is no tree-preserving remedy for a
/// name that is long because it has MANY components, so flattening to
/// one capped component is the only answer that fits whatever the job
/// directory turns out to be.
///
/// # Why 511, and why 1024 was unreachable BY CONSTRUCTION
///
/// It was 1024 until 31 Aug 2026, and 1024 is a number no name can
/// ever use. Measured on APFS that day: the ceiling is 1023 bytes and
/// it applies to the ABSOLUTE path, so `root + '/' + name <= 1023` and
/// a 1024-byte relative name is over budget under EVERY root that
/// exists, the empty one included. The old value could not be right;
/// it could only be wrong by a variable amount.
///
/// 511 splits the measured ceiling evenly - `1023 = 511 + 1 + 511` -
/// so the 511 bytes this does not spend are the guarantee: a name at
/// the cap is reachable under any output root up to 511 bytes, which
/// covers any download directory up to 255 bytes plus a
/// maximum-length job directory beneath it (a job directory is itself
/// a [`sanitize_filename`] result, so it cannot exceed
/// [`MAX_COMPONENT`]). Past that root length nothing can be
/// guaranteed, because the root is unbounded and this function cannot
/// see it - which is why the FALLBACK is strictly more forgiving than
/// the budget: it is one capped component, so it fits under any root
/// up to 767 bytes. The fallback must never be the thing that fails.
///
/// # What the split gives up, said rather than left implicit
///
/// A budget is a trade and this one has a losing side: a name between
/// the cap and the true ceiling would have fitted under a typical root
/// (about 90 bytes on this fleet's installs) and is flattened anyway,
/// so it loses its tree. That is the cost of the answer being
/// root-INDEPENDENT, which it has to be - see below - and it was
/// weighed against the shapes this module exists to protect: a real
/// DVD tree measures 31 bytes over 4 components and a Blu-ray one is
/// no larger (pinned in `a_real_disc_tree_has_headroom_on_every_cap`),
/// so the cap is 16x the longest layout the 29 Aug ruling was written
/// for. An archive deep enough to lose its tree here is one carrying
/// upwards of thirty components, which is nobody's disc and no
/// ordinary source tarball. It also still EXTRACTS, flat, where the
/// disk side used to fail the whole archive.
///
/// One more reason a budget is the honest shape here rather than a
/// calculation: the kernel measures the RESOLVED path, so an ancestor
/// symlink shortens the reservation by however much it expands
/// (measured: 8 bytes through `/var` on this fleet's Macs, which is
/// where `std::env::temp_dir()` lives). [`resolve_out_root`] resolves
/// a root that IS a link and deliberately leaves links above it alone,
/// so not even the write site can compute the true ceiling from the
/// string it holds - which is what rules out spending the budget
/// against the root and keeps this number root-INDEPENDENT.
///
/// # A budget is the only guard there is, because the write has none
///
/// Measured 31 Aug 2026, and it is the opposite of what a reader
/// expects: [`open_out_leaf_under`] - the door
/// `disk::FileWriter::create_under` writes every in-stream payload
/// through - does NOT fail on an over-ceiling path. It walks with
/// `openat`/`mkdirat`, one component per syscall, so the kernel never
/// sees a path long enough to refuse. It creates the file, and the
/// result is worse than an error: `read_dir` LISTS the name and
/// `open`, `stat`, `rename` and `unlink` on the absolute path all
/// return `ENAMETOOLONG`, so neither the product, nor the user's file
/// manager, nor anything else can read the payload or even delete it.
/// There is no error to catch at the write; the name has to be short
/// enough before it is written. Pinned in
/// `every_output_name_is_reachable_under_a_full_length_root`.
///
/// Checked against the OUTPUT rather than the raw name, since 31 Aug
/// 2026, and that is the 31 Aug component ruling applied to this axis:
/// refuse only when capping did not fix it. `a/<5000 bytes>.mkv` is
/// long because ONE component is long, [`cap_component`] has a remedy
/// for that, and the tree survives; a name long because it carries
/// MANY components has no remedy and still flattens. It costs nothing
/// to ask this way round - `contains` and `replace` have already
/// walked the whole name by then - and it removes the growth slop a
/// raw check carries (`sanitize_filename_for` prefixes a reserved DOS
/// stem with `_`, so a raw-checked name can produce an output past the
/// budget it was measured against).
///
/// [`sanitize_filename`]: super::sanitize_filename
const MAX_TOTAL: usize = 511;

/// Longest trailing `.ext` [`cap_component`] will carry over onto a
/// name it had to shorten. Past this the tail is not an extension,
/// it is the rest of somebody's sentence.
const MAX_EXT: usize = 17;

/// Cap one already-sanitized component at [`MAX_COMPONENT`] bytes, so
/// that what comes back is a name the filesystem can actually create.
///
/// EVERY path this ships on refuses a component over 255 bytes - APFS
/// and ext4 count UTF-8 bytes, NTFS counts UTF-16 units, and a string's
/// UTF-8 byte length is never below its UTF-16 unit length, so the one
/// byte cap covers both. Nothing above this function enforced it, and
/// the REFUSAL path made a violation certain rather than merely
/// possible: a name refused for carrying a component over
/// [`MAX_COMPONENT`], or for running past [`MAX_TOTAL`], fell back to
/// `sanitize_filename`, which folds the WHOLE path into ONE component -
/// so the fallback for "this is too long" was by construction at least
/// as long as the thing that was too long. Measured on APFS 30 Aug
/// 2026: `VIDEO_TS/<256 bytes>.VOB` flattens to 269 bytes, a
/// 3-component name over MAX_TOTAL to 1034, a 17-deep tree of 30-byte
/// components to 492 - all three `ENAMETOOLONG`. The module header's
/// promise to "fall back to the flat form" could not be kept for any
/// name the size caps refused.
///
/// The second, quieter source is GROWTH: `sanitize_filename_for`
/// prefixes a reserved DOS stem with `_`, so a component measured at
/// exactly 255 bytes and named `CON...` came back 256 and rode INTO a
/// preserved tree. The cap is applied after sanitizing for that reason.
///
/// Deterministic, because this is a comparison key as much as a path
/// piece (see the module header): every consumer computes it from the
/// same input and must agree. The extension is carried over - routing
/// and `is_final_name` read it, and a shortened name that lost its
/// `.mkv` reads as a container rather than a payload - and a SHA-256
/// prefix of the whole component is appended so two different overlong
/// names cannot collapse onto one file.
///
/// The result cannot itself be a reserved DOS stem, so this does not
/// need a second pass through `sanitize_filename_for`: the input is
/// already sanitized, so its first dot-segment is not reserved, and
/// truncation only reaches that segment when the segment is itself
/// longer than the 225-byte floor on the stem budget below.
fn cap_component(s: &str) -> String {
    cap_component_reserving(s, 0)
}

/// [`cap_component`], holding `reserve` bytes back for a tail the CALLER
/// will compose onto the result. `reserve == 0` is [`cap_component`]
/// itself, byte for byte.
///
/// See [`cap_shared_stem`] for why a reserve is the only answer that
/// keeps a stem shared by several composed names both writable and
/// paired. The whole budget shrinks by `reserve`, including the early
/// return: a 253-byte stem is untouched on its own and must still be
/// shortened when it is about to carry `.en.srt`.
///
/// Saturating, and the degenerate case is stated rather than left to be
/// found: a `reserve` big enough to swallow the whole budget yields just
/// the tag (plus any carried extension), which is still deterministic
/// and still distinct per input. If the tail ALONE is near
/// [`MAX_COMPONENT`] the composed name is unwritable whatever this
/// returns, and no shortening of the stem can change that.
fn cap_component_reserving(s: &str, reserve: usize) -> String {
    if s.len() + reserve <= MAX_COMPONENT {
        return s.to_string();
    }
    use sha2::{Digest, Sha256};
    let digest = Sha256::digest(s.as_bytes());
    let tag: String = digest[..6].iter().map(|b| format!("{b:02x}")).collect();
    // A tail counts as an extension only if it is short and plainly
    // alphanumeric; anything else is prose that happened to hold a dot.
    let ext = match s.rfind('.') {
        Some(i)
            if i > 0
                && s.len() - i <= MAX_EXT
                && s.len() - i > 1
                && s[i + 1..].chars().all(|c| c.is_ascii_alphanumeric()) =>
        {
            &s[i..]
        }
        _ => "",
    };
    // The `-` that joins the tag on. Floor: 255 - 12 - 1 - 17 = 225,
    // less whatever the caller reserved for its own tail.
    let budget = MAX_COMPONENT.saturating_sub(tag.len() + 1 + ext.len() + reserve);
    let mut cut = budget;
    while cut > 0 && !s.is_char_boundary(cut) {
        cut -= 1;
    }
    format!("{}-{tag}{ext}", &s[..cut])
}

/// The flat output name, CAPPED: [`sanitize_filename_for`] followed by
/// [`cap_component`], for a name that becomes exactly one directory
/// entry and has no front door to be refused at.
///
/// # The division this closes, and why it is a division rather than one
/// policy
///
/// Two answers exist for a name too long to write, and which one is
/// right is a property of the CALLER, not of the name:
///
///  * REFUSE - [`name_within_limits`]. Available only where there is
///    still somebody to tell. `nzb::quoted_filename` is the live
///    caller (N6-10): the NZB is in hand, nothing has been fetched, and
///    a refused slot name is a visible complaint about a visible file.
///  * CAP - this function, and [`sanitize_out_name_for`] for a name
///    that may carry a tree. The only answer left once the bytes are
///    already downloaded. A PAR2 FileDesc name, an archive member, an
///    ID3 title, a job folder taken from `nzbname=`: by the time any of
///    those is turned into a path there is no request left to fail, and
///    refusing means the payload has no name at all.
///
/// They are COMPLEMENTS and must not be unified. Measured on APFS
/// 31 Aug 2026: a 255-byte component creates, a 300-byte one is
/// `ENAMETOOLONG` for both `mkdir` and `create` - so every name this
/// function shortens is one the write refused outright. Nothing that
/// works today changes.
///
/// # Why not just call [`sanitize_out_name_for`]
///
/// Because these callers need the name to stay ONE component. A
/// category, a job folder stem and a `.strm` are each a single entry
/// under a root that the caller joins itself; `sanitize_out_name_for`
/// would hand back `a/b/c` for a name carrying separators and put the
/// payload one level down from where the caller believes it is. The
/// two differ ONLY there: for a separator-free name they are equal by
/// construction, exactly as the module header says of the uncapped
/// pair.
///
/// # Cap the COMPOSED name, never the stem
///
/// A caller building `{stem}.{ext}` must sanitize and cap the whole
/// thing, not the stem: a stem capped at 255 with `.mkv` appended is
/// 259 bytes and is refused just the same. [`cap_component`] carries a
/// short alphanumeric extension over the shortening for exactly this
/// reason, so composing first is both correct and the shorter code.
///
/// # The two sites that reach [`sanitize_filename_for`] elsewhere
///
/// Both were left uncapped when this landed on 31 Aug 2026 and both are
/// closed now, each by the door its own shape asks for rather than by
/// this one:
///
///  * `rarfix::sanitized_entry_path` sanitizes per COMPONENT while
///    building a staging path, and that same transform is the
///    filesystem-IDENTITY key the module keys entries by (the dedup in
///    `extract_one_zip`, and `resumeout`'s "did the chase publish
///    exactly here" test). Capping one end without the other splits the
///    key, which is a worse failure than the write error it would fix -
///    so the cap went INSIDE that function, which now calls THIS one per
///    component. That is the one place where the key and the write path
///    are a single value and cannot part. It also spells an overlong
///    flat member exactly as [`sanitize_out_name`] does, so a resume
///    that falls back to byte zero today now matches.
///  * `release::sanitize_name` produces DISPLAY titles as well as
///    folder names - `index::claims`, `index::spots` and `identity`
///    all read it - and a title truncated with a hash tag is wrong on
///    a wall row. Its disk-bound callers (`smart::filing`) cap at
///    their own site instead, which is the same rule as above: the
///    caller owns the answer. They cap through [`cap_shared_stem`] and
///    not through this function, because they compose THREE names off
///    one stem and the sidecar pairing depends on all three sharing it.
pub fn sanitize_filename_capped_for(name: &str, windows: bool) -> String {
    cap_component(&sanitize_filename_for(name, windows))
}

/// [`sanitize_filename_capped_for`] with this platform's rules, the
/// same convention (and reason) as [`sanitize_filename`].
///
/// [`sanitize_filename`]: super::sanitize_filename
pub fn sanitize_filename_capped(name: &str) -> String {
    sanitize_filename_capped_for(name, cfg!(windows))
}

/// Cap an ALREADY-SANITIZED component that the caller is about to
/// compose SEVERAL names off, holding back room for the longest of
/// `tails`.
///
/// # Why a budget, when the rule above is "cap the COMPOSED name"
///
/// That rule is right while the stem is composed exactly ONCE. It stops
/// being right the moment two names have to SHARE a stem, and
/// `smart::filing`'s subtitle sidecars are exactly that: a player finds
/// `Movie.en.srt` beside `Movie.mkv` because the two spell one stem, so
/// the pairing IS the shared prefix. Both obvious moves break it:
///
///  * capping each composed name independently hashes two different
///    inputs, so `{base}.mkv` and `{base}.en.srt` come back with
///    DIFFERENT tags and the subtitle stops being that video's;
///  * capping `base` alone at [`MAX_COMPONENT`] leaves `{base}.mkv`
///    four bytes over, and the write fails exactly as it did before.
///
/// The one answer that keeps both properties is to shorten the stem far
/// enough that the longest tail it will ever carry still fits, and then
/// compose. That is a decision about the SIGNATURE - the cap has to be
/// told what is coming - which is why it is a second door rather than a
/// call-site swap.
///
/// # Why the tails and not a byte count
///
/// Because the caller has them in hand (`.mkv`, `.en.srt`, and `""` for
/// a folder that carries no tail at all) and an off-by-one in the
/// arithmetic reintroduces precisely the write error this closes. An
/// empty `tails` reserves nothing, so this is then [`cap_component`]
/// itself.
///
/// # Preconditions, and what this deliberately does NOT do
///
/// `stem` must already be sanitized, the same precondition
/// [`cap_component`] carries and for the same reason. It is NOT
/// re-sanitized here: the live caller's sanitizer is
/// `release::sanitize_name`, which produces DISPLAY titles as well as
/// folder names (`index::claims`, `index::spots` and `identity` all read
/// it), so the CAP belongs at its disk-bound callers while the sanitize
/// stays where it is. Running `sanitize_filename_for` over its output
/// here would re-decide names that work today, which is a different
/// change from the one this makes.
///
/// The extension carry-over of [`cap_component`] applies to the stem's
/// own trailing dot-segment, which for a release name is almost never
/// there (`-GROUP` is not alphanumeric) and is harmless when it is: the
/// caller appends the real extension afterwards, and the pairing holds
/// either way because every composed name is built from this ONE result.
pub fn cap_shared_stem<'a>(stem: &str, tails: impl IntoIterator<Item = &'a str>) -> String {
    let reserve = tails.into_iter().map(str::len).max().unwrap_or(0);
    cap_component_reserving(stem, reserve)
}

/// Is a BUILT relative output name - components already sanitized and
/// capped, '/'-joined - inside the whole-name budget?
///
/// The one door onto [`MAX_TOTAL`] for a sanitizer outside this
/// module, so the number stays in one place. `rarfix::sanitized_entry_path`
/// is the caller this exists for: it builds its own path component by
/// component (it has to - its result is a `PathBuf` under a staging
/// root, and it is the filesystem-identity key the extractor dedups
/// on), so it cannot go through [`sanitize_relpath_for`], and a second
/// literal there would be two spellings of one policy.
///
/// Deliberately NOT [`name_within_limits`], which judges a RAW
/// candidate at a refuse door and asks the per-component question too.
/// This is asked of an output that is already capped per component, so
/// the component clause could only ever be vacuous, and asking it
/// would read as a check that means something.
pub fn relpath_within_total(rel: &str) -> bool {
    rel.len() <= MAX_TOTAL
}

/// Is this name within the length rules a REFUSE door holds a name to -
/// every component within [`MAX_COMPONENT`] bytes and the whole name
/// within [`MAX_TOTAL`]?
///
/// The length rules, asked on their own so a front door can refuse a
/// name before any network or filesystem work happens. It is
/// deliberately only the length question: traversal, absolute paths,
/// depth and per-component cleaning are decided when the path is
/// actually built, and a caller asking this is asking "could this ever
/// be a filename here", not "is this path safe to join".
///
/// # It is deliberately STRICTER than the CAP path, and was not always
///
/// This was "the LENGTH half of [`sanitize_relpath_for`]'s rules" until
/// 31 Aug 2026, when the per-component cap there stopped refusing and
/// started capping in place. The two now part on that one clause, on
/// purpose rather than by the doc going stale, and the division block
/// on [`sanitize_filename_capped_for`] is why: at a REFUSE door there
/// is still somebody to tell AND a good fallback, so answering
/// name-or-nothing keeps an EXACT-name contract that a silently
/// shortened name would break. Both live callers want exactly that.
/// `nzb::quoted_filename` skips an over-long quoted candidate and the
/// scan carries on to `unquoted_filename` and then to a per-slot
/// `fileNNN` placeholder; the category setter in
/// `serve::settings_setters` tells the person typing it, because a
/// shortened category would not match what their client was configured
/// with - and a category is ONE component, so the per-component clause
/// is the only one that ever fires for it.
///
/// Widening this door to match the CAP path is a separate decision
/// about NZB naming and category validation with no measured demand
/// behind it, and it is NOT what the 31 Aug ruling decided.
///
/// Separator-blind in the same way the rest of this module is: `\` is
/// a component separator alongside `/`, because PAR2 sets and RAR4-era
/// archives built on Windows store backslashes.
///
/// N6-10: `nzb::quoted_filename` is the caller this was extracted for.
/// It had no cap of any kind, so a 5,000-byte quoted name reached
/// materialization and failed there; `unquoted_filename` beside it has
/// capped at 255 since it was written. Reusing this keeps the two
/// halves of the NZB front door on the SAME policy as the disk side,
/// rather than growing a third number.
pub fn name_within_limits(name: &str) -> bool {
    name.len() <= MAX_TOTAL && name.split(['/', '\\']).all(|c| c.len() <= MAX_COMPONENT)
}

/// The tree-preserving output name: `a/b/c` (always '/'-joined, every
/// component individually sanitized) when [`sanitize_relpath_for`] rules
/// the path provably safe, the flat [`sanitize_filename`] form
/// otherwise. This is THE name function for member names - NZB slot
/// names, PAR2 FileDesc names, archive entry names - both for building
/// the on-disk path (via [`join_out_name`]) and as the comparison key
/// every consumer matches on.
///
/// [`sanitize_filename`]: super::sanitize_filename
pub fn sanitize_out_name(name: &str) -> String {
    sanitize_out_name_for(name, cfg!(windows))
}

/// [`sanitize_out_name`] with the platform as a parameter, same
/// convention (and reason) as [`sanitize_filename_for`]: the Windows
/// guarantees are asserted by the suite on the Mac and Linux boxes we
/// actually develop and run CI on.
pub fn sanitize_out_name_for(name: &str, windows: bool) -> String {
    match sanitize_relpath_for(name, windows) {
        Some(p) => p,
        None => cap_component(&sanitize_filename_for(name, windows)),
    }
}

/// The policy core: `Some("a/b/c")` when `name` is a provably safe
/// relative path worth preserving, `None` when the caller must flatten
/// (which it does by falling back to `sanitize_filename`, today's
/// behavior byte-for-byte).
///
/// `None` for: a name with no separator at all (flat is flat), an
/// absolute path or drive/UNC prefix, any `..`/`.`/empty component,
/// more than [`MAX_DEPTH`] components, or a CAPPED form still over
/// [`MAX_TOTAL`] bytes in all. Surviving components each go through the existing
/// per-component rules ([`sanitize_filename_for`]) and are then capped
/// at [`MAX_COMPONENT`] ([`cap_component`]), so control characters,
/// reserved DOS device names, trailing dots and overlong components
/// are all cleaned per component exactly as a flat name would be.
///
/// # Which cap REFUSES and which one CAPS, and why they differ
///
/// All three caps refused until 31 Aug 2026 and one of them should not
/// have. The three are not one policy - each is a different kind of
/// fact - and the ruling this module opens with (29 Aug 2026: a DVD or
/// Blu-ray has to have its directory structure intact for it to play)
/// is what scores them:
///
///  * [`MAX_COMPONENT`] CAPS, in place, keeping the tree. It is a real
///    per-component filesystem limit with an in-place remedy that
///    already exists: [`cap_component`] shortens the one component
///    deterministically and every other component is untouched, so the
///    tree survives. Refusing threw a playable disc's whole layout away
///    to fix one leaf, for precisely the class of name the cap was
///    added to handle. The asymmetry was also indefensible on its own
///    terms - a component that GROWS past the cap while being
///    sanitized has always been capped in place and kept its tree
///    (`a_reserved_stem_cannot_grow_a_component_past_the_cap`), so
///    "was already too long" and "became too long" got opposite
///    answers to the same question.
///  * [`MAX_TOTAL`] REFUSES, because there is no tree-preserving remedy
///    to reach for. A name is over it by carrying MANY components, and
///    no per-component shortening fixes that; the only answer that
///    fits whatever the job directory turns out to be is the flat one
///    capped component. It is checked on the OUTPUT, after capping,
///    which is this same rule applied consistently: a name long
///    because ONE component is long HAS a remedy, so it keeps its
///    tree. Its value moved from 1024 to 511 on 31 Aug 2026 because
///    1024 was unreachable by construction - see [`MAX_TOTAL`], which
///    also records why a budget is the only guard available here.
///  * [`MAX_DEPTH`] REFUSES, and it is the one that is not a
///    filesystem fact at all (measured on APFS 31 Aug 2026: a 20-deep
///    tree creates). It is a policy budget, a real disc is 2-4 deep,
///    the flat form is now writable, and the number is read by a second
///    site that bounds a directory walk with it - see [`MAX_DEPTH`].
///
/// # Why `rarfix::sanitized_entry_path` gets [`MAX_TOTAL`] and NOT [`MAX_DEPTH`]
///
/// It is the same shape of function on the disk-extraction side, and
/// the two limits reach it differently because its `None` and this
/// function's `None` ARE DIFFERENT WORDS. Here `None` means "the
/// caller flattens", and the caller does, so a refused name is a
/// degraded name that still works. There every caller turns `None`
/// into an aborted extraction (`extract_one_zip` bails the whole
/// archive before writing a byte; the tar, 7z and native arms each
/// bail the run), so anything that side REFUSES turns a merely
/// awkward archive from extracted into failed.
///
///  * [`MAX_DEPTH`] stays out. It is a policy budget rather than a
///    filesystem fact (a 20-deep tree creates), so spending an
///    aborted extraction on it buys nothing.
///  * [`MAX_TOTAL`] is now enforced there, because that side does not
///    have to refuse to enforce it: over budget it answers with the
///    same flat capped NAME this function's callers fall back to, so
///    the archive still extracts. Leaving it out was measured to cost
///    the whole archive - an 8x200-byte entry took `extract_one_zip`
///    down with `ENAMETOOLONG` at `create_dir_all` and an ordinary
///    sibling member was not written (31 Aug 2026).
///
/// So the two sides now AGREE on two axes of three. On
/// [`MAX_COMPONENT`] both compose
/// `cap_component(sanitize_filename_for(c))` per component, so
/// `VIDEO_TS/<300 bytes>.VOB` is spelled identically by both (the last
/// case commit 7c3fd6a8a left open); on [`MAX_TOTAL`] both fall back
/// to `sanitize_filename_capped_for` of the whole name, which is the
/// same function, so an over-budget member is spelled identically too.
/// They still part on DEPTH, deliberately and for the reason above;
/// the plan tolerates that (it falls back to byte zero), and it is the
/// cheaper end of the trade.
///
/// `\` counts as a separator alongside `/`: PAR2 sets and RAR4-era
/// archives built on Windows store backslashes, and
/// `rarfix::sanitized_entry_path` already normalizes them the same way.
pub fn sanitize_relpath_for(name: &str, windows: bool) -> Option<String> {
    if !name.contains(['/', '\\']) {
        return None;
    }
    let norm = name.replace('\\', "/");
    // Absolute ("/x") and UNC ("\\server\share", now "//server/share")
    // both start with a separator; the empty first component below
    // would catch them too, but say it plainly.
    if norm.starts_with('/') {
        return None;
    }
    let comps: Vec<&str> = norm.split('/').collect();
    if comps.len() > MAX_DEPTH {
        return None;
    }
    // A drive-letter prefix ("C:", "C:evil") is a path escape on
    // Windows however it is joined (`PathBuf::push` DISCARDS the base
    // for a prefixed piece), and no honest tree post starts with one -
    // refuse on every platform rather than map it into a weird name.
    let first = comps[0].as_bytes();
    if first.len() >= 2 && first[0].is_ascii_alphabetic() && first[1] == b':' {
        return None;
    }
    let mut out: Vec<String> = Vec::with_capacity(comps.len());
    for c in &comps {
        let trimmed = c.trim();
        // "." and ".." are the traversal shapes; a LONGER all-dot run
        // ("...") is not a traversal but is nobody's directory either -
        // sanitize would turn it into a literal "unnamed" segment.
        if trimmed.is_empty() || trimmed.chars().all(|ch| ch == '.') {
            return None;
        }
        let s = sanitize_filename_for(c, windows);
        // `sanitize_filename` cannot yield "", "." or ".." (all-dot
        // names become "unnamed") - hold that here rather than at a
        // distance, since the join below leans on it.
        if s.is_empty() || s == "." || s == ".." {
            return None;
        }
        out.push(cap_component(&s));
    }
    let joined = out.join("/");
    // The TOTAL cap, asked of the OUTPUT: see [`MAX_TOTAL`]. A name
    // that is long because ONE component is long has already been
    // fixed in place by `cap_component` above and keeps its tree; only
    // a name that is long because it carries MANY components reaches
    // this and flattens, and that is the shape with no tree-preserving
    // remedy.
    if joined.len() > MAX_TOTAL {
        return None;
    }
    Some(joined)
}

/// Join a [`sanitize_out_name`] result onto `root`. Component-wise, so
/// the platform's own separator is used on disk; safe by construction
/// because every '/'-separated piece is a sanitized single component
/// (no separators, no `..`, no prefix).
pub fn join_out_name(root: &Path, out_name: &str) -> PathBuf {
    let mut p = root.to_path_buf();
    for c in out_name.split('/') {
        p.push(c);
    }
    p
}

/// The `root`-relative output name of `path` - the inverse of
/// [`join_out_name`], '/'-joined whatever the platform separator. Falls
/// back to the bare file name when `path` is not under `root` (a moved
/// or foreign path), which is exactly what every caller compared before
/// trees existed.
pub fn out_name_of(root: &Path, path: &Path) -> String {
    let bare = || {
        path.file_name()
            .unwrap_or_default()
            .to_string_lossy()
            .into_owned()
    };
    match path.strip_prefix(root) {
        Ok(rel) => {
            let parts: Vec<String> = rel
                .components()
                .filter_map(|c| match c {
                    std::path::Component::Normal(p) => Some(p.to_string_lossy().into_owned()),
                    _ => None,
                })
                .collect();
            if parts.is_empty() {
                bare()
            } else {
                parts.join("/")
            }
        }
        Err(_) => bare(),
    }
}

/// Resolve a job's OUTPUT ROOT once, before anything writes under it.
///
/// [`open_out_leaf`] refuses a payload whose IMMEDIATE PARENT is a
/// symlink, and for a flat name that parent IS the output directory -
/// so `--out /some/symlink` stopped writing and started erroring when
/// that refusal landed (X5-06/08/19, 30 Aug 2026). The clean fix is
/// this one: resolve the root at job start and carry the resolved path
/// down, so the write site never has to decide whether to follow a link.
/// It is NOT to follow symlinks at the write, which is the hole X5-08
/// was.
///
/// ONLY A ROOT THAT IS ITSELF A LINK IS TOUCHED. An ordinary directory
/// comes back byte-identical, which is every install and every test -
/// so this changes no path anybody sees today, and the
/// `\\?\` verbatim form [`std::fs::canonicalize`] returns on Windows
/// cannot reach a spelling that used to work. It also keeps the
/// module's stated hold-out exactly: a symlink ABOVE the root (`/var`
/// -> `/private/var`, a symlinked home, a symlinked volume) is followed
/// as it always was, because only the final component is ever judged
/// and an unlinked root is handed straight back.
///
/// WINDOWS IS THE LOUDER HALF, not an afterthought. `FileType::is_symlink`
/// there is true for a JUNCTION as well as a symlink, and a junction is
/// an ordinary thing for a Windows user to point a downloads folder at -
/// where creating a unix symlink at least takes a deliberate act. The
/// same call covers both.
///
/// A root that does not exist yet is handed back unchanged: there is no
/// link there to resolve, and whatever creates it creates a real
/// directory. A DANGLING link is handed back too - `canonicalize` cannot
/// answer for a target that is not there - which leaves that case
/// failing exactly as it failed before.
pub fn resolve_out_root(dir: &Path) -> PathBuf {
    match std::fs::symlink_metadata(dir) {
        Ok(m) if m.file_type().is_symlink() => match std::fs::canonicalize(dir) {
            Ok(real) => strip_verbatim(real),
            Err(_) => dir.to_path_buf(),
        },
        _ => dir.to_path_buf(),
    }
}

/// Take the `\\?\` prefix back off a canonicalized Windows path when
/// what is left is an ordinary drive path, so the resolved root is
/// spelled the way every other path in the product is.
///
/// Verbatim paths are not merely ugly: they skip Win32 normalization, so
/// external tools (the unrar we shell out to, a user's file manager, the
/// `.rc` compilers this repo already documents the same trap for in
/// `crates/nzbfast/build.rs`) may refuse them. A UNC canonicalization
/// (`\\?\UNC\server\share`) is deliberately LEFT verbatim: dropping the
/// prefix there gives `UNC\server\share`, which names nothing.
#[cfg(windows)]
fn strip_verbatim(p: PathBuf) -> PathBuf {
    let s = p.to_string_lossy();
    let Some(rest) = s.strip_prefix(r"\\?\") else {
        return p;
    };
    // `C:\...` and nothing else. Anything shorter or shaped otherwise
    // (a UNC, a volume GUID) keeps the prefix that makes it valid.
    let b = rest.as_bytes();
    if b.len() >= 3 && b[0].is_ascii_alphabetic() && b[1] == b':' && b[2] == b'\\' {
        PathBuf::from(rest.to_string())
    } else {
        p
    }
}

/// Unix has no verbatim form; `canonicalize` already gives the spelling
/// everything else uses.
#[cfg(not(windows))]
fn strip_verbatim(p: PathBuf) -> PathBuf {
    p
}

/// The `refusing to create output under ...` error the directory walk
/// raises, spelled once so a reader greps one string.
fn create_not_a_real_dir(p: &Path) -> io::Error {
    io::Error::other(format!(
        "refusing to create output under {}: not a real directory",
        p.display()
    ))
}

/// The directory components of `out_name` - everything but the leaf.
fn out_dirs_of(out_name: &str) -> Vec<&str> {
    let comps: Vec<&str> = out_name.split('/').collect();
    comps[..comps.len().saturating_sub(1)].to_vec()
}

/// Whether a walk judges the ROOT's own final component, or follows a
/// link at it. See [`walk_out_dirs`] - the two answers reproduce the
/// asymmetry already on the tree rather than choosing between them.
#[cfg(unix)]
#[derive(Clone, Copy)]
enum RootLink {
    /// Follow it. [`create_out_dirs`]'s answer, and the one
    /// `nzbfast repair --dir <link>` depends on.
    Follow,
    /// Refuse it. [`open_out_leaf`]'s answer, which is what every write
    /// site has always got for a flat name.
    Refuse,
}

/// Walk down from `root` through the directory components of an output
/// name, creating what is missing, and hand back the last directory -
/// BOUND, on unix, so the caller writes into the directory that was
/// checked rather than into whatever the name means a moment later.
///
/// WHERE THE BOUNDARY IS, because everything else follows from it.
/// EVERY component BELOW the root is opened `O_NOFOLLOW` and refused if
/// it is not a real directory - which is the rule [`create_out_dirs`]
/// has always stated, now enforced one component at a time against a
/// descriptor instead of by re-resolving a whole path per step. What
/// happens at the ROOT's own final component is the caller's to say,
/// through `root_link`, and the two answers are not a preference: they
/// reproduce, exactly, the asymmetry that is already on the tree.
/// [`create_out_dirs`] has always FOLLOWED a link at the root (it is a
/// no-op for a flat name, which is how `nzbfast repair --dir <link>`
/// works at all), and [`open_out_leaf`] has always REFUSED one (for a
/// flat name the leaf's parent IS the root). A link ABOVE the root is
/// followed either way - `/var` -> `/private/var`, a symlinked home, a
/// symlinked volume - which is this module's standing hold-out.
///
/// THAT DIFFERENCE IS THE POINT (X5-06/08/19 residue 2, 30 Aug 2026).
/// The landed fix bound the LEAF and its IMMEDIATE PARENT, which is the
/// whole of what the probes measured; an output name may carry up to
/// [`MAX_DEPTH`] components, so `out/a/b/leaf.bin` with `a` swapped for
/// a link between the check and the write was still followed. A BDMV
/// tree (`BDMV/STREAM/00001.m2ts`) is exactly that shape. Walking
/// `openat`-relative from the root means no component is ever named to
/// the kernel with more than one unresolved step in front of it, so
/// there is no swap the write can be aimed through.
///
/// A missing component is created with `mkdirat` and re-opened under
/// the same bar - another worker of this same job making the same tree
/// is the ordinary case, not an error - so the CREATE walk carries the
/// rule too, and not only the walk that follows it.
///
/// Test seam for the window this function exists to close (31 Aug 2026
/// residue item 3): [`AFTER_WALK`] fires once, right here, after the
/// last component is bound and before the caller does anything with it
/// - the same instant `open_leaf_at`/`renameat` are handed the
/// descriptor. Every other test in this family plants its swap BEFORE
/// calling the door, which only proves a swap that predates the walk is
/// refused; this is what lets a test swap the name out from under an
/// ALREADY-BOUND descriptor and confirm the write still lands where the
/// walk actually looked, not through whatever the name means afterward.
#[cfg(unix)]
fn walk_out_dirs(root: &Path, out_name: &str, root_link: RootLink) -> io::Result<File> {
    use std::ffi::CString;
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;

    // The root - see the boundary note above for why this is the
    // caller's call. `ELOOP`/`ENOTDIR` are reported in this module's
    // own words, in the wording that door has always used; anything
    // else is the caller's own path being wrong and is passed through.
    let extra = match root_link {
        RootLink::Follow => 0,
        RootLink::Refuse => libc::O_NOFOLLOW,
    };
    let mut at = OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_CLOEXEC | extra)
        .open(root)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => match root_link {
                RootLink::Follow => create_not_a_real_dir(root),
                RootLink::Refuse => not_a_real_dir(root),
            },
            _ => e,
        })?;
    let mut shown = root.to_path_buf();
    for c in out_dirs_of(out_name) {
        shown.push(c);
        let Ok(name) = CString::new(c.as_bytes()) else {
            // An interior NUL. `sanitize_out_name` maps NUL out, so
            // this is not a component any output name here can carry.
            return Err(create_not_a_real_dir(&shown));
        };
        at = open_subdir(&at, &name, &shown)?;
    }
    #[cfg(test)]
    if let Some(f) = AFTER_WALK.with(|h| h.borrow_mut().take()) {
        f();
    }
    Ok(at)
}

/// Composing a disambiguating tag onto a name already at the caps - in
/// its own file because this one sits inside 3% of its size ceiling.
/// See `relpath/disambiguate.rs`'s module doc.
mod disambiguate;
pub use disambiguate::disambiguated_out_name;

/// [`walk_out_dirs`]'s racing-window test seam - in its own file so a
/// bare `drop(f)` elsewhere in this one can never be mistaken for a
/// reference to it. See `relpath/seam.rs`'s module doc for why.
#[cfg(all(test, unix))]
mod seam;
#[cfg(all(test, unix))]
use seam::{AFTER_WALK, after_walk};

/// One step of [`walk_out_dirs`]: open `name` inside `at`, creating it
/// if it is missing, and never following a link at it.
#[cfg(unix)]
fn open_subdir(at: &File, name: &std::ffi::CString, shown: &Path) -> io::Result<File> {
    use std::os::unix::io::{AsRawFd as _, FromRawFd as _};
    let flags = libc::O_RDONLY | libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC;
    // Two passes at most: open, and open again after creating it. A
    // third would be a loop somebody else can drive.
    for attempt in 0..2 {
        // SAFETY: openat is handed the live descriptor of `at` (which
        // outlives the call), a NUL-terminated path owned by `name`,
        // and integer flags. It writes nothing back through any
        // pointer, and the fd it returns is claimed exactly once below.
        let fd = unsafe { libc::openat(at.as_raw_fd(), name.as_ptr(), flags) };
        if fd >= 0 {
            // SAFETY: `fd` is a fresh, valid, owned descriptor from the
            // openat above (checked non-negative), and nothing else
            // holds or closes it - so `File` takes sole ownership of it
            // exactly once.
            return Ok(unsafe { File::from_raw_fd(fd) });
        }
        let e = io::Error::last_os_error();
        match e.raw_os_error() {
            // `O_NOFOLLOW` on a directory component: a link, or a
            // regular file, where a directory has to be.
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => {
                return Err(create_not_a_real_dir(shown));
            }
            Some(libc::ENOENT) if attempt == 0 => {
                // SAFETY: mkdirat is handed the live descriptor of `at`,
                // a NUL-terminated path owned by `name`, and a mode.
                // It writes nothing back through any pointer.
                let r = unsafe { libc::mkdirat(at.as_raw_fd(), name.as_ptr(), 0o777) };
                if r < 0 {
                    let made = io::Error::last_os_error();
                    // Another worker of this same job creating the same
                    // tree is the ordinary case - the re-open above
                    // holds the same not-a-link bar over whatever is
                    // there now.
                    if made.raw_os_error() != Some(libc::EEXIST) {
                        return Err(made);
                    }
                }
            }
            _ => return Err(e),
        }
    }
    Err(create_not_a_real_dir(shown))
}

/// Create the parent directories `out_name` needs under `root`,
/// component by component, refusing to route the write through anything
/// that is not a REAL directory. The refusal is the containment check
/// the ruling asks for: a symlink already sitting inside the job dir
/// (`VIDEO_TS -> /somewhere`) must not carry the payload outside it, so
/// a symlink - even one pointing back inside - fails the create rather
/// than being followed. Nothing to do for a flat name.
///
/// This hands back nothing but success. A caller that is about to WRITE
/// wants [`open_out_leaf_under`] instead, which keeps the descriptor
/// this walk validated and opens the payload inside it - the directory
/// a path re-resolves to a moment later is not necessarily the one that
/// was checked.
pub fn create_out_dirs(root: &Path, out_name: &str) -> io::Result<()> {
    #[cfg(unix)]
    {
        // A flat name creates nothing, so it must not fail on a root
        // that is merely unusual: keep the walk's one no-op case a
        // no-op.
        if out_dirs_of(out_name).is_empty() {
            return Ok(());
        }
        walk_out_dirs(root, out_name, RootLink::Follow).map(|_| ())
    }
    #[cfg(not(unix))]
    {
        create_out_dirs_by_path(root, out_name)
    }
}

/// The path-walking form of [`create_out_dirs`], for the platform with
/// no `openat`: each component is stat'd and then used, so the window
/// between the two stays open - see [`open_out_leaf`]'s note, and the
/// `windows-path-identity-and-red` claim that owns closing it.
#[cfg(not(unix))]
fn create_out_dirs_by_path(root: &Path, out_name: &str) -> io::Result<()> {
    let mut p = root.to_path_buf();
    for c in out_dirs_of(out_name) {
        p.push(c);
        match std::fs::symlink_metadata(&p) {
            Ok(m) if m.is_dir() => {}
            Ok(_) => return Err(create_not_a_real_dir(&p)),
            Err(e) if e.kind() == io::ErrorKind::NotFound => match std::fs::create_dir(&p) {
                Ok(()) => {}
                // Another worker of this same job creating the same
                // tree is the ordinary case, not an error - re-stat
                // and hold the same not-a-symlink bar.
                Err(e2) if e2.kind() == io::ErrorKind::AlreadyExists => {
                    let m = std::fs::symlink_metadata(&p)?;
                    if !m.is_dir() {
                        return Err(create_not_a_real_dir(&p));
                    }
                }
                Err(e2) => return Err(e2),
            },
            Err(e) => return Err(e),
        }
    }
    Ok(())
}

/// [`create_out_dirs`] + [`join_out_name`] in one call, for sites that
/// need the PATH rather than an open file: the returned path's parents
/// exist (or the whole call failed) and every component is contained
/// under `root`.
///
/// A write site wants [`open_out_leaf_under`]. This hands back a name,
/// and a name is exactly what the X5-06/08/19 family was about - it is
/// kept for the callers that go on to `rename(2)` into it, or that only
/// wanted the directories made.
pub fn prepare_out_path(root: &Path, out_name: &str) -> io::Result<PathBuf> {
    create_out_dirs(root, out_name)?;
    Ok(join_out_name(root, out_name))
}

/// Create the directories `out_name` needs under `root` and open the
/// payload leaf inside the LAST ONE, without ever re-resolving a name
/// the walk already validated.
///
/// This is [`prepare_out_path`] and [`open_out_leaf`] fused, and the
/// fusion is the whole point: taken separately they are two path
/// resolutions with a gap between them, and that gap is what X5-08
/// walked a payload out of the job directory through. Prefer this at
/// every site that is about to write - `open_out_leaf` is what is left
/// for a caller holding only a path, and it can bind no more than the
/// leaf and its immediate parent.
///
/// Same containment boundary as [`walk_out_dirs`], asked with
/// `RootLink::Refuse` - so this refuses exactly what [`open_out_leaf`]
/// refuses at the root (for a flat name the leaf's parent IS the root)
/// and nothing is loosened by moving a write site onto it.
pub fn open_out_leaf_under(root: &Path, out_name: &str, mode: LeafOpen) -> io::Result<File> {
    #[cfg(unix)]
    {
        let leaf = out_name.rsplit('/').next().unwrap_or(out_name);
        if leaf.is_empty() {
            return Err(leaf_is_a_link(&join_out_name(root, out_name)));
        }
        let dir = walk_out_dirs(root, out_name, RootLink::Refuse)?;
        open_leaf_at(&dir, &join_out_name(root, out_name), leaf, mode)
    }
    #[cfg(not(unix))]
    {
        create_out_dirs(root, out_name)?;
        open_out_leaf(&join_out_name(root, out_name), mode)
    }
}

/// Rename `from` onto `out_name` under `root`, with the destination's
/// directories made and BOUND the same way [`open_out_leaf_under`]
/// binds them.
///
/// `rename(2)` does not follow a symlink at the destination's FINAL
/// component - it replaces it - but it does follow every component
/// above, so a publish into `out/a/b/name` with `a` swapped for a link
/// lands the file outside the job directory. That is the same
/// ancestor-swap window the write sites close, on the paths that finish
/// with a rename rather than with an open; only the destination is
/// bound, because the source is a file this job already owns and is not
/// what an attacker gets to redirect.
///
/// Hands back the destination path, which every caller goes on to
/// report or to store.
pub fn rename_out_under(root: &Path, out_name: &str, from: &Path) -> io::Result<PathBuf> {
    let target = join_out_name(root, out_name);
    #[cfg(unix)]
    {
        use std::ffi::CString;
        use std::os::unix::ffi::OsStrExt as _;
        use std::os::unix::io::AsRawFd as _;
        let leaf = out_name.rsplit('/').next().unwrap_or(out_name);
        let (Ok(old), Ok(new)) = (
            CString::new(from.as_os_str().as_bytes()),
            CString::new(leaf.as_bytes()),
        ) else {
            // An interior NUL on either side. `sanitize_out_name` maps
            // NUL out, so this is not a name any output path can carry.
            return Err(leaf_is_a_link(&target));
        };
        let dir = walk_out_dirs(root, out_name, RootLink::Refuse)?;
        // SAFETY: renameat is handed AT_FDCWD plus a NUL-terminated
        // path owned by `old`, and the live descriptor of `dir` (which
        // outlives the call) plus a NUL-terminated name owned by `new`.
        // It writes nothing back through any pointer.
        let r =
            unsafe { libc::renameat(libc::AT_FDCWD, old.as_ptr(), dir.as_raw_fd(), new.as_ptr()) };
        if r < 0 {
            return Err(io::Error::last_os_error());
        }
        Ok(target)
    }
    #[cfg(not(unix))]
    {
        // No `renameat`, so the destination is resolved by path and the
        // window stays open - the same platform residue
        // `open_out_leaf` documents, owned by the same claim.
        create_out_dirs(root, out_name)?;
        std::fs::rename(from, &target)?;
        Ok(target)
    }
}

/// How [`open_out_leaf`] opens the payload leaf.
///
/// The four shapes the output paths need. Three of them CREATE a
/// missing leaf and differ only in what they do to one already there;
/// [`LeafOpen::Existing`] is the odd one out and says so at its own
/// variant, because "create if missing" is the wrong answer for a
/// REOPEN of a file we already wrote.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum LeafOpen {
    /// Create if missing, TRUNCATE if present - the fresh-write open.
    Truncate,
    /// Create if missing, keep the bytes already on disk - the resume
    /// open. A truncate here silently restarts the download it was
    /// called to continue, which is why this is its own mode rather
    /// than a flag somebody can get backwards.
    Keep,
    /// Create, and FAIL if anything is already at the name. For a
    /// destination that must be ours alone (a dedupe copy, a scratch
    /// probe): `create_new` plus the no-follow rule below is the only
    /// combination that cannot be aimed at somebody else's inode.
    CreateNew,
    /// Open a file that MUST already be there, keeping its bytes, and
    /// NEVER create one. The reopen of something this process wrote
    /// earlier - a parked writer coming back after the external par2
    /// (`FileWriter::unpark`), a staged temp being fsynced before its
    /// rename.
    ///
    /// It is its own mode rather than [`LeafOpen::Keep`] because the
    /// two disagree about the one case that matters: a file that has
    /// GONE. `Keep` answers by creating an empty one, and every caller
    /// on this path would then carry on over zero bytes it believes are
    /// the repaired payload. `Existing` reports `NotFound`, which is
    /// what the caller can act on.
    Existing,
}

/// Open the output leaf at `path`, binding the directory that was
/// CHECKED to the file that is WRITTEN.
///
/// This is the one place the containment rule in this module's header
/// becomes enforceable AT THE MOMENT OF USE. [`create_out_dirs`]
/// validates every parent component and refuses one that is not a real
/// directory, but it hands back a PATH, and the write site then opens
/// that path as a separate operation - so anything that changes what
/// the name refers to in between redirects the write. Three confirmed
/// defects were that one gap (X5-06, X5-08, X5-19, 30 Aug 2026): a
/// symlink planted at the payload's own name truncated an outside
/// inode; the same alias survived the non-truncating resume open and
/// RESIZED an outside inode 51 -> 4096 bytes through
/// `preallocate_capped`; and a directory swapped for a symlink between
/// `prepare_out_path` and the open put the payload outside the job
/// directory entirely.
///
/// Two refusals, and they are the whole mechanism:
///
/// * the leaf's PARENT may not be a symlink, and
/// * the LEAF may not be a symlink.
///
/// On unix both are atomic and there is no window between them: the
/// parent is opened `O_DIRECTORY | O_NOFOLLOW` - which is what refuses
/// a swapped parent, since `O_NOFOLLOW` judges the final component -
/// and the leaf is then opened `openat(2)`-relative to THAT DESCRIPTOR
/// with `O_NOFOLLOW` of its own. A descriptor names an inode, not a
/// name, so a swap landing after the directory is open cannot reach the
/// write: the file is created inside the directory that was checked, or
/// not at all.
///
/// On Windows there is no `openat` either, but `NtCreateFile` has
/// `RootDirectory`, so since 31 Aug 2026 the two refusals are the same
/// two steps and the same strength as the unix pair above - see
/// `relpath/winbind.rs`, which holds the FFI and the measurements:
///
/// * the PARENT is opened as a HANDLE, with
///   `FILE_FLAG_BACKUP_SEMANTICS | FILE_FLAG_OPEN_REPARSE_POINT`, and
///   the not-a-link test is made against THAT HANDLE. The leaf is then
///   created relative to it, so a name swapped at the parent after it
///   was opened cannot reach the write.
/// * the LEAF is bound the same way it already was:
///   `FILE_OPEN_REPARSE_POINT`, so a link planted after the check is
///   OPENED rather than followed and the refusal is made against the
///   handle. Both were verified on a real Windows box, which is also
///   where the exposure was confirmed to be real rather than
///   theoretical: without the leaf flag a planted symlink truncated an
///   outside target 15 -> 0 bytes and a dangling one created an outside
///   file, and without the parent bind a create landed in a directory
///   swapped in after the check.
///
/// What is NOT bound there is what is not bound here: a symlink ABOVE
/// the immediate parent is followed on both platforms, and the
/// whole-walk bind is [`open_out_leaf_under`]'s, which is still by path
/// on Windows.
///
/// The exposure is narrower on Windows in any case: creating a symlink
/// needs SeCreateSymbolicLinkPrivilege (an administrator, or Developer
/// Mode), where any unprivileged process can plant one on unix.
///
/// WHAT THIS COSTS, because it is a real behaviour change and not only
/// a hardening: a payload whose immediate parent directory IS a symlink
/// is now refused rather than followed. In every production call that
/// parent is either the job's own output directory or a subdirectory
/// [`create_out_dirs`] made inside it, so a symlink at either is
/// exactly the shape the ruling refuses - but a user who points the
/// output at a symlinked directory and downloads a flat name gets a
/// loud error where they used to get a file. The clean fix for that is
/// to resolve the output root ONCE when the job starts, not to follow
/// symlinks here; note that only the FINAL component is judged, so a
/// symlink anywhere ABOVE the parent (`/var` -> `/private/var`, a
/// symlinked home, a symlinked volume) is followed exactly as before.
pub fn open_out_leaf(path: &Path, mode: LeafOpen) -> io::Result<File> {
    // A bare relative name ("x.bin") has an EMPTY parent, not none;
    // that is the current directory, and it worked before this - so it
    // resolves to "." rather than becoming a new refusal. `None` here
    // is only the filesystem root ("/"); ".." has an empty parent and
    // is caught by the `file_name` arm below, which is what refuses
    // every path that names no file.
    let parent = match path.parent() {
        Some(p) if p.as_os_str().is_empty() => Path::new("."),
        Some(p) => p,
        None => {
            return Err(io::Error::other(format!(
                "refusing to open output {}: it names no parent directory",
                path.display()
            )));
        }
    };
    let Some(leaf) = path.file_name() else {
        return Err(io::Error::other(format!(
            "refusing to open output {}: it names no file",
            path.display()
        )));
    };
    open_leaf_in(parent, leaf, mode)
}

/// The `refusing to route the write through ...` error both platform
/// arms raise, spelled once so a reader greps one string.
fn not_a_real_dir(parent: &Path) -> io::Error {
    io::Error::other(format!(
        "refusing to write output under {}: not a real directory",
        parent.display()
    ))
}

/// The same refusal for the leaf itself.
fn leaf_is_a_link(path: &Path) -> io::Error {
    io::Error::other(format!(
        "refusing to write output {}: an alias is in the way",
        path.display()
    ))
}

/// The parent directory of an output leaf, opened by NAME but refusing
/// to follow a symlink at that name - `O_DIRECTORY | O_NOFOLLOW`, so a
/// directory swapped for an alias between the check and the use is
/// ELOOP rather than a redirected write.
///
/// Spelled once and shared: [`open_leaf_in`] needs it to root its
/// `openat`, and `disk::copy_file_cow`'s macOS clone arm needs the same
/// descriptor for `fclonefileat`, which takes a destination DIRECTORY
/// plus a name. A second hand-rolled copy of these three flags is
/// exactly the "two spellings of one rule" this module exists to end.
#[cfg(unix)]
pub(super) fn open_dir_nofollow(parent: &Path) -> io::Result<File> {
    use std::fs::OpenOptions;
    use std::os::unix::fs::OpenOptionsExt as _;
    OpenOptions::new()
        .read(true)
        .custom_flags(libc::O_DIRECTORY | libc::O_NOFOLLOW | libc::O_CLOEXEC)
        .open(parent)
        .map_err(|e| match e.raw_os_error() {
            Some(libc::ELOOP) | Some(libc::ENOTDIR) => not_a_real_dir(parent),
            _ => e,
        })
}

#[cfg(unix)]
fn open_leaf_in(parent: &Path, leaf: &std::ffi::OsStr, mode: LeafOpen) -> io::Result<File> {
    let dir = open_dir_nofollow(parent)?;
    open_leaf_at(&dir, &parent.join(leaf), leaf, mode)
}

/// Open the payload leaf INSIDE an already-bound directory.
///
/// `dir` names an inode, not a name, so a swap landing after it was
/// opened cannot reach this write: the file is created inside the
/// directory that was checked, or not at all. `shown` is only ever used
/// to spell a refusal - resolving a descriptor back to a path is
/// neither portable nor honest, and the refusals here are read by
/// people rather than parsed.
#[cfg(unix)]
fn open_leaf_at(
    dir: &File,
    shown: &Path,
    leaf: impl AsRef<std::ffi::OsStr>,
    mode: LeafOpen,
) -> io::Result<File> {
    use std::ffi::CString;
    use std::os::unix::ffi::OsStrExt as _;
    use std::os::unix::io::{AsRawFd as _, FromRawFd as _};

    let Ok(name) = CString::new(leaf.as_ref().as_bytes()) else {
        // An interior NUL. `sanitize_filename` maps NUL out, so this is
        // not a name any output path here can carry.
        return Err(leaf_is_a_link(shown));
    };
    // `Existing` is the one mode that does NOT set `O_CREAT`, so its
    // extra flag has to come out of the same match that the create bit
    // does - a caller cannot be handed O_EXCL without O_CREAT, which is
    // undefined, and cannot be handed O_CREAT for a mode whose whole
    // point is that a missing file is an error.
    let (create, extra) = match mode {
        LeafOpen::Truncate => (libc::O_CREAT, libc::O_TRUNC),
        LeafOpen::Keep => (libc::O_CREAT, 0),
        LeafOpen::CreateNew => (libc::O_CREAT, libc::O_EXCL),
        LeafOpen::Existing => (0, 0),
    };
    let flags = libc::O_RDWR | create | libc::O_NOFOLLOW | libc::O_CLOEXEC | extra;
    // SAFETY: openat is handed the live descriptor of `dir` (which
    // outlives the call), a NUL-terminated path owned by `name`, and
    // integer flags plus the mode. It writes nothing back through any
    // pointer, and the fd it returns is claimed exactly once below.
    let fd = unsafe { libc::openat(dir.as_raw_fd(), name.as_ptr(), flags, 0o666 as libc::c_uint) };
    if fd < 0 {
        let e = io::Error::last_os_error();
        return Err(match e.raw_os_error() {
            // O_NOFOLLOW on the leaf: something is aliased at the
            // payload's own name.
            Some(libc::ELOOP) => leaf_is_a_link(shown),
            _ => e,
        });
    }
    // SAFETY: `fd` is a fresh, valid, owned descriptor from the openat
    // above (checked non-negative), and nothing else holds or closes
    // it - so `File` takes sole ownership of it exactly once.
    Ok(unsafe { File::from_raw_fd(fd) })
}

/// `NtCreateFile`'s `RootDirectory`, which is how the leaf below is
/// opened INSIDE the directory that was checked. In its own file because
/// it is FFI plus the measurements that make the FFI checkable, and
/// `relpath.rs` is within a few dozen lines of its size-gate ceiling -
/// the same reasoning as `relpath/seam.rs` next door.
#[cfg(windows)]
mod winbind;

/// The Windows twin of the two calls above, and the same two steps: the
/// parent is opened as a HANDLE that refuses a link at its own name, and
/// the leaf is then created RELATIVE to that handle. Win32 has no
/// `openat`; `NtCreateFile` has `RootDirectory`, which is what the FFI in
/// `relpath/winbind.rs` is for and why it is a file of its own.
#[cfg(windows)]
fn open_leaf_in(parent: &Path, leaf: &std::ffi::OsStr, mode: LeafOpen) -> io::Result<File> {
    let dir = winbind::open_dir_nofollow(parent)?;
    winbind::open_leaf_at(&dir, &parent.join(leaf), leaf, mode)
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The REFUSE/CAP division, asserted from both ends.
    ///
    /// `sanitize_filename` deliberately has NO length cap and never
    /// grows one: it is the flat form the whole tree compares against,
    /// and a cap inside it would silently move every comparison key.
    /// The cap lives in [`sanitize_filename_capped_for`], which the
    /// disk-bound callers reach for, and the refusal lives in
    /// [`name_within_limits`], which the front doors reach for.
    ///
    /// Measured on APFS 31 Aug 2026 and the reason this is worth a
    /// pin at all: a 255-byte component creates and a 300-byte one is
    /// `ENAMETOOLONG` for both `mkdir` and `create`, so a
    /// separator-free overlong name on an uncapped site is not a
    /// cosmetic problem, it is a write that cannot happen.
    #[test]
    fn the_flat_sanitizer_does_not_cap_and_the_capped_one_does() {
        let long = "x".repeat(300);
        for w in [false, true] {
            // The uncapped form is the identity the tree compares on,
            // so it hands back all 300 bytes.
            assert_eq!(
                super::super::sanitize_filename_for(&long, w).len(),
                300,
                "sanitize_filename must stay uncapped (windows={w})"
            );
            // The capped form is a name the filesystem will take.
            let capped = sanitize_filename_capped_for(&long, w);
            assert!(
                capped.len() <= MAX_COMPONENT,
                "{} bytes (windows={w})",
                capped.len()
            );
            // Deterministic: every consumer computes the same key.
            assert_eq!(capped, sanitize_filename_capped_for(&long, w));
            // And it stays ONE component, which is the whole reason
            // these callers cannot simply use `sanitize_out_name_for`.
            assert!(!capped.contains('/'), "the capped flat form is flat");
        }
        // The extension is carried over the shortening, which is why a
        // caller composes `{stem}.{ext}` and caps THAT rather than
        // capping the stem and appending afterwards.
        let composed = sanitize_filename_capped_for(&format!("{long}.mkv"), false);
        assert!(composed.ends_with(".mkv"), "{composed}");
        assert!(composed.len() <= MAX_COMPONENT);
        // Two different overlong names must not collapse onto one file.
        let other = sanitize_filename_capped_for(&format!("{}.mkv", "y".repeat(300)), false);
        assert_ne!(composed, other);

        // A name at or under the cap is untouched by either form, so
        // nothing that works today changes.
        for n in ["movie.mkv", "x"] {
            assert_eq!(
                sanitize_filename_capped_for(n, false),
                super::super::sanitize_filename_for(n, false)
            );
        }
        let at_cap = "z".repeat(MAX_COMPONENT);
        assert_eq!(sanitize_filename_capped_for(&at_cap, false), at_cap);

        // The refusal half, and it is the COMPLEMENT rather than a
        // second opinion: what the front door refuses is exactly what
        // the downstream form would have had to shorten.
        assert!(name_within_limits(&at_cap));
        assert!(!name_within_limits(&long));
    }

    /// The BUDGETED half of the cap, and the property that makes it
    /// different in kind from the one above: several names composed off
    /// ONE stem, all of which have to fit, and all of which have to keep
    /// spelling that one stem.
    ///
    /// The two obvious moves are asserted to fail here rather than
    /// merely described, because they are what a future edit would
    /// reach for.
    #[test]
    fn a_shared_stem_is_capped_against_the_longest_tail_it_will_carry() {
        let stem = "M".repeat(300);
        let tails = [".mkv", ".en.srt", ".forced.fr.srt"];
        let longest = ".forced.fr.srt";

        // Move 1, capping each COMPOSED name on its own: every name
        // fits, and they no longer share a stem, so the sidecar stops
        // being that video's.
        let per_name: Vec<String> = tails
            .iter()
            .map(|t| sanitize_filename_capped_for(&format!("{stem}{t}"), false))
            .collect();
        let video_stem = per_name[0]
            .strip_suffix(".mkv")
            .expect("the carried extension is what routing reads");
        for n in &per_name {
            assert!(n.len() <= MAX_COMPONENT);
        }
        for sidecar in &per_name[1..] {
            assert!(
                !sidecar.starts_with(video_stem),
                "{sidecar} must NOT be pairable with {video_stem} - the tags \
                 are hashes of two different inputs, which is the whole reason \
                 the composed names cannot be capped one at a time"
            );
        }

        // Move 2, capping the stem alone: the stem fits and the composed
        // name does not, which is the write error unchanged.
        let alone = sanitize_filename_capped_for(&stem, false);
        assert_eq!(alone.len(), MAX_COMPONENT);
        assert!(alone.len() + longest.len() > MAX_COMPONENT);

        // The budgeted answer: one stem, and every name composed off it
        // fits.
        let base = cap_shared_stem(&sanitize_filename_for(&stem, false), tails);
        for t in tails {
            let composed = format!("{base}{t}");
            assert!(
                composed.len() <= MAX_COMPONENT,
                "{} bytes for {t}",
                composed.len()
            );
            assert!(composed.starts_with(&base), "every name spells one stem");
        }
        // Deterministic, and distinct per input - the same two properties
        // the unbudgeted cap has to have.
        assert_eq!(
            base,
            cap_shared_stem(&sanitize_filename_for(&stem, false), tails)
        );
        assert_ne!(base, cap_shared_stem(&"N".repeat(300), tails));
        // The reserve is the LONGEST tail, not the first or the sum.
        assert_eq!(
            base,
            cap_shared_stem(&sanitize_filename_for(&stem, false), [longest])
        );

        // No tails is the plain cap, byte for byte.
        let none: [&str; 0] = [];
        assert_eq!(
            cap_shared_stem(&sanitize_filename_for(&stem, false), none),
            alone
        );

        // A stem UNDER the cap on its own still has to be shortened when
        // it is about to carry a tail - the early return moves with the
        // budget or this whole thing is decoration.
        let snug = "s".repeat(MAX_COMPONENT - 2);
        assert_eq!(sanitize_filename_capped_for(&snug, false), snug);
        let capped_snug = cap_shared_stem(&snug, [".en.srt"]);
        assert!(capped_snug.len() + ".en.srt".len() <= MAX_COMPONENT);
        // And one that fits WITH its tail is untouched.
        let fits = "f".repeat(MAX_COMPONENT - 8);
        assert_eq!(cap_shared_stem(&fits, [".en.srt"]), fits);

        // Degenerate: a tail that swallows the whole budget still yields
        // a non-empty, deterministic, per-input stem rather than "" - an
        // empty stem would compose to a hidden file.
        let huge = ".".to_string() + &"t".repeat(MAX_COMPONENT);
        let squeezed = cap_shared_stem(&stem, [huge.as_str()]);
        assert!(!squeezed.is_empty());
        assert_ne!(squeezed, cap_shared_stem(&"N".repeat(300), [huge.as_str()]));
    }

    #[test]
    fn flat_names_are_untouched_and_identical_to_sanitize_filename() {
        for n in [
            "movie.mkv",
            "  ..hidden  ",
            "",
            "CON",
            "evil. ",
            "Movie: The Sequel.mkv",
            "ev\u{7}il\nname\t.mkv",
        ] {
            assert_eq!(sanitize_relpath_for(n, false), None, "{n:?}");
            assert_eq!(
                sanitize_out_name_for(n, false),
                sanitize_filename_for(n, false),
                "{n:?} must be byte-identical to the flat form"
            );
            assert_eq!(
                sanitize_out_name_for(n, true),
                sanitize_filename_for(n, true),
                "{n:?} (windows)"
            );
        }
    }

    /// M4-66 / M4-67 through the OUT-NAME function, which is the half
    /// that matters: this is a comparison KEY as much as a path builder
    /// (see the module header), so two declared names collapsing here is
    /// two payloads claiming one identity - and a format character
    /// surviving here is a key whose printed form is not its bytes.
    ///
    /// Both fixes live in `sanitize_filename_for`, which is what keeps
    /// the flat-identity invariant above true: the flat form and the
    /// per-component form move together, so no site can be left
    /// computing the old name for a new key.
    #[test]
    fn leading_dots_and_format_chars_survive_as_distinct_out_names() {
        for win in [false, true] {
            // Flat: two legal, distinct names stay two names.
            assert_ne!(
                sanitize_out_name_for(".movie.mkv", win),
                sanitize_out_name_for("movie.mkv", win),
                "windows={win}"
            );
            // And inside a preserved tree, per component - a Windows-
            // authored set spells the separator the other way.
            assert_eq!(
                sanitize_out_name_for("VIDEO_TS/.VTS_01_1.VOB", win),
                "VIDEO_TS/_VTS_01_1.VOB"
            );
            assert_eq!(
                sanitize_out_name_for(".Extras\\.readme.txt", win),
                "_Extras/_readme.txt"
            );
            assert_ne!(
                sanitize_out_name_for("a/.b.mkv", win),
                sanitize_out_name_for("a/b.mkv", win),
                "windows={win}"
            );
            // M4-67: no format character reaches a key, flat or in a
            // component. `readme<RLO>gpj.exe` displays as `readmeexe.jpg`.
            let flat = sanitize_out_name_for("readme\u{202e}gpj.exe", win);
            assert_eq!(flat, "readme_gpj.exe");
            let tree = sanitize_out_name_for("Docs\u{200b}/readme\u{202e}gpj.exe", win);
            assert_eq!(tree, "Docs_/readme_gpj.exe");
            for out in [flat, tree] {
                assert!(
                    !out.chars().any(is_format_char_probe),
                    "a format character reached an out-name: {out:?}"
                );
            }
        }
        // An all-dot component is still refused outright rather than
        // becoming "___" - the traversal guard is unmoved by the
        // leading-dot mapping, which runs after it.
        for n in ["a/../b", "a/./b", "a/.../b", "../evil"] {
            assert_eq!(sanitize_relpath_for(n, false), None, "{n:?}");
        }
        // The FLATTEN fallback those shapes fall back to is where the
        // same collapse used to bite hardest: `../evil.bin`, `./evil.bin`
        // and a poster's literal `_evil.bin` were ALL `_evil.bin` before
        // 30 Aug 2026, so a hostile member and an honest one landed on
        // one name. Each maps distinctly now, and none escapes.
        let flat: std::collections::HashSet<String> = ["../evil.bin", "./evil.bin", "_evil.bin"]
            .iter()
            .map(|n| sanitize_out_name_for(n, false))
            .collect();
        assert_eq!(flat.len(), 3, "traversal shapes still collapse: {flat:?}");
        for f in &flat {
            assert!(
                !f.contains('/') && !f.contains('\\'),
                "{f:?} kept a separator"
            );
            assert!(!f.starts_with('.'), "{f:?} landed hidden");
        }
    }

    /// `is_format_char` is private to the parent module and the table is
    /// pinned there (`format_chars_match_the_unicode_category`); this is
    /// only the handful of characters the assertion above needs to look
    /// for, spelled locally so this file does not widen that item's
    /// visibility.
    fn is_format_char_probe(c: char) -> bool {
        matches!(c, '\u{200b}'..='\u{200f}' | '\u{202a}'..='\u{202e}' | '\u{feff}')
    }

    /// M4-104: U+2028/U+2029 are `White_Space`, not Cf, so
    /// `is_format_char` correctly leaves them alone - but that means the
    /// trim removes them at a component's ends and keeps them in the
    /// middle, where a published tree entry renders as two lines. Both
    /// must be mapped, per component, the same way `sanitize_out_name_for`
    /// is already pinned for `is_format_char`'s table just above.
    #[test]
    fn line_and_paragraph_separators_are_mapped_per_component() {
        for win in [false, true] {
            let tree = sanitize_out_name_for("Movie\u{2028}Name/part\u{2029}1.mkv", win);
            assert_eq!(tree, "Movie_Name/part_1.mkv", "windows={win}");
        }
    }

    #[test]
    fn a_disc_tree_is_preserved() {
        assert_eq!(
            sanitize_out_name_for("VIDEO_TS/VTS_01_1.VOB", false),
            "VIDEO_TS/VTS_01_1.VOB"
        );
        // Windows-authored sets spell it with backslashes.
        assert_eq!(
            sanitize_out_name_for("VIDEO_TS\\VTS_01_1.VOB", false),
            "VIDEO_TS/VTS_01_1.VOB"
        );
        assert_eq!(
            sanitize_out_name_for("BDMV/STREAM/00001.m2ts", false),
            "BDMV/STREAM/00001.m2ts"
        );
    }

    /// The whole-name budget's REASON, driven end to end: every name
    /// this module produces has to be reachable by absolute path once
    /// it is written under a full-length job directory.
    ///
    /// The defect this pins was measured on 31 Aug 2026 and is the
    /// opposite of what the caps were written against. Nothing here
    /// fails loudly: [`open_out_leaf_under`] - the door
    /// `disk::FileWriter::create_under` writes every in-stream payload
    /// through - walks with `openat`/`mkdirat`, ONE component per
    /// syscall, so the kernel never sees a path long enough to refuse.
    /// A 998-byte member under an 89-byte root created a file at a
    /// 1088-byte absolute path perfectly happily; `read_dir` then
    /// LISTED it while `open`, `stat`, `rename` and `unlink` on that
    /// path all returned `ENAMETOOLONG`, so the payload could not be
    /// read by the product, imported by anything downstream, or even
    /// deleted by the person who downloaded it.
    ///
    /// So there is no write error to catch on the half that matters,
    /// and a budget on the NAME is the only guard available. That is
    /// what makes the arithmetic below load-bearing rather than
    /// decorative: `MAX_TOTAL` spends half the measured ceiling and
    /// reserves the other half for the root, and this test is the only
    /// thing that checks the reservation is real by taking it.
    ///
    /// Grades the OUTCOME, not the shape: whether a given name comes
    /// back as a tree or flattened is the policy above's business, and
    /// pinning shapes here would make this red for a cap edit that is
    /// perfectly correct. What may never happen is a written file that
    /// cannot be reached.
    ///
    /// APFS-shaped: the ceiling is 1023 bytes there and 4095 on Linux,
    /// so this is a real assertion on the Macs and a free pass on the
    /// CI runners. That is the right way round - the tighter platform
    /// is the one the fleet develops on.
    #[cfg(unix)]
    #[test]
    fn every_output_name_is_reachable_under_a_full_length_root() {
        // A root at exactly the reservation MAX_TOTAL leaves: the
        // budget promises names at the cap survive here, so take the
        // promise rather than testing a comfortable root.
        const ROOT_BUDGET: usize = 511;
        assert_eq!(
            MAX_TOTAL + 1 + ROOT_BUDGET,
            1023,
            "the cap and the root reservation must still sum to the measured \
             APFS ceiling - if MAX_TOTAL moved, say what the new reservation \
             buys before changing this line"
        );
        // RESOLVED, and that is not tidiness: the kernel measures the
        // path it resolves, not the one the caller spells, so an
        // ancestor symlink moves the ceiling under you. This test found
        // that the hard way - `std::env::temp_dir()` is under `/var`,
        // which is a symlink to `/private/var` on macOS, so an absolute
        // path of exactly 1023 bytes was `ENAMETOOLONG` at 1031
        // resolved. Canonicalizing makes the run a statement about the
        // POLICY rather than about where the fixture happened to land.
        //
        // It is also the stated limit of the guarantee `MAX_TOTAL`
        // makes, and the reason no budget can be exact: `resolve_out_root`
        // resolves an output root that IS a link, and deliberately does
        // not resolve links ABOVE it, so a user whose downloads folder
        // sits under a symlinked home has a reservation that many bytes
        // smaller. The remedy for that is a shorter root, and it is not
        // something any cap in this module can compute.
        let base = std::fs::canonicalize(scratch("reachable")).unwrap();
        let mut root = base.clone();
        // Pad to exactly ROOT_BUDGET bytes with legal components.
        while root.as_os_str().len() < ROOT_BUDGET {
            let want = ROOT_BUDGET - root.as_os_str().len() - 1;
            root.push("p".repeat(want.min(MAX_COMPONENT)));
        }
        assert_eq!(root.as_os_str().len(), ROOT_BUDGET, "root padding");
        std::fs::create_dir_all(&root).unwrap();

        let long = "x".repeat(300);
        let at_cap = format!(
            "{}/{}/{}",
            "a".repeat(170),
            "b".repeat(170),
            "c".repeat(169)
        );
        assert_eq!(at_cap.len(), MAX_TOTAL, "the at-the-cap case must be AT it");
        let cases = [
            // The measured incident: many legal components, no single
            // one over the per-component cap.
            (0..5)
                .map(|i| format!("{}{i}", "c".repeat(198)))
                .collect::<Vec<_>>()
                .join("/"),
            // Exactly at the cap, which is the only row that can catch
            // an off-by-one in the reservation.
            at_cap,
            // One byte over it.
            format!(
                "{}/{}/{}",
                "a".repeat(170),
                "b".repeat(170),
                "c".repeat(170)
            ),
            // Long because ONE component is long: capping has a remedy,
            // so this keeps its tree - and must still be reachable.
            format!("a/{}.mkv", "y".repeat(5000)),
            format!("VIDEO_TS/{long}.VOB"),
            // Past every axis at once.
            (0..40)
                .map(|i| format!("{}{i:02}", "d".repeat(200)))
                .collect::<Vec<_>>()
                .join("/"),
            // The ordinary shapes, so a cap edit that breaks them is
            // caught by this test as well as by the corpus above.
            "BDMV/STREAM/00001.m2ts".to_string(),
            "payload.bin".to_string(),
        ];
        for name in &cases {
            let out = sanitize_out_name(name);
            assert!(
                out.len() <= MAX_TOTAL,
                "{} bytes of output is past the budget, so nothing below is a \
                 statement about the root reservation",
                out.len()
            );
            let joined = join_out_name(&root, &out);
            drop(
                open_out_leaf_under(&root, &out, LeafOpen::Truncate)
                    .unwrap_or_else(|e| panic!("writing {} bytes of name failed: {e}", out.len())),
            );
            // THE ASSERTION. The write above cannot make it for us: it
            // reaches the leaf through a directory descriptor, so it
            // succeeds on a path nothing else can name.
            std::fs::metadata(&joined).unwrap_or_else(|e| {
                panic!(
                    "wrote a file nothing can reach: {} bytes of absolute path, {e}",
                    joined.as_os_str().len()
                )
            });
            // And it can be removed again, which is the half a user
            // notices: an unreachable payload cannot be deleted either.
            std::fs::remove_file(&joined).unwrap();
        }
        std::fs::remove_dir_all(&base).ok();
    }

    #[test]
    fn unsafe_paths_flatten_exactly_as_today() {
        for n in [
            "../evil",
            "a/../../evil",
            "a/./b",
            "/abs/path",
            "//server/share/x",
            "\\\\server\\share\\x",
            "C:/evil.dll",
            "C:\\evil.dll",
            "C:evil.dll/x",
            "a//b",
            "a/",
            "/",
            "a/ /b",
            "a/../b",
        ] {
            assert_eq!(sanitize_relpath_for(n, false), None, "{n:?} must flatten");
            assert_eq!(
                sanitize_relpath_for(n, true),
                None,
                "{n:?} must flatten (win)"
            );
            assert_eq!(
                sanitize_out_name_for(n, false),
                sanitize_filename_for(n, false),
                "{n:?} fallback must be byte-identical to today's flat name"
            );
        }
    }

    /// M4-71, first half: does a REAL disc tree hit the caps at all?
    /// Measured 30 Aug 2026 against the DVD-Video and BDMV layouts -
    /// DVD is 2 components deep with a 12-byte longest component,
    /// Blu-ray 4 deep with 16 - against caps of 16 / 255 / 1024. Four
    /// times the depth headroom, sixteen times the component headroom,
    /// thirty-three times the total. The matrix row predicted the caps
    /// flatten a playable disc; they do not, and this pins the
    /// measurement so a future tightening has to argue with the
    /// 29 Aug 2026 ruling in this module's header rather than quietly
    /// undo it.
    #[test]
    fn every_real_disc_tree_path_is_preserved_with_room_to_spare() {
        // The full published layouts, not a sample: the whole point is
        // that the DEEPEST and LONGEST real member still clears.
        let disc = [
            // DVD-Video.
            "VIDEO_TS/VIDEO_TS.IFO",
            "VIDEO_TS/VIDEO_TS.BUP",
            "VIDEO_TS/VIDEO_TS.VOB",
            "VIDEO_TS/VTS_01_0.IFO",
            "VIDEO_TS/VTS_01_1.VOB",
            "AUDIO_TS/AUDIO_TS.IFO",
            // Blu-ray BDMV, including the 4-deep backup and 3D arms
            // that are the deepest anything on a disc goes.
            "BDMV/index.bdmv",
            "BDMV/MovieObject.bdmv",
            "BDMV/PLAYLIST/00000.mpls",
            "BDMV/CLIPINF/00000.clpi",
            "BDMV/STREAM/00000.m2ts",
            "BDMV/STREAM/SSIF/00000.ssif",
            "BDMV/BACKUP/PLAYLIST/00000.mpls",
            "BDMV/BACKUP/CLIPINF/00000.clpi",
            "BDMV/BACKUP/index.bdmv",
            "BDMV/META/DL/bdmt_eng.xml",
            "BDMV/JAR/00000.jar",
            "BDMV/AUXDATA/sound.bdmv",
            "CERTIFICATE/BACKUP/id.bdmv",
            "AACS/Unit_Key_RO.inf",
        ];
        let mut deepest = 0;
        let mut longest = 0;
        let mut widest = 0;
        for path in disc {
            for w in [false, true] {
                assert_eq!(
                    sanitize_out_name_for(path, w),
                    path,
                    "{path:?} must survive intact (windows={w})"
                );
            }
            deepest = deepest.max(path.split('/').count());
            longest = longest.max(path.split('/').map(str::len).max().unwrap_or(0));
            widest = widest.max(path.len());
        }
        // The headroom itself, so a cap edit that keeps every path
        // above passing by ONE byte still has to face this line.
        assert_eq!(deepest, 4, "deepest real disc path, in components");
        assert_eq!(longest, 16, "longest real disc component, in bytes");
        assert_eq!(widest, 31, "longest real disc path, in bytes");
        // 4x, 15x and 16x as measured. Spelled as the multiple rather
        // than as today's constants so a cap edit is scored against the
        // disc and not against itself.
        //
        // The TOTAL multiple was 33x until 31 Aug 2026, when `MAX_TOTAL`
        // went 1024 -> 511. That is not headroom being spent on
        // anything: 1024 was a budget no name could ever use, because
        // the measured ceiling is 1023 bytes and applies to the
        // ABSOLUTE path, so a 1024-byte relative name was over budget
        // under every root that exists. The 511 bytes given up are
        // reserved for the job directory and bought the guarantee in
        // `every_output_name_is_reachable_under_a_full_length_root`.
        // 16x the longest real disc path is still an order of magnitude
        // more than any layout this ruling exists to protect.
        assert!(deepest * 4 <= MAX_DEPTH, "depth headroom shrank");
        assert!(longest * 15 <= MAX_COMPONENT, "component headroom shrank");
        assert!(widest * 16 <= MAX_TOTAL, "total headroom shrank");
    }

    /// M4-71, second half, and the defect that WAS live: when a size
    /// cap bites, the flat fallback is by construction at least as long
    /// as the name that was refused for being too long - so it could
    /// never be written. Measured on APFS: 269, 1034 and 492 bytes,
    /// every one `ENAMETOOLONG`. Every fallback must now be a name the
    /// filesystem will take.
    #[test]
    fn an_over_cap_name_falls_back_to_a_writable_one() {
        let cases = [
            // A component over MAX_COMPONENT. Flattened to 269 bytes
            // until 31 Aug 2026; the tree is KEPT now and the leaf is
            // capped in place, and every assertion below holds either
            // way - which is the point of grading the OUTPUT rather
            // than its shape.
            format!("VIDEO_TS/{}.VOB", "x".repeat(256)),
            // Over MAX_TOTAL in three components. Flattened to 1034.
            format!("a/b/{}", "x".repeat(1030)),
            // Past MAX_DEPTH, deep enough to be over 255 flat too: 492.
            (0..17)
                .map(|i| format!("dir{i:02}_padded_to_thirty_bytes"))
                .collect::<Vec<_>>()
                .join("/"),
            // A name with no separator at all can be overlong too, and
            // it reaches this function by the same door.
            format!("{}.mkv", "y".repeat(400)),
        ];
        let root = scratch("overcap");
        for name in &cases {
            for w in [false, true] {
                let out = sanitize_out_name_for(name, w);
                for c in out.split('/') {
                    assert!(
                        c.len() <= MAX_COMPONENT,
                        "{name:?} -> component {} bytes (windows={w})",
                        c.len()
                    );
                }
            }
            // Not a byte count in the abstract: the filesystem takes it.
            let out = sanitize_out_name_for(name, false);
            let path = prepare_out_path(&root, &out).unwrap();
            std::fs::write(&path, b"x")
                .unwrap_or_else(|e| panic!("{name:?} -> {out:?} is unwritable: {e}"));
            // Deterministic: it is a comparison key, and every consumer
            // recomputes it from the same input.
            assert_eq!(out, sanitize_out_name_for(name, false), "{name:?}");
        }
        // The extension survives, so routing still reads a payload.
        assert!(
            sanitize_out_name_for(&cases[0], false).ends_with(".VOB"),
            "the extension was dropped"
        );
        // Two different overlong names must not collapse onto one file.
        let a = sanitize_out_name_for(&format!("d/{}a.VOB", "x".repeat(300)), false);
        let b = sanitize_out_name_for(&format!("d/{}b.VOB", "x".repeat(300)), false);
        assert_ne!(a, b, "two overlong names collided on one output name");
        std::fs::remove_dir_all(&root).ok();
    }

    /// The quieter half of the same defect: `sanitize_filename_for`
    /// GROWS a reserved DOS stem by one byte, so a component measured
    /// at exactly MAX_COMPONENT came back at 256 and rode into a
    /// PRESERVED tree - past the cap the loop had just enforced.
    #[test]
    fn a_reserved_stem_cannot_grow_a_component_past_the_cap() {
        // The reserved check reads the stem before the FIRST dot, so
        // `CONxxx...` is an ordinary name and does not grow - only a
        // bare reserved stem with the length in its extension does.
        // (Written the other way first, and it passed against the
        // unpatched tree for that reason.)
        let comp = format!("CON.{}", "x".repeat(MAX_COMPONENT - 4));
        assert_eq!(comp.len(), MAX_COMPONENT);
        assert_eq!(
            sanitize_filename_for(&comp, false).len(),
            MAX_COMPONENT + 1,
            "this shape must be the one that grows, or the test proves nothing"
        );
        let name = format!("dir/{comp}");
        for w in [false, true] {
            let out = sanitize_out_name_for(&name, w);
            for c in out.split('/') {
                assert!(c.len() <= MAX_COMPONENT, "{} bytes (windows={w})", c.len());
            }
        }
        // Still a preserved tree, not flattened by the fix.
        assert!(sanitize_out_name_for(&name, false).contains('/'));
    }

    #[test]
    fn caps_flatten_rather_than_truncate() {
        // WHAT CHANGED, 31 Aug 2026: this pinned all THREE caps as
        // refusals. MAX_COMPONENT is now a CAP applied in place and the
        // tree survives it, so its arm below asserts the opposite of
        // what it used to. The other two still refuse. Which cap
        // answers which way, and why the three are not one policy, is
        // on `sanitize_relpath_for`; the short version is that only the
        // component cap has an in-place remedy, and throwing a playable
        // disc's whole layout away to shorten one leaf was the defect.
        let deep = (0..17).map(|_| "d").collect::<Vec<_>>().join("/");
        assert_eq!(sanitize_relpath_for(&deep, false), None);
        let sixteen = (0..16).map(|_| "d").collect::<Vec<_>>().join("/");
        assert!(sanitize_relpath_for(&sixteen, false).is_some());
        // WHAT CHANGED AGAIN, 31 Aug 2026, second ruling: the TOTAL cap
        // is asked of the OUTPUT rather than of the raw name, which is
        // the component ruling above applied to this axis - refuse only
        // when capping did not fix it. So the two halves of "too long"
        // part company here, and both directions are pinned:
        //
        //  * long because MANY components: no per-component shortening
        //    reaches it, so it still refuses and the caller flattens.
        //  * long because ONE component is long: `cap_component` has a
        //    remedy, the leaf is shortened in place and the TREE
        //    SURVIVES. Written `a/<1024 bytes>` and asserted `None`
        //    until that day - the same name that pinned the leaf-only
        //    reading of the component cap as a defect one ruling
        //    earlier.
        //
        // The number moved with it, 1024 -> 511, because 1024 was a
        // budget no name could use: the measured ceiling is 1023 bytes
        // of ABSOLUTE path, so a 1024-byte relative name was over
        // budget under every root that exists. See `MAX_TOTAL`.
        let many = (0..3)
            .map(|_| "x".repeat(200))
            .collect::<Vec<_>>()
            .join("/");
        assert!(many.len() > MAX_TOTAL, "{} bytes", many.len());
        assert!(many.split('/').all(|c| c.len() <= MAX_COMPONENT));
        assert_eq!(sanitize_relpath_for(&many, false), None);
        let long_total = format!("a/{}", "x".repeat(1024));
        let capped = sanitize_relpath_for(&long_total, false)
            .expect("one long component has a remedy, so the tree survives");
        assert_eq!(capped.split('/').count(), 2, "{capped:?}");
        assert!(capped.len() <= MAX_TOTAL, "{} bytes", capped.len());

        // The component cap: kept as a TREE, capped in place, and the
        // OTHER component is untouched - which is the whole point, and
        // is what a flatten could never give back.
        let long_comp = format!("VIDEO_TS/{}.VOB", "x".repeat(256));
        let out = sanitize_relpath_for(&long_comp, false).expect("the tree must survive the cap");
        let comps: Vec<&str> = out.split('/').collect();
        assert_eq!(comps.len(), 2, "{out:?}");
        assert_eq!(comps[0], "VIDEO_TS", "the untouched component moved");
        assert_eq!(comps[1].len(), MAX_COMPONENT, "the leaf was not capped");
        assert!(comps[1].ends_with(".VOB"), "the extension was dropped");

        // And the asymmetry this closed, stated from both ends in one
        // place: a component that was ALREADY over the cap and one that
        // GREW past it while being sanitized now get the same answer.
        // They did not before, and nothing could defend the difference.
        let grew = format!("VIDEO_TS/CON.{}", "x".repeat(MAX_COMPONENT - 4));
        assert!(
            sanitize_relpath_for(&grew, false).is_some_and(|p| p.contains('/')),
            "the growth case must still keep its tree"
        );
    }

    /// The component cap keeps a tree, so the invariant every consumer
    /// leans on has to be asserted UNCONDITIONALLY rather than inferred
    /// from the refusal that used to stand in front of it: whatever
    /// comes back - preserved or flattened - no component is over
    /// MAX_COMPONENT, so `create_dir_all` and `File::create` take it.
    ///
    /// The corpus is the shapes that reach the cap by different doors:
    /// a leaf over it, a leaf that grows over it, a MIDDLE component
    /// over it (the one an "only the leaf matters" reading would miss),
    /// several at once, and a name that is over on two axes so the
    /// refusing caps have to win.
    #[test]
    fn no_component_of_any_output_can_exceed_the_cap() {
        let long = "x".repeat(300);
        let cases = [
            format!("VIDEO_TS/{long}.VOB"),
            format!("VIDEO_TS/CON.{}", "x".repeat(MAX_COMPONENT - 4)),
            format!("{long}/leaf.bin"),
            format!("{long}/{long}/{long}"),
            format!("BDMV/STREAM/{long}.m2ts"),
            // Over MAX_TOTAL as well: the refusing cap decides, and the
            // flat fallback is still capped.
            format!("a/{}/{}", "y".repeat(600), "z".repeat(600)),
        ];
        let root = scratch("everycomponentcapped");
        for name in &cases {
            for w in [false, true] {
                let out = sanitize_out_name_for(name, w);
                assert!(!out.is_empty(), "{name:?} produced no name");
                for c in out.split('/') {
                    assert!(
                        c.len() <= MAX_COMPONENT,
                        "{name:?} -> component {} bytes (windows={w})",
                        c.len()
                    );
                }
            }
            // Idempotent, which the journal depends on by construction:
            // it WRITES an already-sanitized name into its `S` records
            // and runs `sanitize_out_name` over it again on load.
            let out = sanitize_out_name_for(name, false);
            assert_eq!(
                out,
                sanitize_out_name_for(&out, false),
                "{name:?} is not idempotent, so a reloaded journal record moves"
            );
            // Not a byte count in the abstract: the filesystem takes it.
            let path = prepare_out_path(&root, &out).unwrap();
            std::fs::write(&path, b"x")
                .unwrap_or_else(|e| panic!("{name:?} -> {out:?} is unwritable: {e}"));
        }
        // Distinct per input, so two overlong members inside one tree do
        // not collapse onto one file and race on the pool.
        assert_ne!(
            sanitize_out_name_for(&format!("d/{long}a.VOB"), false),
            sanitize_out_name_for(&format!("d/{long}b.VOB"), false)
        );
        std::fs::remove_dir_all(&root).ok();
    }

    #[test]
    fn components_go_through_the_per_component_rules() {
        // Reserved DOS device stems are prefixed per component.
        assert_eq!(sanitize_out_name_for("CON/aux.txt", false), "_CON/_aux.txt");
        // Control characters are mapped inside components.
        assert_eq!(sanitize_out_name_for("a\u{7}b/c.txt", false), "a_b/c.txt");
        // ':' maps on Windows only ("sub/C:evil.dll" cannot escape via a
        // LATER component's drive prefix), stays on unix.
        assert_eq!(
            sanitize_out_name_for("sub/C:evil.dll", true),
            "sub/C_evil.dll"
        );
        assert_eq!(
            sanitize_out_name_for("sub/Movie: 2.mkv", false),
            "sub/Movie: 2.mkv"
        );
        // Trailing dots/spaces trimmed per component; an all-dot
        // component ("...") flattens rather than becoming "unnamed".
        assert_eq!(
            sanitize_out_name_for("dir./file.txt ", false),
            "dir/file.txt"
        );
        assert_eq!(
            sanitize_relpath_for(".../file.txt", false),
            None,
            "an all-dot component is nobody's directory"
        );
    }

    #[test]
    fn join_and_inverse_round_trip() {
        let root = Path::new("/srv/dl/job");
        let name = "VIDEO_TS/VTS_01_1.VOB";
        let p = join_out_name(root, name);
        assert_eq!(p, root.join("VIDEO_TS").join("VTS_01_1.VOB"));
        assert!(p.starts_with(root), "join must stay contained");
        assert_eq!(out_name_of(root, &p), name);
        // Flat names round-trip too.
        assert_eq!(out_name_of(root, &join_out_name(root, "a.bin")), "a.bin");
        // A path outside the root falls back to the bare file name.
        assert_eq!(out_name_of(root, Path::new("/tmp/x/y.bin")), "y.bin");
    }

    #[test]
    fn every_preserved_path_stays_under_the_root() {
        // Adversarial corpus: whatever comes back - preserved or
        // flattened - the join may never leave the root.
        //
        // HOST flavor, not a pinned `windows: false`: the join below
        // runs with the host's own path semantics, and that pairing is
        // the only one the product ever ships (`sanitize_out_name` is
        // cfg-matched). Pinning false held windows-unit red on main,
        // 30 Aug 2026: the unix flat form of "C:\\Windows\\..." keeps
        // its ':' (legal in a unix file name), Windows reads "C:..."
        // as a drive-relative PREFIX, and `Path::join` then discards
        // the root - a containment failure in a configuration that
        // cannot occur.
        let root = Path::new("/srv/dl/job");
        for s in [
            "../../etc/passwd",
            "..\\..\\evil.dll",
            "a/../../../x",
            "/etc/passwd",
            "C:\\Windows\\System32\\evil.dll",
            "\\\\?\\C:\\x",
            "a/b/../c",
            "ok/fine.bin",
            "..",
            ". ./x",
        ] {
            let out = sanitize_out_name(s);
            let joined = join_out_name(root, &out);
            assert!(
                joined.starts_with(root) && joined != root,
                "{s:?} -> {out:?} escaped as {joined:?}"
            );
            assert!(
                !joined
                    .components()
                    .any(|c| matches!(c, std::path::Component::ParentDir)),
                "{s:?} -> {joined:?} kept a ParentDir"
            );
        }
    }

    #[test]
    fn create_out_dirs_builds_the_tree_and_refuses_symlinks() {
        let root = std::env::temp_dir().join(format!("nzbfast-relpath-{}", std::process::id()));
        std::fs::create_dir_all(&root).unwrap();
        // Flat name: nothing to create, nothing to fail.
        create_out_dirs(&root, "plain.bin").unwrap();
        // Tree: parents appear, twice is idempotent.
        let p = prepare_out_path(&root, "VIDEO_TS/sub/VTS_01_1.VOB").unwrap();
        assert!(root.join("VIDEO_TS").join("sub").is_dir());
        assert_eq!(p, root.join("VIDEO_TS").join("sub").join("VTS_01_1.VOB"));
        create_out_dirs(&root, "VIDEO_TS/sub/other.bin").unwrap();
        // A FILE where a directory component should go: refused.
        std::fs::write(root.join("afile"), b"x").unwrap();
        assert!(create_out_dirs(&root, "afile/x.bin").is_err());
        #[cfg(unix)]
        {
            // A symlink planted in the job dir must not be followed,
            // even when it points back inside the tree.
            std::os::unix::fs::symlink(root.join("VIDEO_TS"), root.join("link")).unwrap();
            let e = create_out_dirs(&root, "link/evil.bin").unwrap_err();
            assert!(
                e.to_string().contains("not a real directory"),
                "unexpected error: {e}"
            );
        }
        std::fs::remove_dir_all(&root).ok();
    }

    /// A scratch root that cleans itself up, so a failing assertion
    /// below cannot leave a symlink pointing at somebody's temp dir.
    fn scratch(tag: &str) -> PathBuf {
        let root = std::env::temp_dir().join(format!(
            "nzbfast-leafopen-{tag}-{}-{:?}",
            std::process::id(),
            std::thread::current().id()
        ));
        std::fs::remove_dir_all(&root).ok();
        std::fs::create_dir_all(&root).unwrap();
        root
    }

    #[test]
    fn open_out_leaf_creates_truncates_resumes_and_refuses_a_taken_name() {
        use std::io::{Read as _, Seek as _, Write as _};
        let root = scratch("modes");
        let p = root.join("payload.bin");

        // Truncate: creates, then empties what is there.
        let mut f = open_out_leaf(&p, LeafOpen::Truncate).unwrap();
        f.write_all(b"0123456789").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap().len(), 10);
        let f = open_out_leaf(&p, LeafOpen::Truncate).unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap().len(), 0, "Truncate must empty");

        // Keep: the resume open leaves the bytes alone, and the handle
        // is readable and writable at an offset.
        std::fs::write(&p, b"already here").unwrap();
        let mut f = open_out_leaf(&p, LeafOpen::Keep).unwrap();
        let mut got = String::new();
        f.read_to_string(&mut got).unwrap();
        assert_eq!(got, "already here", "Keep must not truncate");
        f.rewind().unwrap();
        f.write_all(b"A").unwrap();
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), b"Already here");

        // CreateNew: refuses a name already taken, rather than
        // truncating it - the X5-19 rule.
        let e = open_out_leaf(&p, LeafOpen::CreateNew).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::AlreadyExists, "{e}");
        assert_eq!(
            std::fs::read(&p).unwrap(),
            b"Already here",
            "a refused CreateNew must leave the bytes alone"
        );
        let fresh = root.join("fresh.bin");
        drop(open_out_leaf(&fresh, LeafOpen::CreateNew).unwrap());
        assert!(fresh.is_file());

        std::fs::remove_dir_all(&root).ok();
    }

    /// `Existing` is the REOPEN mode and the only one that does not
    /// create. The case it exists for is the one the other three get
    /// wrong: a file that has GONE. `Keep` answers that by making an
    /// empty one, and `FileWriter::unpark` would then hand a caller
    /// zero bytes it believes are the external par2's repaired output
    /// (X5-06/08/19 OWED item 6).
    #[test]
    fn open_out_leaf_existing_reopens_and_never_creates() {
        use std::io::Read as _;
        let root = scratch("existing");
        let p = root.join("payload.bin");

        // A name with nothing at it is NotFound, and stays empty.
        let e = open_out_leaf(&p, LeafOpen::Existing).unwrap_err();
        assert_eq!(e.kind(), io::ErrorKind::NotFound, "{e}");
        assert!(!p.exists(), "Existing must not create the file it refused");

        // And an existing one keeps every byte: this is a reopen, and
        // a truncate here would discard a repair.
        std::fs::write(&p, b"repaired bytes").unwrap();
        let mut f = open_out_leaf(&p, LeafOpen::Existing).unwrap();
        let mut got = String::new();
        f.read_to_string(&mut got).unwrap();
        assert_eq!(got, "repaired bytes");
        drop(f);
        assert_eq!(std::fs::read(&p).unwrap(), b"repaired bytes");

        std::fs::remove_dir_all(&root).ok();
    }

    /// The three confirmed defects this mechanism exists for, at the
    /// level they live at (the e2e probes assert the same three through
    /// `FileWriter`). Every arm plants an alias and asserts the OUTSIDE
    /// inode is untouched - the refusal is the point, not the error
    /// string.
    #[cfg(unix)]
    #[test]
    fn open_out_leaf_refuses_a_planted_leaf_and_a_swapped_parent() {
        const SENTINEL: &[u8] = b"nothing in the job may touch this inode\n";
        let root = scratch("aliases");
        let out = root.join("out");
        let outside = root.join("outside");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        // X5-06, fresh arm: a symlink at the payload's own name.
        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, SENTINEL).unwrap();
        let leaf = out.join("payload.bin");
        std::os::unix::fs::symlink(&sentinel, &leaf).unwrap();
        assert!(open_out_leaf(&leaf, LeafOpen::Truncate).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), SENTINEL);

        // X5-06, resume arm: the non-truncating open follows it too.
        assert!(open_out_leaf(&leaf, LeafOpen::Keep).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), SENTINEL);
        // And CreateNew, which would otherwise report AlreadyExists for
        // the LINK while naming the target.
        assert!(open_out_leaf(&leaf, LeafOpen::CreateNew).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), SENTINEL);
        // And `Existing`, the reopen mode: X5-06/08/19 OWED item 6 is
        // `FileWriter::unpark` coming back to a name after par2 has
        // been renaming inodes around, so the alias it must refuse is
        // one that appeared while the writer was parked.
        assert!(open_out_leaf(&leaf, LeafOpen::Existing).is_err());
        assert_eq!(std::fs::read(&sentinel).unwrap(), SENTINEL);
        std::fs::remove_file(&leaf).unwrap();

        // X5-08: the parent checked is not the parent used. `safe/` is
        // validated as a real directory, then swapped for a symlink.
        let target = prepare_out_path(&out, "safe/payload.bin").unwrap();
        let elsewhere = outside.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::remove_dir(out.join("safe")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("safe")).unwrap();
        let e = open_out_leaf(&target, LeafOpen::Truncate).unwrap_err();
        assert!(
            e.to_string().contains("not a real directory"),
            "unexpected error: {e}"
        );
        assert!(
            !elsewhere.join("payload.bin").exists(),
            "the write followed a parent swapped after validation"
        );

        std::fs::remove_dir_all(&root).ok();
    }

    /// The WINDOWS half of the test above, which that one cannot cover:
    /// its aliases are `std::os::unix::fs::symlink`, and until 31 Aug
    /// 2026 the Windows arm of this mechanism had never been executed
    /// anywhere - it was compile-verified only.
    ///
    /// ATTEMPT-AND-SKIP rather than an unconditional lift, and the
    /// reason is a real one rather than caution: planting a symlink
    /// needs SeCreateSymbolicLinkPrivilege (an administrator, or
    /// Developer Mode), which nothing here can promise about a runner.
    /// An unconditional lift would redden `windows-unit` for an
    /// environmental reason instead of a real one. The skip PRINTS, so
    /// an arm that has quietly stopped running shows in the log rather
    /// than reading as a pass.
    #[cfg(windows)]
    #[test]
    fn open_out_leaf_refuses_a_planted_leaf_on_windows_too() {
        const SENTINEL: &[u8] = b"nothing in the job may touch this inode\n";
        let root = scratch("aliases-win");
        let out = root.join("out");
        let outside = root.join("outside");
        std::fs::create_dir_all(&out).unwrap();
        std::fs::create_dir_all(&outside).unwrap();

        let sentinel = outside.join("sentinel.bin");
        std::fs::write(&sentinel, SENTINEL).unwrap();
        let leaf = out.join("payload.bin");
        if let Err(e) = std::os::windows::fs::symlink_file(&sentinel, &leaf) {
            eprintln!(
                "[relpath] SKIPPED the planted-leaf arm: this box cannot create \
                 a symlink ({e}). It needs SeCreateSymbolicLinkPrivilege."
            );
            std::fs::remove_dir_all(&root).ok();
            return;
        }

        // All three modes, and the assertion is the OUTSIDE inode rather
        // than the error string. Measured on a real box before this
        // landed: with the old open, Truncate took the sentinel to zero
        // bytes and a dangling link CREATED its target.
        // Every variant of the enum the refusal guards, `Existing`
        // included: it arrived later (754615992, the post-repair
        // reopen) and inherits the refusal only because the flag is
        // set before the mode match - which is worth a case rather
        // than a reading.
        for mode in [
            LeafOpen::Truncate,
            LeafOpen::Keep,
            LeafOpen::CreateNew,
            LeafOpen::Existing,
        ] {
            assert!(
                open_out_leaf(&leaf, mode).is_err(),
                "{mode:?} opened a planted symlink"
            );
            assert_eq!(
                std::fs::read(&sentinel).unwrap(),
                SENTINEL,
                "{mode:?} wrote through the link to the outside inode"
            );
        }
        std::fs::remove_file(&leaf).unwrap();

        // A DANGLING link is the X5-08 shape: there is no target, so a
        // following open CREATES one outside the job directory.
        let never = outside.join("never-existed.bin");
        std::fs::remove_file(&never).ok();
        if std::os::windows::fs::symlink_file(&never, &leaf).is_ok() {
            assert!(open_out_leaf(&leaf, LeafOpen::Truncate).is_err());
            assert!(
                !never.exists(),
                "a dangling link was followed and created a file outside the job"
            );
        }

        // A JUNCTION needs no privilege at all and is the other
        // REDIRECTING tag, so it is refused for the same reason.
        let junc = out.join("junction.bin");
        let elsewhere = outside.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        if std::os::windows::fs::symlink_dir(&elsewhere, &junc).is_ok() {
            assert!(open_out_leaf(&junc, LeafOpen::Truncate).is_err());
        }

        // X5-08 ON THIS PLATFORM, which is the arm that did not exist
        // until the parent was bound: `safe/` is validated as a real
        // directory and then swapped for a link. Before 31 Aug 2026 the
        // parent check was a `symlink_metadata` by NAME, so this arm
        // caught the STATIC case and nothing caught the racing one;
        // `open_dir_nofollow` now judges the HANDLE, and
        // `relpath/winbind.rs` carries the case that a link arriving
        // AFTER the bind cannot reach the write at all.
        let target = prepare_out_path(&out, "safe/payload.bin").unwrap();
        let swapped = outside.join("swapped");
        std::fs::create_dir_all(&swapped).unwrap();
        std::fs::remove_dir(out.join("safe")).unwrap();
        if std::os::windows::fs::symlink_dir(&swapped, out.join("safe")).is_ok() {
            let e = open_out_leaf(&target, LeafOpen::Truncate).unwrap_err();
            assert!(
                e.to_string().contains("not a real directory"),
                "unexpected error: {e}"
            );
            assert!(
                !swapped.join("payload.bin").exists(),
                "the write followed a parent swapped after validation"
            );
            std::fs::remove_file(out.join("safe")).ok();
        }

        std::fs::remove_dir_all(&root).ok();
    }

    /// PIN THE PLATFORM FACT THE WINDOWS REFUSAL RESTS ON, because
    /// nothing else can: in the ordinary non-racing case the
    /// `symlink_metadata` arm fires FIRST, so a black-box test of
    /// `open_out_leaf` passes just as well with the flag deleted. This
    /// asks the question the flag exists to answer, directly - drop
    /// `FILE_FLAG_OPEN_REPARSE_POINT` from the open above and this goes
    /// red, which is the only thing standing between a silently
    /// reopened window and a green suite.
    ///
    /// It also pins the DISCRIMINATION. `is_symlink()` is std reading
    /// the handle's reparse TAG, so it is true for the two redirecting
    /// tags and false for a plain file - which is what keeps a OneDrive
    /// placeholder or a dedup stub (reparse points carrying neither
    /// tag) writable. A hardlink is checked here for the same reason:
    /// it is not a reparse point at all and must never be refused,
    /// matching what `O_NOFOLLOW` does on unix.
    #[cfg(windows)]
    #[test]
    fn the_reparse_flag_binds_the_handle_to_the_link_and_not_its_target() {
        use std::fs::OpenOptions;
        use std::os::windows::fs::OpenOptionsExt as _;
        const FILE_FLAG_OPEN_REPARSE_POINT: u32 = 0x0020_0000;

        let root = scratch("reparse-flag");
        let target = root.join("target.bin");
        std::fs::write(&target, b"outside-payload").unwrap();
        let link = root.join("link.bin");
        if std::os::windows::fs::symlink_file(&target, &link).is_err() {
            eprintln!("[relpath] SKIPPED the flag pin: no symlink privilege on this box.");
            std::fs::remove_dir_all(&root).ok();
            return;
        }

        // WITH the flag: the handle is the link itself.
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
            .open(&link)
            .unwrap();
        assert!(
            f.metadata().unwrap().file_type().is_symlink(),
            "the reparse flag did not bind the handle to the link"
        );
        drop(f);

        // WITHOUT it: the same open resolves THROUGH to the target, and
        // that is precisely the hole - the handle looks like an
        // ordinary file because it is somebody else's ordinary file.
        let f = OpenOptions::new()
            .read(true)
            .write(true)
            .open(&link)
            .unwrap();
        assert!(
            !f.metadata().unwrap().file_type().is_symlink(),
            "an unflagged open stopped following the link - re-derive this arm"
        );
        drop(f);

        // A hardlink is not a reparse point and must stay writable.
        let hard = root.join("hard.bin");
        if std::fs::hard_link(&target, &hard).is_ok() {
            let f = OpenOptions::new()
                .read(true)
                .write(true)
                .custom_flags(FILE_FLAG_OPEN_REPARSE_POINT)
                .open(&hard)
                .unwrap();
            assert!(
                !f.metadata().unwrap().file_type().is_symlink(),
                "a hardlink must not read as a redirecting reparse point"
            );
            drop(f);
            drop(open_out_leaf(&hard, LeafOpen::Keep).unwrap());
        }

        std::fs::remove_dir_all(&root).ok();
    }

    /// A symlink ABOVE the parent is followed exactly as before - only
    /// the FINAL component is judged. This is not a detail: on macOS
    /// every temp path runs through `/var` -> `/private/var`, so a rule
    /// that refused an ancestor link would refuse the whole suite.
    #[cfg(unix)]
    #[test]
    fn a_symlink_above_the_parent_is_still_followed() {
        let root = scratch("ancestor");
        let real = root.join("real");
        std::fs::create_dir_all(real.join("job")).unwrap();
        std::os::unix::fs::symlink(&real, root.join("link")).unwrap();

        // .../link/job/payload.bin - `link` is a symlink, `job` (the
        // parent) is not.
        let p = root.join("link").join("job").join("payload.bin");
        drop(open_out_leaf(&p, LeafOpen::Truncate).unwrap());
        assert!(real.join("job").join("payload.bin").is_file());

        std::fs::remove_dir_all(&root).ok();
    }

    /// A bare relative name resolves against the current directory,
    /// exactly as the plain `OpenOptions::open` it replaced did - an
    /// EMPTY parent is "here", not "no parent".
    #[test]
    fn a_bare_relative_name_still_opens_in_the_current_directory() {
        let root = scratch("relative");
        let leaf = format!("bare-{}.bin", std::process::id());
        // Not a `set_current_dir` (process-global, and the suite runs
        // many tests in one process): ask about the parent directly.
        let p = PathBuf::from(&leaf);
        assert_eq!(p.parent().map(Path::to_path_buf), Some(PathBuf::new()));
        let here = root.join(&leaf);
        drop(open_out_leaf(&here, LeafOpen::Truncate).unwrap());
        assert!(here.is_file());
        std::fs::remove_dir_all(&root).ok();
    }

    /// A path that names no file at all is refused rather than being
    /// silently opened as something else.
    ///
    /// "a/" is deliberately NOT in this list: `Path::file_name` strips
    /// a trailing separator, so it reaches here as the ordinary leaf
    /// "a" and is created - which is `Path`'s own normalisation, not a
    /// judgement this function makes. It is safe either way (the leaf
    /// is still no-follow inside the checked parent); it is called out
    /// so the next reader does not add the case and then "fix" the
    /// function to match.
    #[test]
    fn a_path_that_names_no_file_is_refused() {
        for p in ["/", ".."] {
            assert!(
                open_out_leaf(Path::new(p), LeafOpen::Truncate).is_err(),
                "{p:?} must be refused"
            );
        }
        assert_eq!(Path::new("a/").file_name(), Some(std::ffi::OsStr::new("a")));
    }

    // ------------------------------------------- resolve_out_root

    /// The property everything else rests on: a root that is an
    /// ORDINARY DIRECTORY comes back byte-identical. That is every
    /// install and every test, so this function moves no path anybody
    /// sees - including on Windows, where a resolved path would
    /// otherwise arrive in the `\\?\` verbatim form.
    ///
    /// It holds even when an ANCESTOR is a link, which is the module's
    /// stated hold-out and is not hypothetical: on macOS every temp
    /// path runs through `/var` -> `/private/var`, so a resolver that
    /// judged more than the final component would rewrite the whole
    /// suite's paths.
    #[test]
    fn an_ordinary_root_is_handed_back_unchanged() {
        let root = scratch("resolveplain");
        let job = root.join("job");
        std::fs::create_dir_all(&job).unwrap();
        assert_eq!(resolve_out_root(&job), job);
        // A missing directory has no link to resolve either.
        let missing = root.join("not-there");
        assert_eq!(resolve_out_root(&missing), missing);
        std::fs::remove_dir_all(&root).ok();
    }

    /// A LINKED root resolves, and the point of resolving it is that
    /// the flat-name write under it then works: `open_out_leaf` refuses
    /// a symlink parent, and for a flat name that parent IS the output
    /// root. Both halves are asserted, because the resolution on its
    /// own would be a rewrite with no reason.
    #[cfg(unix)]
    #[test]
    fn a_linked_root_resolves_and_the_write_under_it_then_succeeds() {
        let root = scratch("resolvelink");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // Unresolved: this is exactly the regression - a flat payload
        // name under a symlinked --out is refused.
        assert!(open_out_leaf(&link.join("payload.bin"), LeafOpen::Truncate).is_err());

        let resolved = resolve_out_root(&link);
        assert_eq!(resolved, std::fs::canonicalize(&real).unwrap());
        drop(open_out_leaf(&resolved.join("payload.bin"), LeafOpen::Truncate).unwrap());
        assert!(real.join("payload.bin").is_file());
        std::fs::remove_dir_all(&root).ok();
    }

    /// A CHAIN of links resolves the whole way, not one hop - a
    /// one-hop `read_link` would hand back a path that is still a link
    /// and still refused at the write.
    #[cfg(unix)]
    #[test]
    fn a_chain_of_links_resolves_the_whole_way() {
        let root = scratch("resolvechain");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        std::os::unix::fs::symlink(&real, root.join("mid")).unwrap();
        std::os::unix::fs::symlink(root.join("mid"), root.join("top")).unwrap();

        let resolved = resolve_out_root(&root.join("top"));
        assert_eq!(resolved, std::fs::canonicalize(&real).unwrap());
        assert!(!std::fs::symlink_metadata(&resolved).unwrap().is_symlink());
        std::fs::remove_dir_all(&root).ok();
    }

    /// A DANGLING link is handed back unchanged rather than guessed at:
    /// there is no target to resolve to, and whatever fails on it fails
    /// exactly as it failed before this function existed.
    #[cfg(unix)]
    #[test]
    fn a_dangling_link_is_handed_back_unchanged() {
        let root = scratch("resolvedangling");
        let link = root.join("link");
        std::os::unix::fs::symlink(root.join("nothing-here"), &link).unwrap();
        assert_eq!(resolve_out_root(&link), link);
        std::fs::remove_dir_all(&root).ok();
    }

    // ---------------------------------------- the root-anchored chain

    /// THE RESIDUE X5-06/08/19 LEFT OPEN. `open_out_leaf` binds the
    /// leaf and its IMMEDIATE PARENT, so `out/a/b/leaf.bin` with `a`
    /// swapped for a link between the directories being made and the
    /// write is still followed - a name may carry up to `MAX_DEPTH`
    /// components, and `BDMV/STREAM/00001.m2ts` is exactly this shape.
    /// `open_out_leaf_under` walks from the root, so there is no
    /// component with an unresolved step in front of it.
    ///
    /// Both halves are asserted: the OLD door still walks through (so
    /// this test cannot pass because the swap failed to take), and the
    /// new one refuses.
    #[cfg(unix)]
    #[test]
    fn open_out_leaf_under_refuses_a_swapped_ancestor() {
        let root = scratch("ancestorswap");
        let out = root.join("out");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(&out).unwrap();

        // Check: a/b/ is created and validated.
        let target = prepare_out_path(&out, "a/b/leaf.bin").unwrap();
        // The swap, two levels above the leaf.
        std::fs::remove_dir(out.join("a").join("b")).unwrap();
        std::fs::remove_dir(out.join("a")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("a")).unwrap();
        std::fs::create_dir_all(elsewhere.join("b")).unwrap();

        // The path-only door follows it - this is the defect, and it is
        // asserted so the refusal below cannot read as a no-op.
        drop(open_out_leaf(&target, LeafOpen::Truncate).unwrap());
        assert!(elsewhere.join("b").join("leaf.bin").is_file());
        std::fs::remove_file(elsewhere.join("b").join("leaf.bin")).unwrap();

        // The root-anchored door does not.
        let e = open_out_leaf_under(&out, "a/b/leaf.bin", LeafOpen::Truncate).unwrap_err();
        assert!(
            e.to_string().contains("not a real directory"),
            "unexpected error: {e}"
        );
        assert!(
            !elsewhere.join("b").join("leaf.bin").exists(),
            "the write escaped through a swapped ancestor"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// THE RACING WINDOW (31 Aug 2026 residue item 3). Every test above
    /// plants its swap BEFORE calling the door, which only proves a swap
    /// that predates the walk is refused - it says nothing about the
    /// window between the walk validating a component and the leaf being
    /// opened inside it. This uses [`after_walk`] to swap `out/a` for a
    /// symlink to `elsewhere` the instant `walk_out_dirs` has already
    /// bound it - i.e. after the check, before the write - and confirms
    /// the payload still lands in the directory the walk actually
    /// opened (renamed to `a-real` so it stays reachable to check),
    /// never through the name a path-re-resolving door would have
    /// followed instead.
    #[cfg(unix)]
    #[test]
    fn racing_the_leaf_open_against_a_swapped_bound_directory() {
        let root = scratch("racewindow");
        let out = root.join("out");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(out.join("a")).unwrap();

        let out2 = out.clone();
        let elsewhere2 = elsewhere.clone();
        let _guard = after_walk(move || {
            // Fires with `a` already bound by `walk_out_dirs` and no
            // leaf opened yet. Renaming the real directory (rather than
            // deleting it) keeps it reachable under a new name so the
            // test can see where the write actually went.
            std::fs::rename(out2.join("a"), out2.join("a-real")).unwrap();
            std::os::unix::fs::symlink(&elsewhere2, out2.join("a")).unwrap();
        });

        drop(open_out_leaf_under(&out, "a/leaf.bin", LeafOpen::Truncate).unwrap());

        assert!(
            out.join("a-real").join("leaf.bin").is_file(),
            "the write did not land in the directory the walk actually bound"
        );
        assert!(
            !elsewhere.join("leaf.bin").exists(),
            "the write followed the swapped name instead of the bound descriptor"
        );
        std::fs::remove_dir_all(&root).ok();
    }

    /// The root-anchored door keeps every refusal the path-only one
    /// makes BELOW the root - a planted leaf alias and a swapped
    /// immediate parent - so nothing was traded away for the ancestor
    /// coverage above.
    #[cfg(unix)]
    #[test]
    fn open_out_leaf_under_keeps_the_leaf_and_parent_refusals() {
        let root = scratch("underparity");
        let out = root.join("out");
        let outside = root.join("outside");
        std::fs::create_dir_all(&outside).unwrap();
        std::fs::create_dir_all(&out).unwrap();

        // A planted alias at the payload's own name.
        std::fs::write(outside.join("sentinel.bin"), b"keep me").unwrap();
        std::os::unix::fs::symlink(outside.join("sentinel.bin"), out.join("payload.bin")).unwrap();
        let e = open_out_leaf_under(&out, "payload.bin", LeafOpen::Truncate).unwrap_err();
        assert!(e.to_string().contains("an alias is in the way"), "{e}");
        assert_eq!(
            std::fs::read(outside.join("sentinel.bin")).unwrap(),
            b"keep me"
        );

        // A swapped immediate parent.
        prepare_out_path(&out, "safe/x.bin").unwrap();
        std::fs::remove_dir(out.join("safe")).unwrap();
        std::os::unix::fs::symlink(&outside, out.join("safe")).unwrap();
        let e = open_out_leaf_under(&out, "safe/x.bin", LeafOpen::Truncate).unwrap_err();
        assert!(e.to_string().contains("not a real directory"), "{e}");
        assert!(!outside.join("x.bin").exists());
        std::fs::remove_dir_all(&root).ok();
    }

    /// THE TWO DOORS ANSWER DIFFERENTLY AT THE ROOT, on purpose, and
    /// neither answer is new: [`create_out_dirs`] has always followed a
    /// link at the root (it is a no-op for a flat name, which is how
    /// `nzbfast repair --dir <link>` works at all) and [`open_out_leaf`]
    /// has always refused one (for a flat name the leaf's parent IS the
    /// root). Reproducing that asymmetry is what keeps this change from
    /// loosening anything - and it is what keeps
    /// `resolve_out_root` FALSIFIABLE, since a write door that followed
    /// the root would make a symlinked `--out` work whether or not the
    /// job resolved it.
    ///
    /// A link ABOVE the root is followed either way - `/var` ->
    /// `/private/var`, a symlinked home, a symlinked volume - which is
    /// this module's standing hold-out and is what `scratch` itself
    /// runs through on macOS.
    #[cfg(unix)]
    #[test]
    fn the_two_doors_answer_differently_at_the_root() {
        let root = scratch("underroot");
        let real = root.join("real");
        std::fs::create_dir_all(&real).unwrap();
        let link = root.join("link");
        std::os::unix::fs::symlink(&real, &link).unwrap();

        // The create door follows it, exactly as it always has.
        create_out_dirs(&link, "a/b/leaf.bin").unwrap();
        assert!(real.join("a").join("b").is_dir());

        // The write doors do not.
        let e = open_out_leaf_under(&link, "a/b/leaf.bin", LeafOpen::Truncate).unwrap_err();
        assert!(e.to_string().contains("not a real directory"), "{e}");
        assert!(open_out_leaf_under(&link, "flat.bin", LeafOpen::Truncate).is_err());
        std::fs::write(root.join("staged.bin"), b"x").unwrap();
        assert!(rename_out_under(&link, "a/b/leaf.bin", &root.join("staged.bin")).is_err());

        // ...and once the root is RESOLVED, which is what a job does at
        // its start, every one of them lands.
        let resolved = resolve_out_root(&link);
        drop(open_out_leaf_under(&resolved, "a/b/leaf.bin", LeafOpen::Truncate).unwrap());
        assert!(real.join("a").join("b").join("leaf.bin").is_file());
        std::fs::remove_dir_all(&root).ok();
    }

    /// The rename half: a publish lands where it belongs, and the same
    /// swapped ancestor cannot carry it out. `rename(2)` never followed
    /// a link at the destination's FINAL component - it replaces it -
    /// so the ancestor is the whole exposure here.
    #[cfg(unix)]
    #[test]
    fn rename_out_under_lands_and_refuses_a_swapped_ancestor() {
        let root = scratch("renameunder");
        let out = root.join("out");
        let elsewhere = root.join("elsewhere");
        std::fs::create_dir_all(&elsewhere).unwrap();
        std::fs::create_dir_all(&out).unwrap();
        let from = root.join("staged.bin");

        std::fs::write(&from, b"payload").unwrap();
        let landed = rename_out_under(&out, "a/b/name.bin", &from).unwrap();
        assert_eq!(landed, out.join("a").join("b").join("name.bin"));
        assert_eq!(std::fs::read(&landed).unwrap(), b"payload");

        // Swap the ancestor and try again with a fresh source.
        std::fs::remove_file(&landed).unwrap();
        std::fs::remove_dir(out.join("a").join("b")).unwrap();
        std::fs::remove_dir(out.join("a")).unwrap();
        std::os::unix::fs::symlink(&elsewhere, out.join("a")).unwrap();
        std::fs::create_dir_all(elsewhere.join("b")).unwrap();
        std::fs::write(&from, b"payload").unwrap();
        assert!(rename_out_under(&out, "a/b/name.bin", &from).is_err());
        assert!(
            !elsewhere.join("b").join("name.bin").exists(),
            "the publish escaped through a swapped ancestor"
        );
        // The source is still there - a refused publish must not eat it.
        assert!(from.is_file());
        std::fs::remove_dir_all(&root).ok();
    }

    /// A regular FILE where the parent directory should be is refused
    /// in this module's own words, not as a bare ENOTDIR.
    #[test]
    fn a_file_where_the_parent_should_be_is_refused() {
        let root = scratch("notadir");
        std::fs::write(root.join("afile"), b"x").unwrap();
        let e = open_out_leaf(&root.join("afile").join("x.bin"), LeafOpen::Truncate).unwrap_err();
        assert!(
            e.to_string().contains("not a real directory"),
            "unexpected error: {e}"
        );
        std::fs::remove_dir_all(&root).ok();
    }
}
