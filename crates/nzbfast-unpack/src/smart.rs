//! Smart Folders + cleanup rules (two organizational features in the
//! spirit of Usenapp's).
//!
//! - A rules engine evaluated at enqueue: each rule matches the NZB name
//!   (regex, falling back to plain keyword) plus optional size bounds,
//!   and routes the job to a category (= out_root subfolder). First
//!   match wins. A rule can additionally ask for TV filing: at
//!   completion the job is moved to `[Show]/Season NN/` and its video
//!   renamed `Show - S01E02.ext`, reusing wall.rs's scene-name parser.
//! - Cleanup rules: a list of file extensions deleted from a job's
//!   folder after it completes successfully.

use std::path::{Path, PathBuf};
use tracing::{info, warn};

use crate::tools::MutexExt;
use serde::{Deserialize, Serialize};

/// One Smart Folder rule as stored in settings.json ("smart_folders").
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Rule {
    #[serde(default)]
    pub name: String,
    /// Regex on the NZB name (case-insensitive). A pattern that doesn't
    /// compile is used as a plain keyword substring instead, so
    /// "matrix" and "^The\.Bear\." both do what they look like.
    #[serde(default, rename = "match")]
    pub pattern: String,
    /// Skip the rule when THIS matches (same regex-or-keyword rules).
    #[serde(default)]
    pub not_match: String,
    /// Size bounds in bytes, 0 = unbounded. The UI sends SAB-style
    /// strings ("200M"); both forms deserialize.
    #[serde(default, deserialize_with = "de_size")]
    pub min_size: u64,
    #[serde(default, deserialize_with = "de_size")]
    pub max_size: u64,
    /// Category to file the job under (empty = keep the caller's).
    #[serde(default)]
    pub category: String,
    /// File as TV at completion: [Show]/Season NN/ + video rename.
    #[serde(default)]
    pub tv_sort: bool,
}

/// Accept a byte count or a "200M"-style string (what the row editor
/// sends verbatim from its text input).
fn de_size<'de, D: serde::Deserializer<'de>>(d: D) -> Result<u64, D::Error> {
    struct V;
    impl serde::de::Visitor<'_> for V {
        type Value = u64;
        fn expecting(&self, f: &mut std::fmt::Formatter) -> std::fmt::Result {
            f.write_str("bytes or a size string like 200M")
        }
        fn visit_u64<E: serde::de::Error>(self, v: u64) -> Result<u64, E> {
            Ok(v)
        }
        fn visit_i64<E: serde::de::Error>(self, v: i64) -> Result<u64, E> {
            Ok(v.max(0) as u64)
        }
        fn visit_f64<E: serde::de::Error>(self, v: f64) -> Result<u64, E> {
            Ok(v.max(0.0) as u64)
        }
        fn visit_str<E: serde::de::Error>(self, s: &str) -> Result<u64, E> {
            if s.trim().is_empty() {
                return Ok(0);
            }
            crate::sizes::parse_size(s).ok_or_else(|| E::custom(format!("bad size {s:?}")))
        }
    }
    d.deserialize_any(V)
}

/// Case-insensitive regex match; a pattern that isn't a valid regex is
/// read as a `*`/`?` glob if it carries one and as a keyword substring
/// if it does not. Empty pattern matches everything. The one
/// implementation lives in nzbkit::categories (user categories ride the
/// same rule syntax - 24D); this delegate keeps every caller here
/// byte-compatible.
fn pat_match(pattern: &str, name: &str) -> bool {
    nzbkit::categories::pat_match(pattern, name)
}

impl Rule {
    /// Does this rule claim the job?
    ///
    /// `size` IS TAKEN AS A FACT, and its one production caller
    /// ([`first_match`], from `serve::daemon_enqueue::resolve_add_identity`)
    /// hands it `Nzb::eager_bytes` - which is 0 when the manifest
    /// declared no `bytes=` attributes at all. That shape is accepted on
    /// purpose (see `Nzb::geometry_bytes` and the `<segment>` attribute
    /// comment in `nzbkit::nzb`, both of which state the position
    /// outright: "0 posted bytes means unknown, not zero"), so a rule
    /// carrying `min_size` refuses such a job and one carrying only
    /// `max_size` accepts it, in both cases by reading an unknown as a
    /// measurement. [`size_gated`] counts the rules that question can
    /// reach, and `resolve_add_identity` says so in the log rather than
    /// routing in silence.
    ///
    /// F5 (the zero-declared-bytes handoff, claim
    /// `nzb-zero-bytes-downstream`) is the open question of what the
    /// answer SHOULD be - the private notes do not ship, so it is named
    /// by its claim rather than by a path. The one
    /// thing settled there is what it is NOT: `geometry_bytes` cannot
    /// stand in here. That figure is a preallocation CEILING of
    /// declared articles times 16 MiB, and a real article is 768000 or
    /// 716800 bytes, so it runs 21.8x to 23.4x above the truth on an
    /// ordinary post. Substituted here it would match a 190 MB job
    /// against a 4 GB `min_size` and refuse a 24 MB job against a
    /// 500 MB `max_size` - the same silence pointed the other way, and
    /// misrouting where today's answer merely declines. The arithmetic
    /// is driven rather than asserted, in
    /// `smart::tests::geometry_bytes_cannot_stand_in_for_an_unknown_size`.
    pub fn matches(&self, name: &str, size: u64) -> bool {
        if !pat_match(&self.pattern, name) {
            return false;
        }
        if !self.not_match.trim().is_empty() && pat_match(&self.not_match, name) {
            return false;
        }
        if self.min_size > 0 && size < self.min_size {
            return false;
        }
        if self.max_size > 0 && size > self.max_size {
            return false;
        }
        true
    }
}

/// First rule matching this job, or None. Rule order IS priority.
pub fn first_match<'a>(rules: &'a [Rule], name: &str, size: u64) -> Option<&'a Rule> {
    rules.iter().find(|r| r.matches(name, size))
}

/// How many of these rules ask a question about SIZE.
///
/// Named rather than inlined at its one caller because it is the
/// population of [`Rule::matches`]'s open question: a job whose
/// declared bytes are unknown gets a decision out of every one of
/// these, and that decision is made against a 0 the rule cannot tell
/// from a measurement. Zero here means the unknown costs the routing
/// nothing, which is the common case and the reason this stays a log
/// line rather than a refusal.
pub fn size_gated(rules: &[Rule]) -> usize {
    rules
        .iter()
        .filter(|r| r.min_size > 0 || r.max_size > 0)
        .count()
}

/// "par2, sfv, .srr" → ["par2", "sfv", "srr"] (lowercased, dots and
/// leading wildcards stripped - people paste "*.par2" from other apps).
///
/// §163 item 2: an entry that is a real PATTERN keeps its shape instead.
/// The strip above exists because `*.par2` means "the par2 extension",
/// and it must go on meaning that - but it also flattened `Subs/*` and
/// `*sample*.mkv` to a bare extension, which is not what either of those
/// says. [`is_cleanup_pattern`] is the test, and the two kinds live in
/// one list because a pattern is self-describing: it carries a separator
/// or a wildcard, and a bare extension never can.
///
/// Backslashes are folded to `/` here so a Windows-shaped `Subs\*`
/// means the same thing as the posix spelling, and [`cleanup`] has one
/// separator to match against rather than two.
pub fn parse_ext_list(v: &str) -> Vec<String> {
    v.split(',')
        .map(|e| e.trim().to_ascii_lowercase().replace('\\', "/"))
        .map(|e| {
            if is_cleanup_pattern(&e) {
                e
            } else {
                e.trim_start_matches(['*', '.']).to_string()
            }
        })
        .filter(|e| !e.is_empty())
        .collect()
}

/// Is this cleanup-list entry a pattern rather than a bare extension?
///
/// Yes when it carries a path separator, or a wildcard that survives the
/// leading `*.` a pasted `*.par2` starts with. That second half is the
/// whole subtlety: `*.par2` has a wildcard and is NOT a pattern, because
/// stripping the lead leaves `par2` with nothing wild in it, while
/// `*.r??` leaves `r??` and is.
pub fn is_cleanup_pattern(e: &str) -> bool {
    e.contains('/') || e.trim_start_matches(['*', '.']).contains(['*', '?'])
}

/// Archive-password conventions in a submitted NZB name (`Name{{pw}}`,
/// `Name password=pw`, `Name{pw}`), stripped from the name.
///
/// Defined in [`crate::relname`] since the crate-split prep and
/// re-exported here, because the filing code and its tests reach it
/// under both names.
pub use crate::relname::name_password;

/// Video payload. Disc images (`iso`/`img`) count: they ARE the feature for
/// a disc rip, so they must be recognised as the largest video (the sample
/// gate measures against it) as well as kept. `mts` is AVCHD's stream file
/// (a camcorder-rip cousin of `m2ts`) and `evo` is HD-DVD's multiplexed
/// stream - both are the disc's actual playable video, the same role `vob`
/// plays for DVD-Video, so they belong here and not in the companion list.
const VIDEO_EXTS: &[&str] = &[
    "mkv", "mp4", "avi", "m4v", "mov", "wmv", "mpg", "mpeg", "ts", "m2ts", "mts", "webm", "flv",
    "divx", "vob", "evo", "iso", "img",
];

/// Disc-structure and companion-track files that belong to a video payload
/// without being one: a BDMV/VIDEO_TS tree is unplayable with any of them
/// missing, and an external audio track is the release's whole point when
/// the video ships without it. Kept by `keep_media_only`, which would
/// otherwise leave a disc rip that cannot be opened.
/// The audio list has to stay ahead of what releases actually ship. It
/// carried ac3 and dts but not eac3, which is what nearly every current
/// Atmos or DD+ remux posts its external track as - so keep-media-only
/// deleted the one file the release existed for, reported Completed, and
/// left the user no copy anywhere. When in doubt add the extension:
/// keeping a stray audio file costs disk, deleting a wanted one is
/// unrecoverable.
const MEDIA_COMPANION_EXTS: &[&str] = &[
    "bdmv", "mpls", "clpi", "ifo", "bup", "sup", // disc structure and subs
    "cpi", "mpl",  // AVCHD's shortened-name twins of clpi/mpls
    "bdjo", // BD-Java disc object: a Blu-ray menu is unreachable without it
    "jar",  // BD-Java package - see the doc comment below, this one is deliberate
    "aob",  // DVD-Audio's AUDIO_TS payload: an audio object, not a video one
    "mka", "m4a", "ac3", "eac3", "ec3", "dts", "dtshd", "truehd", "thd", "flac", "aac", "opus",
    "mp3", "wav", // external audio tracks
];
// `jar` above is a generic archive extension everywhere else in this repo -
// `is_packed_archive` does not claim it (only `.zip`/`.zipx` match by name;
// `jar` fails `is_container`'s extension check), so there is no
// double-listing to worry about. Inside a job that already cleared
// `keep_media_only`'s video guard, a `.jar` is only ever a BD-Java package
// a Blu-ray menu needs to run - the doctrine above applies with nothing to
// weigh against it: a stray one costs disk, a deleted one breaks disc menus.

/// Subtitle sidecars - kept alongside the media by every cleanup mode.
const SUBTITLE_EXTS: &[&str] = &["srt", "sub", "idx", "ass", "ssa", "vtt", "smi"];

/// Payload that is not video and never clutter: music, audiobooks,
/// books, comics, and the cue/log sheet a lossless rip is verified with.
///
/// `keep_media_only` guards a video-less job by refusing to run at all,
/// which was enough while every release was a film or an episode. User
/// categories (24D) broke that premise: a comics or audiobook category
/// declaring base Movie, shipping ONE bonus .mp4 beside fifty .cbz
/// files, passed the guard and lost the fifty. `.flac`, `.m4a` and
/// `.cbr` survived only by accident - the first two sit in the companion
/// list, and a .cbr is a RAR to `is_packed_archive`. Extension lists are
/// the wrong place to be lucky, so the payload formats are named.
const PAYLOAD_EXTS: &[&str] = &[
    // audio
    "mp3", "m4b", "opus", "ogg", "oga", "wav", "aiff", "aif", "wma", "alac", "ape", "wv", "cue",
    "log", // books and comics
    "epub", "mobi", "azw", "azw3", "pdf", "cbz", "cbr", "cb7", "djvu",
];

/// Usenet furniture removed by `sweep_junk`: PAR2 recovery, the posted
/// NZB, checksum/verification files, scene .nfo/.txt, and website droppings.
/// Deliberately excludes archives (.rar/.7z - a job that still needs them
/// isn't done) and executables (software payloads).
const JUNK_EXTS: &[&str] = &[
    "par2", "nzb", "sfv", "nfo", "url", "txt", "srr", "srs", "diz", "md5", "sha", "sha256",
    "website",
];

/// Is this extension Usenet furniture rather than payload?
///
/// The one reader of [`JUNK_EXTS`] outside this module is the post-drain
/// census (issue #23): a metadata file the recovery set does not cover
/// must not fail a download whose payload is whole. Exposed as a
/// predicate rather than the list so the exclusions that make the list
/// safe - archives and executables are NOT here - travel with it.
pub fn is_junk_ext(ext: &str) -> bool {
    JUNK_EXTS.contains(&ext)
}

fn ext_of(p: &Path) -> String {
    p.extension()
        .map(|e| e.to_string_lossy().to_ascii_lowercase())
        .unwrap_or_default()
}

/// A still-packed archive volume or part: RAR (`.rar`/`.rNN`, rollover
/// and numeric volumes by magic, or extensionless by magic), 7z (`.7z`,
/// `.7z.NNN`, obfuscated), or any zip shape [`nzbkit::zip`] knows.
///
/// `sweep_junk` gets this for free by simply not listing archives in
/// `JUNK_EXTS`, but `keep_media_only` deletes everything that is not
/// media, and an archive we could not unpack is the ONLY copy of the
/// payload. Deleting it left the user with an empty folder, a job marked
/// Completed, and one log line to explain it - the exact shape a zip post
/// used to fail in. Anything still packed stays; the user needs it.
///
/// The extensionless RAR sniff closes the last hole in that rule. An
/// obfuscated post strips extensions and renames its volumes to hashes,
/// so `looks_like_named_rar` - a pure name grammar - sees nothing, while
/// the 7z and zip collectors beside it already sniff exactly this shape.
/// A set we could not unpack (encrypted with no password, unrepairable,
/// a format we don't read) was therefore kept when it was named and
/// deleted when it was obfuscated, and obfuscated is the common case: the
/// whole payload went, with the recovery volumes that could have rebuilt
/// it, on the single most-encountered release shape on usenet.
///
/// Sniffing only where there is NO extension is the same standing rule
/// `nzbkit::zip::is_container` and `sevenz_archive_part` follow: a payload
/// that carries a name (`.mkv`, `.cbz`) is judged on that name and is
/// never opened by this path.
///
/// `zip_parts` is the directory's zip membership from [`zip_part_set`],
/// because some parts cannot answer for themselves: see there.
///
/// `split_parts` is that same move for the RAR and 7z twins of that
/// shape - a numbered byte split whose head sits in part 1 alone - from
/// [`crate::container_part_set`], which reads them with the extractor's
/// own grammar: see there.
/// It carries the PLAIN reading too, unioned in at both call sites from
/// [`crate::split_part_set`]: no part there has a head, so there is no
/// member to spare and the sweep took the whole set (§301).
fn is_packed_archive(
    p: &Path,
    zip_parts: &std::collections::HashSet<PathBuf>,
    split_parts: &std::collections::HashSet<PathBuf>,
) -> bool {
    crate::archname::looks_like_named_rar(p)
        || (p.extension().is_none() && crate::archname::rar_magic(p))
        || crate::archname::sevenz_archive_part(p)
        || zip_parts.contains(p)
        || split_parts.contains(p)
        || nzbkit::zip::is_container(p)
}

/// Does an EXTENSIONLESS file begin like a video container?
///
/// keep-media-only decides by extension, and anything unrecognised is
/// deleted - so a hash-named payload with no extension at all was
/// removed outright. The no-video guard did not save it either: one
/// properly named video in the same folder is enough to arm the sweep,
/// and an obfuscated post that decodes to one named file plus one
/// hash-named one is an ordinary shape. The archive check above already
/// rescues the packed case; this covers the unpacked one.
///
/// Same standing rule as `is_packed_archive`: sniffing happens ONLY
/// where there is no extension. A file that carries a name is judged on
/// that name and is never opened here.
fn looks_like_video_bytes(p: &Path) -> bool {
    if p.extension().is_some() {
        return false;
    }
    // Four MPEG-TS packets, which is what the sync test below needs; the
    // magics above it live in the first twelve bytes and a short file
    // simply reads short.
    let mut buf = [0u8; 4 * 188];
    let Ok(mut f) = std::fs::File::open(p) else {
        return false;
    };
    let Some(n) = videoext::read_head(&mut f, &mut buf) else {
        return false;
    };
    let b = &buf[..n];
    // Matroska/WebM (EBML), the MP4/MOV family and AVI are
    // `mediaprobe::container_ext`'s question, and the NAMING door has
    // always asked it that way. This door hand-wrote the same three
    // magics instead, and the copy was NARROWER: `container_ext` takes
    // an ISO-BMFF whose first box is any of ftyp/moov/mdat/free/skip/
    // wide/styp/sidx with a plausible length, where the copy took
    // `ftyp` at offset 4 and nothing else. So an extensionless
    // fragmented segment (styp-first) or a moov-first MP4 was DELETED
    // here and would have been NAMED `.mp4` there - measured on
    // origin/main at e6195232a, `PROBEASYM removed=2 styp_kept=false
    // moov_kept=false`. A third spelling of one rule is how this class
    // keeps recurring (the TS and ISO9660 drifts below are the same
    // shape twice over), so this asks rather than widens.
    let head = b
        .get(..12)
        .is_some_and(|h| nzbkit::mediaprobe::container_ext(h).is_some())
        // The MPEG program stream is NOT in `container_ext` and stays
        // inline in both doors: its callers ask "can the remuxer walk
        // this", which for the MPEG family is still no, and `video_ext`
        // special-cases it for that reason - see the comment there.
        || (b.len() >= 4 && b[..4] == [0x00, 0x00, 0x01, 0xBA]);
    // MPEG-TS was `b[0] == 0x47` here, which is ONE byte of evidence:
    // GIF87a/GIF89a open with 0x47, and so does every text file starting
    // with a capital G - so a hash-named scene .nfo or SFV leftover was
    // kept as a video payload, forever, by this pass (M4-89). The sync
    // repeating on the 188-byte stride is what identifies the format,
    // and `videoext` has held that rule since the NAMING door hit the
    // same defect; borrowing it rather than writing the test out a
    // second time is the point, since the two were only ever wrong
    // together. ISO9660 is the inverse case: `iso`/`img` are in
    // VIDEO_EXTS because a disc rip IS the feature, but the standard
    // identifier sits 32 KB in where no head buffer reaches, so a
    // hash-named disc image was deleted as unrecognised clutter.
    head || videoext::is_transport_stream(b) || videoext::is_iso9660(&mut f)
}

/// Every file in `dir` that belongs to a zip container, asked as SETS.
///
/// A bare-numeric split zip (`movie.001`, `.002`, `.003`) carries the
/// magic in part 1 only - the rest are raw continuation bytes with
/// nothing in the name or the head to identify them. Asking each file on
/// its own therefore spared `.001` and deleted `.002` onward, leaving a
/// fragment that can never be opened beside a note telling the user the
/// verified archive was waiting for them. `nzbkit::zip::scan` gates the
/// whole set on part 1 and hands back every member, which is the same
/// collector the reporting path uses.
fn zip_part_set(dir: &Path) -> std::collections::HashSet<PathBuf> {
    nzbkit::zip::scan(dir)
        .into_iter()
        .flat_map(|f| f.parts)
        .collect()
}

/// Does the file start with the `PAR2\0PKT` packet magic? Obfuscated
/// posts name their recovery volumes as hashes with no extension - the
/// NZB subject may still read `…vol-01.par2`, but the on-disk name comes
/// from the yEnc header, so `ext_of` sees nothing and the extension list
/// below can't recognise them. The magic is unambiguous (no media
/// container starts with it), so it decides where the name can't. Same
/// detection main.rs's `dir_has_par2` uses for the repair side.
fn par2_magic(p: &Path) -> bool {
    use std::io::Read as _;
    let mut head = [0u8; 8];
    std::fs::File::open(p)
        .and_then(|mut f| f.read_exact(&mut head))
        .map(|()| &head == b"PAR2\x00PKT")
        .unwrap_or(false)
}

/// A real directory - NOT a symlink pointing at one.
///
/// `Path::is_dir` follows symlinks, and every walker below pairs it with
/// `read_dir` and then deletes what it finds. A completed job containing
/// `extras -> /media/shared` therefore had its cleanup pass walk into the
/// real target and delete files there: removing `job/extras/file.nfo`
/// resolves through the link to `/media/shared/file.nfo`. Native extraction
/// never materialises a symlink, but an external extractor or pre-existing
/// filesystem state can, and "we don't create them" is not a boundary.
pub fn is_real_dir(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_dir())
}

/// A real file - NOT a symlink pointing at one. Same reason as
/// [`is_real_dir`]: the walkers delete what they classify, and following a
/// link means deleting outside the job.
pub fn is_real_file(path: &Path) -> bool {
    std::fs::symlink_metadata(path).is_ok_and(|m| m.is_file())
}

/// Deepest directory nesting [`prune_empty_dirs`] will walk. Our own
/// extraction preserves provably safe member paths since the
/// relpath-preserve ruling (`sanitize_out_name`, capped at 16
/// components), so this bounds those trees as well as ones something
/// else built, and bounds the recursion with it.
const PRUNE_MAX_DEPTH: u32 = 8;

/// Finder metadata macOS drops into any folder it has looked at: the
/// per-folder `.DS_Store`, and the `._name` AppleDouble carrying the
/// resource fork of a file copied to a non-native filesystem.
///
/// Neither is content. Left in place they keep a swept `Sample/` husk
/// alive forever - `.DS_Store` has no extension to match (`ext_of` gives
/// "" for a dotfile, so `JUNK_EXTS` never sees it) and at 6148 bytes it is
/// over `is_nameless_scrap`'s 4 KB ceiling, so nothing in the junk sweep
/// can reach it and `prune_empty_dirs` then finds the directory non-empty.
/// A real file, a subdirectory and a symlink all still count as content.
///
/// NEITHER is decided on the name alone, and `.DS_Store` stopped being so
/// at matrix row M4-79. `._name` never was: the prefix is a convention,
/// not a reservation, and a mis-packed archive or a poster-named extra can
/// carry a real payload called `._something.mkv`. `.DS_Store` reads like
/// the safer of the two - that name is Finder's, and in practice nothing
/// else writes it - but "in practice" is not what was holding it. What was
/// holding it is [`nzbkit::disk::sanitize_filename_for`]'s leading-dot
/// MAPPING (M4-66, 7dcadf0a1), which is why no name we publish can be a
/// `.DS_Store` at all; that rule was landed for an unrelated reason, its
/// own message records that PRESERVING the dot was the other candidate,
/// and nothing joined the two facts. Since the caller deletes what this
/// classifies, and deletes it permanently ([`drop_finder_droppings`]),
/// both must also LOOK like what they claim to be - see
/// [`setclaim::looks_like_ds_store`], which carries the measurement and
/// the reason the set claim cannot stand in for it.
///
/// SIZE ALONE WAS NOT THAT LOOK, and matrix row M4-68 is where it stops
/// being one. [`APPLEDOUBLE_MAX`] excludes "every payload worth losing"
/// only at the ROOT, where a `._movie.mkv` is `largest_video` and spared
/// by name anyway. One directory down there is no feature to be, so a
/// FileDesc naming `Docs/._manual.pdf` at 200 KiB is under the ceiling,
/// carries the prefix, and is the only file left in its directory - which
/// is precisely the husk [`prune_empty_dirs`] clears, with a plain
/// `remove_file` and no Trash to undo it from. A size ceiling cannot be
/// spoofed by a name, but it is not evidence ABOUT the bytes: the whole
/// class of payloads it admits is the small one.
///
/// So the ceiling stays as the cheap pre-filter that keeps a 30 GB
/// `._movie.mkv` from ever being opened, and the answer is now the
/// content's: [`setclaim::looks_like_appledouble`] reads the four-byte
/// AppleDouble magic. A NAME may nominate, only CONTENT may finalize
/// (the `wave4-fix-exact-name-authority` rule, 2b7f5495e) - and here the
/// content half costs one four-byte read of a file already established
/// to be under a megabyte.
fn is_finder_dropping(p: &Path) -> bool {
    let Some(name) = p.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return false;
    };
    if !is_real_file(p) {
        return false;
    }
    if name == ".DS_Store" {
        return setclaim::looks_like_ds_store(p);
    }
    name.starts_with("._")
        && p.metadata().is_ok_and(|m| m.len() <= APPLEDOUBLE_MAX)
        && setclaim::looks_like_appledouble(p)
}

/// Largest `._name` file still treated as an AppleDouble sidecar rather
/// than content. See [`is_finder_dropping`].
const APPLEDOUBLE_MAX: u64 = 1024 * 1024;

/// Is every remaining entry of `d` a Finder dropping? (True for an already
/// empty directory, which the caller then removes on its own.)
fn only_finder_droppings(d: &Path) -> bool {
    std::fs::read_dir(d).is_ok_and(|rd| rd.flatten().all(|e| is_finder_dropping(&e.path())))
}

/// Delete the Finder droppings in `d` so the husk can go.
///
/// A plain `remove_file`, deliberately NOT `remove_user_file`: this is the
/// OS's own metadata about a folder that is about to stop existing, not
/// anything the user downloaded or could want back, and routing it to the
/// Trash would put `.DS_Store` files in front of them for no reason.
fn drop_finder_droppings(d: &Path) {
    let Ok(rd) = std::fs::read_dir(d) else { return };
    for entry in rd.flatten() {
        let path = entry.path();
        if is_finder_dropping(&path)
            && let Err(e) = std::fs::remove_file(&path)
        {
            warn!(target: "cleanup", "{}: {e}", path.display());
        }
    }
}

/// Remove subdirectories of `dir` that a sweep just emptied: the `Sample/`
/// or `Proof/` folder whose clips have gone, plus any now-empty parent
/// above it. The sweeps delete files one subdirectory deep but left the
/// husk behind, and a completed job still showing a `Sample` folder reads
/// as though the sweep never ran - NZBGet's DeleteSamples takes the
/// directory too.
///
/// Only a directory whose whole subtree is empty goes. Anything holding a
/// file stays, and so does every parent above it. A symlink counts as
/// content and is never followed or removed: it is not ours, and
/// `remove_dir` on the parent would be the least of what walking into it
/// could cost (see [`is_real_dir`]).
///
/// "Empty" tolerates Finder metadata - see [`is_finder_dropping`]. On
/// macOS the sweep took the sample clip and left `Sample/.DS_Store`, so
/// the husk this exists to remove survived every download.
///
/// `dir` itself is never removed however empty it ends up - the job owns
/// it, and the state that a job's own output directory is missing is one
/// the rest of post-processing does not expect. Returns how many
/// directories went; deliberately NOT folded into the sweeps' file counts.
fn prune_empty_dirs(dir: &Path, depth: u32) -> usize {
    if depth >= PRUNE_MAX_DEPTH {
        return 0;
    }
    let mut removed = 0;
    let Ok(rd) = std::fs::read_dir(dir) else {
        return 0;
    };
    for entry in rd.flatten() {
        let path = entry.path();
        if !is_real_dir(&path) {
            continue;
        }
        // Depth-first: emptying a child can empty its parent.
        removed += prune_empty_dirs(&path, depth + 1);
        if only_finder_droppings(&path) {
            drop_finder_droppings(&path);
        }
        if std::fs::read_dir(&path).is_ok_and(|mut r| r.next().is_none()) {
            match std::fs::remove_dir(&path) {
                Ok(()) => {
                    info!(target: "cleanup", "empty dir {}", path.display());
                    removed += 1;
                }
                Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
            }
        }
    }
    removed
}

/// The resolution the payload's own container reports, when the job has
/// a Matroska main video. The subject line's claim is the poster's; the
/// header is the file's, and where the two disagree the header wins
/// (see `finalize_names`). One bounded head read; anything unreadable
/// returns None and the claim stands.
pub fn measured_res(dir: &Path) -> Option<&'static str> {
    let video = main_video(dir)?;
    if !matches!(ext_of(&video).as_str(), "mkv" | "webm") {
        return None;
    }
    let i = nzbkit::mkv::probe(&video)?;
    Some(nzbkit::mkv::res_bucket(i.width?, i.height?))
}

/// The job's feature: the biggest video in the finished directory, with
/// the sample clip ruled out. What every "ask the payload itself"
/// question is asked of, so they all agree on which file they mean.
///
/// A teaser OF something here, not merely a marker-named file, since
/// matrix row M4-91. `is_sample_clip` alone is a name test with no
/// second opinion of any kind - no size, no duration, no sibling - and
/// it is the strictest of the three sample rules in that respect, which
/// is backwards: this one is the only one that never deletes anything.
/// Measured 30 Aug 2026 on origin/main, this returned `None` for a
/// directory holding `Proof.S01E01.mkv` beside `Proof.S01E00.Special.mkv`
/// (both stems carry the word, so whichever is largest is rejected) and
/// for one holding nothing but `Bulletproof.S01E01.mkv`. `measured_res`
/// and `identity::container_title` then have no video to ask, so the
/// resolution and title the payload itself reports go unread and the
/// poster's subject line stands unchallenged - for a title whose only
/// offence was spelling.
///
/// [`sample::is_teaser_beside`] keeps the protective half: a mislabelled
/// post whose biggest video really is named after a smaller sibling is
/// still ruled out, and a job whose ONLY video is marker-named is the
/// release the user asked for and is now answered rather than skipped.
pub fn main_video(dir: &Path) -> Option<PathBuf> {
    let v = largest_video(dir)?;
    let siblings = files_in_reach(dir);
    (!sample::is_teaser_beside(&v, &siblings)).then_some(v)
}

/// The release name the job's own PAYLOAD is wearing: the stem of
/// [`main_video`], when that stem reads as a name at all.
///
/// Wave-7 row W7-05. `serve::naming::finalize_names` classifies from
/// `job.name`, which is what the .nzb was called, so a fully obfuscated
/// post lands in `BaseBehavior::None` and neither the junk sweep nor the
/// folder rename nor the quality suffix ever fires - however perfectly
/// settle has just named every file inside it. Measured 31 Aug 2026:
/// the same directory with the same settled filenames sweeps 3 files
/// and files itself under its real name when the job name is the
/// release, and sweeps 0 and moves nothing when it is a hash
/// (`research/POST-SETTLE-NAME-AUTHORITY-2026-08-31.md`).
///
/// [`main_video`] and not a directory scan of its own, because that is
/// "the file every ask-the-payload-itself question is asked of, so they
/// all agree on which file they mean" - the same feature `measured_res`
/// and `identity::container_title` read.
///
/// [`nzbkit::release::stem_is_a_name`] is the bar, which is the
/// project's single answer to "is this dark?" and is what keeps a
/// hash-named payload from re-classifying a job as itself.
pub fn payload_release_stem(dir: &Path) -> Option<String> {
    named_feature(dir).map(|(_, stem)| stem)
}

/// [`main_video`] and the stem it wears, when that stem reads as a
/// name. Both public answers above come off one walk of the directory;
/// the split exists so `proved_release_stem` can ask the set about the
/// very path this resolved, rather than resolving it a second time.
fn named_feature(dir: &Path) -> Option<(PathBuf, String)> {
    let v = main_video(dir)?;
    let name = v.file_name()?.to_string_lossy().into_owned();
    let ext = ext_of(&v);
    // An extensionless payload is a video since #43, and its whole
    // filename is then the stem - the same two readings `rename_movie`
    // keeps apart at its own rename.
    let stem = if ext.is_empty() {
        name
    } else {
        name.strip_suffix(&format!(".{ext}"))
            .unwrap_or(&name)
            .to_string()
    };
    nzbkit::release::stem_is_a_name(&stem).then_some((v, stem))
}

/// [`payload_release_stem`], but only when a PAR2 recovery set on disk
/// DECLARES that feature's own path - so the name is PROVED and not
/// merely present.
///
/// Wave-7 row W7-06 needs the stronger bar and W7-05 does not, and the
/// asymmetry is the point rather than an inconsistency. W7-05 arms
/// consequences that are cosmetic or already protected, over a job
/// whose .nzb name carries no title at all - so any readable name beats
/// nothing. W7-06 OVERRIDES a title the user's own metadata renamer
/// produced, and a name on disk that no set declares was written by
/// whichever tier could name it - the weakest of which is a parse of
/// the same subject line. That is not stronger evidence than the job
/// name, and the house rule since `wave4-fix-exact-name-authority` is
/// that a name may nominate and only CONTENT may finalize.
///
/// The set read is [`setclaim::set_declared_paths`], the same oracle
/// both sweeps already trust and bounded the same way. Two things
/// follow from that and are stated rather than left to be found. It is
/// only readable HERE because the sweep is what deletes the `.par2`
/// afterwards, so this must be asked on the finalize tail and nowhere
/// later. And a foreign or decoy set that happens to declare the name
/// already on disk can only ever make the payload keep the name settle
/// gave it - this function never invents one - so the worst it costs is
/// a rename the user does not get.
pub fn proved_release_stem(dir: &Path) -> Option<String> {
    let (v, stem) = named_feature(dir)?;
    setclaim::set_declared_paths(dir)
        .contains(&v)
        .then_some(stem)
}

/// Every real file the one-level sweeps can see: this directory plus one
/// subdirectory down, the same reach as [`sweep_junk`] and
/// [`keep_media_only`]. Symlinks and directories are not files and never
/// appear (see [`is_real_file`]).
///
/// It is every file and not only the videos, because a teaser is named
/// after the RELEASE and what is left carrying that name in a finished
/// directory is as often the `.nfo`, the `.srt` or the `.sfv` as another
/// video.
///
/// DELIBERATELY NOT `feature::largest_video`'s reach, which the M4-81
/// lane widened to a bounded depth-8 walk while leaving the sweeps at
/// one level on the ground that they DELETE what they reach. This is a
/// naming question rather than a deletion one, so it could follow either
/// - and it follows the sweeps, because the names it compares against
/// are the ones a release actually spreads across its own directory. The
/// cost is stated: a feature that lives two or more deep (a Blu-ray
/// tree) has no siblings HERE, [`sample::is_teaser_of_any`] therefore
/// answers false, and [`main_video`] keeps it. That is the direction
/// this whole family is required to err in - it keeps a feature rather
/// than discarding one - and it is exactly what the row M4-81 fixed
/// wanted from the other end.
fn files_in_reach(dir: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let Ok(rd) = std::fs::read_dir(dir) else {
        return out;
    };
    for path in rd.flatten().map(|e| e.path()) {
        if is_real_dir(&path) {
            if let Ok(sub) = std::fs::read_dir(&path) {
                out.extend(sub.flatten().map(|e| e.path()).filter(|p| is_real_file(p)));
            }
        } else if is_real_file(&path) {
            out.push(path);
        }
    }
    out
}

/// Does this cleanup-list entry select this file?
///
/// `ext` and `name` are the file's own, already lowercased; `rel` is its
/// path relative to the job folder, with `/` separators, which for a
/// one-level sweep is either `name` or `sub/name`.
///
/// The three kinds, and why a pattern is matched against one thing or
/// the other rather than both: a bare extension is today's rule
/// unchanged; a pattern WITHOUT a separator is about the filename, so it
/// applies at every level the sweep reaches (`*sample*` should find a
/// sample wherever the unpack put it); a pattern WITH one is about
/// placement, so it is matched against the relative path and `Subs/*`
/// therefore means the Subs folder rather than anything named Subs.
fn cleanup_selects(entry: &str, ext: &str, name: &str, rel: &str) -> bool {
    if !is_cleanup_pattern(entry) {
        return entry == ext;
    }
    nzbkit::categories::glob_match(entry, if entry.contains('/') { rel } else { name })
}

/// Delete files matching `exts` from `dir` (top level plus one
/// subdirectory level - where extraction puts things). Logs each
/// removal; returns `(total, par2)` - how many files went, and how many
/// of those were `.par2` recovery files. The split exists for the
/// history drawer's one-line cleanup report: recovery files are deleted
/// by a default most users never chose (`par_cleanup`), so "12 of those
/// were par2" is the half of the count that answers "where did my
/// recovery data go".
///
/// An entry is a bare extension or a pattern - see [`parse_ext_list`]
/// and [`cleanup_selects`]. The par2 half of the count is taken off the
/// file's own extension either way, so a pattern that happens to sweep
/// recovery files still reports them as recovery files.
pub fn cleanup(dir: &Path, exts: &[String]) -> (usize, usize) {
    let mut removed = 0;
    let mut par2 = 0;
    // Read once, for the whole sweep: see `remove_user_file`.
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    let mut sweep = |d: &Path, prefix: &str| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            let ext = path
                .extension()
                .map(|e| e.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let name = path
                .file_name()
                .map(|n| n.to_string_lossy().to_ascii_lowercase())
                .unwrap_or_default();
            let rel = format!("{prefix}{name}");
            if exts.iter().any(|e| cleanup_selects(e, &ext, &name, &rel)) {
                match remove_swept_file(&path, recoverable, staging.as_deref()) {
                    Ok(_) => {
                        info!(target: "cleanup", "removed {}", path.display());
                        removed += 1;
                        if ext == "par2" {
                            par2 += 1;
                        }
                    }
                    Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
                }
            }
        }
    };
    sweep(dir, "");
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                let sub = path
                    .file_name()
                    .map(|n| n.to_string_lossy().to_ascii_lowercase())
                    .unwrap_or_default();
                sweep(&path, &format!("{sub}/"));
            }
        }
    }
    (removed, par2)
}

/// Recoverable delete for anything that came out of a user's download.
///
/// The cleanup passes used to call `remove_file` directly, so a file the
/// junk heuristics got wrong was gone for good - and those heuristics are
/// exactly the kind that get things wrong (obfuscated posts have no
/// reliable names, and "Proof" once cost a real release). The Trash makes
/// every one of those calls reversible by the person best placed to judge
/// it, which is the whole difference between a wrong guess and data loss.
///
/// Deliberately NOT used for our own spool, journals or placeholders:
/// those are internal churn, and routing them here would bury the user's
/// Trash under files they never saw and cannot act on.
///
/// A recoverable delete NEVER becomes a permanent one. When no Trash will
/// take the path this returns an error and the file stays exactly where it
/// is - see [`trash_attempt`]. It used to hard-delete instead, on the
/// reasoning that leaving clutter forever was worse; that reasoning had it
/// backwards. Every caller of this is a heuristic ("this looks like junk",
/// "this looks like a sample"), the Trash is the only thing that makes a
/// wrong guess survivable, and "the Trash refused, so destroy it" turns
/// the one failure the setting promised to soften into the very outcome it
/// promised to prevent. A user who genuinely wants permanent deletes turns
/// `delete_to_trash` off - the NAS/seedbox default on Linux - and that
/// path is untouched.
///
/// `recoverable` is passed IN rather than read from the process-global
/// here, so one sweep decides once (at its entry) and every file it touches
/// is treated the same way. Re-reading the flag per file meant a settings
/// change - or, in the test suite, another test's `set_delete_to_trash` -
/// landed halfway through a sweep and split it between the two behaviours.
pub fn remove_user_file(path: &Path, recoverable: bool) -> std::io::Result<Removed> {
    if recoverable_wanted(recoverable, path) {
        return match trash_attempt(path) {
            TrashVerdict::Took => Ok(Removed::Trashed),
            TrashVerdict::TookButGone | TrashVerdict::NotFound => Ok(Removed::Gone),
            TrashVerdict::Refused(why) => Err(refusal(&why)),
        };
    }
    // A bounded call that gave up may STILL be running, and Finder may
    // yet move the file to the Trash behind us. Then this direct delete
    // races it and loses with NotFound - which is the outcome we wanted
    // (the file is gone), not a failure to report to the caller.
    match std::fs::remove_file(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removed::Gone),
        Err(e) => Err(e),
        Ok(()) => Ok(Removed::Gone),
    }
}

/// [`remove_user_file`] for a whole DIRECTORY: a completed job's private
/// output folder, deleted as one recoverable unit. One Trash call moves
/// the folder intact - the user gets "the download I deleted" back as a
/// single restorable item, not a thousand loose files - and it costs the
/// same one bounded call a single file does.
///
/// This is what makes the "Deleted files go to the Trash" promise hold
/// for the deletes users actually perform: history "delete + files", a
/// queue delete with files, and the watchlist delete_old upgrade all end
/// at a job directory, and every one of them used to be a bare
/// `remove_dir_all` that no setting could soften.
///
/// This is the delete where refusing to hard-delete matters most: the
/// argument in [`remove_user_file`] applies to a stray `.nfo`, and here it
/// applies to an entire finished download. A `remove_dir_all` behind a
/// failed Trash call is unrecoverable by anyone, and it lands on the user
/// who ASKED for recoverable deletes. The directory is left alone and the
/// caller says so instead.
pub fn remove_user_dir(path: &Path, recoverable: bool) -> std::io::Result<Removed> {
    if recoverable_wanted(recoverable, path) {
        return match trash_attempt(path) {
            TrashVerdict::Took => Ok(Removed::Trashed),
            TrashVerdict::TookButGone | TrashVerdict::NotFound => Ok(Removed::Gone),
            TrashVerdict::Refused(why) => Err(refusal(&why)),
        };
    }
    // NotFound tolerated for the same race as remove_user_file - and for
    // the ordinary case of a job whose directory was never created.
    match std::fs::remove_dir_all(path) {
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(Removed::Gone),
        Err(e) => Err(e),
        Ok(()) => Ok(Removed::Gone),
    }
}

/// What a removal actually DID, as opposed to what the setting asked
/// for.
///
/// The distinction is load-bearing and was missing: "its files went to
/// the Trash" used to be reconstructed by the callers from two globals
/// (`delete_to_trash()` and `!trash_unresponsive()`), never from what
/// happened to those files. On 4 Aug that told a user a 14 GB download
/// was recoverable while it had in fact been destroyed outright - the
/// setting was on, nothing had timed out, and the backend returned Ok.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum Removed {
    /// In a Trash it can be restored from. Only ever reported when that
    /// has been CHECKED, never inferred from the setting.
    Trashed,
    /// Gone, with no promise of getting it back. Covers a deliberate
    /// permanent delete, a path that was already absent, and the case
    /// above: a Trash route that reported success and left nothing
    /// recoverable behind it.
    Gone,
}

/// What the Trash roots held that could be mistaken for this delete,
/// taken BEFORE it happens.
///
/// Without it the check answers "recoverable" for a name that was
/// already sitting there: `~/.Trash` keeps things for weeks, so the
/// second delete of `Movie.mkv` - or a delete of anything whose name
/// starts with a stem already in there - matched an entry from days
/// ago and reported a hard delete as restorable. The claim has to be
/// about an entry that appeared, not one that exists.
#[cfg(target_os = "macos")]
#[derive(Default)]
struct TrashBefore {
    /// The exact target name already present in some root.
    exact: bool,
    /// Every stem-prefixed name already present, across all roots.
    names: std::collections::HashSet<std::ffi::OsString>,
}

#[cfg(target_os = "macos")]
fn trash_snapshot(path: &Path) -> TrashBefore {
    let mut before = TrashBefore::default();
    let Some(name) = path.file_name() else {
        return before;
    };
    let stem = path
        .file_stem()
        .map(|s| s.to_string_lossy().into_owned())
        .unwrap_or_else(|| name.to_string_lossy().into_owned());
    for root in trash_roots(path) {
        if root.join(name).exists() {
            before.exact = true;
        }
        let Ok(entries) = std::fs::read_dir(&root) else {
            continue;
        };
        for e in entries.take(4096).flatten() {
            if e.file_name().to_string_lossy().starts_with(&stem) {
                before.names.insert(e.file_name());
            }
        }
    }
    before
}

/// The two places macOS puts a trashed item: the boot volume's per-user
/// Trash, and a per-volume `.Trashes/<uid>` for anything else. A path
/// under /Volumes/<name> is checked against its own volume first, then
/// the home one - a cross-volume trash lands in the latter.
#[cfg(target_os = "macos")]
fn trash_roots(path: &Path) -> Vec<std::path::PathBuf> {
    let mut roots: Vec<std::path::PathBuf> = Vec::new();
    let comps: Vec<_> = path.components().collect();
    if comps.len() > 2 && path.starts_with("/Volumes") {
        let vol: std::path::PathBuf = comps[..3].iter().collect();
        roots.push(
            vol.join(".Trashes")
                // SAFETY: getuid(2) takes no arguments, touches no
                // memory and cannot fail; it is unsafe only because it
                // is an extern "C" call.
                .join(unsafe { libc::getuid() }.to_string()),
        );
    }
    if let Some(home) = std::env::var_os("HOME") {
        roots.push(std::path::PathBuf::from(home).join(".Trash"));
    }
    roots
}

/// Did `path` actually land somewhere it can be restored from?
///
/// Asked AFTER a Trash route reports success, because that success means
/// only "a backend returned Ok". macOS has two routes and both can
/// answer Ok while the bytes are gone: on a volume whose per-user Trash
/// is not usable - an external disk mounted `noowners` is the ordinary
/// way to get one - Finder's scripted `delete` performs the delete
/// -immediately behaviour its GUI would warn about, and says it worked.
///
/// Deliberately biased towards claiming recoverable: only a positive
/// look in the expected place, coming back empty, downgrades the answer.
/// Anything we cannot determine stays `Trashed`, because crying wolf on
/// a delete that WAS recoverable is its own harm.
#[cfg(target_os = "macos")]
fn landed_in_a_trash(path: &Path, before: &TrashBefore) -> bool {
    let Some(name) = path.file_name().map(|n| n.to_string_lossy().into_owned()) else {
        return true;
    };
    let roots = trash_roots(path);
    if roots.is_empty() {
        return true;
    }
    // Finder disambiguates a name collision by appending to the stem, so
    // an exact hit is the common case and a prefix match covers the
    // rest. Bounded: a long-untended Trash must not turn one delete into
    // a directory walk of tens of thousands of entries.
    //
    // Matched against the BEFORE snapshot throughout: an entry that was
    // already there is somebody else's old delete, and it is the whole
    // reason this check could say "recoverable" about files that had
    // just been destroyed outright.
    for root in &roots {
        if !before.exact && root.join(&name).exists() {
            return true;
        }
        let Ok(entries) = std::fs::read_dir(root) else {
            continue;
        };
        let stem = path
            .file_stem()
            .map(|s| s.to_string_lossy().into_owned())
            .unwrap_or_else(|| name.clone());
        for e in entries.take(4096).flatten() {
            if e.file_name().to_string_lossy().starts_with(&stem)
                && !before.names.contains(&e.file_name())
            {
                return true;
            }
        }
    }
    false
}

/// Every other platform's backend is a real XDG Trash or Recycle Bin,
/// which does not have the "reported success, deleted anyway" mode this
/// guards against. Nothing to second-guess.
#[cfg(not(target_os = "macos"))]
#[derive(Default)]
struct TrashBefore;

#[cfg(not(target_os = "macos"))]
fn trash_snapshot(_path: &Path) -> TrashBefore {
    TrashBefore
}

#[cfg(not(target_os = "macos"))]
fn landed_in_a_trash(_path: &Path, _before: &TrashBefore) -> bool {
    true
}

/// What one recoverable-delete attempt settled on.
enum TrashVerdict {
    /// A Trash route took `path` and it was found afterwards in a Trash
    /// it can be restored from.
    Took,
    /// A Trash route reported success, but nothing recoverable is there:
    /// the path is gone for good. The files ARE removed - the caller
    /// asked for that - but nothing may claim they can be restored.
    TookButGone,
    /// There was nothing at `path` to take.
    NotFound,
    /// No Trash route would take it. Carries the reason for the log. The
    /// caller must NOT fall back to a permanent delete: see
    /// [`remove_user_file`].
    Refused(String),
}

/// The error a refused recoverable delete comes back as. Worded to be
/// READ: a user who asked for recoverable deletes needs to know why their
/// files are still there and what to change, not just that something
/// failed. It reaches them through the dashboard's kept-files notice as
/// well as the log now, so it has to stand up in front of a person.
///
/// Deliberately does NOT name the path, though it once did. Every caller
/// already prints it - `remove_job_files`, the filed-episode sweep, the
/// deferred-trash drain and the watch-folder ingest all log
/// `<path>: <this>` - so the path came out twice in a row on every line,
/// and the notice repeats it a third time in its own sentence.
fn refusal(why: &str) -> std::io::Error {
    std::io::Error::other(format!(
        "the Trash would not take it ({why}). If something else has the \
         files open - a virus scanner or a backup tool often does, for a \
         while after a big download - deleting again in a few minutes \
         usually works. If it keeps happening, turn off \"Deleted files go \
         to the Trash\" in Settings to remove files outright rather than \
         leave them."
    ))
}

/// `NZBFAST_NO_TRASH=1` forces every recoverable delete down the plain
/// permanent-delete branch, as if `delete_to_trash` were off - the
/// explicit override for anything outside [`under_temp_dir`]'s rule,
/// whose doc carries the Finder "-43" story both of them exist to stop.
///
/// It also closes a hole `cfg(test)` could not: the `TRASH` flag defaults
/// off under `cfg(test)` so cleanup suites do not empty their fixtures
/// into the developer's real ~/.Trash, but `cfg!(test)` is evaluated when
/// the LIBRARY is compiled and an integration test links the ordinary
/// non-test build, so every test under `tests/` got the flag ON.
///
/// Read once and cached: this sits under per-file cleanup sweeps.
fn trash_disabled_by_env() -> bool {
    static OFF: std::sync::OnceLock<bool> = std::sync::OnceLock::new();
    *OFF.get_or_init(|| {
        std::env::var("NZBFAST_NO_TRASH").is_ok_and(|v| v == "1" || v.eq_ignore_ascii_case("true"))
    })
}

/// Nothing under the OS temp directory is ever worth a recoverable
/// delete, and asking for one there is actively harmful. The Trash exists
/// so a WRONG GUESS about the user's data survives, and a path in
/// `$TMPDIR` is not the user's data by construction - it is our own
/// scratch, or a test's fixtures, which the OS may reclaim at any moment.
/// Binning it only leaves the user junk to empty, named after something
/// they never had.
///
/// It is also where the recoverable route MISBEHAVES. On macOS the Trash
/// is scripted through Finder and the call is bounded ([`trash_attempt`]),
/// so we give up waiting, the owner of the scratch directory removes it,
/// and Finder arrives to find nothing there: a modal "-43" dialog on the
/// desktop, minutes after the run that caused it and attributed to
/// nothing. The integration suites hit this constantly - each drives a
/// real `nzbfast` child against a `nzbfast-*` scratch dir in `$TMPDIR`,
/// where the library-side `cfg(test)` default that keeps the UNIT tests
/// off Finder cannot reach a spawned binary - so fixing it here fixes all
/// 122 child-spawn sites at once, and the next test someone writes.
///
/// Compared by canonical path so the macOS `/var` -> `/private/var`
/// symlink cannot slip a temp path past the check. An uncanonicalizable
/// path (already gone, unreadable parent) falls back to the path as
/// given: this is a "make it permanent" decision, and the safe direction
/// when unsure is to leave the caller's recoverable request alone.
fn under_temp_dir(path: &Path) -> bool {
    // The library's OWN unit tests are the one place a temp path must
    // still reach the Trash: `trash_tests` proves the recoverable route
    // works and its fixtures can only live in `$TMPDIR`. They are safe
    // there for the reason the integration suites are not - `TRASH`
    // defaults OFF in a test build, so those three serialized,
    // self-cleaning tests are the only callers that ever arrive here
    // recoverable. This gate is aimed squarely at the build they cannot
    // cover: the binary a test spawns, where neither condition holds.
    //
    // NOT `feature = "test-support"`, and that is the one thing about
    // this gate not to "fix" by symmetry with the seams around it. The
    // binary an integration test SPAWNS is built inside the same cargo
    // invocation as the test, so it carries every dev-dependency feature
    // the package turns on - `test-support` included. Exempting on the
    // feature would therefore switch this gate off in exactly the build
    // it was written for, and hand back the "-43" Finder dialog at all
    // 122 child-spawn sites.
    //
    // What a cross-crate caller gets instead is [`force_temp_trash`], a
    // seam that DEFAULTS OFF, so the spawned binary is unaffected by its
    // existence and only a test that asks is exempt. Since the
    // crate-split step 3 cut that is the one route in:
    // `crates/nzbfast`'s tests compile this crate as an ordinary
    // dependency, where `cfg!(test)` is false.
    if cfg!(test) || temp_trash_forced() {
        return false;
    }
    path_is_under(path, &std::env::temp_dir())
}

/// The prefix test behind [`under_temp_dir`], split out so it is testable:
/// `under_temp_dir` answers false under `cfg(test)` by design, so a unit
/// test can never reach the comparison through it.
fn path_is_under(path: &Path, base: &Path) -> bool {
    fn real(p: &Path) -> std::path::PathBuf {
        std::fs::canonicalize(p).unwrap_or_else(|_| p.to_path_buf())
    }
    real(path).starts_with(real(base))
}

/// Fold the overrides into a caller's `recoverable` request. Applied at
/// the two public entry points rather than inside [`trash_attempt`],
/// because they have to mean "delete it permanently", not "refuse and
/// leave it" - a refusal would leave every affected file on disk, which
/// for a temp path is the opposite of what anyone wants.
fn recoverable_wanted(recoverable: bool, path: &Path) -> bool {
    recoverable && !trash_disabled_by_env() && !under_temp_dir(path)
}

/// One recoverable attempt against the Trash.
fn trash_attempt(path: &Path) -> TrashVerdict {
    // Nothing there to bin. Checked BEFORE the backend on purpose: macOS's
    // Finder route reports a path it cannot see as a CLASS error
    // ("Handler can't handle objects of this class", -10010), not as "not
    // found" - the crate only canonicalizes the parent, so a missing leaf
    // sails through to the AppleScript. That produced a live WARN reading
    // "could not move <a user's download> to the Trash - deleting it
    // instead" for a directory that had already gone, which is the most
    // alarming line we could print about a no-op. It is also the shape of
    // the race the old direct-delete fallback swallowed as NotFound.
    // NotFound only. `is_err()` swallowed every other stat failure too -
    // EACCES on a parent that lost search permission, EIO/ESTALE on a
    // dropped SMB or NFS mount - and reported each as "the Trash took
    // it": `Ok(())` out of `remove_user_dir`, `FilesGone::Yes`, no
    // `note_delete_kept`, no warning, and the history row dropped. A NAS
    // user reclaiming space from a share that had just gone away was
    // told the files were deleted while the whole payload was still
    // sitting there, named by nothing - the exact failure class the
    // kept-files notice exists to close. The non-recoverable arms
    // already tolerate only NotFound; this one is now consistent with
    // them.
    if std::fs::symlink_metadata(path).is_err_and(|e| e.kind() == std::io::ErrorKind::NotFound) {
        return TrashVerdict::NotFound;
    }
    if trash_unresponsive() {
        return TrashVerdict::Refused("the Trash is not responding".to_string());
    }
    // Taken BEFORE the call: "is it in the Trash now" cannot tell a
    // fresh entry from one that was already sitting there under the
    // same name.
    let before = trash_snapshot(path);
    match trash_delete_gated(|| trash_delete_bounded(path)) {
        // Ok from the backend is not the answer on its own - see
        // `landed_in_a_trash`.
        Ok(()) => {
            if landed_in_a_trash(path, &before) {
                TrashVerdict::Took
            } else {
                warn!(
                    target: "files",
                    "the Trash reported success for {} but nothing restorable is there - \
                     reporting it as deleted, because that is what happened. A volume \
                     whose per-user Trash is unusable (an external disk mounted \
                     `noowners` is the common one) deletes outright and says it worked.",
                    path.display()
                );
                TrashVerdict::TookButGone
            }
        }
        // Another caller was inside the process's first Trash call when we
        // arrived, and it came back unresponsive. We never made a call of
        // our own, but the verdict is the same one we would have got.
        Err(None) => TrashVerdict::Refused("the Trash is not responding".to_string()),
        Err(Some(e)) => {
            // On a headless Mac the crate's Finder/AppleScript backend
            // does not fail fast: every call blocks ~2 minutes before
            // "AppleEvent timed out (-1712)". A queue of three jobs
            // carries dozens of par2/nfo cleanup files, and those
            // serialized stalls measured as 720 s of a 863 s job - the
            // job is not done until its cleanup is. One timeout means
            // every later call will stall the same way, so the rest of
            // the process stops asking - `trash_delete_gated` has already
            // latched that, before it let anyone else past, and all that
            // is left here is to say so. Ordinary failures (a volume with
            // no trash at all) stay per-path: they are instant and the
            // next file may live somewhere else entirely.
            if looks_like_a_trash_timeout(&e) {
                warn!(
                    target: "cleanup",
                    "the Trash is not responding (headless session?) - \
                     not asking it again this run"
                );
            }
            first_refusal_hint();
            TrashVerdict::Refused(e)
        }
    }
}

/// Said once per process, the first time a recoverable delete is refused.
///
/// The per-path errors go where the caller logs them (a sweep line, a job
/// line), and each one on its own reads like a transient hiccup. This is
/// the sentence that explains the pattern: files are being LEFT, on
/// purpose, and there are exactly two ways out. Once, not per file - a
/// junk sweep refused is a dozen lines by itself.
fn first_refusal_hint() {
    static SAID: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
    if SAID.swap(true, std::sync::atomic::Ordering::Relaxed) {
        return;
    }
    warn!(
        target: "cleanup",
        "the Trash refused a delete, so files are being left in place \
         rather than permanently deleted. Turn off \"Deleted files go to \
         the Trash\" in Settings if you want them removed outright"
    );
}

/// How long a single Trash call may hold up a finished job before we stop
/// waiting for it. Only meaningful on macOS - see `trash_delete_bounded`.
///
/// Generous ON PURPOSE. The Trash is what makes a wrong junk-heuristic
/// guess reversible by the user, which is the whole reason cleanup routes
/// through it, so treating a merely SLOW Finder as a dead one would trade
/// that away for the rest of the process. A healthy Finder answers in
/// milliseconds; nothing legitimate takes half a minute.
#[cfg(target_os = "macos")]
const TRASH_DEADLINE: std::time::Duration = std::time::Duration::from_secs(30);

/// `trash::delete`, but it cannot hold a finished job hostage.
///
/// On macOS the crate's backend asks Finder over AppleScript and waits
/// with no application-level timeout, so on a headless session (ssh, a
/// launchd daemon, a login window nobody has touched) every call blocks
/// for about two minutes before returning "AppleEvent timed out (-1712)".
/// Cleanup runs INSIDE post-processing and a job is not filed to history
/// until it returns, so those stalls are wall-clock the user sees as a
/// download that finished but never appeared: one measured job spent
/// 720 s of its 863 s exactly here. `TRASH_UNRESPONSIVE` already stops
/// the SECOND call paying it, but the first one still did.
///
/// So: run the call on its own thread and stop waiting at
/// `TRASH_DEADLINE`. The thread is left to finish on its own - AppleEvent
/// has no cancel, and abandoning it is the point. The caller then leaves
/// the file alone, and tolerates the race where Finder eventually wins
/// (the path is simply gone next time anyone looks).
///
/// Every other platform calls straight through: the XDG and Windows
/// backends are local filesystem work with no interprocess wait to bound,
/// and a thread per file would be cost for nothing.
///
/// macOS has a SECOND route, and this is where it is taken. See
/// [`trash_via_file_manager`]. The other two platforms have exactly one
/// each, and both fail for reasons no retry would fix - a Windows volume
/// with the Recycle Bin turned off, a mapped network drive that has none,
/// an item too big for the bin's quota; a freedesktop trash on a
/// read-only or foreign-uid mount. Those come back as a refusal and the
/// file stays, which is the same answer this reaches on macOS when both
/// routes are out: the platforms differ in how many chances they get, not
/// in what happens when they are spent.
fn trash_delete_bounded(path: &Path) -> Result<(), String> {
    // No `return`: on non-mac targets the macos block below is stripped,
    // making this block the tail expression - a `return` here trips
    // clippy's needless_return on the Linux CI runner, the only clippy
    // that ever compiles this arm.
    #[cfg(not(any(target_os = "macos", target_os = "android", target_os = "ios")))]
    {
        trash::delete(path).map_err(|e| e.to_string())
    }
    // Android and iOS have no system trash; refuse and the file stays,
    // exactly like the other platforms when their routes are spent.
    #[cfg(any(target_os = "android", target_os = "ios"))]
    {
        // This arm can only refuse, so the recoverable route must be OFF
        // by default here - otherwise every delete-the-files-too keeps
        // the payload and reports the row removed. Checked when
        // compiling FOR these targets, which is the only place the
        // question is answerable, so that adding a platform to one list
        // and not the other stops the build rather than shipping the
        // defect a third time.
        const _: () = assert!(
            !trash_suits_this_platform(),
            "a platform whose trash arm can only refuse must not default the route on"
        );
        let _ = path;
        Err("no system trash on this platform".to_string())
    }
    #[cfg(target_os = "macos")]
    {
        if !finder_is_out() {
            match trash_via_finder(path) {
                Ok(()) => return Ok(()),
                Err(e) => {
                    warn!(
                        target: "cleanup",
                        "Finder would not bin {} ({e}) - using the volume's \
                         own Trash from now on",
                        path.display()
                    );
                    FINDER_IS_OUT.store(true, std::sync::atomic::Ordering::Relaxed);
                }
            }
        }
        trash_via_file_manager(path)
    }
}

/// The Finder/AppleScript route, bounded. First choice on macOS because it
/// is the only one that records "Put Back", so a user restoring a wrongly
/// swept file gets it back WHERE IT WAS rather than having to know where
/// that was.
#[cfg(target_os = "macos")]
fn trash_via_finder(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let p = path.to_path_buf();
    match run_bounded(TRASH_DEADLINE, move || {
        let mut ctx = trash::TrashContext::new();
        ctx.set_delete_method(DeleteMethod::Finder);
        ctx.delete(&p).map_err(|e| e.to_string())
    }) {
        Some(r) => r,
        None => {
            warn!(
                target: "cleanup",
                "Finder did not answer within {}s for {} (headless session?)",
                TRASH_DEADLINE.as_secs(),
                path.display()
            );
            Err("timed out".to_string())
        }
    }
}

/// `NSFileManager.trashItemAtURL`, the route Finder cannot refuse on our
/// behalf: it moves the item into the OWNING VOLUME's `.Trashes/<uid>`
/// itself, with no Finder, no AppleScript and no GUI session in the way.
///
/// It exists here because the Finder route fails in ways that have nothing
/// to do with whether a Trash is available:
///  * `-10010` ("Handler can't handle objects of this class") for a path
///    Finder cannot resolve. Seen live on 3 Aug 2026 against a directory
///    on an external volume;
///  * `-1712` (AppleEvent timed out) on a headless session, which used to
///    condemn the whole process to permanent deletes for its lifetime;
///  * an automation permission prompt nobody is there to answer.
///
/// Measured against an external APFS volume on Apple silicon: Finder
/// 259 ms for one directory, this 40 ms, both landing in the volume's own
/// `/Volumes/<vol>/.Trashes/<uid>`. The one thing it does not do
/// is record Put Back (a macOS bug the crate documents), which is why it
/// is the SECOND choice and not the first - a restore is a drag out of the
/// Trash rather than one menu item, and that is a far smaller loss than
/// the delete it replaces.
///
/// Bounded like the Finder call: this one has no interprocess wait to
/// hang on, but a stale network mount can still block a filesystem call,
/// and a bounded failure now means "leave the file", not "destroy it".
#[cfg(target_os = "macos")]
fn trash_via_file_manager(path: &Path) -> Result<(), String> {
    use trash::macos::{DeleteMethod, TrashContextExtMacos};
    let p = path.to_path_buf();
    match run_bounded(TRASH_DEADLINE, move || {
        let mut ctx = trash::TrashContext::new();
        ctx.set_delete_method(DeleteMethod::NsFileManager);
        ctx.delete(&p).map_err(|e| e.to_string())
    }) {
        Some(r) => r,
        None => Err("timed out".to_string()),
    }
}

/// Latched the first time the Finder route fails, for any reason: every
/// later call on this volume - and most likely every later call at all -
/// goes straight to [`trash_via_file_manager`]. Deliberately never reset,
/// like `TRASH_UNRESPONSIVE`: re-probing costs up to `TRASH_DEADLINE` per
/// delete and buys nothing but a Put Back entry.
///
/// Note what this latch does NOT mean: the Trash is still working. Only
/// `TRASH_UNRESPONSIVE` says there is no route at all.
#[cfg(target_os = "macos")]
static FINDER_IS_OUT: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
#[cfg(target_os = "macos")]
fn finder_is_out() -> bool {
    FINDER_IS_OUT.load(std::sync::atomic::Ordering::Relaxed)
}

/// Run `f` on its own thread and give up waiting after `deadline`.
/// `None` means it had not finished in time; the thread keeps running.
///
/// Split out from `trash_delete_bounded` so the give-up path is testable
/// without a Finder to hang: the whole point of this code is the case
/// that cannot be reproduced on a healthy developer machine.
///
/// `test` as well as `macos` in the gate: only the macOS path calls this
/// at runtime, but the tests below cover it on every platform, and
/// without `test` here a Linux or Windows build warns it is unused.
#[cfg(any(target_os = "macos", test))]
fn run_bounded<T: Send + 'static>(
    deadline: std::time::Duration,
    f: impl FnOnce() -> T + Send + 'static,
) -> Option<T> {
    let (tx, rx) = std::sync::mpsc::channel();
    std::thread::spawn(move || {
        // The receiver is gone once we time out; that send failing is the
        // expected outcome, not an error worth surfacing.
        let _ = tx.send(f());
    });
    rx.recv_timeout(deadline).ok()
}

/// Make one Trash call, with the process's FIRST one serialized so a dead
/// Finder is probed once and not once per concurrent caller.
///
/// `TRASH_UNRESPONSIVE` stops a second call paying the deadline - but only
/// once the first has finished paying it. The check and the latch are not
/// atomic, so any two callers that overlap both read it clear, both start
/// a probe, and both pay `TRASH_DEADLINE` in full. A queue soak on a
/// headless bench box caught exactly that: "the Trash is not responding"
/// printed twice in one leg, ~60 s added to a 208 s queue.
///
/// That soak ran before §64, when the finalize sweeps still called the
/// Trash inline, and two jobs finishing together was the way to reproduce
/// it. They park now (`remove_swept_file`), so sweeps are no longer the
/// overlap - but four callers still reach the Trash directly and three of
/// them are on different threads: the `deferred_trash` worker draining its
/// queue, `delete_filed_episode` filing into the user's library, the
/// watch-dir delete in `tasks.rs`, and a sweep whose park failed
/// (read-only tree, EXDEV, no parent) falling back inline. A worker
/// mid-probe while an episode is filed is the same 2 x 30 s.
///
/// So whoever gets here first probes alone and everyone else waits for the
/// verdict instead of asking again. `Err(None)` is that verdict coming
/// back unresponsive: the caller made no call at all and must delete
/// directly. The latch is set before the gate is released, so a waiter
/// always sees it.
///
/// The gate costs a healthy Trash nothing beyond that first call: any
/// answer - even a failure - proves the backend is alive, and from then on
/// the gate is never taken again and deletes run as concurrently as they
/// always did. Deliberately not `cfg(macos)`: only macOS bounds the call,
/// but every platform reads the latch, and `trash::delete` is what it is.
///
/// The call is passed in rather than made here so the tests can supply one
/// that hangs - same reason `run_bounded` is split out. A Finder that does
/// not answer is the one case a healthy developer machine cannot produce.
fn trash_delete_gated(call: impl FnOnce() -> Result<(), String>) -> Result<(), Option<String>> {
    let _gate = if trash_answered() {
        None
    } else {
        let held = FIRST_TRASH_CALL.lock_ok();
        // Settled while we queued: the thread ahead of us got an answer, so
        // there is nothing left to serialize. Hand the gate straight on
        // rather than holding it across our own call.
        if trash_answered() { None } else { Some(held) }
    };
    // The check that got the caller here is stale - the thread ahead of us
    // may have latched the Trash off while we waited on the gate.
    if trash_unresponsive() {
        return Err(None);
    }
    let outcome = call();
    match &outcome {
        Err(e) if looks_like_a_trash_timeout(e) => {
            // Under the gate on purpose: every thread queued behind us
            // reads this the moment it wakes, and skips the Trash.
            TRASH_UNRESPONSIVE.store(true, std::sync::atomic::Ordering::Relaxed);
        }
        _ => TRASH_ANSWERED.store(true, std::sync::atomic::Ordering::Relaxed),
    }
    outcome.map_err(Some)
}

/// The two shapes a Trash call that gave up comes back as: the crate's own
/// wording, and the raw AppleEvent code behind it.
fn looks_like_a_trash_timeout(msg: &str) -> bool {
    msg.contains("timed out") || msg.contains("-1712")
}

/// Held for the duration of the process's first Trash call - see
/// `trash_delete_gated`. Never taken again once `TRASH_ANSWERED` is set.
static FIRST_TRASH_CALL: std::sync::Mutex<()> = std::sync::Mutex::new(());

/// Set once any Trash call has come back, success or ordinary failure:
/// proof the backend answers, and the point past which the first-call gate
/// has nothing left to protect.
static TRASH_ANSWERED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
fn trash_answered() -> bool {
    TRASH_ANSWERED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Latched when a Trash call gives up waiting - and on macOS only once
/// BOTH routes have (`trash_delete_bounded` falls through to
/// `NSFileManager` before it reports a failure at all). Deliberately never
/// reset: a backend that timed out once will do it again, and each probe
/// costs up to `TRASH_DEADLINE` of a live job.
///
/// Read publicly as "is a recoverable delete actually available", which is
/// why a Finder failure must not set it: `FINDER_IS_OUT` covers that, and
/// the volume's own Trash still works.
static TRASH_UNRESPONSIVE: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(false);
pub fn trash_unresponsive() -> bool {
    TRASH_UNRESPONSIVE.load(std::sync::atomic::Ordering::Relaxed)
}

/// The `$TMPDIR` exemption [`under_temp_dir`] hands to a test that asks,
/// written only by `testseam::force_temp_trash` and DEFAULT OFF, so the
/// binary an integration test spawns - which carries this crate's
/// `test-support` feature whether it wants to or not - behaves exactly
/// as a shipped one does.
static TEMP_TRASH_FORCED: std::sync::atomic::AtomicBool = std::sync::atomic::AtomicBool::new(false);
/// The read side of [`TEMP_TRASH_FORCED`], for `under_temp_dir`.
fn temp_trash_forced() -> bool {
    TEMP_TRASH_FORCED.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where a sweep of `dir` parks recoverable deletes: a hidden folder
/// BESIDE the swept directory, so the park is a same-volume rename.
///
/// Beside, not inside, for two reasons that are both load-bearing. Inside
/// the swept tree the sweep's own one-level descent would walk into it and
/// re-delete what it just parked. And `finalize_names` may move the whole
/// job directory (onto a NAS, into a season folder) the moment the sweep
/// returns - a parked file must stay put while that happens, or the queued
/// path goes stale and the junk rides along into the library.
/// pub(crate): the engine-side sweeps (spent obfuscated volumes in
/// unpack/obfuscated.rs, consumed adoption sources in get/settle/noset.rs and
/// get/tail.rs) park the same way the finalize sweeps do, for the same
/// §64 reason - their deletes run in a job's tail, and an inline Trash
/// call is a Finder wait the job pays.
pub fn trash_staging_dir(dir: &Path) -> Option<PathBuf> {
    Some(dir.parent()?.join(".nzbfast-trash"))
}

/// The sweeps' delete: like `remove_user_file`, but a recoverable delete
/// is parked in `staging` for the background worker instead of talking to
/// the Trash inline. The rename is what actually empties the job
/// directory, and it is instant - so a slow Finder can no longer hold
/// `finalize_completed` (and with it the job's history entry) hostage.
/// See §64: the first Trash call of a headless process used to cost the
/// finalize path 30 s, and before the bound, minutes per file.
///
/// Any staging failure (no parent, EXDEV, a read-only tree) falls through
/// to the inline delete, which still works everywhere it used to.
pub fn remove_swept_file(
    path: &Path,
    recoverable: bool,
    staging: Option<&Path>,
) -> std::io::Result<Removed> {
    // When the latch is set there is no Trash to park FOR: the inline path
    // refuses and leaves the file, and a staging folder full of files
    // nobody will ever dispose of is worse than the file where it was.
    if recoverable
        && !trash_unresponsive()
        && let Some(root) = staging
        && deferred_trash::stage(path, root).is_ok()
    {
        // Staged, not yet disposed of. The worker decides the real
        // outcome later, so this promises nothing: the sweeps that use
        // this path do not report a fate to the user.
        return Ok(Removed::Gone);
    }
    remove_user_file(path, recoverable)
}

// What a filed TV episode is CALLED, and how to recognise one on disk -
// the TV filing target, the episode-title/quality tail, and the
// which-files-are-this-episode questions Play and delete-with-files ask
// of a shared season folder - is a child module (TODO 106 size-gate
// split). Every public and crate-visible door is re-exported, so
// `smart::tv_path` and friends are spelled exactly as they always were.
mod episode;
pub use crate::relname::flatten_name;
pub use episode::{
    EpisodeTitles, FiledDelete, FiledTail, delete_filed_episode, filed_title_segment,
    find_filed_episode_media, tv_path,
};
pub use episode::{filed_bases, is_filed_episode_file};
// Not re-exported: `legacy_tv_path` is filing.rs's alone and is spelled
// `super::episode::legacy_tv_path` there, and the four below are reached
// only by the child test modules through `use super::*`. A private
// `use` keeps them out of `smart`'s surface while leaving every spelling
// in those modules unchanged - and it is `#[cfg(test)]` because that is
// the only build in which anything reads them.
#[cfg(test)]
use episode::{COMPONENT_BYTES, TITLE_SEP, is_rename_tail, reads_as_episode_number};

// Naming and filing a finished job's output - TV organize/rename and the
// three doors that give a name to a payload that arrived without one -
// is a child module (TODO 106 size-gate split). The six public doors are
// re-exported, so every `smart::tv_organize` spelling is unchanged.
mod filing;
pub use filing::{
    nameless_video, rename_movie, rename_nameless_video, rename_obfuscated_video, tv_organize,
    tv_rename,
};

// Moving a finished job to its destination - the rename, the staged copy
// it falls back to across filesystems, and the durability calls under
// both - is a child module (TODO 106 size-gate split). The five public
// doors are re-exported, so `smart::move_tree` and friends are spelled
// exactly as they always were.
mod movetree;
pub use movetree::{PaceFn, copy_tree, dst_is_src_or_inside, move_tree, move_tree_paced, sync_dir};

/// One background worker owns every conversation with the Trash, so no
/// job's finalize ever waits on Finder. See the module for the whole
/// rationale; it lives in its own file under the §91 rule.
mod deferred_trash;

/// Is the Trash somewhere the user can actually find and empty?
///
/// On macOS and Windows, yes: one Trash, one Recycle Bin, both in front
/// of the person the recoverability is for.
///
/// On Linux, no - and worse than no. When the download volume is not the
/// volume the home trash lives on (which is every NAS, every container,
/// every seedbox), the freedesktop rules send the file to a
/// `.Trash-<uid>` directory the crate CREATES at the top of the download
/// volume. So "recoverable" quietly means "moved to another folder on
/// the same disk, forever": the space never comes back, nothing in the
/// UI says where it went, and no desktop is running to empty it. It cost
/// a user their SSD a directory at a time, reported from Unraid on
/// 2 Aug 2026, and they left for another downloader over it.
///
/// So the recoverable default follows the platform, and Linux installs
/// delete outright unless the operator turns `delete_to_trash` back on.
/// Cleanup still tells the log what it removed either way.
///
/// FreeBSD is in the same carve-out for the same reason, not by analogy:
/// the `trash` crate routes every unix except macOS through its one
/// freedesktop backend, so a FreeBSD install reaches the identical
/// `.Trash-<uid>`-on-the-download-volume code, and the population that
/// runs nzbfast on FreeBSD - NAS boxes, jails, headless servers - is the
/// population with no desktop session to ever empty it.
///
/// Android and iOS are excluded too, and for a DIFFERENT KIND of reason
/// that must not be folded into the carve-out above. Linux and FreeBSD
/// are a POLICY choice: the route works there, and we decline it. These
/// two are a CAPABILITY fact - `trash_delete_bounded`'s arm for them can
/// only ever return `Err`, because the platform has no system trash to
/// move anything into. Leaving the route on there does not degrade to a
/// plain delete: `trash_attempt` returns `Refused`, `remove_user_dir`
/// turns that into an `Err`, and the caller keeps the payload, drops the
/// history row and tells the user to turn off a dashboard setting the
/// phone app does not even show. Measured at 40 MB kept on the Android
/// emulator (26 Aug 2026) and 38 MB on iOS (27 Aug 2026), both behind a
/// delete that answered `{"removed":1,"status":true}`.
///
/// TODO 281 AN3 patched only the Android half, by setting
/// `NZBFAST_NO_TRASH=1` in the launcher's CHILD-PROCESS environment. That
/// hook does not generalise: iOS runs the engine IN-PROCESS through
/// `nzbfast-ffi`, so there is no child environment to set, and the same
/// engine shipped the same defect on the second platform. Hence the fix
/// belongs here, in the engine, where it is a fact about the target
/// rather than something each launcher has to remember.
const fn trash_suits_this_platform() -> bool {
    !cfg!(any(target_os = "linux", target_os = "freebsd")) && !platform_has_no_system_trash()
}

/// The platforms with no system trash AT ALL, named once so the default
/// above and the refusing arm of `trash_delete_bounded` cannot drift
/// apart - which is exactly how they were shipped: this predicate said
/// those two platforms had a trash while that arm said they did not.
const fn platform_has_no_system_trash() -> bool {
    cfg!(any(target_os = "android", target_os = "ios"))
}

/// Process-global so the free functions in here need no Daemon handle.
///
/// Defaults OFF under `cfg(test)`: the cleanup suites delete hundreds of
/// fixture files, and with the Trash on they would empty them into the
/// developer's real ~/.Trash and race each other through this one flag;
/// the test that covers the Trash path opts in explicitly.
///
/// `cfg!(test)` AND NOT `feature = "test-support"`, for [`under_temp_dir`]'s
/// reason: a `test-support` term here reads TRUE in the binary an
/// integration test spawns, and this default IS the user-visible
/// platform behaviour that
/// `settings_catalogue::the_trash_default_follows_the_platform` reads out
/// of a freshly launched daemon.
///
/// What the crate-split step 3 cut means for it: `crates/nzbfast`'s unit
/// tests compile this crate as an ordinary dependency, so this term is
/// false there and they run with the flag ON. That is SAFE and is not an
/// oversight - the cleanup suites this note is about are `smart`'s own
/// and moved down here with it, where `cfg!(test)` still holds, and
/// [`under_temp_dir`] forces every `$TMPDIR` path permanent in any build
/// where this term does not fire. The belt is the runtime guard, not the
/// flag.
static TRASH: std::sync::atomic::AtomicBool =
    std::sync::atomic::AtomicBool::new(!cfg!(test) && trash_suits_this_platform());
pub fn set_delete_to_trash(on: bool) {
    TRASH.store(on, std::sync::atomic::Ordering::Relaxed);
}
pub fn delete_to_trash() -> bool {
    TRASH.load(std::sync::atomic::Ordering::Relaxed)
}

/// Where CLEANUP deletes go - the garbage class: spent archive volumes
/// after a successful unpack, consumed adoption sources, sniffed
/// recovery files, and the junk sweep. Separate from `delete_to_trash`
/// (which keeps governing deletes of the downloads THEMSELVES - queue
/// and history deletes, watchlist upgrades, library episode drops)
/// because the two classes pull opposite ways: garbage is high-volume
/// and worthless-by-verdict (50 GB of spent volumes fills a Trash
/// nobody empties), while a deleted download is the user's own data.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum CleanupMode {
    /// Ride `delete_to_trash`, exactly the pre-setting behavior.
    Follow,
    /// Always recoverable, even when download deletes are permanent.
    Trash,
    /// Always permanent, even when download deletes go to the Trash.
    Delete,
}

impl CleanupMode {
    pub fn as_str(self) -> &'static str {
        match self {
            CleanupMode::Follow => "follow",
            CleanupMode::Trash => "trash",
            CleanupMode::Delete => "delete",
        }
    }
    pub fn parse(v: &str) -> Option<CleanupMode> {
        match v {
            "follow" => Some(CleanupMode::Follow),
            "trash" => Some(CleanupMode::Trash),
            "delete" => Some(CleanupMode::Delete),
            _ => None,
        }
    }
}

/// Process-global like `TRASH`, for the same reason. 0=follow 1=trash
/// 2=delete; default `follow` so an upgrade changes nobody's behavior.
static CLEANUP_MODE: std::sync::atomic::AtomicU8 = std::sync::atomic::AtomicU8::new(0);
pub fn set_cleanup_mode(m: CleanupMode) {
    let v = match m {
        CleanupMode::Follow => 0,
        CleanupMode::Trash => 1,
        CleanupMode::Delete => 2,
    };
    CLEANUP_MODE.store(v, std::sync::atomic::Ordering::Relaxed);
}
pub fn cleanup_mode() -> CleanupMode {
    match CLEANUP_MODE.load(std::sync::atomic::Ordering::Relaxed) {
        1 => CleanupMode::Trash,
        2 => CleanupMode::Delete,
        _ => CleanupMode::Follow,
    }
}

/// The `recoverable` flag a GARBAGE sweep should pass to
/// [`remove_user_file`] / [`remove_swept_file`]. Read once at a sweep's
/// entry, same contract as `delete_to_trash`.
pub fn cleanup_recoverable() -> bool {
    match cleanup_mode() {
        CleanupMode::Follow => delete_to_trash(),
        CleanupMode::Trash => true,
        CleanupMode::Delete => false,
    }
}

/// A scrap left inside an archive: no extension at all, and far too small
/// to be anything a user asked for, sitting next to an identified feature.
///
/// Found via a Supergirl release whose junk sweep left a 56-byte file
/// called `GqRTzbOIvUzZg1hqbipRind85vn` beside a 20 GB mkv. It is not in
/// the nzb - every POSTED file there is `30fb7ada….NN` or `.par2`, fully
/// obfuscated - so it came out of the RAR, packed by whoever made the
/// release. Nothing else in `sweep_junk` could see it: no extension to
/// match, not PAR2 magic, and not sample-shaped.
///
/// Kept deliberately narrow, because this is the rule most likely to eat
/// something real:
///  * no extension WHATSOEVER - an unknown extension is somebody's file,
///    and a subtitle or a companion track always has one;
///  * a hard byte ceiling, not a ratio - "small next to a 20 GB feature"
///    would cover a 20 MB file;
///  * only where a feature video was actually identified, so this cannot
///    fire on a music, book or software release, which is exactly where
///    extensionless files are legitimate;
///  * never anything that starts with an archive or media magic number,
///    however small.
fn is_nameless_scrap(p: &Path, ext: &str, feature_len: u64, recoverable: bool) -> bool {
    // ONLY when the delete can be undone. `sweep_junk_drops_extensionless_par2_by_magic`
    // pins the opposite rule - a hash-named blob that is NOT par2 stays,
    // because the magic decides and not the shape of the name - and that
    // invariant was written when a wrong guess was permanent. It still
    // holds wherever it still matters: with the Trash off (NAS, container)
    // this rule is simply not applied, and behaviour is exactly as before.
    if !recoverable || !ext.is_empty() || feature_len == 0 {
        return false;
    }
    let Ok(md) = std::fs::metadata(p) else {
        return false;
    };
    if md.len() > 4096 {
        return false;
    }
    let mut head = [0u8; 8];
    let read = std::fs::File::open(p)
        .and_then(|mut f| {
            use std::io::Read;
            f.read(&mut head)
        })
        .unwrap_or(0);
    let head = &head[..read];
    const MAGIC: &[&[u8]] = &[
        b"Rar!",
        b"PK\x03\x04",
        b"7z\xbc\xaf",
        b"\x1f\x8b",
        b"BZh",
        b"\xfd7zXZ",
        b"\x1aE\xdf\xa3",
        b"RIFF",
        b"%PDF",
        b"\x89PNG",
        b"\xff\xd8\xff",
        b"ID3",
    ];
    !MAGIC.iter().any(|m| head.starts_with(m))
}

/// Auto-rename companion: remove usenet furniture (`.par2`/`.nzb`/`.sfv`/
/// `.nfo`/…, see `JUNK_EXTS`) and sample/proof clips left beside the media,
/// top level + one subdir deep. Never deletes a subtitle, and never the
/// main feature (the largest video) - so a film literally titled "Sample"
/// survives. Returns how many files went.
pub fn sweep_junk(dir: &Path) -> usize {
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    let keep = largest_video(dir);
    // What the SET says, before anything is classified by what the NAME
    // says (matrix row M4-54). After a set succeeds, FileDesc can publish
    // the feature under any name the poster chose, `Great.Movie.nfo`
    // included - and `nfo`/`txt`/`md5` are all on `JUNK_EXTS`. The
    // all-junk guard below cannot save it: one real `trailer.mp4` beside
    // it is `largest_video`, survivors is non-zero, and the sweep deletes
    // the payload the recovery set itself declares.
    //
    // A FileDesc is the strongest statement anyone posted about whether a
    // file belongs to this release, and an extension is the weakest
    // evidence in the tree. Deletion being the strongest action here, the
    // set outranks the extension - the same ordering
    // `wave4-fix-exact-name-authority` (2b7f5495e) settled one layer up.
    //
    // WHAT THIS DOES NOT DO, said rather than left to be found: it does
    // not spare a file for being small, or for being an `.nfo` beside a
    // set. `release.nfo` in the ordinary scene post is not in anyone's
    // recovery set and still goes; the sweep's behaviour on every release
    // whose PAR2 covers only its archive volumes is unchanged, because
    // after extraction those volumes no longer exist and the set declares
    // no surviving path. A poster who DID cover their `.nfo` keeps it,
    // which is the trade: an extra info file the user can delete, against
    // a payload they cannot get back.
    //
    // Read once, ahead of the walk, so the classifier below asks a
    // HashSet rather than re-reading a recovery set per candidate.
    let declared = setclaim::set_declared_paths(dir);
    // The sweep's whole footprint, read ONCE before anything is deleted,
    // so `is_deletable_sample`'s sibling test sees the release as it
    // stands rather than as this pass has already left it - and cannot
    // depend on `read_dir` order. See that function for what it costs.
    let siblings = files_in_reach(dir);
    let keep_len = keep
        .as_ref()
        .and_then(|p| p.metadata().ok())
        .map(|m| m.len())
        .unwrap_or(0);
    // Classify the whole sweep footprint BEFORE deleting any of it, so the
    // all-junk guard below can see the release as it stands rather than as
    // the sweep has already left it.
    let classify = |d: &Path, doomed: &mut Vec<PathBuf>, survivors: &mut usize| {
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            if keep.as_ref() == Some(&path) {
                *survivors += 1;
                continue;
            }
            // The set's own members are payload by declaration - see the
            // note at `declared` above. Checked BEFORE the extension,
            // the sample rule and the scrap rule alike, because every
            // one of them is an inference from the name or the size and
            // this is the poster's statement about the file itself.
            if declared.contains(&path) {
                *survivors += 1;
                continue;
            }
            let ext = ext_of(&path);
            // Magic sniff only where the name has already failed to
            // identify the file: never open a video or a subtitle, so a
            // payload can't be reached by this path however it decodes.
            let sniffable =
                !VIDEO_EXTS.contains(&ext.as_str()) && !SUBTITLE_EXTS.contains(&ext.as_str());
            let junk = JUNK_EXTS.contains(&ext.as_str())
                || (sniffable && par2_magic(&path))
                || is_deletable_sample(&path, keep_len, &siblings)
                || is_nameless_scrap(&path, &ext, keep_len, recoverable);
            if junk {
                doomed.push(path);
            } else {
                *survivors += 1;
            }
        }
    };
    let mut doomed: Vec<PathBuf> = Vec::new();
    let mut survivors = 0usize;
    classify(dir, &mut doomed, &mut survivors);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                classify(&path, &mut doomed, &mut survivors);
            }
        }
    }
    // A sweep that would delete EVERY file in the release does nothing.
    //
    // This function's premise is "keep the payload, drop the furniture
    // beside it" - and when every file it can see is furniture, the
    // premise does not hold: there is nothing here it can tell payload
    // FROM. Exactly the guard `keep_media_only` already applies when it
    // finds no video, and for the same reason. The shapes this bites are
    // real: a release whose whole payload is a text file (found 12 Aug on
    // the torture corpus, where the SFX set unpacked correctly and then
    // lost `test.txt.txt` to the `.txt` entry in JUNK_EXTS), an info-only
    // post, a release that is nothing but its own recovery set. An empty
    // output directory is a worse answer than one file the user can
    // delete, and unlike the delete it is not something they can undo.
    //
    // Deliberately all-or-nothing rather than "keep the largest": ranking
    // furniture invents a payload the sweep has no way to identify, and
    // leaves the other files gone. Skipping says what actually happened.
    if survivors == 0 && !doomed.is_empty() {
        info!(
            target: "cleanup",
            "junk sweep skipped in {}: all {} file(s) look like furniture, \
             and emptying the release is never the right answer",
            dir.display(),
            doomed.len()
        );
        prune_empty_dirs(dir, 0);
        return 0;
    }
    let mut removed = 0;
    for path in doomed {
        match remove_swept_file(&path, recoverable, staging.as_deref()) {
            Ok(_) => {
                info!(target: "cleanup", "junk {}", path.display());
                removed += 1;
            }
            Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
        }
    }
    prune_empty_dirs(dir, 0);
    removed
}

/// Aggressive cleanup: delete everything in `dir` that is NOT a video, a
/// subtitle / companion-track file, or a still-packed archive (top level +
/// one subdir deep). Keeps ALL real videos - a season pack stays whole -
/// but drops sample/proof clips. Returns the number of files removed.
///
/// A job with no video at all is left completely alone: see the guard.
pub fn keep_media_only(dir: &Path) -> usize {
    let mut removed = 0;
    // Read once, for the whole sweep: see `remove_user_file`.
    let recoverable = cleanup_recoverable();
    let staging = trash_staging_dir(dir);
    // The feature size gates sample deletion: a same-size episode in a
    // "Proof"/"Sample" season pack is kept, only a small teaser is dropped.
    let Some(feature) = largest_video(dir) else {
        // No video anywhere in the job, so this function's premise - "keep
        // the media, drop the clutter beside it" - does not hold: there is
        // nothing here it can tell payload from clutter BY, so a music
        // album, an audiobook, a comic or an ebook release would be
        // deleted in full and the job would still report Completed over an
        // empty folder. Reached whenever a user category with base Movie
        // or Tv holds non-video content, which is most of them.
        //
        // This guard is necessary but NOT sufficient: one bonus .mp4 in
        // such a job passes it. That is what PAYLOAD_EXTS is for.
        info!(
            target: "cleanup",
            "keep-media-only: no video in {} - left alone",
            dir.display()
        );
        return 0;
    };
    let feature_len = feature.metadata().map(|m| m.len()).unwrap_or(0);
    // Once for the whole sweep, before the first delete: see `sweep_junk`.
    // This pass removes as it walks, so a per-directory list would give a
    // teaser judged late fewer relatives than one judged early.
    let siblings = files_in_reach(dir);
    // M4-54, the rule `sweep_junk` reads and this one did not (sweep
    // finding 7, 31 Aug 2026): a declared sidecar HAS an extension, so
    // `looks_like_video_bytes` never opens it and this delete took the
    // payload of a poster who named the feature `Great.Movie.nfo`.
    let declared = setclaim::set_declared_paths(dir);
    let mut sweep = |d: &Path| {
        // Once per directory, not once per file: split sets are only
        // recognisable as sets.
        let zip_parts = zip_part_set(d);
        let mut split_parts = crate::container_part_set(d);
        split_parts.extend(crate::split_part_set(d)); // both readings, see `is_packed_archive`
        // A cue sheet names its own track data, so read the sheets once
        // and let them speak for their siblings: see `discimage`.
        let cue_named = discimage::cue_named_files(d);
        let Ok(rd) = std::fs::read_dir(d) else { return };
        for entry in rd.flatten() {
            let path = entry.path();
            if !is_real_file(&path) {
                continue;
            }
            // The daemon's own namespace, never the job's: `.nzbfast.journal`
            // is the live resume record and `.nzbfast.manifest` the settle
            // checksums a later verify reads. Neither is media nor companion
            // nor archive, so without this line the categorical sweep deletes
            // both - and it is the only directory walker in the tree that did
            // not already honour the prefix (diag.rs, repair.rs, unpack.rs and
            // the extract diff walkers all do). It bites on the SECOND pass:
            // an unlock re-runs the whole tail over a directory the first pass
            // already wrote them into.
            if path
                .file_name()
                .is_some_and(|n| n.to_string_lossy().starts_with(".nzbfast"))
            {
                continue;
            }
            // The poster's own statement about this file, and the
            // strongest one anyone made - see `declared` above.
            if declared.contains(&path) {
                continue;
            }
            let ext = ext_of(&path);
            let is_media = VIDEO_EXTS.contains(&ext.as_str())
                && !is_deletable_sample(&path, feature_len, &siblings);
            // Subtitles plus the disc-structure / companion-track files a
            // video payload is incomplete without - see MEDIA_COMPANION_EXTS.
            // An optical-disc image is payload the same way a video
            // file is, and `.cue` sat in PAYLOAD_EXTS while `.bin` sat
            // in no list at all - so a CD image posted as the pair it
            // is ALWAYS posted as kept its index and lost its disc,
            // over a Completed job, with no copy anywhere (M4-88).
            let is_companion = SUBTITLE_EXTS.contains(&ext.as_str())
                || MEDIA_COMPANION_EXTS.contains(&ext.as_str())
                || PAYLOAD_EXTS.contains(&ext.as_str())
                || discimage::is_disc_payload(&path, &ext, &cue_named);
            // An archive still sitting here is payload we could not
            // unpack, not clutter - see `is_packed_archive`. An
            // extensionless file that opens like a video is payload too,
            // just unpacked - see `looks_like_video_bytes`.
            if is_media
                || is_companion
                || is_packed_archive(&path, &zip_parts, &split_parts)
                || looks_like_video_bytes(&path)
            {
                continue;
            }
            match remove_swept_file(&path, recoverable, staging.as_deref()) {
                Ok(_) => {
                    info!(target: "cleanup", "non-media {}", path.display());
                    removed += 1;
                }
                Err(e) => warn!(target: "cleanup", "{}: {e}", path.display()),
            }
        }
    };
    sweep(dir);
    if let Ok(rd) = std::fs::read_dir(dir) {
        for entry in rd.flatten() {
            let path = entry.path();
            if is_real_dir(&path) {
                sweep(&path);
            }
        }
    }
    prune_empty_dirs(dir, 0);
    removed
}

// ---------------------------------------------------------------------------
// M24 passworded archives (the survey's #2 Usenapp borrow)
// ---------------------------------------------------------------------------

// One password per line. Moved to `crate::pwfile` in the crate-split
// prep, beside the setting that names the file; re-exported here for the
// settings path that still spells it `smart::read_password_file`.
pub use crate::pwfile::read_password_file;

// The unlock ladder - `encrypted_archive`, `unlock` and the non-RAR
// shapes under it - is `crate::unlockpw` since the crate-split prep, and
// the operator's passwords file is `crate::pwfile`. Neither is
// re-exported here: nothing in this module spends a password, and the
// callers are all in the daemon.

// §99: the try-order heuristic over that file - remember which
// password unlocked which site's / poster's downloads and try the
// likely line first.
mod pwassoc;
pub use pwassoc::{dominant_poster, nzb_poster, order_passwords, record_password_assoc};

// M4-81: the walk that answers "which file is the movie". Its own
// file for `sample`'s reason below - smart.rs sits under a size-gate
// baseline (TODO 106) - and because the depth it reaches, and why it
// is not the depth the sweeps that call it reach, is the whole
// subject rather than a detail of one.
mod feature;
use feature::largest_video;
// Child module files, not inline: the cases below were most of this
// file's length and smart.rs sits under a size-gate baseline (TODO
// 106), same pattern as cleanup_mode_tests.rs. Two of them because one
// was 3,264 lines - over the gate's own ceiling - so the split is by
// topic: filing and the mover in `tests`, sweeping and renaming in
// `sweep_rename_tests`, with what both need in `testkit`.
mod sample;
pub use sample::skippable_samples;
use sample::{is_deletable_sample, is_sample_named};
mod audioname;
pub use audioname::rename_obfuscated_audio;
mod videoext;
use videoext::video_ext;
// M4-88: optical-disc images and the cue sheet that names one. Its own
// file because smart.rs sits under a size-gate baseline (TODO 106).
mod discimage;
// M4-54 / M4-68: what the SET says against what the NAME says. Its own
// file because smart.rs sits under a size-gate baseline (TODO 106), and
// because the two rules it holds are one idea - see its module note.
mod setclaim;

// `main_video` composed with `identity::container_title`. Its own file
// because the two halves are in two CRATES since the crate-split step 2
// cut, so `identity`'s own test module can no longer reach this one.
#[cfg(test)]
mod container_title_tests;
#[cfg(test)]
mod sweep_rename_tests;
#[cfg(test)]
mod testkit;
// The trash tests' process-global serialisation and the shared PAR2
// index writer. Both lived in `testkit` while this crate and the bin
// were one, and their callers are spread across smart's four test
// children AND `tests_jobs.rs` / `naming/authority_tests.rs`
// - a CRATE away since the step 3 cut, where a `cfg(test)` item is
// invisible whatever its visibility. So they sit in `testseam`, gated on
// `test-support` as well, and are re-exported here so every one of those
// callers keeps reaching them at the path it always used.
#[cfg(any(test, feature = "test-support"))]
pub mod testseam;
#[cfg(any(test, feature = "test-support"))]
pub use testseam::{
    force_temp_trash, force_trash_unresponsive, one_trash_test_at_a_time, par2_index,
    trash_globals_steady,
};
#[cfg(test)]
mod tests;

#[cfg(test)]
mod trash_tests;

/// Put the configured permissions on a finished download (#20).
///
/// `umask` is the same number the shell and the linuxserver containers
/// use, because that is what every guide about this prints: directories
/// get `0o777 & !umask`, files `0o666 & !umask`, so the recommended `002`
/// gives 775/664 and today's `0022` gives 755/644.
///
/// `root` is the job's final directory and is walked in full. `up_to` is
/// the download root, and the directories BETWEEN the two get the
/// directory mode as well - non-recursively, so nothing else living under
/// them is touched. That part is not decoration: to import by renaming,
/// an *arr has to unlink the job directory out of its parent, and unlink
/// needs write permission on the PARENT, not on the directory being
/// moved. Setting only the job's own tree produces a download the *arr
/// can read and still cannot import.
///
/// Errors are logged once and otherwise swallowed. A mode we could not
/// set is a slower import, while refusing to finish the job over it would
/// turn a permissions preference into a failed download.
#[cfg(unix)]
pub fn apply_out_umask(root: &std::path::Path, up_to: Option<&std::path::Path>, umask: u32) {
    use std::os::unix::fs::PermissionsExt;
    let dir_mode = 0o777 & !umask;
    let file_mode = 0o666 & !umask;
    let mut failed: Option<String> = None;
    let mut chmod = |p: &std::path::Path, mode: u32| {
        if let Err(e) = std::fs::set_permissions(p, std::fs::Permissions::from_mode(mode))
            && failed.is_none()
        {
            failed = Some(format!("{}: {e}", p.display()));
        }
    };
    // The job's own tree.
    let mut stack = vec![root.to_path_buf()];
    while let Some(dir) = stack.pop() {
        chmod(&dir, dir_mode);
        let Ok(rd) = std::fs::read_dir(&dir) else {
            continue;
        };
        for ent in rd.flatten() {
            let p = ent.path();
            // symlink_metadata: never follow a link out of the tree and
            // re-mode whatever it points at.
            match std::fs::symlink_metadata(&p) {
                Ok(m) if m.is_dir() => stack.push(p),
                Ok(m) if m.is_file() => chmod(&p, file_mode),
                _ => {}
            }
        }
    }
    // ...and every directory between it and the download root, so the
    // *arr can rename the job out of the one holding it.
    if let Some(stop) = up_to {
        let mut cur = root.parent();
        while let Some(p) = cur {
            if !p.starts_with(stop) {
                break;
            }
            chmod(p, dir_mode);
            if p == stop {
                break;
            }
            cur = p.parent();
        }
    }
    if let Some(first) = failed {
        tracing::warn!(target: "disk", "could not set output permissions ({first})");
    }
}

/// Windows has no mode bits; the setting is stored and reported so a
/// config survives a round trip through either platform.
#[cfg(not(unix))]
pub fn apply_out_umask(_root: &std::path::Path, _up_to: Option<&std::path::Path>, _umask: u32) {}

#[cfg(all(test, unix))]
mod out_umask_tests;

// Child module file, not inline: smart.rs sits under a size-gate
// baseline (TODO 106) and test growth belongs beside it, same pattern
// as pool/unit_tests.rs.
#[cfg(test)]
mod cleanup_mode_tests;

// TODO 142 / issue #32: naming a finished job after its .nzb file, and
// the folder rename it shares with `rename_movie`. A production child
// module for the same size-gate reason.
pub mod nzbname;
pub use nzbname::rename_from_nzb;
