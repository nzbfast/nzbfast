//! `[naming]`, plane 7.A: what the wire says a file is called, and
//! therefore what the client has to end up calling it.
//!
//! Four independent selections, and the whole point of keeping them
//! independent is that the interesting layouts are the combinations.
//! `wire` decides the yEnc `name=` value, `subject` decides whether the
//! Subject and From headers link the files of one post to each other or
//! to anything at all, `part_order` decides whether part indices arrive
//! in their natural order, and `name_bytes` decides whether the name is
//! UTF-8 (N7 raw bytes is chip 10's, and is refused by name until then).
//!
//! **Where the tree goes.** A source file named `sample/s.bin` is one
//! file under one directory, and an ordinary post puts the BASENAME on
//! the wire: `nzbkit::post::plan_with` splits exactly this way and says
//! why at [`nzbkit::post::PlanFile::rel`] - the tree is out-of-band by
//! construction, which is what makes it survive obfuscation. So with no
//! container and no recovery set there is no carrier for the directory
//! part at all, and the honest expectation is that the client ends with
//! a flat file. That is not a gap: a tree that was never posted cannot
//! be recovered, and asserting otherwise would fail every client on
//! earth. N8's tree materialisation is the RECOVERY plane's to prove
//! (P1 and up carry `rel` in their FileDesc packets), which is chip 05.
//!
//! **What [`Plan::final_name`] must never become.** It is the name the
//! oracle asserts the client ends with, and it is derived from what the
//! layout actually carries. The moment it is derived from what the
//! client happens to do instead, the catalog stops being a set of
//! requirements and becomes a set of screenshots.

use crate::assemble::SourceFile;
use crate::profile::{NameBytes, PartOrder, Profile, RecoveryNames, SubjectStyle, WireName};
use crate::recovery::RecoveryFile;
use crate::rng::Rng;

/// The From header of a post whose headers are not being varied.
///
/// `.invalid` is RFC 2606's reserved TLD: it is guaranteed never to
/// resolve, so nothing here can be mistaken for, or accidentally
/// addressed to, a real poster. The catalog ships publicly and a real
/// address in it would be a real address in it for as long as the repo
/// exists.
pub const POSTER: &str = "poster@postfast.invalid";

/// The group every generated layout is posted into. `alt.binaries.test`
/// is one of the two names the catalog README admits; a real binary
/// group name in a public repo names somebody's actual post.
pub const GROUP: &str = "alt.binaries.test";

/// The naming decisions for one file.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct FileNaming {
    /// The source file's relative path, carried through untouched so a
    /// later plane (a recovery set's FileDesc packets) can describe the
    /// file under its real name and its real directory.
    pub rel: String,
    /// The name the SUBJECT quotes when the subject is descriptive.
    /// The real basename under N1, a token under N2, and still the real
    /// basename under N3 - N3 empties `name=`, which is precisely the
    /// shape that leaves the subject and the NZB as the only carriers.
    pub posted: String,
    /// The yEnc `name=` value. Equal to [`FileNaming::posted`] under N1
    /// and N2, and empty under N3.
    pub yenc: String,
    /// The From header for this file's articles. Constant under N1, a
    /// per-file address under N5, where a shared poster would be
    /// exactly the cross-file linkage N5 exists to remove.
    pub poster: String,
    /// N5 furniture: the token a neutral subject carries instead of a
    /// name. `None` when the subject is descriptive.
    pub subject_token: Option<String>,
    /// The name the client must end with: the name this layout
    /// actually CARRIES, which is the whole of what an expectation may
    /// be derived from. The real basename when a descriptive name is on
    /// the wire or in the subject; the token when the layout is opaque,
    /// because a real name that was never posted cannot be recovered
    /// and asserting it would fail every client on earth. See the
    /// module header for why it is never the relative path while
    /// nothing carries a directory.
    pub final_name: String,
}

/// The naming plane's answer for a whole post.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Plan {
    /// The release title a multi-file descriptive post prefixes its
    /// subjects with (`title [2/5] - "file" yEnc (1/4)`). `None`
    /// whenever a title would either say nothing or say too much; see
    /// [`title_for`].
    pub title: Option<String>,
    pub files: Vec<FileNaming>,
    /// N6: whether part indices are shuffled. Carried here rather than
    /// read off the profile again downstream, so the encoder has one
    /// place to look and the plane cannot be half-applied.
    pub reorder_parts: bool,
}

/// Why a naming plan could not be made.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum NamingError {
    /// Two source files would end under one name, so the expectation
    /// the oracle asserts would be ambiguous before the client is even
    /// started. Reachable today only with no name carrier at all
    /// (`a/x.bin` and `b/x.bin` both post as `x.bin`); a recovery set
    /// resolves it by describing each under its relative path, which is
    /// exactly what N8's "flat lookalikes" row is for.
    FinalNameCollision {
        name: String,
        first: String,
        second: String,
    },
    /// The layout carries no name anywhere: `name=` is empty (N3) and
    /// the subject is furniture (N5), with nothing out of band. There
    /// is no name to expect, so there is no expectation to derive, and
    /// a generator that invented one would be writing the client's
    /// answer into the requirement. A recovery set makes the same
    /// combination legal and interesting (P3, names from FileDesc
    /// packets alone), which is the recovery plane's chip.
    NoNameCarrier,
    /// N7, raw non-UTF-8 name bytes. The article map is keyed by
    /// message-id and holds bytes, so the shape is emitable, but the
    /// name has to survive as bytes through the subject, the NZB and
    /// the expectation, and doing half of that is worse than not
    /// starting. Chip 10 owns it.
    RawNameBytesNotImplemented,
}

impl std::fmt::Display for NamingError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::FinalNameCollision {
                name,
                first,
                second,
            } => write!(
                f,
                "[source] {first:?} and {second:?} would both end as {name:?}: this layout \
                 carries no directory anywhere, so the expectation would be ambiguous. \
                 Give them distinct basenames, or select a recovery plane that describes \
                 each under its relative path"
            ),
            Self::NoNameCarrier => f.write_str(
                "[naming] wire = \"empty\" with subject = \"neutral\": nothing on the WIRE \
                 carries a name, so there is no end state to derive from it. Leave one of \
                 the two carriers descriptive. A recovery set covering every member would \
                 make the combination legal and interesting (N3 plus N5 plus P3, names \
                 from FileDesc packets alone), and this plane is refused rather than \
                 guessed until a row selects it: the recovery plane rewrites the \
                 expectation for a covered member and would have to rewrite it for EVERY \
                 member here, which is a stronger requirement than P3 states",
            ),
            Self::RawNameBytesNotImplemented => f.write_str(
                "[naming] name_bytes = \"raw\" (N7) is not implemented yet: it is part of \
                 the encoding and NZB plane work",
            ),
        }
    }
}

/// Apply the naming plane to an assembled source list.
///
/// Draw order, which is part of the determinism contract: for each file
/// in source order, the wire token (only when the wire name is opaque),
/// then the subject furniture token and the poster token (only when the
/// subject is neutral). A selection that needs no token draws nothing,
/// so two profiles differing only in a plane that draws nothing produce
/// the same message-ids, which is what makes a diff between them
/// readable.
pub fn plan(profile: &Profile, sources: &[SourceFile], rng: &mut Rng) -> Result<Plan, NamingError> {
    if profile.naming.name_bytes != NameBytes::Utf8 {
        return Err(NamingError::RawNameBytesNotImplemented);
    }
    let neutral = profile.naming.subject == SubjectStyle::Neutral;
    // Both name carriers emptied at once, with nothing out of band to
    // put one back. Refused rather than guessed; see NoNameCarrier.
    if profile.naming.wire == WireName::Empty && neutral {
        return Err(NamingError::NoNameCarrier);
    }
    let mut files = Vec::with_capacity(sources.len());
    for s in sources {
        let posted = match profile.naming.wire {
            // N2: one token per file, and the SAME token in the subject
            // and in `name=`. Two tokens would be a shape no posting
            // tool produces and would quietly test cross-header
            // reconciliation instead of opacity.
            WireName::Opaque => rng.token(),
            WireName::Descriptive | WireName::Empty => s.base.clone(),
        };
        let yenc = match profile.naming.wire {
            WireName::Empty => String::new(),
            _ => posted.clone(),
        };
        let (subject_token, poster) = if neutral {
            (
                Some(rng.token()),
                format!("{}@postfast.invalid", rng.token()),
            )
        } else {
            (None, POSTER.to_string())
        };
        // The name the layout carries, and therefore the name the
        // client must end with: the token under N2, where the real
        // basename is on no wire, in no subject and in no map.
        let final_name = match profile.naming.wire {
            WireName::Opaque => posted.clone(),
            WireName::Descriptive | WireName::Empty => s.base.clone(),
        };
        files.push(FileNaming {
            rel: s.rel.clone(),
            posted,
            yenc,
            poster,
            subject_token,
            final_name,
        });
    }
    check_final_names(sources, &files)?;
    Ok(Plan {
        title: title_for(profile, sources),
        files,
        reorder_parts: profile.naming.part_order == PartOrder::Reordered,
    })
}

/// The naming decisions for the recovery files, appended to a plan
/// after the payload's.
///
/// The recovery files are posted files like any other, so they get the
/// same three carriers - a `name=`, a subject and a From - and they get
/// them from `[recovery] names` (7.C) rather than from `[naming] wire`
/// (7.A). The two planes are deliberately independent: the interesting
/// obfuscated post is precisely the one whose PAYLOAD is opaque and
/// whose recovery set is announced, so a client that can find the set
/// can name the payload from it (P3). Tying them together would delete
/// that row.
///
/// - `descriptive` and `filedesc-only` post the set under the file
///   names the creator gave it (`movie.par2`, `movie.vol000+01.par2`).
///   `filedesc-only` announces it for exactly the reason above: the set
///   is the sole name source, so a client that cannot see the set has
///   nothing at all.
/// - `opaque` (P2) posts each file under a token of its own, so the set
///   has to be found by sniffing packets rather than by extension.
///
/// The `name=` is never emptied here even under `[naming] wire =
/// "empty"`: an unnamed `.par2` article is a different shape (a packet
/// sniff with no filename hint at all) and it belongs to whichever row
/// selects it, not to every N3 profile by accident.
///
/// Draw order: after every payload draw, so adding a recovery set to a
/// profile leaves the payload's tokens and message-ids exactly where a
/// P0 profile with the same seed put them.
pub fn plan_recovery(profile: &Profile, files: &[RecoveryFile], rng: &mut Rng) -> Vec<FileNaming> {
    let neutral = profile.naming.subject == SubjectStyle::Neutral;
    files
        .iter()
        .map(|f| {
            let posted = match profile.recovery.names {
                // G6: an OUTER set keeps its own name whatever the
                // plane says. It exists to name the inner set, and an
                // outer set nobody can find names nothing - the same
                // rule `crate::companion` states about a sidecar, for
                // the same reason.
                _ if f.outer => f.name.clone(),
                // P10: the DECOY keeps its own name for the same
                // reason, read the other way. Its whole claim is the
                // `.par2` suffix a poster wrote over bytes that are not
                // a set, and a decoy under a token would make no claim
                // at all - it would be an opaque file among opaque
                // files, which is a shape this catalog already carries.
                _ if f.decoy => f.name.clone(),
                RecoveryNames::Opaque => rng.token(),
                RecoveryNames::Descriptive | RecoveryNames::FiledescOnly => f.name.clone(),
            };
            let (subject_token, poster) = if neutral {
                (
                    Some(rng.token()),
                    format!("{}@postfast.invalid", rng.token()),
                )
            } else {
                (None, POSTER.to_string())
            };
            FileNaming {
                rel: f.name.clone(),
                yenc: posted.clone(),
                // Never asserted: a recovery file is usenet furniture
                // and the client sweeps it, so it is absent from the
                // expectation by construction (`layout::expected_files`
                // says so). Set to the posted name rather than left
                // empty, because an empty `final_name` would read as a
                // claim that the file lands nameless.
                final_name: posted.clone(),
                posted,
                poster,
                subject_token,
            }
        })
        .collect()
}

/// G4: the naming entries for the companion sidecars.
///
/// A sidecar is posted under its OWN name whatever the naming plane
/// says, and `crate::companion`'s header is where that rule is argued:
/// the payload rides under tokens precisely because the sidecar says
/// what everything is, and a token-named name source is a name source
/// nothing can find. It is a posted file in every other particular, so
/// it takes the subject plane's answer like any other.
pub fn plan_companion(
    profile: &Profile,
    files: &[crate::companion::CompanionFile],
    rng: &mut Rng,
) -> Vec<FileNaming> {
    let neutral = profile.naming.subject == SubjectStyle::Neutral;
    files
        .iter()
        .map(|f| {
            let (subject_token, poster) = if neutral {
                (
                    Some(rng.token()),
                    format!("{}@postfast.invalid", rng.token()),
                )
            } else {
                (None, POSTER.to_string())
            };
            FileNaming {
                rel: f.name.clone(),
                yenc: f.name.clone(),
                // A sidecar is not swept: it is text under an ordinary
                // extension, not packet-shaped bytes under a token, so
                // it really is part of the end state of a clean run.
                final_name: f.name.clone(),
                posted: f.name.clone(),
                poster,
                subject_token,
            }
        })
        .collect()
}

/// The release title, or `None`, with a reason for each `None`.
///
/// - A neutral-subject post (N5) has no title, because a title shared
///   by every file is the cross-file linkage N5 exists to remove.
/// - An opaque-wire post (N2) has no title, because a descriptive
///   title beside a token name would hand back exactly the identity the
///   token withheld, and the row would then prove nothing.
/// - A single-file post has no title, because `subject_for`'s prefix
///   is `[1/1]` furniture that no real poster writes.
///
/// Otherwise: the stem of the first source file's basename, which is
/// what a real multi-file post's title is a version of.
fn title_for(profile: &Profile, sources: &[SourceFile]) -> Option<String> {
    if profile.naming.subject == SubjectStyle::Neutral
        || profile.naming.wire == WireName::Opaque
        || sources.len() < 2
    {
        return None;
    }
    let base = &sources[0].base;
    let stem = base.rsplit_once('.').map_or(base.as_str(), |(s, _)| s);
    Some(stem.to_string())
}

/// Refuse a plan whose expectation would be ambiguous. Named against
/// the SOURCE paths rather than the wire names, because those are what
/// a profile author would have to change.
fn check_final_names(sources: &[SourceFile], files: &[FileNaming]) -> Result<(), NamingError> {
    let mut seen: std::collections::HashMap<&str, &str> = std::collections::HashMap::new();
    for (s, f) in sources.iter().zip(files) {
        if let Some(first) = seen.insert(&f.final_name, &s.rel) {
            return Err(NamingError::FinalNameCollision {
                name: f.final_name.clone(),
                first: first.to_string(),
                second: s.rel.clone(),
            });
        }
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::assemble::sources as assemble;

    fn plan_of(extra: &str, files: &str) -> Result<Plan, NamingError> {
        let text =
            format!("[layout]\nname = \"t\"\nseed = 1\n\n[source]\nfiles = [{files}]\n\n{extra}");
        let p = Profile::parse(&text).expect("test profile parses");
        let mut rng = Rng::for_profile(&p);
        let s = assemble(&p, &mut rng).expect("sources assemble");
        plan(&p, &s, &mut rng)
    }

    const TWO: &str =
        "{ name = \"movie.mkv\", bytes = 64 }, { name = \"sample/s.mkv\", bytes = 32 }";

    /// N1: the real basename in both carriers, one constant poster, a
    /// title for a multi-file set.
    #[test]
    fn n1_puts_the_real_name_in_both_carriers() {
        let p = plan_of("", TWO).unwrap();
        assert_eq!(p.files[0].posted, "movie.mkv");
        assert_eq!(p.files[0].yenc, "movie.mkv");
        assert_eq!(p.files[1].posted, "s.mkv");
        assert_eq!(p.files[0].poster, POSTER);
        assert_eq!(p.files[1].poster, POSTER);
        assert_eq!(p.title.as_deref(), Some("movie"));
        assert!(p.files.iter().all(|f| f.subject_token.is_none()));
    }

    /// N2: ONE token per file, in the subject and in `name=`. The two
    /// carriers agreeing is the shape; two different tokens would test
    /// something no poster emits.
    #[test]
    fn n2_uses_one_token_in_both_carriers() {
        let p = plan_of("[naming]\nwire = \"opaque\"\n", TWO).unwrap();
        for f in &p.files {
            assert_eq!(f.posted, f.yenc);
            assert_eq!(f.posted.len(), 24, "token shape: {}", f.posted);
        }
        assert_ne!(p.files[0].posted, p.files[1].posted);
        // ...and nothing descriptive leaks back through the title.
        assert_eq!(p.title, None);
        // The real name is on no wire, in no subject and in no map, so
        // the token IS the name the client must end with. Expecting
        // "movie.mkv" here would be expecting a name nobody posted.
        assert_eq!(p.files[0].final_name, p.files[0].posted);
    }

    /// N3: `name=` is emptied and the real name STAYS in the subject.
    /// Emptying both would be N2-with-extra-steps and would not test
    /// "the client trusts the subject or the NZB", which is the row.
    #[test]
    fn n3_empties_the_yenc_name_and_keeps_the_subject_name() {
        let p = plan_of("[naming]\nwire = \"empty\"\n", TWO).unwrap();
        assert_eq!(p.files[0].posted, "movie.mkv");
        assert_eq!(p.files[0].yenc, "");
        assert_eq!(p.files[0].final_name, "movie.mkv");
    }

    /// N3 and N5 together empty both carriers, and with no recovery set
    /// there is nothing left to name the file. Refused, rather than
    /// answered with whatever the client happens to do.
    #[test]
    fn an_empty_name_and_a_neutral_subject_together_are_refused() {
        assert_eq!(
            plan_of("[naming]\nwire = \"empty\"\nsubject = \"neutral\"\n", TWO),
            Err(NamingError::NoNameCarrier)
        );
    }

    /// N5: no name, no shared poster, no title. Any one of the three
    /// left in place is a linkage the row says is absent.
    #[test]
    fn n5_leaves_no_cross_file_linkage() {
        let p = plan_of("[naming]\nsubject = \"neutral\"\n", TWO).unwrap();
        assert_eq!(p.title, None);
        assert!(p.files.iter().all(|f| f.subject_token.is_some()));
        assert_ne!(p.files[0].subject_token, p.files[1].subject_token);
        assert_ne!(p.files[0].poster, p.files[1].poster);
        assert_ne!(p.files[0].poster, POSTER);
    }

    /// The plane is reproducible: same profile, same tokens.
    #[test]
    fn tokens_are_reproducible() {
        let a = plan_of("[naming]\nwire = \"opaque\"\n", TWO).unwrap();
        let b = plan_of("[naming]\nwire = \"opaque\"\n", TWO).unwrap();
        assert_eq!(a, b);
    }

    /// With nothing carrying the directory, the client ends flat, and
    /// the plane says so rather than asserting a tree the layout never
    /// posted.
    #[test]
    fn a_directory_source_ends_flat_with_no_carrier() {
        let p = plan_of("", TWO).unwrap();
        assert_eq!(p.files[1].rel, "sample/s.mkv");
        assert_eq!(p.files[1].final_name, "s.mkv");
    }

    /// ...and two files that would end under one name are refused,
    /// naming the source paths an author would have to change.
    #[test]
    fn flat_lookalikes_are_refused_while_nothing_carries_the_tree() {
        let r = plan_of(
            "",
            "{ name = \"a/x.bin\", bytes = 16 }, { name = \"b/x.bin\", bytes = 16 }",
        );
        match r {
            Err(NamingError::FinalNameCollision {
                name,
                first,
                second,
            }) => {
                assert_eq!(name, "x.bin");
                assert_eq!(first, "a/x.bin");
                assert_eq!(second, "b/x.bin");
            }
            other => panic!("expected a collision refusal, got {other:?}"),
        }
    }

    /// A single-file post carries no `[1/1]` title furniture.
    #[test]
    fn a_single_file_post_has_no_title() {
        let p = plan_of("", "{ name = \"movie.mkv\", bytes = 64 }").unwrap();
        assert_eq!(p.title, None);
    }

    /// N7 is refused by name, not silently downgraded to UTF-8. A
    /// profile selecting a plane that quietly does not happen is the
    /// failure the whole toolkit exists to prevent.
    #[test]
    fn n7_is_refused_by_name() {
        assert_eq!(
            plan_of("[naming]\nname_bytes = \"raw\"\n", TWO),
            Err(NamingError::RawNameBytesNotImplemented)
        );
    }

    /// N6 reaches the encoder as a flag on the plan, so the encoder has
    /// one place to look for it.
    #[test]
    fn n6_is_carried_on_the_plan() {
        assert!(!plan_of("", TWO).unwrap().reorder_parts);
        assert!(
            plan_of("[naming]\npart_order = \"reordered\"\n", TWO)
                .unwrap()
                .reorder_parts
        );
    }
}
