//! File-role-aware fault selection for the chaos mock (TODO 283).
//!
//! [`crate::mock::Chaos`] has around forty knobs and every one of them
//! is applied BY MESSAGE-ID or by connection. Nothing in it knows what a
//! file IS, so the shape that beat us live on 24 Aug 2026 - "the payload
//! serves at 99% and the recovery set is 93% dead" (TODO 282) - could
//! not be written down at all. What tests did instead was a bespoke id
//! census each: `articles.keys().filter(|k| k.contains("r_part2_rar"))`,
//! repeated per test, true only of the fixture it was typed against and
//! silently selecting NOTHING when the fixture's names move (a filter
//! that matches no key is an empty set, a chaos-free server, and a green
//! test).
//!
//! This layer sits BESIDE `Chaos` rather than inside it: a [`FaultPlan`]
//! resolves a [`Role`] to the ids that hold that role in this post, and
//! the applier methods write those ids into the existing knobs. The mock
//! itself is unchanged and every existing test keeps working.
//!
//! ```ignore
//! let plan = FaultPlan::from_segments(&fx.nzb_files);
//! let mut chaos = Chaos::default();
//! plan.role(Role::Recovery).fraction(0.93).missing(&mut chaos);
//! plan.role(Role::Payload).fraction(0.008).missing(&mut chaos);
//! ```
//!
//! **Roles are resolved with the PRODUCT's classifier**, [`NzbFile::kind`]
//! via [`role_of`], not with a second rule written here. `.vol-NN.par2`
//! is a recovery volume in both places or in neither; the day that rule
//! changes, these fixtures change with it. That is the whole point of
//! naming a role instead of a substring.
//!
//! [`NzbFile::kind`]: crate::nzb::NzbFile::kind

use std::collections::HashSet;

use crate::mock::Chaos;
use crate::nzb::{FileKind, classify_subject, classify_subject_detail};

/// One posted file as the planner sees it: what it is called, what its
/// articles are, and how big it is.
#[derive(Debug, Clone)]
pub struct PostFile {
    /// The NZB subject, or the bare filename - whatever the client will
    /// classify on. [`role_of`] applies the same quoted-filename rule
    /// the parser does, so either spelling works.
    pub name: String,
    /// Message-ids in posting order, with or without angle brackets;
    /// [`FaultPlan::new`] normalizes them to the wire form the mock
    /// keys on.
    pub ids: Vec<String>,
    /// Encoded bytes, used by [`Role::LargestVolume`] and friends.
    pub bytes: u64,
}

/// What a file is FOR, as a fault shape names it.
///
/// Everything here resolves through [`role_of`], so a post with no
/// recovery set resolves every PAR2 role to the empty selection rather
/// than to an error - and an empty selection applied to a `Chaos` is a
/// no-op, which is exactly the silent-green trap this module exists to
/// kill. Assert on [`Sel::len`] (or use [`Sel::expect_nonempty`]) in any
/// test whose point is that something was damaged.
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum Role {
    /// Payload: everything that is not part of the PAR2 set.
    Payload,
    /// The whole recovery set - main index plus every volume.
    Recovery,
    /// The small main `.par2` index (there may be more than one).
    Par2Main,
    /// Every `.volNN+MM.par2` recovery volume.
    Par2Volumes,
    /// One recovery volume by position in volume order - see
    /// [`FaultPlan::files_in`] for what that order is. Out of range
    /// resolves empty.
    Par2Volume(usize),
    /// The recovery volume with the most encoded bytes, which is the one
    /// carrying the most slices and so the most expensive single thing
    /// a repair can be denied.
    LargestVolume,
    /// The recovery volume with the fewest encoded bytes - the one the
    /// bootstrap election picks (`NzbCollection::par2_seed_file`).
    SmallestVolume,
    /// The last `n` files in POSTING order, whatever they are. The tail
    /// of a post is where retention and incomplete propagation bite.
    LastPosted(usize),
    /// One file by exact name (subject or filename), for the residue a
    /// role cannot express.
    Named(String),
    /// Every article in the post.
    Everything,
}

/// The role a posted file holds, from its name.
///
/// CALLS [`NzbFile::kind`]'s own rule rather than restating it. It was a
/// hand-copied twin until 30 Aug 2026 - the same three steps written out
/// a second time - so N6-04's decoy-quote defect and N6-05's
/// quoted-`.par2`-with-a-tail defect were each live in two places and
/// fixable in one. Kept as a free function over a `&str` because a fault
/// plan is built from fixture rows, not from a parsed `NzbCollection`.
///
/// [`NzbFile::kind`]: crate::nzb::NzbFile::kind
pub fn role_of(name: &str) -> FileKind {
    classify_subject(name)
}

/// The first-block ordinal a recovery volume declares in its name
/// (`testset.vol012+008.par2` → 12), when it declares one.
///
/// This is what orders [`Role::Par2Volume`], so `Par2Volume(0)` is the
/// set's first volume however the fixture sorted its files, and stays
/// the first volume when a fixture gains a `vol100+`-and-up tail that
/// would sort before `vol012` as text.
///
/// The offset comes off the name's OWN classification, not from a
/// second call to the public `par2_vol_suffix` - which is the
/// raw-subject rule whatever rule produced the kind the caller filtered
/// on (T2, 31 Aug 2026). The two agree at this site, since the caller
/// has already kept only `Par2Volume` and the isolated rule accepts a
/// strict subset of the raw one, but agreeing is not the same as being
/// one rule: `role_of` was a hand-copied twin of `NzbFile::kind` for
/// months on exactly that reasoning.
fn vol_first_block(name: &str) -> Option<u64> {
    let class = classify_subject_detail(name);
    let lower = class.name().to_ascii_lowercase();
    let at = class.vol_suffix()?;
    let digits: String = lower[at + ".vol".len()..]
        .chars()
        .take_while(|c| c.is_ascii_digit())
        .collect();
    // The bare `.vol-NN` shape has nothing before the dash; its ordinal
    // is the number AFTER it, which is what the poster numbers volumes
    // with. `SubjectClass::vol_suffix` has already proven the shape is
    // one of the three it accepts, so this only has to tell them apart.
    if digits.is_empty() {
        let after = &lower[at + ".vol".len()..];
        let tail = after.strip_prefix('-')?;
        return tail
            .chars()
            .take_while(|c| c.is_ascii_digit())
            .collect::<String>()
            .parse()
            .ok();
    }
    digits.parse().ok()
}

/// Message-ids in the form the mock keys on: `<id>`.
fn wire(id: &str) -> String {
    if id.starts_with('<') && id.ends_with('>') {
        id.to_string()
    } else {
        format!("<{id}>")
    }
}

/// A post, resolved into roles.
#[derive(Debug, Clone)]
pub struct FaultPlan {
    files: Vec<PostFile>,
}

impl FaultPlan {
    /// Build from files in POSTING order (NZB order), normalizing every
    /// id to the mock's wire form.
    pub fn new(files: impl IntoIterator<Item = PostFile>) -> FaultPlan {
        FaultPlan {
            files: files
                .into_iter()
                .map(|f| PostFile {
                    ids: f.ids.iter().map(|i| wire(i)).collect(),
                    ..f
                })
                .collect(),
        }
    }

    /// Build from the `(name, segments)` rows the e2e fixtures already
    /// carry, where a segment is `(id, bytes, part_number)`. The file's
    /// `bytes` is the sum of its segments', which is the encoded size -
    /// the same quantity `NzbFile::bytes` reports and `pick_volumes`
    /// plans against.
    pub fn from_segments(rows: &[(String, Vec<(String, u64, u32)>)]) -> FaultPlan {
        FaultPlan::new(rows.iter().map(|(name, segs)| PostFile {
            name: name.clone(),
            ids: segs.iter().map(|(id, _, _)| id.clone()).collect(),
            bytes: segs.iter().map(|(_, b, _)| *b).sum(),
        }))
    }

    /// Every file, in posting order.
    pub fn files(&self) -> &[PostFile] {
        &self.files
    }

    /// The files holding `role`, in posting order - except the volume
    /// roles, which are in VOLUME order: by declared first-block
    /// ordinal, ties broken by name, and volumes whose names declare no
    /// ordinal sorted last among themselves by name. Deterministic
    /// either way, which is what a fixture-independent shape needs.
    pub fn files_in(&self, role: Role) -> Vec<&PostFile> {
        let kind = |f: &PostFile| role_of(&f.name);
        let by_kind = |k: FileKind| -> Vec<&PostFile> {
            self.files.iter().filter(|f| kind(f) == k).collect()
        };
        let volumes = || {
            let mut v = by_kind(FileKind::Par2Volume);
            v.sort_by(|a, b| {
                let (ka, kb) = (vol_first_block(&a.name), vol_first_block(&b.name));
                // None sorts last: Option's own Ord puts it first.
                match (ka, kb) {
                    (Some(x), Some(y)) => x.cmp(&y).then_with(|| a.name.cmp(&b.name)),
                    (Some(_), None) => std::cmp::Ordering::Less,
                    (None, Some(_)) => std::cmp::Ordering::Greater,
                    (None, None) => a.name.cmp(&b.name),
                }
            });
            v
        };
        match role {
            Role::Payload => by_kind(FileKind::Data),
            Role::Par2Main => by_kind(FileKind::Par2Main),
            Role::Par2Volumes => volumes(),
            Role::Recovery => {
                let mut v = by_kind(FileKind::Par2Main);
                v.extend(volumes());
                v
            }
            Role::Par2Volume(i) => volumes().into_iter().skip(i).take(1).collect(),
            Role::LargestVolume => volumes()
                .into_iter()
                .max_by_key(|f| f.bytes)
                .into_iter()
                .collect(),
            Role::SmallestVolume => volumes()
                .into_iter()
                .min_by_key(|f| f.bytes)
                .into_iter()
                .collect(),
            Role::LastPosted(n) => {
                let start = self.files.len().saturating_sub(n);
                self.files[start..].iter().collect()
            }
            Role::Named(ref name) => self.files.iter().filter(|f| &f.name == name).collect(),
            Role::Everything => self.files.iter().collect(),
        }
    }

    /// Every article holding `role`, in the order [`Self::files_in`]
    /// returns the files and posting order within each file.
    pub fn role(&self, role: Role) -> Sel {
        let files = self.files_in(role.clone());
        Sel {
            what: describe(&role),
            ids: files.iter().flat_map(|f| f.ids.iter().cloned()).collect(),
            files: files.len(),
        }
    }

    /// How many articles the whole post has - the denominator for a
    /// loss rate a test wants to state end to end.
    pub fn total_articles(&self) -> usize {
        self.files.iter().map(|f| f.ids.len()).sum()
    }

    /// One line per file: role, name, article count, bytes. For the
    /// failure message of any assertion about a plan - a shape that
    /// selected the wrong thing is otherwise invisible.
    pub fn describe_post(&self) -> String {
        self.files
            .iter()
            .map(|f| {
                format!(
                    "{:?} {} ({} article(s), {} bytes)",
                    role_of(&f.name),
                    f.name,
                    f.ids.len(),
                    f.bytes
                )
            })
            .collect::<Vec<_>>()
            .join("\n")
    }
}

fn describe(role: &Role) -> String {
    format!("{role:?}")
}

/// A resolved set of articles, ready to be narrowed and applied.
#[derive(Debug, Clone)]
pub struct Sel {
    what: String,
    ids: Vec<String>,
    files: usize,
}

impl Sel {
    /// The selected ids, in the wire form the mock keys on.
    pub fn ids(&self) -> &[String] {
        &self.ids
    }

    pub fn len(&self) -> usize {
        self.ids.len()
    }

    pub fn is_empty(&self) -> bool {
        self.ids.is_empty()
    }

    /// How many FILES this selection spans (before any narrowing).
    pub fn files(&self) -> usize {
        self.files
    }

    /// What role produced it, for assertion messages.
    pub fn what(&self) -> &str {
        &self.what
    }

    /// Panic with the plan's own census when the selection is empty.
    ///
    /// A shape whose damage set resolved to nothing is a test that
    /// passes for the wrong reason, which is the exact failure the
    /// substring censuses this module replaces used to have. Call this
    /// wherever the damage is the point.
    pub fn expect_nonempty(self, plan: &FaultPlan) -> Sel {
        assert!(
            !self.ids.is_empty(),
            "fault plan selected NO articles for {} - the shape would be a no-op. \
             The post is:\n{}",
            self.what,
            plan.describe_post()
        );
        self
    }

    /// Narrow to `n` articles spread evenly across the selection.
    ///
    /// Evenly rather than the first `n`: damage concentrated at the head
    /// of a file is a different fault from damage spread through it (a
    /// PAR2 slot maps by offset, and the first article of a volume
    /// carries its headers), and the spread version is the one that
    /// models a provider with holes. Deterministic, so a failing shape
    /// reproduces exactly.
    pub fn evenly(mut self, n: usize) -> Sel {
        let have = self.ids.len();
        if n >= have {
            return self;
        }
        let picked: Vec<String> = (0..n).map(|j| self.ids[j * have / n].clone()).collect();
        self.ids = picked;
        self
    }

    /// Narrow to `f` of the selection (0.0..=1.0), spread evenly.
    ///
    /// **Rounds UP to at least one article whenever `f > 0`.** A live
    /// loss rate of 0.21% over 22,920 segments is 48 articles; the same
    /// fraction over a 40-article fixture is 0.084, and a shape that
    /// silently selected zero would be a green test asserting nothing.
    /// So a fixture too small to express the rate damages one article
    /// and the test is still about damage. When the COUNT is what
    /// matters, say so with [`Self::evenly`] instead.
    pub fn fraction(self, f: f64) -> Sel {
        assert!((0.0..=1.0).contains(&f), "fraction out of range: {f}");
        if f <= 0.0 {
            return Sel {
                ids: Vec::new(),
                ..self
            };
        }
        let n = ((self.ids.len() as f64) * f).round() as usize;
        self.evenly(n.max(1))
    }

    /// Everything EXCEPT the first article of each file, which is where
    /// a yEnc part-1 header and a PAR2 volume's own packets live.
    ///
    /// Only meaningful before narrowing; it works on the selection's
    /// file boundaries as resolved, so call it first.
    pub fn without_heads(mut self, plan: &FaultPlan, role: Role) -> Sel {
        let heads: HashSet<&String> = plan
            .files_in(role)
            .iter()
            .filter_map(|f| f.ids.first())
            .collect();
        self.ids.retain(|id| !heads.contains(id));
        self
    }

    /// Answer every selected article with 430 - the post is not there.
    pub fn missing(&self, c: &mut Chaos) -> &Sel {
        c.missing.extend(self.ids.iter().cloned());
        self
    }

    /// Serve every selected article with a flipped payload byte, so its
    /// yEnc CRC fails - the damaged-post shape, and (with a STAT that
    /// still answers 223) the takedown-by-replacement FALSE GREEN
    /// documented in `crate::preflight`'s module header.
    pub fn corrupt(&self, c: &mut Chaos) -> &Sel {
        c.corrupt.extend(self.ids.iter().cloned());
        self
    }

    /// Cut every selected body off mid-payload and close the socket.
    pub fn truncate(&self, c: &mut Chaos) -> &Sel {
        c.truncate.extend(self.ids.iter().cloned());
        self
    }

    /// Hang the FIRST request for each selected article after the status
    /// line; retries succeed.
    pub fn stall(&self, c: &mut Chaos) -> &Sel {
        c.stall.extend(self.ids.iter().cloned());
        self
    }

    /// Hang the FIRST request for each selected article BEFORE the
    /// status line - the dead-air shape a TTFB budget must cut short.
    pub fn stall_pre(&self, c: &mut Chaos) -> &Sel {
        c.stall_pre.extend(self.ids.iter().cloned());
        self
    }

    /// Serve each selected article's bytes under its NEIGHBOUR's id and
    /// vice versa - the split-brain shape: a fully valid, self-consistent
    /// yEnc body that is simply the WRONG article.
    ///
    /// Its own pcrc32 passes, so nothing about the bytes gives it away;
    /// only the article's declared identity does. Pairwise so the damage
    /// is symmetric and no article is left unserved, and over an ODD
    /// selection the last id is left alone rather than pointed at
    /// itself. Seen live as "downloads complete but never verify" -
    /// see `Chaos::swap`.
    pub fn swap_pairwise(&self, c: &mut Chaos) -> &Sel {
        for pair in self.ids.chunks_exact(2) {
            c.swap.insert(pair[0].clone(), pair[1].clone());
            c.swap.insert(pair[1].clone(), pair[0].clone());
        }
        self
    }

    /// Serve this selection's articles under `other`'s ids and vice
    /// versa, pairing them by position.
    ///
    /// The CROSS-FILE split brain, and the one that bites: a yEnc body
    /// is self-locating - it declares its own name, part number and
    /// begin offset - so swapping two articles WITHIN one file is
    /// self-healing, each body still landing where it belongs. Swapping
    /// across files hands a slot bytes that belong to another file
    /// entirely, which is the shape a mismatched storage backend
    /// actually produces. Pairs only as far as the shorter selection
    /// reaches.
    pub fn swap_with(&self, other: &Sel, c: &mut Chaos) -> &Sel {
        for (a, b) in self.ids.iter().zip(other.ids.iter()) {
            c.swap.insert(a.clone(), b.clone());
            c.swap.insert(b.clone(), a.clone());
        }
        self
    }

    /// Serve every selected article eventually, after `ms` of dead air
    /// on EVERY request - the cold-storage shape.
    pub fn slow_ttfb(&self, ms: u64, c: &mut Chaos) -> &Sel {
        for id in &self.ids {
            c.slow_ttfb.insert(id.clone(), ms);
        }
        self
    }
}

#[cfg(test)]
#[path = "faultplan_tests.rs"]
mod faultplan_tests;
