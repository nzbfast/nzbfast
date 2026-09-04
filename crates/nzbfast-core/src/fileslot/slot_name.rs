//! Which of the two in-band names a downloaded file is written under
//! (GitHub #63).
//!
//! A post carries the filename TWICE and the two can disagree:
//!
//! 1. the NZB `<file subject="...">` line, quoted per the usual
//!    convention or - since v1.2.4, issue #55 - in the clear, which
//!    `nzbkit::nzb::NzbFile::filename_hint_lenient` reads and
//!    `get::plan` makes the slot's `hint`;
//! 2. the yEnc article header's own `name=`, which the decode consumer
//!    sees on every article.
//!
//! ## What was wrong
//!
//! The decode consumer took (2) whenever it was non-empty and fell back
//! to (1) only for a header carrying NO name at all. That is right for
//! the obfuscation this project had seen - #43, #47 and #55, where the
//! SUBJECT is the hash and the yEnc name or the PAR2 FileDesc is the
//! recovery - and it silently loses every name on the opposite
//! polarity, where the poster obfuscates the FILES and writes the real
//! names in the subject.
//!
//! #63 is that post. 17 of 18 files landed under bare hex of varying
//! length (46, 48, 32, 60 characters - the poster's own names, not our
//! fixed-shape `file{idx:03}` placeholder, which is how the report was
//! diagnosed from a screenshot) with clean unquoted subjects sitting in
//! the NZB, already parsed, already correct, and thrown away one layer
//! below the parse.
//!
//! ## The rule
//!
//! A name replaces the name in hand unless doing so GIVES ONE UP: the
//! subject named the file and the candidate is a hash. Nothing else
//! changes - when neither name says anything, or both do, the incumbent
//! positional answer stands.
//!
//! Deliberately NOT "prefer the subject", which would simply trade this
//! reporter's album for #43's. The question is evidence, not position,
//! and `nzbkit::release::stem_is_a_name` is the project's existing
//! answer to it.
//!
//! ## M4-70: which ARTICLE's name, when they disagree
//!
//! Everything above is about the two names a post carries per FILE. A
//! post also carries a yEnc name per ARTICLE, and nothing made those
//! agree either: `write_name` latched the first one and
//! `extract::Extractor`'s write path took a slot's name only when it had
//! none, so every later article's name was dropped with no `!=`
//! anywhere. A four-article file whose FIRST article says `x.dat` and
//! whose other three say `Movie.2024.mkv` published `x.dat` - and the
//! same post with the decoy article stalled published `Movie.2024.mkv`.
//! Identical bytes on the wire; the filename was a function of the
//! network. Measured in both arrival orders 30 Aug 2026
//! (`research/NORAR-M4-70-ARRIVAL-ORDER-NAME-2026-08-30.md`).
//!
//! Nothing AT THE MOMENT OF A WRITE can fix that. When the first article
//! lands there is exactly one name in hand, so first-wins, last-wins and
//! later-upgrades-weaker are all still functions of arrival order with
//! different winners. The evidence that settles it - what every article
//! declared - is not complete until the last article has arrived. So the
//! write still latches (the file has to be called something while it is
//! being written) and the question is RE-DECIDED at settle, off
//! [`NameVotes`], by `get::yencname`.
//!
//! The order-free answer is the one the post itself supports most
//! often: three articles of four say `Movie.2024.mkv`, and a decoy is by
//! construction a minority. A TIE is no evidence and keeps the
//! incumbent, which is the honest answer when the post really does
//! contradict itself down the middle.
//!
//! ## What this does NOT touch
//!
//! The recovery-set match key. `get::workers` passes the yEnc `dec.name`
//! to `nzbkit::live::LiveVerifier::on_data` as a SEPARATE argument, so a
//! slot written under its subject name still matches its FileDesc by the
//! name the set was built from (`live::try_match`), and `get::census`
//! asks `slot_in_set` before it ever compares written names. The same
//! rule is applied a second time to the FileDesc rename in `get::settle`
//! (`filedesc_name_is_better`), because on #63's post - which ships a
//! recovery set PER FILE, generated after the obfuscating rename - the
//! FileDesc lists the hashes back and would otherwise rename the file
//! straight to one again. Since 31 Aug 2026 that second application
//! DEFERS rather than refuses - the file does take the set's spelling
//! and takes the honest one back after the repair - because a member
//! left under a name the set does not know is one the disk-side repair
//! rebuilds a second copy of. The end state is the same and the
//! measurement is on `get::settle::set_name_loses_to_held`.

use super::FileSlot;
use nzbkit::sync::MutexExt;

/// [`FileSlot::name_choice`] states.
pub const NAME_UNDECIDED: u8 = 0;
pub(crate) const NAME_YENC: u8 = 1;
pub(crate) const NAME_HINT: u8 = 2;

/// M4-70: what this slot's ARTICLES declared the file was called.
///
/// A record and not a decision: the write path still latches (see
/// [`FileSlot::write_name`]), and `get::yencname` re-decides at settle
/// off what this collected. Kept per slot rather than per job because
/// the question is per file.
///
/// COST. This is touched once per decoded article on every decode
/// thread, so the agreeing case - which is every article of every
/// ordinary post - is one relaxed load, one string compare and one
/// relaxed add, with no lock and no allocation. Only a name that
/// DISAGREES with the first one reaches the mutex, and only a name not
/// already recorded allocates. The empty `Vec` behind the mutex does not
/// allocate either, so a slot that never sees a disagreement costs one
/// `String` for the whole run.
#[derive(Default)]
pub struct NameVotes {
    /// The first non-empty yEnc name any article declared. Set once.
    first: std::sync::OnceLock<String>,
    /// Articles that declared exactly [`Self::first`].
    agree: std::sync::atomic::AtomicU32,
    /// Every OTHER declared name with its own count, in first-seen
    /// order. Empty on a post whose articles agree, which is nearly all
    /// of them.
    others: std::sync::Mutex<Vec<(String, u32)>>,
    /// Have the articles disagreed yet - `others` non-empty, without
    /// taking its lock.
    ///
    /// It exists for [`Self::contested_records`], which the decode
    /// consumer asks of EVERY article so a contested tally reaches the
    /// journal: the ordinary answer has to cost one relaxed load, the
    /// same bar as the rest of this struct.
    contested: std::sync::atomic::AtomicBool,
}

/// The verdict [`FileSlot::contested_yenc_name`] reaches when a post's
/// articles disagree about a filename and one answer has strictly more
/// of them behind it than any other.
pub struct ContestedName {
    /// The name the post supports: strictly more articles declared it
    /// than declared any rival, and it is NOT the one the write path
    /// latched.
    pub winner: String,
    /// How many articles declared [`Self::winner`], out of every
    /// article that declared any name at all - the whole of what the
    /// rename is justified by, so the log line can say it.
    ///
    /// Deliberately NOT "the incumbent and its votes". The string the
    /// file is on disk under is latched by
    /// `nzbkit::extract::Extractor`'s write path, not by
    /// [`FileSlot::write_name`], which latches only WHICH SOURCE wins
    /// (yEnc header or posted hint) and then hands back each article's
    /// own name. Those two races are decided by different articles on
    /// different threads, so the first name THIS record saw is not
    /// reliably the one on disk. `get::yencname` reads that off the
    /// filesystem instead, and this counts votes.
    pub winner_votes: u32,
    pub total_votes: u32,
    /// EVERY name the articles declared, winner and incumbent included.
    /// The settle tier renames only a file still sitting under one of
    /// these: anything else on disk means a tier that outranks a yEnc
    /// header has already spoken. See `get::yencname`.
    pub declared: Vec<String>,
}

impl NameVotes {
    /// Rebuild a tally an earlier run of this job recorded, so a RESUME
    /// re-decides the same question run 1 would have.
    ///
    /// M4-70's re-decision counts what the articles said, and a resume
    /// never refetches what run 1 already placed - so a tally built from
    /// this run alone is a reading of a post we only partly received.
    /// Rebuilt EMPTY it is worse than partial: `others` is then empty,
    /// [`FileSlot::contested_yenc_name`] answers "every article agreed",
    /// the re-decision never runs at all, and a decoy name run 1's first
    /// article latched stays on the disk. The seed is
    /// `nzbkit::journal::ResumeState::name_votes`, written per contested
    /// slot by `Journal::record_name_votes`.
    ///
    /// The first entry takes [`Self::first`]'s place and the rest become
    /// [`Self::others`], which reconstructs exactly the tally the writer
    /// had: [`FileSlot::contested_yenc_name`] tallies `first` as an
    /// ordinary candidate, so WHICH entry lands there changes no verdict.
    /// This run's own articles then vote into it through [`Self::note`]
    /// like any other.
    pub fn resumed(seed: &[(String, u32)]) -> Self {
        let votes = Self::default();
        let Some(((name, agree), rest)) = seed.split_first() else {
            return votes;
        };
        let _ = votes.first.set(name.clone());
        votes
            .agree
            .store(*agree, std::sync::atomic::Ordering::Relaxed);
        if !rest.is_empty() {
            *votes.others.lock_ok() = rest.to_vec();
            votes
                .contested
                .store(true, std::sync::atomic::Ordering::Relaxed);
        }
        votes
    }

    /// Record one article's declared name. See the cost note on the
    /// struct: the agreeing path takes no lock.
    fn note(&self, yenc_name: &str) {
        use std::sync::atomic::Ordering::Relaxed;
        // `get_or_init` allocates only for the article that wins the
        // race to be first; every later one reads the same `&String`.
        if self.first.get_or_init(|| yenc_name.to_string()) == yenc_name {
            self.agree.fetch_add(1, Relaxed);
            return;
        }
        let mut others = self.others.lock_ok();
        if let Some(e) = others.iter_mut().find(|(n, _)| n == yenc_name) {
            e.1 += 1;
        } else {
            // A post with MANY distinct names per file is a post that
            // will reach no strict winner anyway, so this list is
            // bounded by the disagreement rather than by the article
            // count - and a poster who spends one name per article gets
            // no rename out of it, which is the right answer.
            others.push((yenc_name.to_string(), 1));
        }
        // Under the lock, so it can never read false while `others` is
        // non-empty. Its only reader is the journal question below,
        // which is asked without the lock.
        self.contested
            .store(true, std::sync::atomic::Ordering::Relaxed);
    }
}

impl FileSlot {
    /// M4-70 across a crash: the tally entries the journal must carry
    /// after this article voted, or an empty slice for a slot whose
    /// articles all agree.
    ///
    /// Asked of EVERY decoded article by `get::workers`, so the ordinary
    /// answer costs one relaxed load and no allocation - the same bar as
    /// the rest of [`NameVotes`]. A slot that has disagreed pays a lock
    /// and two short strings per article, against the `R` line it was
    /// already writing.
    ///
    /// BOTH ENTRIES EVERY TIME, rather than only the one that moved.
    /// `first`'s count is what the incumbent's side of the majority is
    /// worth, and it grows on the lock-free path where nothing is
    /// looking; re-stating it costs one line and removes the whole
    /// question of when a tally first became worth writing. The journal's
    /// rule is last-wins per `(slot, name)`, so a repeat is an
    /// overwrite - see `nzbkit::journal::Journal::record_name_votes`.
    pub fn contested_records(&self, yenc_name: &str) -> Vec<(String, u32)> {
        use std::sync::atomic::Ordering::Relaxed;
        if yenc_name.is_empty() || !self.yenc_votes.contested.load(Relaxed) {
            return Vec::new();
        }
        let Some(first) = self.yenc_votes.first.get() else {
            return Vec::new();
        };
        let agree = self.yenc_votes.agree.load(Relaxed);
        let mut out = vec![(first.clone(), agree)];
        if first != yenc_name
            && let Some(e) = self
                .yenc_votes
                .others
                .lock_ok()
                .iter()
                .find(|(n, _)| n == yenc_name)
        {
            out.push(e.clone());
        }
        out
    }

    /// M4-70: the name this post's own articles support, when they
    /// disagree about it.
    ///
    /// `None` - the post says nothing an order-free reading can act on -
    /// in exactly three cases:
    ///
    /// * every article agreed, or none declared a name at all. That is
    ///   the overwhelming common case and it costs one atomic load;
    /// * the top count is TIED. A tie is not weak evidence for one side,
    ///   it is the post contradicting itself down the middle, and there
    ///   is nothing in it strong enough to overwrite a name with.
    ///   Whatever is on disk stands - which is arrival order, but
    ///   arrival order is what the tie LEAVES, and inventing a tiebreak
    ///   would only hide that the post said nothing.
    ///
    /// THE WINNER IS THE PLURALITY OVER EVERY DECLARED NAME, INCLUDING
    /// THE FIRST ONE THIS RECORD SAW, and that is the whole of what
    /// makes the answer order-free. An earlier draft returned `None`
    /// whenever the first name recorded was already the most-voted one,
    /// on the reasoning that there would then be nothing to rename. That
    /// is wrong, and a mutation of the settle tier is what surfaced it:
    /// this record's "first" is whichever article won the `OnceLock`
    /// race HERE, while the name on disk is whichever article won the
    /// `s.name.is_empty()` race in `nzbkit::extract::Extractor` - two
    /// races, two threads, and no reason for them to agree. A post whose
    /// minority name reached the extractor while its majority name
    /// reached this record would have been declared settled and left
    /// under the decoy: M4-70 exactly, with a vote count in front of it.
    /// So this answers only "what do the articles say", `get::yencname`
    /// compares that with what is actually on disk, and neither half
    /// consults an arrival order.
    ///
    /// Deliberately NOT "prefer the name that looks real". That is a
    /// second heuristic layered on the first, and this tier already has
    /// the project's answer to which of two names is worth more, applied
    /// where it belongs: `get::yencname` puts the winner through
    /// `hint_beats` before it renames anything, so a majority of hashes
    /// still cannot take a real posted subject name away.
    pub fn contested_yenc_name(&self) -> Option<ContestedName> {
        use std::sync::atomic::Ordering::Relaxed;
        let first = self.yenc_votes.first.get()?;
        let others = self.yenc_votes.others.lock_ok();
        if others.is_empty() {
            // Every article agreed - there is no question to answer, and
            // this is the path nearly every slot of nearly every job
            // takes.
            return None;
        }
        // One tally over every declared name, the first-seen one taking
        // its place in it as an ordinary candidate.
        let agree = self.yenc_votes.agree.load(Relaxed);
        let tally: Vec<(&str, u32)> = std::iter::once((first.as_str(), agree))
            .chain(others.iter().map(|(n, v)| (n.as_str(), *v)))
            .collect();
        let top = tally.iter().map(|(_, v)| *v).max()?;
        if tally.iter().filter(|(_, v)| *v == top).count() != 1 {
            return None;
        }
        let (winner, winner_votes) = *tally.iter().find(|(_, v)| *v == top)?;
        Some(ContestedName {
            winner: winner.to_string(),
            winner_votes,
            total_votes: tally.iter().map(|(_, v)| *v).sum(),
            declared: tally.iter().map(|(n, _)| (*n).to_string()).collect(),
        })
    }
}

impl FileSlot {
    /// Would taking `candidate` as this slot's name give up the name the
    /// post already told us? See the module header for why this is the
    /// only direction that is refused.
    pub fn hint_beats(&self, candidate: &str) -> bool {
        self.hint_is_posted_name && !nzbkit::release::stem_is_a_name(candidate)
    }

    /// The name this slot's bytes are WRITTEN under, given the yEnc
    /// header name this article declared.
    ///
    /// Latched: running `looks_obfuscated` per article on every decode
    /// thread is the wrong place for it (it tokenizes and allocates) and
    /// every article of one file answers identically, so the first one
    /// decides and the rest pay a relaxed load - the same shape, and for
    /// the same reason, as `streamhub::SeekNames::note_slot_name`. A
    /// race between two decode threads is benign: both compute from the
    /// same `hint` and equal yEnc names, so both store the same value.
    ///
    /// Latching is not a new rule, it is the one already in force one
    /// layer down: `extract::Extractor`'s write path takes a slot's name
    /// only when it has none yet (`s.name.is_empty() && !name.is_empty()`),
    /// so every article after the first was already having its name
    /// ignored. This decides the same question in the same direction,
    /// just early enough to weigh the answer.
    pub fn write_name<'a>(&'a self, yenc_name: &'a str) -> &'a str {
        use std::sync::atomic::Ordering::Relaxed;
        // An article with no name in its header has nothing to weigh.
        if yenc_name.is_empty() {
            return &self.hint;
        }
        // M4-70: record what THIS article said before the latch below
        // throws it away. Every article votes, including the ones that
        // agree - a majority needs both sides counted.
        self.yenc_votes.note(yenc_name);
        let mut choice = self.name_choice.load(Relaxed);
        if choice == NAME_UNDECIDED {
            choice = if self.hint_beats(yenc_name) {
                NAME_HINT
            } else {
                NAME_YENC
            };
            self.name_choice.store(choice, Relaxed);
        }
        if choice == NAME_HINT {
            &self.hint
        } else {
            yenc_name
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::atomic::{AtomicBool, AtomicU8, AtomicUsize};

    /// `hint_is_posted_name` is passed EXPLICITLY rather than derived
    /// here, because the whole point of the flag is that `get::plan`
    /// knows something no inspection of the string can recover: whether
    /// the subject produced this name or the `file{idx:03}` fallback
    /// did.
    fn slot(hint: &str, hint_is_posted_name: bool) -> FileSlot {
        FileSlot {
            hint: hint.into(),
            hint_is_posted_name,
            yenc_votes: Default::default(),
            name_choice: AtomicU8::new(NAME_UNDECIDED),
            is_par2_main: false,
            sample_skipped: false,
            par2_name_demoted: Default::default(),
            par2_sniffed: AtomicBool::new(false),
            total_segments: 1,
            remaining: AtomicUsize::new(0),
            missing: AtomicUsize::new(0),
            errors: AtomicUsize::new(0),
            deferred: AtomicUsize::new(0),
            abandoned: AtomicUsize::new(0),
            capture: std::sync::Mutex::new(None),
        }
    }

    /// The reporter's own post, at the line that lost it: clean unquoted
    /// subject, hash in the yEnc header. Both real names are taken from
    /// #63's screenshots.
    #[test]
    fn a_hash_in_the_yenc_header_does_not_take_a_named_slot() {
        let s = slot("01-duo_something_bi-noir.mp3", true);
        assert_eq!(
            s.write_name("c238183c9ea852006dbc09ffa6a26e987f76060474363d"),
            "01-duo_something_bi-noir.mp3"
        );
        // The hash wearing the right extension is the same defect: what
        // is judged is the stem, so `bare_stem` strips `.mp3` first.
        let s = slot("00-va-sampler-2009-noir.m3u", true);
        assert_eq!(
            s.write_name("4a45d56b74862e71a2a16558948b1b14.m3u"),
            "00-va-sampler-2009-noir.m3u"
        );
    }

    /// #43/#47/#55's polarity, which is shipped and confirmed and must
    /// not move: the SUBJECT is the hash, so the yEnc name is evidence
    /// and wins - including when it is a hash too, since refusing it
    /// would only substitute a different hash.
    #[test]
    fn an_obfuscated_subject_still_takes_the_yenc_name() {
        let s = slot("2137d880a074c9f1e0b3a5d6c7e8f901", false);
        assert_eq!(
            s.write_name("Some.Film.2026.1080p-GRP.mkv"),
            "Some.Film.2026.1080p-GRP.mkv"
        );
        let s = slot("2137d880a074c9f1e0b3a5d6c7e8f901", false);
        assert_eq!(
            s.write_name("d41d8cd98f00b204e9800998ecf8427e"),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    /// The ordinary honest post: both names are real, nothing is at
    /// stake, and the yEnc header keeps winning exactly as before.
    #[test]
    fn an_honest_post_is_untouched() {
        let s = slot("Some.Film.2026.1080p-GRP.part01.rar", true);
        assert_eq!(
            s.write_name("Some.Film.2026.1080p-GRP.part01.rar"),
            "Some.Film.2026.1080p-GRP.part01.rar"
        );
    }

    /// THE reason `hint_is_posted_name` is decided at plan time and not
    /// sniffed off the string. `file003` is the placeholder a subject
    /// naming nothing falls back to, and it is NOT obfuscated-looking -
    /// `looks_obfuscated` passes it - so a version of this rule that
    /// asked the string would prefer the placeholder to the poster's
    /// own name and make an obfuscated post strictly worse.
    #[test]
    fn the_file_nnn_placeholder_never_wins() {
        assert!(
            nzbkit::release::stem_is_a_name("file003"),
            "the placeholder reads as a real name by inspection - which \
             is exactly why the flag cannot be derived from it"
        );
        let s = slot("file003", false);
        assert_eq!(
            s.write_name("d41d8cd98f00b204e9800998ecf8427e"),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    /// Unchanged behaviour: a header with no name at all has nothing to
    /// weigh, so the subject is used whatever it says.
    #[test]
    fn an_empty_yenc_name_falls_back_to_the_hint() {
        let s = slot("real.mkv", true);
        assert_eq!(s.write_name(""), "real.mkv");
        let s = slot("2137d880a074c9f1e0b3a5d6c7e8f901", false);
        assert_eq!(s.write_name(""), "2137d880a074c9f1e0b3a5d6c7e8f901");
        // and it does not latch: the empty arm returns before the
        // decision, so a later article carrying a name still decides.
        let s = slot("real.mkv", true);
        assert_eq!(s.write_name(""), "real.mkv");
        assert_eq!(
            s.name_choice.load(std::sync::atomic::Ordering::Relaxed),
            NAME_UNDECIDED
        );
    }

    /// One file gets ONE name. The first named article decides and every
    /// later article of the slot follows it, so a post whose articles
    /// disagree cannot write half a file under each.
    #[test]
    fn the_choice_latches_on_the_first_named_article() {
        let s = slot("real.mkv", true);
        assert_eq!(s.write_name("d41d8cd98f00b204e9800998ecf8427e"), "real.mkv");
        assert_eq!(
            s.name_choice.load(std::sync::atomic::Ordering::Relaxed),
            NAME_HINT
        );
        // A later article claiming a perfectly good name does not move
        // the file that is already open under the first answer.
        assert_eq!(s.write_name("something.else.mkv"), "real.mkv");

        let s = slot("real.mkv", true);
        assert_eq!(s.write_name("posted.name.mkv"), "posted.name.mkv");
        assert_eq!(
            s.name_choice.load(std::sync::atomic::Ordering::Relaxed),
            NAME_YENC
        );
        assert_eq!(
            s.write_name("d41d8cd98f00b204e9800998ecf8427e"),
            "d41d8cd98f00b204e9800998ecf8427e"
        );
    }

    /// `hint_beats` is the shared predicate `get::settle`'s FileDesc
    /// guard reads too, so pin it in its own right rather than only
    /// through `write_name`.
    #[test]
    fn hint_beats_refuses_only_the_losing_direction() {
        assert!(slot("real.mkv", true).hint_beats("d41d8cd98f00b204e9800998ecf8427e"));
        assert!(!slot("real.mkv", true).hint_beats("other.real.mkv"));
        assert!(
            !slot("d41d8cd98f00b204e9800998ecf8427e", false)
                .hint_beats("another.hash.here.0123456789abcdef")
        );
        assert!(!slot("file003", false).hint_beats("d41d8cd98f00b204e9800998ecf8427e"));
    }

    /// M4-70: the decision itself, in the shape the row measured -
    /// four articles, the first declaring a decoy.
    ///
    /// The unit level is where the RULE is pinned; the e2e pin
    /// (`e2e_norar::namelatch`) is where it is shown to reach the
    /// published filename in both arrival orders. Every article votes,
    /// including the agreeing ones - a majority needs both sides
    /// counted.
    #[test]
    fn a_minority_first_article_loses_to_the_names_the_rest_declare() {
        let s = slot("Hs9kLm42TpQ", false);
        // `write_name` hands back each article's OWN name - it latches
        // which SOURCE wins, not which string. The string is latched one
        // layer down, by the extractor taking a slot's name only when it
        // has none, which is the half that made this arrival-order.
        assert_eq!(s.write_name("x.dat"), "x.dat");
        for _ in 0..3 {
            assert_eq!(s.write_name("Movie.2024.mkv"), "Movie.2024.mkv");
        }
        let c = s.contested_yenc_name().expect("the articles disagree");
        assert_eq!(c.winner, "Movie.2024.mkv");
        assert_eq!((c.winner_votes, c.total_votes), (3, 4));
        // `declared` is what the settle tier tests the on-disk name
        // against, so it has to carry BOTH sides.
        assert!(c.declared.iter().any(|n| n == "x.dat"));
        assert!(c.declared.iter().any(|n| n == "Movie.2024.mkv"));
    }

    /// The control, and the case that is every ordinary post: articles
    /// that agree produce no verdict at all, so the settle tier walks
    /// past the slot without opening anything.
    #[test]
    fn articles_that_agree_leave_the_name_alone() {
        let s = slot("Hs9kLm42TpQ", false);
        for _ in 0..4 {
            assert_eq!(s.write_name("Movie.2024.mkv"), "Movie.2024.mkv");
        }
        assert!(s.contested_yenc_name().is_none());
    }

    /// A TIE is the post contradicting itself down the middle, and
    /// there is nothing in it strong enough to overwrite a name with.
    ///
    /// This is the one place arrival order still decides, and that is
    /// deliberate: it is what the tie LEAVES. Inventing a tiebreak - by
    /// length, by `stem_is_a_name`, by position - would put a second
    /// heuristic on top of the first and hide the fact that the post
    /// said nothing.
    #[test]
    fn a_tie_between_two_declared_names_keeps_the_incumbent() {
        let s = slot("Hs9kLm42TpQ", false);
        s.write_name("a.dat");
        s.write_name("b.mkv");
        assert!(s.contested_yenc_name().is_none(), "1-1 is not a majority");
        // ...and a three-way tie among rivals is no better, however far
        // ahead of the incumbent they all are.
        let t = slot("Hs9kLm42TpQ", false);
        t.write_name("a.dat");
        t.write_name("b.mkv");
        t.write_name("b.mkv");
        t.write_name("c.mkv");
        t.write_name("c.mkv");
        assert!(
            t.contested_yenc_name().is_none(),
            "two rivals on 2 votes each is not one answer, whatever the \
             incumbent's 1 vote says"
        );
    }

    /// The verdict does NOT depend on which article this record saw
    /// first, and that is the property that makes it order-free.
    ///
    /// The same four declarations in the opposite order reach the same
    /// winner. An earlier draft returned `None` here, on the reasoning
    /// that the first-seen name already had the majority so there was
    /// nothing to rename - which quietly assumed this record's first and
    /// the EXTRACTOR's latched name are the same article. They are two
    /// races on two threads. `get::yencname` compares the winner with
    /// what is on disk instead, so this must answer the same way
    /// whichever article got here first.
    #[test]
    fn the_winner_does_not_depend_on_which_article_voted_first() {
        let decoy_first = slot("Hs9kLm42TpQ", false);
        for n in [
            "x.dat",
            "Movie.2024.mkv",
            "Movie.2024.mkv",
            "Movie.2024.mkv",
        ] {
            decoy_first.write_name(n);
        }
        let honest_first = slot("Hs9kLm42TpQ", false);
        for n in [
            "Movie.2024.mkv",
            "Movie.2024.mkv",
            "Movie.2024.mkv",
            "x.dat",
        ] {
            honest_first.write_name(n);
        }
        let a = decoy_first.contested_yenc_name().expect("they disagree");
        let b = honest_first.contested_yenc_name().expect("they disagree");
        assert_eq!(a.winner, "Movie.2024.mkv");
        assert_eq!(
            a.winner, b.winner,
            "the verdict moved with the order the votes were cast in - \
             which is the very thing M4-70 is"
        );
        assert_eq!(
            (a.winner_votes, a.total_votes),
            (b.winner_votes, b.total_votes)
        );
    }

    /// A slot the tests want to resume with a tally already on it.
    fn resumed_slot(hint: &str, seed: &[(&str, u32)]) -> FileSlot {
        let mut s = slot(hint, false);
        s.yenc_votes = NameVotes::resumed(
            &seed
                .iter()
                .map(|(n, v)| ((*n).to_string(), *v))
                .collect::<Vec<_>>(),
        );
        s
    }

    /// M4-70 ACROSS A CRASH. Run 1 decoded the decoy article and died;
    /// run 2 never refetches it, so every article run 2 sees declares
    /// the real name and agrees with itself. Rebuilt from nothing that
    /// is "the articles agreed" and the settle-time re-decision never
    /// runs at all - the disk keeps `x.dat`, which is M4-70 with a crash
    /// in front of it.
    ///
    /// Seeded from the journal it is the ordinary contested question
    /// again, and the whole post's majority answers it.
    #[test]
    fn a_resumed_slot_re_decides_off_the_tally_run_one_recorded() {
        // What today's resume rebuilds: nothing, plus run 2's articles.
        let blind = slot("Hs9kLm42TpQ", false);
        blind.write_name("Movie.2024.mkv");
        blind.write_name("Movie.2024.mkv");
        blind.write_name("Movie.2024.mkv");
        assert!(
            blind.contested_yenc_name().is_none(),
            "an empty tally must not read as agreement - that is the defect"
        );

        // Seeded with what run 1 saw: one article, the decoy.
        let seeded = resumed_slot("Hs9kLm42TpQ", &[("x.dat", 1)]);
        seeded.write_name("Movie.2024.mkv");
        seeded.write_name("Movie.2024.mkv");
        seeded.write_name("Movie.2024.mkv");
        let c = seeded
            .contested_yenc_name()
            .expect("run 1's decoy contests run 2's three");
        assert_eq!(c.winner, "Movie.2024.mkv");
        assert_eq!((c.winner_votes, c.total_votes), (3, 4));
        // The incumbent has to stay in `declared`, or `get::yencname`
        // refuses to touch a file sitting under the name run 1 latched.
        assert!(c.declared.iter().any(|n| n == "x.dat"), "{:?}", c.declared);
    }

    /// A resume must not INVENT a majority either: run 1's own votes
    /// count for their side, so a decoy that really did win run 1 still
    /// wins, and the file keeps the name it is already under.
    #[test]
    fn a_seeded_majority_is_not_overturned_by_a_short_second_run() {
        let s = resumed_slot("Hs9kLm42TpQ", &[("x.dat", 9)]);
        s.write_name("Movie.2024.mkv");
        let c = s.contested_yenc_name().expect("they disagree");
        assert_eq!(c.winner, "x.dat", "9 against 1 is not a rename");
    }

    /// What the decode consumer hands the journal. The ordinary slot -
    /// every article of every file agreeing - must write NOTHING, or a
    /// journal grows a line per article for no reason at all.
    #[test]
    fn only_a_contested_slot_hands_the_journal_a_tally() {
        let agreeing = slot("Hs9kLm42TpQ", false);
        agreeing.write_name("Movie.2024.mkv");
        assert!(agreeing.contested_records("Movie.2024.mkv").is_empty());
        agreeing.write_name("Movie.2024.mkv");
        assert!(agreeing.contested_records("Movie.2024.mkv").is_empty());

        let s = slot("Hs9kLm42TpQ", false);
        s.write_name("x.dat");
        assert!(
            s.contested_records("x.dat").is_empty(),
            "one name is not a disagreement"
        );
        s.write_name("Movie.2024.mkv");
        // BOTH sides, every time: the incumbent's count grows on the
        // lock-free path, so re-stating it is what keeps it current.
        let mut rec = s.contested_records("Movie.2024.mkv");
        rec.sort();
        assert_eq!(
            rec,
            vec![("Movie.2024.mkv".to_string(), 1), ("x.dat".to_string(), 1)]
        );
        s.write_name("x.dat");
        assert_eq!(s.contested_records("x.dat"), vec![("x.dat".to_string(), 2)]);
        // A nameless article said nothing and writes nothing.
        assert!(s.contested_records("").is_empty());
    }

    /// A tally that survived a crash is one the journal can hand back,
    /// whichever entry the writer happened to record first: the verdict
    /// is a plurality over every declared name, so `first` is an
    /// ordinary candidate and the seed's order cannot decide anything.
    #[test]
    fn a_seeds_order_does_not_decide_the_verdict() {
        let a = resumed_slot("Hs9kLm42TpQ", &[("x.dat", 1), ("Movie.2024.mkv", 3)]);
        let b = resumed_slot("Hs9kLm42TpQ", &[("Movie.2024.mkv", 3), ("x.dat", 1)]);
        let (a, b) = (
            a.contested_yenc_name().expect("they disagree"),
            b.contested_yenc_name().expect("they disagree"),
        );
        assert_eq!(a.winner, "Movie.2024.mkv");
        assert_eq!(
            (a.winner, a.winner_votes, a.total_votes),
            (b.winner, b.winner_votes, b.total_votes)
        );
        // A one-entry seed is a slot that never disagreed - a torn
        // journal tail can leave one - and it is no more contested than
        // a fresh slot is.
        let lone = resumed_slot("Hs9kLm42TpQ", &[("x.dat", 4)]);
        assert!(lone.contested_yenc_name().is_none());
        assert!(lone.contested_records("x.dat").is_empty());
    }

    /// An article with no name in its header has nothing to weigh and
    /// must not vote - it is not evidence for the incumbent.
    #[test]
    fn a_nameless_article_casts_no_vote() {
        let s = slot("Hs9kLm42TpQ", false);
        s.write_name("x.dat");
        s.write_name("");
        s.write_name("");
        s.write_name("Movie.2024.mkv");
        s.write_name("Movie.2024.mkv");
        let c = s
            .contested_yenc_name()
            .expect("2 against 1 is still a majority");
        assert_eq!(
            (c.winner_votes, c.total_votes),
            (2, 3),
            "the two nameless articles must not be counted as votes for \
             anything - they said nothing"
        );
    }

    /// GH #63's rule is not suspended by a majority. `get::yencname` puts
    /// the winner through `hint_beats` before it renames anything, so a
    /// post whose articles overwhelmingly agree on a HASH still cannot
    /// take away the real name its subject carried.
    ///
    /// The verdict is still REACHED here - the articles really do
    /// disagree - and it is the settle tier that declines it. Pinned at
    /// both ends so neither half can quietly become the only guard.
    #[test]
    fn a_majority_of_hashes_does_not_beat_a_real_posted_subject_name() {
        let s = slot("Movie.2024.German.DL.1080p.mkv", true);
        s.write_name("aa.bin");
        for _ in 0..5 {
            s.write_name("d41d8cd98f00b204e9800998ecf8427e");
        }
        let c = s.contested_yenc_name().expect("the articles disagree");
        assert_eq!(c.winner, "d41d8cd98f00b204e9800998ecf8427e");
        assert!(
            s.hint_beats(&c.winner),
            "the settle tier's `filedesc_name_is_better` guard is what \
             declines this - a majority of hashes is still hashes"
        );
    }
}
