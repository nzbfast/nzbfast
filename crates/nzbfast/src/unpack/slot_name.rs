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
//! straight to one again.

use super::FileSlot;

/// [`FileSlot::name_choice`] states.
pub(crate) const NAME_UNDECIDED: u8 = 0;
pub(crate) const NAME_YENC: u8 = 1;
pub(crate) const NAME_HINT: u8 = 2;

impl FileSlot {
    /// Would taking `candidate` as this slot's name give up the name the
    /// post already told us? See the module header for why this is the
    /// only direction that is refused.
    pub(crate) fn hint_beats(&self, candidate: &str) -> bool {
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
    pub(crate) fn write_name<'a>(&'a self, yenc_name: &'a str) -> &'a str {
        use std::sync::atomic::Ordering::Relaxed;
        // An article with no name in its header has nothing to weigh.
        if yenc_name.is_empty() {
            return &self.hint;
        }
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
            name_choice: AtomicU8::new(NAME_UNDECIDED),
            is_par2_main: false,
            sample_skipped: false,
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
}
