//! What a video file says about itself: runtime, codecs, track languages.
//!
//! The renamer already asks [`crate::mkv`] "how long, how wide" to check
//! a poster's resolution claim. Synthesised naming needs strictly more
//! than that. When a completed job's main video still carries a hash for
//! a filename and no earlier pass recovered a real one, the only honest
//! evidence left is the bytes on disk, and the discriminating facts in
//! them are the runtime to the minute plus enough of the track layout to
//! guess an original language. Those are what a catalogue can be
//! searched by.
//!
//! Deliberately local-only: one bounded head read, no article fetches,
//! no external tools (the no-bundled-ffmpeg rule). Both parsers are pure
//! over a slice, bounds-checked, depth-capped and element-budgeted,
//! because a completed download is attacker-shaped input.
//!
//! Codec and language spellings are NORMALISED here rather than passed
//! through. Matroska writes `V_MPEG4/ISO/AVC`, MP4 writes `avc1`, and
//! both mean h264; Matroska writes ISO 639-2 (`fre` or `fra`) while the
//! catalogues we query key on ISO 639-1 (`fr`). A caller comparing raw
//! container spellings would be comparing muxers, not content.

/// A file's own account of itself. Every field is independent: a mux
/// that wrote no Duration still yields codecs, and a container with no
/// language tags still yields a runtime.
#[derive(Debug, Default, Clone, PartialEq)]
pub struct MediaFacts {
    /// "mkv" or "mp4" - which parser answered.
    pub container: &'static str,
    pub duration_secs: Option<f64>,
    pub width: Option<u32>,
    pub height: Option<u32>,
    /// The container's own Title, when it wrote one. Not a track fact at
    /// all, and carried here because it is the STRONGEST thing a
    /// nameless payload can say about itself: a muxer writes it at
    /// encode time and a reposter who scrambled the subject line rarely
    /// reaches inside to clear it. A caller that gets a usable Title has
    /// no business asking a catalogue anything. See `read_title` in
    /// [`crate::mkv`] for what "usable" excludes.
    pub title: Option<String>,
    /// Normalised video codec of the first video track ("h264", "h265",
    /// "av1", "vp9", "mpeg2", "mpeg4", "vc1"), or the raw lowercased id
    /// when we do not recognise it.
    pub video_codec: Option<String>,
    /// Normalised audio codecs, in track order, deduplicated.
    pub audio_codecs: Vec<String>,
    /// ISO 639-1 codes of the audio tracks, in track order, deduplicated.
    /// Untagged tracks and the `und` placeholder are dropped.
    pub audio_langs: Vec<String>,
    /// ISO 639-1 codes of the subtitle tracks, same treatment.
    pub sub_langs: Vec<String>,
}

impl MediaFacts {
    /// Runtime rounded to whole minutes, which is the unit every film
    /// catalogue publishes. `None` when the container wrote no duration,
    /// or wrote one too short or too long to be a feature - a 3-minute
    /// or 9-hour "film" is a sample clip or a corrupt header, and
    /// matching a catalogue on it would be matching noise.
    pub fn runtime_minutes(&self) -> Option<u32> {
        let secs = self.duration_secs?;
        if !secs.is_finite() {
            return None;
        }
        let mins = (secs / 60.0).round();
        (FEATURE_MIN_MINUTES..=FEATURE_MAX_MINUTES)
            .contains(&(mins as i64))
            .then_some(mins as u32)
    }

    /// The single original language this file's tracks suggest, as an
    /// ISO 639-1 code, or `None` when they suggest nothing usable.
    ///
    /// The rule is narrow on purpose, because this feeds a filter that
    /// can only make a candidate set SMALLER: a wrong answer removes the
    /// right film and can leave exactly one wrong one, which is the
    /// failure mode the whole feature is built to avoid. So the file
    /// must carry exactly ONE audio language and nothing else - a
    /// multi-audio release is a dub or a festival mux, and neither tells
    /// us what the film was shot in.
    ///
    /// Subtitles deliberately do NOT vote. An English-subbed Korean film
    /// and an English film with English subs look identical from here.
    pub fn original_language(&self) -> Option<&str> {
        match self.audio_langs.as_slice() {
            [one] => Some(one.as_str()),
            _ => None,
        }
    }
}

/// Shortest and longest runtimes we will treat as a feature film. The
/// floor clears sample clips and trailers; the ceiling clears a duration
/// field that overflowed or was written in the wrong unit.
const FEATURE_MIN_MINUTES: i64 = 40;
const FEATURE_MAX_MINUTES: i64 = 300;

/// How much of the file the parsers get. Matroska puts Info and Tracks
/// in the first few KB; MP4 puts `moov` either at the front (a
/// faststart mux) or at the very end, so the tail is read as well - see
/// [`probe`].
const HEAD: u64 = 4 << 20;

/// Read `path` and parse whatever container it turns out to be. `None`
/// means "nothing we could read", never an error worth reporting: the
/// caller's fallback is to leave the filename alone.
pub fn probe(path: &std::path::Path) -> Option<MediaFacts> {
    use std::io::{Read, Seek, SeekFrom};
    let mut f = std::fs::File::open(path).ok()?;
    let len = f.metadata().ok()?.len();
    let mut head = Vec::new();
    (&mut f).take(HEAD).read_to_end(&mut head).ok()?;
    if let Some(facts) = crate::mkv::facts(&head) {
        return Some(facts);
    }
    if let Some(facts) = crate::mp4::facts(&head) {
        return Some(facts);
    }
    // A faststart-less MP4 keeps `moov` at the end, so the head holds
    // only `ftyp` + a multi-gigabyte `mdat` and the walk above found
    // nothing. Read the tail and try again. Matroska never needs this,
    // and a file that did not open with `ftyp` is not worth a second
    // read - checked so a non-MP4 costs exactly one read.
    if !crate::mp4::looks_like_mp4(&head) || len <= HEAD {
        return None;
    }
    f.seek(SeekFrom::Start(len.saturating_sub(HEAD))).ok()?;
    let mut tail = Vec::new();
    (&mut f).take(HEAD).read_to_end(&mut tail).ok()?;
    crate::mp4::facts_unanchored(&tail)
}

/// Container codec spelling to ours. Matroska CodecIDs and MP4 sample
/// entry fourccs both land here, so `V_MPEG4/ISO/AVC` and `avc1` give
/// the same answer.
///
/// An id we do not recognise comes back lowercased and otherwise
/// untouched rather than dropped: it is still a fact about the file, and
/// the shortlist note shows it to the user.
pub fn normalise_codec(raw: &str) -> String {
    let up = raw.trim().to_ascii_uppercase();
    // Matroska ids are prefixed by track type; strip it so the match
    // below is written once.
    let body = up
        .strip_prefix("V_")
        .or_else(|| up.strip_prefix("A_"))
        .or_else(|| up.strip_prefix("S_"))
        .unwrap_or(&up);
    let named = match body {
        "MPEG4/ISO/AVC" | "AVC1" | "AVC3" | "H264" => "h264",
        "MPEGH/ISO/HEVC" | "HVC1" | "HEV1" | "DVH1" | "DVHE" | "H265" => "h265",
        "AV1" | "AV01" => "av1",
        "VP9" | "VP09" => "vp9",
        "VP8" => "vp8",
        "MPEG2" | "MPEG-2" | "MP2V" => "mpeg2",
        "MPEG4/ISO/ASP" | "MP4V" | "DIVX" | "XVID" => "mpeg4",
        "MS/VFW/FOURCC" | "VC1" | "VC-1" | "VC1 " => "vc1",
        "AC3" | "AC-3" => "ac3",
        "EAC3" | "EC-3" | "EC3" => "eac3",
        "TRUEHD" | "MLPA" => "truehd",
        "DTS" | "DTSC" | "DTSE" | "DTSH" | "DTSL" => "dts",
        "AAC" | "MP4A" => "aac",
        "FLAC" | "FLAC " => "flac",
        "OPUS" => "opus",
        "VORBIS" => "vorbis",
        "MPEG/L3" | "MP3" | ".MP3" => "mp3",
        "MPEG/L2" => "mp2",
        "PCM/INT/LIT" | "PCM/INT/BIG" | "LPCM" | "SOWT" | "TWOS" => "pcm",
        _ => return body.to_ascii_lowercase(),
    };
    named.to_string()
}

/// An ISO 639 language tag, however the container spelled it, as ISO
/// 639-1. `None` for the placeholders that mean "nobody said" (`und`,
/// `mis`, `zxx`, empty) and for tags we have no 2-letter code for -
/// those cannot be matched against a catalogue keyed on 639-1, and a tag
/// we pass through unmapped would silently never match.
///
/// BCP 47 tags (`pt-BR`, `zh-Hans`) are cut at the first subtag: the
/// region says where it was dubbed, not what it was shot in.
pub fn normalise_lang(raw: &str) -> Option<String> {
    let low = raw.trim().to_ascii_lowercase();
    let primary = low.split(['-', '_']).next().unwrap_or("");
    if primary.len() == 2 {
        // Already 639-1. Accept only letters, so a stray "12" from a
        // corrupt mdhd is not treated as a language.
        return primary
            .bytes()
            .all(|b| b.is_ascii_lowercase())
            .then(|| primary.to_string());
    }
    // 639-2, in both its bibliographic and terminological spellings -
    // muxers disagree about which to write, and for the languages that
    // have two the pair is exactly the trap this table exists for.
    let two = match primary {
        "eng" => "en",
        "fre" | "fra" => "fr",
        "ger" | "deu" => "de",
        "spa" => "es",
        "ita" => "it",
        "por" => "pt",
        "dut" | "nld" => "nl",
        "swe" => "sv",
        "dan" => "da",
        "nor" | "nob" | "nno" => "no",
        "fin" => "fi",
        "ice" | "isl" => "is",
        "rus" => "ru",
        "ukr" => "uk",
        "pol" => "pl",
        "cze" | "ces" => "cs",
        "slo" | "slk" => "sk",
        "slv" => "sl",
        "hrv" => "hr",
        "srp" => "sr",
        "bul" => "bg",
        "rum" | "ron" => "ro",
        "hun" => "hu",
        "gre" | "ell" => "el",
        "tur" => "tr",
        "jpn" => "ja",
        "kor" => "ko",
        "chi" | "zho" => "zh",
        "hin" => "hi",
        "tam" => "ta",
        "tel" => "te",
        "mal" => "ml",
        "ben" => "bn",
        "mar" => "mr",
        "pan" => "pa",
        "urd" => "ur",
        "tha" => "th",
        "vie" => "vi",
        "ind" => "id",
        "may" | "msa" => "ms",
        "tgl" | "fil" => "tl",
        "ara" => "ar",
        "heb" => "he",
        "per" | "fas" => "fa",
        "cat" => "ca",
        "baq" | "eus" => "eu",
        "glg" => "gl",
        "est" => "et",
        "lav" => "lv",
        "lit" => "lt",
        "gle" => "ga",
        "wel" | "cym" => "cy",
        "afr" => "af",
        "swa" => "sw",
        _ => return None,
    };
    Some(two.to_string())
}

/// Append `v` unless it is already there. Track lists are short enough
/// that a linear scan beats a set, and order is worth keeping: the first
/// audio track is the one a player picks.
pub(crate) fn push_unique(list: &mut Vec<String>, v: String) {
    if !v.is_empty() && !list.contains(&v) {
        list.push(v);
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn codec_spellings_from_both_containers_agree() {
        for raw in ["V_MPEG4/ISO/AVC", "avc1", "AVC3", "h264"] {
            assert_eq!(normalise_codec(raw), "h264", "{raw}");
        }
        for raw in ["V_MPEGH/ISO/HEVC", "hvc1", "hev1", "dvh1"] {
            assert_eq!(normalise_codec(raw), "h265", "{raw}");
        }
        assert_eq!(normalise_codec("A_EAC3"), "eac3");
        assert_eq!(normalise_codec("ec-3"), "eac3");
        assert_eq!(normalise_codec("A_AAC"), "aac");
        assert_eq!(normalise_codec("mp4a"), "aac");
        assert_eq!(normalise_codec("A_TRUEHD"), "truehd");
        assert_eq!(normalise_codec("A_MPEG/L3"), "mp3");
        // Unknown ids survive as themselves rather than vanishing.
        assert_eq!(normalise_codec("V_SOMETHING_NEW"), "something_new");
    }

    #[test]
    fn language_tags_normalise_to_iso_639_1() {
        assert_eq!(normalise_lang("eng").as_deref(), Some("en"));
        // Both 639-2 spellings of the same language, the muxer-disagreement
        // case this table exists for.
        assert_eq!(normalise_lang("fre").as_deref(), Some("fr"));
        assert_eq!(normalise_lang("fra").as_deref(), Some("fr"));
        assert_eq!(normalise_lang("ger").as_deref(), Some("de"));
        assert_eq!(normalise_lang("deu").as_deref(), Some("de"));
        // BCP 47: the region is where it was dubbed, not where it is from.
        assert_eq!(normalise_lang("pt-BR").as_deref(), Some("pt"));
        assert_eq!(normalise_lang("zh-Hans").as_deref(), Some("zh"));
        // Placeholders mean "nobody said" and must not become a filter.
        assert_eq!(normalise_lang("und"), None);
        assert_eq!(normalise_lang(""), None);
        assert_eq!(normalise_lang("zxx"), None);
        // Garbage from a corrupt header is not a language.
        assert_eq!(normalise_lang("12"), None);
        assert_eq!(normalise_lang("qqq"), None);
    }

    #[test]
    fn runtime_rounds_to_minutes_and_refuses_non_features() {
        let f = |secs: f64| MediaFacts {
            duration_secs: Some(secs),
            ..MediaFacts::default()
        };
        assert_eq!(f(6480.0).runtime_minutes(), Some(108)); // 108:00
        assert_eq!(f(6510.0).runtime_minutes(), Some(109)); // 108:30 rounds up
        assert_eq!(f(6470.0).runtime_minutes(), Some(108));
        // A sample clip and an overflowed duration are both refused.
        assert_eq!(f(120.0).runtime_minutes(), None);
        assert_eq!(f(60.0 * 400.0).runtime_minutes(), None);
        assert_eq!(f(f64::INFINITY).runtime_minutes(), None);
        assert_eq!(MediaFacts::default().runtime_minutes(), None);
    }

    #[test]
    fn one_audio_language_is_a_signal_and_two_are_not() {
        let with = |langs: &[&str]| MediaFacts {
            audio_langs: langs.iter().map(|s| s.to_string()).collect(),
            sub_langs: vec!["en".into()],
            ..MediaFacts::default()
        };
        assert_eq!(with(&["ko"]).original_language(), Some("ko"));
        // A dual-audio mux is a dub: it says nothing about the original.
        assert_eq!(with(&["en", "ko"]), with(&["en", "ko"]));
        assert_eq!(with(&["en", "ko"]).original_language(), None);
        // Subtitles never vote - English subs sit on films of every
        // language, so letting them speak would filter to the wrong one.
        assert_eq!(with(&[]).original_language(), None);
    }
}
