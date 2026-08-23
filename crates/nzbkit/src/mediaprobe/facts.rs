//! TODO §76: the queue-row quality chip, and the name-versus-bytes
//! contradiction behind it.
//!
//! [`super::probe`] answers "what is in this container" in full - every
//! track, every language, every chapter. That answer is right for the
//! drawer panel and far too long for a queue row, which has space for
//! about six words. This module reduces it to the six words scene names
//! themselves use ("2160p HEVC · DDP 5.1"), and then does the thing the
//! reduction makes possible: compares them with what the release NAME
//! claims.
//!
//! ## Why the comparison is worth having
//!
//! A poster controls the name completely and the bytes not at all. A
//! 1080p encode uploaded as a 2160p release passes every check we have -
//! the articles are all there, the PAR2 verifies, the RAR unpacks - and
//! is still not the thing the user asked for. The only witness is the
//! container's own header, which is on disk seconds after the job starts.
//!
//! ## Why it is deliberately timid
//!
//! A false "this is fake" is much worse than a missed one: it accuses a
//! good release, and a badge nobody trusts is a badge nobody reads. So
//! every rule here only fires when both sides positively said something
//! and the two statements cannot both be true:
//!
//! - a name that mentions no resolution makes no claim, and is never
//!   contradicted;
//! - Dolby Vision is never checked at all - Matroska carries it in a
//!   BlockAdditionMapping this probe does not read, so "no DV signalled"
//!   is not evidence of absence (see [`hdr_mismatch`]);
//! - an audio claim fails only when NO track in the file belongs to the
//!   claimed family, and only in the direction that flatters the post
//!   (a name saying AC3 over an E-AC3 track is an under-sell, not a
//!   fake);
//! - "Atmos" accepts TrueHD or E-AC3, because the JOC substream that
//!   makes it Atmos is inside the audio, not in the container header.
//!
//! The strings that come out are technical tokens - "2160p", "HEVC",
//! "DDP 5.1" - and are deliberately NOT translated, exactly as
//! `identSource` is not: they read the same in every language, and they
//! are the same tokens the release name uses, which is the whole point
//! of putting them side by side.

use super::MediaInfo;
use serde::{Deserialize, Serialize};

/// The queue-row chip: what the bytes say, plus whatever the name says
/// that they contradict.
///
/// Every field is optional because a half-arrived container answers
/// some of them and not others, and a chip that appears with the
/// resolution and gains its audio a poll later is better than one that
/// waits for the whole set.
#[derive(Debug, Clone, Default, PartialEq, Serialize, Deserialize)]
pub struct MediaFacts {
    /// Scene resolution bucket of the main video track: "2160p",
    /// "1080p", ...
    pub res: Option<String>,
    /// Video codec in the spelling a release name would use: "HEVC",
    /// "H.264", "AV1", ...
    pub vcodec: Option<String>,
    /// Strongest audio track as "DDP 5.1" / "TrueHD 7.1" / "AAC 2.0".
    pub audio: Option<String>,
    /// Dynamic range, when the container signalled colour at all:
    /// "HDR10", "HDR10+", "HLG", "HDR". `None` covers both "SDR" and
    /// "the container said nothing", which the chip treats alike -
    /// neither is worth a badge.
    pub hdr: Option<String>,
    pub duration_ms: Option<u64>,
    /// "mkv", "mp4", "avi", ... - the same lowercase spelling
    /// [`super::Container`] serializes.
    pub container: Option<String>,
    /// Everything the name claims that the bytes deny. Empty is the
    /// overwhelmingly common case and the only one that renders quietly.
    pub mismatch: Vec<Mismatch>,
    /// False while some metadata region has not arrived: the facts above
    /// are what could be read so far. Mirrors [`MediaInfo::complete`],
    /// and tells the prober whether to come back.
    pub complete: bool,
    /// The main video's coded frame size - the RAW INPUT [`res_label`]
    /// reduces to [`MediaFacts::res`], kept beside its own conclusion.
    ///
    /// The fields above are derived labels and this one is not, which
    /// is the whole reason it exists. A bucketing rule is a
    /// judgement call that gets corrected: 67f212a4 fixed `res_label`
    /// promoting a full-height scope encode (2592x1080) to 1440p, and
    /// every row already written was then stuck with the wrong word
    /// forever, because the dimensions the rule had misread were gone.
    /// Correcting one cost a re-probe of the file, which only works
    /// while the file is still on disk - and for a failed or deleted
    /// download it never is.
    ///
    /// Stored, the next such fix is [`rederive_res`]: arithmetic over
    /// two integers, no disk, and it works on a row whose payload was
    /// deleted years ago.
    ///
    /// `None` on every row written before this field existed, and on a
    /// container whose video track has not been read yet. Absent rather
    /// than zero: "not recorded" and "a zero-width frame" are different
    /// answers, and only the first one means fall back to the file.
    ///
    /// This pair was the first of the raw inputs and is no longer the
    /// only one: [`MediaFacts::vcodec_canon`] and the four fields after
    /// it give the audio, codec and HDR labels the same treatment, for
    /// the same reason.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub width: Option<u32>,
    /// The coded frame height. See [`MediaFacts::width`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub height: Option<u32>,
    /// The main video's canonical codec id - the RAW INPUT
    /// [`vcodec_label`] reduces to [`MediaFacts::vcodec`].
    ///
    /// This is the probe's own short name ("hevc", "h264", "av1"), NOT
    /// the container's CodecID (`V_MPEGH/ISO/HEVC`), which is a
    /// different field on the track and is not kept: the label never
    /// sees it. Where the probe did not recognise the container id it
    /// hands back that id lowercased, and that is what lands here -
    /// still the input the label read.
    ///
    /// `None` on every row written before this field existed, and on a
    /// container whose video track has not been read yet. Absent rather
    /// than empty, for the reason [`MediaFacts::width`] gives.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub vcodec_canon: Option<String>,
    /// The strongest audio track's canonical codec id ("eac3", "dts"),
    /// which [`acodec_label`] reduces to the first half of
    /// [`MediaFacts::audio`]. See [`MediaFacts::vcodec_canon`] for why
    /// it is the canonical name and not the container's own.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub acodec_canon: Option<String>,
    /// That track's channel COUNT, which [`channels_label`] reduces to
    /// the second half of [`MediaFacts::audio`] ("5.1").
    ///
    /// The count and the label are not the same fact and the difference
    /// is exactly why this is stored: 7 channels print as "6.1" by a
    /// table this codebase wrote, and a table is a judgement that gets
    /// corrected. Zero means the container stated a track and no count.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channels: Option<u32>,
    /// That track's layout string ("stereo", "5.1", "7 ch"), the OTHER
    /// input [`channels_label`] reads - it is what the label falls back
    /// to when the count is zero.
    ///
    /// Today every prober derives this from the count itself, so it
    /// carries nothing the count does not. It is stored anyway because
    /// the rule here is "keep what the reducer read", not "keep what is
    /// currently independent": a container that does state a layout of
    /// its own (an MP4 `chnl` box) would make it the only witness, and
    /// a row written before that day would be the one that could not be
    /// re-derived.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub channel_layout: Option<String>,
    /// The video's colour transfer characteristic ("pq", "hlg",
    /// "bt709"), one of the two RAW INPUTS `codec::hdr_format` reduces
    /// to [`MediaFacts::hdr`].
    ///
    /// This pair recovers a distinction the label alone destroys.
    /// [`MediaFacts::hdr`] is `None` both for a file the container
    /// positively described as SDR and for one it said nothing about.
    /// The chip treats those alike; [`hdr_mismatch`] very much does
    /// not, because only the first is grounds for contradicting a name.
    /// With these stored, a row can still tell them apart: both absent
    /// means the container was silent.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hdr_transfer: Option<String>,
    /// The video's colour primaries ("bt2020", "bt709"). See
    /// [`MediaFacts::hdr_transfer`].
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub hdr_primaries: Option<String>,
}

/// One contradiction, as two statements the UI can put in a sentence.
/// Both sides are already display-form: the dashboard composes "The name
/// says {claimed}, but the file is {actual}." and needs no table.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct Mismatch {
    pub field: Field,
    /// What the release name claims ("2160p", "x265", "Atmos").
    pub claimed: String,
    /// What the container says ("1080p", "H.264", "AAC 2.0", "SDR").
    pub actual: String,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Field {
    Resolution,
    Video,
    Audio,
    Hdr,
}

impl MediaFacts {
    /// Is there anything worth putting on a row? A probe that identified
    /// the container but read no track yet has nothing to show.
    pub fn any(&self) -> bool {
        self.res.is_some() || self.vcodec.is_some() || self.audio.is_some()
    }

    /// Do these two say the same thing to a READER - same labels, same
    /// contradictions - whatever raw inputs they happen to carry?
    ///
    /// The distinction is what lets a re-derivation pass tell "this row
    /// was labelled wrong" from "this row merely gained the inputs its
    /// label was read from". Conflating them tells the user a number of
    /// corrections that is mostly rows that were right all along, to
    /// the one person in a position to check it.
    ///
    /// Both halves are destructured EXHAUSTIVELY on purpose: a field
    /// added to this struct does not compile until it has been
    /// classified here as a label or as a raw input, so the two methods
    /// cannot silently stop covering it between them.
    pub fn same_labels(&self, other: &Self) -> bool {
        let Self {
            res,
            vcodec,
            audio,
            hdr,
            duration_ms,
            container,
            mismatch,
            complete,
            width: _,
            height: _,
            vcodec_canon: _,
            acodec_canon: _,
            channels: _,
            channel_layout: _,
            hdr_transfer: _,
            hdr_primaries: _,
        } = self;
        *res == other.res
            && *vcodec == other.vcodec
            && *audio == other.audio
            && *hdr == other.hdr
            && *duration_ms == other.duration_ms
            && *container == other.container
            && *mismatch == other.mismatch
            && *complete == other.complete
    }

    /// Do these two carry the same raw inputs? The other half of
    /// [`MediaFacts::same_labels`], and the test for whether a row is
    /// worth re-writing when nothing a reader can see has changed: one
    /// that gains its inputs never needs the file again.
    pub fn same_raw_inputs(&self, other: &Self) -> bool {
        let Self {
            res: _,
            vcodec: _,
            audio: _,
            hdr: _,
            duration_ms: _,
            container: _,
            mismatch: _,
            complete: _,
            width,
            height,
            vcodec_canon,
            acodec_canon,
            channels,
            channel_layout,
            hdr_transfer,
            hdr_primaries,
        } = self;
        *width == other.width
            && *height == other.height
            && *vcodec_canon == other.vcodec_canon
            && *acodec_canon == other.acodec_canon
            && *channels == other.channels
            && *channel_layout == other.channel_layout
            && *hdr_transfer == other.hdr_transfer
            && *hdr_primaries == other.hdr_primaries
    }
}

// ---------------------------------------------------------------------------
// Bytes → chip
// ---------------------------------------------------------------------------

/// Scene resolution bucket for a coded frame size.
///
/// Buckets on an EFFECTIVE height - the larger of the coded height and
/// the height the width would have at 16:9 - because scene names bucket
/// by the format, not by the frame. A 2.39:1 film at 1920x800 is a
/// "1080p" release and a 4:3 broadcast at 1024x576 is not a 720p one;
/// only taking both dimensions gets those two right at once.
///
/// EXCEPT when the coded height already IS a standard height: a scope
/// film scaled to a full 1080 rows keeps its width (2592x1080), and the
/// width rule would promote it a bucket. A frame whose height sits on a
/// standard is named by that height; the width rule exists only for
/// crops, whose heights sit between standards.
pub fn res_label(w: u32, h: u32) -> Option<String> {
    if w == 0 || h == 0 {
        return None;
    }
    // Codecs pad to macroblock multiples, so "is a standard height"
    // tolerates the mod-16 spellings (1088 for 1080, 2176 for 2160).
    const STANDARD: [u32; 8] = [2160, 1440, 1080, 720, 576, 480, 360, 240];
    let standard = STANDARD.iter().any(|s| h.abs_diff(*s) <= 16);
    let eh = if standard {
        u64::from(h)
    } else {
        u64::from(h).max(u64::from(w) * 9 / 16)
    };
    Some(res_bucket(eh).to_string())
}

/// The scene bucket for an effective height, shared by [`res_label`]
/// and the narrow-frame stand-down in [`check`].
fn res_bucket(eh: u64) -> &'static str {
    match eh {
        1800.. => "2160p",
        1250..1800 => "1440p",
        900..1250 => "1080p",
        650..900 => "720p",
        530..650 => "576p",
        400..530 => "480p",
        300..400 => "360p",
        _ => "240p",
    }
}

/// The full 16:9 frame width of a scene resolution class. The claim
/// vocabulary is `release::res_of`'s closed set, so this is a table and
/// not a calculation.
fn class_width(label: &str) -> Option<u32> {
    Some(match label {
        "2160p" => 3840,
        "1440p" => 2560,
        "1080p" => 1920,
        "720p" => 1280,
        "576p" => 1024,
        "480p" => 854,
        _ => return None,
    })
}

/// The narrow-frame stand-down [`check`] applies to a resolution claim:
/// a 4:3 frame encoded at the claimed class's OWN full width.
///
/// Both halves are load-bearing, and neither of them is "taller than
/// 16:9". That test plus a width-implied bucket was the whole condition
/// once, and it excused far more than the 4:3 shape it was written for:
/// a square 1440x1440 frame measures 1440p while its width implies 810
/// rows, which buckets as 720p, so a 720p name walked; a 1920x2560
/// portrait walked against 1080p the same way. Neither is a broadcast
/// frame and both are exactly the mislabel the rule exists to catch.
fn four_by_three_at_class_width(w: u32, h: u32, claimed: &str) -> bool {
    // Codecs pad to macroblock multiples (a 1440-row frame is spelled
    // 1456), so the ratio is matched within one macroblock row rather
    // than exactly - the same tolerance `res_label` gives its heights.
    (u64::from(w) * 3).abs_diff(u64::from(h) * 4) <= 64
        && class_width(claimed).is_some_and(|cw| w.abs_diff(cw) <= 16)
}

/// Canonical probe codec → the spelling a release name would print.
/// Unknown ids pass through uppercased rather than being dropped: an
/// unrecognised codec is still a fact about the file.
fn vcodec_label(canon: &str) -> String {
    match canon {
        "hevc" => "HEVC",
        "h264" => "H.264",
        "av1" => "AV1",
        "vp9" => "VP9",
        "vp8" => "VP8",
        "mpeg2" => "MPEG-2",
        "mpeg4" => "MPEG-4",
        "vc1" => "VC-1",
        "mjpeg" => "MJPEG",
        other => return other.to_ascii_uppercase(),
    }
    .to_string()
}

fn acodec_label(canon: &str) -> String {
    match canon {
        "eac3" => "DDP",
        "ac3" => "DD",
        "truehd" => "TrueHD",
        "dts" => "DTS",
        "aac" => "AAC",
        "flac" => "FLAC",
        "opus" => "Opus",
        "mp3" => "MP3",
        "mp2" => "MP2",
        "pcm" => "PCM",
        "vorbis" => "Vorbis",
        "wma" => "WMA",
        other => return other.to_ascii_uppercase(),
    }
    .to_string()
}

/// Channel count in the form release names write it. The panel says
/// "stereo" because it is prose there; a chip sitting next to a name
/// that says "DDP5.1" should say "5.1" and "2.0", which is also the only
/// spelling of the two that needs no translating.
fn channels_label(n: u32, layout: &str) -> String {
    match n {
        0 => layout.to_string(),
        1 => "1.0".to_string(),
        2 => "2.0".to_string(),
        3 => "2.1".to_string(),
        6 => "5.1".to_string(),
        7 => "6.1".to_string(),
        8 => "7.1".to_string(),
        n => format!("{n}.0"),
    }
}

/// The track a release name is describing when it says "1080p x265":
/// the first video track the container did not disable. Files with two
/// video tracks are nearly always a feature plus a cover image, and the
/// feature is written first.
fn main_video(info: &MediaInfo) -> Option<&super::VideoTrack> {
    info.video
        .iter()
        .find(|v| v.enabled && v.width > 0 && v.height > 0)
        .or_else(|| info.video.iter().find(|v| v.width > 0 && v.height > 0))
}

/// The track a release name is describing when it says "DDP5.1": the
/// STRONGEST one, which is the same rule `release::acodec_of` applies to
/// the name (a post listing "AC3 … DTS-HD" is a DTS-HD release). Most
/// channels wins, then the container's own default flag.
fn main_audio(info: &MediaInfo) -> Option<&super::AudioTrack> {
    info.audio
        .iter()
        .filter(|a| a.enabled)
        .max_by_key(|a| (a.channels, a.default))
        .or_else(|| info.audio.first())
}

/// Everything the chip shows, with no name to compare against.
pub fn summarise(info: &MediaInfo) -> MediaFacts {
    let v = main_video(info);
    let a = main_audio(info);
    MediaFacts {
        res: v.and_then(|v| res_label(v.width, v.height)),
        vcodec: v.map(|v| vcodec_label(&v.codec)),
        audio: a.map(|a| {
            format!(
                "{} {}",
                acodec_label(&a.codec),
                channels_label(a.channels, &a.channel_layout)
            )
        }),
        // "SDR" is the absence of a format, exactly as it is in
        // `release::hdr_of`, and badging it would make a plain encode
        // look like it carried something.
        hdr: v
            .and_then(|v| v.hdr.as_ref())
            .map(|h| h.format.clone())
            .filter(|f| f != "SDR"),
        duration_ms: info.duration_ms,
        container: serde_json::to_value(info.container)
            .ok()
            .and_then(|v| v.as_str().map(str::to_string)),
        mismatch: Vec::new(),
        complete: info.complete,
        width: v.map(|v| v.width),
        height: v.map(|v| v.height),
        vcodec_canon: v.map(|v| v.codec.clone()),
        acodec_canon: a.map(|a| a.codec.clone()),
        channels: a.map(|a| a.channels),
        channel_layout: a.map(|a| a.channel_layout.clone()),
        // Read off the track's colour block rather than off `hdr` above:
        // that one drops "SDR", and an SDR file's tags are precisely
        // what tells a later reader the container was not silent.
        hdr_transfer: v
            .and_then(|v| v.hdr.as_ref())
            .and_then(|h| h.transfer.clone()),
        hdr_primaries: v
            .and_then(|v| v.hdr.as_ref())
            .and_then(|h| h.primaries.clone()),
    }
}

/// Re-run the resolution derivation over the frame size a row already
/// carries, for a row written by a build whose [`res_label`] was wrong.
///
/// This is the cheap half of the history re-derivation: a row with
/// [`MediaFacts::width`] needs no file on disk and no probe, because the
/// only inputs `res_label` ever had are both right here. Returns whether
/// anything actually changed, so a caller can skip the write.
///
/// It re-derives the resolution MISMATCH too, and it has to. The old
/// label is half of that sentence - a 2592x1080 encode named 1080p was
/// labelled 1440p and therefore also accused of lying about it - so
/// correcting the label while leaving the accusation standing would swap
/// one wrong statement for a worse one. The claim is re-parsed from
/// `name` and the same stand-down `check` applies.
///
/// Nothing else is touched, and the reason is no longer that the other
/// families have nothing to work from - since §188 they keep their own
/// raw inputs, so a fix in one of them can re-derive its LABEL by the
/// same arithmetic. Their MISMATCHES still cannot follow: the audio rule
/// asserts an absence over the WHOLE track list and the codec rule reads
/// the container's own CodecID, and a row stores neither. A fix there
/// re-derives the label and restates the `actual` half of an existing
/// mismatch; it must not re-judge whether that mismatch fires, which is
/// the one thing the stored inputs cannot answer.
pub fn rederive_res(facts: &mut MediaFacts, name: &str) -> bool {
    let (Some(w), Some(h)) = (facts.width, facts.height) else {
        return false;
    };
    let res = res_label(w, h);
    let claim = crate::release::parse_release(name);
    let want = match (&claim.res, &res) {
        (Some(claimed), Some(actual))
            if claimed != actual && !four_by_three_at_class_width(w, h, claimed) =>
        {
            Some(Mismatch {
                field: Field::Resolution,
                claimed: claimed.clone(),
                actual: actual.clone(),
            })
        }
        _ => None,
    };
    let mut mismatch: Vec<Mismatch> = facts
        .mismatch
        .iter()
        .filter(|m| m.field != Field::Resolution)
        .cloned()
        .collect();
    // Resolution leads the list `check` builds; keep it there so a
    // re-derived row and a freshly probed one compare equal.
    if let Some(m) = want {
        mismatch.insert(0, m);
    }
    if facts.res == res && facts.mismatch == mismatch {
        return false;
    }
    facts.res = res;
    facts.mismatch = mismatch;
    true
}

// ---------------------------------------------------------------------------
// Bytes versus name
// ---------------------------------------------------------------------------

/// Release-name video codec → the probe's canonical spelling. The two
/// tables meet here and only here; `release` prints the encoder name a
/// scene post uses ("x265") and `mediaprobe` prints the RFC 6381 one
/// ("hevc"), which is [`super::codec`]'s documented deliberate split.
fn name_vcodec_canon(claim: &str) -> Option<&'static str> {
    Some(match claim.to_ascii_lowercase().as_str() {
        "x265" => "hevc",
        "x264" => "h264",
        "av1" => "av1",
        "xvid" | "divx" => "mpeg4",
        "vc-1" => "vc1",
        _ => return None,
    })
}

/// Which probe codecs satisfy an audio claim.
///
/// More than one is allowed on purpose. "Atmos" is a JOC substream
/// inside a TrueHD or E-AC3 stream and no container header says so, so
/// either carrier honours the claim; "DD" over an E-AC3 track is a
/// release under-selling itself, which is not what this badge is for.
/// `None` means the claim is not checkable and nothing is asserted.
fn name_acodec_family(claim: &str) -> Option<&'static [&'static str]> {
    Some(match claim {
        "Atmos" => &["truehd", "eac3"],
        "TrueHD" => &["truehd"],
        "DTS-X" | "DTS-HD" | "DTS" => &["dts"],
        "DDP" => &["eac3"],
        "AC3" => &["ac3", "eac3"],
        "FLAC" => &["flac"],
        // AAC, Opus, MP3: nothing sits below them, so a name claiming
        // one cannot be flattering the post. Silence beats a badge that
        // fires on a correctly-labelled web-dl.
        _ => return None,
    })
}

/// Does the container positively say this video is SDR?
///
/// Only the transfer function and the primaries can answer that; a file
/// carrying a matrix coefficient and nothing else has told us nothing.
/// And the claim itself has to be checkable: Dolby Vision lives in a
/// Matroska BlockAdditionMapping and an MP4 sample-entry fourcc, and
/// this probe reads neither as a DV signal, so a DV name meeting a file
/// with no colour tags is our blind spot rather than the poster's lie.
fn hdr_mismatch(claim: &str, v: &super::VideoTrack) -> Option<Mismatch> {
    if claim == "DV" {
        return None;
    }
    let h = v.hdr.as_ref()?;
    if h.transfer.is_none() && h.primaries.is_none() {
        return None;
    }
    (h.format == "SDR").then(|| Mismatch {
        field: Field::Hdr,
        claimed: claim.to_string(),
        actual: "SDR".to_string(),
    })
}

/// The chip, plus every claim in `name` the bytes deny.
///
/// `name` is the release name as posted - the same string the queue row
/// shows. Parsing it is `release::parse_release`'s job and is not
/// repeated here.
pub fn check(info: &MediaInfo, name: &str) -> MediaFacts {
    let mut facts = summarise(info);
    let claim = crate::release::parse_release(name);
    let Some(v) = main_video(info) else {
        // No video track read yet: a name can claim what it likes and
        // nothing here is in a position to disagree.
        return facts;
    };

    // Resolution. Flagged in BOTH directions: a name and a frame size
    // that disagree is a mislabel whichever way round it goes, and the
    // sentence the UI writes reports both sides rather than accusing.
    //
    // EXCEPT the narrow-frame shape: a 4:3 episode encoded at the full
    // class width (1920x1440 inside a series named 1080p - Gary's SNW
    // "Chiaroscuro" report) is taller than 16:9, so the label reads a
    // height past the named class while the WIDTH is exactly the class
    // the name claims. That is the mirror of the scope case res_label
    // already handles (2592x1080 stays 1080p), and it is not a
    // mislabel: the chip still shows the measured label as a fact, but
    // the warning stands down. A genuine 2560x1440 named 1080p still
    // warns - it is not a 4:3 frame at all. See
    // `four_by_three_at_class_width` for why the shape is tested and
    // not just the height-to-width direction.
    if let (Some(claimed), Some(actual)) = (&claim.res, &facts.res)
        && claimed != actual
        && !four_by_three_at_class_width(v.width, v.height, claimed)
    {
        facts.mismatch.push(Mismatch {
            field: Field::Resolution,
            claimed: claimed.clone(),
            actual: actual.clone(),
        });
    }

    // Video codec, when BOTH sides are in the table. An unrecognised
    // codec on either side asserts nothing - `lookup` hands back the raw
    // id lowercased when it does not know one, and "this raw string is
    // not the word x265" is not evidence of anything.
    //
    // The guard reads the CodecID rather than the resolved name, which
    // also stands down on a VFW-wrapped track: its wrapper id is in
    // nobody's column even though the CodecPrivate inside it resolved
    // fine. That costs a check on a container shape that predates all of
    // this, and it errs in the only direction this module tolerates.
    if let (Some(claimed), Some(want)) = (
        &claim.vcodec,
        claim.vcodec.as_deref().and_then(name_vcodec_canon),
    ) && super::codec::lookup(info.container, &v.codec_id, true).1
        != super::CodecSupport::NotRecognized
        && v.codec != want
    {
        facts.mismatch.push(Mismatch {
            field: Field::Video,
            claimed: claimed.clone(),
            actual: vcodec_label(&v.codec),
        });
    }

    // Audio: the claimed family must appear on SOME track. A release
    // with a TrueHD track and an AC3 compatibility track satisfies both
    // a "TrueHD" and an "AC3" name, which is exactly right.
    //
    // Only on a COMPLETE read: "no track in the claimed family" is an
    // absence claim over the whole track list, and an incomplete probe
    // (a header still downloading, or more tracks than we will list)
    // knows its list is partial - the TrueHD track a name promises may
    // sit in the unread tail while only the AC3 compatibility track was
    // reached. Calling the file fake on evidence like that is the false
    // amber this module must not raise; the video/resolution rules
    // compare a track that WAS read, so they stand. A later complete
    // probe re-judges (`media_settled` requires `complete`).
    if let Some(claimed) = &claim.acodec
        && let Some(family) = name_acodec_family(claimed)
        && info.complete
        && !info.audio.is_empty()
        && !info
            .audio
            .iter()
            .any(|a| family.contains(&a.codec.as_str()))
    {
        facts.mismatch.push(Mismatch {
            field: Field::Audio,
            claimed: claimed.clone(),
            actual: facts.audio.clone().unwrap_or_else(|| "?".to_string()),
        });
    }

    if let Some(claimed) = &claim.hdr
        && let Some(m) = hdr_mismatch(claimed, v)
    {
        facts.mismatch.push(m);
    }
    facts
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::mediaprobe::{Container, ProbeHint, probe, testmux};

    fn probed(bytes: &[u8]) -> MediaInfo {
        probe(
            &mut std::io::Cursor::new(bytes.to_vec()),
            ProbeHint::default(),
        )
        .expect("fixture must parse")
    }

    #[test]
    fn resolution_buckets_take_both_dimensions() {
        // Scope crops the height; the format is still 1080p / 2160p.
        assert_eq!(res_label(1920, 1080).as_deref(), Some("1080p"));
        assert_eq!(res_label(1920, 800).as_deref(), Some("1080p"));
        assert_eq!(res_label(3840, 2160).as_deref(), Some("2160p"));
        assert_eq!(res_label(3840, 1600).as_deref(), Some("2160p"));
        // DCI 4K is wider than UHD and shorter than it: 2160p either way.
        assert_eq!(res_label(4096, 1716).as_deref(), Some("2160p"));
        // 4:3 and anamorphic SD - the width alone would call both of
        // these 720p, which is the bug the effective height exists for.
        assert_eq!(res_label(1024, 576).as_deref(), Some("576p"));
        assert_eq!(res_label(720, 576).as_deref(), Some("576p"));
        assert_eq!(res_label(720, 480).as_deref(), Some("480p"));
        assert_eq!(res_label(1440, 1080).as_deref(), Some("1080p"));
        assert_eq!(res_label(1280, 720).as_deref(), Some("720p"));
        assert_eq!(res_label(2560, 1440).as_deref(), Some("1440p"));
        // Scope scaled by HEIGHT keeps a full 1080 rows and a width past
        // 1920 - still a 1080p release, not a 1440p one (Gary's
        // 2592x1080 SNW report, and every 21:9 "ultrawide 1080p").
        assert_eq!(res_label(2592, 1080).as_deref(), Some("1080p"));
        assert_eq!(res_label(2560, 1080).as_deref(), Some("1080p"));
        // The mod-16 coded spelling of 1080 counts as 1080.
        assert_eq!(res_label(2592, 1088).as_deref(), Some("1080p"));
        // A frame size the container did not state is not a resolution.
        assert_eq!(res_label(0, 1080), None);
        assert_eq!(res_label(1920, 0), None);
    }

    #[test]
    fn the_chip_reads_like_a_release_name() {
        // 1920x1080 h264, AAC stereo + AC3 5.1: the strongest audio wins
        // exactly as it does when the NAME is parsed.
        let f = summarise(&probed(&testmux::mkv_full()));
        assert_eq!(f.res.as_deref(), Some("1080p"));
        assert_eq!(f.vcodec.as_deref(), Some("H.264"));
        assert_eq!(f.audio.as_deref(), Some("DD 5.1"));
        assert_eq!(f.hdr, None, "an untagged encode carries no format");
        assert_eq!(f.container.as_deref(), Some("mkv"));
        assert!(f.any());

        let f = summarise(&probed(&testmux::mkv_hdr()));
        assert_eq!(f.vcodec.as_deref(), Some("HEVC"));
        assert_eq!(f.audio.as_deref(), Some("DDP 5.1"));
        assert_eq!(f.hdr.as_deref(), Some("HDR10"));
    }

    #[test]
    fn a_disabled_track_does_not_speak_for_the_file() {
        // The DTS 5.1 track in this fixture is FlagEnabled 0, so the
        // stereo AAC is what the file actually plays.
        let f = summarise(&probed(&testmux::mkv_disabled_track()));
        assert_eq!(f.audio.as_deref(), Some("AAC 2.0"));
    }

    #[test]
    fn an_honest_name_is_never_contradicted() {
        let info = probed(&testmux::mkv_full());
        for name in [
            "Example.Movie.2019.1080p.BluRay.x264.AC3-GRP",
            // Under-sold: the file's AC3 5.1 satisfies a plain "DD5.1",
            // and a name that mentions no codec claims nothing at all.
            "Example.Movie.2019.1080p.BluRay-GRP",
            "Example.Movie.2019.1080p.WEB.h264.DD5.1-GRP",
        ] {
            assert!(
                check(&info, name).mismatch.is_empty(),
                "false accusation on {name}"
            );
        }
        let hdr = probed(&testmux::mkv_hdr());
        for name in [
            "Example.Movie.2019.2160p.UHD.BluRay.x265.HDR10.DDP5.1-GRP",
            "Example.Movie.2019.1080p.BluRay.HEVC.DDP5.1-GRP",
        ] {
            let m = check(&hdr, name).mismatch;
            // The 2160p name IS a resolution mismatch (the fixture is
            // 1080p); what must not appear is a codec, audio or HDR one.
            assert!(
                m.iter().all(|x| x.field == Field::Resolution),
                "false accusation on {name}: {m:?}"
            );
        }
    }

    /// A 4:3 episode encoded at the full class width (1920x1440 inside
    /// a 1080p-named series - Gary's SNW "Chiaroscuro" report) is not a
    /// mislabel: the width IS the named class, the height is just the
    /// 4:3 shape. The chip may state 1440p as a fact, but the warning
    /// stands down. A genuine 2560x1440 named 1080p still warns.
    #[test]
    fn a_full_width_four_by_three_frame_is_not_a_resolution_mislabel() {
        let mut info = probed(&testmux::mkv_full());
        info.video[0].width = 1920;
        info.video[0].height = 1440;
        let m = check(&info, "Example.Show.S04E04.1080p.WEB.x264.DD5.1-GRP").mismatch;
        assert!(
            !m.iter().any(|x| x.field == Field::Resolution),
            "false accusation on a 1920x1440 4:3 frame named 1080p: {m:?}"
        );
        info.video[0].width = 2560;
        let m = check(&info, "Example.Show.S04E04.1080p.WEB.x264.DD5.1-GRP").mismatch;
        assert!(
            m.iter().any(|x| x.field == Field::Resolution),
            "a real 2560x1440 named 1080p must still warn"
        );
        // The same shape one class down: 1280x960 measures 1080p and is
        // named 720p, and 1280 IS the 720p class width.
        info.video[0].width = 1280;
        info.video[0].height = 960;
        let m = check(&info, "Example.Show.S04E04.720p.WEB.x264.DD5.1-GRP").mismatch;
        assert!(
            !m.iter().any(|x| x.field == Field::Resolution),
            "false accusation on a 1280x960 4:3 frame named 720p: {m:?}"
        );
    }

    /// The stand-down is for a 4:3 frame at the claimed class's OWN full
    /// width, and for nothing else. Every one of these is taller than
    /// 16:9 and every one has a width whose implied bucket lands on the
    /// claimed class - which is all the older test asked for, so all
    /// three were excused. None of them is a 4:3 broadcast frame, and
    /// each is exactly the mislabel the rule exists to catch.
    #[test]
    fn a_square_or_portrait_frame_is_not_excused_as_a_narrow_frame() {
        for (w, h, name, why) in [
            // Square: measures 1440p, width implies 810 rows -> 720p.
            (
                1440,
                1440,
                "Example.Show.S04E04.720p.WEB.x264.DD5.1-GRP",
                "square",
            ),
            // Portrait: measures 2160p, width implies 1080 -> 1080p.
            (
                1920,
                2560,
                "Example.Show.S04E04.1080p.WEB.x264.DD5.1-GRP",
                "portrait",
            ),
            // 2:3, at the 1080p class width but nowhere near 4:3.
            (
                1920,
                2880,
                "Example.Show.S04E04.1080p.WEB.x264.DD5.1-GRP",
                "2:3 tall",
            ),
        ] {
            let mut info = probed(&testmux::mkv_full());
            info.video[0].width = w;
            info.video[0].height = h;
            let m = check(&info, name).mismatch;
            assert!(
                m.iter().any(|x| x.field == Field::Resolution),
                "a {why} {w}x{h} frame named {name} must still warn: {m:?}"
            );
        }
    }

    #[test]
    fn an_upscale_sold_as_uhd_is_caught() {
        let info = probed(&testmux::mkv_full());
        let m = check(&info, "Example.Movie.2019.2160p.BluRay.x265.Atmos-GRP").mismatch;
        let res = m.iter().find(|x| x.field == Field::Resolution).unwrap();
        assert_eq!(
            (res.claimed.as_str(), res.actual.as_str()),
            ("2160p", "1080p")
        );
        let vid = m.iter().find(|x| x.field == Field::Video).unwrap();
        assert_eq!(
            (vid.claimed.as_str(), vid.actual.as_str()),
            ("x265", "H.264")
        );
        let aud = m.iter().find(|x| x.field == Field::Audio).unwrap();
        assert_eq!(
            (aud.claimed.as_str(), aud.actual.as_str()),
            ("Atmos", "DD 5.1")
        );
    }

    #[test]
    fn atmos_is_honoured_by_either_carrier() {
        // No container header says "Atmos" - the JOC substream is inside
        // the audio. A TrueHD or E-AC3 track is as close to proof as
        // this layer gets, and must not be called a fake.
        let hdr = probed(&testmux::mkv_hdr()); // E-AC3 5.1
        assert!(
            check(&hdr, "Example.Movie.2019.1080p.BluRay.x265.Atmos-GRP")
                .mismatch
                .iter()
                .all(|m| m.field != Field::Audio)
        );
    }

    #[test]
    fn dolby_vision_is_never_accused() {
        // Matroska signals DV in a BlockAdditionMapping this probe does
        // not read, so "no DV found" is our blind spot, not a lie. The
        // fixture is a plain SDR h264 encode - the strongest possible
        // temptation to flag it, and it must still stay quiet.
        let info = probed(&testmux::mkv_full());
        let m = check(&info, "Example.Movie.2019.1080p.BluRay.x264.DV.DD5.1-GRP").mismatch;
        assert!(m.iter().all(|x| x.field != Field::Hdr), "{m:?}");
    }

    #[test]
    fn an_hdr_claim_needs_colour_tags_to_be_denied() {
        // mkv_full carries no Colour element at all, so its video track
        // has no `hdr` block: an HDR10 name is unverifiable, not false.
        let info = probed(&testmux::mkv_full());
        assert!(main_video(&info).unwrap().hdr.is_none());
        let m = check(&info, "Example.Movie.2019.1080p.BluRay.x264.HDR10-GRP").mismatch;
        assert!(m.iter().all(|x| x.field != Field::Hdr), "{m:?}");

        // Tag it bt709/bt709 and the container HAS answered - now the
        // claim is contradicted.
        let mut v = main_video(&info).unwrap().clone();
        v.hdr = Some(super::super::Hdr {
            matrix: Some("bt709".into()),
            transfer: Some("bt709".into()),
            primaries: Some("bt709".into()),
            max_cll: None,
            max_fall: None,
            format: "SDR".into(),
        });
        let mut sdr = info.clone();
        sdr.video = vec![v];
        let m = check(&sdr, "Example.Movie.2019.1080p.BluRay.x264.HDR10-GRP").mismatch;
        let h = m.iter().find(|x| x.field == Field::Hdr).unwrap();
        assert_eq!((h.claimed.as_str(), h.actual.as_str()), ("HDR10", "SDR"));
    }

    #[test]
    fn an_unrecognised_codec_accuses_nobody() {
        // A VFW-wrapped track: the probe resolves it to mpeg4 through
        // the CodecPrivate, but the wrapper CodecID is in nobody's
        // column, so the codec check stands down and the XviD name is
        // left alone. Either way round, no accusation.
        let info = probed(&testmux::mkv_vfw_xvid());
        assert!(
            check(&info, "Example.Movie.2003.480p.DVDRip.XviD-GRP")
                .mismatch
                .iter()
                .all(|m| m.field != Field::Video)
        );
        // ...and a codec id in nobody's table stays silent rather than
        // contradicting a name it cannot read.
        let mut odd = info.clone();
        odd.video[0].codec = "wibble".into();
        odd.video[0].codec_id = "V_WIBBLE".into();
        let m = check(&odd, "Example.Movie.2003.480p.DVDRip.x264-GRP").mismatch;
        assert!(m.iter().all(|x| x.field != Field::Video), "{m:?}");
    }

    /// The audio rule asserts an ABSENCE ("no track in the claimed
    /// family"), and an incomplete probe knows its track list may be
    /// partial - the TrueHD track an Atmos name promises can sit in the
    /// unread tail while only the AC3 compatibility track was reached.
    /// It must stand down until the read is complete; the same evidence
    /// on a complete read is a genuine mismatch.
    #[test]
    fn a_partial_track_list_never_calls_the_audio_fake() {
        let mut info = probed(&testmux::mkv_full());
        assert!(info.complete);
        // mkv_full's audio family does not satisfy a DTS name.
        let name = "Example.Movie.2019.1080p.BluRay.x264.DTS-GRP";
        assert!(
            check(&info, name)
                .mismatch
                .iter()
                .any(|m| m.field == Field::Audio),
            "the complete read must still flag the mismatch"
        );
        info.incomplete("this file has more tracks than we will list");
        assert!(
            check(&info, name)
                .mismatch
                .iter()
                .all(|m| m.field != Field::Audio),
            "an incomplete track list is not evidence of absence"
        );
    }

    /// §188: every label this module derives keeps the inputs it was
    /// derived FROM, so the next fix in one of these families is
    /// arithmetic over a stored row rather than a re-probe of a file
    /// that may not exist any more.
    #[test]
    fn every_label_keeps_the_inputs_it_was_reduced_from() {
        let f = summarise(&probed(&testmux::mkv_full()));
        // Resolution, the pair that came first.
        assert_eq!((f.width, f.height), (Some(1920), Some(1080)));
        // Video codec: the probe's canonical id, not "H.264" back again
        // and not the container's V_MPEG4/ISO/AVC either.
        assert_eq!(f.vcodec_canon.as_deref(), Some("h264"));
        // Audio: the AC3 5.1 track wins, and both halves of "DD 5.1"
        // are recoverable from what is stored beside it.
        assert_eq!(f.acodec_canon.as_deref(), Some("ac3"));
        assert_eq!(f.channels, Some(6));
        assert_eq!(f.channel_layout.as_deref(), Some("5.1"));
        // This fixture carries no Colour element at all.
        assert_eq!(
            (f.hdr_transfer.as_deref(), f.hdr_primaries.as_deref()),
            (None, None)
        );

        let h = summarise(&probed(&testmux::mkv_hdr()));
        assert_eq!(h.vcodec_canon.as_deref(), Some("hevc"));
        assert_eq!(h.acodec_canon.as_deref(), Some("eac3"));
        assert_eq!(h.channels, Some(6));
        assert_eq!(h.hdr_transfer.as_deref(), Some("pq"));
        assert_eq!(h.hdr_primaries.as_deref(), Some("bt2020"));
    }

    /// The property the storage exists for: each label is a pure
    /// function of the fields stored beside it, so re-running the
    /// derivation over a ROW reproduces the row - no file, no probe.
    /// A future fix in any of these families is then a change to one of
    /// these functions plus a walk over stored rows.
    #[test]
    fn every_label_rebuilds_from_the_stored_inputs_alone() {
        for fixture in [
            testmux::mkv_full(),
            testmux::mkv_hdr(),
            testmux::mkv_disabled_track(),
            testmux::mkv_vfw_xvid(),
        ] {
            let f = summarise(&probed(&fixture));
            assert_eq!(
                f.res,
                f.width.zip(f.height).and_then(|(w, h)| res_label(w, h)),
                "resolution"
            );
            assert_eq!(
                f.vcodec,
                f.vcodec_canon.as_deref().map(vcodec_label),
                "video codec"
            );
            let audio = f.acodec_canon.as_deref().map(|c| {
                format!(
                    "{} {}",
                    acodec_label(c),
                    channels_label(
                        f.channels.unwrap_or(0),
                        f.channel_layout.as_deref().unwrap_or_default()
                    )
                )
            });
            assert_eq!(f.audio, audio, "audio");
            let hdr = super::super::codec::hdr_format(
                f.hdr_transfer.as_deref(),
                f.hdr_primaries.as_deref(),
            );
            // The label drops "SDR" and the absence of colour tags
            // alike; both spell `None` on the row.
            let hdr = (hdr != "SDR").then_some(hdr);
            assert_eq!(f.hdr, hdr, "dynamic range");
        }
    }

    /// The one thing [`MediaFacts::hdr`] alone cannot say: whether the
    /// container was SILENT about colour or positively said SDR. Only
    /// the second is grounds for contradicting an HDR name, and the
    /// label spells both `None`.
    #[test]
    fn a_stored_row_still_tells_sdr_from_a_silent_container() {
        let silent = summarise(&probed(&testmux::mkv_full()));
        assert_eq!(silent.hdr, None);
        assert!(silent.hdr_transfer.is_none() && silent.hdr_primaries.is_none());

        let info = probed(&testmux::mkv_full());
        let mut v = main_video(&info).unwrap().clone();
        v.hdr = Some(super::super::Hdr {
            matrix: Some("bt709".into()),
            transfer: Some("bt709".into()),
            primaries: Some("bt709".into()),
            max_cll: None,
            max_fall: None,
            format: "SDR".into(),
        });
        let mut sdr = info.clone();
        sdr.video = vec![v];
        let sdr = summarise(&sdr);
        assert_eq!(sdr.hdr, None, "SDR is not a badge");
        assert_eq!(sdr.hdr_transfer.as_deref(), Some("bt709"));
        assert_eq!(sdr.hdr_primaries.as_deref(), Some("bt709"));
        assert!(!silent.same_raw_inputs(&sdr));
        assert!(
            silent.same_labels(&sdr),
            "the chip reads the same either way"
        );
    }

    /// A row written by any build before these fields existed still
    /// loads, and loses nothing it did carry. This is the whole of the
    /// wire compatibility promise: `history.jsonl` is append-only and
    /// its oldest rows outlive every schema they were written under.
    #[test]
    fn a_row_written_before_the_raw_inputs_existed_still_loads() {
        // Verbatim from the live daemon's history.jsonl, §188.
        let old = r#"{"audio":"DDP 5.1","complete":true,"container":"mkv",
            "res":"2160p","vcodec":"HEVC","hdr":"HDR10","duration_ms":60000,
            "mismatch":[{"field":"resolution","claimed":"2160p","actual":"1080p"}]}"#;
        let f: MediaFacts = serde_json::from_str(old).expect("an old row must still load");
        assert_eq!(f.res.as_deref(), Some("2160p"));
        assert_eq!(f.audio.as_deref(), Some("DDP 5.1"));
        assert_eq!(f.mismatch.len(), 1);
        // Absent, not zeroed: "not recorded" and "the container said
        // zero channels" must not read alike, or a re-derivation over
        // stored rows would invent a mono track.
        assert_eq!(f.channels, None);
        assert_eq!(f.vcodec_canon, None);
        assert_eq!(f.acodec_canon, None);
        assert_eq!(f.channel_layout, None);
        assert_eq!(f.hdr_transfer, None);
        assert_eq!(f.hdr_primaries, None);
        assert_eq!((f.width, f.height), (None, None));
    }

    /// And the other direction: a row with no raw inputs serialises to
    /// exactly the JSON the old build wrote, so a downgrade - or an
    /// older reader of the same file - sees nothing new.
    #[test]
    fn an_input_less_row_serialises_to_the_old_shape() {
        let f = MediaFacts {
            res: Some("1080p".into()),
            complete: true,
            ..Default::default()
        };
        let json = serde_json::to_string(&f).unwrap();
        for absent in [
            "width",
            "height",
            "vcodec_canon",
            "acodec_canon",
            "channels",
            "channel_layout",
            "hdr_transfer",
            "hdr_primaries",
        ] {
            assert!(!json.contains(absent), "{absent} must not appear in {json}");
        }
        // A probed row does carry them, and round-trips unchanged.
        let probed = summarise(&probed(&testmux::mkv_hdr()));
        let json = serde_json::to_string(&probed).unwrap();
        assert!(json.contains("\"channels\":6"), "{json}");
        assert_eq!(
            serde_json::from_str::<MediaFacts>(&json).unwrap(),
            probed,
            "a raw-input row must survive the wire"
        );
    }

    /// The split the history re-derivation pass counts on: raw inputs
    /// are invisible to a reader, and everything else is not.
    #[test]
    fn same_labels_masks_the_raw_inputs_and_nothing_else() {
        let f = summarise(&probed(&testmux::mkv_full()));
        // The shape of an old row: same chip, no inputs behind it.
        let mut bare = f.clone();
        bare.width = None;
        bare.height = None;
        bare.vcodec_canon = None;
        bare.acodec_canon = None;
        bare.channels = None;
        bare.channel_layout = None;
        bare.hdr_transfer = None;
        bare.hdr_primaries = None;
        assert!(f.same_labels(&bare), "gaining inputs is not a correction");
        assert!(!f.same_raw_inputs(&bare));
        assert!(f.same_labels(&f) && f.same_raw_inputs(&f));

        // Every visible field is visible.
        for mutate in [
            (|m: &mut MediaFacts| m.res = Some("2160p".into())) as fn(&mut MediaFacts),
            |m| m.vcodec = Some("AV1".into()),
            |m| m.audio = Some("DTS 7.1".into()),
            |m| m.hdr = Some("HDR10".into()),
            |m| m.duration_ms = Some(1),
            |m| m.container = Some("mp4".into()),
            |m| m.complete = !m.complete,
            |m| {
                m.mismatch.push(Mismatch {
                    field: Field::Audio,
                    claimed: "Atmos".into(),
                    actual: "DD 5.1".into(),
                })
            },
        ] {
            let mut other = f.clone();
            mutate(&mut other);
            assert!(!f.same_labels(&other), "{other:?} reads the same as {f:?}");
            assert!(f.same_raw_inputs(&other), "no raw input was touched");
        }
    }

    #[test]
    fn a_container_with_no_tracks_yet_says_nothing() {
        // The state a job is in for its first second: enough bytes to
        // identify the container, none to read a track.
        let info = MediaInfo {
            container: Container::Mkv,
            duration_ms: None,
            playback: super::super::PlaybackPath::Unknown,
            video: vec![],
            audio: vec![],
            subtitles: vec![],
            chapters: vec![],
            title: None,
            complete: false,
            warnings: vec![],
        };
        let f = check(&info, "Example.Movie.2019.2160p.BluRay.x265.Atmos-GRP");
        assert!(!f.any());
        assert!(f.mismatch.is_empty());
        assert!(!f.complete);
    }
}
