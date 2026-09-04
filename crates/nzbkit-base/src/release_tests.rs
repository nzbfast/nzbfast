//! The release-name parser's own test table, moved out whole (TODO 106).
//!
//! release.rs regrew past its size-gate baseline as the dark-verdict and
//! year-is-an-extension rounds landed; its inline `mod tests` was 1,427
//! lines, nearly half the file. Moving it here drops the parser under the
//! 3,000-line ceiling with margin measured in hundreds of lines, and the
//! entry comes off the baseline list entirely.
//!
//! A child module, so `use super::*` names every private helper - the
//! token classifiers, the rescues, the markers - exactly as the inline
//! block did.

use super::*;

fn p(stem: &str) -> Parsed {
    parse_release(stem)
}

/// The words that tell one event from another are the ones the
/// parser could not classify, so keeping `extra` is what stops a
/// whole season collapsing onto one name.
#[test]
fn extra_words_keep_events_apart() {
    let on = NameStyle {
        resolution: true,
        extra_words: true,
        ..Default::default()
    };
    let off = NameStyle {
        resolution: true,
        ..Default::default()
    };

    let race =
        p("Formula1.2026.Round11.Hungary.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR");
    let quali = p("Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.1080p.H264-MWR");
    let next = p("Formula1.2026.Round12.Belgium.Race.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1-MWR");

    // Off: decline, exactly as before, so the poster's name survives.
    assert_eq!(movie_name(&race, &off), None);
    assert_eq!(movie_name(&quali, &off), None);

    // On: three names, three distinct strings.
    let a = movie_name(&race, &on).unwrap();
    let b = movie_name(&quali, &on).unwrap();
    let c = movie_name(&next, &on).unwrap();
    assert_eq!(a, "Formula1 2026 Round11 Hungary Race F1TV 2160p");
    assert_ne!(a, b);
    assert_ne!(a, c);
    assert!(b.contains("Qualifying"));
    assert!(c.contains("Round12") && c.contains("Belgium"));

    // Short numbers carry meaning and must survive ("Week 03").
    let nfl = p("NFL.2025.Week.03.Chiefs.vs.Bills.1080p.WEB.h264-SPORTSNET");
    assert_eq!(
        movie_name(&nfl, &on).unwrap(),
        "NFL 2025 Week 03 Chiefs vs Bills 1080p"
    );
}

/// An edition word straight after an identity word is the name
/// continuing, not an edition. Tester Gary's F1TV post of the show
/// "Paddock Uncut" rendered as "…Paddock [1080p x264]" - the Uncut half
/// of the show's own name was stripped as if it marked an uncut print.
#[test]
fn edition_word_after_identity_stays_in_the_name() {
    // The raw tail rule.
    assert_eq!(
        identity_tail([
            "Dutch", "Grand", "Prix", "Paddock", "Uncut", "1080p", "AHDTV", "x264"
        ]),
        ["Dutch", "Grand", "Prix", "Paddock", "Uncut"]
    );
    // Straight after the year (an empty tail so far) or after a language
    // tag it is still the edition marker it always was.
    assert!(identity_tail(["Uncut", "1080p"]).is_empty());
    assert!(identity_tail(["German", "Uncut", "1080p"]).is_empty());

    // End to end on the user's real NZB name.
    let on = NameStyle {
        resolution: true,
        extra_words: true,
        ..Default::default()
    };
    let show = p("Formula1.2026.Dutch.Grand.Prix.Paddock.Uncut.1080p.AHDTV.x264-DARKSPORT");
    assert_eq!(show.extra, ["Dutch", "Grand", "Prix", "Paddock", "Uncut"]);
    assert_eq!(
        movie_name(&show, &on).unwrap(),
        "Formula1 2026 Dutch Grand Prix Paddock Uncut 1080p"
    );
}

/// The option must not reach an ordinary film. It cannot, because a
/// film that parses cleanly leaves `extra` empty - this pins that.
#[test]
fn extra_words_never_touch_a_clean_film() {
    let on = NameStyle {
        resolution: true,
        extra_words: true,
        ..Default::default()
    };
    for stem in [
        "Example.Movie.2024.1080p.BluRay.x265-GRP",
        "Another.Film.2019.EXTENDED.2160p.UHD.BluRay.x265.DTS-HD.MA.7.1-FGT",
        "A.Film.2020.PROPER.REPACK.1080p.WEB-DL.DD5.1.H264-GRP",
        "Film.AKA.Other.Name.2015.1080p.BluRay.x264-GRP",
        "Le.Film.Francais.2019.FRENCH.1080p.BluRay.x264-GRP",
        "Film.Name.2017.1080p.WEBRip.x264-[YTS.AM]",
    ] {
        let parsed = p(stem);
        assert!(
            parsed.extra.is_empty(),
            "{stem} leaked {:?} into extra",
            parsed.extra
        );
        assert_eq!(
            movie_name(&parsed, &on),
            movie_name(
                &parsed,
                &NameStyle {
                    resolution: true,
                    ..Default::default()
                }
            ),
            "{stem} renamed differently with extra words on"
        );
    }
}

#[test]
fn extra_words_filters_noise_and_declines_when_nothing_is_left() {
    let on = NameStyle {
        resolution: true,
        extra_words: true,
        ..Default::default()
    };
    // Group tag is not repeated; it has its own opt-in.
    let mut m = p("Formula1.2026.Round11.Hungary.Race.1080p-MWR");
    m.extra.push("MWR".into());
    let name = movie_name(&m, &on).unwrap();
    assert_eq!(name.matches("MWR").count(), 0, "group duplicated: {name}");

    // A hash and a long bare number describe nothing.
    let mut n = p("Something.2020.1080p-GRP");
    n.extra = vec![
        "b9320de1deb550b9f2f70716eabbcb19".into(),
        "1234567890".into(),
    ];
    assert_eq!(
        movie_name(&n, &on),
        None,
        "noise-only extra must decline, not collide"
    );

    // Cap: a padded post does not rebuild the whole release name.
    let mut many = p("Event.2020.1080p-GRP");
    many.extra = (1..=12).map(|i| format!("Word{i}")).collect();
    let capped = movie_name(&many, &on).unwrap();
    assert!(
        capped.contains("Word6") && !capped.contains("Word7"),
        "{capped}"
    );
}

#[test]
fn codecs_extracted_friendly() {
    let m = p("Example.Movie.2024.1080p.BluRay.x265.DTS-HD.MA-FGT");
    assert_eq!(m.res.as_deref(), Some("1080p"));
    assert_eq!(m.vcodec.as_deref(), Some("x265"));
    assert_eq!(m.acodec.as_deref(), Some("DTS-HD"));
    assert_eq!(m.source.as_deref(), Some("BluRay"));
    assert_eq!(m.group.as_deref(), Some("FGT"));
    // h264/avc fold to x264; strongest audio wins over a weaker track.
    let a = p("Some.Show.2020.720p.WEB.h264.AC3.DDP5.1-GRP");
    assert_eq!(a.vcodec.as_deref(), Some("x264"));
    assert_eq!(a.acodec.as_deref(), Some("DDP"));
    // Atmos outranks TrueHD regardless of token order.
    assert_eq!(
        p("Film.2021.2160p.TrueHD.Atmos.x265-X").acodec.as_deref(),
        Some("Atmos")
    );
}

#[test]
fn dynamic_range_extracted() {
    // A real DV release names its HDR10 base layer too - the richer
    // format has to win, whichever order the tokens come in.
    let dv = p("Dune.Part.Two.2024.2160p.WEB-DL.DDP5.1.Atmos.DV.HDR.H.265-FLUX");
    assert_eq!(dv.hdr.as_deref(), Some("DV"));
    assert_eq!(dv.acodec.as_deref(), Some("Atmos"));
    assert_eq!(dv.title, "Dune Part Two");
    assert_eq!(
        p("Film.2021.2160p.HDR.DoVi.x265-X").hdr.as_deref(),
        Some("DV")
    );
    // Plain HDR flavours, most specific first.
    assert_eq!(
        p("A.2020.2160p.HDR10+.x265-G").hdr.as_deref(),
        Some("HDR10+")
    );
    assert_eq!(p("A.2020.2160p.HDR10.x265-G").hdr.as_deref(), Some("HDR10"));
    assert_eq!(p("A.2020.2160p.HDR.x265-G").hdr.as_deref(), Some("HDR"));
    assert_eq!(p("A.2020.2160p.HLG.x265-G").hdr.as_deref(), Some("HLG"));
    // SDR states an absence: recording it would make a plain encode
    // look like it carries a format.
    assert_eq!(p("A.2020.1080p.SDR.x264-G").hdr, None);
    assert_eq!(p("A.2020.1080p.BluRay.x264-G").hdr, None);
    // Capturing these must not change what the title parse drops -
    // they were already stripped as furniture.
    assert_eq!(p("A.2020.2160p.HDR.DV.x265-G").title, "A");
}

#[test]
fn friendly_name_builder() {
    let m = p("Example.Movie.2024.1080p.BluRay.x265.DTS-HD.MA-FGT");
    // Default: title + year + resolution only.
    // Brackets around the year and the quality facts are OFF by
    // default, so this is the shipped shape.
    let def = NameStyle {
        resolution: true,
        ..Default::default()
    };
    assert_eq!(
        movie_name(&m, &def).as_deref(),
        Some("Example Movie 2024 1080p")
    );
    // Both bracket styles on: the shape nzbfast produced before they
    // were options, and the one Plex/Jellyfin/Radarr match films on.
    let brk = NameStyle {
        resolution: true,
        year_parens: true,
        quality_brackets: true,
        ..Default::default()
    };
    assert_eq!(
        movie_name(&m, &brk).as_deref(),
        Some("Example Movie (2024) [1080p]")
    );
    // Everything on.
    let full = NameStyle {
        resolution: true,
        video_codec: true,
        audio_codec: true,
        source: true,
        group: true,
        year_parens: true,
        quality_brackets: true,
        extra_words: true,
    };
    assert_eq!(
        movie_name(&m, &full).as_deref(),
        Some("Example Movie (2024) [1080p BluRay x265 DTS-HD]-FGT")
    );
    // Nothing enabled → clean title + year, unbracketed.
    assert_eq!(
        movie_name(&m, &NameStyle::default()).as_deref(),
        Some("Example Movie 2024")
    );
    // No year → title alone; REMUX shows in the source slot.
    let r = p("Some.Movie.2160p.BluRay.REMUX.HEVC-GRP");
    let src = NameStyle {
        resolution: true,
        source: true,
        ..Default::default()
    };
    assert_eq!(
        movie_name(&r, &src).as_deref(),
        Some("Some Movie 2160p REMUX")
    );
    // Obfuscated → no friendly name, keep the original.
    assert_eq!(
        movie_name(&p("2137d880a074fa4075a65ce4e21d2f95"), &full),
        None
    );
}

/// An event post's year is its SEASON, not a release date: everything
/// that identifies it ("Round11.Hungary.Post-Qualifying.Show") comes
/// after the year and the title drops it. Reduced to "Title (Year)"
/// every session of every round of 2026 rendered the same filename
/// and collided on disk, so we decline to rename those at all and the
/// poster's own name survives. Both stems are the user's real NZBs.
#[test]
fn event_releases_are_not_renamed_to_title_year() {
    let style = NameStyle {
        resolution: true,
        ..Default::default()
    };
    let show =
        p("Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR");
    let quali =
        p("Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR");
    // Both used to render "Formula1 (2026) [1080p]".
    assert_eq!(show.title, "Formula1");
    assert_eq!(
        show.extra,
        ["Round11", "Hungary", "Post-Qualifying", "Show", "F1TV"]
    );
    assert_eq!(quali.extra, ["Round11", "Hungary", "Qualifying", "F1TV"]);
    // Which is the point: two different sessions no longer render one
    // filename. Neither is renamed under any style, so each keeps the
    // distinct name it was posted under.
    for s in [&NameStyle::default(), &style] {
        assert_eq!(movie_name(&show, s), None);
        assert_eq!(movie_name(&quali, s), None);
    }
    // Same for other event shapes.
    assert_eq!(
        movie_name(
            &p("MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP"),
            &style
        ),
        None
    );
    assert_eq!(
        movie_name(
            &p("NFL.2026.Week.05.Bears.at.Packers.1080p.WEB-DL-GRP"),
            &style
        ),
        None
    );
    // And the guard is not really about sport: it declines whenever
    // "Title (Year)" would not name the release uniquely, which is
    // just as true of an edition the tag table doesn't know - a
    // "Final Cut" renamed to "Movie (2024)" collides with the
    // theatrical cut of the same year.
    assert_eq!(
        movie_name(&p("Some.Movie.2024.Final.Cut.1080p.BluRay-GRP"), &style),
        None
    );
}

/// Declining the RENAME must not change the KIND. `finalize_names`
/// gates its junk sweep on `Movie | Tv`, so an event post demoted to
/// `Other` (or flipped to `Tv`) would silently stop getting its PAR2
/// litter cleaned up - a non-obvious coupling, pinned here because a
/// future refactor of `extra` could so easily break it.
#[test]
fn declining_to_rename_an_event_leaves_it_a_movie() {
    for stem in [
        "Formula1.2026.Round11.Hungary.Post-Qualifying.Show.F1TV.WEB-DL.1080p.H264.English-MWR",
        "Formula1.2026.Round11.Hungary.Qualifying.F1TV.WEB-DL.2160p.HLG.H265.DDP5.1.English-MWR",
        "MotoGP.2026.Round05.France.Race.1080p.WEB-DL-GRP",
        "Some.Movie.2024.Final.Cut.1080p.BluRay-GRP",
    ] {
        let r = p(stem);
        assert_eq!(r.kind, Kind::Movie, "{stem}");
        assert!(!r.extra.is_empty(), "{stem}");
        assert_eq!(movie_name(&r, &NameStyle::default()), None, "{stem}");
    }
}

/// The opposite half: an ordinary film's year IS its release date and
/// everything after it is furniture, so `extra` stays empty and the
/// friendly rename behaves exactly as it always did - including for
/// dubs, editions and split channel tokens.
#[test]
fn ordinary_movies_still_reduce_to_title_year() {
    let style = NameStyle {
        resolution: true,
        ..Default::default()
    };
    for s in [
        "The.Matrix.1999.1080p.BluRay.x264-GROUP",
        "The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR",
        "The.Matrix.1999.EXTENDED.1080p.BluRay.x264-GRP",
        "The.Matrix.1999.Directors.Cut.1080p.BluRay.x264-GRP",
        "The.Matrix.1999.German.DL.1080p.BluRay.x264-DEU",
        "The.Matrix.1999.MULTi.TRUEFRENCH.1080p.WEB.DD.5.1.H.264-GRP",
        "The.Matrix.1999.720p.BluRay.x264.AAC5.1-YTSMX",
        // Audio ahead of every other tag: only the trailing-digit
        // rule keeps "AAC5"/"DDP51" from reading as identity here.
        "The.Matrix.1999.AAC5.1.1080p.WEB-GRP",
        "The.Matrix.1999.DDP51.2160p.WEB-GRP",
    ] {
        let m = p(s);
        assert_eq!(m.kind, Kind::Movie, "{s}");
        assert!(m.extra.is_empty(), "{s}: extra={:?}", m.extra);
        assert_eq!(
            movie_name(&m, &NameStyle::default()).as_deref(),
            Some("The Matrix 1999"),
            "{s}"
        );
    }
    // And the bracketed shape is still one flag away.
    assert_eq!(
        movie_name(&p("The.Matrix.1999.1080p.BluRay.x264-GROUP"), &style).as_deref(),
        Some("The Matrix 1999 1080p")
    );
    let brk = NameStyle {
        resolution: true,
        year_parens: true,
        quality_brackets: true,
        ..Default::default()
    };
    assert_eq!(
        movie_name(&p("The.Matrix.1999.1080p.BluRay.x264-GROUP"), &brk).as_deref(),
        Some("The Matrix (1999) [1080p]")
    );
}

/// The token verdict the rename and the dupe key both stand on.
#[test]
fn token_roles_split_furniture_from_identity() {
    use TokenRole::*;
    // Quality, source, codec, container, edition, provenance: hard.
    for t in [
        "1080p",
        "WEB-DL",
        "x265",
        "REMUX",
        "HDR",
        "mkv",
        "Directors",
        "Cut",
        "HLG",
    ] {
        assert_eq!(token_role(t), HardFurniture, "{t}");
    }
    // Languages are soft: dropped from a key, but never a stopper.
    for t in ["German", "English", "Hungarian", "MULTi", "TRUEFRENCH"] {
        assert_eq!(token_role(t), SoftFurniture, "{t}");
    }
    // A tag with a channel count glued on folds onto the tag…
    for t in ["AAC5", "DTS5", "DDP51", "DD5"] {
        assert_eq!(token_role(t), HardFurniture, "{t}");
    }
    // …but trailing digits alone decide nothing, so an event counter
    // stays identity. This is the whole reason the strip checks that
    // something is LEFT after the digits go.
    for t in [
        "Round11", "Week05", "Stage11", "Hungary", "F1TV", "11", "05",
    ] {
        assert_eq!(token_role(t), Identity, "{t}");
    }
    // A run of nothing but language tags is furniture; the same run
    // alongside real identity tokens is carried whole.
    assert!(identity_tail(["German", "DL", "1080p"]).is_empty());
    assert_eq!(
        identity_tail(["Hungarian", "Grand", "Prix", "Race", "1080p", "WEB"]),
        ["Hungarian", "Grand", "Prix", "Race"]
    );
}

#[test]
fn non_ascii_titles_keep_distinct_dedupe_keys() {
    // §5 phase 2c: norm_title used to drop every non-ASCII character,
    // so all Japanese TV titles shared the key "t:" - one `titles`
    // row, one poster, for unrelated shows.
    let a = p("進撃の巨人.S04E28.1080p.WEB.H264-GRP");
    let b = p("涼宮ハルヒの憂鬱.S01E01.720p");
    assert_eq!(a.kind, Kind::Tv);
    assert_eq!(a.title, "進撃の巨人");
    assert_eq!(a.season, Some(4));
    assert_eq!(a.episode, Some(28));
    assert_ne!(a.key, b.key);
    assert_eq!(a.key, "t:進撃の巨人");
    // Movies too - and Cyrillic/Greek, already-shipped UI locales.
    assert_eq!(p("君の名は.2016.1080p.BluRay.x264").key, "m:君の名は:2016");
    assert_ne!(p("Брат.1997.1080p").key, p("Брат2.2000.1080p").key);
    // ASCII normalization is unchanged.
    assert_eq!(norm_title("The.Daily-Show!"), "the daily show");
}

#[test]
fn daily_dotted_date_is_tv_not_movie() {
    // Dotted daily dates parsed as Movie-of-2026 before; compact
    // datecodes already worked.
    let d = p("The.Daily.Show.2026.07.21.Guest.1080p.WEB.h264-GRP");
    assert_eq!(d.kind, Kind::Tv);
    assert_eq!(d.title, "The Daily Show");
    assert_eq!(d.year, None);
    // Movies with a trailing year stay movies.
    let m = p("Blade.Runner.2049.2017.2160p.WEB-DL");
    assert_eq!(m.kind, Kind::Movie);
    assert_eq!(m.year, Some(2017));
}

/// The air date is a daily show's whole identity, so the split that
/// turns it into a folder year and a filename has to refuse anything
/// that is not a real date rather than emit half of one.
#[test]
fn air_dates_split_into_a_year_and_a_name() {
    let parts = air_date_parts;
    assert_eq!(
        parts("20260721"),
        Some(("2026".into(), "2026.07.21".into()))
    );
    assert_eq!(
        parts("20150615"),
        Some(("2015".into(), "2015.06.15".into()))
    );
    // Both conventions the parser normalizes reach the same name.
    assert_eq!(
        air_date_parts(
            p("At.Midnight.150615.720p.HDTV-GRP")
                .date
                .as_deref()
                .unwrap()
        ),
        air_date_parts(
            p("At.Midnight.20150615.720p.HDTV-GRP")
                .date
                .as_deref()
                .unwrap()
        )
    );
    assert_eq!(
        parts(
            p("The.Daily.Show.2026.07.21.1080p.WEB-GRP")
                .date
                .as_deref()
                .unwrap()
        ),
        Some(("2026".into(), "2026.07.21".into()))
    );
    // Declines: wrong width, non-digits, out-of-range fields.
    for s in [
        "",
        "2026072",
        "202607211",
        "2026-07-21",
        "2026o721",
        "20261321",
        "20260732",
        "20260700",
        "20260021",
        "00000101",
    ] {
        assert_eq!(air_date_parts(s), None, "{s:?} is not an air date");
    }
    // And declines dates that pass a flat 1..=31 day check but do
    // not exist. These were filed as real episodes, under a season
    // folder named after a day that never happened.
    for s in [
        "20260231", "20260431", "20260631", "20260931", "20261131", "20260230",
    ] {
        assert_eq!(air_date_parts(s), None, "{s:?} is not a day that exists");
    }
    // February is the leap rule, in all three of its cases.
    assert!(air_date_parts("20240229").is_some(), "2024 is a leap year");
    assert_eq!(air_date_parts("20260229"), None, "2026 is not");
    assert_eq!(
        air_date_parts("19000229"),
        None,
        "a century is not, unless…"
    );
    assert!(air_date_parts("20000229").is_some(), "…it divides by 400");
    // The month lengths themselves, at their real boundaries.
    assert!(air_date_parts("20260430").is_some());
    assert!(air_date_parts("20261231").is_some());
}

#[test]
fn year_as_season_marker_is_tv() {
    // "S2026E015" (annual sports/soaps) parsed as Movie before -
    // while dupe_key already treated it as TV.
    let r = p("WWE.Raw.S2026E015.1080p.WEB.h264-GRP");
    assert_eq!(r.kind, Kind::Tv);
    assert_eq!((r.season, r.episode), (Some(2026), Some(15)));
    // A bare "S2026" (no episode) stays a year, not a season pack.
    let m = p("Escape.From.S2026.2160p.WEB-DL");
    assert_eq!(m.kind, Kind::Movie);
}

#[test]
fn movie_with_year_and_quality() {
    let m = p("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR");
    assert_eq!(m.kind, Kind::Movie);
    assert_eq!(m.title, "The Matrix");
    assert_eq!(m.year, Some(1999));
    assert_eq!(m.res.as_deref(), Some("2160p"));
    assert!(m.remux);
    assert_eq!(m.group.as_deref(), Some("FraMeSToR"));
    assert_eq!(m.key, "m:the matrix:1999");
    assert_eq!(quality_label(&m), "2160p REMUX");
}

#[test]
fn tv_episode_and_season_pack_share_a_key() {
    let e = p("Severance.S02E03.1080p.WEB-DL.DDP5.1.H.264-NTb");
    assert_eq!(e.kind, Kind::Tv);
    assert_eq!(e.title, "Severance");
    assert_eq!((e.season, e.episode), (Some(2), Some(3)));
    assert_eq!(e.source.as_deref(), Some("WEB"));
    let s = p("Severance.S01.2160p.ATVP.WEB-DL.DDP5.1.DV.HEVC-CasStudio");
    assert_eq!((s.season, s.episode), (Some(1), None));
    assert_eq!(e.key, s.key);
}

#[test]
fn multi_episode_markers() {
    // §7b: S01E01E02 / S01E01-E02 / S01E01-02 carry a second episode.
    for stem in [
        "Show.Name.S01E01E02.1080p.WEB.h264-GRP",
        "Show.Name.S01E01-E02.1080p.WEB.h264-GRP",
        "Show.Name.S01E01-02.1080p.WEB.h264-GRP",
    ] {
        let p = p(stem);
        assert_eq!(p.kind, Kind::Tv, "{stem}");
        assert_eq!(
            (p.season, p.episode, p.episode2),
            (Some(1), Some(1), Some(2)),
            "{stem}"
        );
    }
    // Quality furniture glued to the episode is NOT a second episode,
    // and a lower second number is a typo, not a range.
    assert_eq!(p("Show.S01E05-720p.HDTV").episode2, None);
    assert_eq!(p("Show.S01E05-E03.1080p.WEB").episode2, None);
    // Single episodes and packs stay episode2-free.
    assert_eq!(p("Severance.S02E03.1080p.WEB-DL").episode2, None);
    assert_eq!(p("Severance.S01.2160p.WEB-DL").episode2, None);
}

#[test]
fn title_that_is_a_year() {
    let m = p("2012.2009.1080p.BluRay.x264-METiS");
    assert_eq!(m.title, "2012");
    assert_eq!(m.year, Some(2009));
    let br = p("Blade.Runner.2049.2017.2160p.WEB-DL.x265-XX");
    assert_eq!(br.title, "Blade Runner 2049");
    assert_eq!(br.year, Some(2017));
}

#[test]
fn no_year_movie_cuts_at_first_tag() {
    let m = p("Inception.1080p.BluRay.x264-SPARKS");
    assert_eq!(m.title, "Inception");
    assert_eq!(m.year, None);
    assert_eq!(m.key, "m:inception");
}

#[test]
fn nxnn_form_and_hyphen_title() {
    let e = p("Spider-Man.Into.the.Spider-Verse.2018.1080p.BluRay.x264-GROUP");
    assert_eq!(e.title, "Spider-Man Into the Spider-Verse");
    let t = p("The.Wire.3x07.720p.HDTV.x264-BATV");
    assert_eq!((t.season, t.episode), (Some(3), Some(7)));
    assert_eq!(t.title, "The Wire");
}

#[test]
fn obfuscated_stems_are_other() {
    assert_eq!(p("2137d880a074fa4075a65ce4e21d2f95").kind, Kind::Other);
    assert_eq!(p("n1iY94U6fTpMVY9GPD").kind, Kind::Other);
    assert_eq!(p("abcdef12.34567890abcdef12.deadbeef99").kind, Kind::Other);
    // …but a real name with a digit-bearing word is NOT obfuscated.
    assert_eq!(p("Apollo.13.1995.1080p.BluRay.x264-XX").kind, Kind::Movie);
}

#[test]
fn rot13_letter_rotated_stem_is_rescued() {
    // Letters ROT13, digits posted as-is - the classic obfuscation.
    // ("The.Wire.3x07.720p.HDTV.x264-BATV" rotated.)
    let t = p("Gur.Jver.3k07.720c.UQGI.k264-ONGI");
    assert_eq!(t.kind, Kind::Tv);
    assert_eq!(t.title, "The Wire");
    assert_eq!((t.season, t.episode), (Some(3), Some(7)));
    assert_eq!(t.res.as_deref(), Some("720p"));
    assert_eq!(t.source.as_deref(), Some("HDTV"));
    assert_eq!(t.group.as_deref(), Some("BATV"));
    assert_eq!(t.key, "t:the wire");
}

#[test]
fn rot18_rotated_stem_is_rescued() {
    // Reported example: letters ROT13 AND digits ROT5 ("275c" →
    // "720p", "K719" → "X264"). Under that same decode "F56r53" is
    // S01E08 - the digits rotate with everything else.
    let t = p("Gur Ovoyr F56r53 275c Oyhenl K719-trpxbf");
    assert_eq!(t.kind, Kind::Tv);
    assert_eq!(t.title, "The Bible");
    assert_eq!((t.season, t.episode), (Some(1), Some(8)));
    assert_eq!(t.res.as_deref(), Some("720p"));
    assert_eq!(t.source.as_deref(), Some("BluRay"));
    assert_eq!(t.group.as_deref(), Some("geckos"));
    assert_eq!(t.key, "t:the bible");

    // Movie form: "The.Matrix.1999.1080p.BluRay.x264-GRP" in ROT18.
    // The letters-only decode also parses (BluRay survives) but the
    // ROT18 decode carries more furniture (year + res) and wins.
    let m = p("Gur.Zngevk.6444.6535c.Oyhenl.k719-TEC");
    assert_eq!(m.kind, Kind::Movie);
    assert_eq!(m.title, "The Matrix");
    assert_eq!(m.year, Some(1999));
    assert_eq!(m.res.as_deref(), Some("1080p"));
    assert_eq!(m.source.as_deref(), Some("BluRay"));
}

#[test]
fn rot18_wins_digit_ties_and_part_suffix_never_blocks_rescue() {
    // "rzretrapl.f58r69.qiqevc.kivq" = ROT18 "emergency.s03e14.
    // dvdrip.xvid". Letters-only decoding scores the same signals
    // (S58E69) - the plausible season must win the tie.
    let p = parse_release("rzretrapl.f58r69.qiqevc.kivq.vag-jcv");
    assert!(p.rescued, "{p:?}");
    assert_eq!(p.title.to_lowercase(), "emergency");
    assert_eq!((p.season, p.episode), (Some(3), Some(14)), "{p:?}");
    // A rotated RAR part suffix (".e64") parses as a bare episode -
    // that alone must not block the rescue.
    let p = parse_release("rzretrapl.f58r69.qiqevc.kivq.vag-jcv.e64");
    assert!(p.rescued, "{p:?}");
    assert_eq!((p.season, p.episode), (Some(3), Some(14)), "{p:?}");
    // A letters-only ROT13 post (digits NOT rotated: "f01r01" =
    // s01e01) keeps its plain numbers - the ROT18 variant would
    // read S56E56, implausible, and loses the tie.
    let p = parse_release("gur.jver.f01r01.qiqevc.kivq");
    assert!(p.rescued, "{p:?}");
    assert_eq!(p.title.to_lowercase(), "the wire");
    assert_eq!((p.season, p.episode), (Some(1), Some(1)), "{p:?}");
}

/// ROT13 in the MUSIC and BOOK groups (2 Sep 2026).
///
/// Four stems off a scratch index of the `music` and `books` interest
/// presets, with the state each reached a user in before this test
/// existed. All four are rotated real releases; none could qualify for
/// a rescue that asked for "Movie or Tv carrying scene signals".
///
///   O.N.C.Iby.664.7566.[jjj.amoeblnygl.pbz].cneg581.ene
///     alt.binaries.sounds.mp3 - junk 0, kind movie, "B A P Vol 119",
///     year 2011. Rescued, but onto the Movies wall as a film.
///   Trbetr Zvpunry - Flzcubavpn [Qryhkr Rqvgvba] (7569)(875).cneg7.ene
///     alt.binaries.sounds.mp3 - junk 60, kind movie, title = the
///     rotated text with " cneg7 ene" on the end. Hidden only by the
///     evidence-free-media rule.
///   Zbovyvgl.Vaqvn.GehrCQS-Nhthfg.7560.cqs.iby55+6.cne7
///     alt.binaries.e-book.magazines - junk 60, kind movie, rotated
///     title, and counted "readable" by the census query (junk < 70).
///   Rney Ubbxre- Qbag Unir Gb Jbeel.cneg6.ene
///     alt.binaries.sounds.mp3 - junk 60, kind movie, rotated title.
///
/// Every one of them decodes through its own ROTATED VOLUME TAIL:
/// ".cneg581.ene" is ".part581.rar", ".iby55+6.cne7" is
/// ".vol00+1.par2". `release_stem` runs before the classifier on the
/// ingest path and cannot see a rotated suffix, so the stems arrive
/// here whole - which is why the rescue cuts the tail off the DECODE
/// and counts it as a signal.
#[test]
fn rot13_rescue_reads_music_and_book_names() {
    let cases: [(&str, &str, Kind, &str, Option<u32>, Option<&str>); 4] = [
        (
            "alt.binaries.sounds.mp3",
            "O.N.C.Iby.664.7566.[jjj.amoeblnygl.pbz].cneg581.ene",
            Kind::Music,
            "B A P Vol 119",
            Some(2011),
            None,
        ),
        (
            "alt.binaries.sounds.mp3",
            "Trbetr Zvpunry - Flzcubavpn [Qryhkr Rqvgvba] (7569)(875).cneg7.ene",
            Kind::Music,
            "George Michael - Symphonica Deluxe Edition",
            Some(2014),
            None,
        ),
        // "Mobility.India.TruePDF-August.2015.pdf" - a MONTHLY, and the
        // rescue reads it as one. Was "Mobility India TruePDF-August" /
        // year 2015 / no date until 2 Sep 2026, which keyed every
        // August of every year onto one card; see
        // `a_monthly_issue_is_a_month_and_a_year`.
        //
        // This case is also what caught the counting trap in the rescue
        // itself: `signals` knew about the year and not the date, so a
        // post that spends its year token on a date lost the fact
        // entirely and the rescue REFUSED a name it had decoded
        // correctly. The date is counted there now.
        (
            "alt.binaries.e-book.magazines",
            "Zbovyvgl.Vaqvn.GehrCQS-Nhthfg.7560.cqs.iby55+6.cne7",
            Kind::Book,
            "Mobility India",
            None,
            Some("201508"),
        ),
        (
            "alt.binaries.sounds.mp3",
            "Rney Ubbxre- Qbag Unir Gb Jbeel.cneg6.ene",
            Kind::Music,
            "Earl Hooker- Dont Have To Worry",
            None,
            None,
        ),
    ];
    for (grp, posted, kind, title, year, date) in cases {
        // The ingest path's own order: reduce the posted name, classify
        // the stem, then let the group put the lane back.
        let stem = crate::names::release_stem(posted);
        let mut p = parse_release(&stem);
        assert!(p.rescued, "{posted}");
        recover_kind_from_group(&mut p, grp, &stem);
        assert_eq!(p.kind, kind, "{posted}");
        assert_eq!(p.title, title, "{posted}");
        assert_eq!(p.year, year, "{posted}");
        assert_eq!(p.date.as_deref(), date, "{posted}");
        // Visible: below the wall's default hide line at 50, for a
        // post of any size (an album is hundreds of MB, a magazine a
        // few - and the tiny-post rule exempts music and books).
        for bytes in [4u64 << 20, 400 << 20] {
            assert!(
                crate::junk::junk_score(&stem, &p, bytes, false) < 50,
                "{posted} at {bytes} bytes",
            );
        }
    }
}

/// The tail is a SIGNAL, never a licence. A stem whose rotation ends in
/// something `release_stem` would cut still needs a second fact or a
/// common English word, because the shape is reachable by accident:
/// ".h264" rotates to ".u264", which the old-style continuation cut
/// (`.r00`-`.z99`) takes.
#[test]
fn a_rotated_volume_tail_alone_does_not_rescue() {
    let p = parse_release("My.Home.Video.h264");
    assert!(!p.rescued, "{p:?}");
    assert_eq!(p.title, "My Home Video");
}

/// The abutting-bracket separator, which is a music-post convention and
/// not a ROT13 matter: it was found through one, and it is worth its
/// own pin because it changes PLAIN names too.
#[test]
fn abutting_brackets_separate_a_year_from_a_bitrate() {
    let p = parse_release("Artist - Album (2014)(320)");
    assert_eq!(p.title, "Artist - Album");
    assert_eq!(p.year, Some(2014));
    // One bracketed group on its own is unaffected, and so is a real
    // title that merely contains brackets.
    let p = parse_release("Dance Classics Hits Vol. 13 (1994)");
    assert_eq!(p.year, Some(1994));
}

#[test]
fn rot13_rescue_never_fires_on_plain_names() {
    // Real furniture in the direct parse ⇒ no rescue attempted.
    let m = p("The.Matrix.1999.2160p.UHD.BluRay.REMUX.HDR.HEVC.TrueHD.Atmos-FraMeSToR");
    assert_eq!(m.title, "The Matrix");
    // A bare title with no furniture stays itself: its rotation is
    // unpronounceable garbage with no scene tokens.
    let bare = p("Inception");
    assert_eq!(
        (bare.kind.clone(), bare.title.as_str()),
        (Kind::Movie, "Inception")
    );
    // Hash and blob names stay Other - their decodes carry no
    // furniture either.
    assert_eq!(p("2137d880a074fa4075a65ce4e21d2f95").kind, Kind::Other);
    assert_eq!(p("abcdef12.34567890abcdef12.deadbeef99").kind, Kind::Other);
    // Real MUSIC and BOOK names, now that those kinds are accepted:
    // rot13 of English is not English, and the pronounceability gate is
    // the whole defence. These are the control arm for it - a plain
    // album or ebook must survive as itself, title unrotated.
    for (stem, title) in [
        (
            "Earl Hooker - Dont Have To Worry",
            "Earl Hooker - Dont Have To Worry",
        ),
        (
            "Dance Classics Hits Vol. 13 (1994)(320)",
            "Dance Classics Hits Vol 13",
        ),
        (
            "Sidney Sheldon - Master of the Game (mobi).mobi",
            "Sidney Sheldon - Master of the Game",
        ),
        (
            "Robin James - [Mara Brent 04] - Mark of Justice (epub).epub",
            "Robin James - Mara Brent 04 - Mark of Justice",
        ),
    ] {
        let r = p(stem);
        assert!(!r.rescued, "{stem}: {r:?}");
        assert_eq!(r.title, title, "{stem}");
    }
}

#[test]
fn software_posts_get_their_own_kind() {
    let s = p("CCleaner.Professional.Plus.v6.36.11041.x64.Setup");
    assert_eq!(s.kind, Kind::Software);
    assert_eq!(s.title, "CCleaner Professional Plus");
    assert_eq!(s.key, "s:ccleaner professional plus");
    let a = p("Adobe.Photoshop.2025.v26.3.Multilingual.x64-TEAM");
    assert_eq!(a.kind, Kind::Software);
    assert_eq!(a.title, "Adobe Photoshop 2025");
    // Strong keyword alone decides; the title cuts at the earliest
    // marker, weak or strong.
    let k = p("Some.App.Incl.Keygen-GROUP");
    assert_eq!(k.kind, Kind::Software);
    assert_eq!(k.title, "Some App");
}

/// A vendor that versions by YEAR is still software.
///
/// These two were on the poster wall as 2026 FILMS: no `v` token and
/// no keygen vocabulary, so the two-weak-hits rule never fired, and
/// a bare trailing year parses as a movie. One unambiguous furniture
/// word plus NO resolution, source or codec anywhere is enough.
#[test]
fn software_versioned_by_year_is_not_a_film() {
    assert_eq!(
        p("Adobe.Illustrator.2026.u6.Multilingual").kind,
        Kind::Software
    );
    assert_eq!(
        p("Android Studio 2026.1.3.7 Latest Offline Installer").kind,
        Kind::Software
    );
    // Cut at the furniture marker, as every other software post is:
    // the version stays in the title, which is what names a build.
    assert_eq!(
        p("Adobe.Illustrator.2026.u6.Multilingual").title,
        "Adobe Illustrator 2026 u6"
    );

    // ...and the narrowness holds. A film with media evidence keeps
    // its kind however software-ish a word it carries, and a film
    // with NO media evidence is not reclassified on a title word -
    // only the furniture a film title does not use counts.
    assert_eq!(
        p("The.Portable.Door.2023.1080p.WEB-DL.x264-GRP").kind,
        Kind::Movie
    );
    assert_eq!(p("Windows.2011").kind, Kind::Movie);
    assert_eq!(p("The.Setup.1995").kind, Kind::Movie);
}

#[test]
fn movies_with_software_ish_words_stay_movies() {
    assert_eq!(p("Setup.2011.1080p.BluRay.x264-GRP").kind, Kind::Movie);
    assert_eq!(
        p("Leon.The.Professional.1994.1080p.BluRay.x264-GRP").kind,
        Kind::Movie
    );
    assert_eq!(
        p("V.For.Vendetta.2006.1080p.BluRay.x264-GRP").kind,
        Kind::Movie
    );
    assert_eq!(p("The.Matrix.1999.1080p.BluRay.x264-GRP").kind, Kind::Movie);
}

#[test]
fn scene_music_splits_on_its_fields() {
    // The shape the normal tokenizer cannot see: hyphens separate
    // fields, underscores stand in for spaces.
    let m = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS");
    assert_eq!(m.kind, Kind::Music);
    assert_eq!(m.title, "Pink Floyd - The Dark Side Of The Moon");
    assert_eq!(m.year, Some(1973));
    assert_eq!(m.group.as_deref(), Some("EOS"));
    assert_eq!(m.key, "mu:pink floyd the dark side of the moon");
    // Format marker in a later field decides without a trailing year
    // rule, and picks the kind.
    let f = p("Massive_Attack-Mezzanine-CD-FLAC-1998-GROUP");
    assert_eq!(f.kind, Kind::Music);
    assert_eq!(f.title, "Massive Attack - Mezzanine");
    assert_eq!(f.year, Some(1998));
    // Various-artists compilations use the same convention.
    let va = p("VA-Now_Thats_What_I_Call_Music_100-2018-NOiR");
    assert_eq!(va.kind, Kind::Music);
    assert_eq!(va.title, "VA - Now Thats What I Call Music 100");
    // A leading disc/track-number field is scene convention, and
    // measured on a live index it is the common case - without
    // dropping it the artist parses as "00".
    let n = p("00-piero_piccioni-the_light_at_the_edge_of_the_world-cd-flac-2014-GRP");
    assert_eq!(n.kind, Kind::Music);
    assert_eq!(
        n.title,
        "piero piccioni - the light at the edge of the world"
    );
    let t = p("000-va-bravo_hits_57-2cd-flac-2007-GRP");
    assert_eq!(t.title, "va - bravo hits 57");
}

#[test]
fn tagged_music_and_books_parse() {
    let m = p("Pink Floyd - The Dark Side of the Moon (1973) [FLAC]");
    assert_eq!(m.kind, Kind::Music);
    assert_eq!(m.title, "Pink Floyd - The Dark Side of the Moon");
    assert_eq!(m.year, Some(1973));
    let mp3 = p("Adele - 30 (2021) [MP3 320]");
    assert_eq!(mp3.kind, Kind::Music);
    assert_eq!(mp3.title, "Adele - 30");
    // "epub" is not release furniture to is_tag, so the marker has to
    // close the title region itself or it lands in the title.
    let b = p("Frank Herbert - Dune (1965) [epub]");
    assert_eq!(b.kind, Kind::Book);
    assert_eq!(b.title, "Frank Herbert - Dune");
    assert_eq!(b.year, Some(1965));
    assert_eq!(b.key, "bk:frank herbert dune");
    for stem in [
        "Andy Weir - Project Hail Mary (2021) [mobi]",
        "Andy Weir - Project Hail Mary (2021) [azw3]",
    ] {
        let x = p(stem);
        assert_eq!(x.kind, Kind::Book, "{stem}");
        assert_eq!(x.title, "Andy Weir - Project Hail Mary", "{stem}");
    }
    // Both halves come back apart for the providers.
    assert_eq!(credit_split(&b.title), Some(("Frank Herbert", "Dune")));
    assert_eq!(credit_split("no separator here"), None);
}

#[test]
fn magazines_and_pdfs_are_books_not_films() {
    // A magazine is posted as its own PDF and carries no other book
    // evidence at all, so every one of them parsed as a MOVIE with a
    // year and sat in the film lane (measured on a live index,
    // 16 Aug 2026).
    let m = p("PC_Games_Hardware_Magazin_September_No_09_2026.pdf");
    assert_eq!(m.kind, Kind::Book);
    assert_eq!(m.title, "PC Games Hardware Magazin September No 09");
    // The marker closes the title region, so ".pdf" cannot land in it.
    assert_eq!(
        p("Some Author - A Title.pdf").title,
        "Some Author - A Title"
    );
    // ...and the safety margin is the same one FLAC rides: any video
    // evidence and the file is a film that happens to name a PDF.
    assert_eq!(p("Some.Doc.2019.1080p.WEB.x264-GRP.pdf").kind, Kind::Movie);
}

#[test]
fn a_fed_name_that_dropped_its_format_marker_recovers_the_lane() {
    // Spotnet's signed title names the WORK; the posted file names the
    // FORMAT. Classification reads the fed title, so the ".epub" went
    // missing and the parse fell through to Movie - which the junk
    // scorer then hid as evidence-free media.
    let mut fed = p("Hetty Luiten - Op eigen benen");
    assert_eq!(fed.kind, Kind::Movie, "the fed name alone says nothing");
    recover_media_kind(
        &mut fed,
        "Hetty Luiten - Op eigen benen",
        "Luiten, Hetty - Op eigen benen.epub",
    );
    assert_eq!(fed.kind, Kind::Book);
    assert_eq!(fed.key, "bk:hetty luiten op eigen benen");
    // The title stays the FED one - only the lane moved.
    assert_eq!(fed.title, "Hetty Luiten - Op eigen benen");
    // Music rides the same seam.
    let mut alb = p("Pink Floyd - The Dark Side of the Moon");
    recover_media_kind(
        &mut alb,
        "Pink Floyd - The Dark Side of the Moon",
        "Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS",
    );
    assert_eq!(alb.kind, Kind::Music);

    // What it must NOT do. A fed name that classified on its own
    // evidence is not ours to overrule...
    let mut film = p("Some.Film.2019.1080p.BluRay.x264-GRP");
    recover_media_kind(
        &mut film,
        "Some.Film.2019.1080p.BluRay.x264-GRP",
        "some.film.epub",
    );
    assert_eq!(film.kind, Kind::Movie, "video evidence stands");
    let mut ep = p("Some.Show.S01E01.WEB-GRP");
    recover_media_kind(&mut ep, "Some.Show.S01E01.WEB-GRP", "some.show.epub");
    assert_eq!(ep.kind, Kind::Tv);
    // ...and a stem that says nothing changes nothing.
    let mut plain = p("Hetty Luiten - Op eigen benen");
    let was = plain.key.clone();
    recover_media_kind(
        &mut plain,
        "Hetty Luiten - Op eigen benen",
        "0a1b2c3d4e5f6071.rar",
    );
    assert_eq!(plain.kind, Kind::Movie);
    assert_eq!(plain.key, was);
    // ...and a row that was never fed a name at all skips the second
    // parse entirely: fed IS the stem, so there is nothing to recover.
    let mut unfed = p("Frank Herbert - Dune (1965) [epub]");
    recover_media_kind(
        &mut unfed,
        "Frank Herbert - Dune (1965) [epub]",
        "Frank Herbert - Dune (1965) [epub]",
    );
    assert_eq!(unfed.kind, Kind::Book, "the stem already said it");
}

#[test]
fn music_keys_ignore_the_edition_year() {
    // A remaster, a vinyl rip and the original are one album, so
    // they have to land on one card - unlike movies, whose year is
    // part of their identity.
    let a = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS");
    let b = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-2011-REMASTERED-GRP");
    assert_eq!(a.key, b.key);
}

#[test]
fn video_evidence_beats_any_audio_marker() {
    // A concert BluRay says FLAC and is still a film; an episode is
    // still an episode. This gate is the whole safety margin for
    // claiming FLAC/MP3 as music markers at all.
    assert_eq!(
        p("Some.Concert.2019.1080p.BluRay.FLAC.x264-GRP").kind,
        Kind::Movie
    );
    assert_eq!(p("Some.Show.S01E01.720p.WEB.FLAC-GRP").kind, Kind::Tv);
    assert_eq!(p("Some.Doc.2019.2160p.REMUX.FLAC-GRP").kind, Kind::Movie);
    // The downloader's own lowercase movie convention has the exact
    // field count and trailing year of a scene album, and is saved
    // only by having no underscore.
    assert_eq!(p("the-matrix-1999-FGT").kind, Kind::Movie);
    assert_eq!(p("the-flash-s01e01-720p").kind, Kind::Tv);
    // A film whose FIRST word is a format marker keeps its title -
    // markers are only read from index 1 on.
    assert_eq!(p("Vinyl.S01E01.720p.WEB-GRP").kind, Kind::Tv);
    assert_eq!(p("Mobi.2019.1080p.WEB-GRP").kind, Kind::Movie);
}

#[test]
fn allcaps_folds_to_title_case() {
    assert_eq!(p("KILL.BILL.VOL.1.2003.2160p-iVy").title, "Kill Bill Vol 1");
}

#[test]
fn fold_preserves_numerals_and_acronyms() {
    // Roman numerals and household acronyms survive the fold...
    assert_eq!(
        p("PLANET.EARTH.II.2016.2160p.WEB-GRP").title,
        "Planet Earth II"
    );
    assert_eq!(
        p("the.office.us.s01e01.720p.web-grp").title,
        "The Office US"
    );
    assert_eq!(
        p("WWE.MONDAY.NIGHT.RAW.2026.720p.WEB-GRP").title,
        "WWE Monday Night Raw"
    );
    assert_eq!(p("US.MARSHALS.1998.1080p.BluRay-GRP").title, "US Marshals");
    // ...but a single-word title is a TITLE, not a suffix: Peele's
    // "Us" must not become "US". (The fold's own >3-letters gate
    // already leaves a lone lowercase "us" untouched - pinned here
    // so a widened fold can't quietly turn it into an acronym.)
    assert_eq!(p("us.2019.1080p.web-grp").title, "us");
    // Mixed-case stems still pass through byte-for-byte.
    assert_eq!(p("Us.2019.1080p.WEB-GRP").title, "Us");
}

#[test]
fn languages_come_from_furniture_not_title() {
    assert_eq!(
        p("Der.Untergang.2004.German.1080p.BluRay.x264-GRP").langs,
        ["german"]
    );
    assert_eq!(
        p("Drama.Show.E178.2001.KOR.CATV.DivX-EyeMaX").langs,
        ["korean"]
    );
    assert_eq!(p("Some.Film.2020.MULTi.1080p.WEB").langs, ["multi"]);
    // A film titled "Rus" is not Russian; untagged stays empty.
    assert!(p("Rus.2019.1080p.WEB").langs.is_empty());
    assert!(p("Plain.Film.2020.1080p.WEB").langs.is_empty());
}

#[test]
fn group_rejects_years_tags_and_numbers() {
    assert_eq!(p("Movie.Name.2003.1080p-2003").group, None);
    assert_eq!(p("Movie.Name.2003.1080p-REMUX").group, None);
    let ok = p("Movie.Name.2003.1080p.WEB-NTb");
    assert_eq!(ok.group.as_deref(), Some("NTb"));
    // WEB-DL's DL must not be eaten as a group when it ends the stem.
    let dl = p("Show.S01E01.1080p.WEB-DL");
    assert_eq!(dl.group, None);
    assert_eq!(dl.source.as_deref(), Some("WEB"));
}

/// Reposters append their own tag after the real group, and with
/// `NameStyle::group` on it would land in the filename.
#[test]
fn reposter_tags_never_become_the_group() {
    let g = |s: &str| p(s).group;
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GRP-Obfuscated").as_deref(),
        Some("GRP")
    );
    assert_eq!(g("Example.Movie.2024.1080p.x264-Obfuscated"), None);
    // They chain, in any case, in any order.
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GRP-xpost-Obfuscated").as_deref(),
        Some("GRP")
    );
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GRP-NZBGeek-postbot-RP").as_deref(),
        Some("GRP")
    );
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GRP-RAKUVFINHEL").as_deref(),
        Some("GRP")
    );
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GRP-AlteZachen").as_deref(),
        Some("GRP")
    );
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GRP.-Chamele0n").as_deref(),
        Some("GRP")
    );
    // A real group that merely CONTAINS one of the words is untouched.
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-RPGroup").as_deref(),
        Some("RPGroup")
    );
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-Sampler").as_deref(),
        Some("Sampler")
    );
    assert_eq!(
        g("Example.Movie.2024.1080p.x264-GEROVA").as_deref(),
        Some("GEROVA")
    );
    // Sonarr strips a bare "-1" too; we do not, it is too risky - so
    // the tail keeps hiding the group instead of exposing a wrong one.
    assert_eq!(g("Example.Movie.2024.1080p.x264-GRP-1"), None);
    // Nothing but tags: no group, and the stem survives as the title.
    assert_eq!(group_of("-Obfuscated"), None);
    assert_eq!(p("-Obfuscated").title, "-Obfuscated");
    // The tag leaves no trace in the rest of the parse either.
    let m = p("Example.Movie.2024.1080p.x264-GRP-Obfuscated");
    assert_eq!(m.title, "Example Movie");
    assert_eq!(m.year, Some(2024));
    assert!(!m.extra.iter().any(|w| w.eq_ignore_ascii_case("obfuscated")));
}

/// Fixed-width hash renames seen in the wild, full-stem anchored.
#[test]
fn obfuscated_hash_shapes_are_caught() {
    for s in [
        "ABCDEFGHIJK123",                   // 11 caps + 3 digits
        "abcdefghijkl123",                  // 12 lowercase + 3 digits
        "d41d8cd98f00b204e9800998ecf8427e", // 32 hex, md5
        "abcdefabcdefabcdefabcdefabcdefAb", // 32 hex, no digits, one cap
        "abcdefghijklmnopqrstuvwx",         // 24 lowercase
        "a1b2c3d4e5f6g7h8i9j0k1l2",         // 24 alnum
    ] {
        assert!(looks_obfuscated(s), "should be obfuscated: {s}");
    }
    // Real names of the same length are separated, and separators are
    // what the anchored shapes cannot contain.
    for s in [
        "The Lord of the Rings The Two Tow", // 33 chars with spaces
        "Everything Everywhere All At Once", // 33 chars with spaces
        "Pirates.Of.The.Caribbean.At.Worl",  // 32 chars, dotted
        "The.Matrix.Reloaded.2003.1080p.BluRay.x264-AMIABLE",
        "Show.S01E01.1080p.WEB-DL.DD5.1.H264-NTb",
        "Week 03",
        // 32 characters of run-together title. The md5 rule is
        // anchored on hex for exactly this: it is unpresentable
        // hex-shaped renames we are after, not any 32-character run
        // of letters somebody typed without separators.
        "ThelordoftheringsReturnoftheking",
    ] {
        assert!(!looks_obfuscated(s), "should NOT be obfuscated: {s}");
    }
}

/// Real stems from the live index. The lowercase-base32 shape was
/// missed by every earlier rule: no digits, no internal capitals.
#[test]
fn obfuscated_lowercase_blobs_are_caught() {
    for s in [
        "nzqymzflnjiyztgyntcynzzytq",
        "MI4WGMRRMI4DAZBWME3GMOLEMDKNRZ",
        "c1bceab2fac4d74f47b0a0e18311ec5c53",
        "ZO01uZT4YhQAGrDQLC3U1",
    ] {
        assert!(looks_obfuscated(s), "should be obfuscated: {s}");
    }
    for s in [
        "Oppenheimer",
        "Interstellar",
        "The.Matrix.1999.1080p.BluRay.x264-GROUP",
        "Nirvana-Nevermind-1991-FAF",
    ] {
        assert!(!looks_obfuscated(s), "should NOT be obfuscated: {s}");
    }
}

/// `stem_is_a_name` is the one verdict the byte-probe picks and the
/// claims apply-gate both ask, so its extension strip is
/// load-bearing in two directions at once: strip too little and a
/// blob reads as a name (the `.7z` band, which cost the prober
/// every probe it should have made); strip too much and a NAME
/// reads as a blob, which lets a mismatched claim rename a release
/// that was perfectly readable.
#[test]
fn the_extension_strip_cuts_suffixes_and_never_years() {
    // A trailing token with a letter is a suffix: take it off.
    for (stem, bare) in [
        (
            "uHpvK7XRYNxbvVQbxuW2fGBAPRpMkJuc.7z",
            "uHpvK7XRYNxbvVQbxuW2fGBAPRpMkJuc",
        ),
        (
            "Costao.2025.1080p.WEB-DL.H.264-DTR.mkv",
            "Costao.2025.1080p.WEB-DL.H.264-DTR",
        ),
    ] {
        assert_eq!(bare_stem(stem), bare, "suffix should come off: {stem}");
    }
    // An all-digit tail is a year or a track number - it stays.
    for stem in ["1917.2019", "Blade.Runner.2049", "Track.01"] {
        assert_eq!(bare_stem(stem), stem, "digits are not an extension: {stem}");
    }

    // What the two callers actually ask, on the shapes that bit.
    assert!(
        !stem_is_a_name("uHpvK7XRYNxbvVQbxuW2fGBAPRpMkJuc.7z"),
        "a blob wearing an archive extension is dark, and probe-worthy"
    );
    assert!(
        stem_is_a_name("1917.2019"),
        "a year-titled release is a NAME - never a rename target"
    );
    assert!(
        stem_is_a_name("Some.Show.S01E01.1080p.WEB-DL.x264-GRP.7z"),
        "R6's trap row keeps reading as a name under its extension"
    );
}

// Hostile-input fuzz: the indexer runs parse_release over every scraped
// subject, which an attacker controls. The parser byte-indexes &str in
// several spots (tv_marker, the version closure, the leading-zero SSEE
// case), so a subject engineered to place a multi-byte UTF-8 char at a
// slice boundary would panic the scan thread (DoS) if any of those sites
// were unguarded. Throw adversarial unicode, control chars, ROT13 bait,
// and pathological separator runs at every public entry point and assert
// it never panics (a panic here fails the test = a real finding).
#[test]
fn parser_never_panics_on_hostile_input() {
    // Cheap deterministic LCG so the corpus is reproducible.
    let mut state: u64 = 0x9e3779b97f4a7c15;
    let mut next = || {
        state = state
            .wrapping_mul(6364136223846793005)
            .wrapping_add(1442695040888963407);
        (state >> 33) as u32
    };
    // Bytes chosen to stress char-boundary math: multi-byte UTF-8 leads,
    // scene separators, digits, and the S/E/v/x markers that drive the
    // byte-slicing branches.
    let alphabet: &[&str] = &[
        "s", "e", "v", "x", "S", "E", "0", "1", "2", "6", "9", ".", "_", "-", " ", "[", "]", "(",
        ")", "é", "ß", "λ", "中", "日", "\u{200f}", "\u{0301}", "🎬", "\u{feff}", "\t", "\n",
        "web", "dl", "1080p", "x265", "2024", "s01e01",
    ];
    // A few fixed adversarial seeds alongside the random corpus.
    let seeds = [
        "",
        "s01ée01", // multi-byte char right after the season 's'
        "vé.6",    // version closure: 'v' then a multi-byte char
        "0é01",    // leading-zero SSEE lookalike with a wide char
        "中文.2024.1080p.WEB-中",
        "\u{feff}s2026é015",
        "----",
        "a-b-c-d-e-f",
        "s99999999999999999999e88888888888888888888",
        &"x".repeat(5000),
        &"1.".repeat(2000),
    ];
    let run = |stem: &str| {
        let parsed = parse_release(stem);
        // Exercise the downstream formatters too - they slice on the
        // parsed fields.
        let _ = norm_title(stem);
        let _ = sanitize_name(stem);
        let _ = quality_label(&parsed);
        let style = NameStyle::default();
        let _ = quality_suffix(&parsed, &style);
        let _ = movie_name(&parsed, &style);
    };
    for s in seeds {
        run(s);
    }
    for _ in 0..20_000 {
        let len = (next() % 40) as usize;
        let mut stem = String::new();
        for _ in 0..len {
            stem.push_str(alphabet[(next() as usize) % alphabet.len()]);
        }
        run(&stem);
    }
}

/// Stage 4 writes real files and folders, and a finished tree gets
/// moved to a NAS/SMB share, so the Windows rules apply whatever host
/// produced the name. Enqueue-time folder naming had these guarantees
/// already; the friendly renamer did not, and could emit a hidden
/// name, a name Windows silently truncates, or a device stem.
#[test]
fn a_friendly_name_is_portable() {
    // Leading dot: hidden on macOS/Linux, and not what anyone asked
    // for on Windows either.
    assert_eq!(sanitize_name(".Hidden Movie (2024)"), "Hidden Movie (2024)");
    assert_eq!(
        sanitize_name("..Hidden Movie (2024)"),
        "Hidden Movie (2024)"
    );
    // Trailing dot / space: Windows strips them, so the name on disk
    // stops matching the name we recorded.
    assert_eq!(sanitize_name("Movie (2024)."), "Movie (2024)");
    assert_eq!(sanitize_name("Movie (2024). "), "Movie (2024)");
    // Reserved DOS device stems: creating one opens the device.
    assert_eq!(sanitize_name("CON"), "_CON");
    assert_eq!(sanitize_name("com1"), "_com1");
    assert_eq!(sanitize_name("nul.mkv"), "_nul.mkv");
    // Path separators and the rest of the illegal set never survive.
    for s in [
        "../../etc/passwd",
        "a\\b",
        "Movie <2024>",
        "Q|A?",
        "x\u{7}y",
    ] {
        let out = sanitize_name(s);
        assert_eq!(
            std::path::Path::new(&out).components().count(),
            1,
            "not a single component: {s:?} -> {out:?}"
        );
        assert!(!out.chars().any(|c| c.is_control()), "{s:?} -> {out:?}");
    }
    // Nothing nameable left: an empty name, so the caller declines.
    for s in ["", "...", " . . ", "----", ":"] {
        assert_eq!(sanitize_name(s), "", "{s:?} should be unnameable");
    }
}

/// A colon separates a title from its subtitle, so it has to be
/// SPELLED OUT, not blanked - "Alien Romulus" reads as one title.
#[test]
fn a_colon_becomes_a_separator() {
    assert_eq!(sanitize_name("Alien: Romulus"), "Alien - Romulus");
    assert_eq!(sanitize_name("Alien:Romulus"), "Alien-Romulus");
    assert_eq!(sanitize_name("Alien : Romulus"), "Alien - Romulus");
    // Doubled separators the expansion creates are collapsed back.
    assert_eq!(sanitize_name("Alien:: Romulus"), "Alien - Romulus");
    assert_eq!(sanitize_name("Alien -: Romulus"), "Alien - Romulus");
    // A dangling colon leaves no dangling separator behind.
    assert_eq!(sanitize_name("Alien: "), "Alien");
    // A hyphen that was always there is not a separator run and is
    // left exactly as the poster wrote it.
    assert_eq!(
        sanitize_name("Spider-Man: Homecoming"),
        "Spider-Man - Homecoming"
    );
    assert_eq!(
        sanitize_name("Mission Impossible - Fallout"),
        "Mission Impossible - Fallout"
    );
}

/// The same guarantees through the real movie entry point, and a
/// legitimately-named release left byte-for-byte alone.
#[test]
fn movie_names_are_portable() {
    let style = NameStyle {
        resolution: true,
        year_parens: true,
        ..Default::default()
    };
    let name = |s: &str| movie_name(&p(s), &style);

    assert_eq!(
        name("Alien: Romulus 2024 1080p WEB-DL x264-GRP").as_deref(),
        Some("Alien - Romulus (2024) 1080p")
    );
    // "CON (2024) 1080p" is not a device stem, but the title alone
    // is - so the guard has to survive the whole build, not just the
    // title. With no year and no quality facts movie_name declines
    // anyway, which is the other half of the same safety.
    assert_eq!(
        name("CON 2024 1080p x264-GRP").as_deref(),
        Some("CON (2024) 1080p")
    );
    assert_eq!(name("CON"), None);
    // Negative: an ordinary release is not reshaped by any of this.
    assert_eq!(
        name("The.Matrix.1999.1080p.BluRay.x264-AMIABLE").as_deref(),
        Some("The Matrix (1999) 1080p")
    );
    // Whatever the shape, what comes out is a usable component.
    for s in [
        ".Hidden.2024.1080p",
        "Movie..2024.1080p",
        "CON.2024.1080p",
        "..2024.1080p",
    ] {
        if let Some(n) = name(s) {
            assert!(!n.starts_with('.') && !n.ends_with('.'), "{s:?} -> {n:?}");
            assert!(!n.ends_with(' '), "{s:?} -> {n:?}");
            assert!(!n.is_empty());
        }
    }
}

/// A reversed stem has to land on EXACTLY the parse its forward form
/// would have given - a flip that recovers the resolution but drops
/// half the name is not a rescue.
#[test]
fn reversed_stems_parse_as_their_forward_form() {
    let same = |fwd: &str| {
        let want = p(fwd);
        let backwards: String = fwd.chars().rev().collect();
        let mut got = p(&backwards);
        assert!(got.rescued, "not rescued: {backwards}");
        got.rescued = want.rescued; // the only field that may differ
        assert_eq!(format!("{got:?}"), format!("{want:?}"), "{backwards}");
    };
    same("Example.Movie.2024.1080p.x264-GRP");
    same("Show.Name.S01E02.720p.HDTV.x264-GRP");
    same("Show.Name.S01E012.2160p.WEB-DL.x265-GRP");
    same("The.Big.Show.2024.480p.DVDRip.XviD-GRP");
    // The shape as posted, group tag left forwards - the flip reads
    // it as "PRG", which is what a whole-stem reversal can promise.
    let m = p("GRP-462x.p0801.4202.eivoM.elpmaxE");
    assert_eq!(m.title, "Example Movie");
    assert_eq!(m.year, Some(2024));
    assert_eq!(m.res.as_deref(), Some("1080p"));
    assert!(m.rescued);
}

/// And the other half: an ordinary name is never flipped, and a
/// backwards-looking token alone is not enough to believe one.
#[test]
fn forward_names_are_never_reversed() {
    for s in [
        "The.Matrix.1999.1080p.BluRay.x264-AMIABLE",
        "Show.S01E01.1080p.WEB-DL.DD5.1.H264-NTb",
        "Frank Herbert - Dune 1965 epub",
        "Formula1.2026.Round11.Hungary.Race.1080p-GRP",
        // "p027" inside a word is not a token, so nothing triggers.
        "Chapter.Mp027x.Notes",
        "Series.Movies.Codeps.Notes",
        // A real trigger token whose flip says nothing: the reversed
        // "title" is the bare number 4202, so the flip is refused
        // and the poster's own name stands.
        "Chapter.p027.2024",
    ] {
        assert!(!p(s).rescued, "should not have flipped: {s}");
    }
    assert_eq!(
        p("The.Matrix.1999.1080p.BluRay.x264-AMIABLE").title,
        "The Matrix"
    );
    assert_eq!(p("Chapter.p027.2024").title, "Chapter p027");
}

/// A forward name that happens to carry ONE backwards-shaped token -
/// a page or catalog marker ("p027", "p0801"), an "NNeNNs" reference
/// - is still a forward name. Reversal keeps vowels, so the flipped
/// title reads as English too and the English test cannot tell the
/// two apart; these are the stems that flipped anyway and renamed a
/// legitimately-named file to "epaT 1080p".
#[test]
fn one_backwards_token_does_not_flip_a_forward_name() {
    let style = NameStyle {
        resolution: true,
        ..Default::default()
    };
    for s in [
        // Only the marker flips, and one resolution is not two facts.
        "Concert.Bootleg.p0801.Tape",
        "Label.Sampler.p027.Promo",
        // A forward YEAR, a forward SOURCE and a forward air date all
        // say the stem already reads forwards.
        "Christmas.p0801.Home.Movies.2019",
        "Example.Movie.DVDRip-p0801",
        "Podcast.p027.260721.Notes",
        // Flips to S43E21: two fields, one token, and a season nobody
        // has ever posted.
        "Lecture.Notes.12e34s.Extra",
    ] {
        assert!(!p(s).rescued, "should not have flipped: {s}");
    }
    // Nothing to offer, so nothing is renamed - and the kind stays
    // Movie rather than being demoted (see finalize_names).
    let tape = p("Concert.Bootleg.p0801.Tape");
    assert_eq!(tape.title, "Concert Bootleg p0801 Tape");
    assert_eq!(movie_name(&tape, &style), None);
    assert_eq!(p("Lecture.Notes.12e34s.Extra").kind, Kind::Movie);
    // Where a name IS offered it is built from the poster's own
    // words forwards, never "9102 seivoM emoH 1080p".
    assert_eq!(
        movie_name(&p("Christmas.p0801.Home.Movies.2019"), &style).as_deref(),
        Some("Christmas p0801 Home Movies 2019")
    );
}

/// A bare YYMMDD run is a daily show's whole identity, but six digits
/// are also how ids and part counts look - so it only reads as a date
/// when it validates AND nothing stronger already named the release.
#[test]
fn six_digit_datecodes_read_as_air_dates() {
    let d = |s: &str| p(s).date;
    let show = p("Show.Name.260721.1080p.WEB.x264-GRP");
    assert_eq!(show.date.as_deref(), Some("20260721"));
    assert_eq!(show.kind, Kind::Tv);
    assert_eq!(show.title, "Show Name");
    assert_eq!(show.year, None);
    // Both conventions normalize to the same identity.
    assert_eq!(
        d("Show.Name.260721.1080p.WEB.x264-GRP"),
        d("Show.Name.20260721.1080p.WEB.x264-GRP")
    );

    // Not a date: month or day out of range, or a year that reads as
    // decades away. The token is left alone as an ordinary word, and
    // a release with no other TV evidence stays a Movie.
    for s in [
        "Show.Name.261321.1080p.WEB-GRP", // month 13
        "Show.Name.260732.1080p.WEB-GRP", // day 32
        "Show.Name.260021.1080p.WEB-GRP", // month 00
        "Show.Name.260700.1080p.WEB-GRP", // day 00
        "Show.Name.123456.1080p.WEB-GRP", // an id, not a date
        "Show.Name.991231.1080p.WEB-GRP", // 2099 is not an air date
    ] {
        assert_eq!(d(s), None, "{s}");
        assert_eq!(p(s).kind, Kind::Movie, "{s}");
        assert!(p(s).title.contains(&s[10..16]), "{s} -> {}", p(s).title);
    }

    // Six digits that are part of an id are not a token at all.
    for s in [
        "Show.Name.ID260721.1080p.WEB-GRP",
        "Show.Name.260721x.1080p.WEB-GRP",
    ] {
        assert_eq!(d(s), None, "{s}");
    }
    // …and neither is a leading run, which is the title.
    assert_eq!(d("260721.1080p.WEB-GRP"), None);

    // Stronger signals win outright: a four-digit year or an SxxEyy
    // marker means the release is not naming its episode by day.
    let m = p("Example.Movie.2024.260721.1080p.WEB-GRP");
    assert_eq!(m.date, None);
    assert_eq!(m.kind, Kind::Movie);
    assert_eq!((m.title.as_str(), m.year), ("Example Movie", Some(2024)));
    let t = p("Show.Name.S01E02.260721.1080p.WEB-GRP");
    assert_eq!(t.date, None);
    assert_eq!((t.season, t.episode), (Some(1), Some(2)));
    // Eight digits stay unambiguous, so a year alongside is fine.
    assert_eq!(
        d("Show.Name.2024.20260721.1080p.WEB-GRP").as_deref(),
        Some("20260721")
    );
}

/// The gate every out-of-band name has to pass before it may rename
/// a user's file: a container Title, a naming oracle's answer. The
/// NO cases are the ones that matter - each of them is a string a
/// real muxer or a real API has handed back.
#[test]
fn release_names_are_told_from_human_titles() {
    for s in [
        "Example.Movie.2019.1080p.BluRay.x264-GRP",
        "Show.Name.S01E02.1080p.WEB.h264-POKE",
        "Example Movie 2019 1080p BluRay x264-GRP",
        "Dune.Part.Two.2024.1080p.WEB.h264-ETHEL",
        "Example.Movie.2019.2160p.WEB-DL.DDP5.1.HDR.H.265-BYNDR",
    ] {
        assert!(looks_like_release_name(s), "{s} should read as a release");
    }
    for s in [
        "",
        "Sintel",
        "Episode 3",
        "The Movie", // a human title: no furniture at all
        "Big Buck Bunny",
        "encoded by Handbrake",
        "video",
        // A member of a release, not the release.
        "Example.Movie.2019.1080p.BluRay.x264-GRP/movie.mkv",
        // Hash-shaped: what a reposter writes when it writes anything.
        "d41d8cd98f00b204e9800998ecf8427e",
        "n1iY94U6fTpMVY9GPD",
    ] {
        assert!(
            !looks_like_release_name(s),
            "{s:?} should NOT read as a release"
        );
    }
    // One signal is not enough - a year alone is how plenty of
    // muxers title a film, and renaming on it would lose the name
    // the poster actually gave.
    assert!(!looks_like_release_name("The Movie 2019"));
}

/// M4-48: a YEAR or SEQUEL NUMBER run onto the title is not a hash.
///
/// The single-token rule that calls a 10+ character alphanumeric with a
/// digit in it a blob ("n1iY94U6fTpMVY9GPD") fires on the perfectly
/// honest subjects a poster writes without separators - "Inception2010",
/// "Terminator2", "Godzilla1998". That verdict is load-bearing twice
/// over: `stem_is_a_name` is what `get::plan` turns into
/// `hint_is_posted_name`, and `get::settle::filedesc_name_is_better`
/// reads that flag to decide whether the PAR2 FileDesc name may replace
/// the name the post already gave. Call the honest subject a blob and
/// GH #63's keep-the-honest-subject rule never arms, so the good file is
/// renamed TO the FileDesc hash - a wrong name on a real file, sitting
/// on disk where the user cannot find it.
///
/// "Terminator2" is the pin that matters: eleven characters, one digit,
/// no separator. A fix that merely raises the length threshold passes
/// the twelve-character "Godzilla1998" and still fails this one.
#[test]
fn a_year_or_sequel_run_onto_a_title_is_not_a_hash() {
    for s in [
        "Terminator2",   // 11 chars, ONE digit - the threshold-proof pin
        "Inception2010", // year run onto the title
        "Avatar2009",
        "Godzilla1998",
        "Terminator2.mkv", // as it actually reaches `stem_is_a_name`
        "Oceans11",
        "Apollo13",
        "Blade Runner 2049", // the separated form, already fine - control
    ] {
        assert!(!looks_obfuscated(bare_stem(s)), "honest subject: {s}");
        assert!(stem_is_a_name(s), "honest subject is a name: {s}");
    }
}

/// The other half of M4-48: stripping the tail must not hand a blob a
/// name. The head is judged by the SAME function, so every rule that
/// already caught a digit-free blob still catches it with a year or a
/// sequel number on the end - and a digit run that is neither a year nor
/// a sequel number is not stripped at all.
#[test]
fn a_numeric_tail_never_launders_a_blob() {
    for s in [
        // Three digits is neither a year nor a sequel number: no strip,
        // and these two are the shapes `obfuscated_hash_shapes_are_caught`
        // has pinned since the rule was written.
        "ABCDEFGHIJK123",
        "abcdefghijkl123",
        // The head still carries digits, so it was never a word plus a
        // number in the first place.
        "a1b2c3d4e5f6g7h8i9j0k1l2",
        "ZO01uZT4YhQAGrDQLC3U1",
        "c1bceab2fac4d74f47b0a0e18311ec5c53",
        "w17vwqfb7antoeed8",
        // Heads the alphabetic rules catch in their own right: scattered
        // internal capitals, a long single-case run, and a hex word.
        "MQHeRbSCIoPs2010",
        "abcdefghijklmnopqrstuvwx99",
        "deadbeef2010",
        // Nothing but digits has no head to keep.
        "2010",
        "141444",
    ] {
        assert!(looks_obfuscated(s), "should still be obfuscated: {s}");
    }
    // The property the strip actually asserts: a year or sequel tail
    // carries NO evidence either way, so the verdict on a stem is the
    // verdict on the same stem without it. Consistency, not a new
    // threshold - including where the answer is "blob".
    for (head, tailed) in [
        ("Terminator", "Terminator2"),
        ("Inception", "Inception2010"),
        ("MQHeRbSCIoPs", "MQHeRbSCIoPs2010"),
        ("abcdefghijklmnopqrstuvwx", "abcdefghijklmnopqrstuvwx99"),
    ] {
        assert_eq!(
            looks_obfuscated(head),
            looks_obfuscated(tailed),
            "a year/sequel tail changed the verdict: {head} vs {tailed}"
        );
    }
}

/// [`adopt_proved_identity`]'s whole contract, in the four directions
/// that matter. Wave-7 row W7-06: two parses of ONE payload, one of
/// them backed by a recovery set's own FileDesc and one by a regex over
/// a subject line anybody can mistype.
#[test]
fn a_proved_parse_corrects_a_claimed_title_and_year_and_nothing_else() {
    // The sharpest live shape: the .nzb names a different film.
    let mut claimed = parse_release("Wrong Film 2019 1080p WEB-DL-OTHER");
    let proved = parse_release("Example Movie 2024 1080p BluRay-GRP");
    assert!(adopt_proved_identity(&mut claimed, &proved));
    assert_eq!(norm_title(&claimed.title), norm_title("Example Movie"));
    assert_eq!(claimed.year, Some(2024));

    // Decoration is not a contradiction: nearly every honest movie post
    // ships a set declaring its payload, so a rule that fired here
    // would retire the metadata renamer for the whole population.
    let mut same = parse_release("Example Movie 2024 1080p BluRay-GRP");
    assert!(!adopt_proved_identity(&mut same, &proved));

    // Nothing is ever CLEARED - a proved parse with no year of its own
    // leaves the claimed year standing.
    let mut yearful = parse_release("Example Movie 2024 1080p BluRay-GRP");
    let yearless = parse_release("Example Movie 1080p BluRay-GRP");
    assert!(!adopt_proved_identity(&mut yearful, &yearless));
    assert_eq!(yearful.year, Some(2024));

    // And a proved year is ADDED to a claim that carried none, which is
    // the one field `Index::movie_year` can only ever fill and never
    // correct.
    let mut yearless = parse_release("Example Movie 1080p BluRay-GRP");
    assert!(adopt_proved_identity(&mut yearless, &proved));
    assert_eq!(yearless.year, Some(2024));
}

/// The deliberate exclusion, pinned so nobody adds it back by reflex:
/// RESOLUTION is not adopted. `smart::measured_res` reads the container
/// and is the project's single answer for that field; a second answer
/// here is exactly the drift this predicate exists to end.
#[test]
fn a_proved_parse_does_not_carry_its_resolution_across() {
    let mut claimed = parse_release("Example Movie 2024 1080p WEB-DL-OTHER");
    let proved = parse_release("Example Movie 2024 2160p BluRay REMUX-GRP");
    assert!(
        !adopt_proved_identity(&mut claimed, &proved),
        "title and year agree, so there is nothing this predicate may move"
    );
    assert_eq!(claimed.res.as_deref(), Some("1080p"));
}

/// The de-doubling rule, and the two ways it must NOT fire.
///
/// The subject nzbfast reads is the one that carries the doubling -
/// measured 1 Sep 2026 against the article subjects themselves - so the
/// predicate has to be exact: halves match byte for byte, internal
/// double spaces and all. That exactness is also the whole defence
/// against a repeated title, which always keeps its separator in one
/// half only.
#[test]
fn a_name_that_is_its_own_text_twice_collapses_to_one_copy() {
    // The live shapes, internal double space preserved.
    assert_eq!(
        undoubled("A Bona Fide Killer  S01E06A Bona Fide Killer  S01E06"),
        Some("A Bona Fide Killer  S01E06")
    );
    assert_eq!(
        undoubled("4 Kings (2021)4 Kings (2021)"),
        Some("4 Kings (2021)")
    );
    assert_eq!(
        undoubled(
            "Hellcat.2025.1080p.AMZN.WEB-DL.DDP5.1.H.264-GP-M-NLsubsHellcat.2025.1080p.AMZN.WEB-DL.DDP5.1.H.264-GP-M-NLsubs"
        ),
        Some("Hellcat.2025.1080p.AMZN.WEB-DL.DDP5.1.H.264-GP-M-NLsubs")
    );
    // Surrounding whitespace is not part of the question.
    assert_eq!(
        undoubled("  Some Show S01E01Some Show S01E01 "),
        Some("Some Show S01E01")
    );

    // A REPEATED title is not a doubled one: the separating space lands
    // in one half only, so the halves can never be equal. This is the
    // case a whitespace-normalising detector would wrongly damn, and it
    // is why the test stays exact.
    assert_eq!(undoubled("New York New York"), None);
    assert_eq!(undoubled("The Show S01E01 The Show S01E01"), None);

    // Below the floor: "fdrfdr" is the one short self-echo on the live
    // index and is left exactly as posted.
    assert_eq!(undoubled("fdrfdr"), None);
    assert_eq!(undoubled("abcabc"), None);

    // Not a doubling at all.
    assert_eq!(undoubled(""), None);
    assert_eq!(undoubled("A Perfectly Ordinary Release Name"), None);
    // Odd length cannot be one. And an EVEN byte length whose midpoint
    // falls inside a multibyte character must answer None rather than
    // panic: "abcdefg\u{e9}hijklmn" is 16 bytes with byte 8 in the
    // middle of the two-byte e-acute.
    assert_eq!(undoubled("Some Show S01E01x"), None);
    let straddles = "abcdefg\u{e9}hijklmn";
    assert_eq!(straddles.len() % 2, 0);
    assert!(!straddles.is_char_boundary(straddles.len() / 2));
    assert_eq!(undoubled(straddles), None);
}

/// The `books` and `music` interest presets, measured on a fresh
/// scratch index 2 Sep 2026 (research/INTEREST-PRESETS-BOOKS-MUSIC-
/// ANIME-2026-09-02.md): four stem shapes those groups post every day
/// that the parser filed as junk or the wrong lane.
#[test]
fn interest_preset_book_stems_reach_the_books_lane() {
    // "max" is the HBO Max source tag; at index 0 it emptied the title
    // and the whole stem was filed Other with junk 100.
    let p = parse_release(
        "Max Allan Collins & Jeff Gelb (ed) - [Flesh and Blood 03] - Guilty as Sin (epub).epub",
    );
    assert_eq!(p.kind, Kind::Book, "{p:?}");
    assert!(p.title.starts_with("Max Allan Collins"), "{:?}", p.title);
    assert_eq!(
        crate::junk::junk_score(
            "Max Allan Collins & Jeff Gelb (ed) - [Flesh and Blood 03] - Guilty as Sin (epub).epub",
            &p,
            800_000,
            false
        ),
        0
    );
    // A tag at index 0 still cannot make a film out of nothing: the
    // leading word is the title and the rest still parses.
    let p = parse_release("Max.Payne.2008.1080p.BluRay.x264-GRP");
    assert_eq!(p.kind, Kind::Movie);
    assert_eq!(p.title, "Max Payne");
    assert_eq!(p.year, Some(2008));
    // An edition number reads as a software version; the extension wins.
    let p = parse_release(
        "Joseph Hansen - Dave Brandstetter 04 The Man Everybody Was Afraid Of (v5.0).epub",
    );
    assert_eq!(p.kind, Kind::Book, "{p:?}");
    // Software that says so and ends in nothing stays software.
    assert_eq!(
        parse_release("Topaz Photo AI Pro 4.1.0 x64 Multilingual").kind,
        Kind::Software
    );
    // A scene-named playlist parses as music through its format marker
    // and used to score 0: a 1.5 KB "album" card beside every album in
    // alt.binaries.sounds.flac. Playlists and cue sheets are furniture.
    for stem in [
        "00-mario_lopez-free_your_mind-cdm-flac-2002.m3u",
        "000-bo_kaspers_orkester-sa_mycket-se-2cd-flac-2013.cue",
        "00-va-superballads_06-cd-flac-2000.log",
    ] {
        let p = parse_release(stem);
        assert!(
            crate::junk::junk_score(stem, &p, 1_500, false) >= 60,
            "{stem}"
        );
    }
    // .cbr is the other comic-book archive; .cbz was already a marker.
    assert_eq!(
        parse_release("Batman - The Long Halloween 01.cbr").kind,
        Kind::Book
    );
}

#[test]
fn group_prior_files_evidence_free_names_by_lane() {
    let mut p = parse_release("Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)");
    assert_eq!(p.kind, Kind::Movie);
    recover_kind_from_group(
        &mut p,
        "alt.binaries.mp3.audiobooks",
        "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
    );
    assert_eq!(p.kind, Kind::Book);
    assert!(p.key.starts_with("bk:"), "{}", p.key);
    assert_eq!(
        p.title,
        "Perry Rhodan 3390 - Die Stunde der Deponentin Ungekuerzt"
    );
    // The scorer follows the lane: books are exempt from the
    // evidence-free-movie rule that hid this at 60.
    assert!(
        crate::junk::junk_score(
            "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
            &p,
            230_000_000,
            false
        ) < 50
    );

    let mut p = parse_release("Dance Classics Hits Vol. 13 (1994)(320)");
    recover_kind_from_group(
        &mut p,
        "alt.binaries.sounds.mp3",
        "Dance Classics Hits Vol. 13 (1994)(320)",
    );
    assert_eq!(p.kind, Kind::Music);
    assert!(p.key.starts_with("mu:"), "{}", p.key);
    // Furniture with an extension the markers did not claim stays
    // where it was: cover art, playlists, sidecars.
    // Measured: 193 rows of one sounds.mp3 lap became visible "music"
    // cards under the first cut of this rule.
    //
    // A ROT13 VOLUME ("...cneg6.ene") was pinned here too and is not
    // any more: it looked like an unclaimed extension only because
    // nothing decoded it, and ".ene" is ".rar" - a volume suffix. The
    // rescue reads it now, so the lane rule reasons over the decode
    // and that stem belongs with the rescued ones
    // (`rot13_rescue_reads_music_and_book_names`).
    for stem in [
        "00-kmfdm-enemy-web-2026.jpg",
        "Hype.m3u",
        "000_VA - MTV New Playlist Rap & RnB Top 200 (2011).jpg",
        "Stephen R. Lawhead.nzb",
    ] {
        let mut p = parse_release(stem);
        let before = p.kind.clone();
        recover_kind_from_group(&mut p, "alt.binaries.sounds.mp3", stem);
        assert_eq!(p.kind, before, "{stem}");
        recover_kind_from_group(&mut p, "alt.binaries.audiobooks", stem);
        assert_eq!(p.kind, before, "{stem}");
    }
    // A dotted version number is software that forgot to say so.
    let mut p = parse_release("Topaz Video AI Pro 8.1.6");
    recover_kind_from_group(
        &mut p,
        "alt.binaries.sounds.mp3",
        "Topaz Video AI Pro 8.1.6",
    );
    assert_ne!(p.kind, Kind::Music);

    // Video evidence in the name overrules the group: the ebook group
    // is 95% TV episodes on the wire and they must stay TV.
    let mut p = parse_release("Teen.Titans.Go!.S09E37.Task.Force.X.720p.HEVC.x265-MeGusta.mkv");
    recover_kind_from_group(
        &mut p,
        "alt.binaries.ebook",
        "Teen.Titans.Go!.S09E37.Task.Force.X.720p.HEVC.x265-MeGusta.mkv",
    );
    assert_eq!(p.kind, Kind::Tv);
    let mut p = parse_release("The.Matrix.1999.1080p.BluRay.x264-GRP");
    recover_kind_from_group(
        &mut p,
        "alt.binaries.sounds.flac",
        "The.Matrix.1999.1080p.BluRay.x264-GRP",
    );
    assert_eq!(p.kind, Kind::Movie);
    // Software says so itself.
    let mut p = parse_release("DVDFab 13.0.6.5 (x64) Multilingual");
    recover_kind_from_group(
        &mut p,
        "alt.binaries.e-book",
        "DVDFab 13.0.6.5 (x64) Multilingual",
    );
    assert_eq!(p.kind, Kind::Software);
    // The parser gave up: an obfuscated stem must not become a "book".
    let mut p = parse_release("b6V2qR8mL4pC7xN9zH3k");
    recover_kind_from_group(&mut p, "alt.binaries.e-book", "b6V2qR8mL4pC7xN9zH3k");
    assert_eq!(p.kind, Kind::Other);
    // No word in the title: a numbered scan is not a card.
    let mut p = parse_release("7.23");
    recover_kind_from_group(&mut p, "alt.binaries.sounds.mp3", "7.23");
    assert_ne!(p.kind, Kind::Music);
    // A group that vouches for nothing changes nothing.
    let mut p = parse_release("Pierre Clostermann - The Big Show");
    recover_kind_from_group(
        &mut p,
        "alt.binaries.boneless",
        "Pierre Clostermann - The Big Show",
    );
    assert_eq!(p.kind, Kind::Movie);

    assert_eq!(
        group_media_kind("alt.binaries.mp3.abooks"),
        Some(Kind::Book)
    );
    assert_eq!(
        group_media_kind("alt.binaries.sounds.mp3.german.hoerbuecher"),
        Some(Kind::Book)
    );
    assert_eq!(
        group_media_kind("alt.binaries.sounds.lossless"),
        Some(Kind::Music)
    );
    assert_eq!(group_media_kind("alt.binaries.teevee"), None);
}

/// Anime is not posted in scene shape, and the parser could not read a
/// word of it. Every stem here is a real subject off
/// alt.binaries.multimedia.anime.highspeed, measured on a scratch index
/// 2 Sep 2026 (research/INTEREST-PRESETS-BOOKS-MUSIC-ANIME-2026-09-02.md
/// section 4): the whole group parsed as evidence-free MOVIES at junk
/// 60, hidden by the wall's default hide line, with the fansub group
/// kept as the title's first word and the episode number thrown away.
#[test]
fn anime_fansub_stems_read_their_group_and_episode() {
    // Before: kind movie, title "SubsPlease Kanojo, Okarishimasu - 09",
    // no episode.
    let a = p("[SubsPlease] Kanojo, Okarishimasu - 09 (1080p) [26591A73].mkv");
    assert_eq!(a.kind, Kind::Tv);
    assert_eq!(a.title, "Kanojo, Okarishimasu");
    assert_eq!((a.season, a.episode), (Some(1), Some(9)));
    assert_eq!(a.group.as_deref(), Some("SubsPlease"));
    assert_eq!(a.res.as_deref(), Some("1080p"));

    // Before: kind movie, title "Later Bleach TYBW 41". A bare trailing
    // number before the quality furniture, with no separator in front
    // of it at all.
    let b = p("[Later] Bleach TYBW 41 (Web 1080p x264 10bit, Dual EAC3 AAC, Dual ASS).mkv");
    assert_eq!(b.kind, Kind::Tv);
    assert_eq!(b.title, "Bleach TYBW");
    assert_eq!((b.season, b.episode), (Some(1), Some(41)));

    // Before: kind TV, but only by accident - the eight-digit CRC in
    // "[51697563]" read as a datecode, so the post was a daily show
    // with no date, no season and no episode. Now it is TV because it
    // says which episode it is, and 1210 survives the four-digit width
    // that would be a year on any other number.
    let c = p("[SubsPlease] Detective Conan - 1210 (480p) [51697563].mkv");
    assert_eq!(c.kind, Kind::Tv);
    assert_eq!(c.title, "Detective Conan");
    assert_eq!((c.season, c.episode), (Some(1), Some(1210)));
    assert_eq!(c.year, None);

    // Same show, every episode: one card, which is the point of the
    // title key.
    assert_eq!(
        c.key,
        p("[Erai-raws] Detective Conan - 1211 [480p].mkv").key
    );

    // Before: kind movie, junk 60, title "sandoe41 Ep 04 1080P][BDRip]
    // [HEVC-10bit][FLAC]" - the bracket RUN arrived as one token so not
    // one quality fact in it was read. The show name is only in the
    // posted FOLDER, so there is nothing here to title the card with
    // and the row stays dark. That is the honest answer, and it has to
    // stay dark deliberately: reading the resolution out of the flattened
    // brackets clears junk_score's evidence-free rule, so an untitled
    // post would otherwise have surfaced.
    let d = p("[sandoe41] Ep. 04 [1080P][BDRip][HEVC-10bit][FLAC].mkv");
    assert_eq!(d.kind, Kind::Other);
    assert!(d.res.is_none() && d.season.is_none());

    // The other two conventions the group posts: "Ep. NN" with a title
    // in front of it, and the re-sub version suffix.
    let e = p("[Erai-raws] Show Name - Ep. 12 [1080p][Multiple Subtitle].mkv");
    assert_eq!(e.title, "Show Name");
    assert_eq!((e.season, e.episode), (Some(1), Some(12)));
    let f = p("[SubsPlease] Show - 09v2 (1080p) [26591A73].mkv");
    assert_eq!(
        (f.title.as_str(), f.season, f.episode),
        ("Show", Some(1), Some(9))
    );

    // A season IN the title is read the ordinary way and never
    // overwritten by the absolute-numbering default, and the episode
    // after it is still read: a bare "S2" alone parses as a season
    // PACK, and the watchlist treats a pack as covering the whole
    // season, so one episode wearing a pack's parse tells a watched
    // show it is finished.
    let g = p("[SubsPlease] Kanojo, Okarishimasu S2 - 05 (1080p) [ABCD1234].mkv");
    assert_eq!(
        (g.title.as_str(), g.season, g.episode),
        ("Kanojo, Okarishimasu", Some(2), Some(5))
    );
    // ...and a real pack stays a pack.
    let h = p("[SubsPlease] Kanojo, Okarishimasu S2 [1080p].mkv");
    assert_eq!((h.season, h.episode), (Some(2), None));

    // The fused "Ep18" one poster on the group writes, and a number
    // with the episode's own title behind it. Before: movie 60,
    // "Exiled-Destiny Zipang Ep18 E3171C5A"; and movie 0, "High School
    // DxD New 09 - I Have a Junior".
    let i = p("[Exiled-Destiny]_Zipang_Ep18_(E3171C5A).mkv");
    assert_eq!(
        (i.title.as_str(), i.season, i.episode),
        ("Zipang", Some(1), Some(18))
    );
    let j =
        p("[Abystoma] High School DxD New 09 - I Have a Junior (BD 720p) [Dual] [828E32A6].mkv");
    assert_eq!(j.kind, Kind::Tv);
    assert_eq!(
        (j.title.as_str(), j.season, j.episode),
        ("High School DxD New", Some(1), Some(9))
    );

    // An opening or ending theme is not an episode: "OP01" carries no
    // bare number and nothing here may invent one.
    let op = p("[FFF] Highschool DxD NEW - OP01 [BD][720p-AAC][79CDB3E5].mkv");
    assert_eq!((op.season, op.episode), (None, None));

    // The dangling hyphen the episode hung off never reaches the title.
    assert_eq!(
        p("[Judas] Attack on Titan - S04E28 [1080p][HEVC x265 10bit]").title,
        "Attack on Titan"
    );
}

/// What the fansub reading must NOT reach. Every shape here parsed the
/// way it does today before the anime lane existed, and has to keep
/// doing so.
#[test]
fn the_fansub_reading_leaves_scene_and_spam_alone() {
    // Scene-shaped anime already parsed correctly and is untouched.
    let scene = p("Tamons.B-Side.2026.S01E13.REPACK.1080p.CR.WEB-DL.DUAL.DDP2.0.H.264-AnoZu.mkv");
    assert_eq!(scene.kind, Kind::Tv);
    assert_eq!(scene.title, "Tamons B-Side");
    assert_eq!(
        (scene.season, scene.episode, scene.year),
        (Some(1), Some(13), Some(2026))
    );

    // A bracketed HEX tag is repost-bot spam, not a fansub group:
    // junk_score damns that shape by name, so the tag stays where it is
    // and the stem stays obfuscated.
    let spam = "[ff63de8461]_[newzNZB]_NGKzwg4lCQF_vMr95eoDx2X9NxbLi";
    assert!(crate::junk::stem_obfuscated(spam, &p(spam)));
    assert!(p(spam).group.is_none());

    // A reposter tag is `strip_reposter_tags`'s to own.
    assert!(p("[nzbgeek] The Movie 2019 1080p").group.is_none());

    // A YEAR is never an episode.
    let film = p("[Group] Some Film 2019 1080p x264-GRP");
    assert_eq!(film.kind, Kind::Movie);
    assert_eq!(
        (film.title.as_str(), film.year, film.episode),
        ("Some Film", Some(2019), None)
    );

    // Outside the fansub convention a trailing bare number is a sequel,
    // a part counter or a track, and nothing here may read it.
    let rocky = p("Rocky 4 1080p BluRay x264-GRP");
    assert_eq!(rocky.kind, Kind::Movie);
    assert_eq!(
        (rocky.title.as_str(), rocky.season, rocky.episode),
        ("Rocky 4", None, None)
    );
    let lecture = p("003 - Estomago.mp4");
    assert_eq!((lecture.season, lecture.episode), (None, None));

    // A stem that is nothing but a tag and a number has no title to
    // keep, and inventing one out of the group tag would put the
    // poster's name on a card.
    assert_eq!(p("[SubsPlease] 09 (1080p).mkv").kind, Kind::Other);
}

/// A daily paper and a dated magazine issue name themselves by DATE, and
/// the parser used to read that date as a year, strand the day in the
/// title and key every issue of one paper onto ONE card.
///
/// Measured 2 Sep 2026 on `463a82376`, through the ingest order
/// (`release_stem` -> `parse_release` -> `recover_kind_from_group` ->
/// `junk_score`), group `alt.binaries.e-book.magazines` at 5 MB:
///
/// ```text
/// The New York Times - 15 August 2026   title "The New York Times - 15 August"  year 2026  date None
/// The Guardian - 15 August 2026         title "The Guardian - 15 August"        year 2026  date None
/// Der Spiegel - 2026-08-15              title "Der Spiegel - 2026-08-15"        year None  date None
/// The New York Times - August 15, 2026  title "The New York Times - August 15," year 2026  date None
/// ```
///
/// All four were `kind=Book junk=0` already - the group prior that
/// landed the same day put them on the Books lane - so the defect this
/// pins is the IDENTITY, not the lane. The lane is asserted anyway,
/// below, because that is the half a naive fix breaks.
#[test]
fn masthead_dates_are_dates_not_years() {
    let grp = "alt.binaries.e-book.magazines";
    // (posted name, title, normalized date)
    let cases = [
        (
            "The New York Times - 15 August 2026.pdf",
            "The New York Times",
            "20260815",
        ),
        (
            "The Guardian - 15 August 2026.pdf",
            "The Guardian",
            "20260815",
        ),
        // ISO after a dash. One TOKEN, because the tokenizer never
        // splits on a hyphen, so the whole date used to land in the
        // title and no year parsed at all.
        ("Der Spiegel - 2026-08-15.pdf", "Der Spiegel", "20260815"),
        // The American order, comma and all.
        (
            "The New York Times - August 15, 2026.pdf",
            "The New York Times",
            "20260815",
        ),
        // A leading-zero day, and the ordinal a masthead sometimes
        // prints instead.
        (
            "The New York Times - 01 September 2026.pdf",
            "The New York Times",
            "20260901",
        ),
        (
            "The Observer - 15th August 2026.pdf",
            "The Observer",
            "20260815",
        ),
        // The three-letter abbreviation, either order.
        ("The Guardian - 15 Aug 2026.pdf", "The Guardian", "20260815"),
        (
            "The Guardian - Aug 15, 2026.pdf",
            "The Guardian",
            "20260815",
        ),
    ];
    for (posted, title, date) in cases {
        let stem = crate::names::release_stem(posted);
        let mut p = parse_release(&stem);
        recover_kind_from_group(&mut p, grp, &stem);
        assert_eq!(p.title, title, "{posted}");
        assert_eq!(p.date.as_deref(), Some(date), "{posted}");
        // The year token was SPENT on the date. Leaving it behind as
        // well would put a "2026" badge on an issue that is not a 2026
        // edition of anything, and is not what the dotted daily arm does.
        assert_eq!(p.year, None, "{posted}");
        // A masthead date is not an air date.
        assert!(!p.daily, "{posted}");
        assert_eq!(p.kind, Kind::Book, "{posted}");
        // The key carries the date, so two issues of one paper are two
        // releases. Before this, both were "bk:the new york times".
        assert_eq!(
            p.key,
            format!("bk:{}:{date}", norm_title(title)),
            "{posted}"
        );
        // The format marker after the date is the end of the identity,
        // not part of it: an `extra` of ["pdf"] is `movie_name`
        // declining to name the issue at all.
        assert!(p.extra.is_empty(), "{posted} extra={:?}", p.extra);
        // Visible: below the wall's default hide line at 50, at a
        // magazine's real size and at a bundle's.
        for bytes in [5u64 << 20, 400 << 20] {
            assert!(
                crate::junk::junk_score(&stem, &p, bytes, false) < 50,
                "{posted} at {bytes} bytes",
            );
        }
    }

    // Two issues of one paper are two keys; the same issue posted twice,
    // in either date order, is one.
    let k = |s: &str| parse_release(&crate::names::release_stem(s)).key;
    assert_ne!(
        k("The New York Times - 15 August 2026.pdf"),
        k("The New York Times - 16 August 2026.pdf")
    );
    assert_eq!(
        k("The New York Times - 15 August 2026.pdf"),
        k("The New York Times - August 15, 2026.pdf")
    );
}

/// The FOLDER form is where a naive fix shows: with no `.pdf` to mark it
/// a book, the only thing that can file a magazine is
/// `recover_kind_from_group`, and that function stands down when the
/// parse carries video evidence. A date IS video evidence when it is an
/// air date - which is why `Parsed::daily` exists and why the guard asks
/// that and not `date.is_some()`. Ask it the wrong way and every dated
/// magazine falls back to an evidence-free movie at junk 60, which is
/// the exact state the group prior had just moved them out of.
#[test]
fn a_masthead_date_does_not_disarm_the_group_prior() {
    for posted in [
        "The New York Times - 15 August 2026",
        "Der Spiegel - 2026-08-15",
        "The Guardian - August 15, 2026",
    ] {
        let mut p = parse_release(posted);
        // Pre-group: an evidence-free movie, exactly as before - the
        // date changed the identity, not the lane.
        assert_eq!(p.kind, Kind::Movie, "{posted}");
        assert!(p.date.is_some() && !p.daily, "{posted}");
        recover_kind_from_group(&mut p, "alt.binaries.e-book.magazines", posted);
        assert_eq!(p.kind, Kind::Book, "{posted}");
        assert!(
            crate::junk::junk_score(posted, &p, 5 << 20, false) < 50,
            "{posted}",
        );
    }
}

/// A dated post spends its year TOKEN on the date, so the year field
/// goes empty - and `junk_score`'s evidence-free rule counted the year
/// and not the date. Left alone, a masthead-dated post in a group with
/// no media prior would have gone from a year-bearing 0 to a hidden 60
/// purely because the parser got better at reading it. The date now
/// counts as the technical marker it is.
#[test]
fn a_date_is_evidence_where_the_year_it_replaced_was() {
    // No group prior, so nothing puts this on the Books lane: it is the
    // evidence-free-movie rule and nothing else deciding.
    let stem = "The New York Times - 15 August 2026";
    let q = p(stem);
    assert_eq!(q.kind, Kind::Movie);
    assert_eq!(q.year, None);
    assert_eq!(q.date.as_deref(), Some("20260815"));
    // Past the tiny-post line, which damns a Movie of any evidence.
    assert!(crate::junk::junk_score(stem, &q, 400 << 20, false) < 50);
    // And the rule still fires on a name that carries nothing at all.
    let bare = p("misfits-wegedeutschensd.mp4");
    assert!(crate::junk::junk_score("misfits-wegedeutschensd.mp4", &bare, 400 << 20, false) >= 60);
}

/// The other boundary: a year on a book that is not a periodical stays a
/// year and grows no date, and a TV daily keeps its AIR date.
///
/// CHANGED 2 Sep 2026, deliberately. This test used to pin the two
/// MONTHLY forms below - "Slam.TruePDF-September.2016.pdf" and
/// "The.Chap.TruePDF-June.July.2016.pdf" - as year-bearing controls,
/// on the reasoning that a month and a year is not a date
/// `Parsed::date` could hold. It can now, at a month precision, and the
/// two stems moved to `a_monthly_issue_is_a_month_and_a_year` with
/// their before-states written out there. What stays here is their
/// FOLDER form, which has no book marker for the month arm to gate on
/// and so is genuinely still year-bearing, and the real books, which
/// are what this test is actually for.
#[test]
fn a_year_is_still_a_year_and_an_air_date_still_an_air_date() {
    // Books. Editions and author-title-year: a year beside a book's
    // title is the edition, not an issue, and nothing about the
    // periodical readings may touch it.
    for (posted, grp, title, year) in [
        (
            "Frank Herbert - Dune (2014) (epub).epub",
            "alt.binaries.e-book",
            "Frank Herbert - Dune",
            Some(2014),
        ),
        (
            "Author - Title (2014).epub",
            "alt.binaries.e-book",
            "Author - Title",
            Some(2014),
        ),
        // The monthlies' FOLDER form: no `.pdf`, so `media_marker` says
        // nothing, the month arm never arms and the year stays exactly
        // where it was. The group prior is the only thing that can file
        // these, and it still does - asserted at the bottom of
        // `a_monthly_is_read_on_the_books_lane_and_nowhere_else`.
        (
            "Slam.TruePDF-September.2016",
            "alt.binaries.e-book.magazines",
            "Slam TruePDF-September",
            Some(2016),
        ),
        (
            "The.Chap.TruePDF-June.July.2016",
            "alt.binaries.e-book.magazines",
            "The Chap TruePDF-June July",
            Some(2016),
        ),
    ] {
        let stem = crate::names::release_stem(posted);
        let mut p = parse_release(&stem);
        recover_kind_from_group(&mut p, grp, &stem);
        assert_eq!(p.kind, Kind::Book, "{posted}");
        assert_eq!(p.title, title, "{posted}");
        assert_eq!(p.year, year, "{posted}");
        assert_eq!(p.date, None, "{posted}");
        assert_eq!(p.key, format!("bk:{}", norm_title(title)), "{posted}");
    }

    // Films keep theirs.
    let m = p("The.Matrix.1999.1080p.BluRay.x264-GRP");
    assert_eq!(m.year, Some(1999));
    assert_eq!(m.date, None);

    // The two daily-TV conventions are untouched, and BOTH still say
    // `daily` - the flag the group prior reads.
    for stem in [
        "Show.Name.260721.1080p.WEB.x264-GRP",
        "The.Daily.Show.2026.07.21.1080p.WEB-GRP",
    ] {
        let d = p(stem);
        assert_eq!(d.kind, Kind::Tv, "{stem}");
        assert_eq!(d.date.as_deref(), Some("20260721"), "{stem}");
        assert!(d.daily, "{stem}");
    }
    // And a dated event still carries its identity tail past the date.
    let epl = p("EPL.2026.08.22.Arsenal.vs.Spurs.1080p");
    assert_eq!(epl.date.as_deref(), Some("20260822"));
    assert_eq!(epl.extra, vec!["Arsenal", "vs", "Spurs"]);
}

/// The date readers refuse what is not a date. A spelled month is the
/// one form that cannot also be a track number, a size or an id, so the
/// arms are held to a real calendar rather than a range check.
#[test]
fn a_date_that_does_not_exist_is_three_ordinary_words() {
    for stem in [
        "The Guardian - 31 February 2026.pdf", // no such day
        "The Guardian - 30 February 2026.pdf",
        "The Guardian - 2026-02-30.pdf",
        "The Guardian - 2026-13-01.pdf", // no such month
        "The Guardian - 2026-08-00.pdf",
        "The Guardian - 15 Augustus 2026.pdf", // not a month
        "The Guardian - 15 Ju 2026.pdf",       // too short to name one
        "Artist - 15 August.pdf",              // no year, so no date
        "The Guardian - 155 August 2026.pdf",  // no such day
    ] {
        assert_eq!(p(stem).date, None, "{stem}");
    }
    // A leap day is a real date in 2024 and not in 2026.
    assert_eq!(
        p("The Guardian - 29 February 2024.pdf").date.as_deref(),
        Some("20240229")
    );
    assert_eq!(p("The Guardian - 29 February 2026.pdf").date, None);
    // A date at index 0 is the title, as everywhere else in this parser.
    assert_eq!(p("2026-08-15.pdf").date, None);
    // A track number beside a month name is not a date without a year:
    // "01 - August" is how a track is written.
    assert_eq!(p("Artist - 01 - August - Song.mp3").date, None);
}

/// `Show - NNN - Episode Title` with no group tag, which the bracketed
/// fansub reading could not reach. Every stem here is a real subject off
/// alt.binaries.multimedia.anime.highspeed, measured on a scratch index
/// 2 Sep 2026 (research/INTEREST-PRESETS-BOOKS-MUSIC-ANIME-2026-09-02.md
/// section 7): all 176 HIDDEN un-bracketed rows on that group were one
/// poster's Bleach dump in this shape, each of them kind movie, junk 60,
/// titled with the whole line and carrying a card of its own.
#[test]
fn a_video_group_reads_the_dashed_episode_number() {
    const GRP: &str = "alt.binaries.multimedia.anime.highspeed";
    // The file and the FOLDER of the same post. The extension is weak
    // evidence and half the corpus has none, so both must land on the
    // same release or one post sits on two cards.
    let keys: Vec<String> = [
        "Bleach - 187 - Ichigo Rages! The Assassin's Secret.mkv",
        "Bleach - 215 - Defend Karakura Town! Entire Appearance Of The Shinigami",
        "Bleach - 162 - Syazel Aporro Laughs, The Net Trapping Renji Is Complete.mkv",
    ]
    .iter()
    .map(|stem| {
        let mut r = p(stem);
        // Before: an evidence-free movie titled with the whole line.
        assert_eq!(r.kind, Kind::Movie, "{stem}");
        assert!(r.episode.is_none(), "{stem}");
        assert!(
            crate::junk::junk_score(stem, &r, 400 << 20, false) >= 60,
            "{stem}"
        );
        recover_kind_from_group(&mut r, GRP, stem);
        recover_episode_from_group(&mut r, GRP, stem);
        assert_eq!(r.kind, Kind::Tv, "{stem}");
        assert_eq!(r.title, "Bleach", "{stem}");
        assert_eq!(r.season, Some(1), "{stem}");
        // And now visible: the episode is the evidence junk_score
        // asked for.
        assert!(
            crate::junk::junk_score(stem, &r, 400 << 20, false) < 50,
            "{stem}"
        );
        (r.episode, r.key)
    })
    .map(|(ep, key)| {
        assert!(ep.is_some());
        key
    })
    .collect();
    // One card for the show, which is the point of the title key.
    assert_eq!(keys[0], keys[1]);
    assert_eq!(keys[0], keys[2]);
    assert_eq!(p("Bleach - 187 - Ichigo Rages!.mkv").episode, None);
}

/// The same shape in a books or music group is a chapter or a track,
/// and reading an episode there would ALSO disarm the lane rescue -
/// `recover_kind_from_group` returns early on `p.episode.is_some()`,
/// and that rescue is the whole reason an audiobook folder reaches the
/// Books lane at all (memo section 5).
#[test]
fn the_dashed_reading_leaves_books_music_and_everything_else_alone() {
    for (grp, stem, want) in [
        // A track, in the group the census measured.
        (
            "alt.binaries.sounds.mp3",
            "Gelugugu - 14 - Blue Sky",
            Kind::Music,
        ),
        (
            "alt.binaries.sounds.mp3.complete_cd",
            "Dance Classics - 03 - Hits Of The Summer",
            Kind::Music,
        ),
        // A chapter.
        (
            "alt.binaries.mp3.audiobooks",
            "Perry Rhodan - 04 - Die Stunde der Deponentin",
            Kind::Book,
        ),
        (
            "alt.binaries.e-book",
            "Robin James - 04 - Mark of Justice",
            Kind::Book,
        ),
        // A group that vouches for nothing at all.
        (
            "alt.binaries.boneless",
            "Bleach - 187 - Ichigo Rages! The Assassin's Secret.mkv",
            Kind::Movie,
        ),
    ] {
        let mut r = p(stem);
        recover_kind_from_group(&mut r, grp, stem);
        recover_episode_from_group(&mut r, grp, stem);
        assert_eq!(r.kind, want, "{grp} {stem}");
        assert_eq!(r.episode, None, "{grp} {stem}");
        assert_eq!(r.season, None, "{grp} {stem}");
    }
    // The lane rescue's own corpus, run through BOTH passes in the
    // ingest path's order: nothing it files may gain an episode.
    for (grp, stem) in [
        (
            "alt.binaries.mp3.audiobooks",
            "Perry Rhodan 3390 - Die Stunde der Deponentin (Ungekuerzt)",
        ),
        (
            "alt.binaries.audiobooks",
            "Pierre Clostermann - The Big Show",
        ),
        (
            "alt.binaries.sounds.mp3",
            "Dance Classics Hits Vol. 13 (1994)(320)",
        ),
    ] {
        let mut r = p(stem);
        recover_kind_from_group(&mut r, grp, stem);
        recover_episode_from_group(&mut r, grp, stem);
        assert!(
            matches!(r.kind, Kind::Book | Kind::Music),
            "{stem} {:?}",
            r.kind
        );
        assert_eq!(r.episode, None, "{stem}");
    }
    // A group says video by a WORD, never by the absence of a book or
    // music word - and a music group with "anime" in it is still music.
    assert!(group_vouches_video(
        "alt.binaries.multimedia.anime.highspeed"
    ));
    assert!(group_vouches_video("alt.binaries.teevee"));
    assert!(!group_vouches_video("alt.binaries.boneless"));
    assert!(!group_vouches_video("alt.binaries.moovee"));
    assert!(!group_vouches_video("alt.binaries.sounds.anime"));
    assert!(!group_vouches_video("alt.binaries.e-book.anime"));
}

/// What the fence buys, asked one refusal at a time. All in a group
/// that DOES vouch for video, so only the shape can be doing the work.
#[test]
fn the_dashed_reading_needs_the_whole_shape() {
    const GRP: &str = "alt.binaries.multimedia.anime.highspeed";
    let read = |stem: &str| {
        let mut r = p(stem);
        recover_episode_from_group(&mut r, GRP, stem);
        r
    };
    // A YEAR is never an episode.
    let film = read("Ghost in the Shell - 1995 - Remastered Edition");
    assert_eq!((film.kind.clone(), film.episode), (Kind::Movie, None));
    // A sequel number trails the title; it is not fenced and has no
    // episode name behind it.
    let seq = read("Ghost in the Shell 2");
    assert_eq!((seq.kind.clone(), seq.episode), (Kind::Movie, None));
    // The numbered-lecture prefix junk_score damns by name: no title in
    // front of the number, so the fence cannot close.
    let lecture = read("003 - Estomago.mp4");
    assert_eq!((lecture.season, lecture.episode), (None, None));
    assert!(crate::junk::junk_score("003 - Estomago.mp4", &lecture, 400 << 20, false) >= 60);
    // Nothing behind the number: a part counter, not an episode.
    assert_eq!(read("Bleach - 187 -").episode, None);
    // Video evidence in the name means the parse stood on its own.
    let scene =
        read("Tamons.B-Side.2026.S01E13.REPACK.1080p.CR.WEB-DL.DUAL.DDP2.0.H.264-AnoZu.mkv");
    assert_eq!((scene.season, scene.episode), (Some(1), Some(13)));
    let hd = read("Some Show - 04 - The Title 1080p WEB-DL x264");
    assert_eq!(hd.episode, None);
    // The bracketed path is untouched: it never reaches this pass, and
    // reads the same as it did before it existed.
    let mut fan = p("[SubsPlease] Kanojo, Okarishimasu - 09 (1080p) [26591A73].mkv");
    let before = fan.clone();
    recover_episode_from_group(
        &mut fan,
        GRP,
        "[SubsPlease] Kanojo, Okarishimasu - 09 (1080p) [26591A73].mkv",
    );
    assert_eq!(
        (fan.kind, fan.title, fan.season, fan.episode),
        (before.kind, before.title, before.season, before.episode)
    );
}

/// A MONTHLY issue is a month and a year, and both belong in the KEY.
///
/// Measured 2 Sep 2026 on the tip, through the real ingest order
/// (`release_stem` -> `parse_release` -> `recover_kind_from_group` ->
/// `junk_score`), group `alt.binaries.e-book.magazines` at 5 MB. Every
/// one was `kind=Book junk=0` already - the lane was right and is not
/// what this pins:
///
/// ```text
/// Slam.TruePDF-September.2016.pdf      "Slam TruePDF-September"      2016  key "bk:slam truepdf september"
/// Slam.TruePDF-September.2017.pdf      "Slam TruePDF-September"      2017  key "bk:slam truepdf september"
/// The.Chap.TruePDF-June.July.2016.pdf  "The Chap TruePDF-June July"  2016  key "bk:the chap truepdf june july"
/// New Scientist - September 2016.pdf   "New Scientist - September"   2016  key "bk:new scientist september"
/// Wired UK - October 2016.pdf          "Wired UK - October"          2016  key "bk:wired uk october"
/// National Geographic - March 2020.pdf "National Geographic - March" 2020  key "bk:national geographic march"
/// ```
///
/// `date` was None on all six, and `media_key` drops the year on
/// purpose (an album's year is an edition marker), so the two Slams -
/// September 2016 and September 2017 - were ONE card, and so was every
/// other September of every other year.
#[test]
fn a_monthly_issue_is_a_month_and_a_year() {
    let grp = "alt.binaries.e-book.magazines";
    // (posted name, title, "yyyymm")
    let cases = [
        // The month glued to a format token by a hyphen the tokenizer
        // never splits on. The token goes with the month, which is
        // right: "TruePDF" is furniture, not part of the masthead.
        ("Slam.TruePDF-September.2016.pdf", "Slam", "201609"),
        ("Slam.TruePDF-September.2017.pdf", "Slam", "201709"),
        // A DOUBLE issue keys on the first of its two months.
        ("The.Chap.TruePDF-June.July.2016.pdf", "The Chap", "201606"),
        ("The.Chap.September-October.2016.pdf", "The Chap", "201609"),
        // The plain masthead form, fenced by the separator.
        (
            "New Scientist - September 2016.pdf",
            "New Scientist",
            "201609",
        ),
        ("Wired UK - October 2016.pdf", "Wired UK", "201610"),
        (
            "National Geographic - March 2020.pdf",
            "National Geographic",
            "202003",
        ),
        // The three-letter abbreviation `month_of` already reads.
        ("New Scientist - Sep 2016.pdf", "New Scientist", "201609"),
        // An issue NUMBER in front of the month is real identity and
        // stays in the title; only the month and the year are spent.
        (
            "Linux Magazine - Issue 250 - September 2021.pdf",
            "Linux Magazine - Issue 250",
            "202109",
        ),
    ];
    for (posted, title, date) in cases {
        let stem = crate::names::release_stem(posted);
        let mut q = parse_release(&stem);
        recover_kind_from_group(&mut q, grp, &stem);
        assert_eq!(q.kind, Kind::Book, "{posted}");
        assert_eq!(q.title, title, "{posted}");
        assert_eq!(q.date.as_deref(), Some(date), "{posted}");
        // Six digits, not eight: a monthly has no day, and the width IS
        // the precision (see `Parsed::date`).
        assert_eq!(q.date.as_deref().map(str::len), Some(6), "{posted}");
        // The year token was spent on the date, as it is for a daily.
        assert_eq!(q.year, None, "{posted}");
        // A publication date, never an air date - the flag
        // `recover_kind_from_group` reads.
        assert!(!q.daily, "{posted}");
        assert_eq!(
            q.key,
            format!("bk:{}:{date}", norm_title(title)),
            "{posted}"
        );
        // The format marker after the date is the end of the identity,
        // not part of it.
        assert!(q.extra.is_empty(), "{posted} extra={:?}", q.extra);
        // Visible: below the wall's default hide line at 50, at a
        // magazine's real size and at a bundle's.
        for bytes in [5u64 << 20, 400 << 20] {
            assert!(
                crate::junk::junk_score(&stem, &q, bytes, false) < 50,
                "{posted} at {bytes} bytes",
            );
        }
    }

    // The defect, stated as the assertion it is: two years of one
    // magazine's September are two releases, and the same issue posted
    // twice is one.
    let k = |s: &str| parse_release(&crate::names::release_stem(s)).key;
    assert_ne!(
        k("Slam.TruePDF-September.2016.pdf"),
        k("Slam.TruePDF-September.2017.pdf")
    );
    assert_ne!(
        k("Slam.TruePDF-September.2016.pdf"),
        k("Slam.TruePDF-October.2016.pdf")
    );
    assert_eq!(
        k("Slam.TruePDF-September.2016.pdf"),
        k("Slam - September 2016.pdf")
    );
    // And a monthly can never collide with a DAILY of the same paper:
    // one date is six digits and the other eight.
    assert_ne!(
        k("The New York Times - 15 August 2026.pdf"),
        k("The New York Times - August 2026.pdf")
    );
}

/// The FENCE is the whole of what makes a monthly safe to read, and it
/// is the same reasoning `dashed_episode` is built on: a month before a
/// year is not, on its own, an issue.
///
/// Every stem here parses today exactly as it did before the month
/// reading landed - measured 2 Sep 2026 on the tip, and asserted below
/// rather than described.
#[test]
fn a_month_with_a_word_in_front_of_it_is_not_an_issue() {
    // A book whose TITLE ends in a month name. Reading this as an issue
    // would eat "One Day in" and file the book under a September 2016
    // that is nothing to do with it.
    let stem = crate::names::release_stem("Author - One Day in September 2016.epub");
    let mut q = parse_release(&stem);
    recover_kind_from_group(&mut q, "alt.binaries.e-book", &stem);
    assert_eq!(q.kind, Kind::Book);
    assert_eq!(q.title, "Author - One Day in September");
    assert_eq!(q.year, Some(2016));
    assert_eq!(q.date, None);
    assert_eq!(q.key, "bk:author one day in september");

    // Films. "Sweet November" is the shape to the letter and must not
    // lose its first word or its year - and it never reaches the arm
    // twice over: no book marker, and a WORD in front of the month.
    for (stem, title, year) in [
        (
            "Sweet.November.2001.1080p.BluRay.x264-GRP",
            "Sweet November",
            2001,
        ),
        ("Sweet November 2001", "Sweet November", 2001),
        // A month at index 0 is the title's own first word.
        ("September.1987.1080p.BluRay.x264-GRP", "September", 1987),
    ] {
        let q = p(stem);
        assert_eq!(q.kind, Kind::Movie, "{stem}");
        assert_eq!(q.title, title, "{stem}");
        assert_eq!(q.year, Some(year), "{stem}");
        assert_eq!(q.date, None, "{stem}");
        assert_eq!(q.key, format!("m:{}:{year}", norm_title(title)), "{stem}");
    }

    // A NUMERIC month is refused, on the reasoning the masthead arms
    // were built on: two digits is also how an issue number, a track
    // number and a disc number look, and only a SPELLED month cannot be
    // one of those.
    let stem = crate::names::release_stem("New Scientist - 09.2016.pdf");
    let mut q = parse_release(&stem);
    recover_kind_from_group(&mut q, "alt.binaries.e-book.magazines", &stem);
    assert_eq!(q.title, "New Scientist - 09");
    assert_eq!(q.year, Some(2016));
    assert_eq!(q.date, None);
}

/// The Books lane is the other half of the gate, and it is what keeps a
/// scene ALBUM's year out of its key - the deliberate decision
/// `media_key` is built on. A month reading that reached Music would
/// undo it.
#[test]
fn a_monthly_is_read_on_the_books_lane_and_nowhere_else() {
    // A music stem carries an AUDIO marker, never a book one, so the
    // arm cannot fire on it whatever its name says.
    for stem in [
        "Various Artists - Top 40 September 2016 (MP3)",
        "Various_Artists-Top_40_September-2016-GRP",
    ] {
        let q = p(stem);
        assert_eq!(q.date, None, "{stem}");
        assert!(!q.key.contains("201609"), "{stem} key={}", q.key);
    }
    // The scene album shape the key rule exists for: the year is the
    // EDITION and stays out, remaster and original on one card.
    let a = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-1973-EOS");
    let b = p("Pink_Floyd-The_Dark_Side_Of_The_Moon-2021-EOS");
    assert_eq!(a.kind, Kind::Music);
    assert_eq!(a.date, None);
    assert_eq!(a.key, b.key);

    // And with the book marker gone - the FOLDER form of a monthly -
    // the arm stands down and the stem keeps the year it always had.
    // That is a stated limit, not an accident: `recover_kind_from_group`
    // still files it on the Books lane and it is still visible, it just
    // has no issue identity, so two Septembers still share a card.
    // Closing it wants a second re-parse inside the group prior, which
    // is a per-row cost on a multi-million-row backfill for a shape a
    // single-file magazine barely has.
    for posted in [
        "Slam.TruePDF-September.2016",
        "The.Chap.TruePDF-June.July.2016",
    ] {
        let mut q = parse_release(posted);
        recover_kind_from_group(&mut q, "alt.binaries.e-book.magazines", posted);
        assert_eq!(q.kind, Kind::Book, "{posted}");
        assert_eq!(q.date, None, "{posted}");
        assert!(q.year.is_some(), "{posted}");
        // The arm that catches a fix which disarms the group prior: on
        // the Books lane, below the wall's hide line.
        assert!(
            crate::junk::junk_score(posted, &q, 5 << 20, false) < 50,
            "{posted}",
        );
    }
}

/// `air_date_parts` writes a name to DISK, and its contract promises the
/// string reads as a real calendar date. A month-precision value has to
/// be DECLINED, never sliced into a "2026.09" that reads as a day
/// nobody wrote.
#[test]
fn air_date_parts_declines_a_month_precision_date() {
    assert_eq!(air_date_parts("202609"), None);
    assert_eq!(air_date_parts("201606"), None);
    // The eight-digit shape it does answer for, unchanged.
    assert_eq!(
        air_date_parts("20260721"),
        Some(("2026".into(), "2026.07.21".into()))
    );
    // And nothing a monthly produces can reach it in the first place:
    // the value only ever lands on a Book, and `tv_path` is Tv-only.
    let q = p("Slam.TruePDF-September.2016.pdf");
    assert_eq!(q.kind, Kind::Book);
    assert_eq!(air_date_parts(q.date.as_deref().unwrap()), None);
}

/// `junk_score`'s evidence-free rule counts the year AND the date, and a
/// monthly gives its year token up to the date. In a group with no media
/// prior - nothing to put it on the Books lane - the swap must not turn
/// a year-bearing row into an evidence-free movie at 60 purely because
/// the parser got better at reading it. Same trap as
/// `a_date_is_evidence_where_the_year_it_replaced_was`, one precision
/// down.
#[test]
fn a_month_is_evidence_where_the_year_it_replaced_was() {
    let stem = "Slam.TruePDF-September.2016.pdf";
    let q = p(stem);
    // The `.pdf` puts it on the Books lane on its own, with no group
    // prior in sight - and a Book is exempt from the tiny-post rule.
    assert_eq!(q.kind, Kind::Book);
    assert_eq!(q.year, None);
    assert_eq!(q.date.as_deref(), Some("201609"));
    for bytes in [5u64 << 20, 400 << 20] {
        assert!(
            crate::junk::junk_score(stem, &q, bytes, false) < 50,
            "{stem} at {bytes}",
        );
    }
    // `looks_like_release_name` counts the year and the date in
    // different slots but one each, so the swap is signal-neutral: this
    // stem carried exactly one signal before the month arm (its year)
    // and carries exactly one after (its date), and a magazine name
    // with no resolution, source or group has never cleared that
    // function's bar of two. Unchanged, and pinned so a later widening
    // of the arm cannot quietly move it either way.
    assert!(!looks_like_release_name("Slam.TruePDF-September.2016.pdf"));
    assert!(!looks_like_release_name("Slam.TruePDF-September.2016"));
}
