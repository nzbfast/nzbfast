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
