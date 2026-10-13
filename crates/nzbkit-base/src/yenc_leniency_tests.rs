//! yEnc leniency: one fixture per sloppy-but-decodable article shape.
//!
//! A list of article shapes other clients decode (Oct 2026), each of which
//! a strict decoder might refuse: the alternative is to place the bytes
//! actually decoded, record the defect, and let the article CRC, the
//! whole-file CRC and PAR2 decide. This file
//! records what BOTH of our decoders do with each shape, so a change to
//! either is a visible diff here rather than a surprise in the field. The
//! per-shape table and the reasoning behind each verdict are in
//! research/YENC-LENIENCY-FIXTURES-2026-10-11.md.
//!
//! Every case runs through the scalar oracle AND the SIMD decoder the
//! downloader calls, and asserts they agree, because the differential fuzz
//! target holds them equal and a fixture that only drove one would let them
//! drift.
//!
//! The wire-level shapes are elsewhere: the NNTP terminator in its own read
//! (shape 6) at `nntp::direct_read_tests` and
//! `nntp::unit_tests::bulk_multiline_matches_line_oracle_at_every_boundary`;
//! part numbers that disagree with the NZB (shape 7) at
//! `pool::steer_seam_tests::a_part_mismatch_is_never_re_asked_from_the_same_server`
//! and the rig legs in `nzbkit/src/pool/rig_tests.rs`.
use super::*;

/// What a shape decodes to.
#[derive(Debug, PartialEq, Eq)]
enum Outcome {
    /// Decoded, placed at this 1-based inclusive range, CRC vouched.
    Vouched(u64, u64),
    /// Decoded and placed, but NOT vouched: PAR2 / the block MD5 decides.
    Unvouched(u64, u64),
    /// Refused; the article costs a PAR2 block like a missing one.
    Refused(YencError),
}
use Outcome::*;

/// One part of a three-part 3000-byte file: bytes 1001..=2000.
const PART: usize = 1000;

fn payload() -> Vec<u8> {
    (0..PART).map(|i| (i * 13 + i / 7) as u8).collect()
}

/// The encoded payload LINES alone (no header, no trailer), CRLF framed,
/// taken from the reference encoder so every shape carries the same bytes.
fn payload_lines(data: &[u8]) -> Vec<u8> {
    let full = encode("x.bin", 3000, Some((2, 3)), 1001, data);
    let lines: Vec<&[u8]> = full.split(|&b| b == b'\n').collect();
    // [=ybegin, =ypart, payload.., =yend, ""]
    let mut out = Vec::new();
    for l in &lines[2..lines.len() - 2] {
        out.extend_from_slice(l);
        out.push(b'\n');
    }
    out
}

/// Both decoders, asserted to agree, reduced to an [`Outcome`].
fn outcome(body: &[u8]) -> Outcome {
    let oracle = decode_checked(body);
    let mut buf = Vec::new();
    let simd = crate::yenc_simd::decode_into_integrity(body, &mut buf, true);
    match oracle {
        Ok((d, vouched)) => {
            let (m, i) = simd.unwrap_or_else(|e| panic!("oracle Ok, SIMD {e:?}"));
            assert_eq!(d.data, buf, "decoders disagree on the bytes");
            assert_eq!(
                (d.begin, d.end),
                (m.begin, m.end),
                "decoders disagree on placement"
            );
            assert_eq!(vouched, i.crc_checked, "decoders disagree on vouching");
            assert_eq!(
                d.data,
                payload(),
                "a decoded shape must carry the payload exactly"
            );
            if vouched {
                Vouched(d.begin, d.end)
            } else {
                Unvouched(d.begin, d.end)
            }
        }
        Err(e) => {
            assert_eq!(
                simd.err().as_ref(),
                Some(&e),
                "decoders disagree on the refusal"
            );
            Refused(e)
        }
    }
}

/// An article assembled from parts, so each shape names only what it changes.
struct Art<'a> {
    pre: &'a [u8],
    begin: &'a [u8],
    part: &'a [u8],
    mid: &'a [u8],
    trailer: Vec<u8>,
    post: &'a [u8],
}

impl Art<'_> {
    fn body(&self) -> Vec<u8> {
        [
            self.pre,
            self.begin,
            self.part,
            self.mid,
            &payload_lines(&payload()),
            &self.trailer,
            self.post,
        ]
        .concat()
    }
}

const MULTI: &[u8] = b"=ybegin part=2 total=3 line=128 size=3000 name=x.bin\r\n";
const SINGLE: &[u8] = b"=ybegin line=128 size=3000 name=x.bin\r\n";
const RANGE: &[u8] = b"=ypart begin=1001 end=2000\r\n";

fn crc() -> u32 {
    crc32fast::hash(&payload())
}

fn part_trailer() -> Vec<u8> {
    format!("=yend size={PART} part=2 pcrc32={:08x}\r\n", crc()).into_bytes()
}

fn art<'a>() -> Art<'a> {
    Art {
        pre: b"",
        begin: MULTI,
        part: RANGE,
        mid: b"",
        trailer: part_trailer(),
        post: b"",
    }
}

fn with_part(part: &[u8]) -> Vec<u8> {
    Art { part, ..art() }.body()
}

#[test]
fn baseline_is_vouched_at_its_range() {
    assert_eq!(outcome(&art().body()), Vouched(1001, 2000));
}

/// Shape 1: `=ypart` with a missing, unreadable or reversed `begin`/`end`,
/// or an `end` past the declared file size.
#[test]
fn shape1_part_range_defects() {
    let geo = |begin, end| {
        Refused(YencError::PartGeometry {
            begin,
            end,
            len: 1000,
        })
    };
    for (label, part, want) in [
        // One field missing or unreadable: the other one plus the decoded
        // length fix the range. Placed, unvouched (was refused before
        // 11 Oct 2026).
        (
            "missing begin",
            &b"=ypart end=2000\r\n"[..],
            Unvouched(1001, 2000),
        ),
        (
            "unreadable begin",
            b"=ypart begin=x1001 end=2000\r\n",
            Unvouched(1001, 2000),
        ),
        (
            "begin=0",
            b"=ypart begin=0 end=2000\r\n",
            Unvouched(1001, 2000),
        ),
        (
            "missing end",
            b"=ypart begin=1001\r\n",
            Unvouched(1001, 2000),
        ),
        (
            "unreadable end",
            b"=ypart begin=1001 end=2O00\r\n",
            Unvouched(1001, 2000),
        ),
        (
            "end=0",
            b"=ypart begin=1001 end=0\r\n",
            Unvouched(1001, 2000),
        ),
        // Exactly swapped: unambiguous, placed at the smaller.
        (
            "reversed",
            b"=ypart begin=2000 end=1001\r\n",
            Unvouched(1001, 2000),
        ),
        // `end` past the declared file size: never checked against `size=`
        // (memory: the random-size poster), so it is an ordinary article.
        // The engine's clamp bounds it by the NZB's posted bytes.
        (
            "end past size",
            b"=ypart begin=2501 end=3500\r\n",
            Vouched(2501, 3500),
        ),
        // Both declared and contradicting the length: ambiguous, REFUSED.
        // Placing by `begin` alone, nothing would ever check that
        // position on a PAR2-less job (the research note, verdict table).
        (
            "end inconsistent",
            b"=ypart begin=1001 end=2100\r\n",
            geo(1001, 2100),
        ),
        (
            "reversed, wrong span",
            b"=ypart begin=2100 end=1001\r\n",
            geo(2100, 1001),
        ),
        // Only `end` declared, and shorter than the payload: nowhere to go.
        (
            "end shorter than payload",
            b"=ypart end=500\r\n",
            geo(1, 500),
        ),
        // A part 2 with NO usable range: used to land at offset 0 with its
        // CRC vouched, on top of part 1. Refused since 11 Oct 2026.
        ("no ypart line", b"", geo(1, 3000)),
        ("ypart with no fields", b"=ypart \r\n", geo(1, 0)),
        (
            "ypart, both unreadable",
            b"=ypart begin=? end=?\r\n",
            geo(1, 0),
        ),
    ] {
        assert_eq!(outcome(&with_part(part)), want, "{label}");
    }
}

/// Part 1 (or a post declaring no part) with no usable range has only one
/// place to go, so it is still decoded - unvouched, the cross-check gone.
#[test]
fn shape1_no_range_on_part_one_still_decodes_at_the_top() {
    let p1 = b"=ybegin part=1 total=3 line=128 size=3000 name=x.bin\r\n";
    let t = format!("=yend size={PART} part=1 pcrc32={:08x}\r\n", crc()).into_bytes();
    let body = Art {
        begin: p1,
        part: b"=ypart \r\n",
        trailer: t,
        ..art()
    }
    .body();
    assert_eq!(outcome(&body), Unvouched(1, 1000));
}

/// A bare `=ypart` with nothing after the keyword is not a header at all
/// (only `=yend` may be bare), so its bytes decode as payload and the
/// trailer's length refuses the article. Recorded, not changed: no client
/// writes it and the length gate is the honest answer.
#[test]
fn shape1_bare_ypart_keyword_is_payload() {
    assert_eq!(
        outcome(&with_part(b"=ypart\r\n")),
        Refused(YencError::LengthMismatch {
            expected: 1005,
            actual: 1000
        })
    );
}

/// The `strict` arm of `place_part`: a trailer whose `size=` is the WHOLE
/// file's is set aside only because the range stands in for it, so that
/// range must hold exactly - inferring it would leave nothing checking the
/// length at all.
#[test]
fn shape1_inference_never_replaces_a_waived_length_gate() {
    let t = format!("=yend size=3000 part=2 pcrc32={:08x}\r\n", crc()).into_bytes();
    let body = Art {
        part: b"=ypart begin=1001 end=2100\r\n",
        trailer: t,
        ..art()
    }
    .body();
    assert_eq!(
        outcome(&body),
        Refused(YencError::PartGeometry {
            begin: 1001,
            end: 2100,
            len: 1000
        })
    );
}

/// An inferred range still answers to the article CRC: the bytes must be
/// right even when their position is left for PAR2.
#[test]
fn shape1_inferred_range_still_refuses_a_bad_crc() {
    let t = format!("=yend size={PART} part=2 pcrc32={:08x}\r\n", crc() ^ 1).into_bytes();
    let body = Art {
        part: b"=ypart begin=1001\r\n",
        trailer: t,
        ..art()
    }
    .body();
    assert!(matches!(
        outcome(&body),
        Refused(YencError::CrcMismatch { .. })
    ));
}

/// Shape 2: a `=ypart` line after a SINGLE-part `=ybegin` (no `part=`).
/// Already decoded and placed by the range, with either CRC spelling.
#[test]
fn shape2_ypart_after_single_part_begin() {
    for trailer in [
        format!("=yend size={PART} pcrc32={:08x}\r\n", crc()),
        // `crc32` on a part is advisory (M4-87); matching, it vouches.
        format!("=yend size={PART} crc32={:08x}\r\n", crc()),
    ] {
        let body = Art {
            begin: SINGLE,
            trailer: trailer.clone().into_bytes(),
            ..art()
        }
        .body();
        assert_eq!(outcome(&body), Vouched(1001, 2000), "{trailer}");
    }
}

/// Shape 3: stray lines before `=ybegin` or around the header.
#[test]
fn shape3_stray_lines() {
    // Before `=ybegin`: nothing is read until the header, so ignored.
    let before = Art {
        pre: b"hello from the poster\r\n-- \r\n",
        ..art()
    };
    assert_eq!(outcome(&before.body()), Vouched(1001, 2000));
    // Blank lines anywhere around the header: skipped.
    let blanks = Art {
        pre: b"\r\n\r\n",
        part: b"\r\n=ypart begin=1001 end=2000\r\n\r\n",
        ..art()
    };
    assert_eq!(outcome(&blanks.body()), Vouched(1001, 2000));
    // A TEXT line between the header lines and the payload is payload to
    // every decoder that cannot see the future: it decodes, the length and
    // the CRC disagree, and the article is refused. SAB keeps a CRC-failed
    // article's bytes and NZBGet marks it bad; either way the block needs
    // repair, so the refusal costs the same block. Recorded, not changed.
    let stray = Refused(YencError::LengthMismatch {
        expected: 1015,
        actual: 1000,
    });
    // A text line BETWEEN `=ybegin` and `=ypart` is header-zone junk: the
    // payload starts after `=ypart`, which is where SABnzbd 5.1.2 and
    // NZBGet 26.3 both start it - measured byte-exact on both, 12 Oct 2026
    // (research/yenc-leniency-clients/). Discarded, and the CRC decides.
    let between = Art {
        part: b"some stray line\r\n=ypart begin=1001 end=2000\r\n",
        ..art()
    };
    assert_eq!(outcome(&between.body()), Vouched(1001, 2000));
    let after = Art {
        mid: b"some stray line\r\n",
        ..art()
    };
    assert_eq!(outcome(&after.body()), stray);
}

/// The limits of the shape-3 discard. Only plain TEXT before the first
/// `=ypart` is junk: an unrecognised `=y` control line there is a
/// declaration we cannot read (an `=yencryption` with the spike flag off is
/// exactly this), so its bytes stay in and the gates refuse, as before. And
/// only the FIRST `=ypart` discards - a duplicate one later must never throw
/// away payload that has already decoded.
#[test]
fn shape3_discard_never_swallows_a_control_line_or_real_payload() {
    let control = Art {
        part: b"=yfuture cipher=x\r\n=ypart begin=1001 end=2000\r\n",
        ..art()
    };
    assert!(matches!(
        outcome(&control.body()),
        Refused(YencError::LengthMismatch { .. })
    ));
    // Real payload, then a duplicate `=ypart`, then the rest of the payload:
    // nothing is discarded, so every byte arrives and the article decodes.
    let lines = payload_lines(&payload());
    let cut = lines.windows(2).position(|w| w == b"\r\n").unwrap() + 2;
    let body = [
        MULTI,
        RANGE,
        &lines[..cut],
        RANGE,
        &lines[cut..],
        &part_trailer(),
    ]
    .concat();
    assert_eq!(outcome(&body), Vouched(1001, 2000));
}

/// Shape 4: a missing `=yend` trailer.
#[test]
fn shape4_missing_trailer() {
    // The header's own range proves every byte arrived: placed, unvouched
    // (no trailer, no CRC - what a bare `=yend` already gets). Refused as
    // `Truncated` before 11 Oct 2026.
    let ranged = Art {
        trailer: Vec::new(),
        ..art()
    };
    assert_eq!(outcome(&ranged.body()), Unvouched(1001, 2000));
    // A single-part post whose `size=` is exactly what decoded: same.
    let single = Art {
        begin: b"=ybegin line=128 size=1000 name=x.bin\r\n",
        part: b"",
        trailer: Vec::new(),
        ..art()
    };
    assert_eq!(outcome(&single.body()), Unvouched(1, 1000));

    // The F12 invariant holds wherever the length is NOT proved: these stay
    // `Truncated`, because a provider can serve a stored-short body with a
    // perfectly good terminator.
    for (label, begin, part) in [
        // Range declared but only half filled.
        (
            "range, cut short",
            MULTI,
            &b"=ypart begin=1001 end=3000\r\n"[..],
        ),
        // Range missing a field: nothing proves the length.
        ("begin only", MULTI, b"=ypart begin=1001\r\n"),
        // Single-part `size=` disagreeing with what decoded.
        ("single, size disagrees", SINGLE, b""),
    ] {
        let body = Art {
            begin,
            part,
            trailer: Vec::new(),
            ..art()
        }
        .body();
        assert_eq!(outcome(&body), Refused(YencError::Truncated), "{label}");
    }
}

/// A body cut anywhere strictly inside its payload, with no trailer, is
/// still `Truncated` on both decoders - the guard on `trailerless_complete`
/// swept over every cut point rather than one.
#[test]
fn shape4_every_cut_inside_the_payload_is_still_truncated() {
    let mut body = art().body();
    let yend = body.windows(5).position(|w| w == b"=yend").unwrap();
    body.truncate(yend);
    let head = MULTI.len() + RANGE.len();
    // A cut that lands on a line's CR leaves every byte; stop before the
    // last line's own CRLF.
    for cut in head..yend - 2 {
        assert_eq!(
            outcome(&body[..cut]),
            Refused(YencError::Truncated),
            "cut at {cut} of {yend}"
        );
    }
}

/// Shape 5: bytes after the `=yend` trailer. The first trailer ends the
/// article (M4-84), so anything after it is ignored.
#[test]
fn shape5_bytes_after_trailer() {
    let lines = payload_lines(&payload());
    for (label, post) in [
        ("text", &b"trailing junk\r\nmore junk\r\n"[..]),
        ("yEnc-looking lines", &lines[..200]),
        ("a second trailer", b"=yend size=99 pcrc32=00000000\r\n"),
    ] {
        let body = Art { post, ..art() }.body();
        assert_eq!(outcome(&body), Vouched(1001, 2000), "{label}");
    }
    // Junk after the fields on the trailer line itself is not a field.
    let t = format!("=yend size={PART} part=2 pcrc32={:08x} junk\r\n", crc()).into_bytes();
    let body = Art {
        trailer: t,
        ..art()
    }
    .body();
    assert_eq!(outcome(&body), Vouched(1001, 2000));
}

/// Shape 6, end to end over a real loopback socket: the NNTP terminator
/// arriving in a SEPARATE network read from the body, split every way the
/// three bytes `.\r\n` (and the `\r\n` before them) can be split. Unit tests
/// already sweep the scanner at every boundary
/// (`nntp::direct_read_tests::the_in_place_scan_finds_a_terminator_split_any_way_across_reads`);
/// this leg proves the CONNECTION hands the decoder a whole article through
/// both read paths the downloader uses, with real TCP segments and a pause
/// between them so each piece lands in its own read.
#[tokio::test]
async fn shape6_terminator_in_its_own_network_read() {
    use std::io::{BufRead as _, BufReader, Write as _};
    // Each split: the bytes up to the cut, then the rest after a pause.
    // `art` ends "...pcrc32=XXXXXXXX\r\n"; the wire adds ".\r\n".
    let article = art().body();
    let mut wire = article.clone();
    wire.extend_from_slice(b".\r\n");
    let n = wire.len();
    let cuts = [n - 3, n - 2, n - 1, n - 4]; // `.\r\n` | `\r\n` | `\n` | `\n.\r\n`
    let fetches = cuts.len() * 2;

    let listener = std::net::TcpListener::bind("127.0.0.1:0").expect("bind");
    let port = listener.local_addr().unwrap().port();
    let server = std::thread::spawn(move || {
        let (s, _) = listener.accept().expect("accept");
        s.set_nodelay(true).unwrap();
        let mut w = s.try_clone().unwrap();
        let mut r = BufReader::new(s);
        w.write_all(b"200 loopback\r\n").unwrap();
        for i in 0..fetches {
            let mut cmd = String::new();
            r.read_line(&mut cmd).unwrap();
            assert!(cmd.starts_with("BODY "), "{cmd:?}");
            let cut = cuts[i % cuts.len()];
            w.write_all(b"222 0 <w@leniency>\r\n").unwrap();
            w.write_all(&wire[..cut]).unwrap();
            w.flush().unwrap();
            std::thread::sleep(std::time::Duration::from_millis(40));
            w.write_all(&wire[cut..]).unwrap();
            w.flush().unwrap();
        }
    });

    let cfg = crate::config::ServerConfig {
        host: "127.0.0.1".into(),
        port,
        tls: false,
        username: None,
        password: None,
        connections: 1,
        pin_connections: false,
        rcvbuf: None,
        level: 0,
        group: None,
        retention_days: 0,
        block_bytes: None,
        block_account: false,
        bind_ip: None,
        socks5: None,
        enabled: true,
        warm_pool: false,
        idle_release_secs: None,
        idle_keep: None,
        max_source_ips: None,
        address_family: Default::default(),
        tls_hostname: None,
        warm_reserve: None,
    };
    let (mut conn, _) = crate::nntp::Connection::connect(&cfg)
        .await
        .expect("connect");
    let check = |raw: &[u8], how: &str| {
        let mut buf = Vec::new();
        let (m, i) = crate::yenc_simd::decode_into_integrity(raw, &mut buf, true)
            .unwrap_or_else(|e| panic!("{how}: {e:?}"));
        assert_eq!(buf, payload(), "{how}");
        assert!(i.crc_checked, "{how}");
        assert_eq!((m.begin, m.end), (1001, 2000), "{how}");
    };
    for (i, cut) in cuts.iter().enumerate() {
        // The serial path.
        let raw = conn.body("<w@leniency>").await.expect("body").expect("222");
        check(&raw, &format!("body(), split at {cut}/{n} (#{i})"));
    }
    for cut in cuts {
        // The two-phase path the download workers read through.
        conn.send("BODY <w@leniency>").await.expect("send");
        let mut raw = Vec::new();
        conn.read_body_into_two_phase(
            &mut raw,
            None,
            std::time::Duration::from_secs(5),
            std::time::Duration::from_secs(5),
        )
        .await
        .expect("two-phase body");
        check(&raw, &format!("two-phase, split at {cut}/{n}"));
    }
    server.join().unwrap();
}
